#!/usr/bin/env python3
"""Root-owned Tec-Tac Tactical/Tec-Tac server backup worker.

Only opaque UUID jobs created by ``tec_tac.server_backup`` are accepted. The
worker contains a fixed operation allow-list and builds all subprocess argument
vectors itself; no module/browser supplied command or executable is executed.
"""
from __future__ import annotations

import fcntl
import grp
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ARCHIVE_RE = re.compile(r"^rmm-backup-[A-Za-z0-9_.-]+\.tar$")
ALLOWED_ACTIONS = {"create_backup", "list_backups", "restore_backup", "apply_retention", "store_secret", "delete_secret"}
BACKUP_CLASSES = {"daily", "weekly", "monthly", "manual"}
DEST_TYPES = {"local", "sftp", "ftp", "scp", "webdav", "s3"}
SAFE_DEST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
SAFE_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_SCP_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]*$|^[A-Za-z0-9._/-]+$")
CONFIG = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
DEFAULT_STATE_ROOT = Path("/var/lib/tec-tac/server-backup")
SELF = Path("/usr/local/sbin/tec-tac-server-backup")
MAX_LOG_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_BACKUP_BYTES = 1024 * 1024 * 1024 * 1024  # 1 TiB, override in config.


class OperationFailed(RuntimeError):
    def __init__(self, message, *, result=None):
        super().__init__(message)
        self.result = result or {}


class LimitedLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8", errors="replace")
        self._written = path.stat().st_size if path.exists() else 0
        self._truncated = False

    def write(self, value):
        text = str(value)
        data = text.encode("utf-8", errors="replace")
        remaining = max(0, MAX_LOG_BYTES - self._written)
        if remaining:
            chunk = data[:remaining]
            self._fh.write(chunk.decode("utf-8", errors="replace"))
            self._written += len(chunk)
        if len(data) > remaining and not self._truncated:
            self._fh.write("\n[TEC-TAC-BACKUP] log output truncated by Core\n")
            self._truncated = True
        self._fh.flush()

    def flush(self):
        self._fh.flush()

    def close(self):
        self._fh.close()


def now():
    return datetime.now(timezone.utc).isoformat()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_config():
    values = {}
    if CONFIG.is_file():
        for raw in CONFIG.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    values.setdefault("TEC_TAC_ROOT", "/opt/tec-tac")
    values.setdefault("TEC_TAC_FRAMEWORK_SOURCE", "/opt/tec-tac-src/framework")
    values.setdefault("TEC_TAC_UI_SOURCE", "/opt/tec-tac-src/ui")
    values.setdefault("TEC_TAC_STATE_ROOT", "/var/lib/tec-tac")
    values.setdefault("TEC_TAC_SERVER_BACKUP_ROOT", "/var/lib/tec-tac/server-backup")
    values.setdefault("TEC_TAC_UI_DEPLOY_ROOT", "/var/lib/tec-tac/ui/tec-tac")
    values.setdefault("TACTICAL_ROOT", "/rmm")
    values.setdefault("TACTICAL_BACKEND_ROOT", "/rmm/api/tacticalrmm")
    values.setdefault("TACTICAL_PYTHON", "/rmm/api/env/bin/python")
    values.setdefault("TACTICAL_USER", "tactical")
    values.setdefault("TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS", "/rmmbackups,/mnt,/media,/srv,/backup,/backups")
    return values


def roots(config=None):
    cfg = config or load_config()
    state = Path(cfg.get("TEC_TAC_SERVER_BACKUP_ROOT") or DEFAULT_STATE_ROOT)
    return {
        "state": state,
        "jobs": state / "jobs",
        "logs": state / "logs",
        "staging": state / "staging",
        "secrets": state / "secrets",
        "pre_restore": state / "pre-restore",
        "lock": state / "server-backup.lock",
    }


def atomic_json(path: Path, payload: dict, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def tactical_identity(config):
    info = pwd.getpwnam(config.get("TACTICAL_USER", "tactical"))
    return info.pw_uid, info.pw_gid, info.pw_name, info.pw_dir


def job_path(job_id, config=None):
    if not JOB_RE.fullmatch(str(job_id)):
        raise SystemExit("invalid job id")
    return roots(config)["jobs"] / f"{job_id}.json"


def load_job(job_id, config=None):
    path = job_path(job_id, config)
    if not path.is_file():
        raise SystemExit("job not found")
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid job document: {exc}")
    if job.get("id") != str(job_id) or job.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("invalid server-backup job")
    if not isinstance(job.get("request"), dict) or not isinstance(job.get("context"), dict):
        raise SystemExit("invalid server-backup job schema")
    return path, job


def validate_job_file(path: Path, config):
    st = path.stat()
    tactical_uid, _, _, _ = tactical_identity(config)
    if st.st_uid not in {0, tactical_uid}:
        raise SystemExit("server-backup job is not owned by root or Tactical service user")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise SystemExit("server-backup job must not be group/world writable")


def ensure_runtime_dirs(config):
    rs = roots(config)
    _, gid, _, _ = tactical_identity(config)
    for key in ("state", "jobs", "logs", "staging", "pre_restore"):
        path = rs[key]
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0, gid)
        os.chmod(path, 0o2750 if key not in {"jobs"} else 0o2770)
    rs["secrets"].mkdir(parents=True, exist_ok=True)
    os.chown(rs["secrets"], 0, 0)
    os.chmod(rs["secrets"], 0o700)
    return rs


def validate_secret(secret):
    if not isinstance(secret, dict) or not secret:
        raise RuntimeError("secret must be a non-empty object")
    out = {}
    total = 0
    for key, value in secret.items():
        name = str(key or "").strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise RuntimeError("secret contains an invalid field name")
        if value is None:
            text = ""
        elif isinstance(value, (str, int, float, bool)):
            text = str(value)
        else:
            raise RuntimeError("secret values must be scalar strings/numbers/booleans")
        total += len(name.encode()) + len(text.encode())
        if len(text) > 32768 or total > 65536:
            raise RuntimeError("secret exceeds the Core size limit")
        out[name] = text
    return out


def claim_job(job_id, config):
    rs = ensure_runtime_dirs(config)
    path, job = load_job(job_id, config)
    validate_job_file(path, config)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")

    # Secret creation is the only operation whose request contains credential
    # material. Move it immediately into a root-only transient file and redact
    # the durable job before the detached worker is launched.
    if job.get("action") == "store_secret":
        secret = validate_secret(job["request"].get("secret"))
        transient = rs["staging"] / f"secret-{job_id}.json"
        atomic_json(transient, secret, mode=0o600)
        os.chown(transient, 0, 0)
        job["request"] = {"secret_transient": str(transient), "redacted": True}

    _, gid, _, _ = tactical_identity(config)
    job["status"] = "dispatched"
    job["stage"] = "dispatched"
    atomic_json(path, job, mode=0o640)
    os.chown(path, 0, gid)
    return path, job


def dispatch(job_id):
    config = load_config()
    claim_job(job_id, config)
    unit = f"tec-tac-server-backup-{job_id}"
    command = [
        "systemd-run", "--quiet", "--collect", f"--unit={unit}",
        "--property=Type=exec", "--property=Nice=10",
        str(SELF), "--run", str(job_id),
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        path, job = load_job(job_id, config)
        transient = Path(str(job.get("request", {}).get("secret_transient") or ""))
        if transient:
            try:
                transient.resolve().relative_to(roots(config)["staging"].resolve())
                transient.unlink(missing_ok=True)
            except Exception:
                pass
        job["request"] = {"redacted": True} if job.get("action") == "store_secret" else job.get("request")
        job.update(status="failed", stage="dispatch", finished_at=now(), error=(result.stderr or "unable to launch server-backup worker").strip(), error_type="DispatchError")
        atomic_json(path, job)
        raise SystemExit(job["error"])


def acquire_lock(config, *, blocking=False):
    rs = roots(config)
    rs["lock"].parent.mkdir(parents=True, exist_ok=True)
    handle = rs["lock"].open("a+")
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(handle.fileno(), flags)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("another Core server backup/restore mutation is already running") from exc
    return handle


def sha256_file(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_regular(path: Path, *, max_bytes=None):
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"expected a regular file: {path}")
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise RuntimeError(f"file exceeds configured maximum size: {path.name}")


def max_backup_bytes(config):
    try:
        return max(1024 * 1024, int(config.get("TEC_TAC_SERVER_BACKUP_MAX_BYTES", DEFAULT_MAX_BACKUP_BYTES)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_BACKUP_BYTES


def run_logged(args, log: LimitedLog, *, env=None, cwd=None, timeout=None, user=None):
    argv = [str(x) for x in args]
    if user:
        argv = ["runuser", "-u", str(user), "--", *argv]
    log.write("[TEC-TAC-BACKUP] exec: " + " ".join(_redact_arg(x) for x in argv) + "\n")
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=cwd)
    started = time.monotonic()
    assert proc.stdout is not None
    while True:
        line = proc.stdout.readline()
        if line:
            log.write(line)
        if proc.poll() is not None:
            for remainder in proc.stdout:
                log.write(remainder)
            break
        if timeout and time.monotonic() - started > timeout:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"command exceeded {timeout} seconds")
    if proc.returncode:
        raise RuntimeError(f"command failed with status {proc.returncode}: {Path(argv[0]).name}")
    return proc.returncode


def _redact_arg(value):
    text = str(value)
    lowered = text.lower()
    if any(token in lowered for token in ("password=", "pass=", "secret_access_key=", "access_key_id=")):
        return "<redacted>"
    return text


def normalize_remote_path(value):
    raw = str(value or "").strip().replace("\\", "/")
    if "\x00" in raw:
        raise RuntimeError("remote path contains NUL")
    p = PurePosixPath(raw or ".")
    if ".." in p.parts:
        raise RuntimeError("remote path may not contain '..'")
    # rclone accepts both absolute and relative remote paths. Preserve leading /
    # but collapse duplicate separators and '.' segments.
    normalized = "/".join(part for part in p.parts if part not in {"/", "."})
    if raw.startswith("/"):
        normalized = "/" + normalized
    return normalized or "."


def safe_config_value(value, label):
    text = str(value or "").strip()
    if "\n" in text or "\r" in text or "\x00" in text:
        raise RuntimeError(f"{label} contains unsupported control characters")
    return text


def allowed_local_path(config, path: Path):
    resolved = path.resolve(strict=False)
    raw_roots = str(config.get("TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS") or "/rmmbackups,/mnt,/media,/srv,/backup,/backups")
    roots = [Path(item.strip()).resolve(strict=False) for item in raw_roots.split(",") if item.strip()]
    for root in roots:
        if resolved == root:
            return resolved
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            pass
    raise RuntimeError("local backup destination is outside the configured Core allow-list")


def validate_destination(raw, config=None):
    if not isinstance(raw, dict):
        raise RuntimeError("destination must be an object")
    item = dict(raw)
    item["id"] = str(item.get("id") if item.get("id") is not None else "").strip()
    item["type"] = str(item.get("type") or "").strip().lower()
    if not item["id"] or not SAFE_DEST_ID_RE.fullmatch(item["id"]):
        raise RuntimeError("destination id is invalid")
    if item["type"] not in DEST_TYPES:
        raise RuntimeError("destination type is unsupported")
    if item["type"] == "local":
        path = Path(str(item.get("path") or "")).expanduser()
        if not path.is_absolute() or str(path) == "/":
            raise RuntimeError("local destination path must be an absolute non-root path")
        item["path"] = str(allowed_local_path(config or load_config(), path))
    else:
        item["remote_path"] = normalize_remote_path(item.get("remote_path"))
        if item["type"] in {"sftp", "ftp", "scp"}:
            host = safe_config_value(item.get("host"), "host")
            username = safe_config_value(item.get("username"), "username")
            if not host or not username or not SAFE_HOST_RE.fullmatch(host) or not SAFE_USER_RE.fullmatch(username):
                raise RuntimeError(f"{item['type']} destination requires host and username")
            item["host"] = host
            item["username"] = username
            try:
                item["port"] = int(item.get("port") or ({"ftp": 21}.get(item["type"], 22)))
            except (TypeError, ValueError) as exc:
                raise RuntimeError("destination port must be an integer") from exc
            if not 1 <= item["port"] <= 65535:
                raise RuntimeError("destination port is out of range")
        if item["type"] == "webdav":
            item["url"] = safe_config_value(item.get("url"), "webdav url")
            if not item["url"]:
                raise RuntimeError("webdav destination requires url")
        if item["type"] == "s3":
            item["bucket"] = safe_config_value(item.get("bucket"), "s3 bucket")
            if not item["bucket"]:
                raise RuntimeError("s3 destination requires bucket")
        ref = str(item.get("secret_ref") or "").strip()
        if ref:
            try:
                uuid.UUID(ref)
            except ValueError as exc:
                raise RuntimeError("destination secret_ref must be an opaque UUID") from exc
            item["secret_ref"] = ref
        if item["type"] == "scp" and not SAFE_SCP_PATH_RE.fullmatch(str(item["remote_path"])):
            raise RuntimeError("SCP remote_path may contain only letters, numbers, dot, underscore, dash and slash")
    return item


def secret_path(config, secret_ref):
    try:
        uuid.UUID(str(secret_ref))
    except ValueError as exc:
        raise RuntimeError("invalid secret reference") from exc
    path = roots(config)["secrets"] / f"{secret_ref}.json"
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("backup destination secret was not found")
    st = path.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError("backup destination secret permissions are unsafe")
    return path


def load_secret(config, destination):
    ref = str(destination.get("secret_ref") or "").strip()
    if not ref:
        return {}
    path = secret_path(config, ref)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("backup destination secret is unreadable") from exc
    return validate_secret(value)


def rclone_obscure(value):
    result = subprocess.run(["rclone", "obscure", "-"], input=str(value), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise RuntimeError("rclone could not prepare an encrypted-at-rest temporary password field")
    return result.stdout.strip()


def ssh_known_hosts(destination, temp: Path, log: LimitedLog):
    policy = str(destination.get("host_key_policy") or "strict").strip().lower()
    fingerprint = str(destination.get("host_key_fingerprint") or destination.get("fingerprint") or "").strip()
    if policy in {"insecure", "none", "off"}:
        return None
    host = destination["host"]
    port = destination["port"]
    result = subprocess.run(["ssh-keyscan", "-p", str(port), "--", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("unable to obtain SSH host key for strict verification")
    known = temp / "known_hosts"
    known.write_text(result.stdout, encoding="utf-8")
    os.chmod(known, 0o600)
    if fingerprint:
        fp = subprocess.run(["ssh-keygen", "-lf", str(known), "-E", "sha256"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if fp.returncode or fingerprint not in fp.stdout:
            raise RuntimeError("SSH host key fingerprint does not match configured fingerprint")
    log.write(f"[TEC-TAC-BACKUP] strict SSH host key verified for {host}:{port}\n")
    return known


def make_rclone_config(config, destination, temp: Path, log: LimitedLog):
    if not shutil.which("rclone"):
        raise RuntimeError("rclone is required for this remote destination type but is not installed")
    dtype = destination["type"]
    secret = load_secret(config, destination)
    lines = ["[tectac]", f"type = {dtype if dtype != 's3' else 's3'}"]
    if dtype == "sftp":
        lines += [f"host = {destination['host']}", f"user = {destination['username']}", f"port = {destination['port']}"]
        if secret.get("password"):
            password = safe_config_value(secret["password"], "password")
            lines.append(f"pass = {rclone_obscure(password)}")
        private_key = secret.get("private_key")
        if private_key:
            key = temp / "id_key"
            key.write_text(private_key, encoding="utf-8")
            os.chmod(key, 0o600)
            lines.append(f"key_file = {key}")
        known = ssh_known_hosts(destination, temp, log)
        if known:
            lines.append(f"known_hosts_file = {known}")
    elif dtype == "ftp":
        lines += [f"host = {destination['host']}", f"user = {destination['username']}", f"port = {destination['port']}"]
        if secret.get("password"):
            password = safe_config_value(secret["password"], "password")
            lines.append(f"pass = {rclone_obscure(password)}")
        tls = str(destination.get("tls_mode") or "none").lower()
        if tls in {"implicit", "tls"}:
            lines.append("tls = true")
        elif tls in {"explicit", "starttls"}:
            lines.append("explicit_tls = true")
    elif dtype == "webdav":
        lines += [f"url = {str(destination.get('url')).strip()}", f"vendor = {str(destination.get('vendor') or 'other').strip()}"]
        if destination.get("username"):
            lines.append(f"user = {str(destination.get('username')).strip()}")
        if secret.get("password"):
            password = safe_config_value(secret["password"], "password")
            lines.append(f"pass = {rclone_obscure(password)}")
    elif dtype == "s3":
        provider = safe_config_value(destination.get("provider") or "Other", "s3 provider")
        lines += [f"provider = {provider}", "env_auth = false"]
        access = secret.get("access_key") or secret.get("access_key_id")
        secret_key = secret.get("secret_key") or secret.get("secret_access_key")
        if access:
            lines.append(f"access_key_id = {safe_config_value(access, 's3 access key')}")
        if secret_key:
            lines.append(f"secret_access_key = {safe_config_value(secret_key, 's3 secret key')}")
        if destination.get("endpoint"):
            lines.append(f"endpoint = {safe_config_value(destination.get('endpoint'), 's3 endpoint')}")
        if destination.get("region"):
            lines.append(f"region = {safe_config_value(destination.get('region'), 's3 region')}")
    else:
        raise RuntimeError(f"rclone adapter not supported for {dtype}")
    cfg = temp / "rclone.conf"
    cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(cfg, 0o600)
    return cfg


def remote_base(destination):
    path = destination.get("remote_path", ".")
    if destination["type"] == "s3":
        bucket = str(destination.get("bucket") or "").strip()
        prefix = normalize_remote_path(destination.get("prefix") or path)
        suffix = "" if prefix in {".", ""} else "/" + prefix.strip("/")
        return f"tectac:{bucket}{suffix}"
    suffix = "" if path in {".", ""} else "/" + str(path).strip("/")
    return f"tectac:{suffix}"


def join_remote(base, name):
    return base.rstrip("/") + "/" + name


def metadata_for_archive(path, backup_class, config):
    server_id = str(config.get("TEC_TAC_INSTALLATION_ID") or "").strip() or None
    return {
        "format_version": 1,
        "backup_class": backup_class,
        "created_at": now(),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "server_id": server_id,
    }


def sidecar_path(path: Path):
    return path.with_name(path.name + ".tectac.json")


def write_sidecar(path: Path, metadata):
    atomic_json(sidecar_path(path), metadata, mode=0o640)


def destination_name(destination):
    return str(destination.get("name") or f"{destination['type']}:{destination['id']}")


def store_local(destination, archive: Path, metadata):
    root = Path(destination["path"])
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise RuntimeError("local destination root may not be a symlink")
    target = root / archive.name
    if archive.resolve() != target.resolve():
        tmp = target.with_name(target.name + ".partial")
        shutil.copy2(archive, tmp)
        os.replace(tmp, target)
    write_sidecar(target, metadata)
    if target.stat().st_size != metadata["size_bytes"] or sha256_file(target) != metadata["sha256"]:
        raise RuntimeError("local backup copy verification failed")
    return {
        "id": destination["id"], "type": "local", "name": destination_name(destination), "ok": True,
        "location": str(target), "size_verified": True, "hash_verified": True,
    }


def store_rclone(config, destination, archive, metadata, log):
    with tempfile.TemporaryDirectory(prefix="tectac-rclone-") as td:
        temp = Path(td)
        cfg = make_rclone_config(config, destination, temp, log)
        base = remote_base(destination)
        archive_remote = join_remote(base, archive.name)
        sidecar = temp / (archive.name + ".tectac.json")
        sidecar.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        run_logged(["rclone", "copyto", str(archive), archive_remote, "--config", str(cfg)], log, timeout=6 * 60 * 60)
        run_logged(["rclone", "copyto", str(sidecar), archive_remote + ".tectac.json", "--config", str(cfg)], log, timeout=30 * 60)
        stat_result = subprocess.run(["rclone", "lsjson", archive_remote, "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        size_ok = False
        if stat_result.returncode == 0:
            try:
                rows = json.loads(stat_result.stdout)
                row = rows[0] if isinstance(rows, list) and rows else rows
                size_ok = int(row.get("Size", -1)) == int(metadata["size_bytes"])
            except Exception:
                size_ok = False
        if not size_ok:
            raise RuntimeError("remote backup size verification failed")
        hash_ok = False
        hash_supported = False
        hash_result = subprocess.run(["rclone", "hash", "SHA-256", archive_remote, "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        if hash_result.returncode == 0 and hash_result.stdout.strip():
            hash_supported = True
            remote_hash = hash_result.stdout.strip().split()[0].lower()
            hash_ok = remote_hash == str(metadata["sha256"]).lower()
            if not hash_ok:
                raise RuntimeError("remote backup SHA-256 verification failed")
        return {
            "id": destination["id"], "type": destination["type"], "name": destination_name(destination), "ok": True,
            "location": archive_remote, "size_verified": True, "hash_verified": hash_ok, "hash_supported": hash_supported,
        }


def scp_args(config, destination, temp, log):
    if not shutil.which("scp") or not shutil.which("ssh"):
        raise RuntimeError("scp and ssh are required for SCP backup destinations")
    secret = load_secret(config, destination)
    private_key = secret.get("private_key")
    if not private_key:
        raise RuntimeError("SCP destinations require a private_key in the referenced Core secret")
    key = temp / "id_key"
    key.write_text(private_key, encoding="utf-8")
    os.chmod(key, 0o600)
    base = ["-i", str(key), "-o", "BatchMode=yes"]
    known = ssh_known_hosts(destination, temp, log)
    if known:
        base += ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}"]
    else:
        base += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    ssh = ["-p", str(destination["port"]), *base]
    scp = ["-P", str(destination["port"]), *base]
    return ssh, scp


def store_scp(config, destination, archive, metadata, log):
    with tempfile.TemporaryDirectory(prefix="tectac-scp-") as td:
        temp = Path(td)
        ssh_common, scp_common = scp_args(config, destination, temp, log)
        remote_dir = destination["remote_path"]
        host = f"{destination['username']}@{destination['host']}"
        # Create only the validated configured directory; module cannot supply a command.
        run_logged(["ssh", *ssh_common, host, "mkdir", "-p", "--", remote_dir], log, timeout=120)
        remote_file = remote_dir.rstrip("/") + "/" + archive.name
        run_logged(["scp", *scp_common, str(archive), f"{host}:{remote_file}"], log, timeout=6 * 60 * 60)
        sidecar = temp / (archive.name + ".tectac.json")
        sidecar.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        run_logged(["scp", *scp_common, str(sidecar), f"{host}:{remote_file}.tectac.json"], log, timeout=30 * 60)
        # Download to a temporary file for strong size/hash verification. SCP has
        # no portable remote hash primitive and verification must not be guessed.
        verify = temp / archive.name
        run_logged(["scp", *scp_common, f"{host}:{remote_file}", str(verify)], log, timeout=6 * 60 * 60)
        if verify.stat().st_size != metadata["size_bytes"] or sha256_file(verify) != metadata["sha256"]:
            raise RuntimeError("SCP backup verification failed")
        return {
            "id": destination["id"], "type": "scp", "name": destination_name(destination), "ok": True,
            "location": f"scp://{destination['host']}:{destination['port']}{remote_file}", "size_verified": True, "hash_verified": True,
        }


def store_destination(config, destination, archive, metadata, log):
    destination = validate_destination(destination, config)
    if destination["type"] == "local":
        return store_local(destination, archive, metadata)
    if destination["type"] == "scp":
        return store_scp(config, destination, archive, metadata, log)
    return store_rclone(config, destination, archive, metadata, log)


def safe_tar_members(tf: tarfile.TarFile):
    members = tf.getmembers()
    for member in members:
        name = member.name.replace("\\", "/")
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise RuntimeError(f"unsafe archive member: {member.name}")
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise RuntimeError(f"unsupported archive member type: {member.name}")
    return members


def make_payload_tar(output: Path, paths, *, exclude_paths=()):
    """Create a gzip tar preserving original absolute paths beneath payload root."""
    excluded = [str(Path(item).resolve()).lstrip("/").rstrip("/") for item in exclude_paths]

    def _filter(info):
        name = info.name.lstrip("/").rstrip("/")
        if any(name == prefix or name.startswith(prefix + "/") for prefix in excluded):
            return None
        return info

    with tarfile.open(output, "w:gz") as tf:
        tf.dereference = True
        seen = set()
        for raw in paths:
            path = Path(raw)
            if not path.exists():
                continue
            resolved = path.resolve()
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            arcname = str(resolved).lstrip("/")
            tf.add(resolved, arcname=arcname, recursive=True, filter=_filter)


def detect_version(path: Path):
    version = path / "VERSION"
    if version.is_file():
        try:
            return version.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


def create_tec_tac_payload(config, temp: Path):
    runtime_root = Path(config["TEC_TAC_ROOT"])
    framework_source = Path(config["TEC_TAC_FRAMEWORK_SOURCE"])
    ui_source = Path(config["TEC_TAC_UI_SOURCE"])
    legacy_ui_source = Path("/opt/tec-tac-ui")
    state_root = Path(config["TEC_TAC_STATE_ROOT"])
    etc_root = runtime_root / "etc"
    system_etc_root = Path("/etc/tec-tac")
    nginx = Path("/etc/nginx/snippets/tec-tac.conf")

    files = {}
    backend = temp / "backend.tar.gz"
    make_payload_tar(backend, [runtime_root, framework_source])
    if backend.stat().st_size > 0:
        files["backend.tar.gz"] = backend
    ui = temp / "ui-source.tar.gz"
    make_payload_tar(ui, [ui_source, legacy_ui_source])
    if ui.stat().st_size > 0:
        files["ui-source.tar.gz"] = ui
    state = temp / "state.tar.gz"
    backup_runtime = Path(config.get("TEC_TAC_SERVER_BACKUP_ROOT") or "/var/lib/tec-tac/server-backup")
    make_payload_tar(
        state,
        [state_root],
        exclude_paths=(
            backup_runtime / "jobs",
            backup_runtime / "logs",
            backup_runtime / "staging",
            backup_runtime / "pre-restore",
            backup_runtime / "server-backup.lock",
        ),
    )
    if state.stat().st_size > 0:
        files["state.tar.gz"] = state
    etc = temp / "etc.tar.gz"
    make_payload_tar(etc, [etc_root, system_etc_root])
    if etc.stat().st_size > 0:
        files["etc.tar.gz"] = etc
    if nginx.is_file():
        nginx_copy = temp / "tec-tac.conf"
        shutil.copy2(nginx, nginx_copy)
        files["nginx/tec-tac.conf"] = nginx_copy

    manifest = {
        "format_version": 1,
        "framework_version": detect_version(framework_source) or detect_version(runtime_root),
        "ui_version": detect_version(Path(config["TEC_TAC_UI_DEPLOY_ROOT"])) or detect_version(ui_source),
        "created_at": now(),
        "paths": {
            "runtime_root": str(runtime_root),
            "framework_source": str(framework_source),
            "ui_source": str(ui_source),
            "legacy_ui_source": str(legacy_ui_source),
            "state_root": str(state_root),
            "etc_root": str(etc_root),
            "system_etc_root": str(system_etc_root),
            "nginx": str(nginx),
        },
        "members": {name: {"sha256": sha256_file(path), "size_bytes": path.stat().st_size} for name, path in files.items()},
    }
    manifest_path = temp / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files["manifest.json"] = manifest_path
    return files, manifest


def append_tec_tac_payload(archive: Path, config, log):
    with tempfile.TemporaryDirectory(prefix="tectac-payload-") as td:
        temp = Path(td)
        files, manifest = create_tec_tac_payload(config, temp)
        with tarfile.open(archive, "a") as tf:
            for name, source in files.items():
                tf.add(source, arcname=f"tec-tac/{name}", recursive=False)
        log.write(f"[TEC-TAC-BACKUP] appended Tec-Tac payload ({len(files)} members)\n")
        return manifest


def operation_create_backup(config, job, log):
    request = job["request"]
    backup_class = str(request.get("backup_class") or "").lower()
    if backup_class not in BACKUP_CLASSES:
        raise RuntimeError("invalid backup_class")
    destinations = request.get("destinations") or []
    if not isinstance(destinations, list):
        raise RuntimeError("destinations must be a list")
    destinations = [validate_destination(item, config) for item in destinations]
    include = request.get("include_tec_tac")
    if not isinstance(include, bool):
        raise RuntimeError("include_tec_tac must be boolean")

    lock = acquire_lock(config)
    try:
        tactical_root = Path(config["TACTICAL_ROOT"])
        script = tactical_root / "backup.sh"
        ensure_regular(script)
        backup_root = Path("/rmmbackups")
        backup_root.mkdir(parents=True, exist_ok=True)
        before = {p.name: p.stat().st_mtime_ns for p in backup_root.glob("rmm-backup-*.tar") if p.is_file()}
        _, _, user, home = tactical_identity(config)
        env = os.environ.copy()
        env.update({"HOME": home, "USER": user, "LOGNAME": user, "GROUP": grp.getgrgid(tactical_identity(config)[1]).gr_name})
        log.write(f"[TEC-TAC-BACKUP] running Tactical backup as {user}\n")
        run_logged([str(script)], log, env=env, cwd=str(tactical_root), timeout=6 * 60 * 60, user=user)
        candidates = []
        for path in backup_root.glob("rmm-backup-*.tar"):
            if not path.is_file() or path.is_symlink():
                continue
            mtime = path.stat().st_mtime_ns
            if path.name not in before or mtime > before.get(path.name, -1):
                candidates.append(path)
        if not candidates:
            raise RuntimeError("Tactical backup completed without a detectable new /rmmbackups/rmm-backup-*.tar archive")
        archive = max(candidates, key=lambda p: p.stat().st_mtime_ns)
        ensure_regular(archive, max_bytes=max_backup_bytes(config))
        if include:
            append_tec_tac_payload(archive, config, log)
            ensure_regular(archive, max_bytes=max_backup_bytes(config))
        metadata = metadata_for_archive(archive, backup_class, config)
        write_sidecar(archive, metadata)

        results = []
        failed = []
        for destination in destinations:
            try:
                result = store_destination(config, destination, archive, metadata, log)
            except Exception as exc:
                result = {
                    "id": destination.get("id"), "type": destination.get("type"), "name": destination_name(destination),
                    "ok": False, "reason": str(exc),
                }
                failed.append(result)
            results.append(result)
        overall = {
            "ok": not failed,
            "archive_name": archive.name,
            "local_path": str(archive),
            "size_bytes": metadata["size_bytes"],
            "sha256": metadata["sha256"],
            "backup_class": backup_class,
            "tec_tac_included": include,
            "destinations": results,
        }
        if failed:
            raise OperationFailed("One or more requested backup destinations failed verification.", result=overall)
        return overall
    finally:
        lock.close()


def sidecar_metadata_local(archive):
    sidecar = sidecar_path(archive)
    if not sidecar.is_file():
        return None
    try:
        value = json.loads(sidecar.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def backup_item(destination, archive_name, location, size, modified, metadata=None):
    cls = str((metadata or {}).get("backup_class") or "unclassified")
    if cls not in BACKUP_CLASSES:
        cls = "unclassified"
    return {
        "backup_ref": f"destination:{destination['id']}:{archive_name}",
        "archive_name": archive_name,
        "destination_id": destination["id"],
        "destination": destination_name(destination),
        "destination_type": destination["type"],
        "location": location,
        "size_bytes": int(size or 0),
        "modified_at": modified,
        "backup_class": cls,
        "sha256": (metadata or {}).get("sha256"),
        "created_at": (metadata or {}).get("created_at"),
    }


def iso_mtime(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()


def list_local(destination):
    root = Path(destination["path"])
    if not root.is_dir():
        return []
    rows = []
    for archive in sorted(root.glob("rmm-backup-*.tar")):
        if not archive.is_file() or archive.is_symlink() or not ARCHIVE_RE.fullmatch(archive.name):
            continue
        st = archive.stat()
        rows.append(backup_item(destination, archive.name, str(archive), st.st_size, iso_mtime(st.st_mtime), sidecar_metadata_local(archive)))
    return rows


def rclone_cat_json(cfg, remote):
    proc = subprocess.run(["rclone", "cat", remote, "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=60)
    if proc.returncode:
        return None
    try:
        value = json.loads(proc.stdout)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def list_rclone(config, destination, log):
    with tempfile.TemporaryDirectory(prefix="tectac-rclone-list-") as td:
        temp = Path(td)
        cfg = make_rclone_config(config, destination, temp, log)
        base = remote_base(destination)
        proc = subprocess.run(["rclone", "lsjson", base, "--files-only", "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        if proc.returncode:
            raise RuntimeError((proc.stderr or "remote listing failed").strip())
        data = json.loads(proc.stdout or "[]")
        rows = []
        for item in data:
            name = str(item.get("Name") or item.get("Path") or "")
            if not ARCHIVE_RE.fullmatch(name):
                continue
            metadata = rclone_cat_json(cfg, join_remote(base, name + ".tectac.json"))
            modified = item.get("ModTime") or (metadata or {}).get("created_at")
            rows.append(backup_item(destination, name, join_remote(base, name), item.get("Size", 0), modified, metadata))
        return rows


def list_scp(config, destination, log):
    with tempfile.TemporaryDirectory(prefix="tectac-scp-list-") as td:
        temp = Path(td)
        ssh_common, scp_common = scp_args(config, destination, temp, log)
        host = f"{destination['username']}@{destination['host']}"
        remote = destination["remote_path"]
        # Fixed find invocation. Path is passed as its own SSH argument and has
        # already been normalized/rejected for '..'.
        proc = subprocess.run(["ssh", *ssh_common, host, "find", remote, "-maxdepth", "1", "-type", "f", "-name", "rmm-backup-*.tar", "-printf", "%f\\t%s\\t%T@\\n"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        if proc.returncode:
            raise RuntimeError("SCP destination listing failed")
        rows = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or not ARCHIVE_RE.fullmatch(parts[0]):
                continue
            name, size, mtime = parts
            side_local = temp / (name + ".tectac.json")
            remote_file = remote.rstrip("/") + "/" + name
            side_proc = subprocess.run(["scp", *scp_common, f"{host}:{remote_file}.tectac.json", str(side_local)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            metadata = None
            if side_proc.returncode == 0:
                try:
                    metadata = json.loads(side_local.read_text(encoding="utf-8"))
                except Exception:
                    metadata = None
            rows.append(backup_item(destination, name, f"scp://{destination['host']}:{destination['port']}{remote_file}", int(size), iso_mtime(float(mtime)), metadata))
        return rows


def list_destination(config, destination, log):
    destination = validate_destination(destination, config)
    if destination["type"] == "local":
        return list_local(destination)
    if destination["type"] == "scp":
        return list_scp(config, destination, log)
    return list_rclone(config, destination, log)


def operation_list_backups(config, job, log):
    destinations = job["request"].get("destinations") or []
    if not isinstance(destinations, list):
        raise RuntimeError("destinations must be a list")
    rows = []
    errors = []
    for raw in destinations:
        destination = validate_destination(raw, config)
        try:
            rows.extend(list_destination(config, destination, log))
        except Exception as exc:
            errors.append({"id": destination["id"], "type": destination["type"], "reason": str(exc)})
    rows.sort(key=lambda item: str(item.get("modified_at") or ""), reverse=True)
    result = {"ok": not errors, "backups": rows, "destination_errors": errors}
    if errors:
        raise OperationFailed("One or more backup destinations could not be listed.", result=result)
    return result


def parse_backup_ref(value):
    raw = str(value or "")
    parts = raw.split(":", 2)
    if len(parts) != 3 or parts[0] != "destination":
        raise RuntimeError("backup_ref is invalid")
    dest_id, name = parts[1], parts[2]
    if not SAFE_DEST_ID_RE.fullmatch(dest_id) or not ARCHIVE_RE.fullmatch(name):
        raise RuntimeError("backup_ref is invalid")
    return dest_id, name


def download_local(destination, name, target):
    source = Path(destination["path"]) / name
    ensure_regular(source, max_bytes=max_backup_bytes(load_config()))
    shutil.copy2(source, target)
    meta = sidecar_metadata_local(source)
    return meta


def download_rclone(config, destination, name, target, log):
    with tempfile.TemporaryDirectory(prefix="tectac-rclone-download-") as td:
        temp = Path(td)
        cfg = make_rclone_config(config, destination, temp, log)
        remote = join_remote(remote_base(destination), name)
        run_logged(["rclone", "copyto", remote, str(target), "--config", str(cfg)], log, timeout=6 * 60 * 60)
        return rclone_cat_json(cfg, remote + ".tectac.json")


def download_scp(config, destination, name, target, log):
    with tempfile.TemporaryDirectory(prefix="tectac-scp-download-") as td:
        temp = Path(td)
        ssh_common, scp_common = scp_args(config, destination, temp, log)
        host = f"{destination['username']}@{destination['host']}"
        remote_file = destination["remote_path"].rstrip("/") + "/" + name
        run_logged(["scp", *scp_common, f"{host}:{remote_file}", str(target)], log, timeout=6 * 60 * 60)
        side = temp / (name + ".tectac.json")
        proc = subprocess.run(["scp", *scp_common, f"{host}:{remote_file}.tectac.json", str(side)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if proc.returncode == 0:
            try:
                return json.loads(side.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None


def download_destination(config, destination, name, target, log):
    destination = validate_destination(destination, config)
    if destination["type"] == "local":
        return download_local(destination, name, target)
    if destination["type"] == "scp":
        return download_scp(config, destination, name, target, log)
    return download_rclone(config, destination, name, target, log)


def validate_tactical_archive(archive: Path, *, restore_tec_tac: bool):
    ensure_regular(archive)
    required_exact = {"rmm/local_settings.py", "systemd/rmm.service", "meshcentral/mesh.tar.gz", "confd/etc-confd.tar.gz"}
    with tarfile.open(archive, "r") as tf:
        members = safe_tar_members(tf)
        names = {m.name.lstrip("./") for m in members}
        missing = sorted(name for name in required_exact if name not in names)
        if missing:
            raise RuntimeError("Tactical backup is missing required members: " + ", ".join(missing))
        if not any(re.fullmatch(r"postgres/db-[^/]+\.psql\.gz", name) for name in names):
            raise RuntimeError("Tactical backup does not contain its tacticalrmm PostgreSQL dump")
        has_manifest = "tec-tac/manifest.json" in names
        if restore_tec_tac and not has_manifest:
            raise RuntimeError("restore_tec_tac was requested but this archive has no Tec-Tac payload")
        manifest = None
        if has_manifest:
            fh = tf.extractfile(next(m for m in members if m.name.lstrip("./") == "tec-tac/manifest.json"))
            if fh is None:
                raise RuntimeError("Tec-Tac payload manifest is unreadable")
            manifest = json.loads(fh.read().decode("utf-8"))
            if not isinstance(manifest, dict) or int(manifest.get("format_version", 0)) != 1:
                raise RuntimeError("Tec-Tac payload manifest format is unsupported")
            for rel, info in (manifest.get("members") or {}).items():
                full = "tec-tac/" + str(rel)
                matches = [m for m in members if m.name.lstrip("./") == full]
                if len(matches) != 1:
                    raise RuntimeError(f"Tec-Tac payload member is missing: {rel}")
                member_fh = tf.extractfile(matches[0])
                if member_fh is None:
                    raise RuntimeError(f"Tec-Tac payload member is unreadable: {rel}")
                digest = hashlib.sha256()
                size = 0
                for block in iter(lambda: member_fh.read(1024 * 1024), b""):
                    digest.update(block); size += len(block)
                if digest.hexdigest() != str(info.get("sha256") or "") or size != int(info.get("size_bytes", -1)):
                    raise RuntimeError(f"Tec-Tac payload checksum failed: {rel}")
        return manifest


def extract_payload_members(archive, target):
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r") as tf:
        safe_tar_members(tf)
        for member in tf.getmembers():
            name = member.name.lstrip("./")
            if not name.startswith("tec-tac/") or not member.isfile():
                continue
            rel = Path(*PurePosixPath(name).parts[1:])
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError(f"unable to extract Tec-Tac payload member {name}")
            with out.open("wb") as dest:
                shutil.copyfileobj(source, dest)
    return target


def safe_extract_payload_tar(path, root=Path("/")):
    with tarfile.open(path, "r:gz") as tf:
        members = safe_tar_members(tf)
        for member in members:
            target = (root / member.name).resolve()
            target.relative_to(root.resolve())
        tf.extractall(root, members=members, numeric_owner=True)


def service_stop_for_restore(log):
    services = ["rmm", "celery", "celerybeat", "daphne", "nats-api", "nats", "meshcentral", "nginx"]
    for service in services:
        subprocess.run(["systemctl", "stop", service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log.write("[TEC-TAC-BACKUP] stopped Tactical services for destructive restore\n")


def run_post_restore_tec_tac(config, manifest, payload_root, log):
    if not manifest:
        return
    for name in ("backend.tar.gz", "ui-source.tar.gz", "state.tar.gz", "etc.tar.gz"):
        path = payload_root / name
        if path.is_file():
            safe_extract_payload_tar(path)
    nginx = payload_root / "nginx" / "tec-tac.conf"
    if nginx.is_file():
        target = Path("/etc/nginx/snippets/tec-tac.conf")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(nginx, target)

    paths = manifest.get("paths") or {}
    framework_source = Path(str(paths.get("framework_source") or config["TEC_TAC_FRAMEWORK_SOURCE"]))
    ui_source = Path(str(paths.get("ui_source") or config["TEC_TAC_UI_SOURCE"]))
    backend_installer = framework_source / "install.sh"
    if not backend_installer.is_file():
        raise RuntimeError(f"restored Tec-Tac framework installer not found at {backend_installer}")
    run_logged(["bash", str(backend_installer)], log, timeout=2 * 60 * 60)
    ui_installer = ui_source / "scripts" / "install.sh"
    if ui_installer.is_file():
        run_logged(["bash", str(ui_installer)], log, timeout=2 * 60 * 60)
    run_logged(["nginx", "-t"], log, timeout=60)
    subprocess.run(["systemctl", "reload", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    tactical_python = Path(config["TACTICAL_PYTHON"])
    manage = Path(config["TACTICAL_BACKEND_ROOT"]) / "manage.py"
    if tactical_python.is_file() and manage.is_file():
        run_logged([str(tactical_python), str(manage), "check"], log, cwd=str(manage.parent), timeout=300, user=config["TACTICAL_USER"])
        route_probe = "from django.urls import reverse; p=reverse('tec-tac-ui-context'); assert p.startswith('/api/tfd/'), p; print(p)"
        run_logged([str(tactical_python), str(manage), "shell", "-c", route_probe], log, cwd=str(manage.parent), timeout=300, user=config["TACTICAL_USER"])
    ui_root = Path(config.get("TEC_TAC_UI_DEPLOY_ROOT") or "/var/lib/tec-tac/ui/tec-tac")
    if not (ui_root / "index.html").is_file():
        raise RuntimeError(f"post-restore Tec-Tac UI verification failed: {ui_root / 'index.html'} is missing")
    for service in ("rmm", "celery", "celerybeat", "nginx"):
        result = subprocess.run(["systemctl", "is-active", "--quiet", service])
        if result.returncode:
            raise RuntimeError(f"post-restore service verification failed: {service}")


def operation_restore_backup(config, job, log):
    request = job["request"]
    dest_id, name = parse_backup_ref(request.get("backup_ref"))
    destination = request.get("destination")
    restore_tec_tac = request.get("restore_tec_tac")
    if not isinstance(restore_tec_tac, bool):
        raise RuntimeError("restore_tec_tac must be boolean")
    if destination is None:
        # A local reference can omit destination only for Tactical's native
        # /rmmbackups root, using destination id "local" or "0".
        if dest_id not in {"local", "0", "native"}:
            raise RuntimeError("destination configuration is required for this backup_ref")
        destination = {"id": dest_id, "type": "local", "name": "Tactical local backups", "path": "/rmmbackups"}
    destination = validate_destination(destination, config)
    if destination["id"] != dest_id:
        raise RuntimeError("backup_ref destination id does not match supplied destination")

    lock = acquire_lock(config)
    rs = roots(config)
    stage = rs["staging"] / f"restore-{job['id']}"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    archive = stage / name
    try:
        metadata = download_destination(config, destination, name, archive, log)
        ensure_regular(archive, max_bytes=max_backup_bytes(config))
        if metadata:
            if int(metadata.get("size_bytes", -1)) != archive.stat().st_size:
                raise RuntimeError("restore archive size does not match backup metadata")
            if metadata.get("sha256") and str(metadata["sha256"]).lower() != sha256_file(archive).lower():
                raise RuntimeError("restore archive SHA-256 does not match backup metadata")
        manifest = validate_tactical_archive(archive, restore_tec_tac=restore_tec_tac)
        payload_root = stage / "tec-tac-payload"
        if manifest:
            extract_payload_members(archive, payload_root)

        tactical_root = Path(config["TACTICAL_ROOT"])
        restore_script_source = tactical_root / "restore.sh"
        ensure_regular(restore_script_source)
        restore_script = stage / "restore.sh"
        shutil.copy2(restore_script_source, restore_script)
        os.chmod(restore_script, 0o755)

        job["stage"] = "restore-prepared"
        atomic_json(job_path(job["id"], config), job)
        service_stop_for_restore(log)

        moved_root = None
        if (tactical_root / "api" / "tacticalrmm").exists():
            moved_root = Path(str(tactical_root) + f".tectac-pre-restore-{stamp()}")
            if moved_root.exists():
                raise RuntimeError(f"pre-restore Tactical preservation path already exists: {moved_root}")
            os.replace(tactical_root, moved_root)
            job["result"] = {
                "ok": False,
                "backup_ref": request.get("backup_ref"),
                "archive_name": name,
                "pre_restore_tactical_path": str(moved_root),
                "restore_tec_tac": restore_tec_tac,
            }
            atomic_json(job_path(job["id"], config), job)
            log.write(f"[TEC-TAC-BACKUP] preserved existing Tactical tree at {moved_root}\n")

        _, _, user, home = tactical_identity(config)
        env = os.environ.copy(); env.update({"HOME": home, "USER": user, "LOGNAME": user, "GROUP": grp.getgrgid(tactical_identity(config)[1]).gr_name})
        # Official Tactical restore.sh insists on the same installation owner
        # and a clean /rmm tree. The old tree was atomically preserved above;
        # the root-owned worker remains outside /rmm while restore executes.
        run_logged([str(restore_script), str(archive)], log, env=env, cwd=home, timeout=10 * 60 * 60, user=user)
        if restore_tec_tac:
            run_post_restore_tec_tac(config, manifest, payload_root, log)
        run_logged(["nginx", "-t"], log, timeout=60)
        result = {
            "ok": True,
            "backup_ref": request.get("backup_ref"),
            "archive_name": name,
            "restore_tec_tac": restore_tec_tac,
            "pre_restore_tactical_path": str(moved_root) if moved_root else None,
            "completed_at": now(),
        }
        return result
    finally:
        # Preserve failed restore staging for diagnostics; successful jobs are
        # cleaned by run_job after result persistence.
        lock.close()


def delete_local(destination, name):
    archive = Path(destination["path"]) / name
    archive.unlink(missing_ok=True)
    sidecar_path(archive).unlink(missing_ok=True)


def delete_rclone(config, destination, name, log):
    with tempfile.TemporaryDirectory(prefix="tectac-rclone-delete-") as td:
        cfg = make_rclone_config(config, destination, Path(td), log)
        remote = join_remote(remote_base(destination), name)
        run_logged(["rclone", "deletefile", remote, "--config", str(cfg)], log, timeout=300)
        subprocess.run(["rclone", "deletefile", remote + ".tectac.json", "--config", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)


def delete_scp(config, destination, name, log):
    with tempfile.TemporaryDirectory(prefix="tectac-scp-delete-") as td:
        temp = Path(td); ssh_common, scp_common = scp_args(config, destination, temp, log)
        host = f"{destination['username']}@{destination['host']}"
        remote_file = destination["remote_path"].rstrip("/") + "/" + name
        run_logged(["ssh", *ssh_common, host, "rm", "-f", "--", remote_file, remote_file + ".tectac.json"], log, timeout=120)


def delete_destination(config, destination, name, log):
    destination = validate_destination(destination, config)
    if destination["type"] == "local": return delete_local(destination, name)
    if destination["type"] == "scp": return delete_scp(config, destination, name, log)
    return delete_rclone(config, destination, name, log)


def operation_apply_retention(config, job, log):
    policies = job["request"].get("policies") or []
    if not isinstance(policies, list):
        raise RuntimeError("policies must be a list")
    lock = acquire_lock(config)
    try:
        deleted = []
        failures = []
        for raw in policies:
            if not isinstance(raw, dict):
                raise RuntimeError("retention policy must be an object")
            destination = validate_destination(raw.get("destination"), config)
            keep = {}
            for cls in ("daily", "weekly", "monthly", "unclassified"):
                value = int(raw.get("keep_" + cls, 0))
                if value < 0 or value > 10000:
                    raise RuntimeError("retention keep values must be between 0 and 10000")
                keep[cls] = value
            rows = list_destination(config, destination, log)
            grouped = {key: [] for key in keep}
            for item in rows:
                cls = item.get("backup_class") if item.get("backup_class") in BACKUP_CLASSES else "unclassified"
                grouped[cls].append(item)
            for cls, items in grouped.items():
                items.sort(key=lambda x: str(x.get("modified_at") or x.get("created_at") or ""), reverse=True)
                for item in items[keep[cls]:]:
                    try:
                        delete_destination(config, destination, item["archive_name"], log)
                        deleted.append({"destination_id": destination["id"], "backup_class": cls, "archive_name": item["archive_name"]})
                    except Exception as exc:
                        failures.append({"destination_id": destination["id"], "archive_name": item["archive_name"], "reason": str(exc)})
        result = {"ok": not failures, "deleted": deleted, "failures": failures}
        if failures:
            raise OperationFailed("One or more retention deletions failed.", result=result)
        return result
    finally:
        lock.close()


def operation_store_secret(config, job, log):
    transient = Path(str(job["request"].get("secret_transient") or ""))
    rs = roots(config)
    try:
        transient.resolve().relative_to(rs["staging"].resolve())
    except Exception as exc:
        raise RuntimeError("secret transient path is invalid") from exc
    ensure_regular(transient)
    secret = validate_secret(json.loads(transient.read_text(encoding="utf-8")))
    ref = str(uuid.uuid4())
    target = rs["secrets"] / f"{ref}.json"
    atomic_json(target, secret, mode=0o600)
    os.chown(target, 0, 0); os.chmod(target, 0o600)
    transient.unlink(missing_ok=True)
    log.write("[TEC-TAC-BACKUP] stored root-only backup credential reference\n")
    return {"ok": True, "secret_ref": ref}


def operation_delete_secret(config, job, log):
    ref = str(job["request"].get("secret_ref") or "")
    path = secret_path(config, ref)
    path.unlink(missing_ok=True)
    log.write("[TEC-TAC-BACKUP] deleted root-only backup credential reference\n")
    return {"ok": True, "secret_ref": ref, "deleted": True}


OPERATIONS = {
    "create_backup": operation_create_backup,
    "list_backups": operation_list_backups,
    "restore_backup": operation_restore_backup,
    "apply_retention": operation_apply_retention,
    "store_secret": operation_store_secret,
    "delete_secret": operation_delete_secret,
}


def run_job(job_id):
    config = load_config()
    rs = ensure_runtime_dirs(config)
    path, job = load_job(job_id, config)
    if job.get("status") not in {"dispatched", "queued"}:
        raise SystemExit("job is not dispatchable")
    log = LimitedLog(rs["logs"] / f"{job_id}.log")
    job.update(status="running", stage="running", started_at=job.get("started_at") or now(), error=None, error_type=None)
    atomic_json(path, job)
    try:
        log.write(f"[TEC-TAC-BACKUP] started {now()} action={job['action']} source={job.get('context', {}).get('source_module')}\n")
        result = OPERATIONS[job["action"]](config, job, log)
        job.update(status="succeeded", stage="complete", finished_at=now(), result=result, error=None, error_type=None)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] completed {job['finished_at']}\n")
        if job["action"] == "restore_backup":
            stage = rs["staging"] / f"restore-{job_id}"
            shutil.rmtree(stage, ignore_errors=True)
    except OperationFailed as exc:
        job.update(status="failed", stage="failed", finished_at=now(), result=exc.result, error=str(exc), error_type=exc.__class__.__name__)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] failed {job['finished_at']}: {exc}\n")
    except Exception as exc:
        job.update(status="failed", stage="failed", finished_at=now(), error=str(exc), error_type=exc.__class__.__name__)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] failed {job['finished_at']}: {exc.__class__.__name__}: {exc}\n")
    finally:
        transient = rs["staging"] / f"secret-{job_id}.json"
        transient.unlink(missing_ok=True)
        log.close()



def require_root_owned(path: Path):
    target = path.resolve()
    st = target.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise SystemExit(f"refusing unsafe privileged helper ownership/mode: {target}")

def main(argv):
    if os.geteuid() != 0:
        raise SystemExit("tec-tac-server-backup must run as root")
    require_root_owned(SELF)
    if len(argv) != 3 or argv[1] not in {"--dispatch", "--run"}:
        raise SystemExit("usage: tec-tac-server-backup --dispatch <uuid> | --run <uuid>")
    job_id = argv[2]
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    if argv[1] == "--dispatch":
        dispatch(job_id)
    else:
        run_job(job_id)


if __name__ == "__main__":
    main(sys.argv)
