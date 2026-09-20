#!/usr/bin/env python3
"""Root-owned Tec-Tac Tactical/Tec-Tac server backup worker.

Only opaque UUID jobs created by ``tec_tac.server_backup`` are accepted. The
worker contains a fixed operation allow-list and builds all subprocess argument
vectors itself; no module/browser supplied command or executable is executed.
"""
from __future__ import annotations

import fcntl
import ftplib
import gzip
import grp
import hashlib
import io
import json
import os
import pwd
import platform
import secrets
import re
import shutil
import socket
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
LEGACY_ARCHIVE_RE = re.compile(r"^rmm-backup-[A-Za-z0-9_.-]+\.tar$")
BUNDLE_RE = re.compile(r"^tec-tac-backup-[A-Za-z0-9_.-]+\.tgz$")
ARCHIVE_RE = BUNDLE_RE
ALLOWED_ACTIONS = {"create_backup", "list_backups", "restore_backup", "apply_retention", "validate_destination", "validate_restore", "store_secret", "delete_secret"}
OVERRIDEABLE_RESTORE_CHECKS = {"target.os"}
TACTICAL_RESTORE_OVERRIDE_BASELINE = "67"
TACTICAL_RESTORE_OS_GATE = """if [[ "$osname" == "debian" ]]; then
  if [[ "$relno" -ne 11 && "$relno" -ne 12 ]]; then
    not_supported
    exit 1
  fi
elif [[ "$osname" == "ubuntu" ]]; then
  if [[ "$fullrelno" != "22.04" ]]; then
    not_supported
    exit 1
  fi
else
  not_supported
  exit 1
fi
"""
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


CREATE_BACKUP_PROGRESS_TOTAL = 8
CREATE_BACKUP_STAGE_LABELS = {
    "prepare": "Preparing backup",
    "tactical.backup": "Creating Tactical native backup",
    "tactical.collect.nginx": "Collecting nginx configuration",
    "tactical.collect.systemd": "Collecting systemd services",
    "tactical.collect.confd": "Collecting Tactical conf.d configuration",
    "tactical.collect.letsencrypt": "Collecting Let's Encrypt certificates",
    "tactical.collect.opt_tactical": "Collecting Tactical reporting assets",
    "tactical.validate": "Validating Tactical native backup",
    "tec_tac.backup": "Creating Tec-Tac recovery component",
    "bundle.create": "Creating recovery bundle",
    "bundle.validate": "Validating recovery bundle",
    "destination.upload": "Uploading recovery bundle",
    "destination.verify": "Verifying destination copy",
    "complete": "Complete",
}


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
        "overrides": state / "restore-overrides",
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
    if job.get("action") == "validate_destination":
        request = job["request"]
        if set(request) != {"destination"} or not isinstance(request.get("destination"), dict):
            raise SystemExit("invalid validate_destination request schema")
    if job.get("action") == "validate_restore":
        request = job["request"]
        if set(request) == {"backup_ref", "destination", "restore_mode"}:
            request["overrides"] = []
        if set(request) != {"backup_ref", "destination", "restore_mode", "overrides"}:
            raise SystemExit("invalid validate_restore request schema")
        if request.get("destination") is not None and not isinstance(request.get("destination"), dict):
            raise SystemExit("invalid validate_restore destination schema")
        if str(request.get("restore_mode") or "").strip().lower() not in {"full", "tactical", "tec_tac"}:
            raise SystemExit("invalid validate_restore mode")
        overrides = request.get("overrides")
        if not isinstance(overrides, list) or any(not isinstance(item, str) for item in overrides):
            raise SystemExit("invalid validate_restore overrides schema")
    if job.get("action") == "restore_backup":
        request = job["request"]
        if set(request) == {"backup_ref", "destination", "restore_mode"}:
            request["overrides"] = {}
        allowed = {"backup_ref", "destination", "restore_mode", "overrides"}
        if set(request) != allowed:
            raise SystemExit("invalid restore_backup request schema")
        if request.get("destination") is not None and not isinstance(request.get("destination"), dict):
            raise SystemExit("invalid restore_backup destination schema")
        if str(request.get("restore_mode") or "").strip().lower() not in {"full", "tactical", "tec_tac"}:
            raise SystemExit("invalid restore_backup mode")
        overrides = request.get("overrides")
        if not isinstance(overrides, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in overrides.items()):
            raise SystemExit("invalid restore_backup overrides schema")
    return path, job


def set_job_stage(config, job_id, stage, *, label=None, current=None, total=None):
    """Persist a safe observable job stage for read-only status consumers."""
    path, job = load_job(job_id, config)
    job["stage"] = str(stage)
    job["stage_label"] = str(label or CREATE_BACKUP_STAGE_LABELS.get(str(stage)) or str(stage).replace(".", " ").replace("-", " ").title())
    if current is not None or total is not None:
        prior = job.get("progress") if isinstance(job.get("progress"), dict) else {}
        job["progress"] = {
            "current": int(current if current is not None else prior.get("current") or 0),
            "total": int(total if total is not None else prior.get("total") or 0),
        }
    atomic_json(path, job)
    return job


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
    for key in ("state", "jobs", "logs", "staging", "pre_restore", "overrides"):
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
    if job.get("action") == "validate_destination":
        try:
            validate_destination(job["request"]["destination"], config)
        except Exception as exc:
            raise SystemExit(f"invalid validate_destination request: {exc}") from exc

    if job.get("action") == "validate_restore":
        request = job["request"]
        try:
            parse_backup_ref(request.get("backup_ref"))
            if request.get("destination") is not None:
                validate_destination(request["destination"], config)
        except Exception as exc:
            raise SystemExit(f"invalid validate_restore request: {exc}") from exc

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
        if item["type"] == "ftp":
            tls_mode = str(item.get("tls_mode") or "none").strip().lower()
            if tls_mode not in {"none", "tls", "explicit", "starttls"}:
                raise RuntimeError("ftp tls_mode must be none or explicit/starttls/tls")
            item["tls_mode"] = tls_mode
        if item["type"] in {"sftp", "scp"}:
            host_key_policy = str(item.get("host_key_policy") or "strict").strip().lower()
            if host_key_policy not in {"strict", "insecure", "none", "off"}:
                raise RuntimeError("SSH host_key_policy must be strict or insecure")
            item["host_key_policy"] = host_key_policy
            if item.get("host_key_fingerprint") or item.get("fingerprint"):
                fingerprint = safe_config_value(item.get("host_key_fingerprint") or item.get("fingerprint"), "SSH host key fingerprint")
                item["host_key_fingerprint"] = fingerprint
        if item["type"] == "webdav":
            item["url"] = safe_config_value(item.get("url"), "webdav url")
            if not item["url"] or not re.match(r"^https?://", item["url"], re.I):
                raise RuntimeError("webdav destination requires an http(s) url")
        if item["type"] == "s3":
            item["provider"] = safe_config_value(item.get("provider") or "Other", "s3 provider")
            item["bucket"] = safe_config_value(item.get("bucket"), "s3 bucket")
            item["prefix"] = normalize_remote_path(item.get("prefix") or item.get("remote_path"))
            if not item["bucket"]:
                raise RuntimeError("s3 destination requires bucket")
            if item.get("endpoint"):
                item["endpoint"] = safe_config_value(item.get("endpoint"), "s3 endpoint")
            if item.get("region"):
                item["region"] = safe_config_value(item.get("region"), "s3 region")
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


def ftp_connect(config, destination, *, timeout=60):
    destination = validate_destination(destination, config)
    secret = load_secret(config, destination)
    password = str(secret.get("password") or "")
    tls_mode = str(destination.get("tls_mode") or "none").lower()
    cls = ftplib.FTP_TLS if tls_mode in {"explicit", "starttls", "tls"} else ftplib.FTP
    ftp = cls(timeout=timeout)
    try:
        ftp.connect(destination["host"], destination["port"], timeout=timeout)
        ftp.login(destination["username"], password)
        if isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()
        ftp.set_pasv(True)
        return ftp
    except Exception:
        try: ftp.close()
        except Exception: pass
        raise


def ftp_prepare_path(ftp, remote_path, *, create=False):
    normalized = normalize_remote_path(remote_path)
    if normalized.startswith("/"):
        ftp.cwd("/")
    parts = [p for p in normalized.strip("/").split("/") if p and p != "."]
    for part in parts:
        try:
            ftp.cwd(part)
        except ftplib.error_perm:
            if not create:
                raise
            try:
                ftp.mkd(part)
            except ftplib.error_perm:
                # A racing creator may have made it; cwd remains authoritative.
                pass
            ftp.cwd(part)


def ftp_store(config, destination, archive, metadata, log):
    ftp = ftp_connect(config, destination, timeout=120)
    try:
        ftp_prepare_path(ftp, destination["remote_path"], create=True)
        with archive.open("rb") as fh:
            ftp.storbinary(f"STOR {archive.name}", fh, blocksize=1024 * 1024)
        side_bytes = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ftp.storbinary(f"STOR {archive.name}.tectac.json", io.BytesIO(side_bytes))
        try:
            remote_size = ftp.size(archive.name)
        except Exception:
            remote_size = None
        if remote_size is not None and int(remote_size) != int(metadata["size_bytes"]):
            raise RuntimeError("FTP backup size verification failed")
        # Strong verification: download and hash the stored object.
        digest = hashlib.sha256(); size = 0
        def consume(block):
            nonlocal size
            digest.update(block); size += len(block)
        ftp.retrbinary(f"RETR {archive.name}", consume, blocksize=1024 * 1024)
        if size != int(metadata["size_bytes"]) or digest.hexdigest().lower() != str(metadata["sha256"]).lower():
            raise RuntimeError("FTP backup SHA-256 verification failed")
        return {
            "id": destination["id"], "type": "ftp", "name": destination_name(destination), "ok": True,
            "location": f"ftp://{destination['host']}:{destination['port']}/{destination['remote_path'].strip('/')}/{archive.name}",
            "size_verified": True, "hash_verified": True,
        }
    finally:
        try: ftp.quit()
        except Exception:
            try: ftp.close()
            except Exception: pass


def ftp_read_json(ftp, name):
    chunks=[]
    try:
        ftp.retrbinary(f"RETR {name}", chunks.append)
        value=json.loads(b"".join(chunks).decode("utf-8"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def ftp_list(config, destination, log):
    ftp = ftp_connect(config, destination, timeout=120)
    try:
        try:
            ftp_prepare_path(ftp, destination["remote_path"], create=False)
        except ftplib.error_perm:
            raise RuntimeError("FTP configured path is inaccessible")
        entries=[]
        try:
            for name, facts in ftp.mlsd():
                entries.append((name, facts or {}))
        except Exception:
            for name in ftp.nlst():
                entries.append((Path(name).name, {}))
        rows=[]
        for name, facts in entries:
            if not (BUNDLE_RE.fullmatch(name) or LEGACY_ARCHIVE_RE.fullmatch(name)):
                continue
            try: size=int(facts.get("size") or ftp.size(name) or 0)
            except Exception: size=0
            modified=None
            raw_modify=str(facts.get("modify") or "")
            if re.fullmatch(r"\d{14}(?:\.\d+)?", raw_modify):
                try: modified=datetime.strptime(raw_modify[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
                except Exception: modified=None
            metadata=ftp_read_json(ftp, name + ".tectac.json")
            location=f"ftp://{destination['host']}:{destination['port']}/{destination['remote_path'].strip('/')}/{name}"
            rows.append(backup_item(destination,name,location,size,modified or (metadata or {}).get("created_at"),metadata))
        return rows
    finally:
        try: ftp.quit()
        except Exception:
            try: ftp.close()
            except Exception: pass


def ftp_download(config, destination, name, target, log):
    ftp=ftp_connect(config,destination,timeout=120)
    try:
        ftp_prepare_path(ftp,destination["remote_path"],create=False)
        with target.open("wb") as fh:
            ftp.retrbinary(f"RETR {name}",fh.write,blocksize=1024*1024)
        return ftp_read_json(ftp,name+".tectac.json")
    finally:
        try: ftp.quit()
        except Exception:
            try: ftp.close()
            except Exception: pass


def ftp_delete(config, destination, name, log):
    ftp=ftp_connect(config,destination,timeout=120)
    try:
        ftp_prepare_path(ftp,destination["remote_path"],create=False)
        ftp.delete(name)
        try: ftp.delete(name+".tectac.json")
        except ftplib.error_perm: pass
    finally:
        try: ftp.quit()
        except Exception:
            try: ftp.close()
            except Exception: pass


def metadata_for_archive(path, backup_class, config, *, components=None, recovery_modes=None):
    server_id = str(config.get("TEC_TAC_INSTALLATION_ID") or "").strip() or None
    return {
        "format_version": 2,
        "artifact_type": "tec-tac-recovery-bundle",
        "backup_class": backup_class,
        "created_at": now(),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "server_id": server_id,
        "components": dict(components or {}),
        "recovery_modes": list(recovery_modes or []),
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
    if destination["type"] == "ftp":
        return ftp_store(config, destination, archive, metadata, log)
    return store_rclone(config, destination, archive, metadata, log)


def _normalize_tar_namespace_path(raw: str, *, base: PurePosixPath | None = None, label: str = "archive path") -> PurePosixPath:
    """Resolve a TAR path inside the archive namespace without touching the host filesystem."""
    text = str(raw or "").replace("\\", "/")
    if not text or "\x00" in text:
        raise RuntimeError(f"unsafe {label}: {raw!r}")
    path = PurePosixPath(text)
    if path.is_absolute():
        raise RuntimeError(f"unsafe {label}: {raw!r}")

    parts = []
    if base is not None:
        parts.extend(part for part in base.parts if part not in ("", "."))
    for part in path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise RuntimeError(f"unsafe {label}: {raw!r}")
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        return PurePosixPath(".")
    return PurePosixPath(*parts)


def safe_tar_members(tf: tarfile.TarFile):
    """Validate TAR members and links strictly within the archive namespace.

    Symlinks and hardlinks are allowed only when both their member path and
    resolved target stay inside the archive extraction namespace.  This is a
    namespace check only: no host filesystem symlink is followed here.
    """
    members = tf.getmembers()
    normalized = {}
    for member in members:
        member_path = _normalize_tar_namespace_path(member.name, label="archive member")
        key = member_path.as_posix()
        if key in normalized:
            raise RuntimeError(f"duplicate archive member path: {member.name}")
        normalized[key] = member
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise RuntimeError(f"unsupported archive member type: {member.name}")

    for member in members:
        member_path = _normalize_tar_namespace_path(member.name, label="archive member")
        if member.issym():
            _normalize_tar_namespace_path(
                member.linkname,
                base=member_path.parent,
                label=f"symlink target for {member.name}",
            )
        elif member.islnk():
            target = _normalize_tar_namespace_path(
                member.linkname,
                label=f"hardlink target for {member.name}",
            )
            if target.as_posix() not in normalized:
                raise RuntimeError(f"hardlink target is not present in archive: {member.name} -> {member.linkname}")
    return members


def _canonical_payload_roots(paths):
    """Return unique existing roots with recursively-covered children removed.

    Payload inputs are canonicalized with Path.resolve() first.  If an included
    directory already recursively covers another requested path, the child is
    discarded so tarfile cannot emit the same normalized archive member twice.
    Input order is preserved for the remaining independent roots.
    """
    resolved_paths = []
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
        resolved_paths.append(resolved)

    roots = []
    for candidate in resolved_paths:
        covered = False
        for ancestor in resolved_paths:
            if ancestor == candidate or not ancestor.is_dir():
                continue
            try:
                candidate.relative_to(ancestor)
            except ValueError:
                continue
            covered = True
            break
        if not covered:
            roots.append(candidate)
    return roots


def make_payload_tar(output: Path, paths, *, exclude_paths=()):
    """Create a gzip tar preserving original absolute paths beneath payload root.

    Requested roots are canonicalized before archiving. Descendants already
    covered recursively by another included directory are omitted; duplicate
    member validation remains authoritative for the resulting archive.
    """
    excluded = [str(Path(item).resolve()).lstrip("/").rstrip("/") for item in exclude_paths]

    def _filter(info):
        name = info.name.lstrip("/").rstrip("/")
        if any(name == prefix or name.startswith(prefix + "/") for prefix in excluded):
            return None
        return info

    with tarfile.open(output, "w:gz") as tf:
        tf.dereference = True
        for resolved in _canonical_payload_roots(paths):
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


def tec_tac_paths(config):
    runtime_root = Path(config["TEC_TAC_ROOT"])
    framework_source = Path(config["TEC_TAC_FRAMEWORK_SOURCE"])
    ui_source = Path(config["TEC_TAC_UI_SOURCE"])
    legacy_ui_source = Path("/opt/tec-tac-ui")
    state_root = Path(config["TEC_TAC_STATE_ROOT"])
    etc_root = runtime_root / "etc"
    system_etc_root = Path("/etc/tec-tac")
    nginx = Path("/etc/nginx/snippets/tec-tac.conf")
    return {
        "runtime_root": runtime_root,
        "framework_source": framework_source,
        "ui_source": ui_source,
        "legacy_ui_source": legacy_ui_source,
        "state_root": state_root,
        "etc_root": etc_root,
        "system_etc_root": system_etc_root,
        "nginx": nginx,
    }


def create_tec_tac_component(config, output: Path):
    paths = tec_tac_paths(config)
    # /var/lib/tec-tac is intentionally excluded in full from recovery payloads.
    # It contains mutable runtime/cache/history/staging data whose inclusion can
    # recursively capture old installers and backup artifacts and cause runaway
    # growth. Durable scheduler/dashboard/preferences data lives in Tactical's
    # PostgreSQL backup; the deployed UI is rebuilt from ui_source on restore.
    include = [
        paths["runtime_root"], paths["framework_source"], paths["ui_source"], paths["legacy_ui_source"],
        # runtime_root already recursively includes runtime_root/etc. Keep the
        # system-level /etc/tec-tac configuration as a separate root.
        paths["system_etc_root"], paths["nginx"],
    ]
    make_payload_tar(output, include, exclude_paths=(paths["state_root"],))
    ensure_regular(output, max_bytes=max_backup_bytes(config))
    return {
        "included": True,
        "archive": "tec-tac/tec-tac-backup.tar.gz",
        "archive_name": "tec-tac-backup.tar.gz",
        "sha256": sha256_file(output),
        "size_bytes": output.stat().st_size,
        "framework_version": detect_version(paths["framework_source"]) or detect_version(paths["runtime_root"]),
        "ui_version": detect_version(Path(config["TEC_TAC_UI_DEPLOY_ROOT"])) or detect_version(paths["ui_source"]),
        "paths": {key: str(value) for key, value in paths.items()},
        "state_policy": {
            "state_root": str(paths["state_root"]),
            "included": False,
            "reason": "mutable runtime/cache/history/staging state is rebuilt after restore",
        },
    }


def create_tactical_component(config, log, job_id):
    tactical_root = Path(config["TACTICAL_ROOT"])
    script = tactical_root / "backup.sh"
    ensure_regular(script)
    backup_root = Path("/rmmbackups")
    backup_root.mkdir(parents=True, exist_ok=True)
    uid, gid, user, home = tactical_identity(config)
    try:
        os.chown(backup_root, uid, gid)
    except PermissionError:
        pass
    before = {p.name: p.stat().st_mtime_ns for p in backup_root.glob("rmm-backup-*.tar") if p.is_file()}

    # Tactical backup.sh v34 still invokes sudo for a small set of root-owned
    # files but does not fail closed if those sudo calls fail. Core supplies a
    # narrow sudo shim which can request only those fixed collection operations
    # through this helper. The Tactical-generated temporary workspace is bound
    # to this opaque create_backup job and no caller-selected source path or
    # command is ever accepted by the privileged helper.
    rs = roots(config)
    tmp_parent = rs["staging"] / f"tactical-native-{job_id}"
    shutil.rmtree(tmp_parent, ignore_errors=True)
    tmp_parent.mkdir(parents=True, exist_ok=True)
    os.chown(tmp_parent, uid, gid)
    os.chmod(tmp_parent, 0o700)
    shim_dir = Path("/usr/local/lib/tec-tac-backup")
    sudo_shim = shim_dir / "sudo"
    ensure_regular(sudo_shim)

    mesh_config = Path("/meshcentral/meshcentral-data/config.json")
    if mesh_config.is_file():
        try:
            mesh_text = mesh_config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            mesh_text = ""
        if "postgres" in mesh_text and shutil.which("jq") is None:
            raise RuntimeError("Tactical backup requires jq for MeshCentral PostgreSQL backup; install jq before running Core backup")

    env = os.environ.copy()
    env.update({
        "HOME": home, "USER": user, "LOGNAME": user,
        "GROUP": grp.getgrgid(gid).gr_name,
        "TMPDIR": str(tmp_parent),
        "TEC_TAC_BACKUP_JOB_ID": str(job_id),
        "PATH": str(shim_dir) + os.pathsep + env.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    })
    set_job_stage(config, job_id, "tactical.backup", current=2, total=CREATE_BACKUP_PROGRESS_TOTAL)
    log.write(f"[TEC-TAC-BACKUP] running Tactical backup as {user} with Core narrow privilege bridge\n")
    try:
        run_logged([str(script)], log, env=env, cwd=str(tactical_root), timeout=6 * 60 * 60, user=user)
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)

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
    set_job_stage(config, job_id, "tactical.validate", current=3, total=CREATE_BACKUP_PROGRESS_TOTAL)
    try:
        # Mandatory trust boundary: never hash, bundle or upload a native
        # Tactical archive until the exact artifact produced by backup.sh has
        # passed restore-readiness validation.
        validate_tactical_native_archive(archive)
    except Exception:
        archive.unlink(missing_ok=True)
        raise
    digest = sha256_file(archive)
    return archive, {
        "included": True,
        "archive": f"tactical/{archive.name}",
        "archive_name": archive.name,
        "sha256": digest,
        "size_bytes": archive.stat().st_size,
    }


def bundle_recovery_modes(include_tactical, include_tec_tac):
    modes=[]
    if include_tactical and include_tec_tac: modes.append("full")
    if include_tactical: modes.append("tactical")
    if include_tec_tac: modes.append("tec_tac")
    return modes


def create_recovery_bundle(config, temp: Path, *, backup_class, tactical_archive=None, tactical_meta=None, tec_tac_archive=None, tec_tac_meta=None):
    created_at=now()
    components={
        "tactical": tactical_meta or {"included": False},
        "tec_tac": tec_tac_meta or {"included": False},
    }
    modes=bundle_recovery_modes(bool(tactical_meta), bool(tec_tac_meta))
    manifest={
        "format_version": 2,
        "artifact_type": "tec-tac-recovery-bundle",
        "created_at": created_at,
        "installation_id": str(config.get("TEC_TAC_INSTALLATION_ID") or "").strip() or None,
        "backup_class": backup_class,
        "components": components,
        "recovery_modes": modes,
    }
    manifest_path=temp/"manifest.json"
    manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    checksum_lines=[]
    if tactical_archive is not None:
        checksum_lines.append(f"{tactical_meta['sha256']}  tactical/{tactical_archive.name}")
    if tec_tac_archive is not None:
        checksum_lines.append(f"{tec_tac_meta['sha256']}  tec-tac/tec-tac-backup.tar.gz")
    checksums=temp/"checksums.sha256"
    checksums.write_text("\n".join(checksum_lines)+"\n",encoding="utf-8")
    bundle_name=datetime.now(timezone.utc).strftime("tec-tac-backup-%Y_%m_%d__%H_%M_%S.tgz")
    output=Path("/rmmbackups")/bundle_name
    output.parent.mkdir(parents=True,exist_ok=True)
    partial=output.with_name(output.name+".partial")
    partial.unlink(missing_ok=True)
    with tarfile.open(partial,"w:gz") as tf:
        tf.add(manifest_path,arcname="manifest.json",recursive=False)
        tf.add(checksums,arcname="checksums.sha256",recursive=False)
        if tactical_archive is not None:
            tf.add(tactical_archive,arcname=f"tactical/{tactical_archive.name}",recursive=False)
        if tec_tac_archive is not None:
            tf.add(tec_tac_archive,arcname="tec-tac/tec-tac-backup.tar.gz",recursive=False)
    os.replace(partial,output)
    ensure_regular(output,max_bytes=max_backup_bytes(config))
    # Prove the copied Tactical member is byte-identical to the authoritative native archive.
    if tactical_archive is not None:
        with tarfile.open(output,"r:gz") as tf:
            member=tf.getmember(f"tactical/{tactical_archive.name}")
            fh=tf.extractfile(member)
            if fh is None: raise RuntimeError("recovery bundle Tactical component is unreadable")
            digest=hashlib.sha256(); size=0
            for block in iter(lambda:fh.read(1024*1024),b""):
                digest.update(block); size+=len(block)
            if digest.hexdigest()!=tactical_meta["sha256"] or size!=tactical_meta["size_bytes"]:
                raise RuntimeError("Tactical archive changed while creating recovery bundle")
    return output, manifest


def operation_create_backup(config, job, log):
    request = job["request"]
    backup_class = str(request.get("backup_class") or "").lower()
    if backup_class not in BACKUP_CLASSES:
        raise RuntimeError("invalid backup_class")
    destinations = request.get("destinations") or []
    if not isinstance(destinations, list):
        raise RuntimeError("destinations must be a list")
    destinations = [validate_destination(item, config) for item in destinations]
    include_tactical=request.get("include_tactical")
    include_tec_tac=request.get("include_tec_tac")
    if not isinstance(include_tactical,bool) or not isinstance(include_tec_tac,bool):
        raise RuntimeError("include_tactical and include_tec_tac must be boolean")
    if not include_tactical and not include_tec_tac:
        raise RuntimeError("at least one recovery component must be included")

    set_job_stage(config, job["id"], "prepare", current=1, total=CREATE_BACKUP_PROGRESS_TOTAL)
    lock = acquire_lock(config)
    try:
        with tempfile.TemporaryDirectory(prefix="tectac-recovery-bundle-") as td:
            temp=Path(td)
            tactical_archive=tactical_meta=None
            if include_tactical:
                tactical_archive,tactical_meta=create_tactical_component(config,log,job["id"])
            else:
                set_job_stage(config, job["id"], "tactical.validate", current=3, total=CREATE_BACKUP_PROGRESS_TOTAL)
            tec_archive=tec_meta=None
            set_job_stage(config, job["id"], "tec_tac.backup", current=4, total=CREATE_BACKUP_PROGRESS_TOTAL)
            if include_tec_tac:
                tec_archive=temp/"tec-tac-backup.tar.gz"
                tec_meta=create_tec_tac_component(config,tec_archive)
            set_job_stage(config, job["id"], "bundle.create", current=5, total=CREATE_BACKUP_PROGRESS_TOTAL)
            bundle,manifest=create_recovery_bundle(
                config,temp,backup_class=backup_class,
                tactical_archive=tactical_archive,tactical_meta=tactical_meta,
                tec_tac_archive=tec_archive,tec_tac_meta=tec_meta,
            )
            set_job_stage(config, job["id"], "bundle.validate", current=6, total=CREATE_BACKUP_PROGRESS_TOTAL)
            validation_stage=temp/"bundle-validation"
            validation_stage.mkdir(parents=True,exist_ok=True)
            try:
                validation_mode="full" if include_tactical and include_tec_tac else ("tactical" if include_tactical else "tec_tac")
                validate_recovery_bundle(bundle,validation_mode,validation_stage)
            finally:
                shutil.rmtree(validation_stage,ignore_errors=True)
            component_flags={key:{"included":bool(value.get("included"))} for key,value in manifest["components"].items()}
            metadata=metadata_for_archive(bundle,backup_class,config,components=component_flags,recovery_modes=manifest["recovery_modes"])
            write_sidecar(bundle,metadata)
            if tactical_archive is not None and tactical_archive.exists():
                tactical_archive.unlink()
                log.write("[TEC-TAC-BACKUP] removed native source archive after byte-identical recovery bundle verification\n")
            results=[]; failed=[]
            if not destinations:
                set_job_stage(config, job["id"], "destination.upload", current=7, total=CREATE_BACKUP_PROGRESS_TOTAL)
                set_job_stage(config, job["id"], "destination.verify", current=8, total=CREATE_BACKUP_PROGRESS_TOTAL)
            for destination in destinations:
                set_job_stage(config, job["id"], "destination.upload", label=f"Uploading recovery bundle to {destination_name(destination)}", current=7, total=CREATE_BACKUP_PROGRESS_TOTAL)
                try:
                    result=store_destination(config,destination,bundle,metadata,log)
                    set_job_stage(config, job["id"], "destination.verify", label=f"Verifying destination copy at {destination_name(destination)}", current=8, total=CREATE_BACKUP_PROGRESS_TOTAL)
                    if not isinstance(result,dict) or result.get("ok") is False:
                        raise RuntimeError(str((result or {}).get("reason") if isinstance(result,dict) else "destination verification failed"))
                except Exception as exc:
                    result={"id":destination.get("id"),"type":destination.get("type"),"name":destination_name(destination),"ok":False,"reason":str(exc)}
                    failed.append(result)
                results.append(result)
            overall={
                "ok":not failed,
                "archive_name":bundle.name,
                "local_path":str(bundle),
                "size_bytes":metadata["size_bytes"],
                "sha256":metadata["sha256"],
                "backup_class":backup_class,
                "format_version":2,
                "components":manifest["components"],
                "recovery_modes":manifest["recovery_modes"],
                "destinations":results,
            }
            if failed:
                raise OperationFailed("One or more requested backup destinations failed verification.",result=overall)
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
    metadata = metadata or {}
    cls = str(metadata.get("backup_class") or "unclassified")
    if cls not in BACKUP_CLASSES:
        cls = "unclassified"
    legacy = bool(LEGACY_ARCHIVE_RE.fullmatch(archive_name))
    if legacy:
        format_version = int(metadata.get("format_version") or 1)
        components = metadata.get("components") if isinstance(metadata.get("components"), dict) else {"tactical": {"included": True}, "tec_tac": {"included": False}}
        modes = metadata.get("recovery_modes") if isinstance(metadata.get("recovery_modes"), list) else ["tactical"]
    else:
        format_version = int(metadata.get("format_version") or 2)
        components = metadata.get("components") if isinstance(metadata.get("components"), dict) else {}
        modes = metadata.get("recovery_modes") if isinstance(metadata.get("recovery_modes"), list) else []
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
        "sha256": metadata.get("sha256"),
        "created_at": metadata.get("created_at"),
        "format_version": format_version,
        "legacy": legacy,
        "components": components,
        "recovery_modes": modes,
    }


def iso_mtime(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()


def list_local(destination):
    root = Path(destination["path"])
    if not root.is_dir():
        return []
    rows = []
    for archive in sorted(root.iterdir()):
        if not archive.is_file() or archive.is_symlink():
            continue
        if not (BUNDLE_RE.fullmatch(archive.name) or LEGACY_ARCHIVE_RE.fullmatch(archive.name)):
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
            if not (BUNDLE_RE.fullmatch(name) or LEGACY_ARCHIVE_RE.fullmatch(name)):
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
            if len(parts) != 3 or not (BUNDLE_RE.fullmatch(parts[0]) or LEGACY_ARCHIVE_RE.fullmatch(parts[0])):
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
    if destination["type"] == "ftp":
        return ftp_list(config, destination, log)
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
    if not SAFE_DEST_ID_RE.fullmatch(dest_id) or not (BUNDLE_RE.fullmatch(name) or LEGACY_ARCHIVE_RE.fullmatch(name)):
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
    if destination["type"] == "ftp":
        return ftp_download(config, destination, name, target, log)
    return download_rclone(config, destination, name, target, log)


def _stream_gzip_member(tf, member, label):
    source = tf.extractfile(member)
    if source is None:
        raise RuntimeError(f"{label} is unreadable")
    try:
        with gzip.GzipFile(fileobj=source, mode="rb") as gz:
            for _ in iter(lambda: gz.read(1024 * 1024), b""):
                pass
    except Exception as exc:
        raise RuntimeError(f"{label} gzip stream is corrupt: {exc}") from exc


def _stream_tar_gzip_member(tf, member, label):
    source = tf.extractfile(member)
    if source is None:
        raise RuntimeError(f"{label} is unreadable")
    try:
        with tarfile.open(fileobj=source, mode="r:gz") as nested:
            safe_tar_members(nested)
    except Exception as exc:
        raise RuntimeError(f"{label} tar/gzip stream is corrupt: {exc}") from exc


def validate_tactical_native_archive(archive: Path):
    """Read-only compatibility validation for Tactical backup.sh v34 / restore.sh v67."""
    ensure_regular(archive, max_bytes=max_backup_bytes(load_config()))
    required_exact = {
        "rmm/local_settings.py",
        "meshcentral/mesh.tar.gz",
        "confd/etc-confd.tar.gz",
        "nginx/rmm.conf",
        "nginx/frontend.conf",
        "nginx/meshcentral.conf",
        "systemd/rmm.service",
        "systemd/celery.service",
        "systemd/celerybeat.service",
        "systemd/meshcentral.service",
        "systemd/nats.service",
        "systemd/nats-api.service",
    }
    with tarfile.open(archive, "r") as tf:
        members = safe_tar_members(tf)
        by_name = {m.name.lstrip("./"): m for m in members}
        names = set(by_name)
        missing = sorted(name for name in required_exact if name not in names)
        if missing:
            raise RuntimeError("Tactical backup is missing required members: " + ", ".join(missing))
        # Current upstream backup uses daphne.service; accept uvicorn.service for
        # forward-compatible restored backups where that service has migrated.
        if not ({"systemd/daphne.service", "systemd/uvicorn.service"} & names):
            raise RuntimeError("Tactical backup is missing its daphne/uvicorn systemd unit")
        db_names = [name for name in names if re.fullmatch(r"postgres/db-[^/]+\.psql\.gz", name)]
        if not db_names:
            raise RuntimeError("Tactical backup does not contain its tacticalrmm PostgreSQL dump")
        mesh_db = [name for name in names if re.fullmatch(r"postgres/mesh-db-[^/]+\.psql\.gz", name)]
        mongo_material = any(name == "meshcentral/mongo" or name.startswith("meshcentral/mongo/") for name in names)
        if not mesh_db and not mongo_material:
            raise RuntimeError("Tactical backup does not contain supported MeshCentral database material")
        for name in db_names + mesh_db:
            _stream_gzip_member(tf, by_name[name], name)
        _stream_tar_gzip_member(tf, by_name["meshcentral/mesh.tar.gz"], "meshcentral/mesh.tar.gz")
        _stream_tar_gzip_member(tf, by_name["confd/etc-confd.tar.gz"], "confd/etc-confd.tar.gz")
        # Optional archives are validated when present, but absence follows
        # Tactical restore fallback semantics.
        for name in ("certs/etc-letsencrypt.tar.gz", "opt/opt-tactical.tar.gz"):
            if name in by_name:
                _stream_tar_gzip_member(tf, by_name[name], name)
    return True


def validate_tec_tac_component(path: Path, component_meta=None):
    ensure_regular(path, max_bytes=max_backup_bytes(load_config()))
    meta = component_meta or {}
    expected_paths = []
    for value in (meta.get("paths") or {}).values():
        text = str(value or "").strip()
        if text.startswith("/"):
            expected_paths.append(text.lstrip("/"))
    with tarfile.open(path, "r:gz") as tf:
        members = safe_tar_members(tf)
        if not members:
            raise RuntimeError("Tec-Tac component is empty")
        names = {member.name.lstrip("./") for member in members}
        state_root = str(((meta.get("state_policy") or {}).get("state_root")) or "/var/lib/tec-tac").strip().lstrip("/").rstrip("/")
        for name in names:
            if name == "rmm" or name.startswith("rmm/"):
                raise RuntimeError("Tec-Tac recovery component may not contain Tactical /rmm tracked source")
            if state_root and (name == state_root or name.startswith(state_root + "/")):
                raise RuntimeError("Tec-Tac recovery component may not contain /var/lib/tec-tac mutable state")
        # Paths recorded in the manifest must be structurally safe. The
        # recovery component intentionally excludes /var/lib/tec-tac and must
        # still contain framework/runtime and configuration payloads.
        for rel in expected_paths:
            pp = PurePosixPath(rel)
            if pp.is_absolute() or ".." in pp.parts:
                raise RuntimeError("Tec-Tac component manifest contains an unsafe source path")
        classes = {
            "framework": any(name == "opt/tec-tac" or name.startswith("opt/tec-tac/") or name.startswith("opt/tec-tac-src/framework/") for name in names),
            "config": any(name == "etc/tec-tac" or name.startswith("etc/tec-tac/") or name.startswith("opt/tec-tac/etc/") for name in names),
        }
        if not classes["framework"]:
            raise RuntimeError("Tec-Tac component does not contain framework/runtime payload")
        if not classes["config"]:
            raise RuntimeError("Tec-Tac component does not contain configuration payload")
    return True

def parse_checksum_file(text):
    records={}
    for raw in str(text or "").splitlines():
        line=raw.strip()
        if not line: continue
        match=re.fullmatch(r"([0-9a-fA-F]{64})\s{2}([^\s].*)",line)
        if not match:
            raise RuntimeError("recovery bundle checksums.sha256 contains an invalid line")
        rel=match.group(2).strip().replace("\\","/")
        pp=PurePosixPath(rel)
        if pp.is_absolute() or ".." in pp.parts:
            raise RuntimeError("recovery bundle checksum path is unsafe")
        if rel in records:
            raise RuntimeError("recovery bundle checksum file contains duplicate paths")
        records[rel]=match.group(1).lower()
    return records


def extract_verified_bundle_member(tf, member, target, expected_hash, expected_size):
    source=tf.extractfile(member)
    if source is None:
        raise RuntimeError(f"recovery bundle member is unreadable: {member.name}")
    target.parent.mkdir(parents=True,exist_ok=True)
    digest=hashlib.sha256(); size=0
    with target.open("wb") as out:
        for block in iter(lambda:source.read(1024*1024),b""):
            out.write(block); digest.update(block); size+=len(block)
    if size != int(expected_size) or digest.hexdigest().lower() != str(expected_hash).lower():
        target.unlink(missing_ok=True)
        raise RuntimeError(f"recovery bundle component checksum failed: {member.name}")
    return target


def validate_recovery_bundle(bundle: Path, restore_mode: str, stage: Path, *, validate_components=True):
    ensure_regular(bundle, max_bytes=max_backup_bytes(load_config()))
    if not BUNDLE_RE.fullmatch(bundle.name):
        raise RuntimeError("recovery bundle filename is invalid")
    with tarfile.open(bundle,"r:gz") as tf:
        members=safe_tar_members(tf)
        names=[m.name.lstrip("./") for m in members]
        if len(names) != len(set(names)):
            raise RuntimeError("recovery bundle contains duplicate member paths")
        by_name={m.name.lstrip("./"):m for m in members}
        if "manifest.json" not in by_name or "checksums.sha256" not in by_name:
            raise RuntimeError("recovery bundle requires manifest.json and checksums.sha256")
        mf=tf.extractfile(by_name["manifest.json"]); cf=tf.extractfile(by_name["checksums.sha256"])
        if mf is None or cf is None: raise RuntimeError("recovery bundle metadata is unreadable")
        manifest=json.loads(mf.read().decode("utf-8"))
        if not isinstance(manifest,dict) or int(manifest.get("format_version",0)) != 2:
            raise RuntimeError("recovery bundle format is unsupported")
        if manifest.get("artifact_type") not in (None,"tec-tac-recovery-bundle"):
            raise RuntimeError("recovery bundle artifact type is invalid")
        checksums=parse_checksum_file(cf.read().decode("utf-8"))
        modes=manifest.get("recovery_modes") or []
        if restore_mode not in modes:
            raise RuntimeError(f"recovery bundle does not support restore mode {restore_mode}")
        components=manifest.get("components") or {}
        required=[]
        if restore_mode in {"full","tactical"}: required.append("tactical")
        if restore_mode in {"full","tec_tac"}: required.append("tec_tac")
        extracted={}
        for key in required:
            meta=components.get(key) or {}
            if not meta.get("included"):
                raise RuntimeError(f"recovery bundle does not include required component: {key}")
            rel=str(meta.get("archive") or "")
            expected = "tec-tac/tec-tac-backup.tar.gz" if key=="tec_tac" else rel
            if key=="tactical" and not re.fullmatch(r"tactical/rmm-backup-[A-Za-z0-9_.-]+\.tar",rel):
                raise RuntimeError("recovery bundle Tactical component path is invalid")
            if key=="tec_tac" and rel != expected:
                raise RuntimeError("recovery bundle Tec-Tac component path is invalid")
            member=by_name.get(rel)
            if member is None or not member.isfile():
                raise RuntimeError(f"recovery bundle component is missing: {key}")
            manifest_hash=str(meta.get("sha256") or "").lower()
            checksum_hash=str(checksums.get(rel) or "").lower()
            if not manifest_hash or checksum_hash != manifest_hash:
                raise RuntimeError(f"recovery bundle checksum record mismatch: {key}")
            target=stage/("tactical-native.tar" if key=="tactical" else "tec-tac-backup.tar.gz")
            extract_verified_bundle_member(tf,member,target,manifest_hash,int(meta.get("size_bytes",-1)))
            extracted[key]=target
        # Every declared included component must have a checksum record even when
        # the selected emergency mode does not read/hash that component.
        for key,meta in components.items():
            if not isinstance(meta,dict) or not meta.get("included"): continue
            rel=str(meta.get("archive") or "")
            if not rel or str(checksums.get(rel) or "").lower()!=str(meta.get("sha256") or "").lower():
                raise RuntimeError(f"recovery bundle metadata/checksum declaration is incomplete: {key}")
    if validate_components and "tactical" in extracted: validate_tactical_native_archive(extracted["tactical"])
    if validate_components and "tec_tac" in extracted: validate_tec_tac_component(extracted["tec_tac"], (manifest.get("components") or {}).get("tec_tac") or {})
    return manifest,extracted


def safe_extract_payload_tar(path, root=Path("/")):
    with tarfile.open(path, "r:gz") as tf:
        members = safe_tar_members(tf)
        for member in members:
            target = (root / member.name).resolve()
            target.relative_to(root.resolve())
            name=member.name.lstrip("./")
            if name == "rmm" or name.startswith("rmm/"):
                raise RuntimeError("Tec-Tac payload may not overwrite Tactical tracked source")
        tf.extractall(root, members=members, numeric_owner=True)


def service_stop_for_restore(log):
    services = ["rmm", "celery", "celerybeat", "daphne", "nats-api", "nats", "meshcentral", "nginx"]
    for service in services:
        subprocess.run(["systemctl", "stop", service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log.write("[TEC-TAC-BACKUP] stopped Tactical services for destructive restore\n")


def verify_tactical_runtime(config, log):
    run_logged(["nginx","-t"],log,timeout=60)
    standard_ui=Path("/var/www/rmm/dist/index.html")
    if not standard_ui.is_file():
        raise RuntimeError(f"standard Tactical UI verification failed: {standard_ui} is missing")
    tactical_python=Path(config["TACTICAL_PYTHON"]); manage=Path(config["TACTICAL_BACKEND_ROOT"])/"manage.py"
    if tactical_python.is_file() and manage.is_file():
        run_logged([str(tactical_python),str(manage),"check"],log,cwd=str(manage.parent),timeout=300,user=config["TACTICAL_USER"])
    for service in ("rmm","celery","celerybeat","nginx"):
        if subprocess.run(["systemctl","is-active","--quiet",service]).returncode:
            raise RuntimeError(f"post-restore Tactical service verification failed: {service}")


def run_post_restore_tec_tac(config, component_meta, component_archive, log):
    safe_extract_payload_tar(component_archive)
    paths=(component_meta or {}).get("paths") or {}
    framework_source=Path(str(paths.get("framework_source") or config["TEC_TAC_FRAMEWORK_SOURCE"]))
    ui_source=Path(str(paths.get("ui_source") or config["TEC_TAC_UI_SOURCE"]))
    backend_installer=framework_source/"install.sh"
    if not backend_installer.is_file():
        raise RuntimeError(f"restored Tec-Tac framework installer not found at {backend_installer}")
    run_logged(["bash",str(backend_installer)],log,timeout=2*60*60)
    ui_installer=ui_source/"scripts"/"install.sh"
    if ui_installer.is_file(): run_logged(["bash",str(ui_installer)],log,timeout=2*60*60)
    run_logged(["nginx","-t"],log,timeout=60)
    subprocess.run(["systemctl","reload","nginx"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tactical_python=Path(config["TACTICAL_PYTHON"]); manage=Path(config["TACTICAL_BACKEND_ROOT"])/"manage.py"
    if tactical_python.is_file() and manage.is_file():
        run_logged([str(tactical_python),str(manage),"check"],log,cwd=str(manage.parent),timeout=300,user=config["TACTICAL_USER"])
        route_probe="from django.urls import reverse; p=reverse('tec-tac-ui-context'); assert p.startswith('/api/tfd/'), p; print(p)"
        run_logged([str(tactical_python),str(manage),"shell","-c",route_probe],log,cwd=str(manage.parent),timeout=300,user=config["TACTICAL_USER"])
    ui_root=Path(config.get("TEC_TAC_UI_DEPLOY_ROOT") or "/var/lib/tec-tac/ui/tec-tac")
    if not (ui_root/"index.html").is_file(): raise RuntimeError(f"post-restore Tec-Tac UI verification failed: {ui_root/'index.html'} is missing")
    verify_tactical_runtime(config,log)



VALIDATE_RESTORE_STATUSES = {"passed", "warning", "failed", "not_applicable", "not_run"}


def _vr_section():
    return {"status": "not_run", "checks": []}


def _vr_check(report, section, check_id, label, status, detail=""):
    if status not in VALIDATE_RESTORE_STATUSES:
        status = "failed"
    sec = report["sections"][section]
    sec["checks"].append({
        "id": check_id, "label": label, "status": status, "detail": str(detail or ""),
        "overrideable": bool(check_id in OVERRIDEABLE_RESTORE_CHECKS and section == "target"),
        "overridden": False,
    })
    ranks = {"failed": 5, "warning": 4, "passed": 3, "not_run": 2, "not_applicable": 1}
    current = sec.get("status", "not_run")
    if ranks[status] > ranks.get(current, 0):
        sec["status"] = status
    if status == "failed":
        report["errors"].append(str(detail or label))
    elif status == "warning":
        report["warnings"].append(str(detail or label))


def _vr_new(request, name):
    return {
        "ok": False,
        "artifact_valid": False,
        "target_ready": False,
        "restore_mode": str(request.get("restore_mode") or ""),
        "backup_ref": str(request.get("backup_ref") or ""),
        "archive_name": name,
        "format_version": None,
        "legacy": False,
        "validated_at": now(),
        "staged_bytes": 0,
        "compatibility_baseline": {"tactical_backup_script": "34", "tactical_restore_script": "67"},
        "sections": {key: _vr_section() for key in ("source", "bundle", "tactical", "tec_tac", "target")},
        "warnings": [],
        "errors": [],
    }


def _mutation_active(config):
    try:
        lock = acquire_lock(config)
    except RuntimeError:
        return True
    else:
        lock.close()
        return False


def _os_release():
    values = {}
    path = Path("/etc/os-release")
    if path.is_file():
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw:
                continue
            k, v = raw.split("=", 1)
            values[k] = v.strip().strip('"')
    return values


def validate_target_preflight(config, report, mode, staged_bytes, *, mutation_lock_held=False):
    target = report["sections"]["target"]
    target["status"] = "passed"
    if mutation_lock_held:
        _vr_check(report, "target", "target.mutation_lock", "Backup/restore mutation", "passed", "This restore job owns the Core mutation lock.")
    elif _mutation_active(config):
        _vr_check(report, "target", "target.mutation_lock", "Backup/restore mutation", "failed", "another Core server backup/restore mutation is active")
    else:
        _vr_check(report, "target", "target.mutation_lock", "Backup/restore mutation", "passed", "No destructive backup/restore mutation is active.")

    arch = platform.machine().lower()
    if mode in {"full", "tactical"}:
        _vr_check(report, "target", "target.arch", "CPU architecture", "passed" if arch in {"x86_64", "aarch64"} else "failed", arch)
        osr = _os_release(); os_id = str(osr.get("ID") or "").lower(); ver = str(osr.get("VERSION_ID") or "")
        supported = (os_id == "debian" and ver.split(".")[0] in {"11", "12"}) or (os_id == "ubuntu" and ver == "22.04")
        _vr_check(report, "target", "target.os", "Operating system", "passed" if supported else "failed", f"{os_id or 'unknown'} {ver or 'unknown'}")
        mem_kb = 0
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1]); break
        except Exception:
            pass
        _vr_check(report, "target", "target.memory", "System memory", "passed" if mem_kb >= 3627528 else "failed", f"{mem_kb} KiB detected; Tactical restore baseline requires at least 3627528 KiB")
    else:
        _vr_check(report, "target", "target.arch", "CPU architecture", "not_applicable", "Tactical restore.sh is not used for Tec-Tac-only recovery.")
        _vr_check(report, "target", "target.os", "Operating system", "not_applicable", "Tactical restore.sh is not used for Tec-Tac-only recovery.")
        _vr_check(report, "target", "target.memory", "System memory", "not_applicable", "Tactical restore.sh minimum is not applied to Tec-Tac-only recovery.")

    rs = roots(config)
    try:
        usage = shutil.disk_usage(rs["staging"])
        # Conservative read-only estimate: staged bundle + extracted selected
        # components + one additional copy/safety margin, plus 2 GiB.
        required = max(2 * 1024**3, int(staged_bytes) * 3)
        _vr_check(report, "target", "target.disk", "Staging free space", "passed" if usage.free >= required else "failed", f"free={usage.free} required_estimate={required}")
    except Exception as exc:
        _vr_check(report, "target", "target.disk", "Staging free space", "failed", str(exc))

    required_tools = ["tar", "gzip"]
    if mode in {"full", "tactical"}:
        required_tools += ["bash", "runuser", "systemctl", "curl", "wget", "git"]
    if mode in {"full", "tec_tac"}:
        required_tools += ["nginx"]
    missing = sorted(tool for tool in set(required_tools) if shutil.which(tool) is None)
    _vr_check(report, "target", "target.tools", "Required executables", "passed" if not missing else "failed", "all required executables found" if not missing else "missing: " + ", ".join(missing))

    if mode in {"full", "tactical"}:
        hosts = ["github.com", "deb.nodesource.com", "apt.postgresql.org"]
        failed = []
        for host in hosts:
            try:
                socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            except OSError:
                failed.append(host)
        _vr_check(report, "target", "target.dns", "Restore dependency DNS", "passed" if not failed else "failed", "DNS resolution available" if not failed else "unable to resolve: " + ", ".join(failed))
    else:
        _vr_check(report, "target", "target.dns", "Restore dependency DNS", "not_applicable", "Tactical package/bootstrap restore is not used.")

    if mode in {"full", "tactical"}:
        try:
            _, _, user, _ = tactical_identity(config)
            _vr_check(report, "target", "target.user", "Tactical restore user", "passed", user)
        except Exception as exc:
            _vr_check(report, "target", "target.user", "Tactical restore user", "failed", str(exc))
    else:
        tactical_root = Path(config["TACTICAL_ROOT"])
        healthy = (tactical_root / "api" / "tacticalrmm").exists()
        _vr_check(report, "target", "target.tactical_present", "Existing Tactical installation", "passed" if healthy else "failed", str(tactical_root))


def _find_vr_check(report, check_id):
    for section_name, section in (report.get("sections") or {}).items():
        for check in section.get("checks") or []:
            if check.get("id") == check_id:
                return section_name, check
    return None, None


def _recompute_vr_section(report, section_name):
    section = report["sections"][section_name]
    checks = section.get("checks") or []
    if not checks:
        section["status"] = "not_run"
        return
    effective = []
    for check in checks:
        status = check.get("status")
        if status == "failed" and check.get("overridden"):
            status = "warning"
        effective.append(status)
    if "failed" in effective:
        section["status"] = "failed"
    elif "warning" in effective:
        section["status"] = "warning"
    elif "passed" in effective:
        section["status"] = "passed"
    elif "not_run" in effective:
        section["status"] = "not_run"
    else:
        section["status"] = "not_applicable"


def _override_fingerprint(backup_ref, restore_mode, check_id, detail):
    payload = {
        "backup_ref": str(backup_ref or ""),
        "restore_mode": str(restore_mode or ""),
        "check_id": str(check_id or ""),
        "original_detail": str(detail or ""),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _persist_restore_override(config, job, report, check_id, check):
    requested_by = str((job.get("context") or {}).get("requested_by") or "").strip()
    if not requested_by:
        raise RuntimeError("restore override acceptance requires context.requested_by for audit")
    audit_id = str(uuid.uuid4())
    record = {
        "id": audit_id,
        "accepted_by": requested_by,
        "accepted_at": now(),
        "backup_ref": str(report.get("backup_ref") or ""),
        "restore_mode": str(report.get("restore_mode") or ""),
        "check_id": check_id,
        "original_status": "failed",
        "original_detail": str(check.get("detail") or ""),
        "fingerprint": _override_fingerprint(report.get("backup_ref"), report.get("restore_mode"), check_id, check.get("detail")),
        "validation_job_id": str(job.get("id") or ""),
        "source_module": (job.get("context") or {}).get("source_module"),
        "source_action": (job.get("context") or {}).get("source_action"),
        "source_run_id": (job.get("context") or {}).get("source_run_id"),
    }
    target = roots(config)["overrides"] / f"{audit_id}.json"
    atomic_json(target, record, mode=0o640)
    _, gid, _, _ = tactical_identity(config)
    os.chown(target, 0, gid)
    return record


def _accept_validation_overrides(config, job, report, requested):
    accepted = {}
    for check_id in requested:
        if check_id not in OVERRIDEABLE_RESTORE_CHECKS:
            raise RuntimeError(f"restore check is not overrideable: {check_id}")
        section_name, check = _find_vr_check(report, check_id)
        if section_name != "target" or check is None:
            raise RuntimeError(f"restore override check was not produced by validation: {check_id}")
        if check.get("status") != "failed":
            raise RuntimeError(f"restore override may only be accepted for a failed check: {check_id}")
        record = _persist_restore_override(config, job, report, check_id, check)
        check["overridden"] = True
        check["override_audit_id"] = record["id"]
        accepted[check_id] = record["id"]
        detail = str(check.get("detail") or "")
        try:
            report["errors"].remove(detail)
        except ValueError:
            pass
        report["warnings"].append(f"{check_id} failed but was explicitly overridden by {record['accepted_by']} (audit {record['id']})")
        _recompute_vr_section(report, section_name)
    report["accepted_overrides"] = accepted
    return accepted


def _authorize_restore_overrides(config, report, supplied):
    authorized = {}
    for check_id, audit_id in supplied.items():
        if check_id not in OVERRIDEABLE_RESTORE_CHECKS:
            raise RuntimeError(f"restore check is not overrideable: {check_id}")
        try:
            uuid.UUID(str(audit_id))
        except ValueError as exc:
            raise RuntimeError(f"invalid restore override audit id for {check_id}") from exc
        section_name, check = _find_vr_check(report, check_id)
        if section_name != "target" or check is None or check.get("status") != "failed":
            raise RuntimeError(f"restore override does not match a current failed check: {check_id}")
        path = roots(config)["overrides"] / f"{audit_id}.json"
        if not path.is_file():
            raise RuntimeError(f"restore override audit record was not found: {check_id}")
        record = json.loads(path.read_text(encoding="utf-8"))
        expected = _override_fingerprint(report.get("backup_ref"), report.get("restore_mode"), check_id, check.get("detail"))
        if record.get("fingerprint") != expected:
            raise RuntimeError(f"restore override is stale or belongs to a different backup/mode/check: {check_id}")
        if record.get("backup_ref") != report.get("backup_ref") or record.get("restore_mode") != report.get("restore_mode") or record.get("check_id") != check_id:
            raise RuntimeError(f"restore override audit binding mismatch: {check_id}")
        check["overridden"] = True
        check["override_audit_id"] = str(audit_id)
        authorized[check_id] = str(audit_id)
        detail = str(check.get("detail") or "")
        try:
            report["errors"].remove(detail)
        except ValueError:
            pass
        report["warnings"].append(f"{check_id} failed but authorized override audit {audit_id} is being honoured for restore execution")
        _recompute_vr_section(report, section_name)
    report["accepted_overrides"] = authorized
    return authorized


def _target_effectively_ready(report):
    for check in report["sections"]["target"].get("checks") or []:
        if check.get("status") == "failed" and not check.get("overridden"):
            return False
    return True


def operation_validate_restore(config, job, log):
    request = job["request"]
    dest_id, name = parse_backup_ref(request.get("backup_ref"))
    mode = str(request.get("restore_mode") or "").strip().lower()
    destination = request.get("destination")
    report = _vr_new(request, name)
    if destination is None:
        if dest_id not in {"local", "0", "native"}:
            _vr_check(report, "source", "source.destination", "Backup destination", "failed", "destination configuration is required for this backup_ref")
            return report
        destination = {"id": dest_id, "type": "local", "name": "Tactical local backups", "path": "/rmmbackups"}
    try:
        destination = validate_destination(destination, config)
        if destination["id"] != dest_id:
            raise RuntimeError("backup_ref destination id does not match supplied destination")
        _vr_check(report, "source", "source.destination", "Backup destination", "passed", f"{destination['type']}:{destination['id']}")
    except Exception as exc:
        _vr_check(report, "source", "source.destination", "Backup destination", "failed", str(exc))
        return report

    rs = roots(config)
    stage = rs["staging"] / f"validate-restore-{job['id']}"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    downloaded = stage / name
    try:
        try:
            metadata = download_destination(config, destination, name, downloaded, log)
            ensure_regular(downloaded, max_bytes=max_backup_bytes(config))
            report["staged_bytes"] = downloaded.stat().st_size
            _vr_check(report, "source", "source.object", "Recovery object", "passed", "Recovery object copied to protected validation staging.")
            if metadata:
                if not isinstance(metadata, dict):
                    raise RuntimeError("backup sidecar metadata is invalid")
                if metadata.get("size_bytes") is not None and int(metadata.get("size_bytes")) != downloaded.stat().st_size:
                    raise RuntimeError("recovery object size does not match sidecar metadata")
                if metadata.get("sha256") and str(metadata["sha256"]).lower() != sha256_file(downloaded).lower():
                    raise RuntimeError("recovery object SHA-256 does not match sidecar metadata")
                _vr_check(report, "source", "source.sidecar", "Sidecar metadata", "passed", "Sidecar structure/size/hash accepted.")
            else:
                _vr_check(report, "source", "source.sidecar", "Sidecar metadata", "warning", "No sidecar metadata was available; artifact integrity will be established from the recovery object itself.")
        except Exception as exc:
            _vr_check(report, "source", "source.object", "Recovery object", "failed", str(exc))
            return report

        if LEGACY_ARCHIVE_RE.fullmatch(name):
            report["format_version"] = 1; report["legacy"] = True
            if mode != "tactical":
                _vr_check(report, "bundle", "bundle.mode", "Recovery mode", "failed", "legacy Tactical archives support only tactical restore mode")
            else:
                _vr_check(report, "bundle", "bundle.legacy", "Legacy Tactical archive", "passed", "Native Tactical archive selected for Tactical-only validation.")
                try:
                    validate_tactical_native_archive(downloaded)
                    _vr_check(report, "tactical", "tactical.compatibility", "Tactical restore compatibility", "passed", "Validated against backup.sh v34 / restore.sh v67 compatibility baseline.")
                except Exception as exc:
                    _vr_check(report, "tactical", "tactical.compatibility", "Tactical restore compatibility", "failed", str(exc))
            _vr_check(report, "tec_tac", "tec_tac.component", "Tec-Tac component", "not_applicable", "Legacy native Tactical archive has no independent Tec-Tac component.")
        else:
            try:
                manifest, extracted = validate_recovery_bundle(downloaded, mode, stage, validate_components=False)
                report["format_version"] = int(manifest.get("format_version") or 0)
                report["legacy"] = False
                _vr_check(report, "bundle", "bundle.structure", "Recovery bundle structure", "passed", "Manifest, checksums and selected component hash/size are valid.")
            except Exception as exc:
                _vr_check(report, "bundle", "bundle.structure", "Recovery bundle structure", "failed", str(exc))
                manifest = {}; extracted = {}

            if "tactical" in extracted:
                try:
                    validate_tactical_native_archive(extracted["tactical"])
                    _vr_check(report, "tactical", "tactical.compatibility", "Tactical restore compatibility", "passed", "Native Tactical component is safe/readable and compatible with backup.sh v34 / restore.sh v67 requirements.")
                except Exception as exc:
                    _vr_check(report, "tactical", "tactical.compatibility", "Tactical restore compatibility", "failed", str(exc))
            else:
                _vr_check(report, "tactical", "tactical.component", "Tactical component", "not_applicable" if mode == "tec_tac" else "not_run", "Tactical component is not selected by this recovery mode.")

            if "tec_tac" in extracted:
                try:
                    validate_tec_tac_component(extracted["tec_tac"], (manifest.get("components") or {}).get("tec_tac") or {})
                    _vr_check(report, "tec_tac", "tec_tac.component", "Tec-Tac recovery component", "passed", "Tec-Tac component is safe/readable and contains required payload classes.")
                except Exception as exc:
                    _vr_check(report, "tec_tac", "tec_tac.component", "Tec-Tac recovery component", "failed", str(exc))
            else:
                _vr_check(report, "tec_tac", "tec_tac.component", "Tec-Tac component", "not_applicable" if mode == "tactical" else "not_run", "Tec-Tac component is not selected by this recovery mode.")

        artifact_sections = ["bundle"] + (["tactical"] if mode in {"full", "tactical"} else []) + (["tec_tac"] if mode in {"full", "tec_tac"} else [])
        report["artifact_valid"] = all(report["sections"][name]["status"] not in {"failed", "not_run"} for name in artifact_sections)
        validate_target_preflight(config, report, mode, report["staged_bytes"])
        requested_overrides = request.get("overrides") or []
        if requested_overrides:
            _accept_validation_overrides(config, job, report, requested_overrides)
        else:
            report["accepted_overrides"] = {}
        report["target_ready"] = _target_effectively_ready(report)
        report["ok"] = bool(report["artifact_valid"] and report["target_ready"])
        report["validated_at"] = now()
        log.write(f"[TEC-TAC-BACKUP] non-destructive restore validation completed mode={mode} artifact_valid={report['artifact_valid']} target_ready={report['target_ready']}\n")
        return report
    finally:
        try:
            shutil.rmtree(stage)
        except Exception as exc:
            # The operation never expands cleanup scope beyond its job-owned
            # validation staging directory.
            report["warnings"].append(f"validation staging cleanup failed: {exc}")


def _prepare_tactical_restore_script(source: Path, staged: Path, *, os_override_audit_id: str | None, log):
    """Prepare restore.sh before any destructive restore step.

    No override means an exact byte-for-byte copy. An authorized target.os
    override removes only the inspected Tactical v67 support rejection while
    retaining the real lsb_release-derived identity and codename variables.
    """
    ensure_regular(source)
    raw = source.read_bytes()
    if not os_override_audit_id:
        staged.write_bytes(raw)
        os.chmod(staged, 0o755)
        return {"adjusted": False, "baseline": None, "audit_id": None}

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Tactical restore.sh is not UTF-8; refusing target.os override patch") from exc

    match = re.search(r'^SCRIPT_VERSION=["\']?([0-9]+)["\']?\s*$', text, re.MULTILINE)
    version = match.group(1) if match else None
    if version != TACTICAL_RESTORE_OVERRIDE_BASELINE:
        raise RuntimeError(
            f"target.os override is bound to Tactical restore.sh v{TACTICAL_RESTORE_OVERRIDE_BASELINE}; "
            f"found {version or 'unknown'}"
        )
    if text.count(TACTICAL_RESTORE_OS_GATE) != 1:
        raise RuntimeError(
            "Tactical restore.sh v67 OS-support gate did not match the inspected baseline exactly; "
            "refusing to prepare an override-aware restore script"
        )

    replacement = (
        '# TEC-TAC: Tactical OS support rejection bypassed under an authorized target.os override.\n'
        'printf >&2 "${YELLOW}Tec-Tac: continuing under authorized target.os restore override.${NC}\\n"\n'
    )
    patched = text.replace(TACTICAL_RESTORE_OS_GATE, replacement, 1)
    if patched == text or 'osname=$(lsb_release -si)' not in patched or 'codename=$(lsb_release -sc)' not in patched:
        raise RuntimeError("Unable to prove safe target.os override patch while preserving real OS identity")
    staged.write_text(patched, encoding="utf-8")
    os.chmod(staged, 0o755)
    log.write(
        f"[TEC-TAC-BACKUP] staged Tactical restore.sh v{version} adjusted only for target.os "
        f"under authorized override audit {os_override_audit_id}\n"
    )
    return {"adjusted": True, "baseline": version, "audit_id": str(os_override_audit_id)}


def operation_restore_backup(config, job, log):
    request=job["request"]
    dest_id,name=parse_backup_ref(request.get("backup_ref"))
    destination=request.get("destination")
    mode=str(request.get("restore_mode") or "").strip().lower()
    if mode not in {"full","tactical","tec_tac"}: raise RuntimeError("restore_mode must be full, tactical, or tec_tac")
    if destination is None:
        if dest_id not in {"local","0","native"}: raise RuntimeError("destination configuration is required for this backup_ref")
        destination={"id":dest_id,"type":"local","name":"Tactical local backups","path":"/rmmbackups"}
    destination=validate_destination(destination,config)
    if destination["id"]!=dest_id: raise RuntimeError("backup_ref destination id does not match supplied destination")

    lock=acquire_lock(config)
    rs=roots(config); stage=rs["staging"]/f"restore-{job['id']}"
    shutil.rmtree(stage,ignore_errors=True); stage.mkdir(parents=True,exist_ok=True)
    downloaded=stage/name
    try:
        metadata=download_destination(config,destination,name,downloaded,log)
        ensure_regular(downloaded,max_bytes=max_backup_bytes(config))
        if metadata:
            if int(metadata.get("size_bytes",-1))!=downloaded.stat().st_size: raise RuntimeError("restore artifact size does not match backup metadata")
            if metadata.get("sha256") and str(metadata["sha256"]).lower()!=sha256_file(downloaded).lower(): raise RuntimeError("restore artifact SHA-256 does not match backup metadata")

        if LEGACY_ARCHIVE_RE.fullmatch(name):
            if mode!="tactical": raise RuntimeError("legacy Tactical archives support only tactical restore mode")
            validate_tactical_native_archive(downloaded)
            manifest={"format_version":1,"legacy":True,"components":{"tactical":{"included":True}},"recovery_modes":["tactical"]}
            extracted={"tactical":downloaded}
        else:
            manifest,extracted=validate_recovery_bundle(downloaded,mode,stage)

        # Destructive restore must enforce the same target-readiness policy as
        # non-destructive validation. A persisted override token can waive only
        # a specifically allow-listed target check; artifact validation above is
        # never overrideable.
        preflight = _vr_new(request, name)
        preflight["artifact_valid"] = True
        preflight["staged_bytes"] = downloaded.stat().st_size
        validate_target_preflight(config, preflight, mode, preflight["staged_bytes"], mutation_lock_held=True)
        supplied_overrides = request.get("overrides") or {}
        if supplied_overrides:
            _authorize_restore_overrides(config, preflight, supplied_overrides)
        else:
            preflight["accepted_overrides"] = {}
        preflight["target_ready"] = _target_effectively_ready(preflight)
        preflight["ok"] = bool(preflight["artifact_valid"] and preflight["target_ready"])
        if not preflight["target_ready"]:
            raise OperationFailed("Restore target preflight failed; resolve or explicitly override eligible checks before destructive restore.", result=preflight)
        job["restore_preflight"] = preflight
        atomic_json(job_path(job["id"],config),job)

        job["stage"]="restore-prepared"; atomic_json(job_path(job["id"],config),job)
        moved_root=None
        if mode in {"full","tactical"}:
            tactical_root=Path(config["TACTICAL_ROOT"])
            restore_script_source=tactical_root/"restore.sh"; ensure_regular(restore_script_source)
            restore_script=stage/"restore.sh"
            os_override_audit_id = (preflight.get("accepted_overrides") or {}).get("target.os")
            restore_script_preparation = _prepare_tactical_restore_script(
                restore_script_source, restore_script,
                os_override_audit_id=os_override_audit_id, log=log,
            )
            job["restore_script_preparation"] = restore_script_preparation
            atomic_json(job_path(job["id"],config),job)
            service_stop_for_restore(log)
            if (tactical_root/"api"/"tacticalrmm").exists():
                moved_root=Path(str(tactical_root)+f".tectac-pre-restore-{stamp()}")
                if moved_root.exists(): raise RuntimeError(f"pre-restore Tactical preservation path already exists: {moved_root}")
                os.replace(tactical_root,moved_root)
                job["result"]={"ok":False,"backup_ref":request.get("backup_ref"),"archive_name":name,"restore_mode":mode,"pre_restore_tactical_path":str(moved_root)}
                atomic_json(job_path(job["id"],config),job)
                log.write(f"[TEC-TAC-BACKUP] preserved existing Tactical tree at {moved_root}\n")
            _,_,user,home=tactical_identity(config)
            env=os.environ.copy(); env.update({"HOME":home,"USER":user,"LOGNAME":user,"GROUP":grp.getgrgid(tactical_identity(config)[1]).gr_name})
            run_logged([str(restore_script),str(extracted["tactical"])],log,env=env,cwd=home,timeout=10*60*60,user=user)
            if mode=="full":
                run_post_restore_tec_tac(config,(manifest.get("components") or {}).get("tec_tac") or {},extracted["tec_tac"],log)
            else:
                verify_tactical_runtime(config,log)
        else:
            # Tec-Tac-only recovery deliberately leaves Tactical and its database intact.
            run_post_restore_tec_tac(config,(manifest.get("components") or {}).get("tec_tac") or {},extracted["tec_tac"],log)

        return {
            "ok":True,"backup_ref":request.get("backup_ref"),"archive_name":name,"restore_mode":mode,
            "format_version":int(manifest.get("format_version") or 1),
            "pre_restore_tactical_path":str(moved_root) if moved_root else None,
            "accepted_overrides":dict((job.get("restore_preflight") or {}).get("accepted_overrides") or {}),
            "completed_at":now(),
        }
    finally:
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
    if destination["type"] == "ftp": return ftp_delete(config, destination, name, log)
    return delete_rclone(config, destination, name, log)


VALIDATION_CHECKS = ("configuration", "connection", "authentication", "path_access", "write", "read", "integrity", "delete")


def validation_result(destination):
    return {
        "ok": False,
        "destination_id": str(destination.get("id") or ""),
        "type": str(destination.get("type") or ""),
        "validated_at": now(),
        "checks": {name: "not_run" for name in VALIDATION_CHECKS},
    }


def _validation_fail(result, stage, reason):
    result["checks"][stage] = "failed"
    result["reason"] = str(reason)
    result["validated_at"] = now()
    raise OperationFailed(str(reason), result=result)


def _capture_command(args, *, timeout=120):
    try:
        proc = subprocess.run(
            [str(x) for x in args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, "", "timeout"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _connection_failure_stage(stderr):
    text = str(stderr or "").lower()
    auth_words = (
        "authentication", "login failed", "login incorrect", "invalid credentials",
        "unauthorized", "forbidden", "incorrect password", "invalid access key",
        "signaturedoesnotmatch", "invalidaccesskeyid", "530 login",
        "no supported authentication methods", "publickey", "password failed",
    )
    return "authentication" if any(word in text for word in auth_words) else "connection"


def _confirm_rclone_absent(base, object_name, cfg):
    code, out, _err = _capture_command([
        "rclone", "lsf", base, "--files-only", "--include", object_name, "--config", str(cfg)
    ], timeout=60)
    if code != 0:
        return False
    return not any(line.strip() == object_name for line in out.splitlines())


def validate_rclone_roundtrip(config, destination, payload, expected_hash, result, log, temp, object_name):
    try:
        cfg = make_rclone_config(config, destination, temp, log)
    except Exception as exc:
        _validation_fail(result, "configuration", str(exc))
    result["checks"]["configuration"] = "passed"
    base = remote_base(destination)
    remote = join_remote(base, object_name)
    created = False
    deleted = False
    original_failure = None
    try:
        # mkdir both proves the configured target namespace can be addressed and
        # mirrors the write semantics used by normal backup fan-out.
        code, _out, err = _capture_command(["rclone", "mkdir", base, "--config", str(cfg)], timeout=120)
        if code != 0:
            stage = _connection_failure_stage(err)
            result["checks"][stage] = "failed"
            if stage == "authentication":
                result["checks"]["connection"] = "passed"
                reason = "authentication failed"
            else:
                reason = "connection failed"
            result["reason"] = reason
            raise OperationFailed(reason, result=result)
        result["checks"]["connection"] = "passed"
        result["checks"]["authentication"] = "passed"

        code, _out, err = _capture_command(["rclone", "lsf", base, "--max-depth", "1", "--config", str(cfg)], timeout=120)
        if code != 0:
            result["checks"]["path_access"] = "failed"
            result["reason"] = "configured path is inaccessible"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["path_access"] = "passed"

        code, _out, err = _capture_command(["rclone", "copyto", str(payload), remote, "--config", str(cfg)], timeout=300)
        if code != 0:
            result["checks"]["write"] = "failed"
            result["reason"] = "write failed"
            raise OperationFailed(result["reason"], result=result)
        created = True
        result["checks"]["write"] = "passed"

        downloaded = temp / "validation-download.bin"
        code, _out, err = _capture_command(["rclone", "copyto", remote, str(downloaded), "--config", str(cfg)], timeout=300)
        if code != 0 or not downloaded.is_file():
            result["checks"]["read"] = "failed"
            result["reason"] = "read failed"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["read"] = "passed"
        if downloaded.stat().st_size != payload.stat().st_size or sha256_file(downloaded) != expected_hash:
            result["checks"]["integrity"] = "failed"
            result["reason"] = "round-trip integrity verification failed"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["integrity"] = "passed"

        code, _out, err = _capture_command(["rclone", "deletefile", remote, "--config", str(cfg)], timeout=120)
        if code != 0:
            result["checks"]["delete"] = "failed"
            result["reason"] = "delete failed"
            raise OperationFailed(result["reason"], result=result)
        if not _confirm_rclone_absent(base, object_name, cfg):
            result["checks"]["delete"] = "failed"
            result["reason"] = "delete could not be confirmed"
            raise OperationFailed(result["reason"], result=result)
        deleted = True
        result["checks"]["delete"] = "passed"
    except OperationFailed as exc:
        original_failure = exc
        raise
    finally:
        if created and not deleted:
            code, _out, _err = _capture_command(["rclone", "deletefile", remote, "--config", str(cfg)], timeout=120)
            if code == 0 and _confirm_rclone_absent(base, object_name, cfg):
                result["checks"]["delete"] = "passed"
            else:
                result["checks"]["delete"] = "failed"
                if original_failure is None:
                    result["reason"] = "validation object cleanup failed"


def validate_scp_roundtrip(config, destination, payload, expected_hash, result, log, temp, object_name):
    try:
        ssh_common, scp_common = scp_args(config, destination, temp, log)
    except Exception as exc:
        _validation_fail(result, "configuration", str(exc))
    result["checks"]["configuration"] = "passed"
    host = f"{destination['username']}@{destination['host']}"
    remote_dir = destination["remote_path"]
    remote_file = remote_dir.rstrip("/") + "/" + object_name
    created = False
    deleted = False
    original_failure = None
    try:
        code, _out, err = _capture_command(["ssh", *ssh_common, host, "true"], timeout=120)
        if code != 0:
            stage = _connection_failure_stage(err)
            result["checks"][stage] = "failed"
            if stage == "authentication":
                result["checks"]["connection"] = "passed"
                reason = "authentication failed"
            else:
                reason = "connection failed"
            result["reason"] = reason
            raise OperationFailed(reason, result=result)
        result["checks"]["connection"] = "passed"
        result["checks"]["authentication"] = "passed"

        code, _out, err = _capture_command(["ssh", *ssh_common, host, "mkdir", "-p", "--", remote_dir], timeout=120)
        if code != 0:
            result["checks"]["path_access"] = "failed"
            result["reason"] = "configured path is inaccessible"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["path_access"] = "passed"

        code, _out, err = _capture_command(["scp", *scp_common, str(payload), f"{host}:{remote_file}"], timeout=300)
        if code != 0:
            result["checks"]["write"] = "failed"
            result["reason"] = "write failed"
            raise OperationFailed(result["reason"], result=result)
        created = True
        result["checks"]["write"] = "passed"

        downloaded = temp / "validation-download.bin"
        code, _out, err = _capture_command(["scp", *scp_common, f"{host}:{remote_file}", str(downloaded)], timeout=300)
        if code != 0 or not downloaded.is_file():
            result["checks"]["read"] = "failed"
            result["reason"] = "read failed"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["read"] = "passed"
        if downloaded.stat().st_size != payload.stat().st_size or sha256_file(downloaded) != expected_hash:
            result["checks"]["integrity"] = "failed"
            result["reason"] = "round-trip integrity verification failed"
            raise OperationFailed(result["reason"], result=result)
        result["checks"]["integrity"] = "passed"

        code, _out, err = _capture_command(["ssh", *ssh_common, host, "rm", "-f", "--", remote_file], timeout=120)
        if code != 0:
            result["checks"]["delete"] = "failed"
            result["reason"] = "delete failed"
            raise OperationFailed(result["reason"], result=result)
        code, _out, err = _capture_command(["ssh", *ssh_common, host, "test", "!", "-e", remote_file], timeout=120)
        if code != 0:
            result["checks"]["delete"] = "failed"
            result["reason"] = "delete could not be confirmed"
            raise OperationFailed(result["reason"], result=result)
        deleted = True
        result["checks"]["delete"] = "passed"
    except OperationFailed as exc:
        original_failure = exc
        raise
    finally:
        if created and not deleted:
            code, _out, _err = _capture_command(["ssh", *ssh_common, host, "rm", "-f", "--", remote_file], timeout=120)
            if code == 0:
                result["checks"]["delete"] = "passed"
            else:
                result["checks"]["delete"] = "failed"
                if original_failure is None:
                    result["reason"] = "validation object cleanup failed"


def validate_ftp_roundtrip(config, destination, payload, expected_hash, result, object_name):
    ftp=None; created=False
    try:
        try:
            destination=validate_destination(destination,config)
            result["checks"]["configuration"]="passed"
        except Exception as exc:
            _validation_fail(result,"configuration",str(exc))
        try:
            ftp=ftp_connect(config,destination,timeout=60)
            result["checks"]["connection"]="passed"
            result["checks"]["authentication"]="passed"
        except ftplib.error_perm as exc:
            result["checks"]["connection"]="passed"
            _validation_fail(result,"authentication","authentication failed")
        except Exception as exc:
            _validation_fail(result,"connection","connection failed")
        try:
            ftp_prepare_path(ftp,destination["remote_path"],create=True)
            result["checks"]["path_access"]="passed"
        except Exception:
            _validation_fail(result,"path_access","configured path is inaccessible")
        try:
            with payload.open("rb") as fh:
                ftp.storbinary(f"STOR {object_name}",fh,blocksize=65536)
            created=True; result["checks"]["write"]="passed"
        except Exception:
            _validation_fail(result,"write","write failed")
        downloaded=bytearray()
        try:
            ftp.retrbinary(f"RETR {object_name}",downloaded.extend,blocksize=65536)
            result["checks"]["read"]="passed"
        except Exception:
            _validation_fail(result,"read","read failed")
        if len(downloaded)!=payload.stat().st_size or hashlib.sha256(downloaded).hexdigest()!=expected_hash:
            _validation_fail(result,"integrity","round-trip integrity verification failed")
        result["checks"]["integrity"]="passed"
        try:
            ftp.delete(object_name)
            names=[Path(x).name for x in ftp.nlst()]
            if object_name in names:
                raise RuntimeError("delete could not be confirmed")
            created=False; result["checks"]["delete"]="passed"
        except Exception:
            _validation_fail(result,"delete","delete failed")
    finally:
        if ftp is not None and created:
            try:
                ftp.delete(object_name)
                result["checks"]["delete"]="passed"
            except Exception:
                result["checks"]["delete"]="failed"
        if ftp is not None:
            try: ftp.quit()
            except Exception:
                try: ftp.close()
                except Exception: pass


def validate_local_roundtrip(config, destination, payload, expected_hash, result, object_name):
    try:
        destination = validate_destination(destination, config)
        result["checks"]["configuration"] = "passed"
        result["checks"]["connection"] = "not_applicable"
        result["checks"]["authentication"] = "not_applicable"
        root = Path(destination["path"])
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink():
            _validation_fail(result, "path_access", "local destination root may not be a symlink")
        result["checks"]["path_access"] = "passed"
        target = root / object_name
        created = False
        try:
            shutil.copy2(payload, target)
            created = True
            result["checks"]["write"] = "passed"
            with target.open("rb") as fh:
                while fh.read(1024 * 1024):
                    pass
            result["checks"]["read"] = "passed"
            if target.stat().st_size != payload.stat().st_size or sha256_file(target) != expected_hash:
                _validation_fail(result, "integrity", "round-trip integrity verification failed")
            result["checks"]["integrity"] = "passed"
            target.unlink()
            if target.exists():
                _validation_fail(result, "delete", "delete could not be confirmed")
            result["checks"]["delete"] = "passed"
        finally:
            if created and target.exists():
                try:
                    target.unlink()
                    if result["checks"]["delete"] == "not_run":
                        result["checks"]["delete"] = "passed"
                except OSError:
                    result["checks"]["delete"] = "failed"
    except OperationFailed:
        raise
    except Exception as exc:
        stage = next((name for name in VALIDATION_CHECKS if result["checks"][name] == "not_run"), "configuration")
        _validation_fail(result, stage, str(exc))


def operation_validate_destination(config, job, log):
    raw = job["request"].get("destination")
    result = validation_result(raw if isinstance(raw, dict) else {})
    try:
        destination = validate_destination(raw, config)
    except Exception as exc:
        _validation_fail(result, "configuration", str(exc))

    result["destination_id"] = destination["id"]
    result["type"] = destination["type"]
    object_name = f".tectac-validation-{job['id']}.bin"
    with tempfile.TemporaryDirectory(prefix="tectac-validate-") as td:
        temp = Path(td)
        payload = temp / "validation.bin"
        payload.write_bytes(secrets.token_bytes(64 * 1024))
        expected_hash = sha256_file(payload)
        try:
            if destination["type"] == "local":
                validate_local_roundtrip(config, destination, payload, expected_hash, result, object_name)
            elif destination["type"] == "scp":
                validate_scp_roundtrip(config, destination, payload, expected_hash, result, log, temp, object_name)
            elif destination["type"] == "ftp":
                validate_ftp_roundtrip(config, destination, payload, expected_hash, result, object_name)
            else:
                validate_rclone_roundtrip(config, destination, payload, expected_hash, result, log, temp, object_name)
        except OperationFailed as exc:
            result.update(exc.result or {})
            result["ok"] = False
            result["validated_at"] = now()
            raise OperationFailed(str(exc), result=result) from exc
    if result["checks"]["delete"] != "passed":
        result["ok"] = False
        result["reason"] = "validation object cleanup was not confirmed"
        raise OperationFailed(result["reason"], result=result)
    result["ok"] = True
    result["validated_at"] = now()
    result.pop("reason", None)
    log.write(f"[TEC-TAC-BACKUP] destination validation succeeded id={destination['id']} type={destination['type']}\n")
    return result


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
    "validate_destination": operation_validate_destination,
    "validate_restore": operation_validate_restore,
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
    job.update(status="running", stage="running", stage_label="Running", started_at=job.get("started_at") or now(), error=None, error_type=None)
    if job.get("action") == "create_backup": job["progress"]={"current":0,"total":CREATE_BACKUP_PROGRESS_TOTAL}
    atomic_json(path, job)
    try:
        log.write(f"[TEC-TAC-BACKUP] started {now()} action={job['action']} source={job.get('context', {}).get('source_module')}\n")
        result = OPERATIONS[job["action"]](config, job, log)
        job.update(status="succeeded", stage="complete", stage_label="Complete", finished_at=now(), result=result, error=None, error_type=None)
        if job.get("action") == "create_backup": job["progress"]={"current":CREATE_BACKUP_PROGRESS_TOTAL,"total":CREATE_BACKUP_PROGRESS_TOTAL}
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] completed {job['finished_at']}\n")
        if job["action"] == "restore_backup":
            stage = rs["staging"] / f"restore-{job_id}"
            shutil.rmtree(stage, ignore_errors=True)
    except OperationFailed as exc:
        job.update(status="failed", stage="failed", stage_label="Failed", finished_at=now(), result=exc.result, error=str(exc), error_type=exc.__class__.__name__)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] failed {job['finished_at']}: {exc}\n")
    except Exception as exc:
        job.update(status="failed", stage="failed", stage_label="Failed", finished_at=now(), error=str(exc), error_type=exc.__class__.__name__)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-BACKUP] failed {job['finished_at']}: {exc.__class__.__name__}: {exc}\n")
    finally:
        transient = rs["staging"] / f"secret-{job_id}.json"
        transient.unlink(missing_ok=True)
        log.close()



def _validate_tactical_workspace(config, job_id, workspace):
    rs = roots(config)
    expected_parent = (rs["staging"] / f"tactical-native-{job_id}").resolve()
    path = Path(workspace)
    if path.is_symlink() or not path.is_dir():
        raise SystemExit("invalid Tactical backup privileged workspace")
    resolved = path.resolve()
    if resolved.parent != expected_parent or not resolved.name.startswith("tacticalrmm-"):
        raise SystemExit("Tactical backup privileged workspace is outside the active job staging root")
    uid, _, _, _ = tactical_identity(config)
    if path.stat().st_uid != uid:
        raise SystemExit("Tactical backup privileged workspace is not owned by the Tactical service user")
    return path


def _open_workspace_dir(workspace: Path, relative):
    parts = [part for part in PurePosixPath(relative).parts if part not in {"", "."}]
    fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            if part in {".."}:
                raise SystemExit("unsafe Tactical backup workspace path")
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except Exception:
        try: os.close(fd)
        except Exception: pass
        raise


def _write_workspace_file(workspace: Path, relative_dir, filename, source: Path, owner_uid: int, owner_gid: int):
    dirfd = _open_workspace_dir(workspace, relative_dir)
    try:
        outfd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        try:
            with source.open("rb") as src, os.fdopen(outfd, "wb", closefd=False) as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
            # The privileged bridge runs as root, but Tactical backup.sh later
            # archives this workspace as the Tactical service account. Hand the
            # completed file to that exact account while keeping it private.
            os.fchown(outfd, owner_uid, owner_gid)
            os.fchmod(outfd, 0o600)
            st = os.fstat(outfd)
            if st.st_uid != owner_uid or st.st_gid != owner_gid:
                raise SystemExit("privileged Tactical backup output ownership verification failed")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise SystemExit("privileged Tactical backup output mode verification failed")
            if not (st.st_mode & stat.S_IRUSR):
                raise SystemExit("privileged Tactical backup output is not readable by the Tactical service user")
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SystemExit("privileged Tactical backup output is readable or writable by unintended accounts")
        finally:
            os.close(outfd)
    finally:
        os.close(dirfd)


def _resolve_fixed_nginx_site_source(source: Path, allowed_root: Path = Path("/etc/nginx/sites-available")):
    """Resolve one fixed nginx sites-enabled source without relaxing symlink policy elsewhere."""
    try:
        root = allowed_root.resolve(strict=True)
        target = source.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"required nginx backup source cannot be resolved safely: {source}") from exc
    if not root.is_dir() or root.is_symlink():
        raise SystemExit(f"allowed nginx configuration root is unavailable or unsafe: {root}")
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"nginx backup source resolves outside the allowed configuration root: {source} -> {target}") from exc
    ensure_regular(target)
    return target


def _archive_fixed_tree(source: Path):
    fd, tmp_name = tempfile.mkstemp(prefix="tectac-priv-", suffix=".tar.gz")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        subprocess.run(["/usr/bin/tar", "-czf", str(tmp), "-C", str(source), "."], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=1800)
        return tmp
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def tactical_privileged(job_id, operation, workspace):
    config = load_config()
    path, job = load_job(job_id, config)
    validate_job_file(path, config)
    if job.get("action") != "create_backup" or job.get("status") != "running":
        raise SystemExit("Tactical privileged collection is only available to an active create_backup job")
    ws = _validate_tactical_workspace(config, job_id, workspace)
    tactical_uid, tactical_gid, _, _ = tactical_identity(config)
    nginx = {
        "nginx-rmm": Path("/etc/nginx/sites-enabled/rmm.conf"),
        "nginx-frontend": Path("/etc/nginx/sites-enabled/frontend.conf"),
        "nginx-meshcentral": Path("/etc/nginx/sites-enabled/meshcentral.conf"),
    }
    if operation in nginx:
        set_job_stage(config, job_id, "tactical.collect.nginx", current=2, total=CREATE_BACKUP_PROGRESS_TOTAL)
        requested = nginx[operation]
        src = _resolve_fixed_nginx_site_source(requested)
        # Preserve Tactical's expected archive member name from sites-enabled,
        # even though the bytes are read from the validated sites-available target.
        _write_workspace_file(ws, "nginx", requested.name, src, tactical_uid, tactical_gid)
        return
    if operation == "systemd":
        set_job_stage(config, job_id, "tactical.collect.systemd", current=2, total=CREATE_BACKUP_PROGRESS_TOTAL)
        names = ["rmm.service", "celery.service", "celerybeat.service", "meshcentral.service", "nats.service", "nats-api.service"]
        daphne = Path("/etc/systemd/system/daphne.service")
        uvicorn = Path("/etc/systemd/system/uvicorn.service")
        names.append("daphne.service" if daphne.is_file() else "uvicorn.service")
        for name in names:
            src = Path("/etc/systemd/system") / name; ensure_regular(src)
            _write_workspace_file(ws, "systemd", name, src, tactical_uid, tactical_gid)
        return
    trees = {
        "confd": (Path("/etc/conf.d"), "confd", "etc-confd.tar.gz"),
        "letsencrypt": (Path("/etc/letsencrypt"), "certs", "etc-letsencrypt.tar.gz"),
        "opt-tactical": (Path("/opt/tactical"), "opt", "opt-tactical.tar.gz"),
    }
    if operation in trees:
        substage = {"confd":"tactical.collect.confd","letsencrypt":"tactical.collect.letsencrypt","opt-tactical":"tactical.collect.opt_tactical"}[operation]
        set_job_stage(config, job_id, substage, current=2, total=CREATE_BACKUP_PROGRESS_TOTAL)
        source, rel, filename = trees[operation]
        if not source.is_dir() or source.is_symlink():
            raise SystemExit(f"required privileged Tactical backup source is unavailable: {source}")
        tmp = _archive_fixed_tree(source)
        try:
            _write_workspace_file(ws, rel, filename, tmp, tactical_uid, tactical_gid)
        finally:
            tmp.unlink(missing_ok=True)
        return
    raise SystemExit("unsupported Tactical backup privileged operation")


def require_root_owned(path: Path):
    target = path.resolve()
    st = target.stat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise SystemExit(f"refusing unsafe privileged helper ownership/mode: {target}")

def main(argv):
    if os.geteuid() != 0:
        raise SystemExit("tec-tac-server-backup must run as root")
    require_root_owned(SELF)
    if len(argv) == 5 and argv[1] == "--tactical-privileged":
        job_id, operation, workspace = argv[2], argv[3], argv[4]
        if not JOB_RE.fullmatch(job_id):
            raise SystemExit("invalid job id")
        tactical_privileged(job_id, operation, workspace)
        return
    if len(argv) != 3 or argv[1] not in {"--dispatch", "--run"}:
        raise SystemExit("usage: tec-tac-server-backup --dispatch <uuid> | --run <uuid> | --tactical-privileged <uuid> <operation> <workspace>")
    job_id = argv[2]
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    if argv[1] == "--dispatch":
        dispatch(job_id)
    else:
        run_job(job_id)


if __name__ == "__main__":
    main(sys.argv)
