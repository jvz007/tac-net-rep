#!/usr/bin/python3
"""Root-owned Tec-Tac self-update worker.

Installed outside both replaceable repositories. Dispatch creates an independent
systemd transient service so framework updates may restart Tactical services
without terminating the update worker itself.
"""
from __future__ import annotations

import fcntl
import hashlib
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
import uuid
import zipfile
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

TREE_MANIFEST = "tec-tac-release.json"
TREE_SIGNATURE = "tec-tac-release.json.sig"
MAX_TREE_FILES = 20000
DEFAULT_SIGNED_RELEASE_MIN_VERSION = {"framework": "1.15.37", "ui": None}
TRUST_LEVEL_RANK = {"unsigned": 0, "signed_development": 1, "signed_production": 2, "secure_signed": 3}

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
STATE_ROOT = Path("/var/lib/tec-tac/system-updates")
JOBS_ROOT = STATE_ROOT / "jobs"
STAGED_ROOT = STATE_ROOT / "staged"
RUNNING_ROOT = STATE_ROOT / "running"
LOGS_ROOT = STATE_ROOT / "logs"
BACKUPS_ROOT = STATE_ROOT / "backups"
HISTORY_ROOT = STATE_ROOT / "history"
LOCK_PATH = STATE_ROOT / "update.lock"
LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")
_LIFECYCLE_LOCK_HANDLE = None
CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
SELF = Path("/usr/local/sbin/tec-tac-system-update")
PRIVILEGED_TRUST = Path("/usr/local/lib/tec-tac-security/privileged-trust.py")
RUNNING_REQUEST_ROOT = RUNNING_ROOT / "requests"
# 1.17.98: installers run only from root-only staging copies below INSTALL_STAGE_ROOT; installed provenance is kept per component.
INSTALL_STAGE_ROOT = STATE_ROOT / "install-stage"
PROVENANCE_ROOT = STATE_ROOT / "provenance"
STAGED_SOURCE_ENV = "TEC_TAC_STAGED_SOURCE_CHECKOUT"
ACCOUNT_SECURITY_POLICY = Path("/etc/tec-tac/policy/account-security-policy.json")
ACCOUNT_SECURITY_AUDIT = Path("/var/log/tec-tac/account-security-policy-audit.jsonl")



def _resolve_trusted_bash() -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for raw in ("/bin/bash", "/usr/bin/bash"):
        try:
            fd = os.open(raw, flags)
        except OSError:
            continue
        try:
            info = os.fstat(fd)
            if (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and not (info.st_mode & 0o022)
                and (info.st_mode & 0o111)
            ):
                return raw
        finally:
            os.close(fd)
    raise RuntimeError("trusted root-owned executable bash was not found in /bin/bash or /usr/bin/bash")

TRUSTED_BASH = _resolve_trusted_bash()

def now():
    return datetime.now(timezone.utc).isoformat()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_config():
    values = {}
    if CONFIG.is_symlink():
        raise RuntimeError("Tec-Tac config must be a regular non-symlink file")
    if CONFIG.exists():
        if not CONFIG.is_file():
            raise RuntimeError("Tec-Tac config must be a regular non-symlink file")
        info = CONFIG.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Tec-Tac config must be root-owned and not group/world writable")
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def privileged_env(extra=None):
    """Return a child environment with caller-controlled Tec-Tac overrides removed."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("TEC_TAC_")}
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return env


def atomic_json(path, payload, mode=0o640, *, uid=None, gid=None):
    """Atomically write JSON without following attacker-controlled temp paths.

    Ownership and mode are applied to the already-open temporary inode before
    publication, so callers never chmod/chown a name in a Tactical-writable
    directory after the atomic rename.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchmod(fd, mode)
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else int(uid), -1 if gid is None else int(gid))
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)


def _read_json_nofollow(path, *, max_bytes=1024 * 1024, label="job file"):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SystemExit(f"{label} is unsafe or unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(f"{label} is not a regular file")
        if info.st_size > max_bytes:
            raise SystemExit(f"{label} is unexpectedly large")
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SystemExit(f"{label} is unexpectedly large")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SystemExit(f"{label} is invalid") from exc
        if not isinstance(value, dict):
            raise SystemExit(f"{label} is invalid")
        return value
    finally:
        os.close(fd)


def job_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    try:
        job = _read_json_nofollow(path, label="system update job")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("job not found") from exc
        raise
    if job.get("id") != job_id or job.get("action") != "install":
        raise SystemExit("invalid system update job")
    if job.get("component") not in {"framework", "ui"}:
        raise SystemExit("invalid system update component")
    return path, job


def tactical_gid(config):
    return pwd.getpwnam(config.get("TACTICAL_USER", "tactical")).pw_gid


def acquire_lifecycle_lock():
    """Serialize system updates with all module lifecycle mutations."""
    global _LIFECYCLE_LOCK_HANDLE
    LIFECYCLE_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LIFECYCLE_LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("another Tec-Tac lifecycle operation is already running") from exc
    _LIFECYCLE_LOCK_HANDLE = handle


def running_request_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return RUNNING_REQUEST_ROOT / f"{job_id}.json"


def load_running_request(job_id):
    path = running_request_path(job_id)
    try:
        request = _read_json_nofollow(path, label="claimed update request")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("claimed update request not found") from exc
        raise
    if request.get("id") != job_id or request.get("action") != "install":
        raise SystemExit("claimed update request is invalid")
    if request.get("component") not in {"framework", "ui"}:
        raise SystemExit("claimed update component is invalid")
    return path, request


def _open_staged_root_fd():
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(STAGED_ROOT, flags)
    except OSError as exc:
        raise SystemExit("managed system-update staging root is unsafe or unreadable") from exc
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise SystemExit("managed system-update staging root is not a directory")
    return fd


def _read_staged_metadata(root_fd: int, upload_id: str):
    name = f"{upload_id}.json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(name, flags, dir_fd=root_fd)
    except OSError as exc:
        raise SystemExit("staged update metadata is unsafe or missing") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("staged update metadata is not a regular file")
        if info.st_size > 1024 * 1024:
            raise SystemExit("staged update metadata is unexpectedly large")
        chunks = []
        remaining = 1024 * 1024 + 1
        while remaining > 0:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        if remaining <= 0:
            raise SystemExit("staged update metadata is unexpectedly large")
        try:
            payload = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SystemExit("staged update metadata is invalid") from exc
        if not isinstance(payload, dict):
            raise SystemExit("staged update metadata is invalid")
        if payload.get("upload_id") not in (None, upload_id):
            raise SystemExit("staged update metadata upload id mismatch")
        return payload, info
    finally:
        os.close(fd)


def _select_staged_package(root_fd: int, upload_id: str):
    candidates = [f"{upload_id}.zip", f"{upload_id}.tgz", f"{upload_id}.tar.gz"]
    found = []
    for name in candidates:
        try:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SystemExit("unable to inspect staged system-update package") from exc
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("staged system-update package is not a regular file")
        found.append((name, info))
    if len(found) != 1:
        raise SystemExit("staged system-update package is missing or ambiguous")
    return found[0]


def _select_optional_staged_file(root_fd: int, name: str):
    try:
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit("unable to inspect staged signed release sidecar") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit("staged signed release sidecar is not a regular file")
    if info.st_size <= 0 or info.st_size > 1024 * 1024:
        raise SystemExit("staged signed release sidecar has an invalid size")
    return info


def _copy_staged_package(root_fd: int, source_name: str, expected_info, destination: Path) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        src_fd = os.open(source_name, flags, dir_fd=root_fd)
    except OSError as exc:
        raise SystemExit("staged system-update package is unsafe or unreadable") from exc
    try:
        src_info = os.fstat(src_fd)
        if not stat.S_ISREG(src_info.st_mode):
            raise SystemExit("staged system-update package is not a regular file")
        if (src_info.st_dev, src_info.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise SystemExit("staged system-update package changed during claim")
        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            dst_fd = os.open(destination, out_flags, 0o600)
        except OSError as exc:
            raise SystemExit("unable to create root-private system-update package") from exc
        try:
            os.fchmod(dst_fd, 0o600)
            os.fchown(dst_fd, 0, 0)
            while True:
                block = os.read(src_fd, 1024 * 1024)
                if not block:
                    break
                view = memoryview(block)
                while view:
                    written = os.write(dst_fd, view)
                    if written <= 0:
                        raise OSError("short write while claiming system-update package")
                    view = view[written:]
            os.fsync(dst_fd)
        finally:
            os.close(dst_fd)

        # Unlink only the exact directory entry opened above. If the Tactical
        # account raced the name after open, leave its replacement in staging
        # for unprivileged cleanup rather than deleting an unverified inode.
        try:
            current = os.stat(source_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and current.st_dev == src_info.st_dev and current.st_ino == src_info.st_ino:
            os.unlink(source_name, dir_fd=root_fd)
    finally:
        os.close(src_fd)
    return destination


def _unlink_staged_metadata_if_same(root_fd: int, upload_id: str, expected_info) -> None:
    name = f"{upload_id}.json"
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if current.st_dev == expected_info.st_dev and current.st_ino == expected_info.st_ino:
        os.unlink(name, dir_fd=root_fd)


SOURCE_TYPES = {"release", "branch", "offline"}
SOURCE_TEXT_MAX = 200


def sanitise_source(value):
    """Provenance of an install (1.17.2): where the staged package came from.

    It is recorded in the history row only. It is never an execution authority:
    the helper re-verifies trust as root. Anything unexpected is dropped.
    """
    if not isinstance(value, dict) or not isinstance(value.get("type"), str) or value["type"] not in SOURCE_TYPES:
        return {"type": "offline"}
    clean = {"type": value["type"]}
    for key in ("repository", "ref"):
        item = value.get(key)
        if isinstance(item, str) and 0 < len(item) <= SOURCE_TEXT_MAX and item.isprintable():
            clean[key] = item
    commit = value.get("commit")
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        clean["commit"] = commit.lower()
    return clean


def claim_job(job_id):
    status_path, request = load_job(job_id)
    if request.get("status") != "queued":
        raise SystemExit("job is not queued")
    cfg = load_config()
    gid = tactical_gid(cfg)
    for root, mode in ((RUNNING_ROOT, 0o2750), (RUNNING_REQUEST_ROOT, 0o2750), (LOGS_ROOT, 0o2750), (BACKUPS_ROOT, 0o2750), (HISTORY_ROOT, 0o2750)):
        root.mkdir(parents=True, exist_ok=True)
        os.chown(root, 0, gid if root != RUNNING_REQUEST_ROOT else 0)
        os.chmod(root, mode if root != RUNNING_REQUEST_ROOT else 0o700)

    upload_id = str(request.get("upload_id") or "")
    if not JOB_RE.fullmatch(upload_id):
        raise SystemExit("invalid staged upload id")

    root_fd = _open_staged_root_fd()
    try:
        meta, meta_info = _read_staged_metadata(root_fd, upload_id)
        preview = meta.get("preview") if isinstance(meta.get("preview"), dict) else {}
        if str(preview.get("component") or request.get("component")) != str(request.get("component")):
            raise SystemExit("staged component does not match request")

        source_name, source_info = _select_staged_package(root_fd, upload_id)
        suffix = ".tar.gz" if source_name.endswith(".tar.gz") else Path(source_name).suffix
        target = RUNNING_ROOT / f"{job_id}{suffix}"
        _copy_staged_package(root_fd, source_name, source_info, target)

        manifest_source = f"{upload_id}.release.json"
        signature_source = f"{upload_id}.release.json.sig"
        manifest_info = _select_optional_staged_file(root_fd, manifest_source)
        signature_info = _select_optional_staged_file(root_fd, signature_source)
        if (manifest_info is None) != (signature_info is None):
            target.unlink(missing_ok=True)
            raise SystemExit("detached signed update sidecars are incomplete")
        running_manifest = None
        running_signature = None
        if manifest_info is not None and signature_info is not None:
            running_manifest = RUNNING_ROOT / f"{job_id}.release.json"
            running_signature = RUNNING_ROOT / f"{job_id}.release.json.sig"
            _copy_staged_package(root_fd, manifest_source, manifest_info, running_manifest)
            _copy_staged_package(root_fd, signature_source, signature_info, running_signature)

        immutable = {
            "id": job_id,
            "action": "install",
            "component": str(request.get("component")),
            "upload_id": upload_id,
            "allow_downgrade": bool(request.get("allow_downgrade", False)),
            "package_path": str(target),
            "package_filename": str(meta.get("filename") or source_name),
            "release_manifest_path": str(running_manifest) if running_manifest is not None else None,
            "release_signature_path": str(running_signature) if running_signature is not None else None,
            "source": sanitise_source(request.get("source")),
        }
        req_path = running_request_path(job_id)
        atomic_json(req_path, immutable, mode=0o600, uid=0, gid=0)
        _unlink_staged_metadata_if_same(root_fd, upload_id, meta_info)
    finally:
        os.close(root_fd)

    request["status"] = "dispatched"
    request["stage"] = "dispatched"
    atomic_json(status_path, request, mode=0o640, uid=0, gid=gid)
    return status_path, immutable

def dispatch(job_id):
    claim_job(job_id)
    unit = f"tec-tac-system-update-{job_id}"
    command = [
        "systemd-run", "--quiet", "--collect", f"--unit={unit}",
        "--property=Type=exec", "--property=Nice=5",
        str(SELF), "--run", job_id,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=privileged_env())
    if result.returncode != 0:
        message = (result.stderr or "unable to create system update worker unit").strip()
        path, job = load_job(job_id)
        job["status"] = "failed"
        job["stage"] = "dispatch"
        job["finished_at"] = now()
        job["error"] = message
        job["error_type"] = "DispatchError"
        atomic_json(path, job)
        raise SystemExit(message)


def safe_name(name):
    value = PurePosixPath(name.replace("\\", "/"))
    if value.is_absolute() or ".." in value.parts:
        raise RuntimeError(f"unsafe archive path: {name!r}")
    return Path(*value.parts)


def extract_archive(archive, dest):
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                rel = safe_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"archive contains symlink: {info.filename}")
                target = (dest / rel).resolve()
                target.relative_to(dest.resolve())
            zf.extractall(dest)
        return
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                rel = safe_name(member.name)
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise RuntimeError(f"archive contains unsupported member: {member.name}")
                target = (dest / rel).resolve()
                target.relative_to(dest.resolve())
            tf.extractall(dest, filter="data")
        return
    raise RuntimeError("unsupported package archive")


def detect_root(extracted, component):
    matches = []
    for root, dirs, _files in os.walk(extracted):
        path = Path(root)
        depth = len(path.relative_to(extracted).parts)
        if depth > 3:
            dirs[:] = []
            continue
        if component == "framework":
            ok = (path / "VERSION").is_file() and (path / "install.sh").is_file() and (path / "framwork" / "tec_tac").is_dir()
        else:
            ok = (path / "VERSION").is_file() and (path / "package.json").is_file() and (path / "src" / "App.vue").is_file() and (path / "scripts" / "install.sh").is_file()
        if ok:
            matches.append(path)
            dirs[:] = []
    if len(matches) != 1:
        raise RuntimeError(f"expected one {component} repository root, found {len(matches)}")
    return matches[0]


def _configured_source_paths():
    """The source checkouts named in the root-owned config (not resolved). Git runs only in these."""
    cfg = load_config()
    return {source_checkout_path("framework", cfg), source_checkout_path("ui", cfg)}


def source_checkout_path(component, cfg=None):
    """The configured source checkout of a component, exactly as the root-owned config names it (1.17.98: never resolved).

    Resolving would follow a link the Tactical account could place in the path. open_source_checkout checks every folder
    above it and opens it without following a link before root changes an owner, reads a file or runs Git in it.
    """
    cfg = load_config() if cfg is None else cfg
    if component == "framework":
        raw = cfg.get("TEC_TAC_FRAMEWORK_SOURCE", "/opt/tec-tac-src/framework")
    else:
        raw = cfg.get("TEC_TAC_UI_SOURCE", "/opt/tec-tac-src/ui")
    path = Path(os.path.normpath(str(raw)))
    if not path.is_absolute() or len(path.parts) < 3:
        raise RuntimeError(f"configured {component} source checkout must be an absolute path below a folder: {raw!r}")
    return path


def open_source_checkout(target, component="source"):
    """Open a source checkout for root without following a link anywhere in its path (1.17.98, review round 6).

    Every folder from / down to the checkout's parent is opened with O_NOFOLLOW|O_DIRECTORY from the folder above it and must
    be root-owned and not group/world writable, so the Tactical account cannot swap a folder above the checkout for a link. The
    checkout itself is opened with O_NOFOLLOW|O_DIRECTORY from that root-owned parent descriptor. Returns the descriptor; the
    caller closes it.
    """
    path = Path(os.path.normpath(str(target)))
    if not path.is_absolute() or len(path.parts) < 2:
        raise RuntimeError(f"{component} source checkout must be an absolute path: {target}")
    fd = os.open("/", _NOFOLLOW_DIR)
    try:
        current = Path("/")
        for part in path.parts[1:]:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError(f"{component} source checkout {path}: the folder {current} is not root-owned or is group/world writable, "
                                   "so root will not work in the checkout below it. Fix the folder's owner and mode first.")
            try:
                child = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            except OSError as exc:
                where = current / part
                raise RuntimeError(f"{component} source checkout {path}: {where} is a symbolic link or not a folder ({exc.strerror or exc}); "
                                   "root will not follow it") from exc
            os.close(fd)
            fd = child
            current = current / part
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _check_source_location(target, component="source"):
    os.close(open_source_checkout(target, component))


# 1.17.98: the source checkouts belong to the Tactical account and stay that way (spec "System Update Checkout and Ownership
# Fix", Johan and Sol, 2 November 2026). Every Git call runs AS that account, never as root, so nothing a Tactical-writable
# .git/config, hook or attribute names can run with root's rights, and Git's own ownership guard stays on. Root never runs
# anything from a checkout: an installer runs only from a root-owned staging copy that was checked against the signed
# release manifest (stage_release_tree, verify_staged_tree, run_install).
_GIT_HARDENING = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
                  "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
GIT_LOCAL_TIMEOUT_SECONDS = 300
GIT_NETWORK_TIMEOUT_SECONDS = 600


def _git_runas(cfg):
    """(uid, gid, home) of the Tactical account when the helper runs as root; None otherwise (tests only, never a server)."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    name, uid, gid = _tactical_account(cfg)
    try:
        home = pwd.getpwnam(name).pw_dir or "/nonexistent"
    except KeyError:
        home = "/nonexistent"
    return uid, gid, home


def _git_environment(home=None):
    """A fixed environment for Git. HOME is the Tactical account's own, so its own credential settings serve a fetch (1.17.98)."""
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "HOME": str(home or "/nonexistent"), "GIT_TERMINAL_PROMPT": "0", "GIT_LITERAL_PATHSPECS": "1",
    }


def _git(command, target, *, check=True, capture=True, timeout=GIT_LOCAL_TIMEOUT_SECONDS, cfg=None):
    resolved = Path(os.path.normpath(str(target)))
    cfg = load_config() if cfg is None else cfg
    runas = _git_runas(cfg)
    if runas is not None:
        if resolved not in _configured_source_paths():
            raise RuntimeError(f"refusing to run Git outside the configured source checkouts: {resolved}")
        _check_source_location(resolved)  # 1.17.98: no link and only root-owned, non-writable folders above it
    args = ["/usr/bin/git", *_GIT_HARDENING, "-C", str(resolved), *command]
    extra = {"user": runas[0], "group": runas[1], "extra_groups": []} if runas else {}
    home = runas[2] if runas else os.environ.get("HOME")
    try:
        result = subprocess.run(
            args,
            cwd=str(resolved),
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
            env=_git_environment(home),
            timeout=timeout,
            **extra,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git {command[0]} timed out after {timeout} seconds in {resolved}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "git command failed").strip()
        raise RuntimeError(f"git {' '.join(command)} failed: {detail}")
    return result


def _version_key(value):
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", str(value or "").strip(), re.I)
    if not match:
        return (0, 0, 0, 0, str(value or "").lower())
    nums = tuple(int(x or 0) for x in match.groups()[:3])
    suffix = (match.group(4) or "").strip()
    rebuild = re.fullmatch(r"-(\d+)", suffix)
    if rebuild:
        return (*nums, 2, int(rebuild.group(1)))
    return (*nums, 1 if not suffix else 0, suffix.lower())


def _signed_release_min_version(component):
    cfg = load_config()
    key = f"TEC_TAC_{component.upper()}_SIGNED_RELEASE_MIN_VERSION"
    value = str(cfg.get(key) or DEFAULT_SIGNED_RELEASE_MIN_VERSION.get(component) or "").strip()
    return value or None


def _safe_tree_rel(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value or value.startswith("/"):
        raise RuntimeError(f"unsafe signed release path: {value!r}")
    pure = PurePosixPath(value)
    parts = pure.parts
    if not parts or any(part in {"", ".", "..", ".git"} for part in parts):
        raise RuntimeError(f"unsafe signed release path: {value!r}")
    normalized = "/".join(parts)
    if normalized != value:
        raise RuntimeError(f"non-canonical signed release path: {value!r}")
    if len(parts) == 1 and normalized in {TREE_MANIFEST, TREE_SIGNATURE}:
        raise RuntimeError(f"signing output cannot be listed in signed tree: {value}")
    return normalized


def _digest_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"signed release entry must be a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    if size != info.st_size:
        raise RuntimeError(f"signed release file changed while hashing: {path}")
    return size, digest.hexdigest()


def _tree_inventory(root):
    root = Path(root).resolve()
    found = {}
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        for entry in directory.iterdir():
            name = entry.name
            if not prefix and (name == ".git" or name in {TREE_MANIFEST, TREE_SIGNATURE}):
                continue
            rel = _safe_tree_rel(f"{prefix}/{name}" if prefix else name)
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append((entry, rel))
            elif stat.S_ISREG(info.st_mode):
                found[rel] = _digest_file(entry)
                if len(found) > MAX_TREE_FILES:
                    raise RuntimeError("signed release contains too many files")
            else:
                raise RuntimeError(f"signed release contains a link or special file: {rel}")
    return dict(sorted(found.items()))


def verify_signed_tree_snapshot(root, component, expected_version, trust):
    """Reconfirm the exact signed manifest/signature and complete tree before install."""
    if not isinstance(trust, dict) or not trust.get("verified") or not trust.get("signed"):
        raise RuntimeError("signed release verification context is missing")
    manifest_path = Path(root) / TREE_MANIFEST
    signature_path = Path(root) / TREE_SIGNATURE
    for path, label in ((manifest_path, "manifest"), (signature_path, "signature")):
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"signed release {label} is missing from execution tree") from exc
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"signed release {label} is not a regular file")
    manifest_bytes = manifest_path.read_bytes()
    signature_bytes = signature_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != str(trust.get("manifest_sha256") or ""):
        raise RuntimeError("execution checkout signed manifest differs from inspected manifest")
    if hashlib.sha256(signature_bytes).hexdigest() != str(trust.get("signature_sha256") or ""):
        raise RuntimeError("execution checkout signed signature differs from inspected signature")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("execution checkout signed manifest is invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 2:
        raise RuntimeError("execution checkout signed manifest schema mismatch")
    expected = {
        "component": component,
        "version": str(expected_version),
        "publisher_id": str(trust.get("publisher_id") or ""),
        "key_id": str(trust.get("key_id") or ""),
        "algorithm": "Ed25519",
    }
    for field, value in expected.items():
        if str(manifest.get(field) or "") != value:
            raise RuntimeError(f"execution checkout signed manifest {field} mismatch")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_TREE_FILES:
        raise RuntimeError("execution checkout signed file list is invalid")
    declared = {}
    previous = None
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise RuntimeError("execution checkout signed file entry is invalid")
        rel = _safe_tree_rel(entry.get("path"))
        if previous is not None and rel < previous:
            raise RuntimeError("execution checkout signed file list is not sorted")
        previous = rel
        if rel in declared:
            raise RuntimeError(f"duplicate execution checkout signed path: {rel}")
        size = entry.get("size")
        digest = str(entry.get("sha256") or "").strip().lower()
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(f"invalid execution checkout signed metadata for {rel}")
        declared[rel] = (size, digest)
    actual = _tree_inventory(root)
    if declared != actual:
        missing = len(set(declared) - set(actual))
        extra = len(set(actual) - set(declared))
        changed = sum(1 for key in set(declared) & set(actual) if declared[key] != actual[key])
        raise RuntimeError(f"execution checkout differs from verified signed tree (missing={missing}, extra={extra}, changed={changed})")
    if len(actual) != int(trust.get("file_count") or 0):
        raise RuntimeError("execution checkout signed file count differs from inspected release")
    return len(actual)


def _privileged_trust_command(config, *args, input_text=None):
    if not PRIVILEGED_TRUST.is_file():
        raise RuntimeError(f"privileged trust verifier is missing: {PRIVILEGED_TRUST}")
    info = PRIVILEGED_TRUST.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("privileged trust verifier is not root-owned or is writable")
    result = subprocess.run([sys.executable, str(PRIVILEGED_TRUST), *map(str, args)], input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, env=privileged_env())
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "root trust verification failed").strip())
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("root trust verifier returned invalid output") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("root trust verifier returned invalid data")
    return payload


def _root_verify_tree(config, root, component):
    return _privileged_trust_command(config, "verify-tree", str(root), str(component))


def set_root_trust_policy(level, actor=""):
    cfg = load_config()
    current = _privileged_trust_command(cfg, "get-policy")
    requested = str(level or "").strip().lower()
    if requested not in TRUST_LEVEL_RANK:
        raise RuntimeError("invalid trust policy level")
    existing = str(current.get("minimum_level") or "")
    if existing not in TRUST_LEVEL_RANK:
        raise RuntimeError("current root trust policy is invalid")
    if TRUST_LEVEL_RANK[requested] < TRUST_LEVEL_RANK[existing]:
        raise RuntimeError("lowering the root trust policy requires the root console command tec-tac-trust-policy")
    args = ["set-policy", requested]
    if actor:
        args += ["--updated-by", str(actor)]
    args += ["--updated-at", now()]
    return _privileged_trust_command(cfg, *args)


def _account_security_current_state():
    if not ACCOUNT_SECURITY_POLICY.exists():
        return {"state": "missing", "protect_superuser_accounts": False}
    try:
        payload = _read_json_nofollow(ACCOUNT_SECURITY_POLICY, max_bytes=64 * 1024, label="account security policy")
    except SystemExit:
        return {"state": "unreadable", "protect_superuser_accounts": None}
    value = payload.get("protect_superuser_accounts")
    if isinstance(value, bool):
        return {"state": "readable", "protect_superuser_accounts": value}
    return {"state": "unreadable", "protect_superuser_accounts": None}


def _append_root_account_security_audit(payload):
    audit_root = ACCOUNT_SECURITY_AUDIT.parent
    audit_root.mkdir(parents=True, exist_ok=True)
    os.chown(audit_root, 0, 0)
    os.chmod(audit_root, 0o755)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(ACCOUNT_SECURITY_AUDIT, flags, 0o600)
    except OSError as exc:
        raise RuntimeError("root account security audit is unavailable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o077):
            raise RuntimeError("root account security audit has unsafe ownership or mode")
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        fcntl.flock(fd, fcntl.LOCK_EX)
        line = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(fd, line)
        os.fsync(fd)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def set_root_account_security_policy(value, actor=""):
    requested = str(value or "").strip().lower()
    if requested not in {"true", "false"}:
        raise RuntimeError("account security policy value must be true or false")
    POLICY_ROOT = ACCOUNT_SECURITY_POLICY.parent
    POLICY_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(POLICY_ROOT, 0, 0)
    os.chmod(POLICY_ROOT, 0o755)
    previous = _account_security_current_state()
    payload = {
        "schema": 1,
        "protect_superuser_accounts": requested == "true",
        "updated_at": now(),
        "updated_by": str(actor or "")[:150] or None,
    }
    # L85: a direct sudo invocation must never create an invisible policy
    # mutation. The root-owned audit intent is durable before the policy write,
    # and records the actual sudo invoker independently of the caller-supplied
    # application actor label.
    _append_root_account_security_audit({
        "schema": 1,
        "event": "account_security_policy_change_requested",
        "timestamp": payload["updated_at"],
        "sudo_user": str(os.environ.get("SUDO_USER") or "root")[:150],
        "sudo_uid": str(os.environ.get("SUDO_UID") or os.getuid())[:32],
        "actor_label": payload["updated_by"],
        "before": previous,
        "requested": {"protect_superuser_accounts": payload["protect_superuser_accounts"]},
    })
    atomic_json(ACCOUNT_SECURITY_POLICY, payload, mode=0o644, uid=0, gid=0)
    return payload


def _tactical_account(config):
    name = config.get("TACTICAL_USER", "tactical")
    try:
        entry = pwd.getpwnam(name)
    except KeyError as exc:
        raise RuntimeError(f"the Tactical service account {name} does not exist") from exc
    return name, entry.pw_uid, entry.pw_gid


def _owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def _group_name(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)


def normalise_source_owner(target, component, config=None, *, require_git=True):
    """Make the whole checkout, .git included, belong to the Tactical account (1.17.98, spec: "Ownership must be explicit").

    The source checkout is a Tactical-owned working copy: root runs nothing from it, so giving it to that account widens nothing.
    A checkout an older update left mixed (a root-owned worktree with a Tactical-owned .git, "dubious ownership") is repaired
    here. A path owned by any third account is refused, as before, with the command that fixes it. Every name is changed through
    the directory descriptor that listed it and no link is followed. A root-owned file with a second hard link is refused, so a
    link planted to a root file elsewhere can never be handed over. Returns the number of paths changed.
    """
    config = load_config() if config is None else config
    tactical, uid, gid = _tactical_account(config)
    root = Path(os.path.normpath(str(target)))
    if not os.path.lexists(root):
        raise RuntimeError(f"{component} source checkout is missing: {root}")
    # 1.17.98 (review round 6): the walk starts from a descriptor opened without following a link, below root-owned folders only.
    root_fd = open_source_checkout(root, component)
    try:
        try:
            git_info = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            git_info = None
            if require_git:
                raise RuntimeError(f"{component} source checkout is missing: {root / '.git'}") from None
        if git_info is not None and not stat.S_ISDIR(git_info.st_mode):
            raise RuntimeError(f"{component} source checkout path must be a real directory, not a link or file: {root / '.git'}")
        return _normalise_owner_from_fd(root_fd, root, component, tactical, uid, gid)
    finally:
        os.close(root_fd)


def _normalise_owner_from_fd(root_fd, root, component, tactical, uid, gid):
    allowed = {0, uid}
    fix = f"chown -R {tactical}:{_group_name(gid)} {root}"
    changed = 0
    top = True
    for current, dirs, files, dirfd in os.fwalk(".", dir_fd=root_fd, follow_symlinks=False):
        current = os.path.normpath(os.path.join(str(root), current))
        if top:
            info = os.fstat(dirfd)
            if info.st_uid not in allowed:
                raise RuntimeError(f"{component} source checkout {root} is owned by {_owner_name(info.st_uid)}, but it must be owned by {tactical}. Fix it with: {fix}")
            if (info.st_uid, info.st_gid) != (uid, gid):
                os.fchown(dirfd, uid, gid)
                changed += 1
            top = False
        for name in dirs + files:
            listed = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if listed.st_uid not in allowed:
                raise RuntimeError(f"{component} source checkout {os.path.join(current, name)} is owned by {_owner_name(listed.st_uid)}, but it must be owned by {tactical}. Fix it with: {fix}")
            if (listed.st_uid, listed.st_gid) == (uid, gid):
                continue
            if stat.S_ISDIR(listed.st_mode):
                flags = _NOFOLLOW_DIR
            elif stat.S_ISREG(listed.st_mode):
                flags = _NOFOLLOW_READ
            else:
                continue  # a link, socket or pipe is never followed or opened; its own owner does not let anyone write the tree
            # The owner is changed through a descriptor of the inode that was checked, so a name swapped after the check
            # (for example for a hard link to a root file) is never what is changed.
            try:
                fd = os.open(name, flags, dir_fd=dirfd)
            except OSError as exc:
                raise RuntimeError(f"{component} source checkout {os.path.join(current, name)} changed while its owner was set: {exc.strerror or exc}") from exc
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) != (listed.st_dev, listed.st_ino) or info.st_uid not in allowed:
                    raise RuntimeError(f"{component} source checkout {os.path.join(current, name)} changed while its owner was set")
                if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink > 1:
                    raise RuntimeError(f"{component} source checkout {os.path.join(current, name)} is a root-owned file with more than one hard link, so it is not handed to {tactical}. Remove it, then update again.")
                os.fchown(fd, uid, gid)
            finally:
                os.close(fd)
            changed += 1
    return changed


def _printable(text, limit=300):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(text or "")).strip()[:limit]


def _listing(lines, limit=20):
    shown = [_printable(line) for line in lines[:limit]]
    if len(lines) > limit:
        shown.append(f"... and {len(lines) - limit} more")
    return shown


def _known_generated(component, rel):
    """An untracked file System Update may delete: Python bytecode, and an untracked UI package-lock.json left by UI 0.10.4 and earlier."""
    parts = PurePosixPath(rel).parts
    if "__pycache__" in parts or rel.endswith((".pyc", ".pyo")):
        return True
    return component == "ui" and rel == "package-lock.json"


def prepare_source_checkout(target, component, cfg=None, log=None):
    """Spec steps 3 and 4: ownership, then a clean checkout at its own HEAD, all Git as the Tactical account (1.17.98).

    A managed checkout is disposable (spec "Source checkout should be disposable"): tracked changes are written to the update
    log and restored to HEAD. Untracked files are removed only when they are known generated files (_known_generated); any
    other untracked file stops the update before anything is installed, with the list, because it may be an administrator's.
    Ignored files (node_modules, dist) stay: Git status does not show them and nothing runs from the checkout.
    """
    cfg = load_config() if cfg is None else cfg
    target = Path(target)
    if not (target / ".git").is_dir():
        raise RuntimeError(f"{component} source is not a Git checkout: {target}")
    changed = normalise_source_owner(target, component, cfg)
    if changed and log is not None:
        log.write(f"[TEC-TAC-UPDATE] gave {changed} {component} source checkout paths to the Tactical account (one owner for the whole checkout)\n")
    head = _git(["rev-parse", "--verify", "HEAD"], target, cfg=cfg).stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise RuntimeError(f"{component} source checkout HEAD is not a commit: {_printable(head, 80)}")
    branch_result = _git(["symbolic-ref", "--quiet", "--short", "HEAD"], target, check=False, cfg=cfg)
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None

    tracked = [line for line in _git(["status", "--porcelain", "--untracked-files=no"], target, cfg=cfg).stdout.splitlines() if line.strip()]
    restored = []
    if tracked:
        restored = _listing(tracked, 200)
        if log is not None:
            log.write(f"[TEC-TAC-UPDATE] {component} source checkout had {len(tracked)} tracked change(s); restoring them to HEAD {head[:12]}:\n")
            for line in _listing(tracked):
                log.write(f"[TEC-TAC-UPDATE]   {line}\n")
            log.flush()
        _git(["reset", "--quiet", "--hard", "HEAD"], target, cfg=cfg)

    others = _git(["ls-files", "--others", "--exclude-standard", "-z"], target, cfg=cfg).stdout
    untracked = [name for name in others.split("\0") if name]
    generated = [name for name in untracked if _known_generated(component, name)]
    unknown = [name for name in untracked if not _known_generated(component, name)]
    if unknown:
        listing = "\n".join(_listing(unknown))
        raise RuntimeError(f"{component} source checkout {target} has untracked files that System Update will not delete:\n{listing}\n"
                           "Move or remove them, then update again. Nothing was installed.")
    for start in range(0, len(generated), 200):
        _git(["clean", "-f", "-q", "--", *generated[start:start + 200]], target, cfg=cfg)
    status = _git(["status", "--porcelain", "--untracked-files=all"], target, cfg=cfg).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is not clean after it was restored to HEAD: {_printable(status.splitlines()[0])}")
    return {"head": head, "branch": branch, "restored_changes": restored, "removed_generated": _listing(generated, 200),
            "owner_changed": changed, "moved": False}


_SAFE_REF = re.compile(r"^(?![-./])(?!.*\.\.)(?!.*//)(?!.*@\{)(?!.*\.lock$)[A-Za-z0-9._/-]{1,200}(?<![./])$")


def _source_commit(source):
    """The exact commit of a branch or release candidate (40 hex, recorded when the job was claimed), else None (offline)."""
    if not isinstance(source, dict) or source.get("type") not in {"branch", "release"}:
        return None
    commit = str(source.get("commit") or "").lower()
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None


def move_source_to_commit(target, component, source, cfg=None, log=None):
    """Spec step 5: put the checkout on exactly the selected commit, as the Tactical account (1.17.98).

    The commit is the one the candidate was staged from, pinned when the job was claimed. Nothing looks a branch up again: a
    fetch only brings the objects in, and HEAD is then set to that SHA and checked. A branch source moves the local branch of
    that name (git checkout -B <ref> <sha>); a release source leaves a detached HEAD at the tag's commit.
    """
    cfg = load_config() if cfg is None else cfg
    commit = _source_commit(source)
    if commit is None:
        raise RuntimeError(f"{component} update has no exact commit to move the source checkout to")
    ref = source.get("ref") if isinstance(source.get("ref"), str) and _SAFE_REF.fullmatch(source.get("ref")) else None

    def present():
        return _git(["cat-file", "-e", f"{commit}^{{commit}}"], target, check=False, cfg=cfg).returncode == 0

    if not present():
        errors = []
        for args in ([["fetch", "--no-tags", "--quiet", "origin", ref]] if ref else []) + [["fetch", "--no-tags", "--quiet", "origin", commit]]:
            result = _git(args, target, check=False, timeout=GIT_NETWORK_TIMEOUT_SECONDS, cfg=cfg)
            if result.returncode != 0:
                errors.append(_printable(result.stderr or result.stdout or f"exit {result.returncode}"))
            if present():
                break
        if not present():
            tactical = cfg.get("TACTICAL_USER", "tactical")
            raise RuntimeError(f"{component} source checkout does not have commit {commit}, and git fetch as {tactical} could not get it "
                               f"({'; '.join(errors) or 'no message'}). Check it with: sudo -u {tactical} git -C {target} fetch origin")
    if source.get("type") == "branch" and ref:
        _git(["checkout", "--quiet", "--force", "-B", ref, commit], target, cfg=cfg)
    else:
        _git(["checkout", "--quiet", "--force", "--detach", commit], target, cfg=cfg)
    head = _git(["rev-parse", "--verify", "HEAD"], target, cfg=cfg).stdout.strip().lower()
    if head != commit:
        raise RuntimeError(f"{component} source checkout is at {head[:12]} after the move, expected {commit}")
    status = _git(["status", "--porcelain", "--untracked-files=all"], target, cfg=cfg).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is not clean at {commit[:12]}: {_printable(status.splitlines()[0])}")
    if log is not None:
        log.write(f"[TEC-TAC-UPDATE] {component} source checkout is at exactly {commit}" + (f" (branch {ref})" if source.get("type") == "branch" and ref else " (detached)") + "\n")
        log.flush()
    return commit


def restore_source_checkout(target, component, git_state, cfg=None):
    """Rollback for the source: the exact HEAD and branch it had before the update, as the Tactical account (1.17.98).

    Nothing is cleaned beyond Git's own reset: no -x, so ignored files and an administrator's files are left alone.
    """
    cfg = load_config() if cfg is None else cfg
    old_head = str((git_state or {}).get("head") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", old_head):
        raise RuntimeError("rollback Git state is missing the previous HEAD")
    old_branch = (git_state or {}).get("branch")
    normalise_source_owner(target, component, cfg)
    _git(["reset", "--quiet", "--hard"], target, cfg=cfg)
    if isinstance(old_branch, str) and _SAFE_REF.fullmatch(old_branch):
        _git(["checkout", "--quiet", "--force", "-B", old_branch, old_head], target, cfg=cfg)
    else:
        _git(["checkout", "--quiet", "--force", "--detach", old_head], target, cfg=cfg)
    head = _git(["rev-parse", "--verify", "HEAD"], target, cfg=cfg).stdout.strip().lower()
    if head != old_head:
        raise RuntimeError(f"{component} source checkout is at {head[:12]} after the rollback, expected {old_head}")


def verify_source_checkout(target, component, cfg=None, expected_head=None):
    """Post-update assertions for a source checkout (1.17.98, spec "Post-update verification").

    The directory and its .git belong to the Tactical account and its group, HEAD is the expected commit, and
    git status --porcelain is empty.
    """
    cfg = load_config() if cfg is None else cfg
    tactical, uid, gid = _tactical_account(cfg)
    target = Path(target)
    for path in (target, target / ".git"):
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid):
            raise RuntimeError(f"{component} source checkout {path} is owned by {_owner_name(info.st_uid)}:{_group_name(info.st_gid)}, "
                               f"expected {tactical}:{_group_name(gid)}")
    if expected_head:
        head = _git(["rev-parse", "--verify", "HEAD"], target, cfg=cfg).stdout.strip().lower()
        if head != str(expected_head).lower():
            raise RuntimeError(f"{component} source checkout is at {head[:12]}, expected {expected_head}")
    status = _git(["status", "--porcelain"], target, cfg=cfg).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is dirty after update: {_printable(status.splitlines()[0])}")


def verify_source_runtime_layout(component, source_root, cfg=None, expected_head=None):
    cfg = load_config() if cfg is None else cfg
    runtime_root = Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")).resolve()
    if (runtime_root / ".git").exists():
        raise RuntimeError("Tec-Tac runtime unexpectedly contains Git metadata")
    if not (Path(source_root) / ".git").is_dir():
        raise RuntimeError(f"{component} source checkout lost Git metadata")
    runtime_framework = Path(cfg.get("TEC_TAC_FRAMEWORK_ROOT", "/opt/tec-tac/framework")).resolve()
    if component == "framework" and runtime_framework == Path(os.path.normpath(str(source_root))):
        raise RuntimeError("framework source and runtime resolve to the same path")
    verify_source_checkout(source_root, component, cfg, expected_head)


def _backup_add_dir(tf, dirfd, arcname, excluded, top):
    """Add one directory's entries to the archive through descriptors: no link is followed, no path is re-resolved (1.17.98)."""
    with os.scandir(dirfd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        if top and name in excluded:
            continue
        listed = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        arc = f"{arcname}/{name}"
        if stat.S_ISDIR(listed.st_mode):
            child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=dirfd)
            try:
                info = os.fstat(child)
                if (info.st_dev, info.st_ino) != (listed.st_dev, listed.st_ino):
                    raise RuntimeError(f"source checkout changed while the backup was taken: {arc}")
                member = tarfile.TarInfo(arc)
                member.type = tarfile.DIRTYPE
                member.mode = stat.S_IMODE(info.st_mode)
                member.mtime = int(info.st_mtime)
                tf.addfile(member)
                _backup_add_dir(tf, child, arc, excluded, False)
            finally:
                os.close(child)
        elif stat.S_ISREG(listed.st_mode):
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=dirfd)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (listed.st_dev, listed.st_ino):
                    raise RuntimeError(f"source checkout changed while the backup was taken: {arc}")
                member = tarfile.TarInfo(arc)
                member.size = info.st_size
                member.mode = stat.S_IMODE(info.st_mode)
                member.mtime = int(info.st_mtime)
                tf.addfile(member, handle)
        # Links and special files are left out: a rollback archive may hold neither, and the signed manifest has none.


def backup_root(target, component, old_version, job_id):
    BACKUPS_ROOT.mkdir(parents=True, exist_ok=True)
    safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "_", old_version or "unknown")
    backup = BACKUPS_ROOT / f"{component}-{safe_version}-{stamp()}-{job_id[:8]}.tar.gz"

    excluded_roots = {".git"}
    if component == "ui":
        excluded_roots.update({"node_modules", "dist"})

    root = Path(os.path.normpath(str(target)))
    # 1.17.98: the checkout may still belong to the web account, so nothing is read by path. Every entry is opened through the
    # descriptor that listed it with O_NOFOLLOW, so a file swapped for a link between listing and reading is refused, never archived.
    fd = open_source_checkout(root, component)
    try:
        info = os.fstat(fd)
        with tarfile.open(backup, "w:gz") as tf:
            top = tarfile.TarInfo(root.name)
            top.type = tarfile.DIRTYPE
            top.mode = stat.S_IMODE(info.st_mode)
            top.mtime = int(info.st_mtime)
            tf.addfile(top)
            _backup_add_dir(tf, fd, root.name, excluded_roots, True)
    finally:
        os.close(fd)
    os.chmod(backup, 0o640)
    return backup


def _read_root_held_version(path, tactical_uid, tactical_gid):
    """VERSION from root-held state: no link anywhere in the path, and neither the file nor any folder above it writable by the
    Tactical account (not its owner, not group-writable for its group, not world-writable). "" when that does not hold.
    """
    path = Path(os.path.normpath(str(path)))

    def held(info):
        return (info.st_uid != tactical_uid and not (info.st_mode & stat.S_IWOTH)
                and not (info.st_gid == tactical_gid and info.st_mode & stat.S_IWGRP))

    try:
        fd = os.open("/", _NOFOLLOW_DIR)
    except OSError:
        return ""
    try:
        for part in path.parts[1:-1]:
            if not held(os.fstat(fd)):
                return ""
            child = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        if not held(os.fstat(fd)):
            return ""
        version_fd = os.open(path.name, _NOFOLLOW_READ, dir_fd=fd)
    except OSError:
        return ""
    finally:
        os.close(fd)
    try:
        info = os.fstat(version_fd)
        if not stat.S_ISREG(info.st_mode) or not held(info):
            return ""
        text = os.read(version_fd, 256).decode("utf-8", "replace").strip()
    finally:
        os.close(version_fd)
    return text if _VERSION_TEXT.fullmatch(text) else ""


def installed_version(component, cfg):
    """The installed version from root-held state, never from the Tactical-owned checkout (1.17.98, review round 6).

    Framework: the runtime VERSION (/opt/tec-tac/VERSION, root:root 0644 under the ownership rule). UI: the deployed UI VERSION
    (written by the UI installer under /var/lib/tec-tac/ui), else the root-owned provenance this helper recorded. "" when unknown.
    """
    try:
        _, uid, gid = _tactical_account(cfg)
    except RuntimeError:
        return ""  # unknown: the update is then refused inside the job, which records the reason
    if component == "framework":
        return _read_root_held_version(Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")) / "VERSION", uid, gid)
    deployed = _read_root_held_version(Path(cfg.get("TEC_TAC_UI_DEPLOY_ROOT", "/var/lib/tec-tac/ui/tec-tac")) / "VERSION", uid, gid)
    if deployed:
        return deployed
    record = _read_provenance("ui") or {}
    value = str(record.get("version") or "")
    return value if _VERSION_TEXT.fullmatch(value) else ""


def verify_rollback_tree(config, target, component, old_version, *, purpose="rollback"):
    """Refuse to run a rollback (or restore) installer from bytes that are not the signed release that was installed (1.17.98).

    ``target`` is a root-owned staging copy (stage_release_tree). The privileged verifier must find a signed, trusted manifest
    that matches the whole staged tree, and that manifest must be for the expected version. No signed manifest, no installer:
    the development override for unsigned updates is not applied here, exactly as before.
    """
    wanted = str(old_version or "").strip()
    if not wanted or wanted == "unknown":
        raise RuntimeError(f"{purpose} verification failed: the installed version is unknown, so its signed release cannot be checked")
    try:
        trust = _root_verify_tree(config, target, component)
    except RuntimeError as exc:
        raise RuntimeError(f"{purpose} verification failed: the restored {component} tree does not match a signed release ({exc}); its installer was not run") from exc
    if not isinstance(trust, dict) or not trust.get("verified") or not trust.get("signed"):
        raise RuntimeError(f"{purpose} verification failed: the restored {component} tree has no signed manifest; its installer was not run")
    if str(trust.get("version") or "").strip() != wanted:
        raise RuntimeError(f"{purpose} verification failed: the restored {component} tree is version {trust.get('version')}, expected {wanted}; its installer was not run")
    _VERIFIED_STAGES.add(str(Path(target).resolve()))
    return trust


def verify_staged_tree(config, staged, component, *, against=None, expected_version=None):
    """Check a staged forward-update tree with the privileged verifier before its installer runs (1.17.98).

    The verifier applies the root trust policy, including the development override for unsigned updates exactly as before.
    ``against`` is the trust of the package checked at extraction: the staged manifest must be the same manifest.
    """
    trust = _root_verify_tree(config, staged, component)
    if against is not None and trust.get("manifest_sha256") != against.get("manifest_sha256"):
        raise RuntimeError("execution checkout signed manifest differs from staged verified manifest")
    if expected_version is not None:
        version = _read_version_file(Path(staged))
        if version != str(expected_version):
            raise RuntimeError(f"staged {component} tree is version {version or 'unknown'}, expected {expected_version}")
    _VERIFIED_STAGES.add(str(Path(staged).resolve()))
    return trust


_VERSION_TEXT = re.compile(r"^[0-9A-Za-z.+-]{1,64}$")


def _read_version_file(root):
    """The VERSION of a tree, read as root without following a link (at most 256 bytes); "" when it is not a plain version.

    A source checkout belongs to the Tactical account, so its VERSION may be a link to a root-only file or hold anything. Only
    text that looks like a version (letters, digits, ".", "+", "-", at most 64) is ever returned, logged or written to a job file.
    """
    try:
        fd = os.open(str(Path(root) / "VERSION"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        text = os.read(fd, 256).decode("utf-8", "replace").strip()
    finally:
        os.close(fd)
    return text if _VERSION_TEXT.fullmatch(text) else ""


def remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


@contextmanager
def private_update_work_dir(job_id):
    """Create a root-private extraction directory and always remove it.

    RUNNING_ROOT is intentionally readable/traversable by the Tactical group for
    status artifacts, so update payload extraction must live below a 0700
    root-owned child.  The context manager guarantees cleanup on both normal
    completion and exceptions.
    """
    if not JOB_RE.fullmatch(str(job_id)):
        raise RuntimeError("invalid system update job id for private work directory")
    work = RUNNING_ROOT / f"{job_id}.work"
    remove_path(work)
    work.mkdir(parents=False, mode=0o700)
    os.chown(work, 0, 0)
    os.chmod(work, 0o700)
    try:
        yield work
    finally:
        remove_path(work)


# 1.17.98: the trees an installer may run from. A tree is added only by verify_staged_tree or verify_rollback_tree, after the
# privileged verifier checked it, and only when it lies inside the root-only staging root.
_VERIFIED_STAGES = set()
_STAGE_LABEL = re.compile(r"^[a-z0-9-]{1,40}$")


@contextmanager
def install_stage(stage_id, label):
    """A root-only staging directory for one tree (1.17.98, spec "Use staging instead of mutating source").

    /var/lib/tec-tac/system-updates/install-stage is a real directory, root:root 0700, checked before use, and never inside a
    source checkout. The per-run directory below it is 0700 and is removed afterwards whatever happened.
    """
    if not JOB_RE.fullmatch(str(stage_id)) or not _STAGE_LABEL.fullmatch(str(label)):
        raise RuntimeError("invalid staging directory name")
    INSTALL_STAGE_ROOT.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(INSTALL_STAGE_ROOT, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(INSTALL_STAGE_ROOT)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"system update staging root is not a real directory: {INSTALL_STAGE_ROOT}")
    os.chown(INSTALL_STAGE_ROOT, 0, 0, follow_symlinks=False)
    os.chmod(INSTALL_STAGE_ROOT, 0o700)
    stage = INSTALL_STAGE_ROOT / f"{stage_id}-{label}"
    remove_path(stage)
    os.mkdir(stage, 0o700)
    try:
        yield stage
    finally:
        prefix = str(stage.resolve())
        for item in [item for item in _VERIFIED_STAGES if item == prefix or item.startswith(prefix + os.sep)]:
            _VERIFIED_STAGES.discard(item)
        remove_path(stage)


_STAGE_MANIFEST_MAX = 16 * 1024 * 1024
_STAGE_SIGNATURE_MAX = 1024 * 1024
_NOFOLLOW_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _read_small_at(dirfd, name, limit, label):
    try:
        fd = os.open(name, _NOFOLLOW_READ, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be read safely (a link or unreadable): {exc.strerror or exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError(f"{label} is not a regular file of an acceptable size")
        chunks, remaining = [], limit + 1
        while remaining > 0:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > limit:
            raise RuntimeError(f"{label} is unexpectedly large")
        return data
    finally:
        os.close(fd)


def _signed_file_entries(manifest_bytes, component):
    """The (path, size, sha256) list of a schema-2 signed manifest. Only chooses what to copy; the privileged verifier decides trust."""
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("signed release manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 2 or manifest.get("component") != component:
        raise RuntimeError(f"signed release manifest is not a schema-2 {component} manifest")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_TREE_FILES:
        raise RuntimeError("signed release file list is invalid")
    entries, seen = [], set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise RuntimeError("signed release file entry is invalid")
        rel = _safe_tree_rel(entry.get("path"))
        size, digest = entry.get("size"), str(entry.get("sha256") or "").lower()
        if rel in seen or isinstance(size, bool) or not isinstance(size, int) or size < 0 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(f"signed release metadata is invalid for {rel}")
        seen.add(rel)
        entries.append((rel, size, digest))
    return entries


def _copy_file_at(dirfd, name, dest, rel, expected=None):
    """Copy one regular file (opened without following a link) into a fresh root-owned file; compare size and SHA-256 when given."""
    fd = os.open(name, _NOFOLLOW_READ, dir_fd=dirfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{rel} is not a regular file")
        mode = 0o755 if info.st_mode & 0o111 else 0o644
        out = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        digest, size = hashlib.sha256(), 0
        try:
            os.fchown(out, 0, 0)
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                view = memoryview(block)
                while view:
                    view = view[os.write(out, view):]
            os.fchmod(out, mode)
        finally:
            os.close(out)
    finally:
        os.close(fd)
    if expected is not None and (size, digest.hexdigest()) != expected:
        raise RuntimeError(f"{rel} differs from the signed release manifest; nothing was installed")


def _copy_whole_tree_at(dirfd, dest, prefix=""):
    """Copy a root-private extracted package (the unsigned development case only). Links and special files are refused."""
    with os.scandir(dirfd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        if not prefix and name == ".git":
            continue
        rel = f"{prefix}/{name}" if prefix else name
        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _NOFOLLOW_DIR, dir_fd=dirfd)
            try:
                os.mkdir(dest / name, 0o755)
                _copy_whole_tree_at(child, dest / name, rel)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            _copy_file_at(dirfd, name, dest / name, rel)
        else:
            raise RuntimeError(f"release tree contains a link or special file: {rel}")


def stage_release_tree(source, dest, component, *, allow_unsigned=False):
    """Copy a release tree into a root-owned staging directory (1.17.98). Returns ``dest``.

    Signed tree: exactly the files the signed manifest lists, plus the manifest and its signature. Each file is opened through
    descriptors with no link followed and compared with the manifest while it is copied, so a changed install.sh stops here.
    Untracked and ignored files of a checkout (node_modules, dist, bytecode) are never copied. Ownership is set explicitly
    (root:root, directories 0755, files 0644 or 0755): nothing is carried over from the source. The caller still runs the
    privileged verifier on the result (verify_staged_tree or verify_rollback_tree) before any installer.
    An unsigned tree is staged only when ``allow_unsigned`` is set, which run_job does only for a package the root policy
    accepted under the development override, and only from the root-private extraction, never from a checkout.
    """
    dest = Path(dest)
    os.mkdir(dest, 0o755)
    os.chown(dest, 0, 0)
    src_path = Path(os.path.normpath(str(source)))
    src_fd = open_source_checkout(src_path, component) if src_path in _configured_source_paths() else os.open(str(source), _NOFOLLOW_DIR)
    try:
        manifest_bytes = _read_small_at(src_fd, TREE_MANIFEST, _STAGE_MANIFEST_MAX, "signed release manifest")
        signature_bytes = _read_small_at(src_fd, TREE_SIGNATURE, _STAGE_SIGNATURE_MAX, "signed release signature")
        if manifest_bytes is None and signature_bytes is None:
            if not allow_unsigned:
                raise RuntimeError(f"the {component} tree at {source} has no signed release manifest, so root will not run its installer")
            _copy_whole_tree_at(src_fd, dest)
        elif manifest_bytes is None or signature_bytes is None:
            raise RuntimeError(f"the {component} tree at {source} has an incomplete signed release manifest")
        else:
            for rel, size, digest in _signed_file_entries(manifest_bytes, component):
                parts = rel.split("/")
                opened = []
                try:
                    current = src_fd
                    for part in parts[:-1]:
                        current = os.open(part, _NOFOLLOW_DIR, dir_fd=current)
                        opened.append(current)
                    out_dir = dest.joinpath(*parts[:-1])
                    out_dir.mkdir(parents=True, exist_ok=True)
                    _copy_file_at(current, parts[-1], out_dir / parts[-1], rel, (size, digest))
                except FileNotFoundError as exc:
                    raise RuntimeError(f"{rel} is missing from the {component} tree; nothing was installed") from exc
                except OSError as exc:
                    raise RuntimeError(f"{rel} in the {component} tree is a link or cannot be read ({exc.strerror or exc}); nothing was installed") from exc
                finally:
                    for fd in reversed(opened):
                        os.close(fd)
            for name, data in ((TREE_MANIFEST, manifest_bytes), (TREE_SIGNATURE, signature_bytes)):
                out = os.open(str(dest / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    os.fchown(out, 0, 0)
                    os.write(out, data)
                    os.fchmod(out, 0o644)
                finally:
                    os.close(out)
    finally:
        os.close(src_fd)
    for current, dirs, _files in os.walk(dest):
        for name in dirs:
            os.chown(os.path.join(current, name), 0, 0, follow_symlinks=False)
            os.chmod(os.path.join(current, name), 0o755)
    os.chmod(dest, 0o755)
    return dest


def extract_rollback_backup(backup, dest, target):
    """Extract the root-held backup of the old checkout into a root-only staging directory (1.17.98). Returns the component folder."""
    backup = Path(backup)
    if backup.is_symlink() or not backup.is_file():
        raise RuntimeError("rollback backup is missing or is not a regular file")
    os.mkdir(dest, 0o700)
    with tarfile.open(backup, "r:gz") as tf:
        members = _validated_rollback_members(tf, Path(target))
        tf.extractall(dest, members=members, filter="data")
    tree = Path(dest) / Path(target).name
    if tree.is_symlink() or not tree.is_dir():
        raise RuntimeError("rollback backup did not produce the expected component directory")
    return tree


# 1.17.98: the one ownership rule for the trusted Framework runtime (spec "Trusted deployed runtime"). install.sh applies and checks
# it through this helper (--runtime-ownership), and the system updater, a rollback and a restore apply and check it after their
# installer, so they cannot drift. Dynamic runtime folders (extensions, reportsets) are not in the rule and are never touched.
# A tree is root:root with every directory 0755 and every file 0644, or 0755 when it had an execute bit; no group or other write.
RUNTIME_OWNERSHIP_RULE = (
    ("framework", "tree", 0o755),
    ("scripts", "tree", 0o755),
    ("templates", "tree", 0o755),
    ("VERSION", "file", 0o644),
    ("tec_tac_package.json", "file", 0o644),
)


def runtime_ownership_targets(root, framework=None, scripts=None):
    root = Path(root)
    paths = {
        "framework": Path(framework) if framework else root / "framework",
        "scripts": Path(scripts) if scripts else root / "scripts",
        "templates": root / "templates",
        "VERSION": root / "VERSION",
        "tec_tac_package.json": root / "tec_tac_package.json",
    }
    return [(role, kind, mode, paths[role]) for role, kind, mode in RUNTIME_OWNERSHIP_RULE]


def _runtime_targets_from_config(cfg):
    return runtime_ownership_targets(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac"), cfg.get("TEC_TAC_FRAMEWORK_ROOT"), cfg.get("TEC_TAC_SCRIPTS_ROOT"))


def _rule_mode(info):
    if stat.S_ISDIR(info.st_mode):
        return 0o755
    return 0o755 if info.st_mode & 0o111 else 0o644


def _set_owner_mode_fd(fd, mode):
    os.fchown(fd, 0, 0)
    os.fchmod(fd, mode)


def apply_runtime_ownership(targets, *, skip_missing=False):
    """Set the runtime rule explicitly (never relying on cp -a or archive extraction). Returns the number of paths checked.

    Directories are taken first, through their own descriptor, so once a directory is root-owned nobody else can add or swap
    an entry in it. Files are opened without following a link and changed through that descriptor; a link is only re-owned,
    never followed. Device files and sockets are refused.
    """
    count = 0
    for role, kind, mode, path in targets:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if skip_missing:
                continue
            raise RuntimeError(f"Tec-Tac runtime {role} is missing: {path}") from None
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"Tec-Tac runtime {role} must not be a symbolic link: {path}")
        if kind == "file":
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"Tec-Tac runtime {role} must be a regular file: {path}")
            fd = os.open(str(path), _NOFOLLOW_READ)
            try:
                _set_owner_mode_fd(fd, mode)
            finally:
                os.close(fd)
            count += 1
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"Tec-Tac runtime {role} must be a directory: {path}")
        top = True
        for current, dirs, files, dirfd in os.fwalk(str(path), follow_symlinks=False):
            _set_owner_mode_fd(dirfd, mode if top else 0o755)
            top = False
            count += 1
            for name in files:
                entry = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                if stat.S_ISLNK(entry.st_mode):
                    os.chown(name, 0, 0, dir_fd=dirfd, follow_symlinks=False)
                elif stat.S_ISREG(entry.st_mode):
                    fd = os.open(name, _NOFOLLOW_READ, dir_fd=dirfd)
                    try:
                        _set_owner_mode_fd(fd, _rule_mode(os.fstat(fd)))
                    finally:
                        os.close(fd)
                else:
                    raise RuntimeError(f"Tec-Tac runtime {role} contains a special file: {os.path.join(current, name)}")
                count += 1
            for name in dirs:
                entry = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                if stat.S_ISLNK(entry.st_mode):
                    os.chown(name, 0, 0, dir_fd=dirfd, follow_symlinks=False)
    return count


def verify_runtime_ownership(targets):
    """Every rule path is root:root, the top path has exactly its mode, and nothing below is group/other writable or setuid. Returns problems."""
    problems = []
    for role, kind, mode, path in targets:
        try:
            info = os.lstat(path)
        except OSError:
            problems.append(f"{path} is missing")
            continue
        if stat.S_ISLNK(info.st_mode) or (kind == "file") != stat.S_ISREG(info.st_mode):
            problems.append(f"{path} is not a {'regular file' if kind == 'file' else 'directory'}")
            continue
        if (info.st_uid, info.st_gid) != (0, 0) or stat.S_IMODE(info.st_mode) != mode:
            problems.append(f"{path} is {_owner_name(info.st_uid)}:{_group_name(info.st_gid)} {stat.S_IMODE(info.st_mode):04o}, expected root:root {mode:04o}")
        if kind == "tree":
            for current, dirs, files, dirfd in os.fwalk(str(path), follow_symlinks=False):
                for name in dirs + files:
                    entry = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                    if stat.S_ISLNK(entry.st_mode):
                        continue
                    if (entry.st_uid, entry.st_gid) != (0, 0) or entry.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
                        problems.append(f"{os.path.join(current, name)} is {_owner_name(entry.st_uid)}:{_group_name(entry.st_gid)} {stat.S_IMODE(entry.st_mode):04o}")
                if len(problems) > 20:
                    return problems[:20] + ["... and more"]
    return problems


def enforce_runtime_ownership(cfg, log=None):
    """Apply, then check, the runtime rule after a Framework installer ran (forward update, rollback or restore)."""
    targets = _runtime_targets_from_config(cfg)
    count = apply_runtime_ownership(targets)
    problems = verify_runtime_ownership(targets)
    if problems:
        raise RuntimeError("Tec-Tac runtime ownership verification failed: " + "; ".join(problems))
    if log is not None:
        log.write(f"[TEC-TAC-SECURITY] runtime ownership rule applied and verified on {count} paths (root:root, 0755 trees, 0644 VERSION and package manifest)\n")
        log.flush()


def _set_config_line(key, value):
    """Set one KEY=value line of the root-owned config, written atomically as root:root 0644. Returns True when it changed."""
    if CONFIG.is_symlink() or not CONFIG.is_file():
        return False
    info = CONFIG.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("Tec-Tac config must be root-owned and not group/world writable")
    value = str(value)
    if "\n" in value or "\r" in value:
        raise RuntimeError(f"config value for {key} may not contain a line break")
    lines = CONFIG.read_text(encoding="utf-8").splitlines(keepends=True)
    wanted = f"{key}={value}\n"
    found = [index for index, line in enumerate(lines) if line.startswith(f"{key}=")]
    if found and all(lines[index].rstrip("\r\n") == wanted.rstrip("\n") for index in found):
        return False
    for index in found:
        lines[index] = wanted
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(wanted)
    fd, tmp_name = tempfile.mkstemp(prefix=".tec-tac.conf.", suffix=".tmp", dir=str(CONFIG.parent))
    try:
        os.write(fd, "".join(lines).encode("utf-8"))
        os.fchmod(fd, 0o644)
        os.fchown(fd, 0, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp_name, CONFIG)
    return True


def repin_framework_source(expected, log=None):
    """Keep TEC_TAC_FRAMEWORK_SOURCE pointing at the source checkout after an installer ran from staging (1.17.98).

    install.sh from this release records the checkout it is told about (TEC_TAC_STAGED_SOURCE_CHECKOUT). An older installer run
    by a rollback or a restore records its own folder, which is the staging copy. That one line is put back; the rest of the
    root-owned config is kept as the installer wrote it.
    """
    changed = _set_config_line("TEC_TAC_FRAMEWORK_SOURCE", expected)
    if changed and log is not None:
        log.write(f"[TEC-TAC-UPDATE] config TEC_TAC_FRAMEWORK_SOURCE set back to the source checkout {expected}\n")
        log.flush()
    return changed


# 1.17.98: module jobs run the UI's module sync script as root (UI_SYNC_SCRIPT), and the module helpers refuse a script that is not
# root-owned. The UI checkout now belongs to the Tactical account, so root keeps its own copy of that script, and of the config
# reader it sources, in a root-only folder. The copy is taken only from a UI tree the privileged verifier checked.
UI_SYNC_TOOLS_ROOT = Path("/usr/local/lib/tec-tac-ui-sync")
UI_SYNC_TOOL_FILES = (("scripts/sync-modules.sh", 0o755), ("scripts/tec-tac-config.sh", 0o644))


def capture_ui_sync_tools(staged):
    """Read the UI module sync script (and the config reader it sources) from a verified staged tree, before its installer runs.

    The bytes are taken right after the privileged verifier checked the tree, so nothing the installer does in its own folder can
    change what is published. Returns None when this UI release has no such script.
    """
    tree = Path(staged).resolve()
    if str(tree) not in _VERIFIED_STAGES:
        raise RuntimeError("refusing to publish UI sync tools from a tree that was not staged and verified by the root helper")
    tools = {}
    for rel, mode in UI_SYNC_TOOL_FILES:
        path = tree / rel
        if path.is_symlink() or not path.is_file():
            return None
        tools[rel] = (path.read_bytes(), mode)
    return tools


def publish_ui_sync_tools(tools, log=None):
    """Write captured UI sync tools to UI_SYNC_TOOLS_ROOT (root-owned, replaced as a whole) and point UI_SYNC_SCRIPT at them.

    Returns the published script, or None when there was nothing to publish (UI_SYNC_SCRIPT is unchanged then).
    """
    if not tools:
        if log is not None:
            log.write("[TEC-TAC-UPDATE] this UI release has no module sync script; UI_SYNC_SCRIPT is unchanged\n")
        return None
    UI_SYNC_TOOLS_ROOT.parent.mkdir(parents=True, exist_ok=True)
    fresh = UI_SYNC_TOOLS_ROOT.with_name(f".{UI_SYNC_TOOLS_ROOT.name}.new-{os.getpid()}")
    old = UI_SYNC_TOOLS_ROOT.with_name(f".{UI_SYNC_TOOLS_ROOT.name}.old-{os.getpid()}")
    remove_path(fresh)
    remove_path(old)
    os.mkdir(fresh, 0o755)
    os.mkdir(fresh / "scripts", 0o755)
    for path in (fresh, fresh / "scripts"):
        os.chown(path, 0, 0)
        os.chmod(path, 0o755)
    for rel, (data, mode) in tools.items():
        out = os.open(str(fresh / rel), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchown(out, 0, 0)
            os.write(out, data)
            os.fchmod(out, mode)
        finally:
            os.close(out)
    if UI_SYNC_TOOLS_ROOT.is_symlink() or UI_SYNC_TOOLS_ROOT.exists():
        os.rename(UI_SYNC_TOOLS_ROOT, old)
    os.rename(fresh, UI_SYNC_TOOLS_ROOT)
    remove_path(old)
    script = UI_SYNC_TOOLS_ROOT / "scripts" / "sync-modules.sh"
    _set_config_line("UI_SYNC_SCRIPT", script)
    if log is not None:
        log.write(f"[TEC-TAC-UPDATE] UI module sync script published root-owned at {script} (UI_SYNC_SCRIPT)\n")
        log.flush()
    return script


def publish_ui_sync_from_checkout(out=None):
    """install.sh calls this (--publish-ui-sync): stage and verify the UI checkout (signed required), then publish its sync script."""
    out = sys.stdout if out is None else out
    cfg = load_config()
    target = source_checkout_path("ui", cfg)
    if not (target / "scripts" / "sync-modules.sh").is_file():
        out.write(f"[TEC-TAC] no UI checkout with a module sync script at {target}; UI_SYNC_SCRIPT is unchanged\n")
        return None
    # 1.17.98 (review round 6): the staged UI must be the installed UI, as root recorded it; the checkout's VERSION decides nothing.
    version = installed_version("ui", cfg)
    if not version:
        raise RuntimeError("the installed UI version cannot be read from root-held state; the UI module sync script was not published")
    with install_stage(str(uuid.uuid4()), "ui-sync") as stage_dir:
        staged = stage_release_tree(target, stage_dir / "tree", "ui")
        verify_rollback_tree(cfg, staged, "ui", version, purpose="UI module sync")
        return publish_ui_sync_tools(capture_ui_sync_tools(staged), out)


def _read_provenance(component):
    path = PROVENANCE_ROOT / f"{component}.json"
    if not path.exists():
        return None
    try:
        return _read_json_nofollow(path, max_bytes=64 * 1024, label="installed provenance")
    except SystemExit:
        return None


def write_provenance(component, payload, gid):
    """Record (or, for a rollback, put back) the installed provenance: repository, ref and the exact 40-character commit (1.17.98)."""
    PROVENANCE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(PROVENANCE_ROOT, 0, gid)
    os.chmod(PROVENANCE_ROOT, 0o750)
    path = PROVENANCE_ROOT / f"{component}.json"
    if payload is None:
        path.unlink(missing_ok=True)
        return
    atomic_json(path, payload, mode=0o640, uid=0, gid=gid)


def install_restored_component(component, out=None, expected=None):
    """Run a restored component's installer the same way a System Update does (1.17.98, called by the server-backup restore).

    The restored checkout is given to the Tactical account, copied into a root-only staging directory and checked by the privileged
    verifier against its signed manifest for the version it says it is (signed required, like a rollback). Only then does its
    installer run, from the staging copy. A changed install.sh, or any other changed file, stops here before anything runs.
    """
    if component not in {"framework", "ui"}:
        raise RuntimeError("component must be framework or ui")
    out = sys.stdout if out is None else out
    cfg = load_config()
    target = source_checkout_path(component, cfg)
    # The privileged verifier imports the restored runtime framework, which must be root-owned first.
    apply_runtime_ownership(_runtime_targets_from_config(cfg), skip_missing=True)
    # 1.17.98 (review round 6): the version the restored tree must be signed for comes from the backup's own manifest (passed by
    # the backup helper) or, for the Framework, from the restored root-owned runtime. Never from the checkout's VERSION.
    version = str(expected or "").strip()
    if version and not _VERSION_TEXT.fullmatch(version):
        raise RuntimeError(f"restore verification failed: the expected {component} version {version!r} is not a version")
    if not version and component == "framework":
        version = installed_version("framework", cfg)
    if not version:
        raise RuntimeError(f"restore verification failed: the backup records no {component} version, so the restored tree cannot be checked; its installer was not run")
    with install_stage(str(uuid.uuid4()), f"restore-{component}") as stage_dir:
        staged = stage_release_tree(target, stage_dir / "tree", component)
        verify_rollback_tree(cfg, staged, component, version, purpose="restore")
        ui_tools = capture_ui_sync_tools(staged) if component == "ui" else None
        out.write(f"[TEC-TAC-RESTORE] {component} {version} staged and verified against its signed release; running its installer\n")
        out.flush()
        rc = run_install(component, staged, out, source_checkout=target)
        if component == "ui" and rc == 0:
            publish_ui_sync_tools(ui_tools, out)
    if component == "framework":
        repin_framework_source(target, out)
    if rc != 0:
        raise RuntimeError(f"restored {component} installer exited with status {rc}")
    # Only after the copy was staged and verified: the restored checkout goes to the Tactical account, one owner.
    changed = normalise_source_owner(target, component, cfg, require_git=False)
    out.write(f"[TEC-TAC-RESTORE] {component} source checkout {target}: {changed} paths given to the Tactical account\n")
    if component == "framework":
        enforce_runtime_ownership(cfg, out)
    out.write(f"[TEC-TAC-RESTORE] {component} {version} installed from the verified staging copy\n")
    out.flush()
    return version


def normalize_release_tree_security(root):
    """Normalize verified release content before any root installer runs.

    Release signatures cover bytes, not filesystem ownership or mode metadata.
    Reject links/special files, make every release path root-owned, and strip
    setuid/setgid plus group/other write bits without changing legitimate
    executable/read bits.  Git metadata is excluded because it is retained from
    the pre-existing root-managed checkout and is not release payload content.
    """
    root = Path(root)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError("release execution root must be a real directory")

    def normalize_one(path):
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise RuntimeError(f"release execution tree contains unsupported path: {path}")
        os.chown(path, 0, 0, follow_symlinks=False)
        mode = stat.S_IMODE(st.st_mode)
        safe_mode = mode & ~(stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)
        if safe_mode != mode:
            os.chmod(path, safe_mode, follow_symlinks=False)

    normalize_one(root)
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if current == root and entry.name == ".git":
                    continue
                path = Path(entry.path)
                normalize_one(path)
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)


def copy_tree_contents(source, target):
    for item in source.iterdir():
        if item.name == ".git":
            continue
        dest = target / item.name
        if item.is_dir():
            if dest.exists() and not dest.is_dir():
                remove_path(dest)
            shutil.copytree(item, dest, dirs_exist_ok=True, copy_function=shutil.copy2)
        else:
            if dest.is_dir():
                remove_path(dest)
            shutil.copy2(item, dest)



FRAMEWORK_OWNED_PLUGIN_PATHS = {
    ("extensions", "example"),
    ("extensions", "reporting"),
    ("reportsets", "example"),
}


VOLATILE_PLUGIN_DIRS = {"__pycache__"}
VOLATILE_PLUGIN_SUFFIXES = {".pyc", ".pyo"}


def _volatile_plugin_path(path, root):
    """Return True for runtime-generated artifacts that are not package content."""
    rel = path.relative_to(root)
    if any(part in VOLATILE_PLUGIN_DIRS for part in rel.parts):
        return True
    return path.is_file() and path.suffix.lower() in VOLATILE_PLUGIN_SUFFIXES


def _tree_digest(root):
    """Stable digest for persistent plugin content, excluding runtime bytecode caches."""
    import hashlib
    digest = hashlib.sha256()
    root = Path(root)
    if not root.exists():
        return None
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        if _volatile_plugin_path(path, root):
            continue
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(b"P\0" + rel + b"\0")
        if path.is_symlink():
            digest.update(b"L\0" + os.readlink(path).encode("utf-8") + b"\0")
        elif path.is_file():
            digest.update(b"F\0")
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        elif path.is_dir():
            digest.update(b"D\0")
    return digest.hexdigest()


def snapshot_dynamic_plugins(target):
    """Inventory dynamically installed modules before a framework self-update."""
    inventory = {}
    for top in ("extensions", "reportsets"):
        root = target / top
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or (top, child.name) in FRAMEWORK_OWNED_PLUGIN_PATHS:
                continue
            inventory[f"{top}/{child.name}"] = _tree_digest(child)
    return inventory


def verify_dynamic_plugins(target, inventory):
    missing = []
    changed = []
    for relative, expected in inventory.items():
        path = target / relative
        if not path.is_dir():
            missing.append(relative)
            continue
        actual = _tree_digest(path)
        if actual != expected:
            changed.append(relative)
    if missing or changed:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if changed:
            details.append("changed: " + ", ".join(changed))
        raise RuntimeError("framework update altered dynamically installed modules (" + "; ".join(details) + ")")

def deploy_framework(source, target):
    target.mkdir(parents=True, exist_ok=True)
    # Replace framework-owned roots, but preserve dynamically installed
    # extension/reportset directories that are absent from a framework package.
    for name in ("framwork", "scripts", "tests", "docs", "templates"):
        remove_path(target / name)
    for item in list(target.iterdir()):
        if item.name in {".git", "extensions", "reportsets"}:
            continue
        if item.is_file() or item.is_symlink():
            item.unlink(missing_ok=True)
    for relative in FRAMEWORK_OWNED_PLUGIN_PATHS:
        incoming = source.joinpath(*relative)
        existing = target.joinpath(*relative)
        if incoming.exists():
            remove_path(existing)
    copy_tree_contents(source, target)


def deploy_ui(source, target):
    target.mkdir(parents=True, exist_ok=True)
    for item in list(target.iterdir()):
        if item.name == ".git":
            continue
        remove_path(item)
    copy_tree_contents(source, target)


def _validated_rollback_members(tf, target):
    members = tf.getmembers()
    expected_top = target.name
    if not members:
        raise RuntimeError("rollback backup is empty")
    for member in members:
        rel = safe_name(member.name)
        if not rel.parts or rel.parts[0] != expected_top:
            raise RuntimeError(f"rollback backup contains an unexpected top-level path: {member.name}")
        if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
            raise RuntimeError(f"rollback backup contains an unsupported member: {member.name}")
    return members


def restore_backup(backup, target):
    """Restore a rollback archive without destroying the live tree first.

    The complete archive is validated and extracted into a sibling staging
    directory before the installed checkout is touched.  Only then do we use
    same-filesystem renames to quarantine the live tree and publish the staged
    rollback tree.  The live quarantine remains available until the swap has
    completed, so malformed/truncated archives cannot erase a working install.
    """
    backup = Path(backup)
    target = Path(target)
    parent = target.parent
    if backup.is_symlink() or not backup.is_file():
        raise RuntimeError("rollback backup is missing or is not a regular file")

    with tempfile.TemporaryDirectory(prefix=f".{target.name}.rollback-stage-", dir=parent) as raw_stage:
        stage_parent = Path(raw_stage)
        with tarfile.open(backup, "r:gz") as tf:
            members = _validated_rollback_members(tf, target)
            tf.extractall(stage_parent, members=members, filter="data")

        staged_target = stage_parent / target.name
        if staged_target.is_symlink() or not staged_target.is_dir():
            raise RuntimeError("rollback backup did not produce the expected component directory")

        quarantine = None
        moved_git = False
        if target.exists() or target.is_symlink():
            raw_quarantine = Path(tempfile.mkdtemp(prefix=f".{target.name}.rollback-live-", dir=parent))
            raw_quarantine.rmdir()
            quarantine = raw_quarantine
            os.replace(target, quarantine)

        try:
            if quarantine is not None:
                preserved_git = quarantine / ".git"
                if preserved_git.exists() and not (staged_target / ".git").exists():
                    os.replace(preserved_git, staged_target / ".git")
                    moved_git = True
            os.replace(staged_target, target)
        except Exception:
            if quarantine is not None:
                if moved_git and not (quarantine / ".git").exists() and (staged_target / ".git").exists():
                    os.replace(staged_target / ".git", quarantine / ".git")
                if not target.exists() and quarantine.exists():
                    os.replace(quarantine, target)
            raise
        else:
            if quarantine is not None:
                remove_path(quarantine)


INSTALL_TIMEOUT_SECONDS = 1800
VERIFY_TIMEOUT_SECONDS = 120  # 1.17.96: was 90; this check runs the same contract-catalog step as install.sh (46 s on dev02)


def _run_bounded(command, *, log, timeout, cwd=None, env=None, label="command"):
    try:
        result = subprocess.run(
            command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, text=True,
            stdin=subprocess.DEVNULL, env=env, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} timed out after {timeout} seconds") from exc
    return result.returncode


# 1.17.43: an installer returns INSTALL_REFUSED_EXIT (EX_CONFIG 78) only when its pre-flight refused before it changed anything.
# Core's install.sh does so from refuse(); the UI installer does so from the UI release that ships it (a request to the UI area).
# Any other non-zero status keeps the full rollback. The installer's words are printed after INSTALLER_REFUSAL_MARKER.
INSTALL_REFUSED_EXIT = 78
INSTALLER_REFUSAL_MARKER = "[TEC-TAC-INSTALL] REFUSED:"


class _UpdateRefused(RuntimeError):
    """The installer's pre-flight refused before it changed anything (status 78). Not a failed deployment: no installer re-run, no rollback check."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _installer_refusal_reason(log_path):
    """The installer's own words for a refusal, read from the end of the update log (the last 64 KiB only)."""
    try:
        with log_path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 65536))
            tail = handle.read().decode("utf-8", "replace")
    except OSError:
        return "the installer gave no reason"
    lines = [line for line in tail.splitlines() if INSTALLER_REFUSAL_MARKER in line]
    if not lines:
        return "the installer gave no reason"
    reason = re.sub(r"\s+", " ", lines[-1].split(INSTALLER_REFUSAL_MARKER, 1)[1]).strip().rstrip(".")
    return reason[:300] or "the installer gave no reason"


# 1.17.96, narrowed in 1.17.97: a rollback must not fail only because one of the installer's verification steps TIMED OUT. install.sh exits
# INSTALL_VERIFY_FAILED_EXIT (79) with a "[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying <step>" line when a check fails after the files are in place,
# and run_verify_step logs "VERIFY STEP FAILED: <step> (timed out after N s; ...)" when that check hit its time limit (exit 124). Only that pair,
# for the same step, in what the rollback installer itself wrote, is a warning. A check that failed for any other reason (a model or RBAC
# assertion, a missing route, a registry assertion) means the restored Core may not load, so it is a real ROLLBACK FAILED, like a restore error,
# another exit status, no marker, or the old installer's text (exit 1 and "ERROR: ... verification failed or timed out."), which cannot prove a
# timeout. All 12 verification steps run before install.sh restarts the services, so "timeout only" is the whole rule.
INSTALL_VERIFY_FAILED_EXIT = 79
INSTALLER_VERIFY_MARKER = "[TEC-TAC-INSTALL] VERIFY-FAILED:"
INSTALLER_VERIFY_STEP_FAILED = "VERIFY STEP FAILED:"
INSTALLER_VERIFY_STEPS = (
    "Framework model/RBAC",
    "Framework API route",
    "Tec-Tac developer contract catalog",
    "Tec-Tac Tactical Report Manager bridge",
    "Tec-Tac scheduler/capability Celery task",
    "Tec-Tac capability registry",
    "Tec-Tac session-security capability",
    "Tec-Tac Core Resource Directory capability",
    "Core server-backup capability",
    "Core server-maintenance capability",
    "Core Tactical operations capability",
    "Core Tactical websocket ticket capability",
)


def _log_size(log_path):
    try:
        return log_path.stat().st_size
    except OSError:
        return None


def _log_tail_lines(log_path, since):
    """The lines written to the update log from byte offset ``since`` on (at most the last 64 KiB). None when the log cannot be read."""
    if since is None:
        return None
    try:
        with log_path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(since, handle.tell() - 65536))
            return handle.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None


def _rollback_verification_step(rc, log_path, since):
    """The label of the verification step that TIMED OUT in the rollback installer, or None for any other failure (1.17.97).

    A warning needs all of: exit status 79, the "[TEC-TAC-INSTALL] VERIFY-FAILED: Verifying <step>" marker, and the installer's own
    "VERIFY STEP FAILED: <step> (timed out after N s ..." line for that same step, all written after byte offset ``since``. Nothing else counts: no
    marker, a step that failed without a timeout, a timeout line of another step, or the old installer's text (exit 1) is a failed rollback."""
    if rc != INSTALL_VERIFY_FAILED_EXIT:
        return None
    lines = _log_tail_lines(log_path, since)
    if not lines:
        return None
    step = ""
    for line in reversed(lines):
        if INSTALLER_VERIFY_MARKER in line:
            label = re.sub(r"\s+", " ", line.split(INSTALLER_VERIFY_MARKER, 1)[1]).strip()
            if label.startswith("Verifying "):
                step = label[len("Verifying "):].strip()
            break
    if not step or step not in INSTALLER_VERIFY_STEPS:
        return None
    timed_out = f"{INSTALLER_VERIFY_STEP_FAILED} {step} (timed out after "
    if not any(timed_out in line for line in lines):
        return None
    return "Verifying " + step


def run_install(component, target, log, *, source_checkout=None):
    """Run a component's own installer, only from a staged tree this helper verified (1.17.98).

    The tree must lie inside the root-only staging root and must have passed verify_staged_tree or verify_rollback_tree.
    Root never runs an installer from a source checkout. The Framework installer is told which checkout it represents
    (TEC_TAC_STAGED_SOURCE_CHECKOUT), so it records that path, not the staging copy, as TEC_TAC_FRAMEWORK_SOURCE.
    """
    tree = Path(target).resolve()
    if str(tree) not in _VERIFIED_STAGES or INSTALL_STAGE_ROOT.resolve() not in tree.parents:
        raise RuntimeError("refusing to run an installer from a tree that was not staged and verified by the root helper")
    if component == "framework":
        command = [TRUSTED_BASH, str(tree / "install.sh")]
    else:
        command = [TRUSTED_BASH, str(tree / "scripts" / "install.sh")]
    extra = {STAGED_SOURCE_ENV: str(source_checkout)} if component == "framework" and source_checkout else None
    return _run_bounded(command, log=log, timeout=INSTALL_TIMEOUT_SECONDS, env=privileged_env(extra), label=f"{component} installer")


def _read_package_version(target):
    manifest = target / "tec_tac_package.json"
    if not manifest.is_file():
        raise RuntimeError("tec_tac_package.json is missing after deployment")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to read deployed tec_tac_package.json: {exc}") from exc
    return str(data.get("version") or "").strip()


def verify(component, target, expected, log):
    """Check the deployed runtime after an installer. ``target`` is the Framework runtime root (VERSION, tec_tac_package.json)."""
    if component == "framework":
        version = (target / "VERSION").read_text(encoding="utf-8").strip()
        if version != expected:
            raise RuntimeError(f"VERSION verification failed: expected {expected}, found {version}")
        manifest_version = _read_package_version(target)
        if manifest_version != expected:
            raise RuntimeError(f"package manifest verification failed: expected {expected}, found {manifest_version or 'missing'}")
        config = load_config()
        tactical_user = config.get("TACTICAL_USER", "tactical")
        py = Path(config.get("TACTICAL_PYTHON", "/rmm/api/env/bin/python"))
        manage = Path(config.get("TACTICAL_BACKEND_ROOT", "/rmm/api/tacticalrmm")) / "manage.py"
        runtime_framework = Path(config.get("TEC_TAC_FRAMEWORK_ROOT", "/opt/tec-tac/framework"))
        env = privileged_env({"PYTHONPATH": str(runtime_framework)})
        checks = [
            ([str(py), str(manage), "check"], "Django system check"),
            ([str(py), str(manage), "migrate", "tec_tac", "--check"], "Tec-Tac migration check"),
            ([str(py), str(manage), "shell", "-c",
              "from django.urls import resolve; assert resolve('/api/tfd/system/updates/').url_name == 'tec-tac-system-update-status'; print('system update route OK')"],
             "framework route verification"),
            ([str(py), str(manage), "shell", "-c",
              "from tec_tac.contracts import build_contract_catalog; c=build_contract_catalog(); expected=" + repr(expected) + "; assert c['framework_version']==expected, {'expected':expected,'actual':c['framework_version']}; print('contract version OK', expected)"],
             "framework contract verification"),
        ]
        for command, label in checks:
            # manage.py imports Tactical local_settings.py and the Tactical virtualenv.
            # Both are Tactical-owned, so they must never execute in the root helper.
            command = ["runuser", "-u", tactical_user, "--", *command]
            rc = _run_bounded(command, cwd=str(manage.parent), log=log, env=env, timeout=VERIFY_TIMEOUT_SECONDS, label=label)
            if rc != 0:
                raise RuntimeError(f"{label} failed with status {rc}")
        recovery = Path(load_config().get("TEC_TAC_SCRIPTS_ROOT", "/opt/tec-tac/scripts")) / "recovery"
        missing_exec = [p.name for p in sorted(recovery.glob("*.sh")) if not os.access(p, os.X_OK)]
        if missing_exec:
            raise RuntimeError("recovery script executable verification failed: " + ", ".join(missing_exec))
    else:
        deployed = Path(load_config().get("TEC_TAC_UI_DEPLOY_ROOT", "/var/lib/tec-tac/ui/tec-tac"))
        index = deployed / "index.html"
        deployed_version = deployed / "VERSION"
        if not index.is_file() or index.stat().st_size == 0:
            raise RuntimeError("deployed Tec-Tac UI index.html was not found or is empty")
        if not deployed_version.is_file():
            raise RuntimeError("deployed Tec-Tac UI VERSION file was not found")
        actual = deployed_version.read_text(encoding="utf-8").strip()
        if actual != expected:
            raise RuntimeError(f"deployed UI VERSION verification failed: expected {expected}, found {actual}")


def run_job(job_id):
    path, status = load_job(job_id)
    if status.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    _, immutable = load_running_request(job_id)
    job = {**immutable, "status": status.get("status"), "stage": status.get("stage"), "created_at": status.get("created_at")}
    cfg = load_config()
    result_gid = tactical_gid(cfg)
    component = job["component"]
    target = source_checkout_path(component, cfg)
    package = Path(job["package_path"])
    log_path = LOGS_ROOT / f"{job_id}.log"
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)

    with LOCK_PATH.open("a+") as lock, log_path.open("a", encoding="utf-8") as log:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another Tec-Tac system update is already running") from exc
        acquire_lifecycle_lock()

        job["status"] = "running"
        job["started_at"] = now()
        job["stage"] = "preflight"
        atomic_json(path, job)
        log.write(f"[TEC-TAC-UPDATE] started {now()} component={component} version={job.get('version')} source={job.get('source')}\n")
        log.flush()

        if not target.is_dir():
            raise RuntimeError(f"installed component root is missing: {target}")
        # 1.17.98 (review round 6): the installed version comes from root-held state (runtime VERSION, deployed UI VERSION or
        # provenance), never from the Tactical-owned checkout. It drives the downgrade gate, the backup name and the version a
        # rollback must verify. The checkout's VERSION is recorded for display only and must agree before anything changes.
        old_version = installed_version(component, cfg) or "unknown"
        job["installed_version"] = old_version
        job["source_checkout_version"] = _read_version_file(target) or "unknown"  # 1.17.67: the version installed before this update; Core's audit row says "1.17.16 -> 1.17.17"
        runtime_root = Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")).resolve()
        previous_provenance = _read_provenance(component)
        dynamic_inventory = {}
        git_state = None
        backup = None
        installer_started = False
        commit = _source_commit(job.get("source"))
        try:
            job["stage"] = "extract"
            atomic_json(path, job)
            with private_update_work_dir(job_id) as work:
                extract_archive(package, work)
                source = detect_root(work, component)
                detached_manifest = Path(str(job.get("release_manifest_path") or "")) if job.get("release_manifest_path") else None
                detached_signature = Path(str(job.get("release_signature_path") or "")) if job.get("release_signature_path") else None
                if (detached_manifest is None) != (detached_signature is None):
                    raise RuntimeError("detached signed update sidecars are incomplete")
                if detached_manifest is not None and detached_signature is not None:
                    manifest_target = source / TREE_MANIFEST
                    signature_target = source / TREE_SIGNATURE
                    if manifest_target.exists() or signature_target.exists():
                        raise RuntimeError("signed release metadata is ambiguous between archive and detached uploads")
                    shutil.copyfile(detached_manifest, manifest_target)
                    shutil.copyfile(detached_signature, signature_target)
                    os.chmod(manifest_target, 0o600)
                    os.chmod(signature_target, 0o600)
                package_version = (source / "VERSION").read_text(encoding="utf-8").strip()
                job["version"] = package_version
                job["stage"] = "root-verify-staged"
                atomic_json(path, job)
                trust = _root_verify_tree(cfg, source, component)
                job["release_trust"] = trust
                log.write(f"[TEC-TAC-UPDATE] root verified staged tree publisher={trust.get('publisher_id','')} key={trust.get('key_id','')} level={trust.get('root_policy',{}).get('actual_level')}\n")
                if trust.get("root_policy", {}).get("development_unsigned_override"):
                    log.write("[TEC-TAC-SECURITY] WARNING: unsigned system update accepted by root-owned DEVELOPMENT override.\n")
                log.flush()

                installed_key = _version_key(old_version)
                requested_key = _version_key(package_version)
                if old_version == "unknown" and not (bool(job.get("allow_downgrade")) and str(cfg.get("TEC_TAC_ALLOW_SYSTEM_DOWNGRADES") or "").strip().lower() in {"1", "true", "yes", "on"}):
                    raise RuntimeError(f"the installed {component} version cannot be read from root-held state, so the downgrade policy cannot be checked; "
                                       "nothing was changed. Reinstall the component from the command line, or request a controlled downgrade.")
                if requested_key < installed_key:
                    if not bool(job.get("allow_downgrade")):
                        raise RuntimeError("downgrade requires explicit allow_downgrade request")
                    root_allow = str(cfg.get("TEC_TAC_ALLOW_SYSTEM_DOWNGRADES") or "").strip().lower() in {"1", "true", "yes", "on"}
                    if not root_allow:
                        raise RuntimeError("system downgrade is blocked by root-owned policy; set TEC_TAC_ALLOW_SYSTEM_DOWNGRADES=true in the root-owned Tec-Tac config for a controlled downgrade")

                # Spec steps 3 and 4 (1.17.98): one owner for the whole checkout, then a clean checkout at its own HEAD.
                # Tracked changes are logged and restored as the Tactical account; the source is never given to root.
                job["stage"] = "source-prepare"
                atomic_json(path, job)
                git_state = prepare_source_checkout(target, component, cfg, log)
                job["source_git"] = {"head": git_state["head"], "branch": git_state["branch"]}
                if git_state["restored_changes"]:
                    job["source_restored_changes"] = git_state["restored_changes"]
                # The checkout at HEAD is what the backup (the rollback copy) holds, so it must be the installed release.
                checkout_now = _read_version_file(target) or "unknown"
                job["source_checkout_version"] = checkout_now
                if old_version != "unknown" and checkout_now != old_version:
                    raise RuntimeError(f"{component} source checkout is at version {checkout_now}, but the installed {component} is {old_version} "
                                       "(root-held record). Move the checkout back to the installed release (git checkout as the Tactical account), "
                                       "then update again. Nothing was installed.")

                job["stage"] = "backup"
                atomic_json(path, job)
                backup = backup_root(target, component, old_version, job_id)
                job["backup_path"] = str(backup)
                atomic_json(path, job)
                log.write(f"[TEC-TAC-UPDATE] backup={backup}\n")
                log.flush()

                # Spec step 5: the exact commit the candidate came from, with no second branch lookup.
                if commit:
                    job["stage"] = "source-commit"
                    atomic_json(path, job)
                    git_state["moved"] = True
                    move_source_to_commit(target, component, job.get("source"), cfg, log)
                    job["source_git"]["commit"] = commit
                    checkout_version = _read_version_file(target)
                    if checkout_version != package_version:
                        raise RuntimeError(f"{component} source checkout at {commit[:12]} is version {checkout_version or 'unknown'}, but the verified package is {package_version}")
                else:
                    log.write(f"[TEC-TAC-UPDATE] offline package with no commit: the {component} source checkout stays at {git_state['head'][:12]}\n")
                    log.flush()

                # Spec step 6, staging model: root copies the tree into a root-only staging directory, the privileged verifier
                # checks that copy against the signed manifest, and only then the component's own installer runs, from the copy.
                job["stage"] = "root-verify-execution"
                atomic_json(path, job)
                with install_stage(job_id, "install") as stage_dir:
                    stage_from = target if commit and trust.get("signed") else source
                    staged = stage_release_tree(stage_from, stage_dir / "tree", component, allow_unsigned=not trust.get("signed"))
                    execution_trust = verify_staged_tree(cfg, staged, component, against=trust, expected_version=package_version)
                    ui_tools = capture_ui_sync_tools(staged) if component == "ui" else None
                    job["release_trust"] = execution_trust
                    log.write(f"[TEC-TAC-UPDATE] root verified the staged execution tree files={execution_trust.get('file_count', 0)} from={'source checkout' if stage_from == target else 'package'} commit={commit or 'none'}\n")
                    log.flush()
                    if component == "framework":
                        dynamic_inventory = snapshot_dynamic_plugins(runtime_root)

                    job["stage"] = "install"
                    atomic_json(path, job)
                    log.write(f"[TEC-TAC-UPDATE] running {component} installer from the verified staging copy\n")
                    log.flush()
                    installer_started = True
                    rc = run_install(component, staged, log, source_checkout=target)
                    if component == "ui" and rc == 0:
                        publish_ui_sync_tools(ui_tools, log)
                if component == "framework":
                    repin_framework_source(target, log)
                if rc == INSTALL_REFUSED_EXIT:
                    raise _UpdateRefused(_installer_refusal_reason(log_path))
                if rc != 0:
                    raise RuntimeError(f"{component} installer exited with status {rc}")

            # Spec steps 7 to 9: runtime ownership, provenance, a clean Tactical-owned source.
            job["stage"] = "verify"
            atomic_json(path, job)
            verify(component, runtime_root, str(job.get("version")), log)
            if component == "framework":
                verify_dynamic_plugins(runtime_root, dynamic_inventory)
                enforce_runtime_ownership(cfg, log)
            verify_source_runtime_layout(component, target, cfg, expected_head=commit or git_state["head"])
            source_info = job.get("source") if isinstance(job.get("source"), dict) else {}
            provenance = {"component": component, "version": str(job.get("version")), "type": source_info.get("type", "offline"),
                          "repository": source_info.get("repository"), "ref": source_info.get("ref"), "commit": commit,
                          "job_id": job_id, "recorded_at": now()}
            job["installed_provenance"] = provenance
            write_provenance(component, provenance, result_gid)
            log.write(f"[TEC-TAC-UPDATE] provenance repository={provenance['repository']} ref={provenance['ref']} commit={commit or 'none (offline)'}\n")
            job["rollback"] = {"performed": False, "status": "not-required"}
            job["status"] = "succeeded"
            job["stage"] = "complete"
            job["finished_at"] = now()
            job["error"] = None
            job["error_type"] = None
            log.write(f"[TEC-TAC-UPDATE] completed {now()}\n")
        except Exception as exc:
            log.write(f"[TEC-TAC-UPDATE] update failed: {exc}\n")
            log.flush()
            job["error"] = str(exc)
            job["error_type"] = exc.__class__.__name__
            rollback_error = None
            refused = isinstance(exc, _UpdateRefused)
            if refused or not installer_started:
                # 1.17.43: the installer's pre-flight refused before it changed anything; 1.17.98: or the update stopped before the
                # installer ran. Nothing was installed, so no installer runs now. Only the source checkout goes back to its old HEAD.
                if refused:
                    job["error"] = f"The installer refused the update before changing anything: {exc.reason}. The installed version is unchanged."
                    job["error_type"] = "InstallerRefused"
                    log.write("[TEC-TAC-UPDATE] update refused by the installer pre-flight; nothing was installed; restoring the source checkout only\n")
                elif git_state:
                    log.write("[TEC-TAC-UPDATE] update stopped before the installer ran; restoring the source checkout only\n")
                log.flush()
                reason = "installer-refused" if refused else "before-install"
                if git_state:
                    job["stage"] = "rollback"
                    atomic_json(path, job)
                    try:
                        restore_source_checkout(target, component, git_state, cfg)
                        job["rollback"] = {"performed": False, "status": "not-required", "reason": reason}
                        job["stage"] = "failed-pre-mutation"
                    except Exception as src_exc:
                        log.write(f"[TEC-TAC-UPDATE] SOURCE RESTORE FAILED: {src_exc}\n")
                        log.flush()
                        job["rollback"] = {"performed": True, "status": "failed", "version": old_version, "reason": reason, "error": str(src_exc)}
                        job["stage"] = "rollback-failed"
                else:
                    # Root verification or the downgrade policy failed before the checkout was touched. Nothing to roll back.
                    job["rollback"] = {"performed": False, "status": "not-required"}
                    job["stage"] = "failed-pre-mutation"
            else:
                log.write("[TEC-TAC-UPDATE] restoring previous component backup\n")
                log.flush()
                job["stage"] = "rollback"
                atomic_json(path, job)
                try:
                    if backup is None:
                        raise RuntimeError("rollback source is unavailable")
                    # 1.17.98: the old installer runs only from a root-only staging copy of the root-held backup that verifies
                    # against the signed release that was installed. It never runs from the checkout.
                    with install_stage(job_id, "rollback") as stage_dir:
                        restored_tree = extract_rollback_backup(backup, stage_dir / "backup", target)
                        staged = stage_release_tree(restored_tree, stage_dir / "tree", component)
                        verify_rollback_tree(cfg, staged, component, old_version)
                        ui_tools = capture_ui_sync_tools(staged) if component == "ui" else None
                        log.write(f"[TEC-TAC-UPDATE] rollback tree verified against the signed release {old_version}\n")
                        log.flush()
                        rollback_log_start = _log_size(log_path)
                        rollback_rc = run_install(component, staged, log, source_checkout=target)
                        if component == "ui" and rollback_rc == 0:
                            publish_ui_sync_tools(ui_tools, log)
                    if component == "framework":
                        repin_framework_source(target, log)
                    verification_warning = None
                    if rollback_rc != 0:
                        log.flush()
                        verification_warning = _rollback_verification_step(rollback_rc, log_path, rollback_log_start)
                        if verification_warning is None:
                            raise RuntimeError(f"rollback installer exited with status {rollback_rc}")
                    if component == "framework":
                        verify_dynamic_plugins(runtime_root, dynamic_inventory)
                        enforce_runtime_ownership(cfg, log)
                    restore_source_checkout(target, component, git_state, cfg)
                    verify_source_runtime_layout(component, target, cfg, expected_head=git_state["head"])
                    write_provenance(component, previous_provenance, result_gid)
                    if verification_warning is None:
                        job["rollback"] = {"performed": True, "status": "succeeded", "version": old_version}
                    else:
                        # 1.17.96: the files are restored and checked; only one of the installer's own checks reported a failure. A warning, not a failed rollback.
                        job["rollback"] = {
                            "performed": True, "status": "warning", "version": old_version, "warning": verification_warning,
                            "installer_exit_status": rollback_rc,
                            # 1.17.97: the installer stopped at that step, so what comes after it did not run
                            "incomplete_stages": ["helper scripts", "timers", "service restart"],
                            "restart": "systemctl restart rmm daphne celery celerybeat",
                            "advice": (f"{verification_warning} timed out, so the installer stopped there. The helper scripts, the timers and the restart of the "
                                       f"Tec-Tac services may not have run. Restart the services (rmm, daphne, celery, celerybeat) and check {verification_warning}."),
                        }
                        log.write(f"[TEC-TAC-UPDATE] restored {old_version}, verification warning: {verification_warning}\n")
                except Exception as rb_exc:
                    rollback_error = str(rb_exc)
                    job["rollback"] = {"performed": True, "status": "failed", "version": old_version, "error": rollback_error}
                    log.write(f"[TEC-TAC-UPDATE] ROLLBACK FAILED: {rollback_error}\n")
                    if git_state:
                        try:
                            restore_source_checkout(target, component, git_state, cfg)
                        except Exception as src_exc:
                            log.write(f"[TEC-TAC-UPDATE] SOURCE RESTORE FAILED: {src_exc}\n")
                job["stage"] = "rolled-back" if rollback_error is None else "rollback-failed"
            job["status"] = "failed"
            job["finished_at"] = now()
        finally:
            # Reuse the config-derived Tactical gid captured before the update
            # starts. Re-reading config/user identity here can fail after an
            # otherwise handled update error and leave the job stuck running.
            atomic_json(path, job, mode=0o640, uid=0, gid=result_gid)
            HISTORY_ROOT.mkdir(parents=True, exist_ok=True)
            atomic_json(HISTORY_ROOT / path.name, job, mode=0o640, uid=0, gid=result_gid)
            try:
                package.unlink(missing_ok=True)
            except OSError:
                pass
            for sidecar_key in ("release_manifest_path", "release_signature_path"):
                raw_sidecar = job.get(sidecar_key)
                if not raw_sidecar:
                    continue
                try:
                    Path(str(raw_sidecar)).unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                running_request_path(job_id).unlink(missing_ok=True)
            except OSError:
                pass
            try:
                os.chmod(log_path, 0o640)
            except OSError:
                pass


def mark_failed(job_id, error):
    try:
        path, job = load_job(job_id)
        if job.get("status") in {"succeeded", "failed"}:
            return
        job["status"] = "failed"
        job["finished_at"] = now()
        job["error"] = str(error) or error.__class__.__name__
        job["error_type"] = error.__class__.__name__
        atomic_json(path, job)
    except Exception:
        pass


def runtime_ownership_cli(action, root, framework, scripts):
    """install.sh calls this (1.17.98), so the installer applies and checks the same rule as the updater, rollback and restore."""
    targets = runtime_ownership_targets(root, framework, scripts)
    if action == "apply":
        count = apply_runtime_ownership(targets)
        print(f"[TEC-TAC] runtime ownership rule applied to {count} paths")
    problems = verify_runtime_ownership(targets)
    if problems:
        raise SystemExit("Tec-Tac runtime ownership verification failed: " + "; ".join(problems))
    print("[TEC-TAC] runtime ownership verified: framework, scripts and templates root:root 0755; VERSION and tec_tac_package.json root:root 0644")


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if len(sys.argv) >= 3 and sys.argv[1] == "--set-trust-policy":
        level = sys.argv[2]
        actor = sys.argv[3] if len(sys.argv) >= 4 else ""
        try:
            print(json.dumps(set_root_trust_policy(level, actor), sort_keys=True))
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif len(sys.argv) >= 3 and sys.argv[1] == "--set-account-security-policy":
        value = sys.argv[2]
        actor = sys.argv[3] if len(sys.argv) >= 4 else ""
        try:
            print(json.dumps(set_root_account_security_policy(value, actor), sort_keys=True))
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif len(sys.argv) == 6 and sys.argv[1] == "--runtime-ownership" and sys.argv[2] in {"apply", "verify"}:
        try:
            runtime_ownership_cli(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif len(sys.argv) == 2 and sys.argv[1] == "--publish-ui-sync":
        try:
            publish_ui_sync_from_checkout()
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif len(sys.argv) in {3, 4} and sys.argv[1] == "--install-restored":
        try:
            install_restored_component(sys.argv[2], expected=sys.argv[3] if len(sys.argv) == 4 else None)
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    elif len(sys.argv) == 3 and sys.argv[1] in {"--dispatch", "--run"}:
        if sys.argv[1] == "--dispatch":
            dispatch(sys.argv[2])
        else:
            try:
                run_job(sys.argv[2])
            except BaseException as exc:
                mark_failed(sys.argv[2], exc)
                raise
    else:
        raise SystemExit("usage: tec-tac-system-update --dispatch|--run <job-id> | --set-trust-policy <level> [actor] | --set-account-security-policy <true|false> [actor] | --runtime-ownership apply|verify <root> <framework> <scripts> | --install-restored framework|ui [version] | --publish-ui-sync")
