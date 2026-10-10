#!/usr/bin/python3
"""Root-owned worker for durable Core server-maintenance jobs.

The helper executes only administrator-registered manifests.  It never accepts
a command, shell text, environment or executable path from a module request.
"""
from __future__ import annotations

import fcntl
import grp
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
CONFIG_POINTER = Path("/etc/tec-tac/config-path")


def _installed_config_path(pointer=CONFIG_POINTER, default=DEFAULT_CONFIG):
    try:
        st = pointer.lstat()
    except FileNotFoundError:
        return default
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"Tec-Tac config-path pointer is not a regular file: {pointer}")
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise RuntimeError(f"Tec-Tac config-path pointer must be root-owned and not group/world writable: {pointer}")
    raw = pointer.read_text(encoding="utf-8").strip()
    path = Path(raw)
    if not raw or "\n" in raw or "\r" in raw or not path.is_absolute():
        raise RuntimeError(f"Tec-Tac config-path pointer is invalid: {pointer}")
    return path


CONFIG = _installed_config_path()
DEFAULT_STATE_ROOT = Path("/var/lib/tec-tac/server-maintenance")
DEFAULT_REGISTRY_ROOT = Path("/etc/tec-tac/server-maintenance/actions.d")
DEFAULT_ACTION_ROOT = Path("/usr/local/lib/tec-tac/server-maintenance/actions")
DEFAULT_EXTENSIONS_ROOT = Path("/opt/tec-tac/extensions")


def _root_owned_layout():
    """Load helper trust roots from one verified, no-follow config descriptor."""
    values = {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(CONFIG, flags)
    except FileNotFoundError:
        return values
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"Tec-Tac config is not a regular file: {CONFIG}")
        if st.st_uid != 0 or (st.st_mode & 0o022):
            raise RuntimeError(f"Tec-Tac config must be root-owned and not group/world writable: {CONFIG}")
        with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    finally:
        os.close(fd)
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _trusted_root(layout, key, default):
    raw = str(layout.get(key) or default)
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeError(f"{key} must be an absolute path in the root-owned Tec-Tac config")
    return path


_ROOT_LAYOUT_ERROR = None
try:
    _ROOT_LAYOUT = _root_owned_layout()
    STATE_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_ROOT", DEFAULT_STATE_ROOT)
    REGISTRY_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT", DEFAULT_REGISTRY_ROOT)
    ACTION_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_ACTION_ROOT", DEFAULT_ACTION_ROOT)
    EXTENSIONS_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_EXTENSIONS_ROOT", DEFAULT_EXTENSIONS_ROOT)
except (OSError, UnicodeError, RuntimeError, ValueError) as exc:
    # Keep imports/diagnostics safe while ensuring every privileged operation
    # fails closed through load_config() when the root-owned config is invalid.
    _ROOT_LAYOUT = {}
    _ROOT_LAYOUT_ERROR = exc
    STATE_ROOT = DEFAULT_STATE_ROOT
    REGISTRY_ROOT = DEFAULT_REGISTRY_ROOT
    ACTION_ROOT = DEFAULT_ACTION_ROOT
    EXTENSIONS_ROOT = DEFAULT_EXTENSIONS_ROOT
JOBS_ROOT = STATE_ROOT / "jobs"
CANCEL_ROOT = STATE_ROOT / "cancel-requests"
LOGS_ROOT = STATE_ROOT / "logs"
RUNNING_ROOT = STATE_ROOT / "running"
AUDIT_FILE = STATE_ROOT / "audit.jsonl"
LOCK_FILE = STATE_ROOT / "server-maintenance.lock"
ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ALLOWED_PARAMETER_TYPES = {"string", "integer", "boolean", "enum"}
# 1.17.17: an action manifest may carry the Tec-Tac permission a caller needs (checked by Core's Python side) and the owning module
PERMISSION_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,149}$")
OWNER_MODULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
# 1.17.17: actions a signed module registers from its manifest (--register-module). Everything below is root-only.
MODULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODULE_ACTIONS_KEY = "server_maintenance_actions"
MODULE_ACTIONS_MAX = 16
MODULE_EXECUTABLE_PREFIX = "server_maintenance/actions/"
MODULE_REGISTER_PERMISSION = "server_maintenance.register"
MODULE_ACTION_KEYS = frozenset({"id", "description", "permission", "executable", "argv", "parameters", "timeout_seconds", "success_exit_codes", "revision", "protected"})
MAX_MODULE_MANIFEST_BYTES = 1024 * 1024
MAX_MODULE_EXECUTABLE_BYTES = 64 * 1024 * 1024
ROOT_UID = 0
_cancel_requested = False
_child = None


def now():
    return datetime.now(timezone.utc).isoformat()


def load_config():
    if _ROOT_LAYOUT_ERROR is not None:
        raise RuntimeError(f"Tec-Tac config is invalid: {_ROOT_LAYOUT_ERROR}") from _ROOT_LAYOUT_ERROR
    return dict(_ROOT_LAYOUT)


def tactical_gid():
    cfg = load_config()
    user = cfg.get("TACTICAL_USER", "tactical")
    try:
        import pwd
        return pwd.getpwnam(user).pw_gid
    except KeyError:
        return os.getgid()


def ensure_layout():
    gid = tactical_gid()
    for path, mode in ((STATE_ROOT, 0o2750), (JOBS_ROOT, 0o2770), (CANCEL_ROOT, 0o2770), (LOGS_ROOT, 0o2750), (RUNNING_ROOT, 0o700)):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(path, 0, 0 if path == RUNNING_ROOT else gid)
        except PermissionError:
            pass
        os.chmod(path, mode)
    REGISTRY_ROOT.mkdir(parents=True, exist_ok=True)
    ACTION_ROOT.mkdir(parents=True, exist_ok=True)


def atomic_json(path, payload, mode=0o640, *, uid=None, gid=None):
    """Atomically write JSON without following attacker-controlled temp symlinks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        data = (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")
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


def mirror_job(job):
    atomic_json(job_path(job["id"]), job, mode=0o640, uid=0 if os.geteuid() == 0 else None, gid=tactical_gid() if os.geteuid() == 0 else None)


def claimed_dir(job_id):
    if not JOB_RE.fullmatch(str(job_id or "")):
        raise RuntimeError("invalid job id")
    return RUNNING_ROOT / str(job_id)


def claimed_job_path(job_id):
    return claimed_dir(job_id) / "job.json"


def _read_json_nofollow(path):
    # O_NONBLOCK prevents a malicious FIFO/device substitution from hanging a
    # privileged helper before fstat() can reject the non-regular object.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"state file is not a regular file: {path}")
        with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
            return json.load(handle)
    finally:
        os.close(fd)


def claim_job(job_id):
    source = job_path(job_id)
    try:
        job = _read_json_nofollow(source)
    except FileNotFoundError as exc:
        raise RuntimeError("job not found") from exc
    if not isinstance(job, dict) or str(job.get("id")) != str(job_id):
        raise RuntimeError("job file is invalid")
    root = claimed_dir(job_id)
    root.mkdir(parents=True, exist_ok=False)
    if os.geteuid() == 0:
        os.chown(root, 0, 0)
    os.chmod(root, 0o700)
    path = claimed_job_path(job_id)
    atomic_json(path, job, mode=0o600, uid=0 if os.geteuid() == 0 else None, gid=0 if os.geteuid() == 0 else None)
    return path, job


def load_claimed_job(job_id):
    path = claimed_job_path(job_id)
    try:
        job = _read_json_nofollow(path)
    except FileNotFoundError as exc:
        raise RuntimeError("claimed job not found") from exc
    if not isinstance(job, dict) or str(job.get("id")) != str(job_id):
        raise RuntimeError("claimed job is invalid")
    return path, job


def write_claimed_job(path, job, **changes):
    job.update(changes)
    atomic_json(path, job, mode=0o600, uid=0 if os.geteuid() == 0 else None, gid=0 if os.geteuid() == 0 else None)
    mirror_job(job)
    return job


def append_audit(event, *, job=None, detail=None):
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    row = {
        "at": now(),
        "event": str(event),
        "job_id": str((job or {}).get("id") or "") or None,
        "action": str((job or {}).get("action") or "") or None,
        "context": dict((job or {}).get("context") or {}),
        "status": (job or {}).get("status"),
        "detail": detail or {},
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    os.chmod(AUDIT_FILE, 0o640)


def job_path(job_id):
    if not JOB_RE.fullmatch(str(job_id or "")):
        raise RuntimeError("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    try:
        job = _read_json_nofollow(path)
    except FileNotFoundError as exc:
        raise RuntimeError("job not found") from exc
    if not isinstance(job, dict) or str(job.get("id")) != str(job_id):
        raise RuntimeError("job file is invalid")
    return path, job


def update_job(path, job, **changes):
    job.update(changes)
    if path.parent == JOBS_ROOT:
        mirror_job(job)
    else:
        atomic_json(path, job)
    return job


def validate_executable(path_value):
    raw = Path(str(path_value or ""))
    if not raw.is_absolute():
        raise RuntimeError("registered action executable must be an absolute path")
    if raw.is_symlink():
        raise RuntimeError("registered action executable may not be a symlink")
    resolved = raw.resolve(strict=True)
    action_root = ACTION_ROOT.resolve(strict=True)
    try:
        resolved.relative_to(action_root)
    except ValueError as exc:
        raise RuntimeError("registered action executable must live below the Core action root") from exc
    st = resolved.stat()
    if not resolved.is_file() or st.st_uid != 0 or (st.st_mode & 0o022) or not os.access(resolved, os.X_OK):
        raise RuntimeError("registered action executable must be root-owned, executable, and not group/world writable")
    return resolved


def validate_manifest(payload, *, require_executable=True):
    if not isinstance(payload, dict):
        raise RuntimeError("action manifest must be a JSON object")
    action_id = str(payload.get("id") or "").strip()
    if not ACTION_ID_RE.fullmatch(action_id):
        raise RuntimeError("action id is invalid")
    executable = validate_executable(payload.get("executable")) if require_executable else Path(str(payload.get("executable") or ""))
    argv = payload.get("argv") or []
    if not isinstance(argv, list) or len(argv) > 64:
        raise RuntimeError("action argv must be an array with at most 64 entries")
    schema = payload.get("parameters") or {}
    if not isinstance(schema, dict) or len(schema) > 64:
        raise RuntimeError("action parameters must be an object with at most 64 entries")
    for name, spec in schema.items():
        if not ACTION_ID_RE.fullmatch(str(name or "")):
            raise RuntimeError(f"parameter name {name!r} is invalid")
        if not isinstance(spec, dict):
            raise RuntimeError(f"parameter {name!r} schema must be an object")
        ptype = str(spec.get("type") or "string")
        if ptype not in ALLOWED_PARAMETER_TYPES:
            raise RuntimeError(f"parameter {name!r} has unsupported type")
        if ptype == "enum" and (not isinstance(spec.get("choices"), list) or not spec.get("choices")):
            raise RuntimeError(f"enum parameter {name!r} requires choices")
        if "pattern" in spec:
            re.compile(str(spec["pattern"]))
    for item in argv:
        if isinstance(item, str):
            if "\x00" in item or len(item) > 4096:
                raise RuntimeError("registered literal argv entry is invalid")
        elif isinstance(item, dict) and set(item) == {"param"} and str(item["param"]) in schema:
            pass
        else:
            raise RuntimeError("registered argv entries must be literal strings or {'param': '<registered-name>'}")
    permission = payload.get("permission")
    if permission is not None and (not isinstance(permission, str) or not PERMISSION_CODE_RE.fullmatch(permission)):
        raise RuntimeError("action permission must be a Tec-Tac permission code")
    owner_module = payload.get("owner_module")
    if owner_module is not None and (not isinstance(owner_module, str) or not OWNER_MODULE_RE.fullmatch(owner_module)):
        raise RuntimeError("action owner_module must be a module id")
    timeout = int(payload.get("timeout_seconds") or 3600)
    if timeout < 1 or timeout > MAX_TIMEOUT_SECONDS:
        raise RuntimeError("action timeout_seconds is outside the allowed range")
    success_codes = payload.get("success_exit_codes", [0])
    if not isinstance(success_codes, list) or not success_codes or any(isinstance(v, bool) or not isinstance(v, int) for v in success_codes):
        raise RuntimeError("success_exit_codes must be a non-empty integer array")
    return {
        **payload,
        "id": action_id,
        "executable": str(executable),
        "argv": argv,
        "parameters": schema,
        "timeout_seconds": timeout,
        "success_exit_codes": success_codes,
        "revision": str(payload.get("revision") or "1"),
        "enabled": payload.get("enabled", True) is True,
    }


def verify_registered_executable_hash(manifest):
    """An action a module registered carries the SHA-256 of the executable Core copied (1.17.17). Dispatch and run read it back and
    compare, so an executable that changed since registration fails closed. A hotfix that changes an executable does not re-register,
    so the hash fails and the action stops until the module is installed again. Actions an administrator registered by hand carry no
    hash and are checked as before."""
    expected = manifest.get("executable_sha256")
    if manifest.get("registered_by") != "module-manifest" and expected is None:
        return
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise RuntimeError("registered action has no valid executable_sha256")
    actual = _sha256_nofollow(Path(manifest["executable"]))
    if not hmac.compare_digest(actual, expected):
        raise RuntimeError("registered action executable no longer matches its registered SHA-256; install the module again to register it")


def action_path(action_id):
    if not ACTION_ID_RE.fullmatch(str(action_id or "")):
        raise RuntimeError("invalid action id")
    return REGISTRY_ROOT / f"{action_id}.json"


def load_action(action_id):
    path = action_path(action_id)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("registered action is unavailable") from exc
    manifest = validate_manifest(payload)
    if manifest["id"] != str(action_id):
        raise RuntimeError("registered action id does not match its filename")
    if not manifest["enabled"]:
        raise RuntimeError("registered action is disabled")
    verify_registered_executable_hash(manifest)
    return manifest


def validate_parameters(action, raw):
    if not isinstance(raw, dict):
        raise RuntimeError("job parameters must be an object")
    schema = action["parameters"]
    unknown = sorted(set(raw) - set(schema))
    if unknown:
        raise RuntimeError("unknown action parameter(s): " + ", ".join(unknown))
    normalized = {}
    public = {}
    for name, spec in schema.items():
        if name in raw:
            value = raw[name]
        elif "default" in spec:
            value = spec["default"]
        elif spec.get("required", False):
            raise RuntimeError(f"required action parameter {name!r} is missing")
        else:
            continue
        ptype = str(spec.get("type") or "string")
        if ptype == "string":
            if not isinstance(value, str):
                raise RuntimeError(f"parameter {name!r} must be a string")
            max_length = max(1, min(int(spec.get("max_length", 4096)), 65536))
            if len(value) > max_length:
                raise RuntimeError(f"parameter {name!r} is too long")
            if spec.get("pattern") and not re.fullmatch(str(spec["pattern"]), value):
                raise RuntimeError(f"parameter {name!r} does not match its registered pattern")
        elif ptype == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise RuntimeError(f"parameter {name!r} must be an integer")
            if "minimum" in spec and value < int(spec["minimum"]):
                raise RuntimeError(f"parameter {name!r} is below its minimum")
            if "maximum" in spec and value > int(spec["maximum"]):
                raise RuntimeError(f"parameter {name!r} is above its maximum")
        elif ptype == "boolean":
            if not isinstance(value, bool):
                raise RuntimeError(f"parameter {name!r} must be true or false")
        elif ptype == "enum":
            if value not in spec.get("choices", []):
                raise RuntimeError(f"parameter {name!r} must be one of its registered choices")
        normalized[name] = value
        public[name] = "<redacted>" if bool(spec.get("sensitive", False)) else value
    return normalized, public


def render_argv(action, parameters):
    values = []
    for item in action["argv"]:
        if isinstance(item, str):
            values.append(item)
            continue
        name = str(item["param"])
        if name not in parameters:
            raise RuntimeError(f"registered argv requires omitted optional parameter {name!r}")
        value = parameters[name]
        if isinstance(value, bool):
            value = "true" if value else "false"
        values.append(str(value))
    return [str(action["executable"]), *values]


def register_manifest(source):
    source = Path(source).resolve(strict=True)
    payload = json.loads(source.read_text(encoding="utf-8"))
    manifest = validate_manifest(payload)
    ensure_layout()
    target = action_path(manifest["id"])
    atomic_json(target, manifest, mode=0o644)
    os.chown(target, 0, 0)
    append_audit("action.registered", detail={"action": manifest["id"], "revision": manifest["revision"]})
    print(target)


def unregister_manifest(action_id):
    path = action_path(action_id)
    if path.exists():
        path.unlink()
    append_audit("action.unregistered", detail={"action": str(action_id)})


# ---------------------------------------------------------------------------------------------------------------- module actions
def _untrusted(st):
    """Not root-owned, or writable by a group or anyone else (the test of privileged-trust._require_root_owned_nonwritable)."""
    return st.st_uid != ROOT_UID or bool(st.st_mode & 0o022)


def _module_id(value):
    if not isinstance(value, str) or not MODULE_ID_RE.fullmatch(value):
        raise RuntimeError("module id is invalid")
    return value


def _require_trusted_path(path, label, *, directory=False):
    """lstat, never follow: the path is a real file or directory, root-owned and not group or world writable."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} is not available: {path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise RuntimeError(f"{label} may not be a symlink: {path}")
    if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
        raise RuntimeError(f"{label} is not a {'directory' if directory else 'regular file'}: {path}")
    if _untrusted(st):
        raise RuntimeError(f"{label} must be root-owned and not group/world writable: {path}")


def _read_trusted_file(path, label, *, max_bytes):
    """Read one regular file with no symlink following. Its owner and mode are checked on the open descriptor, so a swap after
    the check cannot change what is read."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} is not readable: {path}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"{label} is not a regular file: {path}")
        if _untrusted(st):
            raise RuntimeError(f"{label} must be root-owned and not group/world writable: {path}")
        if st.st_size > max_bytes:
            raise RuntimeError(f"{label} is larger than {max_bytes} bytes: {path}")
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(max_bytes + 1)
    finally:
        os.close(fd)


def _sha256_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"registered action executable is not a regular file: {path}")
        digest = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _write_root_file(path, data, mode):
    """Atomically write root-owned bytes: unique temp file, mode and owner set before the rename, no symlink followed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _module_actions_from_manifest(module_id, payload):
    """The same rules registry.py applies when the package is installed, applied again here to the root-owned installed manifest
    (never to job metadata). Returns (version, actions)."""
    if str(payload.get("id", module_id)) != module_id:
        raise RuntimeError("installed manifest id does not match the module folder")
    if str(payload.get("type", "extension")) != "extension":
        raise RuntimeError("only an extension may register server-maintenance actions")
    raw = payload.get(MODULE_ACTIONS_KEY)
    version = str(payload.get("version", "0.0.0")).strip() or "0.0.0"
    if raw is None:
        return version, []
    if not isinstance(raw, list) or len(raw) > MODULE_ACTIONS_MAX:
        raise RuntimeError(f"{MODULE_ACTIONS_KEY} must be an array of at most {MODULE_ACTIONS_MAX} entries")
    if not raw:
        return version, []
    publisher = payload.get("publisher_permissions") or []
    if not isinstance(publisher, list) or MODULE_REGISTER_PERMISSION not in publisher:
        raise RuntimeError(f"module {module_id} must declare publisher_permissions {MODULE_REGISTER_PERMISSION!r} to register actions")
    groups = payload.get("permission_groups") or {}
    declared = {str(code) for codes in groups.values() if isinstance(codes, list) for code in codes} if isinstance(groups, dict) else set()
    actions, seen = [], set()
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) - MODULE_ACTION_KEYS:
            raise RuntimeError("a server-maintenance action entry must be an object with only the documented keys")
        action_id = entry.get("id")
        if not isinstance(action_id, str) or not ACTION_ID_RE.fullmatch(action_id):
            raise RuntimeError("a server-maintenance action id is invalid")
        if not action_id.startswith(module_id + ".") or action_id == module_id + ".":
            raise RuntimeError(f"action id {action_id!r} must start with {module_id + '.'!r}")
        if action_id in seen:
            raise RuntimeError(f"action {action_id!r} is declared twice")
        seen.add(action_id)
        permission = entry.get("permission")
        if not isinstance(permission, str) or permission not in declared:
            raise RuntimeError(f"action {action_id!r} needs a permission the module declares in permission_groups")
        executable = entry.get("executable")
        if not isinstance(executable, str) or not executable or "\x00" in executable or "\\" in executable or executable.startswith("/"):
            raise RuntimeError(f"action {action_id!r} executable must be a relative path inside the module folder")
        parts = executable.split("/")
        if any(part in ("", ".", "..") for part in parts) or not executable.startswith(MODULE_EXECUTABLE_PREFIX) or len(parts) < 3:
            raise RuntimeError(f"action {action_id!r} executable must be a file below {MODULE_EXECUTABLE_PREFIX}")
        protected = entry.get("protected", False)
        if not isinstance(protected, bool):
            raise RuntimeError(f"action {action_id!r} protected must be true or false")
        actions.append({**entry, "protected": protected})
    return version, actions


def _module_managed(action_id):
    """True when the registry file of this action was written by --register-module (not registered by hand)."""
    try:
        payload = json.loads(action_path(action_id).read_text(encoding="utf-8"))
    except (OSError, ValueError, RuntimeError):
        return False
    return isinstance(payload, dict) and payload.get("registered_by") == "module-manifest"


def _remove_owned_actions(module_id, *, keep=()):
    """Delete the registry files whose owner_module is this module, except the ids in ``keep``. Returns the removed ids."""
    removed = []
    if not REGISTRY_ROOT.is_dir():
        return removed
    for path in sorted(REGISTRY_ROOT.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("owner_module") != module_id:
            continue
        action_id = str(payload.get("id") or path.stem)
        if action_id in keep:
            continue
        path.unlink(missing_ok=True)
        removed.append(action_id)
        append_audit("action.unregistered", detail={"action": action_id, "module": module_id})
    return removed


def register_module(module_id):
    """Register the server-maintenance actions an installed module declares (1.17.17, ``--register-module <module-id>``).

    Reads ``<extensions root>/<module>/tec_tac.json``, which must be root-owned and not group or world writable, checks the
    declared actions again, copies each executable into the Core action root under ``<module-id>/`` as a root-owned 0755 file (an
    action never runs from the module folder), records the SHA-256, owner_module, permission and version in the registry JSON, and
    removes the registry files of this module that the manifest no longer declares, so an upgrade drops stale actions. Actions
    marked ``protected: true`` are not registered. Only the root module job helpers call this; the Tactical account's sudo rule
    does not reach it."""
    module_id = _module_id(module_id)
    ensure_layout()
    folder = EXTENSIONS_ROOT / module_id
    _require_trusted_path(folder, "installed module folder", directory=True)
    raw = _read_trusted_file(folder / "tec_tac.json", "installed module manifest", max_bytes=MAX_MODULE_MANIFEST_BYTES)
    if len(raw) > MAX_MODULE_MANIFEST_BYTES:
        raise RuntimeError("installed module manifest is too large")
    version, actions = _module_actions_from_manifest(module_id, json.loads(raw.decode("utf-8")))
    # Phase 1: read and check every executable before anything is changed.
    staged = []
    for action in actions:
        if action["protected"]:
            append_audit("action.skipped_protected", detail={"action": action["id"], "module": module_id})
            continue
        relative = action["executable"]
        current = folder
        parts = relative.split("/")
        for index, part in enumerate(parts):
            current = current / part
            _require_trusted_path(current, f"action {action['id']} executable path", directory=index < len(parts) - 1)
        data = _read_trusted_file(current, f"action {action['id']} executable", max_bytes=MAX_MODULE_EXECUTABLE_BYTES)
        if len(data) > MAX_MODULE_EXECUTABLE_BYTES:
            raise RuntimeError(f"action {action['id']} executable is too large")
        # The typed rules (argv, parameters, timeout, exit codes, permission) are applied before anything is copied.
        validate_manifest({
            "id": action["id"], "executable": str(ACTION_ROOT / module_id / relative[len(MODULE_EXECUTABLE_PREFIX):]), "argv": action.get("argv") or [],
            "parameters": action.get("parameters") or {}, "timeout_seconds": action.get("timeout_seconds", 3600),
            "success_exit_codes": action.get("success_exit_codes", [0]), "permission": action["permission"], "owner_module": module_id,
        }, require_executable=False)
        existing = action_path(action["id"])
        if existing.is_file():
            try:
                owner = json.loads(existing.read_text(encoding="utf-8")).get("owner_module")
            except (OSError, ValueError):
                owner = None
            if isinstance(owner, str) and owner and owner != module_id:
                raise RuntimeError(f"action {action['id']} is already registered by module {owner}")
        staged.append((action, relative[len(MODULE_EXECUTABLE_PREFIX):], data))
    # Phase 2: copy the executables, then write the registry files (atomic, root-owned), then drop what the manifest dropped.
    target_root = ACTION_ROOT / module_id
    target_root.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(target_root, 0, 0)
    os.chmod(target_root, 0o755)
    registered, wanted_files = [], set()
    for action, subpath, data in staged:
        target = target_root / subpath
        if not target.resolve().is_relative_to(target_root.resolve()):
            raise RuntimeError(f"action {action['id']} executable would leave the module action folder")
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_root_file(target, data, 0o755)
        wanted_files.add(target.resolve())
        manifest = validate_manifest({
            "id": action["id"], "revision": str(action.get("revision") or "1"), "description": str(action.get("description") or ""),
            "executable": str(target), "argv": action.get("argv") or [], "parameters": action.get("parameters") or {},
            "timeout_seconds": action.get("timeout_seconds", 3600), "success_exit_codes": action.get("success_exit_codes", [0]), "enabled": True,
            "permission": action["permission"], "owner_module": module_id, "owner_version": version,
            "executable_sha256": hashlib.sha256(data).hexdigest(), "registered_by": "module-manifest",
        })
        _write_root_file(action_path(action["id"]), (json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8"), 0o644)
        append_audit("action.registered", detail={"action": manifest["id"], "revision": manifest["revision"], "module": module_id, "module_version": version,
                                                   "executable_sha256": manifest["executable_sha256"], "permission": manifest["permission"]})
        registered.append(manifest["id"])
    # Stale actions: the registry files this module owns that the manifest no longer declares. A protected action stays only when an
    # administrator registered it by hand; one an earlier version registered from the manifest is dropped.
    keep = {action["id"] for action in actions if not action["protected"]}
    keep |= {action["id"] for action in actions if action["protected"] and not _module_managed(action["id"])}
    removed = _remove_owned_actions(module_id, keep=keep)
    # Stale executables: nothing under the module's action folder that no registered action points at.
    for path in sorted(target_root.rglob("*"), reverse=True):
        if path.is_file() or path.is_symlink():
            if path.resolve() not in wanted_files:
                path.unlink(missing_ok=True)
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass
    append_audit("module.actions_registered", detail={"module": module_id, "module_version": version, "actions": registered, "removed": removed})
    print(",".join(registered))


def unregister_module(module_id):
    """Remove every action and executable a module owns (1.17.17, ``--unregister-module <module-id>``): the registry files whose
    owner_module is the module and the module's own folder under the Core action root. Nothing of another module's."""
    module_id = _module_id(module_id)
    removed = _remove_owned_actions(module_id)
    folder = ACTION_ROOT / module_id
    if folder.is_symlink():
        folder.unlink()
    elif folder.is_dir():
        shutil.rmtree(folder)
    append_audit("module.actions_unregistered", detail={"module": module_id, "actions": removed})
    print(",".join(removed))


def _systemd_unit(job_id):
    return "tec-tac-server-maintenance-" + str(job_id)


def dispatch(job_id):
    ensure_layout()
    public_path = job_path(job_id)
    try:
        path, job = claim_job(job_id)
    except FileExistsError as exc:
        raise RuntimeError("job has already been claimed") from exc
    if job.get("status") != "queued":
        raise RuntimeError("job is not queued")
    try:
        action = load_action(str(job.get("action") or ""))
        if str(job.get("action_revision") or "1") != action["revision"]:
            raise RuntimeError("registered action revision changed after the job was created")
        normalized, public = validate_parameters(action, job.get("parameters") or {})
        job["parameters"] = normalized
        job["public_parameters"] = public
    except Exception as exc:
        write_claimed_job(path, job,
            status="failed", stage="validation", finished_at=now(),
            failure={"classification":"validation_failed","message":str(exc),"error_type":exc.__class__.__name__},
        )
        append_audit("job.validation_failed", job=job, detail={"message": str(exc)})
        raise

    write_claimed_job(path, job, status="dispatched", stage="dispatched", unit=_systemd_unit(job_id))
    append_audit("job.dispatched", job=job)
    command = [
        "systemd-run",
        "--quiet",
        "--unit", _systemd_unit(job_id),
        "--collect",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=30s",
        str(Path(__file__).resolve()), "--run", str(job_id),
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=20)
    except Exception as exc:
        write_claimed_job(path, job,
            status="dispatch_failed", stage="dispatch", finished_at=now(),
            failure={"classification":"dispatch_failed","message":str(getattr(exc,"stderr","") or exc),"error_type":exc.__class__.__name__},
        )
        append_audit("job.dispatch_failed", job=job, detail={"message": str(exc)})
        raise


def _signal_cancel(signum, frame):
    global _cancel_requested, _child
    _cancel_requested = True
    child = _child
    if child is not None and child.poll() is None:
        try:
            child.terminate()
        except Exception:
            pass


def run_job(job_id):
    global _child, _cancel_requested
    ensure_layout()
    path, job = load_claimed_job(job_id)
    if job.get("status") not in {"dispatched", "waiting_for_lock", "running", "cancelling"}:
        raise RuntimeError("job is not in a runnable state")
    action = load_action(str(job.get("action") or ""))
    if str(job.get("action_revision") or "1") != action["revision"]:
        raise RuntimeError("registered action revision changed after dispatch")
    parameters, public = validate_parameters(action, job.get("parameters") or {})
    job["parameters"] = parameters
    job["public_parameters"] = public

    signal.signal(signal.SIGTERM, _signal_cancel)
    signal.signal(signal.SIGINT, _signal_cancel)
    lock_handle = LOCK_FILE.open("a+")
    write_claimed_job(path, job, status="waiting_for_lock", stage="waiting_for_lock", lock={"scope":"global","state":"waiting","acquired_at":None})
    append_audit("job.waiting_for_lock", job=job)
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    except Exception as exc:
        write_claimed_job(path, job, status="failed", stage="lock", finished_at=now(), failure={"classification":"lock_failed","message":str(exc),"error_type":exc.__class__.__name__})
        append_audit("job.lock_failed", job=job, detail={"message": str(exc)})
        raise

    current = load_claimed_job(job_id)[1]
    if current.get("cancel_requested_at") or _cancel_requested:
        write_claimed_job(path, current, status="cancelled", stage="cancelled", finished_at=now(), lock={"scope":"global","state":"released","acquired_at":None}, exit_result={"success":False,"exit_code":None,"signal":None,"timed_out":False}, failure={"classification":"cancelled","message":"Job was cancelled before execution."})
        append_audit("job.cancelled", job=current, detail={"before_execution": True})
        return

    acquired = now()
    job = current
    write_claimed_job(path, job, status="running", stage="running", started_at=job.get("started_at") or acquired, lock={"scope":"global","state":"acquired","acquired_at":acquired})
    append_audit("job.started", job=job)

    stdout_path = LOGS_ROOT / f"{job_id}.stdout.log"
    stderr_path = LOGS_ROOT / f"{job_id}.stderr.log"
    lifecycle_path = LOGS_ROOT / f"{job_id}.log"
    for output_path in (stdout_path, stderr_path, lifecycle_path):
        output_path.touch(exist_ok=True)
        os.chmod(output_path, 0o640)
        if os.geteuid() == 0:
            os.chown(output_path, 0, tactical_gid())
    argv = render_argv(action, parameters)
    timeout = int(action["timeout_seconds"])
    timed_out = False
    exit_code = None
    term_signal = None
    try:
        with lifecycle_path.open("a", encoding="utf-8") as lifecycle, stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
            lifecycle.write(f"[{now()}] action={action['id']} revision={action['revision']} started\n")
            lifecycle.flush()
            _child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True)
            deadline = time.monotonic() + timeout
            while _child.poll() is None:
                if _cancel_requested:
                    try: _child.terminate()
                    except Exception: pass
                if time.monotonic() >= deadline:
                    timed_out = True
                    try: _child.terminate()
                    except Exception: pass
                    try: _child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try: _child.kill()
                        except Exception: pass
                    break
                time.sleep(0.25)
            exit_code = _child.wait()
            if exit_code is not None and exit_code < 0:
                term_signal = -exit_code
            lifecycle.write(f"[{now()}] exit_code={exit_code} timed_out={timed_out} cancel_requested={_cancel_requested}\n")
            lifecycle.flush()
    except Exception as exc:
        job = load_claimed_job(job_id)[1]
        write_claimed_job(path, job,
            status="failed", stage="failed", finished_at=now(),
            lock={"scope":"global","state":"released","acquired_at":acquired},
            exit_result={"success":False,"exit_code":exit_code,"signal":term_signal,"timed_out":timed_out},
            failure={"classification":"worker_error","message":str(exc),"error_type":exc.__class__.__name__},
        )
        append_audit("job.failed", job=job, detail={"classification":"worker_error","message":str(exc)})
        raise
    finally:
        _child = None
        try: fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        except Exception: pass
        lock_handle.close()

    job = load_claimed_job(job_id)[1]
    cancelled = bool(job.get("cancel_requested_at")) or _cancel_requested
    success = (exit_code in set(action["success_exit_codes"])) and not timed_out and not cancelled
    if cancelled:
        status, stage = "cancelled", "cancelled"
        failure = {"classification":"cancelled","message":"Job was cancelled."}
    elif timed_out:
        status, stage = "failed", "failed"
        failure = {"classification":"timeout","message":f"Registered action exceeded {timeout} seconds."}
    elif success:
        status, stage, failure = "succeeded", "complete", None
    else:
        status, stage = "failed", "failed"
        failure = {"classification":"execution_failed","message":f"Registered action exited with status {exit_code}."}
    write_claimed_job(path, job,
        status=status, stage=stage, finished_at=now(),
        lock={"scope":"global","state":"released","acquired_at":acquired},
        exit_result={"success":success,"exit_code":exit_code,"signal":term_signal,"timed_out":timed_out},
        failure=failure,
    )
    append_audit("job.finished", job=job, detail={"status":status,"classification":failure.get("classification") if failure else None,"exit_code":exit_code})


def cancel_job(job_id):
    ensure_layout()
    legacy_public_only = False
    try:
        path, job = load_claimed_job(job_id)
    except RuntimeError:
        # Jobs dispatched by pre-claim Core releases have only the public job
        # record.  They still use the UUID-derived systemd unit, so cancellation
        # can safely stop that exact unit without trusting mutable argv/action
        # fields from the legacy public record.
        path, job = load_job(job_id)
        if job.get("status") in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
            return
        legacy_public_only = True
    cancel_context = None
    cancel_request = CANCEL_ROOT / f"{job_id}.json"
    if cancel_request.is_file() and not cancel_request.is_symlink():
        try:
            payload = _read_json_nofollow(cancel_request)
            if isinstance(payload, dict) and str(payload.get("job_id")) == str(job_id) and isinstance(payload.get("context"), dict):
                cancel_context = dict(payload["context"])
        except (OSError, ValueError, json.JSONDecodeError, RuntimeError):
            cancel_context = None
        cancel_request.unlink(missing_ok=True)
    if job.get("status") in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
        return
    requested_at = now()
    writer = update_job if legacy_public_only else write_claimed_job
    writer(path, job, status="cancelling", stage="cancelling", cancel_requested_at=requested_at, cancel_context=cancel_context)
    append_audit("job.cancel_requested", job=job, detail={"cancel_context": cancel_context or {}, "legacy_public_only": legacy_public_only})
    # Never trust a mutable legacy job's unit name.  Server-maintenance units
    # are always derived from the validated UUID.
    unit = _systemd_unit(job_id)
    result = subprocess.run(["systemctl", "stop", unit], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        current = (load_job(job_id)[1] if legacy_public_only else load_claimed_job(job_id)[1])
        if current.get("status") not in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
            writer(path, current, status="failed", stage="cancel", finished_at=now(), failure={"classification":"cancel_failed","message":(result.stderr or "Unable to stop maintenance unit.").strip()})
            append_audit("job.cancel_failed", job=current, detail={"message": result.stderr.strip()})
            raise RuntimeError((result.stderr or "Unable to stop maintenance unit.").strip())
    current = (load_job(job_id)[1] if legacy_public_only else load_claimed_job(job_id)[1])
    if current.get("status") not in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
        writer(path, current,
            status="cancelled", stage="cancelled", finished_at=now(),
            lock={"scope":"global","state":"released","acquired_at":(current.get("lock") or {}).get("acquired_at")},
            exit_result=current.get("exit_result") or {"success":False,"exit_code":None,"signal":signal.SIGTERM,"timed_out":False},
            failure={"classification":"cancelled","message":"Job was cancelled."},
        )
        append_audit("job.cancelled", job=current)

def usage():
    raise SystemExit("usage: tec-tac-server-maintenance --dispatch|--run|--cancel <job-id> | --register <manifest.json> | --unregister <action-id> | --register-module|--unregister-module <module-id>")


def main():
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if len(sys.argv) != 3:
        usage()
    mode, value = sys.argv[1], sys.argv[2]
    if mode == "--dispatch": dispatch(value)
    elif mode == "--run": run_job(value)
    elif mode == "--cancel": cancel_job(value)
    elif mode == "--register": register_manifest(value)
    elif mode == "--unregister": unregister_manifest(value)
    elif mode == "--register-module": register_module(value)
    elif mode == "--unregister-module": unregister_module(value)
    else: usage()


if __name__ == "__main__":
    main()
