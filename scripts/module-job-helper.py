#!/usr/bin/python3
"""Root-owned asynchronous worker for Tec-Tac module lifecycle jobs."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import tarfile
import tempfile
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
PLUGIN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
STATE_FILE = STATE_ROOT / "module-state.json"
MODULE_STATE_LOCK = STATE_ROOT / "module-state.lock"
JOBS_ROOT = STATE_ROOT / "jobs"
STAGED_ROOT = STATE_ROOT / "staged"
RUNNING_ROOT = STATE_ROOT / "running"
LOGS_ROOT = STATE_ROOT / "logs"
CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")
PRIVILEGED_TRUST = Path("/usr/local/lib/tec-tac-security/privileged-trust.py")
RUNNING_REQUEST_ROOT = RUNNING_ROOT / "requests"
_LIFECYCLE_LOCK_HANDLE = None



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

def acquire_lifecycle_lock():
    """Serialize module lifecycle work with framework/UI system updates."""
    global _LIFECYCLE_LOCK_HANDLE
    LIFECYCLE_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LIFECYCLE_LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("another Tec-Tac lifecycle operation is already running") from exc
    _LIFECYCLE_LOCK_HANDLE = handle




def now():
    return datetime.now(timezone.utc).isoformat()


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
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.fchmod(fd, mode)
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else int(uid), -1 if gid is None else int(gid))
        os.close(fd); fd = -1
        os.replace(tmp, path)
    finally:
        if fd >= 0: os.close(fd)
        tmp.unlink(missing_ok=True)


# 1.17.17: a signed module registers its Core server-maintenance actions from its manifest (``server_maintenance_actions``) when it is
# installed, and they are removed when it is removed. The work is done by Core's root server-maintenance helper, which re-checks the
# root-owned installed manifest. This helper only asks for it: --register-module and --unregister-module are reachable here and
# never through the Tactical account's sudo rule.
SERVER_MAINTENANCE_HELPER = Path("/usr/local/sbin/tec-tac-server-maintenance")
MAX_SERVER_ACTION_MANIFEST_BYTES = 1024 * 1024


def manifest_declares_server_actions(repo_root, module_id):
    """True when the installed manifest declares at least one server_maintenance_actions entry. Only the decision is made here, so
    the read is lenient; the root helper checks the owner, the mode and every rule before it registers anything."""
    path = Path(repo_root) / "extensions" / module_id / "tec_tac.json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        data = os.read(fd, MAX_SERVER_ACTION_MANIFEST_BYTES + 1)
    except OSError:
        return False
    finally:
        os.close(fd)
    try:
        payload = json.loads(data[:MAX_SERVER_ACTION_MANIFEST_BYTES].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    actions = payload.get("server_maintenance_actions") if isinstance(payload, dict) else None
    return isinstance(actions, list) and bool(actions)


def sync_server_maintenance_actions(repo_root, module_id, log, *, remove=False):
    """Register (or, with ``remove``, unregister) the server-maintenance actions of one module. A module that declares none has
    its earlier actions dropped, which is how an upgrade removes a stale action. Raises RuntimeError with a plain message when the
    root helper refuses or fails, so the job fails."""
    declared = (not remove) and manifest_declares_server_actions(repo_root, module_id)
    helper = SERVER_MAINTENANCE_HELPER
    if not helper.is_file():
        if declared:
            raise RuntimeError(f"module {module_id} declares server-maintenance actions but the Core server-maintenance helper is not installed")
        return
    info = helper.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f"refusing to run a non-root-owned or writable server-maintenance helper: {helper}")
    flag = "--register-module" if declared else "--unregister-module"
    log.write(f"[TEC-TAC-SERVER-MAINTENANCE] {'registering' if declared else 'removing'} server-maintenance actions of {module_id}\n")
    log.flush()
    result = subprocess.run([str(helper), flag, module_id], stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env(), check=False)
    if result.returncode:
        verb = "registration" if declared else "removal"
        raise RuntimeError(f"server-maintenance action {verb} failed for module {module_id} (status {result.returncode}). See the job log for the reason.")


def forget_module_state(plugin_id, log=None):
    """Remove lifecycle state for a module whose files were successfully removed."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    if not MODULE_STATE_LOCK.exists():
        MODULE_STATE_LOCK.touch(mode=0o600, exist_ok=True)
        os.chown(MODULE_STATE_LOCK, 0, 0)
        os.chmod(MODULE_STATE_LOCK, 0o600)
    with MODULE_STATE_LOCK.open("r+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            if not STATE_FILE.is_file():
                return False
            try:
                state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"module state is unreadable after removal: {exc}") from exc
            modules = state.get("modules")
            if not isinstance(modules, dict):
                raise RuntimeError("module state has an invalid structure after removal")
            if plugin_id not in modules:
                return False
            del modules[plugin_id]
            atomic_json(STATE_FILE, state)
            os.chown(STATE_FILE, 0, 0)
            os.chmod(STATE_FILE, 0o644)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    if log is not None:
        log.write(f"[TEC-TAC-MODULE] removed stale runtime state for {plugin_id}\n")
        log.flush()
    return True


# ------------------------------------------------------------ AD-20 hand-back on uninstall (1.17.15, Johan CQ43)
# An uninstall of an enabled replacement switches the module it replaces back on, in the same job. Core asks for it in
# ``enable_modules``; this worker re-checks every rule from root-owned manifests before anything is removed, the way
# module-v2-job-helper.py checks a disable. The rules are the same: each module is the replaced module of the module being
# removed, is a core or server module, is disabled now, and no other enabled module replaces it.
REPLACEABLE_CATEGORIES = frozenset({"core", "server"})
MAX_MANIFEST_BYTES = 1024 * 1024


def _trusted_stat(info):
    """Root-owned and not writable by group or others."""
    return info.st_uid == 0 and not (info.st_mode & 0o022)


def _read_manifest_file(path):
    """The manifest as a dict, or None when it is missing, a symlink, not a root-owned regular file, too large or not JSON."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    chunks, total = [], 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not _trusted_stat(info) or info.st_size > MAX_MANIFEST_BYTES:
            return None
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > MAX_MANIFEST_BYTES:
                return None
            chunks.append(block)
    finally:
        os.close(fd)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _installed_manifest(repo_root, module_id):
    """{id, category, replaces} of an installed extension, read as root-owned files only, or None."""
    if not PLUGIN_RE.fullmatch(str(module_id)):
        return None
    folder = Path(repo_root) / "extensions" / module_id
    try:
        info = os.lstat(folder)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or not _trusted_stat(info):
        return None
    payload = _read_manifest_file(folder / "tec_tac.json")
    if payload is None or str(payload.get("id") or "").strip() != module_id:
        return None
    return {
        "id": module_id,
        "category": str(payload.get("category") or "").strip().lower(),
        "replaces": str(payload.get("replaces") or "").strip(),
    }


def _installed_ids(repo_root):
    try:
        names = [entry.name for entry in (Path(repo_root) / "extensions").iterdir()]
    except OSError:
        return []
    return sorted(name for name in names if PLUGIN_RE.fullmatch(name))


def _state_modules():
    """The ``modules`` map of module-state.json, empty when there is no state file. RuntimeError when it cannot be read."""
    if not STATE_FILE.is_file():
        return {}
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"module state is unreadable: {exc}") from exc
    modules = state.get("modules") if isinstance(state, dict) else None
    if not isinstance(modules, dict):
        raise RuntimeError("module state has an invalid structure")
    return modules


def _enabled_in(modules, module_id):
    return bool((modules.get(module_id) or {}).get("enabled", True))


def plan_remove_hand_back(repo_root, plugin_id, enable_modules):
    """The replaced modules an uninstall may switch back on, each re-checked from root-owned manifests while the module
    being removed is still installed. Returns the sorted ids (empty when nothing was asked for). Raises RuntimeError with
    nothing changed when a rule does not hold."""
    wanted = sorted({str(item) for item in (enable_modules or [])})
    if not wanted:
        return []
    for module_id in wanted:
        if not PLUGIN_RE.fullmatch(module_id):
            raise RuntimeError(f"invalid module id in the hand-back list: {module_id!r}")
    removed = _installed_manifest(repo_root, plugin_id)
    if removed is None:
        raise RuntimeError(f"cannot verify the hand-back for {plugin_id}: no trusted manifest")
    modules = _state_modules()
    if not _enabled_in(modules, plugin_id):
        raise RuntimeError(f"module replacement rule refuses a hand-back for {plugin_id}: it is not enabled")
    for module_id in wanted:
        target = _installed_manifest(repo_root, module_id)
        if target is None:
            raise RuntimeError(f"cannot verify the hand-back of {module_id}: no trusted manifest")
        if module_id == plugin_id or target["category"] not in REPLACEABLE_CATEGORIES:
            raise RuntimeError(f"module replacement rule refuses enabling {module_id} as a hand-back: it is not a core or server module")
        if removed["replaces"] != module_id:
            raise RuntimeError(f"module replacement rule refuses enabling {module_id} as a hand-back: {plugin_id} does not replace it")
        if _enabled_in(modules, module_id):
            raise RuntimeError(f"module replacement rule refuses enabling {module_id} as a hand-back: it is enabled already")
        rivals = []
        for other_id in _installed_ids(repo_root):
            if other_id in (plugin_id, module_id):
                continue
            other = _installed_manifest(repo_root, other_id)
            if other is not None and other["replaces"] == module_id and _enabled_in(modules, other_id):
                rivals.append(other_id)
        if rivals:
            raise RuntimeError(f"module replacement rule refuses enabling {module_id} as a hand-back: {', '.join(rivals)} also replaces it and stays enabled")
    return wanted


def set_module_enabled(module_ids, enabled):
    """Write the enabled flag of each module into module-state.json, under the state lock (1.17.15, CQ43)."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    if not MODULE_STATE_LOCK.exists():
        MODULE_STATE_LOCK.touch(mode=0o600, exist_ok=True)
        os.chown(MODULE_STATE_LOCK, 0, 0)
        os.chmod(MODULE_STATE_LOCK, 0o600)
    with MODULE_STATE_LOCK.open("r+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            if not STATE_FILE.is_file():
                raise RuntimeError("module state is missing; the replaced module cannot be switched back on")
            try:
                state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"module state is unreadable: {exc}") from exc
            modules = state.get("modules") if isinstance(state, dict) else None
            if not isinstance(modules, dict):
                raise RuntimeError("module state has an invalid structure")
            for module_id in module_ids:
                record = dict(modules.get(module_id) or {})
                record["enabled"] = bool(enabled)
                modules[module_id] = record
            atomic_json(STATE_FILE, state)
            os.chown(STATE_FILE, 0, 0)
            os.chmod(STATE_FILE, 0o644)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


# ---------------------------------------------------------------------------------------------- AD-21 category (1.17.13)
KNOWN_CATEGORIES = frozenset({"", "core", "server", "premium", "test"})
MAX_MANIFEST_BYTES = 1024 * 1024


def development_server():
    """True only when the root-owned config says TEC_TAC_ENVIRONMENT=development. Fails closed (twin of module_category)."""
    try:
        return str(load_config().get("TEC_TAC_ENVIRONMENT") or "production").strip().lower() == "development"
    except (OSError, RuntimeError, ValueError):
        return False


def category_refused(category, development=None):
    """True when a module of this declared category must not be installed here: effective test, not a development server."""
    development = development_server() if development is None else development
    return (str(category or "").strip().lower() or "test") == "test" and not development


def package_category(package_path, plugin_id):
    """The declared category of the extension manifest inside the root-private package snapshot.

    Raises RuntimeError when the manifest cannot be found or read, or names a category Core does not know: the install
    then fails closed. Nothing is extracted to disk."""
    package = Path(package_path)
    found = []

    def consider(name, reader):
        parts = [part for part in name.split("/") if part]
        if len(parts) < 3 or parts[-1] != "tec_tac.json" or parts[-3] != "extensions":
            return
        data = reader()
        if len(data) > MAX_MANIFEST_BYTES:
            raise RuntimeError("module manifest is too large")
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("module manifest is unreadable") from exc
        if isinstance(payload, dict) and payload.get("type") == "extension":
            found.append(payload)

    if package.name.lower().endswith(".zip"):
        with zipfile.ZipFile(package) as archive:
            for member in archive.infolist():
                if not member.is_dir() and member.file_size <= MAX_MANIFEST_BYTES:
                    consider(member.filename, lambda m=member: archive.read(m))
    else:
        with tarfile.open(package, "r:*") as archive:
            for member in archive:
                if member.isfile() and member.size <= MAX_MANIFEST_BYTES:
                    consider(member.name, lambda m=member: archive.extractfile(m).read())
    if len(found) != 1:
        raise RuntimeError(f"module package must contain exactly one extension manifest; found {len(found)}")
    payload = found[0]
    if payload.get("id") != plugin_id:
        raise RuntimeError("module package manifest does not match the requested module")
    raw = payload.get("category", "")
    if not isinstance(raw, str) or raw.strip().lower() not in KNOWN_CATEGORIES:
        raise RuntimeError("module manifest names an unknown category")
    return raw.strip().lower()


def remember_category(plugin_id, category):
    """Write the manifest category into the module's state entry (AD-21 condition 5), under the state lock."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    if not MODULE_STATE_LOCK.exists():
        MODULE_STATE_LOCK.touch(mode=0o600, exist_ok=True)
        os.chown(MODULE_STATE_LOCK, 0, 0)
        os.chmod(MODULE_STATE_LOCK, 0o600)
    with MODULE_STATE_LOCK.open("r+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            state = {"schema": 1, "modules": {}}
            if STATE_FILE.is_file():
                try:
                    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise RuntimeError(f"module state is unreadable: {exc}") from exc
            modules = state.get("modules")
            if not isinstance(modules, dict):
                raise RuntimeError("module state has an invalid structure")
            record = dict(modules.get(plugin_id) or {})
            record["category"] = str(category)
            modules[plugin_id] = record
            atomic_json(STATE_FILE, state)
            os.chown(STATE_FILE, 0, 0)
            os.chmod(STATE_FILE, 0o644)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _read_json_nofollow(path, *, max_bytes=2 * 1024 * 1024, label="job file"):
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
        data = bytearray()
        while len(data) <= max_bytes:
            block = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > max_bytes:
            raise SystemExit(f"{label} is unexpectedly large")
        try:
            value = json.loads(bytes(data).decode("utf-8"))
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
        job = _read_json_nofollow(path, label="module job")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("job not found") from exc
        raise
    if job.get("id") != job_id:
        raise SystemExit("job id mismatch")
    action = job.get("action")
    if action not in {"install", "remove"}:
        raise SystemExit("unsupported action")
    plugin_id = str(job.get("plugin_id", ""))
    if not PLUGIN_RE.fullmatch(plugin_id):
        raise SystemExit("invalid plugin id")
    return path, job


def tactical_identity(config=None):
    config = config or load_config()
    user = pwd.getpwnam(config.get("TACTICAL_USER", "tactical"))
    return user.pw_uid, user.pw_gid


def _private_artifact_copy(source_value, destination: Path, label: str) -> Path:
    """Snapshot one direct staged file into a new root-private inode.

    The Tactical-writable metadata may name only one plain file directly below
    ``STAGED_ROOT``.  The directory itself is opened once without following a
    symlink, then the source is opened and (when safe) unlinked relative to that
    directory fd.  This prevents a symlinked intermediate directory from
    redirecting root to an arbitrary host file.
    """
    source = Path(os.path.abspath(str(source_value or "")))
    staged_root = Path(os.path.abspath(str(STAGED_ROOT)))
    name = source.name
    if source.parent != staged_root or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name):
        raise SystemExit(f"invalid staged {label} path")

    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(staged_root, dir_flags)
    except OSError as exc:
        raise SystemExit("managed module staging root is unsafe or unreadable") from exc
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            src_fd = os.open(name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise SystemExit(f"staged {label} is unsafe or unreadable") from exc
        try:
            src_stat = os.fstat(src_fd)
            if not stat.S_ISREG(src_stat.st_mode):
                raise SystemExit(f"staged {label} is not a regular file")

            destination.parent.mkdir(parents=True, exist_ok=True)
            parent_stat = destination.parent.stat()
            if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o077:
                raise SystemExit("root-private module claim directory has unsafe ownership or permissions")

            out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                dst_fd = os.open(destination, out_flags, 0o600)
            except OSError as exc:
                raise SystemExit(f"unable to create root-private {label} snapshot") from exc
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
                            raise OSError("short write while claiming module artifact")
                        view = view[written:]
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)

            # Only unlink the exact directory entry we opened.  If Tactical
            # races the name after open, leave the replacement for unprivileged
            # cleanup instead of deleting an unverified inode as root.
            try:
                current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None and current.st_dev == src_stat.st_dev and current.st_ino == src_stat.st_ino:
                os.unlink(name, dir_fd=root_fd)
        finally:
            os.close(src_fd)
    finally:
        os.close(root_fd)
    return destination

def running_request_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return RUNNING_REQUEST_ROOT / f"{job_id}.json"


def load_running_request(job_id):
    path = running_request_path(job_id)
    try:
        job = _read_json_nofollow(path, label="claimed module request")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("claimed module request not found") from exc
        raise
    if job.get("id") != job_id or job.get("action") not in {"install", "remove"}:
        raise SystemExit("claimed module request is invalid")
    return path, job


def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")
    uid, gid = tactical_identity()
    RUNNING_ROOT.mkdir(parents=True, exist_ok=True)
    RUNNING_REQUEST_ROOT.mkdir(parents=True, exist_ok=True)
    LOGS_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(RUNNING_ROOT, 0, gid); os.chmod(RUNNING_ROOT, 0o2750)
    os.chown(RUNNING_REQUEST_ROOT, 0, 0); os.chmod(RUNNING_REQUEST_ROOT, 0o700)
    os.chown(LOGS_ROOT, 0, gid); os.chmod(LOGS_ROOT, 0o2750)

    immutable = {
        "id": job_id,
        "action": job["action"],
        "plugin_id": str(job.get("plugin_id") or ""),
        "replace": bool(job.get("replace", False)),
    }
    if job["action"] == "remove":
        # 1.17.15 (CQ43): the replaced modules an uninstall switches back on. plan_remove_hand_back re-checks them.
        immutable["enable_modules"] = list(job.get("enable_modules") or [])
    if job["action"] == "install":
        upload_id = str(job.get("upload_id") or "")
        if not JOB_RE.fullmatch(upload_id):
            raise SystemExit("invalid module upload id")
        meta = STAGED_ROOT / f"{upload_id}.json"
        try:
            stage_meta = _read_json_nofollow(meta, label="staged module metadata")
        except SystemExit as exc:
            if not os.path.lexists(meta):
                raise SystemExit("staged module metadata missing") from exc
            raise
        package_path = Path(str(stage_meta.get("package_path") or ""))
        run_dir = RUNNING_ROOT / job_id
        run_dir.mkdir(parents=True, exist_ok=False)
        os.chown(run_dir, 0, 0); os.chmod(run_dir, 0o700)
        package_target = run_dir / ("package" + ("".join(package_path.suffixes) or ".zip"))
        _private_artifact_copy(package_path, package_target, "module package")
        immutable["upload_id"] = upload_id
        immutable["package_path"] = str(package_target)
        for source_key, target_key in (("signature_path", "signature_path"), ("release_metadata_path", "release_metadata_path")):
            raw = stage_meta.get(source_key)
            if not raw:
                continue
            source = Path(str(raw))
            target = run_dir / source.name
            _private_artifact_copy(source, target, source_key)
            immutable[target_key] = str(target)
        meta.unlink(missing_ok=True)

    req_path = running_request_path(job_id)
    atomic_json(req_path, immutable, mode=0o600, uid=0, gid=0)
    job["status"] = "dispatched"; job["stage"] = "dispatched"
    atomic_json(path, job, mode=0o640, uid=0, gid=gid)
    return path, immutable

def dispatch(job_id):
    claim_job(job_id)
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--run", job_id],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        env=privileged_env(),
    )


def _privileged_verify_package(config, job):
    if job.get("action") != "install":
        return None
    if not PRIVILEGED_TRUST.is_file():
        raise RuntimeError(f"privileged trust verifier is missing: {PRIVILEGED_TRUST}")
    info = PRIVILEGED_TRUST.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("privileged trust verifier is not root-owned or is writable")
    command = [sys.executable, str(PRIVILEGED_TRUST), "verify-package", str(job["package_path"])]
    if job.get("signature_path"):
        command += ["--signature", str(job["signature_path"])]
    if job.get("release_metadata_path"):
        command += ["--metadata", str(job["release_metadata_path"])]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, env=privileged_env())
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "root module trust verification failed").strip())
    try:
        trust = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("root module trust verifier returned invalid output") from exc
    if not isinstance(trust, dict):
        raise RuntimeError("root module trust verifier returned invalid data")
    return trust


def run_job_record(status, immutable):
    """The record run_job works on: what Core queued (requested_by, enable_modules, ...) with the root-side fields on top.
    1.17.15: it used to start from the running request alone, so the final write dropped what Core had queued."""
    return {**status, **immutable, "status": status.get("status"), "stage": status.get("stage"), "created_at": status.get("created_at")}


def run_job(job_id):
    path, status = load_job(job_id)
    if status.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    _, immutable = load_running_request(job_id)
    job = run_job_record(status, immutable)
    acquire_lifecycle_lock()
    config = load_config()
    root_trust = _privileged_verify_package(config, job)
    if root_trust is not None:
        job["publisher_trust"] = root_trust
    repo_root = Path(config.get("REPO_ROOT", "/opt/tec-tac")).resolve()
    ui_sync = Path(config.get("UI_SYNC_SCRIPT", "/opt/tec-tac-src/ui/scripts/sync-modules.sh"))
    ui_root = config.get("UI_ROOT", "/var/lib/tec-tac/ui/tec-tac")
    install_script = repo_root / "scripts/install-extension.sh"
    remove_script = repo_root / "scripts/remove-extension.sh"
    if not install_script.is_file() or not remove_script.is_file():
        raise SystemExit("Tec-Tac lifecycle scripts are missing")

    def require_root_owned_executable_source(path):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit(f"refusing to execute non-root-owned or writable lifecycle script: {path}")

    require_root_owned_executable_source(install_script)
    require_root_owned_executable_source(remove_script)
    if ui_sync.is_file():
        require_root_owned_executable_source(ui_sync)

    log_path = LOGS_ROOT / f"{job_id}.log"
    job["status"] = "running"
    job["stage"] = "lifecycle"
    job["started_at"] = now()
    atomic_json(path, job)

    command = None
    declared_category = None
    category_failed = False
    handback = []
    if job["action"] == "install":
        package = Path(job["package_path"])
        # AD-21 (1.17.13): re-check the category from the root-private package before anything is installed.
        try:
            declared_category = package_category(package, job["plugin_id"])
            if category_refused(declared_category):
                raise RuntimeError(f"module {job['plugin_id']} is a Test module (or states no category) and this is not a development server: refusing to install it")
        except (RuntimeError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-MODULE] category check failed: {exc}\n")
            # 1.17.14 (held Low from the 1.17.13-1 review): no early return. Set the failure and fall through to the shared
            # tail, which chmods the log, removes the running request and the root-private package snapshot.
            job["error"] = str(exc)
            job["error_type"] = "CategoryRefused"
            category_failed = True
        if not category_failed:
            command = [TRUSTED_BASH, str(install_script), str(package)]
            if job.get("replace"):
                command.append("--replace")
    else:
        # 1.17.15 (CQ43): the hand-back is checked while the module being removed is still installed, before anything changes.
        try:
            handback = plan_remove_hand_back(repo_root, job["plugin_id"], job.get("enable_modules"))
            command = [TRUSTED_BASH, str(remove_script), job["plugin_id"], "", "--yes"]
        except (RuntimeError, OSError) as exc:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-MODULE] hand-back check failed: {exc}\n")
            job["error"] = str(exc)
            job["error_type"] = "HandBackRefused"

    rc = 1
    if command is not None:
        try:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-MODULE] started {now()} action={job['action']} plugin={job['plugin_id']}\n")
                trust = job.get("publisher_trust") if isinstance(job.get("publisher_trust"), dict) else {}
                log.write(f"[TEC-TAC-MODULE] publisher_trust state={trust.get('state','unknown')} publisher={trust.get('publisher_id','')} key={trust.get('key_id','')} sha256={job.get('package_sha256','')}\n")
                log.flush()
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env())
                rc = result.returncode
                if rc == 0 and job["action"] == "install" and declared_category is not None:
                    remember_category(job["plugin_id"], declared_category)
                if rc == 0 and job["action"] == "remove":
                    # Removal is not complete until its persistent runtime state is
                    # cleared. Otherwise later UI/system updates can fail because
                    # module-state.json still marks a deleted extension as enabled.
                    forget_module_state(job["plugin_id"], log)
                    # 1.17.17: the module's server-maintenance actions go with it.
                    sync_server_maintenance_actions(repo_root, job["plugin_id"], log, remove=True)
                    if handback:
                        # 1.17.15 (CQ43): the replaced module comes back on in the same job, after the uninstall.
                        set_module_enabled(handback, True)
                        job["enabled_modules"] = list(handback)
                        log.write(f"[TEC-TAC-MODULE] enabled replaced module(s) handed back: {', '.join(handback)}\n")
                        log.flush()
                if rc == 0 and ui_sync.is_file():
                    job["stage"] = "ui-sync"
                    atomic_json(path, job)
                    log.write("[TEC-TAC-MODULE] synchronizing deployed UI modules\n")
                    log.flush()
                    sync_env = privileged_env({"TEC_TAC_UI_ROOT": ui_root})
                    sync = subprocess.run([TRUSTED_BASH, str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=sync_env)
                    if sync.returncode != 0:
                        rc = sync.returncode
                        log.write(f"[TEC-TAC-MODULE] UI module sync failed rc={rc}\n")
                    elif job["action"] == "install":
                        manifest = repo_root / "extensions" / job["plugin_id"] / "tec_tac_ui.json"
                        if manifest.is_file():
                            module_dir = Path(ui_root) / "modules" / job["plugin_id"]
                            if not module_dir.is_dir():
                                rc = 1
                                job["error"] = f"UI verification failed: {module_dir} was not deployed."
                                job["error_type"] = "UiVerificationError"
                                log.write(f"[TEC-TAC-MODULE] {job['error']}\n")
                            else:
                                log.write(f"[TEC-TAC-MODULE] UI verification OK: {module_dir}\n")
                elif rc == 0:
                    log.write(f"[TEC-TAC-MODULE] UI sync script not found at {ui_sync}; backend install succeeded\n")
                if rc == 0 and job["action"] == "install":
                    # 1.17.17: register the server-maintenance actions the installed module declares (and drop what an upgrade
                    # dropped). Same step, in the same place after the runtime sync, as module-v2-job-helper.py.
                    job["stage"] = "server-maintenance-actions"
                    atomic_json(path, job)
                    sync_server_maintenance_actions(repo_root, job["plugin_id"], log)
        except Exception as exc:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-MODULE] worker exception: {exc}\n")
            job["error"] = str(exc)
            job["error_type"] = exc.__class__.__name__
            rc = 1

    try:
        os.chmod(log_path, 0o640)
    except OSError:
        pass

    job["finished_at"] = now()
    if rc == 0:
        job["status"] = "succeeded"
        job["stage"] = "complete"
        job["error"] = None
        job["error_type"] = None
        if job["action"] == "install":
            try:
                Path(job["package_path"]).unlink(missing_ok=True)
            except OSError:
                pass
    else:
        job["status"] = "failed"
        if not job.get("error"):
            job["error"] = f"Lifecycle command exited with status {rc}. See log tail."
            job["error_type"] = "LifecycleCommandError"
    atomic_json(path, job)
    try:
        running_request_path(job_id).unlink(missing_ok=True)
        run_dir = RUNNING_ROOT / job_id
        if run_dir.is_dir():
            shutil.rmtree(run_dir)
    except OSError:
        pass


def mark_failed(job_id, error):
    try:
        path, job = load_job(job_id)
        job["status"] = "failed"
        job["stage"] = job.get("stage") or "worker"
        job["finished_at"] = now()
        job["error"] = str(error) or error.__class__.__name__
        job["error_type"] = error.__class__.__name__
        atomic_json(path, job)
    except Exception:
        pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if len(sys.argv) != 3 or sys.argv[1] not in {"--dispatch", "--run"}:
        raise SystemExit("usage: tec-tac-module-job --dispatch|--run <job-id>")
    if sys.argv[1] == "--dispatch":
        dispatch(sys.argv[2])
    else:
        try:
            run_job(sys.argv[2])
        except BaseException as exc:
            mark_failed(sys.argv[2], exc)
            raise
