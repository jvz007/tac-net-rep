#!/usr/bin/python3
"""Root-owned Tec-Tac Module Management v2 lifecycle worker.

This worker handles enable/disable and multi-package/bundle orchestration. Single
package install/remove jobs continue to use the proven v1 worker.

Rollback scope for bundle/batch failure is code + enabled-state. Database
migrations already applied by a package are intentionally not auto-reversed.
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
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
PLUGIN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
JOBS_ROOT = STATE_ROOT / "jobs"
STAGED_ROOT = STATE_ROOT / "staged"
RUNNING_ROOT = STATE_ROOT / "running-v2"
LOGS_ROOT = STATE_ROOT / "logs"
BACKUP_ROOT = STATE_ROOT / "bundle-backups"
MODULE_STATE = STATE_ROOT / "module-state.json"
CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")
PRIVILEGED_TRUST = Path("/usr/local/lib/tec-tac-security/privileged-trust.py")
RUNNING_REQUEST_ROOT = RUNNING_ROOT / "requests"
_LIFECYCLE_LOCK_HANDLE = None


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


BUNDLES_ROOT = STAGED_ROOT / "bundles"
BATCHES_ROOT = STAGED_ROOT / "batches"
ALLOWED_ACTIONS = {"enable", "disable", "visibility", "bundle_install", "batch_install"}


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


def module_state_lock(exclusive=True):
    MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
    path = MODULE_STATE.with_name("module-state.lock")
    if not path.exists():
        # This is a root-only mutation lock. Tactical readers rely on atomic
        # module-state.json replacement and must not be able to hold an
        # exclusive flock that stalls privileged lifecycle workers.
        path.touch(mode=0o600, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, 0o600)
    handle = path.open("r+" if exclusive else "r")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    return handle


def load_module_state_unlocked(*, mutation=False):
    if not MODULE_STATE.is_file():
        return {"schema": 1, "modules": {}}
    try:
        payload = json.loads(MODULE_STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        if mutation:
            raise RuntimeError(f"module-state.json is unreadable; refusing to overwrite it: {exc}") from exc
        return {"schema": 1, "modules": {}, "_corrupt": True, "_error": str(exc)}
    if not isinstance(payload, dict) or not isinstance(payload.get("modules", {}), dict):
        if mutation:
            raise RuntimeError("module-state.json has an invalid structure; refusing to overwrite it")
        return {"schema": 1, "modules": {}, "_corrupt": True, "_error": "invalid structure"}
    payload.setdefault("schema", 1)
    payload.setdefault("modules", {})
    return payload


def load_module_state():
    handle = module_state_lock(False)
    try:
        return load_module_state_unlocked()
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN); handle.close()


def save_module_state_unlocked(state):
    if state.get("_corrupt"):
        raise RuntimeError("corrupt module state cannot be saved")
    atomic_json(MODULE_STATE, state, 0o644)
    try:
        os.chown(MODULE_STATE, 0, 0)
        os.chmod(MODULE_STATE, 0o644)
    except OSError:
        pass


def mutate_module_state(callback):
    handle = module_state_lock(True)
    try:
        state = load_module_state_unlocked(mutation=True)
        callback(state)
        save_module_state_unlocked(state)
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN); handle.close()


def set_enabled(module_ids, enabled):
    def apply(state):
        for module_id in module_ids:
            record = dict(state["modules"].get(module_id) or {})
            record["enabled"] = bool(enabled)
            state["modules"][module_id] = record
    mutate_module_state(apply)


def set_visible(module_id, visible):
    def apply(state):
        record = dict(state["modules"].get(module_id) or {})
        record["visible"] = bool(visible)
        state["modules"][module_id] = record
    mutate_module_state(apply)


def remember_version(module_id, version, source=None):
    def apply(state):
        record = dict(state["modules"].get(module_id) or {})
        record.setdefault("enabled", True)
        record["version"] = str(version)
        if source:
            record["source"] = dict(source)
            record["source"]["installed_at"] = now()
        state["modules"][module_id] = record
    mutate_module_state(apply)

def migrate_module_state_identity(old_id, new_id):
    def apply(state):
        if new_id in state["modules"]:
            raise RuntimeError(f"destination module state already exists: {new_id}")
        record = state["modules"].pop(old_id, None)
        if record is not None:
            state["modules"][new_id] = record
    mutate_module_state(apply)

def run_identity_migration(config, action, log, *, reverse=False):
    old_id = str(action.get("previous_module_id") or "")
    new_id = str(action.get("id") or "")
    migration = action.get("migration") or {}
    if not old_id or not new_id:
        raise RuntimeError("rename action is missing module identities")
    tactical_root = config.get("TACTICAL_ROOT", "/rmm")
    python = Path(tactical_root) / "api/env/bin/python"
    manage = Path(tactical_root) / "api/tacticalrmm/manage.py"
    if not python.is_file() or not manage.is_file():
        raise RuntimeError("Tactical Python/manage.py is unavailable for module identity migration")
    tactical_user = config.get("TACTICAL_USER", "tactical")
    env = privileged_env({
        "TEC_TAC_IDENTITY_OLD": old_id,
        "TEC_TAC_IDENTITY_NEW": new_id,
        "TEC_TAC_IDENTITY_MIGRATION": json.dumps(migration, separators=(",", ":")),
        "TEC_TAC_IDENTITY_REVERSE": "1" if reverse else "0",
    })
    code = (
        "import json,os; "
        "from tec_tac.module_identity import apply_identity_migration; "
        "apply_identity_migration("
        "old_id=os.environ['TEC_TAC_IDENTITY_OLD'],"
        "new_id=os.environ['TEC_TAC_IDENTITY_NEW'],"
        "migration=json.loads(os.environ['TEC_TAC_IDENTITY_MIGRATION']),"
        "reverse=os.environ.get('TEC_TAC_IDENTITY_REVERSE')=='1')"
    )
    direction = "rollback" if reverse else "apply"
    log.write(f"[TEC-TAC-MODULE-V2] {direction} identity migration {old_id} -> {new_id}\n")
    log.flush()
    result = subprocess.run(
        ["runuser", "-u", tactical_user, "--", str(python), str(manage), "shell", "-c", code],
        stdout=log, stderr=subprocess.STDOUT, text=True, env=env,
    )
    if result.returncode:
        raise RuntimeError(f"module identity migration {direction} failed with status {result.returncode}")


def _read_json_nofollow(path, *, max_bytes=4 * 1024 * 1024, label="job file"):
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
        job = _read_json_nofollow(path, label="module v2 job")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("job not found") from exc
        raise
    if job.get("id") != job_id or job.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("invalid v2 job")
    return path, job


def tactical_gid(config=None):
    config = config or load_config()
    return pwd.getpwnam(config.get("TACTICAL_USER", "tactical")).pw_gid


def running_request_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return RUNNING_REQUEST_ROOT / f"{job_id}.json"


def load_running_request(job_id):
    path = running_request_path(job_id)
    try:
        job = _read_json_nofollow(path, label="claimed v2 request")
    except SystemExit as exc:
        if not path.exists():
            raise SystemExit("claimed v2 request not found") from exc
        raise
    if job.get("id") != job_id or job.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("claimed v2 request is invalid")
    return path, job


def _claim_artifact(source_value, claim_dir, label):
    """Snapshot one direct staged artifact into a new root-private inode.

    Standalone package artifacts may be direct children of ``STAGED_ROOT``;
    bundles and their sidecars may be direct children of ``BUNDLES_ROOT``.
    No deeper path is accepted.  Source open/stat/unlink operations are all
    relative to directory fds opened with ``O_NOFOLLOW``.
    """
    source = Path(os.path.abspath(str(source_value or "")))
    staged_root = Path(os.path.abspath(str(STAGED_ROOT)))
    bundles_root = Path(os.path.abspath(str(BUNDLES_ROOT)))
    name = source.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name):
        raise SystemExit(f"invalid staged {label} path")
    if source.parent == staged_root:
        root_kind = "staged"
    elif source.parent == bundles_root:
        root_kind = "bundles"
    else:
        raise SystemExit(f"invalid staged {label} path")

    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        staged_fd = os.open(staged_root, dir_flags)
    except OSError as exc:
        raise SystemExit("managed v2 staging root is unsafe or unreadable") from exc
    root_fd = staged_fd
    bundles_fd = None
    try:
        if root_kind == "bundles":
            try:
                bundles_fd = os.open("bundles", dir_flags, dir_fd=staged_fd)
            except OSError as exc:
                raise SystemExit("managed v2 bundle staging root is unsafe or unreadable") from exc
            root_fd = bundles_fd

        target = claim_dir / name
        if target.exists():
            target = claim_dir / f"{label}-{name}"

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            src_fd = os.open(name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise SystemExit(f"staged {label} is unsafe or unreadable") from exc
        try:
            src_stat = os.fstat(src_fd)
            if not stat.S_ISREG(src_stat.st_mode):
                raise SystemExit(f"staged {label} is not a regular file")
            parent_stat = claim_dir.stat()
            if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o077:
                raise SystemExit("root-private v2 claim directory has unsafe ownership or permissions")

            out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                dst_fd = os.open(target, out_flags, 0o600)
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
                            raise OSError("short write while claiming v2 artifact")
                        view = view[written:]
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)

            try:
                current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None and current.st_dev == src_stat.st_dev and current.st_ino == src_stat.st_ino:
                os.unlink(name, dir_fd=root_fd)
        finally:
            os.close(src_fd)
    finally:
        if bundles_fd is not None:
            os.close(bundles_fd)
        os.close(staged_fd)
    return str(target)


def _execution_artifact_copy(source_value, claim_dir, execution_root, label):
    """Copy one already-claimed artifact into the final root-private execution set.

    Verification, extraction and installation must all operate on this new inode.
    The claimed request path is used only as an input to this copy step and is
    never reopened later in the lifecycle.
    """
    source = Path(os.path.abspath(str(source_value or "")))
    expected_parent = Path(os.path.abspath(str(claim_dir)))
    if source.parent != expected_parent:
        raise RuntimeError(f"{label} is outside the root-private v2 claim directory")
    name = source.name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name):
        raise RuntimeError(f"invalid claimed {label} filename")

    execution_root.mkdir(parents=True, exist_ok=True)
    root_stat = execution_root.stat()
    if root_stat.st_uid != 0 or root_stat.st_mode & 0o077:
        raise RuntimeError("root-private v2 execution directory has unsafe ownership or permissions")

    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        claim_fd = os.open(expected_parent, dir_flags)
    except OSError as exc:
        raise RuntimeError("root-private v2 claim directory is unsafe or unreadable") from exc
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            src_fd = os.open(name, flags, dir_fd=claim_fd)
        except OSError as exc:
            raise RuntimeError(f"claimed {label} is unsafe or unreadable") from exc
        try:
            src_stat = os.fstat(src_fd)
            if not stat.S_ISREG(src_stat.st_mode):
                raise RuntimeError(f"claimed {label} is not a regular file")
            if src_stat.st_uid != 0 or src_stat.st_mode & 0o022:
                raise RuntimeError(f"claimed {label} is not root-owned and immutable")

            target = execution_root / f"{label}-{name}"
            out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                dst_fd = os.open(target, out_flags, 0o600)
            except OSError as exc:
                raise RuntimeError(f"unable to create root-private execution snapshot for {label}") from exc
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
                            raise OSError("short write while snapshotting v2 execution artifact")
                        view = view[written:]
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)
        finally:
            os.close(src_fd)
    finally:
        os.close(claim_fd)
    return str(target)


def _snapshot_v2_job_artifacts(job_id, job, execution_root):
    """Return a job whose artifact paths are final root-private execution copies."""
    claim_dir = RUNNING_ROOT / f"{job_id}.claimed"
    snap = json.loads(json.dumps(job))
    action = snap.get("action")
    if action == "bundle_install":
        snap["bundle_path"] = _execution_artifact_copy(snap.get("bundle_path"), claim_dir, execution_root, "bundle")
        for key in ("signature_path", "release_metadata_path"):
            if snap.get(key):
                snap[key] = _execution_artifact_copy(snap.get(key), claim_dir, execution_root, key)
    elif action == "batch_install":
        artifacts = snap.get("artifacts") if isinstance(snap.get("artifacts"), list) else [{**item, "kind": "package"} for item in (snap.get("packages") or [])]
        rewritten = []
        for index, item in enumerate(artifacts):
            row = dict(item)
            kind = str(row.get("kind") or "package")
            path_key = "bundle_path" if kind == "bundle" else "path"
            row[path_key] = _execution_artifact_copy(row.get(path_key), claim_dir, execution_root, f"artifact-{index}")
            for key in ("signature_path", "release_metadata_path"):
                if row.get(key):
                    row[key] = _execution_artifact_copy(row.get(key), claim_dir, execution_root, f"{key}-{index}")
            rewritten.append(row)
        snap["artifacts"] = rewritten
        snap.pop("packages", None)
    return snap

def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")
    gid = tactical_gid()
    for directory in (RUNNING_ROOT, LOGS_ROOT, BACKUP_ROOT):
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, 0, gid); os.chmod(directory, 0o2750)
    RUNNING_REQUEST_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(RUNNING_REQUEST_ROOT, 0, 0); os.chmod(RUNNING_REQUEST_ROOT, 0o700)
    claim_dir = RUNNING_ROOT / f"{job_id}.claimed"
    claim_dir.mkdir(parents=True, exist_ok=False)
    os.chown(claim_dir, 0, 0); os.chmod(claim_dir, 0o700)

    immutable = {key: value for key, value in job.items() if key not in {"status", "stage", "created_at", "started_at", "finished_at", "error", "error_type", "publisher_trust"}}
    immutable["id"] = job_id
    if job.get("action") == "bundle_install":
        immutable["bundle_path"] = _claim_artifact(job.get("bundle_path"), claim_dir, "bundle")
        for key in ("signature_path", "release_metadata_path"):
            if job.get(key):
                immutable[key] = _claim_artifact(job.get(key), claim_dir, key)
    elif job.get("action") == "batch_install":
        artifacts = []
        source_artifacts = job.get("artifacts") if isinstance(job.get("artifacts"), list) else [{**item, "kind": "package"} for item in (job.get("packages") or [])]
        for index, item in enumerate(source_artifacts):
            row = {k: v for k, v in item.items() if k not in {"publisher_trust", "package_sha256"}}
            kind = str(row.get("kind") or "package")
            path_key = "bundle_path" if kind == "bundle" else "path"
            row[path_key] = _claim_artifact(item.get(path_key), claim_dir, f"artifact-{index}")
            for key in ("signature_path", "release_metadata_path"):
                if item.get(key):
                    row[key] = _claim_artifact(item.get(key), claim_dir, f"{key}-{index}")
            artifacts.append(row)
        immutable["artifacts"] = artifacts
        immutable.pop("packages", None)

    req_path = running_request_path(job_id)
    atomic_json(req_path, immutable, 0o600, uid=0, gid=0)
    job["status"] = "dispatched"; job["stage"] = "dispatched"
    atomic_json(path, job, 0o640, uid=0, gid=gid)
    return path, immutable

def dispatch(job_id):
    claim_job(job_id)
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--run", job_id],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True, env=privileged_env(),
    )


def require_root_owned(path):
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f"refusing non-root-owned or writable lifecycle script: {path}")


def sync_and_reload(config, log, *, refresh_workers=False):
    ui_sync = Path(config.get("UI_SYNC_SCRIPT", "/opt/tec-tac-src/ui/scripts/sync-modules.sh"))
    ui_root = config.get("UI_ROOT", "/var/lib/tec-tac/ui/tec-tac")
    reload_script = Path(config.get("REPO_ROOT", "/opt/tec-tac")) / "scripts/reload-rmm-uwsgi.sh"
    if ui_sync.is_file():
        require_root_owned(ui_sync)
        env = privileged_env({"TEC_TAC_UI_ROOT": ui_root})
        result = subprocess.run(["/usr/bin/bash", str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
        if result.returncode:
            raise RuntimeError(f"UI module synchronization failed with status {result.returncode}")
    if reload_script.is_file():
        require_root_owned(reload_script)
        result = subprocess.run(["/usr/bin/bash", str(reload_script)], stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env())
        if result.returncode:
            raise RuntimeError(f"Tactical graceful reload failed with status {result.returncode}")
    if refresh_workers:
        log.write("[TEC-TAC-MODULE-V2] restarting Tactical Celery worker for module runtime refresh\n")
        log.flush()
        last_restart_rc = 0
        for attempt in range(1, 4):
            log.write(f"[TEC-TAC-MODULE-V2] Celery refresh attempt {attempt}/3\n")
            log.flush()
            result = subprocess.run(["systemctl", "restart", "celery"], stdout=log, stderr=subprocess.STDOUT, text=True)
            last_restart_rc = result.returncode
            for _ in range(10):
                active = subprocess.run(["systemctl", "is-active", "--quiet", "celery"], stdout=log, stderr=subprocess.STDOUT, text=True)
                if active.returncode == 0:
                    log.write("[TEC-TAC-MODULE-V2] celery: active (module runtime refreshed)\n")
                    log.flush()
                    return
                time.sleep(1)
            log.write(f"[TEC-TAC-MODULE-V2] Celery did not become active after attempt {attempt}; restart status={last_restart_rc}\n")
            subprocess.run(["systemctl", "status", "celery", "--no-pager", "-l"], stdout=log, stderr=subprocess.STDOUT, text=True)
            subprocess.run(["journalctl", "-u", "celery", "-n", "25", "--no-pager"], stdout=log, stderr=subprocess.STDOUT, text=True)
            subprocess.run(["systemctl", "reset-failed", "celery"], stdout=log, stderr=subprocess.STDOUT, text=True)
            log.flush()
            time.sleep(2)
        raise RuntimeError(f"Tactical Celery is not active after three refresh attempts (last restart status {last_restart_rc})")


def backup_modules(repo_root, module_ids, backup_root):
    records = {}
    for module_id in module_ids:
        record = {"extension": False, "reportset": False}
        for kind in ("extensions", "reportsets"):
            src = repo_root / kind / module_id
            if src.is_dir():
                dst = backup_root / kind / module_id
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(src, dst)
                record["extension" if kind == "extensions" else "reportset"] = True
        records[module_id] = record
    atomic_json(backup_root / "contents.json", records)
    if MODULE_STATE.is_file():
        shutil.copy2(MODULE_STATE, backup_root / "module-state.json")
    return records


def restore_modules(repo_root, module_ids, backup_root, log):
    records_path = backup_root / "contents.json"
    records = json.loads(records_path.read_text(encoding="utf-8")) if records_path.is_file() else {}
    log.write("[TEC-TAC-MODULE-V2] restoring pre-job module code/state\n")
    for module_id in module_ids:
        for kind, key in (("extensions", "extension"), ("reportsets", "reportset")):
            target = repo_root / kind / module_id
            if target.exists():
                shutil.rmtree(target)
            source = backup_root / kind / module_id
            if records.get(module_id, {}).get(key) and source.is_dir():
                shutil.copytree(source, target)
    state_backup = backup_root / "module-state.json"
    if state_backup.is_file():
        shutil.copy2(state_backup, MODULE_STATE)
    elif MODULE_STATE.is_file():
        MODULE_STATE.unlink()


def install_packages(repo_root, packages, order, actions, log, backup_root):
    install_script = repo_root / "scripts/install-extension.sh"
    if not install_script.is_file():
        raise RuntimeError("Tec-Tac install-extension.sh is missing")
    require_root_owned(install_script)
    package_by_id = {item["id"]: Path(item["path"]) for item in packages}
    actions_by_id = {item["id"]: item for item in actions}
    backup_ids = list(order)
    for action in actions:
        previous = str(action.get("previous_module_id") or "")
        if previous and previous not in backup_ids:
            backup_ids.append(previous)
    backup_modules(repo_root, backup_ids, backup_root)
    for module_id in order:
        package = package_by_id[module_id]
        if not package.is_file():
            raise RuntimeError(f"staged package missing for {module_id}: {package}")
        action = actions_by_id.get(module_id) or {}
        rename_from = str(action.get("previous_module_id") or "") if action.get("action") == "rename" else ""
        if rename_from:
            for kind in ("extensions", "reportsets"):
                old_root = repo_root / kind / rename_from
                if old_root.exists():
                    shutil.rmtree(old_root)
            log.write(f"[TEC-TAC-MODULE-V2] renaming module identity {rename_from} -> {module_id}\n")
            replace = False
        else:
            replace = (repo_root / "extensions" / module_id).is_dir()
        command = ["/usr/bin/bash", str(install_script), str(package)]
        if replace:
            command.append("--replace")
        verb = "renaming" if rename_from else ("replacing" if replace else "installing")
        log.write(f"[TEC-TAC-MODULE-V2] {verb} {module_id}\n")
        log.flush()
        env = privileged_env({"TEC_TAC_DEFER_WORKER_REFRESH": "1"})
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
        if result.returncode:
            raise RuntimeError(f"install failed for {module_id} with status {result.returncode}")
    return backup_ids


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_expected_hash(path, expected, label):
    expected = str(expected or "").strip().lower()
    if not expected:
        raise RuntimeError(f"{label} is missing package_sha256")
    actual = _sha256_file(path)
    if actual != expected:
        raise RuntimeError(f"{label} SHA-256 changed after trust verification")


def _privileged_verify_artifact(config, path, signature=None, metadata=None):
    if not PRIVILEGED_TRUST.is_file():
        raise RuntimeError(f"privileged trust verifier is missing: {PRIVILEGED_TRUST}")
    st = PRIVILEGED_TRUST.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError("privileged trust verifier is not root-owned or is writable")
    command = [sys.executable, str(PRIVILEGED_TRUST), "verify-package", str(path)]
    if signature: command += ["--signature", str(signature)]
    if metadata: command += ["--metadata", str(metadata)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, env=privileged_env())
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "root v2 trust verification failed").strip())
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("root v2 trust verifier returned invalid output") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("root v2 trust verifier returned invalid data")
    return payload


def _verify_v2_job_trust(config, job):
    if job.get("action") == "bundle_install":
        return [_privileged_verify_artifact(config, job["bundle_path"], job.get("signature_path"), job.get("release_metadata_path"))]
    if job.get("action") == "batch_install":
        rows = []
        for item in job.get("artifacts") or []:
            kind = str(item.get("kind") or "package")
            path = item.get("bundle_path") if kind == "bundle" else item.get("path")
            rows.append(_privileged_verify_artifact(config, path, item.get("signature_path"), item.get("release_metadata_path")))
        return rows
    return []



def _authenticated_module_facts(root_trust):
    facts = {}
    for trust in root_trust or []:
        for row in trust.get("artifact_modules") or []:
            module_id = str(row.get("id") or "")
            if not PLUGIN_RE.fullmatch(module_id):
                raise RuntimeError("root verifier returned invalid module identity")
            if module_id in facts:
                raise RuntimeError(f"duplicate authenticated module id: {module_id}")
            facts[module_id] = {
                "version": str(row.get("version") or ""),
                "previous_module_ids": set(str(v) for v in (row.get("previous_module_ids") or [])),
            }
    return facts


def _validate_install_plan_against_signed_artifacts(job, packages, root_trust):
    """Bind mutable orchestration fields to facts extracted from signed bytes."""
    facts = _authenticated_module_facts(root_trust)
    package_ids = {str(item.get("id") or "") for item in packages}
    if not package_ids or package_ids != set(facts):
        raise RuntimeError("install plan package identities do not match root-verified signed artifacts")
    for item in packages:
        module_id = str(item.get("id") or "")
        supplied_version = str(item.get("version") or "").strip()
        signed_version = facts[module_id]["version"]
        if supplied_version and supplied_version != signed_version:
            raise RuntimeError(f"install plan version mismatch for {module_id}")
        item["version"] = signed_version

    plan = job.get("plan") if isinstance(job.get("plan"), dict) else {}
    order = [str(value) for value in (plan.get("order") or [])]
    if len(order) != len(set(order)) or set(order) != package_ids:
        raise RuntimeError("install order does not exactly match root-verified signed artifacts")
    actions = plan.get("actions") or []
    if not isinstance(actions, list):
        raise RuntimeError("install actions are invalid")
    action_ids = []
    for action in actions:
        if not isinstance(action, dict):
            raise RuntimeError("install action is invalid")
        module_id = str(action.get("id") or "")
        if module_id not in facts:
            raise RuntimeError("install action targets an unauthenticated module")
        action_ids.append(module_id)
        supplied_version = str(action.get("version") or "").strip()
        if supplied_version and supplied_version != facts[module_id]["version"]:
            raise RuntimeError(f"install action version mismatch for {module_id}")
        action["version"] = facts[module_id]["version"]
        previous = str(action.get("previous_module_id") or "").strip()
        if previous and previous not in facts[module_id]["previous_module_ids"]:
            raise RuntimeError(f"rename source for {module_id} is not authorized by the signed module manifest")
    if set(action_ids) != package_ids or len(action_ids) != len(package_ids):
        raise RuntimeError("install actions do not exactly match root-verified signed artifacts")
    return order, actions

def _authenticated_bundle_files(trust):
    rows = trust.get("artifact_package_files") if isinstance(trust, dict) else None
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("root verifier did not return authenticated bundle package mapping")
    result = []
    seen_ids = set()
    seen_files = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("root verifier returned invalid bundle package mapping")
        module_id = str(row.get("id") or "")
        filename = str(row.get("file") or "")
        version = str(row.get("version") or "")
        if not PLUGIN_RE.fullmatch(module_id) or not filename or not version:
            raise RuntimeError("root verifier returned invalid bundle package mapping")
        normalized = Path(filename)
        if normalized.is_absolute() or ".." in normalized.parts or len(normalized.parts) < 1:
            raise RuntimeError("root verifier returned unsafe bundle package path")
        if module_id in seen_ids or filename in seen_files:
            raise RuntimeError("root verifier returned duplicate bundle package mapping")
        seen_ids.add(module_id); seen_files.add(filename)
        result.append({"id": module_id, "file": filename, "version": version})
    return result


def _extract_verified_bundle(source, extract, expected_hash, label):
    if not source.is_file():
        raise RuntimeError("root-private bundle snapshot is missing")
    _require_expected_hash(source, expected_hash, label)
    extract.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source) as zf:
        for member in zf.infolist():
            name = Path(member.filename)
            if name.is_absolute() or ".." in name.parts:
                raise RuntimeError("unsafe path in bundle")
        zf.extractall(extract)


def _resolve_authenticated_bundle_packages(extract, mapping, source_label):
    result = []
    for item in mapping:
        filename = str(item["file"])
        candidate = (extract / filename).resolve()
        try:
            candidate.relative_to(extract.resolve())
        except ValueError as exc:
            raise RuntimeError(f"authenticated bundle package path escapes bundle: {filename}") from exc
        if not candidate.is_file():
            raise RuntimeError(f"authenticated bundle package file is missing: {filename}")
        result.append({"id": item["id"], "path": str(candidate), "version": item["version"], "source": source_label})
    return result


def bundle_packages(job, running_root, root_trust):
    source = Path(str(job.get("bundle_path", ""))).resolve()
    extract = running_root / "bundle"
    _extract_verified_bundle(source, extract, root_trust.get("package_sha256"), "bundle")
    mapping = _authenticated_bundle_files(root_trust)
    return _resolve_authenticated_bundle_packages(extract, mapping, job.get("source"))


def batch_packages(job, running_root, root_trust):
    result = []
    artifacts = job.get("artifacts")
    if not isinstance(artifacts, list):
        # Compatibility with pre-1.15.8 jobs.
        artifacts = [{**item, "kind": "package"} for item in (job.get("packages") or [])]

    seen_ids = set()
    if not isinstance(root_trust, list) or len(root_trust) != len(artifacts):
        raise RuntimeError("root trust results do not match staged batch artifacts")
    for index, item in enumerate(artifacts):
        kind = str(item.get("kind") or "package")
        artifact_trust = root_trust[index]
        source = Path(str(item.get("bundle_path") if kind == "bundle" else item.get("path", ""))).resolve()
        if not source.is_file():
            raise RuntimeError(f"staged batch artifact missing: {item.get('id') or item.get('bundle_id') or index}")

        if kind == "bundle":
            extract = running_root / f"bundle-{index}"
            _extract_verified_bundle(source, extract, artifact_trust.get("package_sha256"), f"batch bundle {index}")
            mapping = _authenticated_bundle_files(artifact_trust)
            expanded = _resolve_authenticated_bundle_packages(extract, mapping, item.get("source"))
            for package in expanded:
                module_id = str(package["id"])
                if module_id in seen_ids:
                    raise RuntimeError(f"duplicate module id in batch: {module_id}")
                seen_ids.add(module_id)
                result.append(package)
            continue

        module_id = str(item.get("id") or "")
        if module_id in seen_ids:
            raise RuntimeError(f"duplicate module id in batch: {module_id}")
        seen_ids.add(module_id)
        _require_expected_hash(source, artifact_trust.get("package_sha256"), f"batch package {module_id or index}")
        result.append({"id": module_id, "path": str(source), "source": item.get("source")})
    return result



def cleanup_successful_stage(job, log):
    """Remove staging artifacts after a successful v2 install job."""
    if job.get("action") == "bundle_install":
        source = Path(str(job.get("bundle_path", "")))
        try:
            source.resolve().relative_to(STAGED_ROOT.resolve())
            source.unlink(missing_ok=True)
        except Exception:
            pass
        for key in ("signature_path", "release_metadata_path"):
            if job.get(key):
                try: Path(str(job[key])).unlink(missing_ok=True)
                except OSError: pass
        upload_id = str(job.get("upload_id") or "")
        if JOB_RE.fullmatch(upload_id):
            (BUNDLES_ROOT / f"{upload_id}.json").unlink(missing_ok=True)
    elif job.get("action") == "batch_install":
        artifacts = job.get("artifacts")
        if not isinstance(artifacts, list):
            artifacts = [{**item, "kind": "package"} for item in (job.get("packages") or [])]
        for item in artifacts:
            kind = str(item.get("kind") or "package")
            source = Path(str(item.get("bundle_path") if kind == "bundle" else item.get("path", "")))
            try:
                source.resolve().relative_to(STAGED_ROOT.resolve())
                source.unlink(missing_ok=True)
            except Exception:
                pass
            for key in ("signature_path", "release_metadata_path"):
                if item.get(key):
                    try: Path(str(item[key])).unlink(missing_ok=True)
                    except OSError: pass
            upload_id = str(item.get("upload_id") or "")
            if JOB_RE.fullmatch(upload_id):
                root = BUNDLES_ROOT if kind == "bundle" else STAGED_ROOT
                (root / f"{upload_id}.json").unlink(missing_ok=True)
        batch_id = str(job.get("batch_id") or "")
        if JOB_RE.fullmatch(batch_id):
            (BATCHES_ROOT / f"{batch_id}.json").unlink(missing_ok=True)
    log.write("[TEC-TAC-MODULE-V2] cleaned successful staged artifacts\n")

def run_job(job_id):
    path, status = load_job(job_id)
    if status.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    _, immutable = load_running_request(job_id)
    job = {**immutable, "status": status.get("status"), "stage": status.get("stage"), "created_at": status.get("created_at")}
    acquire_lifecycle_lock()
    config = load_config()
    repo_root = Path(config.get("REPO_ROOT", "/opt/tec-tac")).resolve()
    log_path = LOGS_ROOT / f"{job_id}.log"
    running = RUNNING_ROOT / job_id
    backup = BACKUP_ROOT / job_id
    running.mkdir(parents=True, exist_ok=False)
    os.chown(running, 0, 0); os.chmod(running, 0o700)
    backup.mkdir(parents=True, exist_ok=True)

    # Finalize the immutable execution set before invoking any trust verifier.
    # Every later verification, extraction and install consumes only these
    # root-owned 0600 snapshots, never the claimed/request staging paths.
    job = _snapshot_v2_job_artifacts(job_id, job, running)
    root_trust = _verify_v2_job_trust(config, job)
    if root_trust:
        job["root_publisher_trust"] = root_trust

    job["status"] = "running"
    job["stage"] = "lifecycle"
    job["started_at"] = now()
    atomic_json(path, job)

    rc = 1
    touched = []
    try:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[TEC-TAC-MODULE-V2] started {now()} action={job['action']} target={job.get('plugin_id')}\n")
            trust = job.get("publisher_trust") if isinstance(job.get("publisher_trust"), dict) else {}
            if trust:
                log.write(f"[TEC-TAC-MODULE-V2] publisher_trust state={trust.get('state','unknown')} publisher={trust.get('publisher_id','')} key={trust.get('key_id','')} sha256={job.get('package_sha256','')}\n")
            if job["action"] in {"enable", "disable"}:
                affected = [str(value) for value in job.get("affected_modules") or [job["plugin_id"]]]
                if any(not PLUGIN_RE.fullmatch(value) for value in affected):
                    raise RuntimeError("invalid affected module id")
                # Enable one target; disable may cascade through dependants.
                enabled = job["action"] == "enable"
                set_enabled(affected, enabled)
                touched = affected
                job["stage"] = "runtime-sync"
                atomic_json(path, job)
                sync_and_reload(config, log, refresh_workers=True)
            elif job["action"] == "visibility":
                module_id = str(job.get("plugin_id") or "")
                if not PLUGIN_RE.fullmatch(module_id):
                    raise RuntimeError("invalid module id")
                set_visible(module_id, bool(job.get("visible", True)))
                touched = [module_id]
                job["stage"] = "ui-sync"
                atomic_json(path, job)
                sync_and_reload(config, log)
            else:
                packages = bundle_packages(job, running, root_trust[0]) if job["action"] == "bundle_install" else batch_packages(job, running, root_trust)
                order, actions = _validate_install_plan_against_signed_artifacts(job, packages, root_trust)
                if any(not PLUGIN_RE.fullmatch(value) for value in order):
                    raise RuntimeError("invalid install order")
                touched = order
                applied_renames = []
                backup_ids = list(order)
                try:
                    backup_ids = install_packages(repo_root, packages, order, actions, log, backup)
                    sources = {item.get("id"): item.get("source") for item in packages}
                    for action in actions:
                        if action.get("action") == "rename":
                            run_identity_migration(config, action, log)
                            migrate_module_state_identity(action["previous_module_id"], action["id"])
                            applied_renames.append(action)
                        remember_version(action["id"], action.get("version") or "0.0.0", sources.get(action["id"]))
                    job["stage"] = "runtime-sync"
                    atomic_json(path, job)
                    sync_and_reload(config, log, refresh_workers=True)
                    cleanup_successful_stage(job, log)
                except Exception:
                    job["stage"] = "rollback"
                    atomic_json(path, job)
                    for action in reversed(applied_renames):
                        try:
                            run_identity_migration(config, action, log, reverse=True)
                        except Exception as identity_rollback_exc:
                            log.write(f"[TEC-TAC-MODULE-V2] identity rollback failed: {identity_rollback_exc}\n")
                    restore_modules(repo_root, backup_ids, backup, log)
                    try:
                        sync_and_reload(config, log, refresh_workers=True)
                    except Exception as rollback_exc:
                        log.write(f"[TEC-TAC-MODULE-V2] rollback runtime sync failed: {rollback_exc}\n")
                    raise
            rc = 0
    except Exception as exc:
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        try:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-MODULE-V2] failed: {exc}\n")
        except OSError:
            pass

    job["finished_at"] = now()
    if rc == 0:
        job["status"] = "succeeded"
        job["stage"] = "complete"
        job["error"] = None
        job["error_type"] = None
    else:
        job["status"] = "failed"
        if not job.get("stage"):
            job["stage"] = "failed"
    atomic_json(path, job)
    try:
        running_request_path(job_id).unlink(missing_ok=True)
        claim_dir = RUNNING_ROOT / f"{job_id}.claimed"
        if claim_dir.is_dir():
            shutil.rmtree(claim_dir)
    except OSError:
        pass


def mark_failed(job_id, error):
    try:
        path, job = load_job(job_id)
        job["status"] = "failed"
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
        raise SystemExit("usage: tec-tac-module-v2-job --dispatch|--run <job-id>")
    if sys.argv[1] == "--dispatch":
        dispatch(sys.argv[2])
    else:
        try:
            run_job(sys.argv[2])
        except BaseException as exc:
            mark_failed(sys.argv[2], exc)
            raise
