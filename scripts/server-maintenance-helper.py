#!/usr/bin/env python3
"""Root-owned worker for durable Core server-maintenance jobs.

The helper executes only administrator-registered manifests.  It never accepts
a command, shell text, environment or executable path from a module request.
"""
from __future__ import annotations

import fcntl
import grp
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

CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
DEFAULT_STATE_ROOT = Path("/var/lib/tec-tac/server-maintenance")
DEFAULT_REGISTRY_ROOT = Path("/etc/tec-tac/server-maintenance/actions.d")
DEFAULT_ACTION_ROOT = Path("/usr/local/lib/tec-tac/server-maintenance/actions")


def _root_owned_layout():
    """Load helper trust roots only from the fixed root-owned Tec-Tac config.

    Privileged helper trust roots must never come from process environment.
    The config is optional for bootstrap/tests; when present it must be a
    regular root-owned file that is not group/world writable or a symlink.
    """
    values = {}
    try:
        st = CONFIG.lstat()
    except FileNotFoundError:
        return values
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"Tec-Tac config is not a regular file: {CONFIG}")
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise RuntimeError(f"Tec-Tac config must be root-owned and not group/world writable: {CONFIG}")
    for raw in CONFIG.read_text(encoding="utf-8").splitlines():
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


_ROOT_LAYOUT = _root_owned_layout()
STATE_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_ROOT", DEFAULT_STATE_ROOT)
REGISTRY_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT", DEFAULT_REGISTRY_ROOT)
ACTION_ROOT = _trusted_root(_ROOT_LAYOUT, "TEC_TAC_SERVER_MAINTENANCE_ACTION_ROOT", DEFAULT_ACTION_ROOT)
JOBS_ROOT = STATE_ROOT / "jobs"
CANCEL_ROOT = STATE_ROOT / "cancel-requests"
LOGS_ROOT = STATE_ROOT / "logs"
RUNNING_ROOT = STATE_ROOT / "running"
AUDIT_FILE = STATE_ROOT / "audit.jsonl"
LOCK_FILE = STATE_ROOT / "server-maintenance.lock"
ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ALLOWED_PARAMETER_TYPES = {"string", "integer", "boolean", "enum"}
MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
_cancel_requested = False
_child = None


def now():
    return datetime.now(timezone.utc).isoformat()


def load_config():
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
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
        job = json.loads(path.read_text(encoding="utf-8"))
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
    try:
        path, job = load_claimed_job(job_id)
    except RuntimeError:
        # A cancellation can race with the short pre-claim dispatch window.
        public_path, public_job = load_job(job_id)
        if public_job.get("status") in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
            return
        raise RuntimeError("job has not reached the claimed execution state")
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
    write_claimed_job(path, job, status="cancelling", stage="cancelling", cancel_requested_at=requested_at, cancel_context=cancel_context)
    append_audit("job.cancel_requested", job=job, detail={"cancel_context": cancel_context or {}})
    unit = str(job.get("unit") or _systemd_unit(job_id))
    result = subprocess.run(["systemctl", "stop", unit], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        current = load_claimed_job(job_id)[1]
        if current.get("status") not in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
            write_claimed_job(path, current, status="failed", stage="cancel", finished_at=now(), failure={"classification":"cancel_failed","message":(result.stderr or "Unable to stop maintenance unit.").strip()})
            append_audit("job.cancel_failed", job=current, detail={"message": result.stderr.strip()})
            raise RuntimeError((result.stderr or "Unable to stop maintenance unit.").strip())
    current = load_claimed_job(job_id)[1]
    if current.get("status") not in {"succeeded", "failed", "cancelled", "dispatch_failed"}:
        write_claimed_job(path, current,
            status="cancelled", stage="cancelled", finished_at=now(),
            lock={"scope":"global","state":"released","acquired_at":(current.get("lock") or {}).get("acquired_at")},
            exit_result=current.get("exit_result") or {"success":False,"exit_code":None,"signal":signal.SIGTERM,"timed_out":False},
            failure={"classification":"cancelled","message":"Job was cancelled."},
        )
        append_audit("job.cancelled", job=current)

def usage():
    raise SystemExit("usage: tec-tac-server-maintenance --dispatch|--run|--cancel <job-id> | --register <manifest.json> | --unregister <action-id>")


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
    else: usage()


if __name__ == "__main__":
    main()
