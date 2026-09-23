#!/usr/bin/env python3
"""Root-owned asynchronous worker for Tec-Tac module lifecycle jobs."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
PLUGIN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
STATE_FILE = STATE_ROOT / "module-state.json"
JOBS_ROOT = STATE_ROOT / "jobs"
STAGED_ROOT = STATE_ROOT / "staged"
RUNNING_ROOT = STATE_ROOT / "running"
LOGS_ROOT = STATE_ROOT / "logs"
CONFIG = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
LIFECYCLE_LOCK_PATH = Path("/var/lib/tec-tac/lifecycle.lock")
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




def now():
    return datetime.now(timezone.utc).isoformat()


def load_config():
    values = {}
    if CONFIG.is_file():
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def atomic_json(path, payload):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def forget_module_state(plugin_id, log=None):
    """Remove lifecycle state for a module whose files were successfully removed."""
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
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE_FILE)
    if log is not None:
        log.write(f"[TEC-TAC-MODULE] removed stale runtime state for {plugin_id}\n")
        log.flush()
    return True


def job_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    if not path.is_file():
        raise SystemExit("job not found")
    job = json.loads(path.read_text(encoding="utf-8"))
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


def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")
    uid, gid = tactical_identity()
    RUNNING_ROOT.mkdir(parents=True, exist_ok=True)
    LOGS_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(RUNNING_ROOT, 0, gid)
    os.chmod(RUNNING_ROOT, 0o2750)
    os.chown(LOGS_ROOT, 0, gid)
    os.chmod(LOGS_ROOT, 0o2750)

    if job["action"] == "install":
        package_path = Path(str(job.get("package_path", ""))).resolve()
        try:
            package_path.relative_to(STAGED_ROOT.resolve())
        except ValueError:
            raise SystemExit("invalid staged package path")
        if not package_path.is_file():
            raise SystemExit("staged package missing")
        target = RUNNING_ROOT / f"{job_id}{''.join(package_path.suffixes)}"
        os.replace(package_path, target)
        os.chown(target, 0, gid)
        os.chmod(target, 0o640)
        meta = STAGED_ROOT / f"{job.get('upload_id')}.json"
        if meta.is_file():
            try:
                stage_meta = json.loads(meta.read_text(encoding="utf-8"))
                for key in ("signature_path", "release_metadata_path"):
                    if stage_meta.get(key):
                        Path(str(stage_meta[key])).unlink(missing_ok=True)
            except Exception:
                pass
            meta.unlink()
        job["package_path"] = str(target)

    job["status"] = "dispatched"
    job["stage"] = "dispatched"
    atomic_json(path, job)
    os.chown(path, 0, gid)
    os.chmod(path, 0o640)
    return path, job


def dispatch(job_id):
    claim_job(job_id)
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--run", job_id],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_job_package_hash(job):
    if job.get("action") != "install":
        return
    expected = str(job.get("package_sha256") or "").strip().lower()
    if not expected:
        raise RuntimeError("install job is missing package_sha256")
    package = Path(str(job.get("package_path") or ""))
    if not package.is_file():
        raise RuntimeError("staged package is missing")
    actual = _sha256_file(package)
    if actual != expected:
        raise RuntimeError("staged package SHA-256 changed after trust verification")


def run_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    acquire_lifecycle_lock()
    _verify_job_package_hash(job)
    config = load_config()
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
    if job["action"] == "install":
        package = Path(job["package_path"])
        command = ["bash", str(install_script), str(package)]
        if job.get("replace"):
            command.append("--replace")
    else:
        command = ["bash", str(remove_script), job["plugin_id"], "", "--yes"]

    rc = 1
    try:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[TEC-TAC-MODULE] started {now()} action={job['action']} plugin={job['plugin_id']}\n")
            trust = job.get("publisher_trust") if isinstance(job.get("publisher_trust"), dict) else {}
            log.write(f"[TEC-TAC-MODULE] publisher_trust state={trust.get('state','unknown')} publisher={trust.get('publisher_id','')} key={trust.get('key_id','')} sha256={job.get('package_sha256','')}\n")
            log.flush()
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, text=True)
            rc = result.returncode
            if rc == 0 and job["action"] == "remove":
                # Removal is not complete until its persistent runtime state is
                # cleared. Otherwise later UI/system updates can fail because
                # module-state.json still marks a deleted extension as enabled.
                forget_module_state(job["plugin_id"], log)
            if rc == 0 and ui_sync.is_file():
                job["stage"] = "ui-sync"
                atomic_json(path, job)
                log.write("[TEC-TAC-MODULE] synchronizing deployed UI modules\n")
                log.flush()
                sync_env = os.environ.copy()
                sync_env["TEC_TAC_UI_ROOT"] = ui_root
                sync = subprocess.run(["bash", str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=sync_env)
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
