#!/usr/bin/env python3
"""Root-owned Tec-Tac Module Management v2 lifecycle worker.

This worker handles enable/disable and multi-package/bundle orchestration. Single
package install/remove jobs continue to use the proven v1 worker.

Rollback scope for bundle/batch failure is code + enabled-state. Database
migrations already applied by a package are intentionally not auto-reversed.
"""
from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import shutil
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


BUNDLES_ROOT = STAGED_ROOT / "bundles"
BATCHES_ROOT = STAGED_ROOT / "batches"
ALLOWED_ACTIONS = {"enable", "disable", "visibility", "bundle_install", "batch_install"}


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


def atomic_json(path, payload, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_module_state():
    if not MODULE_STATE.is_file():
        return {"schema": 1, "modules": {}}
    payload = json.loads(MODULE_STATE.read_text(encoding="utf-8"))
    payload.setdefault("schema", 1)
    payload.setdefault("modules", {})
    return payload


def save_module_state(state):
    atomic_json(MODULE_STATE, state, 0o644)
    try:
        os.chown(MODULE_STATE, 0, 0)
        os.chmod(MODULE_STATE, 0o644)
    except OSError:
        pass


def set_enabled(module_ids, enabled):
    state = load_module_state()
    for module_id in module_ids:
        record = dict(state["modules"].get(module_id) or {})
        record["enabled"] = bool(enabled)
        state["modules"][module_id] = record
    save_module_state(state)


def set_visible(module_id, visible):
    state = load_module_state()
    record = dict(state["modules"].get(module_id) or {})
    record["visible"] = bool(visible)
    state["modules"][module_id] = record
    save_module_state(state)


def remember_version(module_id, version, source=None):
    state = load_module_state()
    record = dict(state["modules"].get(module_id) or {})
    record.setdefault("enabled", True)
    record["version"] = str(version)
    if source:
        record["source"] = dict(source)
        record["source"]["installed_at"] = now()
    state["modules"][module_id] = record
    save_module_state(state)

def migrate_module_state_identity(old_id, new_id):
    state = load_module_state()
    if new_id in state["modules"]:
        raise RuntimeError(f"destination module state already exists: {new_id}")
    record = state["modules"].pop(old_id, None)
    if record is not None:
        state["modules"][new_id] = record
        save_module_state(state)


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
    env = os.environ.copy()
    env["TEC_TAC_IDENTITY_OLD"] = old_id
    env["TEC_TAC_IDENTITY_NEW"] = new_id
    env["TEC_TAC_IDENTITY_MIGRATION"] = json.dumps(migration, separators=(",", ":"))
    env["TEC_TAC_IDENTITY_REVERSE"] = "1" if reverse else "0"
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


def job_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    if not path.is_file():
        raise SystemExit("job not found")
    job = json.loads(path.read_text(encoding="utf-8"))
    if job.get("id") != job_id or job.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("invalid v2 job")
    return path, job


def tactical_gid(config=None):
    config = config or load_config()
    return pwd.getpwnam(config.get("TACTICAL_USER", "tactical")).pw_gid


def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")
    gid = tactical_gid()
    for directory in (RUNNING_ROOT, LOGS_ROOT, BACKUP_ROOT):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(directory, 0, gid)
            os.chmod(directory, 0o2750)
        except OSError:
            pass
    job["status"] = "dispatched"
    job["stage"] = "dispatched"
    atomic_json(path, job)
    try:
        os.chown(path, 0, gid)
    except OSError:
        pass
    return path, job


def dispatch(job_id):
    claim_job(job_id)
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--run", job_id],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
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
        env = os.environ.copy()
        env["TEC_TAC_UI_ROOT"] = ui_root
        result = subprocess.run(["bash", str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
        if result.returncode:
            raise RuntimeError(f"UI module synchronization failed with status {result.returncode}")
    if reload_script.is_file():
        require_root_owned(reload_script)
        result = subprocess.run(["bash", str(reload_script)], stdout=log, stderr=subprocess.STDOUT, text=True)
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
        command = ["bash", str(install_script), str(package)]
        if replace:
            command.append("--replace")
        verb = "renaming" if rename_from else ("replacing" if replace else "installing")
        log.write(f"[TEC-TAC-MODULE-V2] {verb} {module_id}\n")
        log.flush()
        env = os.environ.copy()
        env["TEC_TAC_DEFER_WORKER_REFRESH"] = "1"
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
        if result.returncode:
            raise RuntimeError(f"install failed for {module_id} with status {result.returncode}")
    return backup_ids


def bundle_packages(job, running_root):
    source = Path(str(job.get("bundle_path", ""))).resolve()
    if not source.is_file():
        raise RuntimeError("staged bundle is missing")
    try:
        source.relative_to(STAGED_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError("invalid staged bundle path") from exc
    copied = running_root / "bundle.zip"
    shutil.copy2(source, copied)
    extract = running_root / "bundle"
    extract.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(copied) as zf:
        for member in zf.infolist():
            name = Path(member.filename)
            if name.is_absolute() or ".." in name.parts:
                raise RuntimeError("unsafe path in bundle")
        zf.extractall(extract)
    package_files = job.get("bundle", {}).get("package_files") or []
    result = []
    for item in package_files:
        filename = str(item.get("file", ""))
        matches = list(extract.rglob(filename))
        if len(matches) != 1:
            raise RuntimeError(f"bundle package file could not be uniquely resolved: {filename}")
        result.append({"id": item["id"], "path": str(matches[0]), "version": item.get("version")})
    return result


def batch_packages(job, running_root):
    result = []
    artifacts = job.get("artifacts")
    if not isinstance(artifacts, list):
        # Compatibility with pre-1.15.8 jobs.
        artifacts = [{**item, "kind": "package"} for item in (job.get("packages") or [])]

    seen_ids = set()
    for index, item in enumerate(artifacts):
        kind = str(item.get("kind") or "package")
        source = Path(str(item.get("bundle_path") if kind == "bundle" else item.get("path", ""))).resolve()
        try:
            source.relative_to(STAGED_ROOT.resolve())
        except ValueError as exc:
            raise RuntimeError("invalid staged batch artifact path") from exc
        if not source.is_file():
            raise RuntimeError(f"staged batch artifact missing: {item.get('id') or item.get('bundle_id') or index}")

        if kind == "bundle":
            copied = running_root / f"bundle-{index}.zip"
            shutil.copy2(source, copied)
            extract = running_root / f"bundle-{index}"
            extract.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(copied) as zf:
                for member in zf.infolist():
                    name = Path(member.filename)
                    if name.is_absolute() or ".." in name.parts:
                        raise RuntimeError("unsafe path in bundle")
                zf.extractall(extract)
            for package in item.get("package_files") or []:
                module_id = str(package.get("id") or "")
                filename = str(package.get("file") or "")
                matches = list(extract.rglob(filename))
                if len(matches) != 1:
                    raise RuntimeError(f"bundle package file could not be uniquely resolved: {filename}")
                if module_id in seen_ids:
                    raise RuntimeError(f"duplicate module id in batch: {module_id}")
                seen_ids.add(module_id)
                result.append({"id": module_id, "path": str(matches[0]), "version": package.get("version")})
            continue

        module_id = str(item.get("id") or "")
        if module_id in seen_ids:
            raise RuntimeError(f"duplicate module id in batch: {module_id}")
        seen_ids.add(module_id)
        suffix = "".join(source.suffixes) or ".zip"
        target = running_root / f"package-{index}-{module_id}{suffix}"
        shutil.copy2(source, target)
        result.append({"id": module_id, "path": str(target), "source": item.get("source")})
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
            upload_id = str(item.get("upload_id") or "")
            if JOB_RE.fullmatch(upload_id):
                root = BUNDLES_ROOT if kind == "bundle" else STAGED_ROOT
                (root / f"{upload_id}.json").unlink(missing_ok=True)
        batch_id = str(job.get("batch_id") or "")
        if JOB_RE.fullmatch(batch_id):
            (BATCHES_ROOT / f"{batch_id}.json").unlink(missing_ok=True)
    log.write("[TEC-TAC-MODULE-V2] cleaned successful staged artifacts\n")

def run_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    acquire_lifecycle_lock()
    config = load_config()
    repo_root = Path(config.get("REPO_ROOT", "/opt/tec-tac")).resolve()
    log_path = LOGS_ROOT / f"{job_id}.log"
    running = RUNNING_ROOT / job_id
    backup = BACKUP_ROOT / job_id
    running.mkdir(parents=True, exist_ok=True)
    backup.mkdir(parents=True, exist_ok=True)

    job["status"] = "running"
    job["stage"] = "lifecycle"
    job["started_at"] = now()
    atomic_json(path, job)

    rc = 1
    touched = []
    try:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[TEC-TAC-MODULE-V2] started {now()} action={job['action']} target={job.get('plugin_id')}\n")
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
                order = list((job.get("plan") or {}).get("order") or [])
                if not order or any(not PLUGIN_RE.fullmatch(value) for value in order):
                    raise RuntimeError("invalid install order")
                packages = bundle_packages(job, running) if job["action"] == "bundle_install" else batch_packages(job, running)
                touched = order
                actions = list((job.get("plan") or {}).get("actions") or [])
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
