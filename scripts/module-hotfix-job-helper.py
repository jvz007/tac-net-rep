#!/usr/bin/env python3
"""Root-owned worker for managed Tec-Tac module hotfixes."""
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
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

HOTFIX_ROOT = Path("/var/lib/tec-tac/module-manager/hotfixes")
STAGED_ROOT = HOTFIX_ROOT / "staged"
JOBS_ROOT = HOTFIX_ROOT / "jobs"
LOGS_ROOT = HOTFIX_ROOT / "logs"
RUNNING_ROOT = HOTFIX_ROOT / "running"
BACKUPS_ROOT = HOTFIX_ROOT / "backups"
APPLIED_ROOT = HOTFIX_ROOT / "applied"
HISTORY_ROOT = HOTFIX_ROOT / "history"
CONFIG = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
LIFECYCLE_LOCK = Path("/var/lib/tec-tac/lifecycle.lock")
JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MODULE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HOTFIX_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_ACTIONS = {"apply", "rollback"}
_LOCK_HANDLE = None


def now():
    return datetime.now(timezone.utc).isoformat()


def load_config():
    values = {}
    if CONFIG.is_file():
        for raw in CONFIG.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def atomic_json(path: Path, payload: dict, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sha256_file(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def acquire_lock():
    global _LOCK_HANDLE
    LIFECYCLE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = LIFECYCLE_LOCK.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("another Tec-Tac lifecycle operation is already running") from exc
    _LOCK_HANDLE = handle


def tactical_gid(config):
    return pwd.getpwnam(config.get("TACTICAL_USER", "tactical")).pw_gid


def job_path(job_id):
    if not JOB_RE.fullmatch(job_id or ""):
        raise SystemExit("invalid hotfix job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    if not path.is_file():
        raise SystemExit("hotfix job not found")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("id") != job_id or payload.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("invalid hotfix job")
    return path, payload


def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("hotfix job is not queued")
    config = load_config()
    gid = tactical_gid(config)
    for directory in (RUNNING_ROOT, LOGS_ROOT, BACKUPS_ROOT, APPLIED_ROOT, HISTORY_ROOT):
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
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def require_root_owned(path: Path):
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f"refusing non-root-owned or writable Core helper: {path}")


def safe_relative(value):
    raw = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise RuntimeError(f"unsafe hotfix target path: {value!r}")
    if any(not part or part.startswith(".") for part in path.parts):
        raise RuntimeError(f"unsupported hotfix target path: {value!r}")
    if path.name in {"tec_tac.json", "tec_tac_ui.json"} or "migrations" in path.parts or "lifecycle" in path.parts:
        raise RuntimeError(f"hotfix target is not permitted: {value!r}")
    return path.as_posix()


def module_roots(config, module_id):
    if not MODULE_RE.fullmatch(module_id or ""):
        raise RuntimeError("invalid module id")
    ext = Path(config.get("TEC_TAC_EXTENSIONS_ROOT", "/opt/tec-tac/extensions")) / module_id
    rep = Path(config.get("TEC_TAC_REPORTSETS_ROOT", "/opt/tec-tac/reportsets")) / module_id
    return {"extension": ext.resolve(), "reportset": rep.resolve()}


def module_version(root, module_id):
    manifest = root / "tec_tac.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if payload.get("id") != module_id:
        raise RuntimeError("installed module identity mismatch")
    version = str(payload.get("version") or "")
    if not version:
        raise RuntimeError("installed module version is missing")
    return version


def load_archive_manifest(package: Path):
    if not zipfile.is_zipfile(package):
        raise RuntimeError("staged hotfix is not a ZIP archive")
    with zipfile.ZipFile(package) as zf:
        for info in zf.infolist():
            name = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if name.is_absolute() or ".." in name.parts or stat.S_ISLNK(mode):
                raise RuntimeError(f"unsafe archive member: {info.filename}")
        matches = [i.filename for i in zf.infolist() if not i.is_dir() and PurePosixPath(i.filename).name == "tec_tac_hotfix.json"]
        if len(matches) != 1:
            raise RuntimeError("hotfix archive must contain exactly one tec_tac_hotfix.json")
        member = matches[0]
        manifest = json.loads(zf.read(member).decode("utf-8"))
        prefix = PurePosixPath(member).parent
        base = "" if str(prefix) == "." else prefix.as_posix().rstrip("/") + "/"
    if manifest.get("type") != "tec-tac-hotfix" or manifest.get("schema") != 1:
        raise RuntimeError("unsupported hotfix manifest")
    return base, manifest


def normalize_targets(manifest, prefix):
    module_id = str(manifest.get("module_id") or "")
    hotfix_id = str(manifest.get("id") or "")
    base_version = str(manifest.get("base_version") or "")
    if not MODULE_RE.fullmatch(module_id) or not HOTFIX_RE.fullmatch(hotfix_id) or not base_version:
        raise RuntimeError("invalid hotfix identity/version")
    rows = manifest.get("targets")
    if not isinstance(rows, list) or not rows or len(rows) > 64:
        raise RuntimeError("invalid hotfix target list")
    result = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("invalid hotfix target")
        component = str(row.get("component") or "")
        if component not in {"extension", "reportset"}:
            raise RuntimeError("invalid hotfix target component")
        rel = safe_relative(row.get("path"))
        before = str(row.get("sha256_before") or "").lower()
        after = str(row.get("sha256_after") or "").lower()
        if not SHA256_RE.fullmatch(before) or not SHA256_RE.fullmatch(after):
            raise RuntimeError("invalid hotfix target hash")
        key = (component, rel)
        if key in seen:
            raise RuntimeError("duplicate hotfix target")
        seen.add(key)
        result.append({
            "component": component,
            "path": rel,
            "sha256_before": before,
            "sha256_after": after,
            "payload_member": f"{prefix}payload/{component}/{rel}",
        })
    any_python = any(row["path"].endswith(".py") for row in result)
    any_ui = any(row["component"] == "extension" and row["path"].startswith("ui/") for row in result)
    validation = manifest.get("validation") if isinstance(manifest.get("validation"), dict) else {}
    return module_id, hotfix_id, base_version, result, {
        "reload": "django" if any_python else ("django" if manifest.get("reload") == "django" else "none"),
        "ui_sync": bool(manifest.get("ui_sync") or any_ui),
        "python_compile": bool(validation.get("python_compile") or any_python),
        "django_check": bool(validation.get("django_check") or any_python),
    }


def extract_payload(package, targets, running):
    extracted = {}
    with zipfile.ZipFile(package) as zf:
        names = {info.filename: info for info in zf.infolist() if not info.is_dir()}
        for row in targets:
            member = row["payload_member"]
            info = names.get(member)
            if info is None:
                raise RuntimeError(f"missing hotfix payload file: {row['component']}/{row['path']}")
            dest = running / "payload" / row["component"] / row["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            if hashlib.sha256(data).hexdigest() != row["sha256_after"]:
                raise RuntimeError(f"hotfix payload hash mismatch: {row['component']}/{row['path']}")
            dest.write_bytes(data)
            extracted[(row["component"], row["path"])] = dest
    return extracted


def copy_atomic(source, target, stat_from):
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tec-tac-hotfix-", dir=str(target.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copyfile(source, tmp)
        os.chmod(tmp, stat.S_IMODE(stat_from.st_mode))
        os.chown(tmp, stat_from.st_uid, stat_from.st_gid)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def validate_runtime(config, targets, effective, log):
    tactical_root = Path(config.get("TACTICAL_ROOT", "/rmm"))
    python = Path(config.get("TACTICAL_PYTHON", tactical_root / "api/env/bin/python"))
    manage = Path(config.get("TACTICAL_BACKEND_ROOT", tactical_root / "api/tacticalrmm")) / "manage.py"
    tactical_user = config.get("TACTICAL_USER", "tactical")
    if effective.get("python_compile"):
        for target in targets:
            if not target["path"].endswith(".py"):
                continue
            result = subprocess.run([str(python), "-m", "py_compile", str(target["target_path"])], stdout=log, stderr=subprocess.STDOUT, text=True)
            if result.returncode:
                raise RuntimeError(f"Python compile validation failed: {target['component']}/{target['path']}")
    if effective.get("django_check"):
        result = subprocess.run(["runuser", "-u", tactical_user, "--", str(python), str(manage), "check"], cwd=str(manage.parent), stdout=log, stderr=subprocess.STDOUT, text=True)
        if result.returncode:
            raise RuntimeError(f"Django system check failed with status {result.returncode}")


def sync_reload(config, effective, log):
    if effective.get("ui_sync"):
        ui_sync = Path(config.get("UI_SYNC_SCRIPT", "/opt/tec-tac-src/ui/scripts/sync-modules.sh"))
        if ui_sync.is_file():
            require_root_owned(ui_sync)
            env = os.environ.copy()
            env["TEC_TAC_UI_ROOT"] = config.get("UI_ROOT", "/var/lib/tec-tac/ui/tec-tac")
            result = subprocess.run(["bash", str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
            if result.returncode:
                raise RuntimeError(f"UI module synchronization failed with status {result.returncode}")
    if effective.get("reload") == "django":
        reload_script = Path(config.get("REPO_ROOT", "/opt/tec-tac")) / "scripts/reload-rmm-uwsgi.sh"
        require_root_owned(reload_script)
        result = subprocess.run(["bash", str(reload_script)], stdout=log, stderr=subprocess.STDOUT, text=True)
        if result.returncode:
            raise RuntimeError(f"Tactical graceful reload failed with status {result.returncode}")


def apply_job(path, job, config, log):
    module_id = str(job.get("module_id") or "")
    hotfix_id = str(job.get("hotfix_id") or "")
    package = Path(str(job.get("package_path") or "")).resolve()
    try:
        package.relative_to(STAGED_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError("staged hotfix path is outside the managed staging root") from exc
    if not package.is_file() or sha256_file(package) != job.get("package_sha256"):
        raise RuntimeError("staged hotfix package is missing or changed")
    prefix, manifest = load_archive_manifest(package)
    parsed_module, parsed_hotfix, base_version, targets, effective = normalize_targets(manifest, prefix)
    if parsed_module != module_id or parsed_hotfix != hotfix_id or base_version != job.get("base_version"):
        raise RuntimeError("hotfix job identity does not match package manifest")
    roots = module_roots(config, module_id)
    versions = {component: module_version(root, module_id) for component, root in roots.items()}
    if versions["extension"] != versions["reportset"] or versions["extension"] != base_version:
        raise RuntimeError("installed module version no longer matches the hotfix base version")
    record_path = APPLIED_ROOT / module_id / f"{hotfix_id}.json"
    if record_path.exists():
        raise RuntimeError("hotfix is already applied")
    running = RUNNING_ROOT / job["id"]
    backup_root = BACKUPS_ROOT / module_id / hotfix_id / job["id"]
    running.mkdir(parents=True, exist_ok=True)
    backup_root.mkdir(parents=True, exist_ok=True)
    extracted = extract_payload(package, targets, running)
    resolved = []
    for row in targets:
        root = roots[row["component"]]
        target = (root / row["path"]).resolve()
        target.relative_to(root)
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"hotfix target is not a regular file: {row['component']}/{row['path']}")
        if sha256_file(target) != row["sha256_before"]:
            raise RuntimeError(f"hotfix base hash changed: {row['component']}/{row['path']}")
        backup = backup_root / row["component"] / row["path"]
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, backup, follow_symlinks=False)
        resolved.append({**row, "target_path": target, "backup_path": backup, "payload_path": extracted[(row["component"], row["path"])]})
    mutated = []
    try:
        job["stage"] = "apply-files"
        atomic_json(path, job)
        for row in resolved:
            st = row["target_path"].stat()
            copy_atomic(row["payload_path"], row["target_path"], st)
            if sha256_file(row["target_path"]) != row["sha256_after"]:
                raise RuntimeError(f"post-write hash mismatch: {row['component']}/{row['path']}")
            mutated.append(row)
        job["stage"] = "validate"
        atomic_json(path, job)
        validate_runtime(config, resolved, effective, log)
        job["stage"] = "runtime-sync"
        atomic_json(path, job)
        sync_reload(config, effective, log)
    except Exception:
        log.write("[TEC-TAC-HOTFIX] apply failed; restoring original files\n")
        log.flush()
        for row in reversed(mutated):
            try:
                current = row["target_path"].stat()
                copy_atomic(row["backup_path"], row["target_path"], current)
            except Exception as restore_exc:
                log.write(f"[TEC-TAC-HOTFIX] rollback restore failed: {restore_exc}\n")
        try:
            sync_reload(config, effective, log)
        except Exception as refresh_exc:
            log.write(f"[TEC-TAC-HOTFIX] rollback runtime refresh failed: {refresh_exc}\n")
        job["rolled_back"] = True
        atomic_json(path, job)
        raise
    record = {
        "id": hotfix_id,
        "module_id": module_id,
        "base_version": base_version,
        "description": str(manifest.get("description") or ""),
        "applied_at": now(),
        "applied_by": job.get("requested_by"),
        "job_id": job["id"],
        "package_sha256": job.get("package_sha256"),
        "reload": effective["reload"],
        "ui_sync": effective["ui_sync"],
        "validation": {"python_compile": effective["python_compile"], "django_check": effective["django_check"]},
        "targets": [{key: row[key] for key in ("component", "path", "sha256_before", "sha256_after")} for row in resolved],
        "backup_root": str(backup_root),
    }
    atomic_json(record_path, record)
    try:
        os.chown(record_path, 0, tactical_gid(config))
    except OSError:
        pass
    upload_id = str(job.get("upload_id") or "")
    package.unlink(missing_ok=True)
    if JOB_RE.fullmatch(upload_id):
        (STAGED_ROOT / f"{upload_id}.json").unlink(missing_ok=True)
    return record


def latest_record(module_id):
    root = APPLIED_ROOT / module_id
    rows = []
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            rows.append((str(payload.get("applied_at") or ""), path, payload))
    rows.sort(key=lambda row: row[0])
    return rows[-1] if rows else None


def rollback_job(path, job, config, log):
    module_id = str(job.get("module_id") or "")
    hotfix_id = str(job.get("hotfix_id") or "")
    latest = latest_record(module_id)
    if not latest or latest[2].get("id") != hotfix_id:
        raise RuntimeError("hotfixes must be rolled back in reverse application order")
    record_path, record = latest[1], latest[2]
    roots = module_roots(config, module_id)
    base_version = str(record.get("base_version") or "")
    if module_version(roots["extension"], module_id) != base_version or module_version(roots["reportset"], module_id) != base_version:
        raise RuntimeError("installed module version no longer matches the applied hotfix base")
    backup_root = Path(str(record.get("backup_root") or "")).resolve()
    try:
        backup_root.relative_to(BACKUPS_ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError("hotfix backup path is outside the managed backup root") from exc
    targets = []
    for row in record.get("targets") or []:
        component = row.get("component")
        rel = safe_relative(row.get("path"))
        root = roots.get(component)
        if root is None:
            raise RuntimeError("invalid hotfix component in applied record")
        target = (root / rel).resolve()
        target.relative_to(root)
        backup = (backup_root / component / rel).resolve()
        backup.relative_to(backup_root)
        if not target.is_file() or not backup.is_file():
            raise RuntimeError(f"hotfix target/backup missing: {component}/{rel}")
        if sha256_file(target) != row.get("sha256_after"):
            raise RuntimeError(f"current file no longer matches applied hotfix: {component}/{rel}")
        if sha256_file(backup) != row.get("sha256_before"):
            raise RuntimeError(f"hotfix backup hash is invalid: {component}/{rel}")
        targets.append({**row, "component": component, "path": rel, "target_path": target, "backup_path": backup})
    job["stage"] = "restore-files"
    atomic_json(path, job)
    for row in reversed(targets):
        st = row["target_path"].stat()
        copy_atomic(row["backup_path"], row["target_path"], st)
        if sha256_file(row["target_path"]) != row["sha256_before"]:
            raise RuntimeError(f"hotfix rollback hash mismatch: {row['component']}/{row['path']}")
    effective = {
        "reload": record.get("reload") or "none",
        "ui_sync": bool(record.get("ui_sync")),
        "python_compile": bool((record.get("validation") or {}).get("python_compile")),
        "django_check": bool((record.get("validation") or {}).get("django_check")),
    }
    job["stage"] = "validate"
    atomic_json(path, job)
    validate_runtime(config, targets, effective, log)
    job["stage"] = "runtime-sync"
    atomic_json(path, job)
    sync_reload(config, effective, log)
    history = dict(record)
    history["status"] = "rolled_back"
    history["rolled_back_at"] = now()
    history["rolled_back_by"] = job.get("requested_by")
    history["rollback_job_id"] = job["id"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    history_path = HISTORY_ROOT / module_id / f"{hotfix_id}.{stamp}.json"
    atomic_json(history_path, history)
    record_path.unlink(missing_ok=True)
    return history


def supersede(module_id, new_version):
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if not MODULE_RE.fullmatch(module_id or ""):
        raise SystemExit("invalid module id")
    root = APPLIED_ROOT / module_id
    if not root.is_dir():
        return 0
    moved = 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        payload["status"] = "superseded"
        payload["superseded_at"] = now()
        payload["superseded_by_version"] = str(new_version)
        history = HISTORY_ROOT / module_id / f"{payload.get('id', path.stem)}.{stamp}.superseded.json"
        atomic_json(history, payload)
        path.unlink(missing_ok=True)
        moved += 1
    try:
        root.rmdir()
    except OSError:
        pass
    return moved


def run_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("hotfix job was not dispatched")
    acquire_lock()
    config = load_config()
    log_path = LOGS_ROOT / f"{job_id}.log"
    job["status"] = "running"
    job["stage"] = "preflight"
    job["started_at"] = now()
    atomic_json(path, job)
    try:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[TEC-TAC-HOTFIX] started {job['started_at']} action={job['action']} module={job.get('module_id')} hotfix={job.get('hotfix_id')}\n")
            log.flush()
            if job["action"] == "apply":
                apply_job(path, job, config, log)
            else:
                rollback_job(path, job, config, log)
            job["status"] = "succeeded"
            job["stage"] = "complete"
            job["finished_at"] = now()
            job["error"] = None
            job["error_type"] = None
            atomic_json(path, job)
            log.write(f"[TEC-TAC-HOTFIX] completed {job['finished_at']}\n")
    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = job.get("stage") or "failed"
        job["finished_at"] = now()
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        atomic_json(path, job)
        try:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[TEC-TAC-HOTFIX] FAILED {job['finished_at']}: {exc.__class__.__name__}: {exc}\n")
        except OSError:
            pass
        raise


def main(argv):
    if len(argv) == 3 and argv[1] == "--dispatch":
        if os.geteuid() != 0:
            raise SystemExit("must run as root")
        dispatch(argv[2])
        return 0
    if len(argv) == 3 and argv[1] == "--run":
        if os.geteuid() != 0:
            raise SystemExit("must run as root")
        run_job(argv[2])
        return 0
    if len(argv) == 4 and argv[1] == "--supersede":
        count = supersede(argv[2], argv[3])
        print(f"[TEC-TAC-HOTFIX] superseded {count} applied hotfix(es) for {argv[2]} -> {argv[3]}")
        return 0
    raise SystemExit("usage: module-hotfix-job-helper.py --dispatch <job-id> | --run <job-id> | --supersede <module-id> <new-version>")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
