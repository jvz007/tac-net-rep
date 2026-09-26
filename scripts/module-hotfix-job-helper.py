#!/usr/bin/python3
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
CONFIG = Path("/opt/tec-tac/etc/tec-tac.conf")
PRIVILEGED_TRUST = Path("/usr/local/lib/tec-tac-security/privileged-trust.py")
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
    if CONFIG.is_symlink():
        raise RuntimeError("Tec-Tac config must be a regular non-symlink file")
    if CONFIG.exists():
        if not CONFIG.is_file():
            raise RuntimeError("Tec-Tac config must be a regular non-symlink file")
        info = CONFIG.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Tec-Tac config must be root-owned and not group/world writable")
        for raw in CONFIG.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
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


def atomic_json(path: Path, payload: dict, mode=0o640, *, uid=None, gid=None):
    """Atomically write JSON without following attacker-controlled temp symlinks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else int(uid), -1 if gid is None else int(gid))
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while storing hotfix JSON")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp_name, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


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


def load_job(job_id, *, claimed=False):
    path = (RUNNING_ROOT if claimed else JOBS_ROOT) / f"{job_id}.json"
    if not JOB_RE.fullmatch(job_id or ""):
        raise SystemExit("invalid hotfix job id")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("hotfix job not found")
    if claimed:
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise SystemExit("claimed hotfix job is not root-private")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("id") != job_id or payload.get("action") not in ALLOWED_ACTIONS:
        raise SystemExit("invalid hotfix job")
    return path, payload


def mirror_job(job_id, payload, gid):
    path = JOBS_ROOT / f"{job_id}.json"
    atomic_json(path, payload, mode=0o640, uid=0, gid=gid)


def claim_job(job_id):
    source, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("hotfix job is not queued")
    config = load_config()
    gid = tactical_gid(config)
    for directory in (RUNNING_ROOT, LOGS_ROOT, BACKUPS_ROOT, APPLIED_ROOT, HISTORY_ROOT):
        directory.mkdir(parents=True, exist_ok=True)
    os.chown(RUNNING_ROOT, 0, 0)
    os.chmod(RUNNING_ROOT, 0o700)
    for directory in (LOGS_ROOT, BACKUPS_ROOT, APPLIED_ROOT, HISTORY_ROOT):
        try:
            os.chown(directory, 0, gid)
            os.chmod(directory, 0o2750)
        except OSError:
            pass
    claimed = RUNNING_ROOT / f"{job_id}.json"
    if claimed.exists():
        raise SystemExit("hotfix job is already claimed")
    job["status"] = "dispatched"
    job["stage"] = "dispatched"
    atomic_json(claimed, job, mode=0o600, uid=0, gid=0)
    mirror_job(job_id, job, gid)
    return claimed, job


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


def write_claimed_job(path: Path, job: dict, config: dict):
    atomic_json(path, job, mode=0o600, uid=0, gid=0)
    mirror_job(str(job["id"]), job, tactical_gid(config))




def _copy_nofollow_to_private(source: Path, destination: Path, *, required: bool = True) -> Path | None:
    """Copy one staged artifact into root-private storage without following links."""
    source = Path(source)
    destination = Path(destination)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        src_fd = os.open(source, flags)
    except FileNotFoundError:
        if required:
            raise RuntimeError(f"staged hotfix artifact is missing: {source.name}")
        return None
    except OSError as exc:
        raise RuntimeError(f"staged hotfix artifact is unsafe or unreadable: {source.name}") from exc
    try:
        src_stat = os.fstat(src_fd)
        if not stat.S_ISREG(src_stat.st_mode):
            raise RuntimeError(f"staged hotfix artifact is not a regular file: {source.name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        parent_stat = destination.parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o077:
            raise RuntimeError("root-private hotfix working directory has unsafe ownership or permissions")
        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            dst_fd = os.open(destination, out_flags, 0o600)
        except OSError as exc:
            raise RuntimeError(f"unable to create root-private hotfix artifact: {destination.name}") from exc
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
                        raise OSError("short write while claiming hotfix artifact")
                    view = view[written:]
            os.fsync(dst_fd)
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)
    return destination


def claim_staged_artifacts(job: dict) -> tuple[Path, Path | None, Path | None]:
    """Freeze Tactical-writable hotfix artifacts before root verifies or executes them."""
    upload_id = str(job.get("upload_id") or "")
    job_id = str(job.get("id") or "")
    if not JOB_RE.fullmatch(upload_id) or not JOB_RE.fullmatch(job_id):
        raise RuntimeError("invalid staged hotfix/job identity")
    expected_package = STAGED_ROOT / f"{upload_id}.zip"
    declared = Path(str(job.get("package_path") or ""))
    if declared != expected_package:
        raise RuntimeError("hotfix package path does not match managed staging identity")

    work = RUNNING_ROOT / job_id
    work.mkdir(parents=True, exist_ok=False, mode=0o700) if not work.exists() else None
    os.chown(work, 0, 0)
    os.chmod(work, 0o700)
    package = _copy_nofollow_to_private(expected_package, work / "hotfix.zip", required=True)
    signature = _copy_nofollow_to_private(STAGED_ROOT / f"{upload_id}.sig", work / "hotfix.sig", required=False)
    metadata = _copy_nofollow_to_private(STAGED_ROOT / f"{upload_id}.release.json", work / "hotfix.release.json", required=False)
    expected_sha = str(job.get("package_sha256") or "").lower()
    if not SHA256_RE.fullmatch(expected_sha) or sha256_file(package) != expected_sha:
        raise RuntimeError("root-private hotfix package hash does not match queued job")
    return package, signature, metadata

def privileged_verify_hotfix(package: Path, signature: Path | None, metadata: Path | None):
    if not PRIVILEGED_TRUST.is_file():
        raise RuntimeError(f"privileged trust verifier is missing: {PRIVILEGED_TRUST}")
    require_root_owned(PRIVILEGED_TRUST)
    command = [sys.executable, str(PRIVILEGED_TRUST), "verify-hotfix", str(package)]
    if signature is not None:
        command += ["--signature", str(signature)]
    if metadata is not None:
        command += ["--metadata", str(metadata)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, env=privileged_env())
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "root hotfix trust verification failed").strip())
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("root hotfix trust verifier returned invalid output") from exc
    if not isinstance(payload, dict) or not payload.get("root_policy", {}).get("accepted"):
        raise RuntimeError("root hotfix trust verifier did not return an accepted policy result")
    return payload


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
    tactical_python = Path(config.get("TACTICAL_PYTHON", tactical_root / "api/env/bin/python"))
    system_python = Path("/usr/bin/python3")
    manage = Path(config.get("TACTICAL_BACKEND_ROOT", tactical_root / "api/tacticalrmm")) / "manage.py"
    tactical_user = config.get("TACTICAL_USER", "tactical")
    if effective.get("python_compile"):
        for target in targets:
            if not target["path"].endswith(".py"):
                continue
            result = subprocess.run([str(system_python), "-I", "-m", "py_compile", str(target["target_path"])], stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env())
            if result.returncode:
                raise RuntimeError(f"Python compile validation failed: {target['component']}/{target['path']}")
    if effective.get("django_check"):
        result = subprocess.run(["runuser", "-u", tactical_user, "--", str(tactical_python), str(manage), "check"], cwd=str(manage.parent), stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env())
        if result.returncode:
            raise RuntimeError(f"Django system check failed with status {result.returncode}")


def sync_reload(config, effective, log):
    if effective.get("ui_sync"):
        ui_sync = Path(config.get("UI_SYNC_SCRIPT", "/opt/tec-tac-src/ui/scripts/sync-modules.sh"))
        if ui_sync.is_file():
            require_root_owned(ui_sync)
            env = privileged_env({"TEC_TAC_UI_ROOT": config.get("UI_ROOT", "/var/lib/tec-tac/ui/tec-tac")})
            result = subprocess.run(["/usr/bin/bash", str(ui_sync)], stdout=log, stderr=subprocess.STDOUT, text=True, env=env)
            if result.returncode:
                raise RuntimeError(f"UI module synchronization failed with status {result.returncode}")
    if effective.get("reload") == "django":
        reload_script = Path(config.get("REPO_ROOT", "/opt/tec-tac")) / "scripts/reload-rmm-uwsgi.sh"
        require_root_owned(reload_script)
        result = subprocess.run(["/usr/bin/bash", str(reload_script)], stdout=log, stderr=subprocess.STDOUT, text=True, env=privileged_env())
        if result.returncode:
            raise RuntimeError(f"Tactical graceful reload failed with status {result.returncode}")


def apply_job(path, job, config, log):
    module_id = str(job.get("module_id") or "")
    hotfix_id = str(job.get("hotfix_id") or "")
    upload_id = str(job.get("upload_id") or "")
    package, signature_path, metadata_path = claim_staged_artifacts(job)
    root_trust = privileged_verify_hotfix(package, signature_path, metadata_path)
    job["root_publisher_trust"] = root_trust
    write_claimed_job(path, job, config)
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
        write_claimed_job(path, job, config)
        for row in resolved:
            st = row["target_path"].stat()
            copy_atomic(row["payload_path"], row["target_path"], st)
            if sha256_file(row["target_path"]) != row["sha256_after"]:
                raise RuntimeError(f"post-write hash mismatch: {row['component']}/{row['path']}")
            mutated.append(row)
        job["stage"] = "validate"
        write_claimed_job(path, job, config)
        validate_runtime(config, resolved, effective, log)
        job["stage"] = "runtime-sync"
        write_claimed_job(path, job, config)
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
        write_claimed_job(path, job, config)
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
        "publisher_trust": root_trust,
        "reload": effective["reload"],
        "ui_sync": effective["ui_sync"],
        "validation": {"python_compile": effective["python_compile"], "django_check": effective["django_check"]},
        "targets": [{key: row[key] for key in ("component", "path", "sha256_before", "sha256_after")} for row in resolved],
        "backup_root": str(backup_root),
    }
    atomic_json(record_path, record, mode=0o640, uid=0, gid=tactical_gid(config))
    upload_id = str(job.get("upload_id") or "")
    package.unlink(missing_ok=True)
    if JOB_RE.fullmatch(upload_id):
        (STAGED_ROOT / f"{upload_id}.sig").unlink(missing_ok=True)
        (STAGED_ROOT / f"{upload_id}.release.json").unlink(missing_ok=True)
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
    write_claimed_job(path, job, config)
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
    write_claimed_job(path, job, config)
    validate_runtime(config, targets, effective, log)
    job["stage"] = "runtime-sync"
    write_claimed_job(path, job, config)
    sync_reload(config, effective, log)
    history = dict(record)
    history["status"] = "rolled_back"
    history["rolled_back_at"] = now()
    history["rolled_back_by"] = job.get("requested_by")
    history["rollback_job_id"] = job["id"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    history_path = HISTORY_ROOT / module_id / f"{hotfix_id}.{stamp}.json"
    atomic_json(history_path, history, mode=0o640, uid=0, gid=tactical_gid(config))
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
    path, job = load_job(job_id, claimed=True)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("hotfix job was not dispatched")
    acquire_lock()
    config = load_config()
    log_path = LOGS_ROOT / f"{job_id}.log"
    job["status"] = "running"
    job["stage"] = "preflight"
    job["started_at"] = now()
    write_claimed_job(path, job, config)
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
            write_claimed_job(path, job, config)
            log.write(f"[TEC-TAC-HOTFIX] completed {job['finished_at']}\n")
    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = job.get("stage") or "failed"
        job["finished_at"] = now()
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        write_claimed_job(path, job, config)
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
