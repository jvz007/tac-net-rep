#!/usr/bin/env python3
"""Root-owned Tec-Tac self-update worker.

Installed outside both replaceable repositories. Dispatch creates an independent
systemd transient service so framework updates may restart Tactical services
without terminating the update worker itself.
"""
from __future__ import annotations

import fcntl
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
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
STATE_ROOT = Path("/var/lib/tec-tac/system-updates")
JOBS_ROOT = STATE_ROOT / "jobs"
STAGED_ROOT = STATE_ROOT / "staged"
RUNNING_ROOT = STATE_ROOT / "running"
LOGS_ROOT = STATE_ROOT / "logs"
BACKUPS_ROOT = STATE_ROOT / "backups"
HISTORY_ROOT = STATE_ROOT / "history"
LOCK_PATH = STATE_ROOT / "update.lock"
CONFIG = Path("/etc/tec-tac/system-update.conf")
SELF = Path("/usr/local/sbin/tec-tac-system-update")


def now():
    return datetime.now(timezone.utc).isoformat()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def job_path(job_id):
    if not JOB_RE.fullmatch(job_id):
        raise SystemExit("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def load_job(job_id):
    path = job_path(job_id)
    if not path.is_file():
        raise SystemExit("job not found")
    job = json.loads(path.read_text(encoding="utf-8"))
    if job.get("id") != job_id or job.get("action") != "install":
        raise SystemExit("invalid system update job")
    if job.get("component") not in {"framework", "ui"}:
        raise SystemExit("invalid system update component")
    return path, job


def tactical_gid(config):
    return pwd.getpwnam(config.get("TACTICAL_USER", "tactical")).pw_gid


def claim_job(job_id):
    path, job = load_job(job_id)
    if job.get("status") != "queued":
        raise SystemExit("job is not queued")
    cfg = load_config()
    gid = tactical_gid(cfg)
    for root, mode in ((RUNNING_ROOT, 0o2750), (LOGS_ROOT, 0o2750), (BACKUPS_ROOT, 0o2750), (HISTORY_ROOT, 0o2750)):
        root.mkdir(parents=True, exist_ok=True)
        os.chown(root, 0, gid)
        os.chmod(root, mode)
    package = Path(str(job.get("package_path", ""))).resolve()
    try:
        package.relative_to(STAGED_ROOT.resolve())
    except ValueError:
        raise SystemExit("invalid staged package path")
    if not package.is_file():
        raise SystemExit("staged package missing")
    target = RUNNING_ROOT / f"{job_id}{''.join(package.suffixes)}"
    os.replace(package, target)
    os.chown(target, 0, gid)
    os.chmod(target, 0o640)
    meta = STAGED_ROOT / f"{job.get('upload_id')}.json"
    meta.unlink(missing_ok=True)
    job["package_path"] = str(target)
    job["status"] = "dispatched"
    job["stage"] = "dispatched"
    atomic_json(path, job)
    os.chown(path, 0, gid)
    return path, job


def dispatch(job_id):
    claim_job(job_id)
    unit = f"tec-tac-system-update-{job_id}"
    command = [
        "systemd-run", "--quiet", "--collect", f"--unit={unit}",
        "--property=Type=exec", "--property=Nice=5",
        str(SELF), "--run", job_id,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
            tf.extractall(dest)
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


def backup_root(target, component, old_version, job_id):
    BACKUPS_ROOT.mkdir(parents=True, exist_ok=True)
    safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "_", old_version or "unknown")
    backup = BACKUPS_ROOT / f"{component}-{safe_version}-{stamp()}-{job_id[:8]}.tar.gz"
    with tarfile.open(backup, "w:gz") as tf:
        tf.add(target, arcname=target.name)
    os.chmod(backup, 0o640)
    return backup


def remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


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


def _tree_digest(root):
    """Stable digest for a plugin tree, including relative paths and file bytes."""
    import hashlib
    digest = hashlib.sha256()
    root = Path(root)
    if not root.exists():
        return None
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
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


def restore_backup(backup, target):
    parent = target.parent
    preserved_git = target / ".git"
    git_tmp = None
    if preserved_git.exists():
        git_tmp = parent / f".{target.name}.git.rollback"
        remove_path(git_tmp)
        os.replace(preserved_git, git_tmp)
    remove_path(target)
    with tarfile.open(backup, "r:gz") as tf:
        tf.extractall(parent)
    if git_tmp and git_tmp.exists() and not (target / ".git").exists():
        os.replace(git_tmp, target / ".git")
    elif git_tmp:
        remove_path(git_tmp)


INSTALL_TIMEOUT_SECONDS = 1800
VERIFY_TIMEOUT_SECONDS = 90


def _run_bounded(command, *, log, timeout, cwd=None, env=None, label="command"):
    try:
        result = subprocess.run(
            command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, text=True,
            stdin=subprocess.DEVNULL, env=env, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} timed out after {timeout} seconds") from exc
    return result.returncode


def run_install(component, target, log):
    if component == "framework":
        command = ["bash", str(target / "install.sh")]
    else:
        command = ["bash", str(target / "scripts" / "install.sh")]
    return _run_bounded(command, log=log, timeout=INSTALL_TIMEOUT_SECONDS, label=f"{component} installer")


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
    version = (target / "VERSION").read_text(encoding="utf-8").strip()
    if version != expected:
        raise RuntimeError(f"VERSION verification failed: expected {expected}, found {version}")
    manifest_version = _read_package_version(target)
    if manifest_version != expected:
        raise RuntimeError(f"package manifest verification failed: expected {expected}, found {manifest_version or 'missing'}")

    if component == "framework":
        py = Path("/rmm/api/env/bin/python")
        manage = Path("/rmm/api/tacticalrmm/manage.py")
        env = {**os.environ, "PYTHONPATH": str(target / "framwork")}
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
            rc = _run_bounded(command, cwd="/rmm/api/tacticalrmm", log=log, env=env, timeout=VERIFY_TIMEOUT_SECONDS, label=label)
            if rc != 0:
                raise RuntimeError(f"{label} failed with status {rc}")
        recovery = target / "scripts" / "recovery"
        missing_exec = [p.name for p in sorted(recovery.glob("*.sh")) if not os.access(p, os.X_OK)]
        if missing_exec:
            raise RuntimeError("recovery script executable verification failed: " + ", ".join(missing_exec))
    else:
        deployed = Path("/var/lib/tec-tac/ui/tec-tac")
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
    path, job = load_job(job_id)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    cfg = load_config()
    component = job["component"]
    target = Path(cfg.get("FRAMEWORK_ROOT", "/opt/tec-tac") if component == "framework" else cfg.get("UI_REPO_ROOT", "/opt/tec-tac-ui")).resolve()
    package = Path(job["package_path"])
    log_path = LOGS_ROOT / f"{job_id}.log"
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)

    with LOCK_PATH.open("a+") as lock, log_path.open("a", encoding="utf-8") as log:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another Tec-Tac system update is already running") from exc

        job["status"] = "running"
        job["started_at"] = now()
        job["stage"] = "preflight"
        atomic_json(path, job)
        log.write(f"[TEC-TAC-UPDATE] started {now()} component={component} version={job.get('version')} source={job.get('source')}\n")
        log.flush()

        if not target.is_dir():
            raise RuntimeError(f"installed component root is missing: {target}")
        old_version = (target / "VERSION").read_text(encoding="utf-8").strip() if (target / "VERSION").is_file() else "unknown"

        job["stage"] = "backup"
        atomic_json(path, job)
        backup = backup_root(target, component, old_version, job_id)
        job["backup_path"] = str(backup)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-UPDATE] backup={backup}\n")
        log.flush()

        try:
            job["stage"] = "extract"
            atomic_json(path, job)
            work = RUNNING_ROOT / f"{job_id}.work"
            remove_path(work)
            work.mkdir(parents=True)
            extract_archive(package, work)
            source = detect_root(work, component)
            package_version = (source / "VERSION").read_text(encoding="utf-8").strip()
            if package_version != job.get("version"):
                raise RuntimeError("package VERSION changed after inspection")

            job["stage"] = "deploy"
            atomic_json(path, job)
            dynamic_inventory = snapshot_dynamic_plugins(target) if component == "framework" else {}
            if component == "framework":
                deploy_framework(source, target)
                verify_dynamic_plugins(target, dynamic_inventory)
            else:
                deploy_ui(source, target)

            job["stage"] = "install"
            atomic_json(path, job)
            log.write(f"[TEC-TAC-UPDATE] running {component} installer\n")
            log.flush()
            rc = run_install(component, target, log)
            if rc != 0:
                raise RuntimeError(f"{component} installer exited with status {rc}")

            job["stage"] = "verify"
            atomic_json(path, job)
            verify(component, target, str(job.get("version")), log)
            job["rollback"] = {"performed": False, "status": "not-required"}
            job["status"] = "succeeded"
            job["stage"] = "complete"
            job["finished_at"] = now()
            job["error"] = None
            job["error_type"] = None
            log.write(f"[TEC-TAC-UPDATE] completed {now()}\n")
        except Exception as exc:
            log.write(f"[TEC-TAC-UPDATE] update failed: {exc}\n")
            log.write("[TEC-TAC-UPDATE] restoring previous component backup\n")
            log.flush()
            job["stage"] = "rollback"
            job["error"] = str(exc)
            job["error_type"] = exc.__class__.__name__
            atomic_json(path, job)
            rollback_error = None
            try:
                restore_backup(backup, target)
                rollback_rc = run_install(component, target, log)
                if rollback_rc != 0:
                    raise RuntimeError(f"rollback installer exited with status {rollback_rc}")
                job["rollback"] = {"performed": True, "status": "succeeded", "version": old_version}
            except Exception as rb_exc:
                rollback_error = str(rb_exc)
                job["rollback"] = {"performed": True, "status": "failed", "version": old_version, "error": rollback_error}
                log.write(f"[TEC-TAC-UPDATE] ROLLBACK FAILED: {rollback_error}\n")
            job["status"] = "failed"
            job["stage"] = "rolled-back" if rollback_error is None else "rollback-failed"
            job["finished_at"] = now()
        finally:
            atomic_json(path, job)
            HISTORY_ROOT.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, HISTORY_ROOT / path.name)
            try:
                package.unlink(missing_ok=True)
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


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    if len(sys.argv) != 3 or sys.argv[1] not in {"--dispatch", "--run"}:
        raise SystemExit("usage: tec-tac-system-update --dispatch|--run <job-id>")
    if sys.argv[1] == "--dispatch":
        dispatch(sys.argv[2])
    else:
        try:
            run_job(sys.argv[2])
        except BaseException as exc:
            mark_failed(sys.argv[2], exc)
            raise
