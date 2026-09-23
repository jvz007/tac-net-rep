#!/usr/bin/env python3
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
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

TREE_MANIFEST = "tec-tac-release.json"
TREE_SIGNATURE = "tec-tac-release.json.sig"
MAX_TREE_FILES = 20000
DEFAULT_SIGNED_RELEASE_MIN_VERSION = {"framework": "1.15.37", "ui": None}

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
CONFIG = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
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


def _git(command, target, *, check=True, capture=True):
    args = ["git", "-C", str(target), *command]
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
    )
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
    return (*nums, 1 if not suffix else 0, suffix.lower())


def _signed_release_min_version(component):
    cfg = load_config()
    key = f"TEC_TAC_{component.upper()}_SIGNED_RELEASE_MIN_VERSION"
    value = str(os.environ.get(key) or cfg.get(key) or DEFAULT_SIGNED_RELEASE_MIN_VERSION.get(component) or "").strip()
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


def _enforce_release_signature_cutoff(job):
    source = job.get("source") if isinstance(job.get("source"), dict) else {}
    if str(source.get("type") or "") != "release":
        return
    component = str(job.get("component") or "")
    minimum = _signed_release_min_version(component)
    if not minimum or _version_key(job.get("version")) < _version_key(minimum):
        return
    trust = job.get("release_trust") if isinstance(job.get("release_trust"), dict) else {}
    if not trust.get("verified") or not trust.get("signed"):
        raise RuntimeError(f"signed {component} release required from version {minimum}")


def prepare_source_checkout(target, component):
    """Validate the source checkout before any destructive update work."""
    if not (target / ".git").is_dir():
        raise RuntimeError(f"{component} source is not a Git checkout: {target}")

    # UI 0.10.4 and earlier could leave this npm-generated file untracked.
    # It is safe to remove only when Git confirms it is not tracked.
    if component == "ui":
        package_lock = target / "package-lock.json"
        if package_lock.exists():
            tracked = _git(["ls-files", "--error-unmatch", "package-lock.json"], target, check=False)
            if tracked.returncode != 0:
                package_lock.unlink()

    if _git(["diff", "--quiet"], target, check=False, capture=False).returncode != 0:
        raise RuntimeError(f"{component} source checkout has uncommitted tracked changes")
    if _git(["diff", "--cached", "--quiet"], target, check=False, capture=False).returncode != 0:
        raise RuntimeError(f"{component} source checkout has staged changes")
    status = _git(["status", "--porcelain", "--untracked-files=all"], target).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is not clean: {status.splitlines()[0]}")

    head = _git(["rev-parse", "HEAD"], target).stdout.strip()
    branch_result = _git(["symbolic-ref", "--quiet", "--short", "HEAD"], target, check=False)
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
    return {"head": head, "branch": branch}


def _replace_checkout_contents(source, target):
    """Replace a clean checkout worktree while retaining only its .git metadata."""
    for item in list(target.iterdir()):
        if item.name == ".git":
            continue
        remove_path(item)
    copy_tree_contents(source, target)


def apply_source_update(source, target, component, job):
    """Move the source checkout to the staged update and return rollback metadata."""
    previous = prepare_source_checkout(target, component)
    source_meta = job.get("source") if isinstance(job.get("source"), dict) else {}
    source_type = str(source_meta.get("type") or "offline")
    commit = str(source_meta.get("commit") or "").strip()

    if source_type in {"release", "branch"}:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise RuntimeError("online update is missing its resolved Git commit SHA")
        _git(["fetch", "--quiet", "origin", commit], target)
        _git(["cat-file", "-e", f"{commit}^{{commit}}"], target)
        _git(["reset", "--hard", commit], target)
        _git(["clean", "-fd"], target)
        mode = "online"
        update_branch = None
    else:
        safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(job.get("version") or "unknown"))
        update_branch = f"tec-tac/offline/{component}-{safe_version}-{str(job.get('id') or '')[:8]}"
        if _git(["show-ref", "--verify", "--quiet", f"refs/heads/{update_branch}"], target, check=False).returncode == 0:
            raise RuntimeError(f"offline update branch already exists: {update_branch}")
        _git(["checkout", "-b", update_branch], target)
        _replace_checkout_contents(source, target)
        _git(["add", "-A"], target)
        commit_result = _git(
            ["-c", "user.name=Tec-Tac System Update", "-c", "user.email=tec-tac@localhost",
             "commit", "--allow-empty", "--quiet", "-m",
             f"Tec-Tac offline {component} update {job.get('version')}"],
            target, check=False,
        )
        if commit_result.returncode != 0:
            detail = (commit_result.stderr or commit_result.stdout or "unable to create offline update commit").strip()
            raise RuntimeError(detail)
        commit = _git(["rev-parse", "HEAD"], target).stdout.strip()
        mode = "offline"

    status = _git(["status", "--porcelain", "--untracked-files=all"], target).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is dirty immediately after update: {status.splitlines()[0]}")
    return {**previous, "mode": mode, "update_branch": update_branch, "update_head": commit}


def restore_git_source(target, git_state):
    """Restore the source checkout to its exact pre-update HEAD/branch."""
    old_head = str((git_state or {}).get("head") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", old_head):
        raise RuntimeError("rollback Git state is missing the previous HEAD")
    old_branch = (git_state or {}).get("branch")
    update_branch = (git_state or {}).get("update_branch")

    _git(["reset", "--hard"], target)
    _git(["clean", "-fd"], target)
    if old_branch:
        _git(["checkout", "--quiet", old_branch], target)
        _git(["reset", "--hard", old_head], target)
    else:
        _git(["checkout", "--quiet", "--detach", old_head], target)
    if update_branch and update_branch != old_branch:
        _git(["branch", "-D", update_branch], target, check=False)
    _git(["clean", "-fd"], target)


def verify_source_runtime_layout(component, source_root):
    cfg = load_config()
    runtime_root = Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")).resolve()
    if (runtime_root / ".git").exists():
        raise RuntimeError("Tec-Tac runtime unexpectedly contains Git metadata")
    if not (source_root / ".git").is_dir():
        raise RuntimeError(f"{component} source checkout lost Git metadata")
    status = _git(["status", "--porcelain", "--untracked-files=all"], source_root).stdout.strip()
    if status:
        raise RuntimeError(f"{component} source checkout is dirty after update: {status.splitlines()[0]}")
    runtime_framework = Path(cfg.get("TEC_TAC_FRAMEWORK_ROOT", "/opt/tec-tac/framework")).resolve()
    if component == "framework" and runtime_framework == source_root.resolve():
        raise RuntimeError("framework source and runtime resolve to the same path")


def backup_root(target, component, old_version, job_id):
    BACKUPS_ROOT.mkdir(parents=True, exist_ok=True)
    safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "_", old_version or "unknown")
    backup = BACKUPS_ROOT / f"{component}-{safe_version}-{stamp()}-{job_id[:8]}.tar.gz"

    excluded_roots = {".git"}
    if component == "ui":
        excluded_roots.update({"node_modules", "dist"})

    def archive_filter(info):
        parts = Path(info.name).parts
        # info.name starts with target.name because arcname=target.name.
        if len(parts) > 1 and parts[1] in excluded_roots:
            return None
        return info

    with tarfile.open(backup, "w:gz") as tf:
        tf.add(target, arcname=target.name, filter=archive_filter)
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
        runtime_framework = Path(load_config().get("TEC_TAC_FRAMEWORK_ROOT", "/opt/tec-tac/framework"))
        env = {**os.environ, "PYTHONPATH": str(runtime_framework)}
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
    path, job = load_job(job_id)
    if job.get("status") not in {"dispatched", "running"}:
        raise SystemExit("job was not dispatched")
    cfg = load_config()
    component = job["component"]
    target = Path(cfg.get("TEC_TAC_FRAMEWORK_SOURCE", "/opt/tec-tac-src/framework") if component == "framework" else cfg.get("TEC_TAC_UI_SOURCE", "/opt/tec-tac-src/ui")).resolve()
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
        old_version = (target / "VERSION").read_text(encoding="utf-8").strip() if (target / "VERSION").is_file() else "unknown"
        expected_package_sha = str(job.get("package_sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_package_sha):
            raise RuntimeError("staged package SHA-256 is missing from job metadata")
        if _digest_file(package)[1] != expected_package_sha:
            raise RuntimeError("staged package bytes changed after inspection")
        _enforce_release_signature_cutoff(job)

        job["stage"] = "backup"
        atomic_json(path, job)
        backup = backup_root(target, component, old_version, job_id)
        job["backup_path"] = str(backup)
        atomic_json(path, job)
        log.write(f"[TEC-TAC-UPDATE] backup={backup}\n")
        log.flush()

        dynamic_inventory = {}
        git_state = None
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
            trust = job.get("release_trust") if isinstance(job.get("release_trust"), dict) else {}
            if trust.get("signed") or trust.get("verified"):
                job["stage"] = "verify-staged-signature-tree"
                atomic_json(path, job)
                file_count = verify_signed_tree_snapshot(source, component, package_version, trust)
                log.write(f"[TEC-TAC-UPDATE] verified staged signed tree files={file_count} publisher={trust.get('publisher_id')} key={trust.get('key_id')}\n")
                log.flush()

            job["stage"] = "deploy"
            atomic_json(path, job)
            runtime_root = Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")).resolve()
            dynamic_inventory = snapshot_dynamic_plugins(runtime_root) if component == "framework" else {}
            git_state = apply_source_update(source, target, component, job)
            job["source_git"] = {k: v for k, v in git_state.items() if v is not None}
            atomic_json(path, job)
            if trust.get("signed") or trust.get("verified"):
                job["stage"] = "verify-execution-signature-tree"
                atomic_json(path, job)
                file_count = verify_signed_tree_snapshot(target, component, package_version, trust)
                log.write(f"[TEC-TAC-UPDATE] verified execution checkout signed tree files={file_count} commit={job.get('source_git', {}).get('update_head')}\n")
                log.flush()
            if component == "framework":
                verify_dynamic_plugins(runtime_root, dynamic_inventory)

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
            if component == "framework":
                verify_dynamic_plugins(runtime_root, dynamic_inventory)
            verify_source_runtime_layout(component, target)
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
                if git_state:
                    restore_git_source(target, git_state)
                else:
                    restore_backup(backup, target)
                rollback_rc = run_install(component, target, log)
                if rollback_rc != 0:
                    raise RuntimeError(f"rollback installer exited with status {rollback_rc}")
                if component == "framework":
                    verify_dynamic_plugins(Path(cfg.get("TEC_TAC_ROOT", "/opt/tec-tac")).resolve(), dynamic_inventory)
                verify_source_runtime_layout(component, target)
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
