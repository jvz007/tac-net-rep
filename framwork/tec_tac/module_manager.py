"""Tec-Tac module discovery, package inspection, staging, and job dispatch.

The Django process never performs privileged installation work directly.
It validates/stages packages under /var/lib/tec-tac/module-manager and asks the
root-owned helper installed by ``install.sh`` to execute an opaque UUID job.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .registry import RegistryError, discover_plugins, get_plugins

STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
STAGED_ROOT = STATE_ROOT / "staged"
JOBS_ROOT = STATE_ROOT / "jobs"
LOGS_ROOT = STATE_ROOT / "logs"
HELPER = Path("/usr/local/sbin/tec-tac-module-job")
MAX_PACKAGE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
PROTECTED_PLUGIN_IDS = frozenset({"example", "legacy-reporting-poc"})


class ModuleManagerError(RuntimeError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)


def _safe_archive_name(name: str) -> Path:
    normalized = name.replace("\\", "/")
    value = PurePosixPath(normalized)
    if value.is_absolute() or ".." in value.parts:
        raise ModuleManagerError(f"Unsafe archive path: {name!r}")
    return Path(*value.parts)


def _extract_archive(archive: Path, dest: Path) -> None:
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ModuleManagerError("Archive contains too many members.")
            if sum(info.file_size for info in infos) > MAX_EXTRACTED_BYTES:
                raise ModuleManagerError("Archive expands beyond the allowed size limit.")
            for info in infos:
                rel = _safe_archive_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ModuleManagerError(f"Archive contains a symbolic link: {info.filename!r}")
                target = (dest / rel).resolve()
                try:
                    target.relative_to(dest.resolve())
                except ValueError as exc:
                    raise ModuleManagerError(f"Archive path escapes extraction root: {info.filename!r}") from exc
            zf.extractall(dest)
        return

    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ModuleManagerError("Archive contains too many members.")
            if sum(member.size for member in members if member.isfile()) > MAX_EXTRACTED_BYTES:
                raise ModuleManagerError("Archive expands beyond the allowed size limit.")
            for member in members:
                rel = _safe_archive_name(member.name)
                if member.issym() or member.islnk():
                    raise ModuleManagerError(f"Archive contains a link: {member.name!r}")
                if not (member.isdir() or member.isfile()):
                    raise ModuleManagerError(f"Archive contains an unsupported special file: {member.name!r}")
                target = (dest / rel).resolve()
                try:
                    target.relative_to(dest.resolve())
                except ValueError as exc:
                    raise ModuleManagerError(f"Archive path escapes extraction root: {member.name!r}") from exc
            tf.extractall(dest)
        return

    raise ModuleManagerError("Package must end in .zip, .tar.gz, or .tgz")


def _find_pair(extracted: Path) -> tuple[Path, Path]:
    extensions = []
    reportsets = []
    for manifest in extracted.rglob("tec_tac.json"):
        parent = manifest.parent
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ModuleManagerError(f"Unable to read {manifest.name}: {exc}") from exc
        if parent.parent.name == "extensions" and payload.get("type") == "extension":
            extensions.append(parent)
        elif parent.parent.name == "reportsets" and payload.get("type") == "reportset":
            reportsets.append(parent)
    if len(extensions) != 1:
        raise ModuleManagerError(f"Package must contain exactly one extension manifest; found {len(extensions)}")
    if len(reportsets) != 1:
        raise ModuleManagerError(f"Package must contain exactly one reportset manifest; found {len(reportsets)}")
    return extensions[0], reportsets[0]


def _read_ui_manifest(extension_root: Path, plugin_id: str, permission_codes: set[str]) -> dict | None:
    path = extension_root / "tec_tac_ui.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleManagerError(f"Unable to read UI manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModuleManagerError("UI manifest must contain a JSON object.")
    module_id = str(payload.get("id", "")).strip()
    if module_id != plugin_id:
        raise ModuleManagerError(f"UI manifest id {module_id!r} must match extension id {plugin_id!r}.")
    entry = str(payload.get("entry", "")).strip()
    public = payload.get("public")
    if public is not None and not isinstance(public, dict):
        raise ModuleManagerError("UI manifest public must be an object when provided.")

    public_entry = ""
    public_base_path = ""
    if public:
        public_entry = str(public.get("entry", "")).strip()
        if not public_entry:
            raise ModuleManagerError("UI manifest public.entry is required when public UI is declared.")
        expected_base = f"/public/{plugin_id}"
        public_base_path = str(public.get("base_path", expected_base)).strip()
        if public_base_path != expected_base:
            raise ModuleManagerError(
                f"Public UI base_path must be exactly {expected_base!r}."
            )

    if not entry and not public_entry:
        raise ModuleManagerError("UI manifest must declare entry, public.entry, or both.")

    entry_path = None
    if entry:
        entry_path = (extension_root / entry).resolve()
        try:
            entry_path.relative_to(extension_root.resolve())
        except ValueError as exc:
            raise ModuleManagerError("UI entry escapes the extension root.") from exc
        if not entry_path.is_file():
            raise ModuleManagerError(f"UI entry does not exist: {entry}")

    public_entry_path = None
    if public_entry:
        public_entry_path = (extension_root / public_entry).resolve()
        try:
            public_entry_path.relative_to(extension_root.resolve())
        except ValueError as exc:
            raise ModuleManagerError("Public UI entry escapes the extension root.") from exc
        if not public_entry_path.is_file():
            raise ModuleManagerError(f"Public UI entry does not exist: {public_entry}")

    if entry_path and public_entry_path and entry_path.parent != public_entry_path.parent:
        raise ModuleManagerError(
            "Authenticated and public UI entries must share the same bundle directory."
        )

    permissions = payload.get("permissions") or []
    if not isinstance(permissions, list) or any(not isinstance(item, str) or not item.strip() for item in permissions):
        raise ModuleManagerError("UI manifest permissions must be an array of non-empty strings.")
    unknown = sorted(set(permissions) - permission_codes)
    if unknown:
        raise ModuleManagerError("UI manifest references undeclared extension permission(s): " + ", ".join(unknown))
    navigation = payload.get("navigation") or {}
    if not isinstance(navigation, dict):
        raise ModuleManagerError("UI manifest navigation must be an object.")
    return {
        "version": str(payload.get("version", "0.0.0")),
        "entry": entry or None,
        "navigation": navigation,
        "permissions": permissions,
        "public": (
            {"entry": public_entry, "base_path": public_base_path}
            if public_entry
            else None
        ),
    }


def _permission_codes(plugin) -> set[str]:
    return {code for _, values in plugin.permission_groups for code in values}


def _pair_payload(extension, reportset, *, ui: dict | None = None, installed: bool = True) -> dict:
    permissions = _permission_codes(extension)
    return {
        "id": extension.plugin_id,
        "extension_version": extension.version,
        "reportset_version": reportset.version,
        "versions_match": extension.version == reportset.version,
        "django_apps": list(extension.django_apps) + list(reportset.django_apps),
        "permission_groups": [
            {"name": name, "permissions": list(values)} for name, values in extension.permission_groups
        ],
        "permission_count": len(permissions),
        "ui": ui,
        "ui_enabled": ui is not None,
        "authenticated_ui_enabled": bool(ui and ui.get("entry")),
        "public_ui_enabled": bool(ui and ui.get("public")),
        "installed": installed,
        "managed": extension.plugin_id not in PROTECTED_PLUGIN_IDS,
        "protected": extension.plugin_id in PROTECTED_PLUGIN_IDS,
    }


def installed_catalog() -> list[dict]:
    plugins = get_plugins()
    extensions = {p.plugin_id: p for p in plugins if p.plugin_type == "extension"}
    reportsets = {p.plugin_id: p for p in plugins if p.plugin_type == "reportset"}
    result = []
    for plugin_id, extension in sorted(extensions.items()):
        reportset = reportsets.get(plugin_id)
        if reportset is None:
            continue
        ui_error = None
        try:
            ui = _read_ui_manifest(extension.root, plugin_id, _permission_codes(extension))
        except ModuleManagerError as exc:
            ui = None
            ui_error = str(exc)
        item = _pair_payload(extension, reportset, ui=ui)
        item["ui_error"] = ui_error
        item["status"] = "invalid-ui" if ui_error else ("reference" if item["protected"] else "installed")
        result.append(item)
    for plugin in sorted((p for p in plugins if p.plugin_type == "legacy"), key=lambda p: p.plugin_id):
        result.append({
            "id": plugin.plugin_id,
            "extension_version": plugin.version,
            "reportset_version": None,
            "versions_match": None,
            "django_apps": list(plugin.django_apps),
            "permission_groups": [],
            "permission_count": 0,
            "ui": None,
            "ui_enabled": False,
            "authenticated_ui_enabled": False,
            "public_ui_enabled": False,
            "installed": True,
            "managed": False,
            "protected": True,
            "legacy": True,
            "status": "legacy",
        })
    return result


def inspect_archive(archive: Path) -> dict:
    archive = archive.resolve()
    if not archive.is_file():
        raise ModuleManagerError("Staged package was not found.")
    with tempfile.TemporaryDirectory(prefix="tec-tac-inspect-") as tmp:
        extracted = Path(tmp) / "payload"
        extracted.mkdir()
        _extract_archive(archive, extracted)
        ext_root, rep_root = _find_pair(extracted)
        if ext_root.name != rep_root.name:
            raise ModuleManagerError("Extension and ReportSet IDs do not match.")
        stage = Path(tmp) / "registry"
        (stage / "extensions").mkdir(parents=True)
        (stage / "reportsets").mkdir(parents=True)
        shutil.copytree(ext_root, stage / "extensions" / ext_root.name)
        shutil.copytree(rep_root, stage / "reportsets" / rep_root.name)
        try:
            discovered = discover_plugins(stage / "extensions", stage / "reportsets")
        except RegistryError as exc:
            raise ModuleManagerError(str(exc)) from exc
        extension = next(p for p in discovered if p.plugin_type == "extension")
        reportset = next(p for p in discovered if p.plugin_type == "reportset")
        ui = _read_ui_manifest(extension.root, extension.plugin_id, _permission_codes(extension))
        package = _pair_payload(extension, reportset, ui=ui, installed=False)

    installed = {item["id"]: item for item in installed_catalog()}
    current = installed.get(package["id"])
    package["already_installed"] = current is not None
    package["current"] = current
    package["replace_required"] = current is not None
    protected = package["id"] in PROTECTED_PLUGIN_IDS
    package["protected"] = protected
    package["managed"] = not protected
    package["installable"] = bool(package["versions_match"]) and not protected
    if protected:
        package["install_block_reason"] = "This module ID is framework-protected and cannot be installed or replaced from the UI."
    elif not package["versions_match"]:
        package["install_block_reason"] = "Extension and ReportSet versions must match."
    else:
        package["install_block_reason"] = None
    return package


def _allowed_suffix(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tar.gz"):
        return ".tar.gz"
    if lower.endswith(".tgz"):
        return ".tgz"
    if lower.endswith(".zip"):
        return ".zip"
    raise ModuleManagerError("Package must end in .zip, .tar.gz, or .tgz")


def stage_uploaded_package(upload) -> dict:
    size = int(getattr(upload, "size", 0) or 0)
    if size <= 0:
        raise ModuleManagerError("Package is empty.")
    if size > MAX_PACKAGE_BYTES:
        raise ModuleManagerError(f"Package exceeds the {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB limit.")
    suffix = _allowed_suffix(str(getattr(upload, "name", "package")))
    STAGED_ROOT.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    package_path = STAGED_ROOT / f"{upload_id}{suffix}"
    digest = hashlib.sha256()
    written = 0
    with package_path.open("wb") as handle:
        for chunk in upload.chunks():
            written += len(chunk)
            if written > MAX_PACKAGE_BYTES:
                handle.close()
                package_path.unlink(missing_ok=True)
                raise ModuleManagerError(f"Package exceeds the {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB limit.")
            digest.update(chunk)
            handle.write(chunk)
    os.chmod(package_path, 0o640)
    try:
        preview = inspect_archive(package_path)
    except Exception:
        package_path.unlink(missing_ok=True)
        raise
    metadata = {
        "upload_id": upload_id,
        "filename": str(getattr(upload, "name", package_path.name)),
        "package_path": str(package_path),
        "sha256": digest.hexdigest(),
        "size": written,
        "created_at": _utcnow(),
        "preview": preview,
    }
    _atomic_json(STAGED_ROOT / f"{upload_id}.json", metadata)
    return {k: v for k, v in metadata.items() if k != "package_path"}


def _load_stage(upload_id: str) -> dict:
    try:
        uuid.UUID(str(upload_id))
    except ValueError as exc:
        raise ModuleManagerError("Invalid upload id.") from exc
    meta_path = STAGED_ROOT / f"{upload_id}.json"
    if not meta_path.is_file():
        raise ModuleManagerError("Staged package was not found or has already been consumed.")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleManagerError("Staged package metadata is invalid.") from exc
    path = Path(str(meta.get("package_path", ""))).resolve()
    try:
        path.relative_to(STAGED_ROOT.resolve())
    except ValueError as exc:
        raise ModuleManagerError("Staged package path is invalid.") from exc
    if not path.is_file():
        raise ModuleManagerError("Staged package file is missing.")
    meta["package_path"] = str(path)
    return meta



def discard_stage(upload_id: str) -> None:
    meta = _load_stage(upload_id)
    package = Path(meta["package_path"])
    package.unlink(missing_ok=True)
    (STAGED_ROOT / f"{upload_id}.json").unlink(missing_ok=True)

def _new_job(payload: dict) -> dict:
    JOBS_ROOT.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": _utcnow(),
        "started_at": None,
        "finished_at": None,
        "stage": "queued",
        "error": None,
        "error_type": None,
        **payload,
    }
    _atomic_json(JOBS_ROOT / f"{job_id}.json", job)
    return job


def _dispatch(job_id: str) -> None:
    if not HELPER.is_file():
        raise ModuleManagerError(f"Privileged module helper is not installed at {HELPER}.")
    try:
        subprocess.run(
            ["sudo", "-n", str(HELPER), "--dispatch", job_id],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise ModuleManagerError(f"Unable to dispatch privileged module job: {detail.strip()}") from exc


def queue_install(upload_id: str, replace: bool = False, requested_by: str | None = None) -> dict:
    meta = _load_stage(upload_id)
    preview = inspect_archive(Path(meta["package_path"]))
    if not preview.get("installable", False):
        raise ModuleManagerError(preview.get("install_block_reason") or "Package is not installable.")
    if preview["already_installed"] and not replace:
        raise ModuleManagerError("This module is already installed; replacement must be explicitly confirmed.")
    if not preview["already_installed"] and replace:
        raise ModuleManagerError("Replacement was requested but the module is not currently installed.")
    job = _new_job({
        "action": "install",
        "plugin_id": preview["id"],
        "upload_id": upload_id,
        "package_path": meta["package_path"],
        "replace": bool(replace),
        "package_sha256": meta.get("sha256"),
        "package_filename": meta.get("filename"),
        "requested_by": str(requested_by) if requested_by else None,
    })
    try:
        _dispatch(job["id"])
    except Exception as exc:
        job["status"] = "dispatch_failed"
        job["stage"] = "dispatch"
        job["finished_at"] = _utcnow()
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        _atomic_json(JOBS_ROOT / f"{job['id']}.json", job)
        raise
    return public_job(job)


def queue_remove(plugin_id: str, requested_by: str | None = None) -> dict:
    if not plugin_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in plugin_id):
        raise ModuleManagerError("Invalid module id.")
    installed = {item["id"]: item for item in installed_catalog()}
    item = installed.get(plugin_id)
    if not item:
        raise ModuleManagerError("Module is not installed.")
    if not item.get("managed"):
        raise ModuleManagerError("This module is framework-protected and cannot be removed from the UI.")
    job = _new_job({
        "action": "remove",
        "plugin_id": plugin_id,
        "purge_data": False,
        "requested_by": str(requested_by) if requested_by else None,
    })
    try:
        _dispatch(job["id"])
    except Exception as exc:
        job["status"] = "dispatch_failed"
        job["stage"] = "dispatch"
        job["finished_at"] = _utcnow()
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        _atomic_json(JOBS_ROOT / f"{job['id']}.json", job)
        raise
    return public_job(job)


def public_job(job: dict) -> dict:
    allowed = {
        "id", "status", "created_at", "started_at", "finished_at", "stage", "error", "error_type",
        "action", "plugin_id", "replace", "purge_data", "package_sha256", "package_filename", "requested_by",
    }
    result = {key: value for key, value in job.items() if key in allowed}
    log_path = LOGS_ROOT / f"{job.get('id')}.log"
    if log_path.is_file():
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            result["log_tail"] = lines[-40:]
        except OSError:
            result["log_tail"] = []
    else:
        result["log_tail"] = []
    return result


def get_job(job_id: str) -> dict:
    try:
        uuid.UUID(str(job_id))
    except ValueError as exc:
        raise ModuleManagerError("Invalid job id.") from exc
    path = JOBS_ROOT / f"{job_id}.json"
    if not path.is_file():
        raise ModuleManagerError("Module job was not found.")
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleManagerError("Module job status is unreadable.") from exc
    return public_job(job)


def list_jobs(*, limit: int = 200) -> list[dict]:
    """Return persistent module lifecycle history, newest first.

    Job JSON files are already the authoritative lifecycle records. History reads
    those records instead of maintaining a second audit store, so old installs,
    upgrades, removals and state changes remain visible after the active job UI
    has gone away.
    """
    try:
        limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        limit = 200
    if not JOBS_ROOT.is_dir():
        return []
    rows = []
    for path in JOBS_ROOT.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            row = public_job(payload)
            actions = ((payload.get("plan") or {}).get("actions") or []) if isinstance(payload.get("plan"), dict) else []
            module_ids = [str(item.get("id")) for item in actions if isinstance(item, dict) and item.get("id")]
            if not module_ids and payload.get("plugin_id") and payload.get("plugin_id") != "batch":
                module_ids = [str(payload.get("plugin_id"))]
            row["module_ids"] = module_ids
            row["batch"] = bool(payload.get("action") in {"batch_install", "bundle_install"} or payload.get("plugin_id") == "batch")
            rows.append(row)
        except (OSError, json.JSONDecodeError):
            continue
    rows.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return rows[:limit]
