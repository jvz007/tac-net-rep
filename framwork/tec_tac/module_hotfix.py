"""Managed Tec-Tac module hotfix lifecycle.

Hotfixes are declarative, bounded file overlays for an exact installed module
version.  Core owns staging, validation, dispatch, history and rollback.  A
hotfix package never contains executable lifecycle hooks.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from .module_manager import ModuleManagerError, _atomic_json, _utcnow
from .trusted_publishers import PublisherTrustError, verify_release_files
from .trust_policy import TrustPolicyError, require_accepted as require_trust_accepted

HOTFIX_ROOT = Path("/var/lib/tec-tac/module-manager/hotfixes")
HOTFIX_STAGED_ROOT = HOTFIX_ROOT / "staged"
HOTFIX_JOBS_ROOT = HOTFIX_ROOT / "jobs"
HOTFIX_LOGS_ROOT = HOTFIX_ROOT / "logs"
HOTFIX_APPLIED_ROOT = HOTFIX_ROOT / "applied"
HOTFIX_HISTORY_ROOT = HOTFIX_ROOT / "history"
HOTFIX_HELPER = Path("/usr/local/sbin/tec-tac-module-hotfix")
CONFIG_FILE = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
HOTFIX_MANIFEST = "tec_tac_hotfix.json"
MAX_HOTFIX_BYTES = 25 * 1024 * 1024
MAX_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_TARGETS = 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
MODULE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ALLOWED_COMPONENTS = {"extension", "reportset"}
ALLOWED_RELOADS = {"none", "django"}


class ModuleHotfixError(ModuleManagerError):
    pass


def _config() -> dict[str, str]:
    values: dict[str, str] = {}
    if CONFIG_FILE.is_file():
        for raw in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _module_roots(module_id: str) -> dict[str, Path]:
    if not MODULE_RE.fullmatch(module_id or ""):
        raise ModuleHotfixError("Invalid module id.")
    cfg = _config()
    ext_base = Path(cfg.get("TEC_TAC_EXTENSIONS_ROOT", "/opt/tec-tac/extensions"))
    rep_base = Path(cfg.get("TEC_TAC_REPORTSETS_ROOT", "/opt/tec-tac/reportsets"))
    return {
        "extension": (ext_base / module_id).resolve(),
        "reportset": (rep_base / module_id).resolve(),
    }


def _manifest_version(root: Path, expected_id: str) -> str:
    manifest = root / "tec_tac.json"
    if not manifest.is_file():
        raise ModuleHotfixError(f"Installed module manifest is missing: {manifest}")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleHotfixError(f"Installed module manifest is unreadable: {manifest}") from exc
    if str(payload.get("id") or "") != expected_id:
        raise ModuleHotfixError(f"Installed module manifest identity does not match {expected_id}.")
    version = str(payload.get("version") or "").strip()
    if not version:
        raise ModuleHotfixError("Installed module version is missing.")
    return version


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative_path(value: str) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ModuleHotfixError(f"Unsafe hotfix target path: {value!r}")
    if any(not part or part.startswith(".") for part in path.parts):
        raise ModuleHotfixError(f"Unsupported hotfix target path: {value!r}")
    if path.name in {"tec_tac.json", "tec_tac_ui.json"}:
        raise ModuleHotfixError("Hotfixes may not replace module manifests; publish a normal module release instead.")
    if "migrations" in path.parts or "lifecycle" in path.parts:
        raise ModuleHotfixError("Hotfixes may not modify migrations or lifecycle hooks; publish a normal module release instead.")
    return path.as_posix()


def _zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_archive_members(zf: zipfile.ZipFile) -> None:
    expanded = 0
    seen = set()
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ModuleHotfixError(f"Unsafe path in hotfix archive: {name}")
        if _zip_member_is_symlink(info):
            raise ModuleHotfixError(f"Hotfix archives may not contain symlinks: {name}")
        if name in seen:
            raise ModuleHotfixError(f"Duplicate archive member: {name}")
        seen.add(name)
        expanded += int(info.file_size or 0)
        if expanded > MAX_EXPANDED_BYTES:
            raise ModuleHotfixError("Hotfix expanded size exceeds the 50 MiB limit.")


def _find_manifest(zf: zipfile.ZipFile) -> tuple[str, dict]:
    matches = [i.filename for i in zf.infolist() if not i.is_dir() and PurePosixPath(i.filename).name == HOTFIX_MANIFEST]
    if len(matches) != 1:
        raise ModuleHotfixError(f"Hotfix archive must contain exactly one {HOTFIX_MANIFEST}.")
    member = matches[0]
    try:
        payload = json.loads(zf.read(member).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
        raise ModuleHotfixError("Hotfix manifest is invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise ModuleHotfixError("Hotfix manifest must contain a JSON object.")
    prefix = PurePosixPath(member).parent
    base = "" if str(prefix) == "." else prefix.as_posix().rstrip("/") + "/"
    return base, payload


def _normalize_manifest(payload: dict) -> dict:
    allowed = {"type", "schema", "id", "module_id", "base_version", "description", "reload", "ui_sync", "validation", "targets"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ModuleHotfixError("Unsupported hotfix manifest key(s): " + ", ".join(unknown))
    if payload.get("type") != "tec-tac-hotfix":
        raise ModuleHotfixError("Hotfix manifest type must be 'tec-tac-hotfix'.")
    if payload.get("schema") != 1:
        raise ModuleHotfixError("Hotfix manifest schema must be 1.")
    hotfix_id = str(payload.get("id") or "").strip()
    module_id = str(payload.get("module_id") or "").strip()
    base_version = str(payload.get("base_version") or "").strip()
    if not hotfix_id or not ID_RE.fullmatch(hotfix_id):
        raise ModuleHotfixError("Hotfix id may contain only letters, numbers, dot, dash and underscore.")
    if not module_id or not MODULE_RE.fullmatch(module_id):
        raise ModuleHotfixError("Hotfix module_id is invalid.")
    if not base_version:
        raise ModuleHotfixError("Hotfix base_version is required and must identify the exact installed module version.")
    reload_mode = str(payload.get("reload") or "none").strip().lower()
    if reload_mode not in ALLOWED_RELOADS:
        raise ModuleHotfixError("Hotfix reload must be 'none' or 'django'.")
    validation = payload.get("validation") or {}
    if not isinstance(validation, dict):
        raise ModuleHotfixError("Hotfix validation must be an object.")
    validation_allowed = {"python_compile", "django_check"}
    if set(validation) - validation_allowed:
        raise ModuleHotfixError("Hotfix validation contains unsupported keys.")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ModuleHotfixError("Hotfix targets must be a non-empty array.")
    if len(targets) > MAX_TARGETS:
        raise ModuleHotfixError(f"Hotfix may replace at most {MAX_TARGETS} files.")
    normalized_targets = []
    seen_targets = set()
    for row in targets:
        if not isinstance(row, dict):
            raise ModuleHotfixError("Each hotfix target must be an object.")
        if set(row) - {"component", "path", "sha256_before", "sha256_after"}:
            raise ModuleHotfixError("Hotfix target contains unsupported keys.")
        component = str(row.get("component") or "").strip().lower()
        if component not in ALLOWED_COMPONENTS:
            raise ModuleHotfixError("Hotfix target component must be 'extension' or 'reportset'.")
        rel = _safe_relative_path(row.get("path"))
        before = str(row.get("sha256_before") or "").strip().lower()
        after = str(row.get("sha256_after") or "").strip().lower()
        if not SHA256_RE.fullmatch(before) or not SHA256_RE.fullmatch(after):
            raise ModuleHotfixError("Hotfix target hashes must be lowercase SHA-256 hex strings.")
        key = (component, rel)
        if key in seen_targets:
            raise ModuleHotfixError(f"Duplicate hotfix target: {component}/{rel}")
        seen_targets.add(key)
        normalized_targets.append({"component": component, "path": rel, "sha256_before": before, "sha256_after": after})
    any_python = any(row["path"].endswith(".py") for row in normalized_targets)
    any_ui = any(row["component"] == "extension" and (row["path"] == "ui" or row["path"].startswith("ui/")) for row in normalized_targets)
    return {
        "type": "tec-tac-hotfix",
        "schema": 1,
        "id": hotfix_id,
        "module_id": module_id,
        "base_version": base_version,
        "description": str(payload.get("description") or "").strip(),
        "reload": "django" if any_python else reload_mode,
        "ui_sync": bool(payload.get("ui_sync", False) or any_ui),
        "validation": {
            "python_compile": bool(validation.get("python_compile", False) or any_python),
            "django_check": bool(validation.get("django_check", False) or any_python),
        },
        "targets": normalized_targets,
    }


def inspect_hotfix_archive(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        raise ModuleHotfixError("Hotfix package was not found.")
    if path.stat().st_size > MAX_HOTFIX_BYTES:
        raise ModuleHotfixError("Hotfix package exceeds the 25 MiB limit.")
    if not zipfile.is_zipfile(path):
        raise ModuleHotfixError("Hotfix packages must be ZIP archives.")
    with zipfile.ZipFile(path) as zf:
        _validate_archive_members(zf)
        prefix, raw = _find_manifest(zf)
        manifest = _normalize_manifest(raw)
        permitted_files = {prefix + HOTFIX_MANIFEST, prefix + "README.md", prefix + "README.txt"}
        payload_members = {}
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            if name in permitted_files:
                continue
            payload_prefix = prefix + "payload/"
            if not name.startswith(payload_prefix):
                raise ModuleHotfixError(f"Unexpected file outside hotfix payload: {name}")
            payload_members[name] = info
        roots = _module_roots(manifest["module_id"])
        extension_version = _manifest_version(roots["extension"], manifest["module_id"])
        reportset_manifest = roots["reportset"] / "tec_tac.json"
        reportset_version = _manifest_version(roots["reportset"], manifest["module_id"]) if reportset_manifest.is_file() else None
        if reportset_version is not None and extension_version != reportset_version:
            raise ModuleHotfixError("Installed extension/reportset versions do not match.")
        if extension_version != manifest["base_version"]:
            raise ModuleHotfixError(
                f"Hotfix targets {manifest['module_id']} {manifest['base_version']}, but installed version is {extension_version}."
            )
        expected_payload_members = {f"{prefix}payload/{row['component']}/{row['path']}" for row in manifest["targets"]}
        unexpected_payload = sorted(set(payload_members) - expected_payload_members)
        if unexpected_payload:
            raise ModuleHotfixError("Hotfix payload contains undeclared file(s): " + ", ".join(unexpected_payload))
        targets = []
        for row in manifest["targets"]:
            payload_name = f"{prefix}payload/{row['component']}/{row['path']}"
            info = payload_members.get(payload_name)
            if info is None:
                raise ModuleHotfixError(f"Hotfix payload file is missing: {row['component']}/{row['path']}")
            payload_hash = hashlib.sha256(zf.read(info)).hexdigest()
            if payload_hash != row["sha256_after"]:
                raise ModuleHotfixError(f"Payload SHA-256 does not match manifest for {row['component']}/{row['path']}.")
            root = roots[row["component"]]
            target = (root / row["path"]).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ModuleHotfixError("Hotfix target escaped the module root.") from exc
            if not target.is_file() or target.is_symlink():
                raise ModuleHotfixError(f"Hotfix target must already exist as a regular module file: {row['component']}/{row['path']}")
            installed_hash = _sha256_file(target)
            if installed_hash != row["sha256_before"]:
                raise ModuleHotfixError(
                    f"Installed file does not match hotfix base SHA-256: {row['component']}/{row['path']}"
                )
            targets.append({**row, "payload_member": payload_name, "installed_sha256": installed_hash})
    already = applied_hotfix(manifest["module_id"], manifest["id"])
    if already:
        raise ModuleHotfixError(f"Hotfix {manifest['id']} is already applied to {manifest['module_id']}.")
    return {
        **manifest,
        "installed_version": extension_version,
        "targets": targets,
        "package_sha256": _sha256_file(path),
        "installable": True,
    }


def _copy_hotfix_sidecar(upload, destination: Path, *, limit: int = 1024 * 1024) -> None:
    written = 0
    with destination.open("wb") as handle:
        for chunk in upload.chunks():
            written += len(chunk)
            if written > limit:
                handle.close()
                destination.unlink(missing_ok=True)
                raise ModuleHotfixError("Hotfix trust sidecar exceeds the 1 MiB limit.")
            handle.write(chunk)
    os.chmod(destination, 0o640)


def _verify_hotfix_trust(*, package_path: Path, package_filename: str, signature_path: Path | None, signature_filename: str | None, metadata_path: Path | None) -> dict:
    try:
        trust = verify_release_files(
            package_path=package_path,
            package_filename=package_filename,
            signature_path=signature_path,
            signature_filename=signature_filename,
            metadata_path=metadata_path,
            required_permissions=("module.install",),
            require_signed=False,
        )
        trust["acceptance_policy"] = require_trust_accepted(trust, subject="Module hotfix")
        return trust
    except (PublisherTrustError, TrustPolicyError) as exc:
        raise ModuleHotfixError(f"Hotfix publisher trust verification failed: {exc}") from exc


def stage_uploaded_hotfix(upload, signature_upload=None, metadata_upload=None) -> dict:
    HOTFIX_STAGED_ROOT.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    package_path = HOTFIX_STAGED_ROOT / f"{upload_id}.zip"
    original_filename = str(getattr(upload, "name", "hotfix.zip"))
    total = 0
    with package_path.open("wb") as handle:
        for chunk in upload.chunks():
            total += len(chunk)
            if total > MAX_HOTFIX_BYTES:
                package_path.unlink(missing_ok=True)
                raise ModuleHotfixError("Hotfix package exceeds the 25 MiB limit.")
            handle.write(chunk)
    os.chmod(package_path, 0o640)
    sig_path = None
    metadata_path = None
    try:
        preview = inspect_hotfix_archive(package_path)
        if signature_upload is not None:
            sig_path = HOTFIX_STAGED_ROOT / f"{upload_id}.sig"
            _copy_hotfix_sidecar(signature_upload, sig_path)
        if metadata_upload is not None:
            metadata_path = HOTFIX_STAGED_ROOT / f"{upload_id}.release.json"
            _copy_hotfix_sidecar(metadata_upload, metadata_path)
        signature_filename = str(getattr(signature_upload, "name", "")) or None if signature_upload is not None else None
        publisher_trust = _verify_hotfix_trust(
            package_path=package_path,
            package_filename=original_filename,
            signature_path=sig_path,
            signature_filename=signature_filename,
            metadata_path=metadata_path,
        )
    except Exception:
        package_path.unlink(missing_ok=True)
        if sig_path: sig_path.unlink(missing_ok=True)
        if metadata_path: metadata_path.unlink(missing_ok=True)
        raise
    meta = {
        "upload_id": upload_id,
        "filename": original_filename,
        "package_path": str(package_path),
        "sha256": preview["package_sha256"],
        "preview": preview,
        "publisher_trust": publisher_trust,
        "created_at": _utcnow(),
    }
    if sig_path is not None:
        meta["signature_path"] = str(sig_path)
        meta["signature_filename"] = str(getattr(signature_upload, "name", sig_path.name))
    if metadata_path is not None:
        meta["release_metadata_path"] = str(metadata_path)
        meta["release_metadata_filename"] = str(getattr(metadata_upload, "name", metadata_path.name))
    _atomic_json(HOTFIX_STAGED_ROOT / f"{upload_id}.json", meta)
    return {key: value for key, value in meta.items() if key not in {"package_path", "signature_path", "release_metadata_path"}}


def _load_stage(upload_id: str) -> dict:
    try:
        uuid.UUID(str(upload_id))
    except ValueError as exc:
        raise ModuleHotfixError("Invalid hotfix upload id.") from exc
    path = HOTFIX_STAGED_ROOT / f"{upload_id}.json"
    if not path.is_file():
        raise ModuleHotfixError("Staged hotfix was not found.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleHotfixError("Staged hotfix metadata is unreadable.") from exc
    return payload


def discard_hotfix_stage(upload_id: str) -> None:
    meta = _load_stage(upload_id)
    for key in ("package_path", "signature_path", "release_metadata_path"):
        if meta.get(key):
            Path(str(meta[key])).unlink(missing_ok=True)
    (HOTFIX_STAGED_ROOT / f"{upload_id}.json").unlink(missing_ok=True)


def _dispatch(job_id: str) -> None:
    if not HOTFIX_HELPER.is_file():
        raise ModuleHotfixError(f"Module hotfix helper is not installed at {HOTFIX_HELPER}.")
    try:
        subprocess.run(
            ["sudo", "-n", str(HOTFIX_HELPER), "--dispatch", job_id],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
        )
    except Exception as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise ModuleHotfixError(f"Unable to dispatch module hotfix job: {str(detail).strip()}") from exc


def _new_job(payload: dict) -> dict:
    HOTFIX_JOBS_ROOT.mkdir(parents=True, exist_ok=True)
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
    _atomic_json(HOTFIX_JOBS_ROOT / f"{job_id}.json", job)
    return job


def _queue(payload: dict) -> dict:
    job = _new_job(payload)
    try:
        _dispatch(job["id"])
    except Exception as exc:
        job.update({"status": "dispatch_failed", "stage": "dispatch", "finished_at": _utcnow(), "error": str(exc), "error_type": exc.__class__.__name__})
        _atomic_json(HOTFIX_JOBS_ROOT / f"{job['id']}.json", job)
        raise
    return public_hotfix_job(job)


def queue_apply_hotfix(upload_id: str, *, requested_by: str | None = None) -> dict:
    meta = _load_stage(upload_id)
    package = Path(meta["package_path"])
    preview = inspect_hotfix_archive(package)
    trust = _verify_hotfix_trust(
        package_path=package,
        package_filename=str(meta.get("filename") or package.name),
        signature_path=Path(meta["signature_path"]) if meta.get("signature_path") else None,
        signature_filename=str(meta.get("signature_filename") or "") or None,
        metadata_path=Path(meta["release_metadata_path"]) if meta.get("release_metadata_path") else None,
    )
    return _queue({
        "action": "apply",
        "upload_id": str(upload_id),
        "package_path": str(package),
        "package_sha256": preview["package_sha256"],
        "signature_path": meta.get("signature_path"),
        "release_metadata_path": meta.get("release_metadata_path"),
        "publisher_trust": trust,
        "module_id": preview["module_id"],
        "hotfix_id": preview["id"],
        "base_version": preview["base_version"],
        "description": preview.get("description", ""),
        "preview": preview,
        "requested_by": str(requested_by) if requested_by else None,
    })


def _record_path(module_id: str, hotfix_id: str) -> Path:
    return HOTFIX_APPLIED_ROOT / module_id / f"{hotfix_id}.json"


def applied_hotfix(module_id: str, hotfix_id: str) -> dict | None:
    if not MODULE_RE.fullmatch(module_id or "") or not ID_RE.fullmatch(hotfix_id or ""):
        return None
    path = _record_path(module_id, hotfix_id)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def list_applied_hotfixes(module_id: str | None = None) -> list[dict]:
    if module_id is not None and not MODULE_RE.fullmatch(module_id or ""):
        raise ModuleHotfixError("Invalid module id.")
    roots = [HOTFIX_APPLIED_ROOT / module_id] if module_id else list(HOTFIX_APPLIED_ROOT.glob("*")) if HOTFIX_APPLIED_ROOT.is_dir() else []
    rows = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    rows.sort(key=lambda row: str(row.get("applied_at") or ""))
    return rows


def queue_rollback_hotfix(module_id: str, hotfix_id: str, *, requested_by: str | None = None) -> dict:
    record = applied_hotfix(module_id, hotfix_id)
    if not record:
        raise ModuleHotfixError("Applied hotfix record was not found.")
    module_rows = list_applied_hotfixes(module_id)
    if module_rows and module_rows[-1].get("id") != hotfix_id:
        raise ModuleHotfixError("Hotfixes must be rolled back in reverse application order.")
    return _queue({
        "action": "rollback",
        "module_id": module_id,
        "hotfix_id": hotfix_id,
        "base_version": record.get("base_version"),
        "description": record.get("description", ""),
        "requested_by": str(requested_by) if requested_by else None,
    })


def public_hotfix_job(job: dict) -> dict:
    allowed = {
        "id", "status", "created_at", "started_at", "finished_at", "stage", "error", "error_type",
        "action", "module_id", "hotfix_id", "base_version", "description", "package_sha256", "requested_by", "rolled_back",
    }
    result = {key: value for key, value in job.items() if key in allowed}
    log = HOTFIX_LOGS_ROOT / f"{job.get('id')}.log"
    if log.is_file():
        try:
            result["log_tail"] = log.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
        except OSError:
            result["log_tail"] = []
    else:
        result["log_tail"] = []
    return result


def get_hotfix_job(job_id: str) -> dict:
    try:
        uuid.UUID(str(job_id))
    except ValueError as exc:
        raise ModuleHotfixError("Invalid hotfix job id.") from exc
    path = HOTFIX_JOBS_ROOT / f"{job_id}.json"
    if not path.is_file():
        raise ModuleHotfixError("Hotfix job was not found.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleHotfixError("Hotfix job status is unreadable.") from exc
    return public_hotfix_job(payload)


def hotfix_summary(module_id: str) -> dict:
    rows = list_applied_hotfixes(module_id)
    return {
        "count": len(rows),
        "ids": [str(row.get("id")) for row in rows if row.get("id")],
        "latest": rows[-1].get("id") if rows else None,
    }
