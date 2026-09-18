"""Tec-Tac Module Management v2.

Adds persistent enable/disable state, package dependency/version resolution,
framework/UI compatibility checks, multi-package install plans and bundle
inspection while preserving the 1.3.x package lifecycle implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from . import registry as registry_module
from .module_manager import (
    HELPER as V1_HELPER,
    JOBS_ROOT,
    MAX_PACKAGE_BYTES,
    ModuleManagerError,
    PROTECTED_PLUGIN_IDS,
    STAGED_ROOT,
    _atomic_json,
    _dispatch as dispatch_v1_job,
    _extract_archive,
    _find_pair,
    _load_stage,
    _new_job,
    _utcnow,
    discard_stage,
    get_job,
    inspect_archive,
    installed_catalog as installed_catalog_v1,
    public_job,
    stage_uploaded_package,
)
from .module_state import (
    ModuleStateError,
    is_enabled,
    is_visible,
    load_state,
    module_record,
    version_satisfies,
)

V2_HELPER = Path("/usr/local/sbin/tec-tac-module-v2-job")
BUNDLES_ROOT = STAGED_ROOT / "bundles"
BATCHES_ROOT = STAGED_ROOT / "batches"
BUNDLE_MANIFEST = "tec_tac_bundle.json"
FRAMEWORK_VERSION_FILE = Path("/opt/tec-tac/VERSION")
UI_VERSION_FILE = Path("/var/lib/tec-tac/ui/tec-tac/VERSION")
UI_PACKAGE_FILE = Path("/var/lib/tec-tac/ui/tec-tac/package.json")


class ModuleManagerV2Error(ModuleManagerError):
    pass


def _read_json(path: Path, label: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleManagerV2Error(f"Unable to read {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModuleManagerV2Error(f"{label} must contain a JSON object.")
    return payload


def _string_map(payload: dict, key: str) -> dict[str, str]:
    raw = payload.get(key) or {}
    if not isinstance(raw, dict):
        raise ModuleManagerV2Error(f"Manifest key {key!r} must be an object.")
    result = {}
    for module_id, constraint in raw.items():
        module_id = str(module_id).strip()
        constraint = str(constraint).strip() or "*"
        if not module_id:
            raise ModuleManagerV2Error(f"Manifest key {key!r} contains a blank module id.")
        # Validate constraint syntax immediately.
        try:
            version_satisfies("0.0.0", constraint)
        except ModuleStateError as exc:
            raise ModuleManagerV2Error(str(exc)) from exc
        result[module_id] = constraint
    return result


def _ui_default_visible(extension_root: Path) -> bool:
    """Return the package-declared default navigation visibility.

    The package may suggest a default, but persisted Module Manager state is the
    operator override and therefore takes precedence once set.
    """
    path = extension_root / "tec_tac_ui.json"
    if not path.is_file():
        return True
    payload = _read_json(path, "UI manifest")
    if isinstance(payload.get("visible"), bool):
        return payload["visible"]
    navigation = payload.get("navigation")
    if isinstance(navigation, dict) and isinstance(navigation.get("visible"), bool):
        return navigation["visible"]
    return True


def _extension_metadata(extension_root: Path) -> dict:
    payload = _read_json(extension_root / "tec_tac.json", "extension manifest")
    return {
        "id": str(payload.get("id", "")).strip(),
        "version": str(payload.get("version", "0.0.0")).strip(),
        "dependencies": _string_map(payload, "dependencies"),
        "optional_dependencies": _string_map(payload, "optional_dependencies"),
        "requires": _string_map(payload, "requires"),
        "default_visible": _ui_default_visible(extension_root),
    }


def _installed_extension_metadata(module_id: str) -> dict:
    root = registry_module.EXTENSIONS_ROOT / module_id
    if not root.is_dir():
        return {"id": module_id, "version": "0.0.0", "dependencies": {}, "optional_dependencies": {}, "requires": {}}
    return _extension_metadata(root)


def _runtime_versions() -> dict[str, str | None]:
    framework = None
    ui = None
    if FRAMEWORK_VERSION_FILE.is_file():
        framework = FRAMEWORK_VERSION_FILE.read_text(encoding="utf-8").strip()
    if UI_VERSION_FILE.is_file():
        ui = UI_VERSION_FILE.read_text(encoding="utf-8").strip()
    elif UI_PACKAGE_FILE.is_file():
        try:
            ui = str(json.loads(UI_PACKAGE_FILE.read_text(encoding="utf-8")).get("version") or "").strip() or None
        except (OSError, json.JSONDecodeError):
            ui = None
    return {"framework": framework, "ui": ui}


def _check_runtime_requirements(requires: dict[str, str]) -> list[dict]:
    versions = _runtime_versions()
    results = []
    for component, constraint in requires.items():
        current = versions.get(component)
        if component not in {"framework", "ui"}:
            results.append({"component": component, "constraint": constraint, "current": None, "satisfied": False, "reason": "unknown runtime component"})
            continue
        if not current:
            results.append({"component": component, "constraint": constraint, "current": None, "satisfied": False, "reason": "version unavailable"})
            continue
        try:
            ok = version_satisfies(current, constraint)
        except ModuleStateError as exc:
            raise ModuleManagerV2Error(str(exc)) from exc
        results.append({"component": component, "constraint": constraint, "current": current, "satisfied": ok, "reason": None if ok else "version constraint not satisfied"})
    return results


def installed_catalog_v2() -> list[dict]:
    base = installed_catalog_v1()
    state = load_state()
    metadata = {}
    for item in base:
        if item.get("legacy"):
            continue
        try:
            metadata[item["id"]] = _installed_extension_metadata(item["id"])
        except Exception as exc:
            metadata[item["id"]] = {"id": item["id"], "version": item.get("extension_version") or "0.0.0", "dependencies": {}, "optional_dependencies": {}, "requires": {}, "default_visible": True, "metadata_error": str(exc)}

    reverse = {item["id"]: [] for item in base}
    for module_id, meta in metadata.items():
        for dep_id, constraint in meta.get("dependencies", {}).items():
            reverse.setdefault(dep_id, []).append({"id": module_id, "constraint": constraint})

    result = []
    for item in base:
        item = dict(item)
        if item.get("legacy"):
            item.update({"enabled": True, "visible": True, "dependencies": {}, "optional_dependencies": {}, "requires": {}, "dependants": []})
            result.append(item)
            continue
        meta = metadata.get(item["id"], {})
        enabled = is_enabled(item["id"], state)
        visible = is_visible(item["id"], state, default=meta.get("default_visible", True))
        hard = meta.get("dependencies", {})
        optional = meta.get("optional_dependencies", {})
        dep_status = []
        installed_by_id = {entry["id"]: entry for entry in base}
        for dep_id, constraint in hard.items():
            installed = installed_by_id.get(dep_id)
            dep_status.append({
                "id": dep_id,
                "constraint": constraint,
                "installed_version": installed.get("extension_version") if installed else None,
                "installed": bool(installed),
                "enabled": bool(installed and is_enabled(dep_id, state)),
                "satisfied": bool(installed and version_satisfies(installed.get("extension_version") or "0.0.0", constraint)),
            })
        record = module_record(item["id"], state)
        item.update({
            "enabled": enabled,
            "visible": visible,
            "status": (item.get("status") if item.get("ui_error") else ("enabled" if enabled else "disabled")),
            "dependencies": hard,
            "optional_dependencies": optional,
            "requires": meta.get("requires", {}),
            "default_visible": meta.get("default_visible", True),
            "dependency_status": dep_status,
            "dependants": reverse.get(item["id"], []),
            "runtime_requirements": _check_runtime_requirements(meta.get("requires", {})),
            "metadata_error": meta.get("metadata_error"),
            "source": record.get("source"),
        })
        result.append(item)
    return result


def _package_metadata(archive: Path) -> dict:
    preview = inspect_archive(archive)
    with tempfile.TemporaryDirectory(prefix="tec-tac-v2-package-") as tmp:
        root = Path(tmp) / "payload"
        root.mkdir()
        _extract_archive(archive, root)
        ext_root, _ = _find_pair(root)
        metadata = _extension_metadata(ext_root)
    preview = dict(preview)
    preview.update({
        "dependencies": metadata["dependencies"],
        "optional_dependencies": metadata["optional_dependencies"],
        "requires": metadata["requires"],
        "runtime_requirements": _check_runtime_requirements(metadata["requires"]),
    })
    return preview


def _future_catalog(candidates: list[dict]) -> dict[str, dict]:
    current = {item["id"]: dict(item) for item in installed_catalog_v2() if not item.get("legacy")}
    for candidate in candidates:
        current[candidate["id"]] = {
            "id": candidate["id"],
            "extension_version": candidate["extension_version"],
            "enabled": True,
            "dependencies": candidate.get("dependencies", {}),
            "optional_dependencies": candidate.get("optional_dependencies", {}),
            "requires": candidate.get("requires", {}),
        }
    return current


def resolve_install_plan(candidates: list[dict]) -> dict:
    if not candidates:
        raise ModuleManagerV2Error("Install plan contains no packages.")
    ids = [item["id"] for item in candidates]
    if len(set(ids)) != len(ids):
        raise ModuleManagerV2Error("Install plan contains duplicate module IDs.")
    future = _future_catalog(candidates)
    problems = []
    optional = []

    for candidate in candidates:
        runtime = candidate.get("runtime_requirements", [])
        for check in runtime:
            if not check["satisfied"]:
                problems.append({"module": candidate["id"], "type": "runtime", **check})
        for dep_id, constraint in candidate.get("dependencies", {}).items():
            dep = future.get(dep_id)
            if not dep:
                problems.append({"module": candidate["id"], "type": "missing_dependency", "dependency": dep_id, "constraint": constraint})
                continue
            version = dep.get("extension_version") or "0.0.0"
            if not version_satisfies(version, constraint):
                problems.append({"module": candidate["id"], "type": "dependency_version", "dependency": dep_id, "constraint": constraint, "version": version})
        for dep_id, constraint in candidate.get("optional_dependencies", {}).items():
            dep = future.get(dep_id)
            optional.append({
                "module": candidate["id"], "dependency": dep_id, "constraint": constraint,
                "installed": bool(dep),
                "satisfied": bool(dep and version_satisfies(dep.get("extension_version") or "0.0.0", constraint)),
            })

    # Existing enabled modules may also depend on a package being replaced.
    candidate_ids = set(ids)
    for module_id, item in future.items():
        if module_id in candidate_ids or not item.get("enabled", True):
            continue
        for dep_id, constraint in item.get("dependencies", {}).items():
            if dep_id not in candidate_ids:
                continue
            dep_version = future[dep_id].get("extension_version") or "0.0.0"
            if not version_satisfies(dep_version, constraint):
                problems.append({"module": module_id, "type": "breaks_dependant", "dependency": dep_id, "constraint": constraint, "version": dep_version})

    graph = {item["id"]: set() for item in candidates}
    for item in candidates:
        for dep_id in item.get("dependencies", {}):
            if dep_id in graph:
                graph[item["id"]].add(dep_id)

    order = []
    remaining = {key: set(value) for key, value in graph.items()}
    while remaining:
        ready = sorted(key for key, deps in remaining.items() if not deps)
        if not ready:
            problems.append({"type": "dependency_cycle", "modules": sorted(remaining)})
            break
        for module_id in ready:
            order.append(module_id)
            remaining.pop(module_id)
        for deps in remaining.values():
            deps.difference_update(ready)

    by_id = {item["id"]: item for item in candidates}
    installed = {item["id"]: item for item in installed_catalog_v2()}
    actions = []
    for module_id in order:
        candidate = by_id[module_id]
        actions.append({
            "id": module_id,
            "version": candidate["extension_version"],
            "action": "replace" if module_id in installed else "install",
            "current_version": installed.get(module_id, {}).get("extension_version"),
            "dependencies": candidate.get("dependencies", {}),
        })

    return {
        "valid": not problems,
        "problems": problems,
        "optional_dependencies": optional,
        "order": order,
        "actions": actions,
    }



def _plan_with_requested_order(plan: dict, requested_order) -> dict:
    """Return a copy of *plan* using a caller-selected dependency-safe order.

    The dependency resolver remains authoritative: callers may only reorder
    packages that are independent of one another. Every hard dependency that is
    part of the staged install must still appear before its dependant.
    """
    if requested_order in (None, []):
        return dict(plan)
    if not isinstance(requested_order, list) or any(not isinstance(value, str) for value in requested_order):
        raise ModuleManagerV2Error("Install order must be an array of module IDs.")
    order = [value.strip() for value in requested_order]
    if any(not value for value in order) or len(order) != len(set(order)):
        raise ModuleManagerV2Error("Install order contains blank or duplicate module IDs.")

    resolved = list(plan.get("order") or [])
    if len(order) != len(resolved) or set(order) != set(resolved):
        raise ModuleManagerV2Error("Install order must contain every staged module exactly once.")

    actions_by_id = {item["id"]: item for item in plan.get("actions") or []}
    position = {module_id: index for index, module_id in enumerate(order)}
    for module_id in order:
        action = actions_by_id.get(module_id) or {}
        for dependency_id in (action.get("dependencies") or {}):
            if dependency_id in position and position[dependency_id] > position[module_id]:
                raise ModuleManagerV2Error(
                    f"Install order is invalid: {module_id} requires {dependency_id} to be installed first."
                )

    updated = dict(plan)
    updated["order"] = order
    updated["actions"] = [actions_by_id[module_id] for module_id in order]
    return updated

def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_multiple_packages(uploads) -> dict:
    uploads = list(uploads)
    if not uploads:
        raise ModuleManagerV2Error("At least one package is required.")
    if len(uploads) == 1:
        return stage_uploaded_artifact(uploads[0])
    staged = []
    try:
        for upload in uploads:
            stage = stage_uploaded_package(upload)
            meta = _load_stage(stage["upload_id"])
            preview = _package_metadata(Path(meta["package_path"]))
            staged.append({**stage, "preview": preview})
        plan = resolve_install_plan([item["preview"] for item in staged])
        batch_id = str(uuid.uuid4())
        BATCHES_ROOT.mkdir(parents=True, exist_ok=True)
        payload = {
            "kind": "batch",
            "upload_id": batch_id,
            "created_at": _utcnow(),
            "packages": staged,
            "plan": plan,
        }
        _atomic_json(BATCHES_ROOT / f"{batch_id}.json", payload)
        return payload
    except Exception:
        for item in staged:
            try:
                discard_stage(item["upload_id"])
            except Exception:
                pass
        raise


def _inspect_bundle(path: Path) -> dict:
    if not path.name.lower().endswith(".zip"):
        raise ModuleManagerV2Error("Tec-Tac bundles must be ZIP archives.")
    with tempfile.TemporaryDirectory(prefix="tec-tac-bundle-") as tmp:
        root = Path(tmp) / "bundle"
        root.mkdir()
        _extract_archive(path, root)
        manifests = list(root.rglob(BUNDLE_MANIFEST))
        if len(manifests) != 1:
            raise ModuleManagerV2Error(f"Bundle must contain exactly one {BUNDLE_MANIFEST}.")
        manifest = _read_json(manifests[0], "bundle manifest")
        if str(manifest.get("type", "")).strip() != "bundle":
            raise ModuleManagerV2Error("Bundle manifest type must be 'bundle'.")
        bundle_id = str(manifest.get("id", "")).strip()
        version = str(manifest.get("version", "0.0.0")).strip()
        entries = manifest.get("packages")
        if not bundle_id or not isinstance(entries, list) or not entries:
            raise ModuleManagerV2Error("Bundle requires id and a non-empty packages array.")
        candidates = []
        package_files = []
        for raw in entries:
            if isinstance(raw, str):
                filename = raw
                expected_id = None
                expected_version = None
            elif isinstance(raw, dict):
                filename = str(raw.get("file", "")).strip()
                expected_id = str(raw.get("id", "")).strip() or None
                expected_version = str(raw.get("version", "")).strip() or None
            else:
                raise ModuleManagerV2Error("Bundle package entries must be strings or objects.")
            candidate_path = (manifests[0].parent / filename).resolve()
            try:
                candidate_path.relative_to(root.resolve())
            except ValueError as exc:
                raise ModuleManagerV2Error("Bundle package path escapes bundle root.") from exc
            if not candidate_path.is_file():
                raise ModuleManagerV2Error(f"Bundle package not found: {filename}")
            preview = _package_metadata(candidate_path)
            if expected_id and preview["id"] != expected_id:
                raise ModuleManagerV2Error(f"Bundle expected module {expected_id!r} but {filename!r} contains {preview['id']!r}.")
            if expected_version and preview["extension_version"] != expected_version:
                raise ModuleManagerV2Error(f"Bundle expected {preview['id']} version {expected_version}, found {preview['extension_version']}.")
            candidates.append(preview)
            package_files.append({"id": preview["id"], "file": filename, "version": preview["extension_version"]})
        plan = resolve_install_plan(candidates)
        return {
            "kind": "bundle",
            "id": bundle_id,
            "version": version,
            "packages": candidates,
            "package_files": package_files,
            "plan": plan,
            "installable": plan["valid"],
            "install_block_reason": None if plan["valid"] else "Bundle dependency plan is not satisfiable.",
        }


def stage_uploaded_artifact(upload) -> dict:
    name = str(getattr(upload, "name", "package"))
    # First stage using the hardened 1.3.x uploader. A bundle does not satisfy
    # v1's exactly-one-pair rule, so bundle staging has its own bounded writer.
    if "bundle" not in name.lower():
        try:
            staged = stage_uploaded_package(upload)
            meta = _load_stage(staged["upload_id"])
            preview = _package_metadata(Path(meta["package_path"]))
            plan = resolve_install_plan([preview])
            staged["preview"] = {**preview, "kind": "package", "plan": plan, "installable": bool(preview.get("installable")) and plan["valid"], "install_block_reason": preview.get("install_block_reason") if not preview.get("installable") else (None if plan["valid"] else "Dependency plan is not satisfiable.")}
            _atomic_json(STAGED_ROOT / f"{staged['upload_id']}.json", {**meta, "preview": staged["preview"]})
            return staged
        except ModuleManagerError as first_error:
            # A valid bundle may have an arbitrary filename; retry as bundle.
            if not name.lower().endswith(".zip"):
                raise
            bundle_error = first_error
    else:
        bundle_error = None

    size = int(getattr(upload, "size", 0) or 0)
    if size <= 0 or size > MAX_PACKAGE_BYTES:
        raise ModuleManagerV2Error("Bundle is empty or exceeds the package size limit.")
    BUNDLES_ROOT.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    path = BUNDLES_ROOT / f"{upload_id}.zip"
    digest = hashlib.sha256()
    written = 0
    try:
        with path.open("wb") as handle:
            for chunk in upload.chunks():
                written += len(chunk)
                if written > MAX_PACKAGE_BYTES:
                    raise ModuleManagerV2Error("Bundle exceeds the package size limit.")
                digest.update(chunk)
                handle.write(chunk)
        os.chmod(path, 0o640)
        preview = _inspect_bundle(path)
    except Exception as exc:
        path.unlink(missing_ok=True)
        if bundle_error is not None and not isinstance(exc, ModuleManagerV2Error):
            raise bundle_error
        raise
    payload = {
        "kind": "bundle",
        "upload_id": upload_id,
        "filename": name,
        "bundle_path": str(path),
        "sha256": digest.hexdigest(),
        "size": written,
        "created_at": _utcnow(),
        "preview": preview,
    }
    _atomic_json(BUNDLES_ROOT / f"{upload_id}.json", payload)
    return {key: value for key, value in payload.items() if key != "bundle_path"}



def discard_v2_stage(upload_id: str) -> None:
    """Discard any v2 staged artifact and its child v1 package stages."""
    try:
        batch = _load_batch(upload_id)
    except ModuleManagerV2Error:
        batch = None
    if batch is not None:
        for package in batch.get("packages") or []:
            try:
                discard_stage(package["upload_id"])
            except Exception:
                pass
        (BATCHES_ROOT / f"{upload_id}.json").unlink(missing_ok=True)
        return

    try:
        bundle = _load_bundle(upload_id)
    except ModuleManagerV2Error:
        bundle = None
    if bundle is not None:
        Path(str(bundle.get("bundle_path", ""))).unlink(missing_ok=True)
        (BUNDLES_ROOT / f"{upload_id}.json").unlink(missing_ok=True)
        return

    discard_stage(upload_id)

def _load_batch(batch_id: str) -> dict:
    try:
        uuid.UUID(str(batch_id))
    except ValueError as exc:
        raise ModuleManagerV2Error("Invalid batch id.") from exc
    path = BATCHES_ROOT / f"{batch_id}.json"
    if not path.is_file():
        raise ModuleManagerV2Error("Staged batch was not found.")
    return _read_json(path, "batch metadata")


def _load_bundle(upload_id: str) -> dict:
    try:
        uuid.UUID(str(upload_id))
    except ValueError as exc:
        raise ModuleManagerV2Error("Invalid bundle upload id.") from exc
    path = BUNDLES_ROOT / f"{upload_id}.json"
    if not path.is_file():
        raise ModuleManagerV2Error("Staged bundle was not found.")
    return _read_json(path, "bundle metadata")


def _dispatch_v2(job_id: str) -> None:
    if not V2_HELPER.is_file():
        raise ModuleManagerV2Error(f"Module Management v2 helper is not installed at {V2_HELPER}.")
    import subprocess
    try:
        subprocess.run(["sudo", "-n", str(V2_HELPER), "--dispatch", job_id], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=8)
    except Exception as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise ModuleManagerV2Error(f"Unable to dispatch Module Management v2 job: {str(detail).strip()}") from exc


def _queue_v2(payload: dict) -> dict:
    job = _new_job(payload)
    try:
        _dispatch_v2(job["id"])
    except Exception as exc:
        job["status"] = "dispatch_failed"
        job["stage"] = "dispatch"
        job["finished_at"] = _utcnow()
        job["error"] = str(exc)
        job["error_type"] = exc.__class__.__name__
        _atomic_json(JOBS_ROOT / f"{job['id']}.json", job)
        raise
    return public_job(job)


def queue_v2_install(upload_id: str, requested_order=None) -> dict:
    # Individual v1-staged package.
    try:
        meta = _load_stage(upload_id)
    except ModuleManagerError:
        meta = None
    if meta:
        preview = _package_metadata(Path(meta["package_path"]))
        plan = resolve_install_plan([preview])
        plan = _plan_with_requested_order(plan, requested_order)
        if not preview.get("installable") or not plan["valid"]:
            raise ModuleManagerV2Error(preview.get("install_block_reason") or "Package dependency plan is not satisfiable.")
        replace = bool(preview.get("already_installed"))
        source = meta.get("source_provenance")
        if source:
            # Online repository packages still use the proven extension install script,
            # but run through the v2 worker so source provenance is committed only
            # after a successful install.
            action = {
                "id": preview["id"],
                "version": preview["extension_version"],
                "action": "replace" if replace else "install",
                "current_version": preview.get("installed_version"),
                "dependencies": preview.get("dependencies", {}),
            }
            return _queue_v2({
                "action": "batch_install",
                "plugin_id": preview["id"],
                "batch_id": upload_id,
                "packages": [{
                    "id": preview["id"],
                    "path": meta["package_path"],
                    "upload_id": upload_id,
                    "source": source,
                }],
                "plan": {**plan, "actions": [action]},
            })
        # Local/offline single-package deployment keeps using the proven v1 worker.
        from .module_manager import queue_install
        return queue_install(upload_id, replace=replace)

    # Bundle staging.
    bundle = _load_bundle(upload_id)
    plan = bundle.get("preview", {}).get("plan") or {}
    if not plan.get("valid"):
        raise ModuleManagerV2Error("Bundle dependency plan is not satisfiable.")
    plan = _plan_with_requested_order(plan, requested_order)
    return _queue_v2({
        "action": "bundle_install",
        "plugin_id": bundle["preview"]["id"],
        "upload_id": upload_id,
        "bundle_path": bundle["bundle_path"],
        "plan": plan,
        "bundle": bundle["preview"],
    })


def queue_batch_install(batch_id: str, requested_order=None) -> dict:
    batch = _load_batch(batch_id)
    plan = batch.get("plan") or {}
    if not plan.get("valid"):
        raise ModuleManagerV2Error("Batch dependency plan is not satisfiable.")
    plan = _plan_with_requested_order(plan, requested_order)
    package_paths = []
    for package in batch.get("packages", []):
        meta = _load_stage(package["upload_id"])
        package_paths.append({"id": package["preview"]["id"], "path": meta["package_path"], "upload_id": package["upload_id"]})
    return _queue_v2({
        "action": "batch_install",
        "plugin_id": "batch",
        "batch_id": batch_id,
        "packages": package_paths,
        "plan": plan,
    })


def _enabled_dependants(module_id: str) -> list[dict]:
    catalog = installed_catalog_v2()
    state = load_state()
    result = []
    for item in catalog:
        if item.get("legacy") or not is_enabled(item["id"], state):
            continue
        constraint = (item.get("dependencies") or {}).get(module_id)
        if constraint:
            result.append({"id": item["id"], "constraint": constraint})
    return result


def validate_enable(module_id: str) -> dict:
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if target.get("protected"):
        raise ModuleManagerV2Error("Protected framework modules cannot be enabled/disabled from the UI.")
    problems = []
    for dep_id, constraint in (target.get("dependencies") or {}).items():
        dep = catalog.get(dep_id)
        if not dep:
            problems.append({"type": "missing_dependency", "dependency": dep_id, "constraint": constraint})
            continue
        if not dep.get("enabled"):
            problems.append({"type": "disabled_dependency", "dependency": dep_id, "constraint": constraint})
        if not version_satisfies(dep.get("extension_version") or "0.0.0", constraint):
            problems.append({"type": "dependency_version", "dependency": dep_id, "constraint": constraint, "version": dep.get("extension_version")})
    for check in target.get("runtime_requirements") or []:
        if not check.get("satisfied"):
            problems.append({"type": "runtime", **check})
    return {"valid": not problems, "problems": problems}


def queue_set_enabled(module_id: str, enabled: bool, cascade: bool = False) -> dict:
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if not target.get("managed"):
        raise ModuleManagerV2Error("Protected modules cannot be enabled or disabled from the UI.")
    affected = [module_id]
    if enabled:
        validation = validate_enable(module_id)
        if not validation["valid"]:
            raise ModuleManagerV2Error("Module cannot be enabled until its dependencies and runtime requirements are satisfied.")
    else:
        dependants = _enabled_dependants(module_id)
        if dependants and not cascade:
            names = ", ".join(item["id"] for item in dependants)
            raise ModuleManagerV2Error(f"Module is required by enabled module(s): {names}. Disable dependants first or request cascade.")
        if cascade:
            # Recursively disable enabled dependants before the requested module.
            seen = set()
            def visit(mid):
                for dep in _enabled_dependants(mid):
                    if dep["id"] not in seen:
                        seen.add(dep["id"])
                        visit(dep["id"])
                        affected.append(dep["id"])
            visit(module_id)
            affected = [mid for mid in affected if mid != module_id] + [module_id]
    return _queue_v2({
        "action": "enable" if enabled else "disable",
        "plugin_id": module_id,
        "enabled": bool(enabled),
        "cascade": bool(cascade),
        "affected_modules": affected,
    })


def queue_set_visibility(module_id: str, visible: bool) -> dict:
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if not target.get("managed"):
        raise ModuleManagerV2Error("Protected modules cannot change navigation visibility from the UI.")
    return _queue_v2({
        "action": "visibility",
        "plugin_id": module_id,
        "visible": bool(visible),
    })


def validate_remove(module_id: str) -> dict:
    dependants = _enabled_dependants(module_id)
    return {"valid": not dependants, "dependants": dependants}
