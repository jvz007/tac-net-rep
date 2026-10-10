"""Tec-Tac Module Management v2.

Adds persistent enable/disable state, package dependency/version resolution,
framework/UI compatibility checks, multi-package install plans and bundle
inspection while preserving the 1.3.x package lifecycle implementation.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import shutil
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import module_category
from . import module_replacement
from . import registry as registry_module
from .capabilities import capability_status, get_capability
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
    _copy_sidecar,
    _verify_stage_trust,
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
logger = logging.getLogger("tec_tac.module_manager_v2")

FRAMEWORK_VERSION_FILE = Path("/opt/tec-tac/VERSION")
UI_VERSION_FILE = Path("/var/lib/tec-tac/ui/tec-tac/VERSION")
UI_PACKAGE_FILE = Path("/var/lib/tec-tac/ui/tec-tac/package.json")


class ModuleManagerV2Error(ModuleManagerError):
    pass


class LicensingRequirementError(ModuleManagerV2Error):
    """Raised when a package-declared licensing gate is not satisfied."""

    def __init__(self, result: dict):
        self.result = dict(result or {})
        reason = self.result.get("reason") or "Module licensing requirement is not satisfied."
        super().__init__(str(reason))

    def as_payload(self) -> dict:
        return {
            "detail": str(self),
            "code": "licensing_requirement_failed",
            "licensing": self.result,
        }


class ModuleReplacementConfirmationRequired(ModuleManagerV2Error):
    """Raised when an enable or install would disable a replaced module and the request did not name exactly that list.

    It is a refusal (HTTP 400, code ``replacement_confirmation_required``) carrying the fresh ``will_disable`` list, so
    a caller can show it and ask again. An old caller that sends no list simply sees a refusal."""

    def __init__(self, will_disable, subject: str):
        self.will_disable = sorted(set(will_disable))
        names = ", ".join(self.will_disable)
        super().__init__(
            f"{subject} replaces {names} and will disable it. Confirm that list to go ahead: send disable_replaced with {names}."
        )

    def as_payload(self) -> dict:
        return {"detail": str(self), "code": "replacement_confirmation_required", "will_disable": list(self.will_disable)}


class ModuleReplacementSecondConfirmationRequired(ModuleManagerV2Error):
    """Raised when enabling a core or server module would switch off an enabled replacement and the request did not carry
    ``confirm_replacement_switch: true`` (1.17.12, Johan CQ32).

    The first confirmation (the ``disable_replaced`` list) has already passed when this is raised. It is a refusal (HTTP
    400, code ``replacement_second_confirmation_required``) carrying the fresh ``will_disable`` list and the module id.
    1.17.14 (CQ35): it also carries ``dependants``, [{replacement, modules[]}], the enabled modules that name a replacement
    that will be switched off directly in their dependencies. It is a warning shown in this confirmation, never a refusal."""

    def __init__(self, will_disable, module_id: str, dependants=None):
        self.will_disable = sorted(set(will_disable))
        self.module_id = str(module_id)
        self.dependants = [dict(item) for item in (dependants or [])]
        names = ", ".join(self.will_disable)
        text = (f"Module {self.module_id!r} is replaced by {names}, which is enabled. Enabling {self.module_id!r} will switch {names} off. ")
        for item in self.dependants:
            text += f"Enabled module(s) {', '.join(item['modules'])} depend directly on {item['replacement']!r}. "
        super().__init__(text + "Confirm the switch to go ahead: send confirm_replacement_switch with true.")

    def as_payload(self) -> dict:
        return {"detail": str(self), "code": "replacement_second_confirmation_required",
                "will_disable": list(self.will_disable), "module": self.module_id, "dependants": [dict(item) for item in self.dependants]}


class ModuleReplacementHandBackConfirmationRequired(ModuleManagerV2Error):
    """Raised when disabling a replacement would leave the module it replaces off, because that module cannot be enabled,
    and the request did not carry ``confirm_without_hand_back: true`` (1.17.14, Johan CQ34).

    It is a refusal (HTTP 400, code ``replacement_hand_back_confirmation_required``) carrying ``will_enable`` (the modules
    that can come back), ``hand_back_unavailable`` ([{module, reasons[], required_modules[]}]) and the module id. An old
    caller that sends no flag sees a refusal and nothing is queued."""

    def __init__(self, module_id: str, will_enable, unavailable):
        self.module_id = str(module_id)
        self.will_enable = sorted(set(will_enable))
        self.hand_back_unavailable = [dict(item) for item in unavailable]
        parts = []
        for item in self.hand_back_unavailable:
            parts.append(f"{item['module']!r} cannot be enabled ({'; '.join(item['reasons'])})")
        super().__init__(
            f"Disabling {self.module_id!r} would leave module(s) it replaces switched off: {'; '.join(parts)}. "
            "Confirm to go ahead without them: send confirm_without_hand_back with true."
        )

    def as_payload(self) -> dict:
        return {"detail": str(self), "code": "replacement_hand_back_confirmation_required", "module": self.module_id,
                "will_enable": list(self.will_enable), "hand_back_unavailable": [dict(item) for item in self.hand_back_unavailable]}


def _confirmed_disables(will_disable, disable_replaced, subject: str) -> list[str]:
    """The ids the job may disable. Empty when nothing would be disabled; else the request must name exactly that list."""
    needed = sorted(set(will_disable or []))
    if not needed:
        return []
    given = sorted({str(value) for value in disable_replaced}) if isinstance(disable_replaced, (list, tuple)) else []
    if given != needed:
        raise ModuleReplacementConfirmationRequired(needed, subject)
    return needed


def _audit_plan_disables(actor, plan: dict, job: dict) -> None:
    """One "asked to switch" audit row per install action whose job will disable a replaced module. It records the
    request, not a change: the outcome rows follow when the job has finished. The audit write never raises."""
    for action in plan.get("actions") or []:
        disabled = list(action.get("will_disable") or [])
        if disabled:
            module_replacement.audit_switch_queued(actor, str(action.get("id") or ""), job.get("id"), disabled=disabled)


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



def _identity_migration_metadata(payload: dict, module_id: str) -> dict:
    raw = payload.get("migration") or {}
    if not raw:
        return {"previous_module_ids": [], "permissions": {}, "scheduler_actions": {}, "ui_routes": {}, "dashboard_widgets": {}}
    if not isinstance(raw, dict):
        raise ModuleManagerV2Error("Manifest migration must be a JSON object.")
    previous = raw.get("previous_module_ids") or []
    if not isinstance(previous, list) or not previous:
        raise ModuleManagerV2Error("Manifest migration.previous_module_ids must be a non-empty array.")
    previous = [str(value or "").strip() for value in previous]
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    if any(not value or any(ch not in allowed_chars for ch in value) for value in previous):
        raise ModuleManagerV2Error("Manifest migration.previous_module_ids contains an invalid module ID.")
    if len(set(previous)) != len(previous) or module_id in previous:
        raise ModuleManagerV2Error("Manifest migration.previous_module_ids must be unique and may not include the current module ID.")

    def mapping(name):
        value = raw.get(name) or {}
        if not isinstance(value, dict):
            raise ModuleManagerV2Error(f"Manifest migration.{name} must be an object.")
        result = {}
        for old, new in value.items():
            old = str(old or "").strip(); new = str(new or "").strip()
            if not old or not new:
                raise ModuleManagerV2Error(f"Manifest migration.{name} contains a blank mapping.")
            result[old] = new
        return result

    permissions = mapping("permissions")
    actions = mapping("scheduler_actions")
    routes = mapping("ui_routes")
    widgets = mapping("dashboard_widgets")
    old_prefixes = tuple(value + "." for value in previous)
    for old, new in permissions.items():
        if not old.startswith(old_prefixes) or not new.startswith(module_id + "."):
            raise ModuleManagerV2Error("Permission migration entries must map a previous module namespace to the current module namespace.")
    for old, new in actions.items():
        if not old.startswith(old_prefixes) or not new.startswith(module_id + "."):
            raise ModuleManagerV2Error("Scheduler action migration entries must map a previous module namespace to the current module namespace.")
    return {
        "previous_module_ids": previous,
        "permissions": permissions,
        "scheduler_actions": actions,
        "ui_routes": routes,
        "dashboard_widgets": widgets,
    }

def _installed_rename_source(candidate: dict, installed_by_id: dict) -> str | None:
    migration = candidate.get("migration") or {}
    previous = list(migration.get("previous_module_ids") or [])
    matches = [module_id for module_id in previous if module_id in installed_by_id]
    if len(matches) > 1:
        raise ModuleManagerV2Error(
            f"Module {candidate['id']!r} declares multiple previous IDs that are installed: {', '.join(matches)}."
        )
    return matches[0] if matches else None

def _licensing_metadata(payload: dict) -> dict:
    raw = payload.get("licensing")
    if raw in (None, {}):
        return {"required": False}
    if not isinstance(raw, dict):
        raise ModuleManagerV2Error("Manifest key 'licensing' must be an object.")

    required = raw.get("required", False)
    if not isinstance(required, bool):
        raise ModuleManagerV2Error("Manifest licensing.required must be true or false.")

    product = str(raw.get("product", "")).strip()
    capability = str(raw.get("capability", "")).strip()
    capability_version = str(raw.get("capability_version", "")).strip()

    if required:
        if not product:
            raise ModuleManagerV2Error("Licensed modules must declare licensing.product.")
        if not capability or "." not in capability:
            raise ModuleManagerV2Error("Licensed modules must declare a namespaced licensing.capability.")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        if any(ch not in allowed for ch in capability):
            raise ModuleManagerV2Error("Manifest licensing.capability contains unsupported characters.")
        if not capability_version:
            raise ModuleManagerV2Error("Licensed modules must declare licensing.capability_version.")
        try:
            version_satisfies("0.0.0", capability_version)
        except ModuleStateError as exc:
            raise ModuleManagerV2Error(f"Invalid licensing capability version range: {exc}") from exc

    return {
        "required": required,
        "product": product or None,
        "capability": capability or None,
        "capability_version": capability_version or None,
    }


def _normalize_entitlement_result(value, *, module_id: str, module_version: str, licensing: dict, cap_status: dict) -> dict:
    if isinstance(value, bool):
        licensed = value
        reason = None if value else f"Product {licensing['product']!r} is not licensed."
        details = {}
    elif isinstance(value, dict):
        details = dict(value)
        if "licensed" in details:
            licensed = bool(details.get("licensed"))
        elif "entitled" in details:
            licensed = bool(details.get("entitled"))
        elif "allowed" in details:
            licensed = bool(details.get("allowed"))
        else:
            licensed = False
        reason = details.get("reason") or details.get("message")
        if not licensed and not reason:
            reason = f"Product {licensing['product']!r} is not licensed."
    else:
        licensed = False
        details = {"provider_result": str(value)}
        reason = "Licensing provider returned an unsupported entitlement result."

    return {
        "required": True,
        "module": module_id,
        "module_version": module_version,
        "product": licensing.get("product"),
        "capability": licensing.get("capability"),
        "required_capability_version": licensing.get("capability_version"),
        "capability_version": cap_status.get("capability_version"),
        "provider_module": cap_status.get("module_id"),
        "state": "licensed" if licensed else "unlicensed",
        "licensed": licensed,
        "reason": None if licensed else str(reason or "Module is not licensed."),
        "details": details,
    }


def check_licensing_requirement(candidate: dict) -> dict:
    licensing = dict(candidate.get("licensing") or {"required": False})
    module_id = str(candidate.get("id") or candidate.get("plugin_id") or "").strip()
    module_version = str(candidate.get("extension_version") or candidate.get("version") or "0.0.0").strip()
    if not licensing.get("required"):
        return {
            "required": False,
            "module": module_id,
            "module_version": module_version,
            "licensed": True,
            "state": "not-required",
            "reason": None,
        }

    capability_id = licensing.get("capability")
    capability_version = licensing.get("capability_version")
    cap_status = capability_status(capability_id, version=capability_version)
    if not cap_status.get("available"):
        result = {
            "required": True,
            "module": module_id,
            "module_version": module_version,
            "product": licensing.get("product"),
            "capability": capability_id,
            "required_capability_version": capability_version,
            "capability_version": cap_status.get("capability_version"),
            "provider_module": cap_status.get("module_id"),
            "state": cap_status.get("state") or "capability-unavailable",
            "licensed": False,
            "reason": cap_status.get("reason") or "Licensing capability is unavailable.",
            "capability_status": cap_status,
        }
        raise LicensingRequirementError(result)

    provider = get_capability(capability_id, version=capability_version)
    checker = getattr(provider, "check_entitlement", None)
    if not callable(checker):
        result = {
            "required": True,
            "module": module_id,
            "module_version": module_version,
            "product": licensing.get("product"),
            "capability": capability_id,
            "required_capability_version": capability_version,
            "capability_version": cap_status.get("capability_version"),
            "provider_module": cap_status.get("module_id"),
            "state": "provider-contract-invalid",
            "licensed": False,
            "reason": "Licensing capability provider does not expose check_entitlement().",
        }
        raise LicensingRequirementError(result)

    try:
        value = checker(
            product=licensing.get("product"),
            module_id=module_id,
            module_version=module_version,
        )
    except Exception as exc:
        result = {
            "required": True,
            "module": module_id,
            "module_version": module_version,
            "product": licensing.get("product"),
            "capability": capability_id,
            "required_capability_version": capability_version,
            "capability_version": cap_status.get("capability_version"),
            "provider_module": cap_status.get("module_id"),
            "state": "provider-error",
            "licensed": False,
            "reason": f"Licensing entitlement check failed: {exc.__class__.__name__}: {exc}",
            "error_type": exc.__class__.__name__,
        }
        raise LicensingRequirementError(result) from exc

    result = _normalize_entitlement_result(
        value,
        module_id=module_id,
        module_version=module_version,
        licensing=licensing,
        cap_status=cap_status,
    )
    if not result["licensed"]:
        raise LicensingRequirementError(result)
    return result


def _enforce_candidate_licensing(candidate: dict) -> dict:
    result = check_licensing_requirement(candidate)
    candidate["licensing_status"] = result
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


def _replacement_metadata(payload: dict) -> dict:
    """The AD-20 manifest keys, parsed with the registry's own rules (extensions only)."""
    module_id = str(payload.get("id", "")).strip()
    category = str(payload.get("category") or "").strip().lower()
    try:
        replaces, capabilities, declared = registry_module._replacement_keys(payload, "extension", module_id, category)
    except registry_module.RegistryError as exc:
        raise ModuleManagerV2Error(str(exc)) from exc
    return {"replaces": replaces or None, "capabilities": dict(capabilities) if declared else None}


def _extension_metadata(extension_root: Path) -> dict:
    payload = _read_json(extension_root / "tec_tac.json", "extension manifest")
    return {
        "id": str(payload.get("id", "")).strip(),
        "name": str(payload.get("name") or payload.get("id") or "").strip(),
        "category": str(payload.get("category") or "").strip().lower(),
        "version": str(payload.get("version", "0.0.0")).strip(),
        "dependencies": _string_map(payload, "dependencies"),
        "optional_dependencies": _string_map(payload, "optional_dependencies"),
        "requires": _string_map(payload, "requires"),
        "licensing": _licensing_metadata(payload),
        "migration": _identity_migration_metadata(payload, str(payload.get("id", "")).strip()),
        "default_visible": _ui_default_visible(extension_root),
        **_replacement_metadata(payload),
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

    try:
        replacement_model = module_replacement.live_model(state=state)
        replacement_rows = {row["module_id"]: row for row in module_replacement.replacement_status(model=replacement_model)}
    except Exception:
        replacement_model, replacement_rows = {}, {}
    planning_model = _model_with_pending_jobs(replacement_model) if replacement_model else {}

    result = []
    for item in base:
        item = dict(item)
        if item.get("legacy"):
            item.update({"enabled": True, "visible": True, "dependencies": {}, "optional_dependencies": {}, "requires": {}, "dependants": [],
                         "replaces": None, "replacement": None, "replaced_by": None, "will_disable": [], "will_enable": [],
                         "second_confirmation_required": False, "replacement_dependants": [],
                         "hand_back_unavailable": [], "hand_back_confirmation_required": False})
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
                # 1.17.11: the honoured replacement that stands in for a disabled dependency, else null. ``enabled`` stays truthful.
                "satisfied_by": module_replacement.satisfies_dependency(replacement_model, dep_id) if replacement_model else None,
            })
        record = module_record(item["id"], state)
        try:
            from .module_hotfix import hotfix_summary
            hotfixes = hotfix_summary(item["id"])
        except Exception:
            hotfixes = {"count": 0, "ids": [], "latest": None}
        item.update({
            "enabled": enabled,
            "visible": visible,
            "status": (item.get("status") if item.get("ui_error") else ("enabled" if enabled else "disabled")),
            "hotfixes": hotfixes,
            "dependencies": hard,
            "optional_dependencies": optional,
            "requires": meta.get("requires", {}),
            "licensing": meta.get("licensing", {"required": False}),
            "default_visible": meta.get("default_visible", True),
            "dependency_status": dep_status,
            "dependants": reverse.get(item["id"], []),
            "runtime_requirements": _check_runtime_requirements(meta.get("requires", {})),
            "metadata_error": meta.get("metadata_error"),
            "source": record.get("source"),
            # 1.17.13 (AD-21): the manifest is read first. ``category_state`` is what the install wrote to module state
            # (null for a module installed before 1.17.13); a different value is flagged, never trusted.
            "category_state": record.get("category") if isinstance(record.get("category"), str) else None,
            "category_mismatch": isinstance(record.get("category"), str) and module_category.normalize(record.get("category")) != module_category.normalize(item.get("category")),
            "replaces": item.get("replaces"),
            "replacement": replacement_rows.get(item["id"]),
            "replaced_by": module_replacement.replaced_by(item["id"], model=replacement_model) if replacement_model else None,
            # 1.17.11: the modules that enabling this one would disable (empty when none).
            "will_disable": module_replacement.disable_plan(planning_model, item["id"]) if planning_model else [],
            # 1.17.12: for a disabled core or server module, will_disable names its enabled replacement (CQ32) and
            # second_confirmation_required is true. For an enabled replacement, will_enable names the replaced module that
            # disabling it switches back on (CQ33).
            "will_enable": module_replacement.hand_back_plan(planning_model, item["id"]) if planning_model else [],
            "second_confirmation_required": module_replacement.switches_replacement(planning_model, item["id"]) if planning_model else False,
            # 1.17.14: what disabling an enabled replacement cannot hand back (CQ34) and what enabling a replaced module
            # would leave directly depending on the replacement it switches off (CQ35). Filled in below.
            "replacement_dependants": [],
            "hand_back_unavailable": [],
            "hand_back_confirmation_required": False,
        })
        result.append(item)
    _add_replacement_warnings(result, planning_model)
    return result


def _add_replacement_warnings(rows: list[dict], planning_model: dict) -> None:
    """Fill the 1.17.14 warning fields of the catalogue rows, in place. ``will_enable`` keeps only the modules that can come
    back. Never raises: a failure leaves the fields as they were (empty), and the queue-time check still runs."""
    if not planning_model:
        return
    catalog = {row["id"]: row for row in rows}
    for row in rows:
        if row.get("legacy"):
            continue
        try:
            if row.get("will_enable"):
                can, cannot = _hand_back_split(catalog, planning_model, row["id"], row["will_enable"], {row["id"]})
                row["will_enable"] = can
                row["hand_back_unavailable"] = _unavailable_rows(cannot)
                row["hand_back_confirmation_required"] = bool(cannot)
            if row.get("second_confirmation_required") and row.get("will_disable"):
                row["replacement_dependants"] = _replacement_dependants(catalog, planning_model, row["id"], row["will_disable"])
        except Exception:
            logger.exception("Could not work out the replacement warnings for module %s.", row.get("id"))


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
        "licensing": metadata.get("licensing", {"required": False}),
        "migration": metadata.get("migration", {}),
        "replaces": metadata.get("replaces"),
        "capabilities": metadata.get("capabilities"),
    })
    return preview


def _future_catalog(candidates: list[dict]) -> dict[str, dict]:
    current = {item["id"]: dict(item) for item in installed_catalog_v2() if not item.get("legacy")}
    installed_snapshot = dict(current)
    for candidate in candidates:
        rename_from = _installed_rename_source(candidate, installed_snapshot)
        if rename_from and candidate["id"] in installed_snapshot:
            # Ambiguous merge: both identities are deployed. Require operator cleanup.
            continue
        if rename_from:
            current.pop(rename_from, None)
        current[candidate["id"]] = {
            "id": candidate["id"],
            "extension_version": candidate["extension_version"],
            "enabled": True,
            "dependencies": candidate.get("dependencies", {}),
            "optional_dependencies": candidate.get("optional_dependencies", {}),
            "requires": candidate.get("requires", {}),
        }
    return current


def _replacement_install_model(candidates: list[dict]) -> dict:
    """The live module model with the install candidates merged in. Raises when module state cannot be read."""
    model = dict(module_replacement.live_model())
    for candidate in candidates:
        was = model.get(candidate["id"])
        model[candidate["id"]] = module_replacement.Node(
            id=candidate["id"],
            category=str(candidate.get("category") or ""),
            enabled=was.enabled if was is not None else True,
            replaces=str(candidate.get("replaces") or ""),
            capabilities=candidate.get("capabilities"),
        )
    return model


def _replacement_install_problems(candidates: list[dict], installed: dict[str, dict]) -> list[dict]:
    """Replacement problems for this install plan (problem types replacement_conflict and replacement_incomplete)."""
    try:
        model = _replacement_install_model(candidates)
    except Exception as exc:
        return [{"type": "replacement_incomplete", "reason": "state-unreadable", "message": f"Module state could not be read: {exc}"}]
    return module_replacement.install_problems(model, [item["id"] for item in candidates], installed_ids=installed)


def resolve_install_plan(candidates: list[dict]) -> dict:
    if not candidates:
        raise ModuleManagerV2Error("Install plan contains no packages.")
    ids = [item["id"] for item in candidates]
    if len(set(ids)) != len(ids):
        raise ModuleManagerV2Error("Install plan contains duplicate module IDs.")
    installed = {item["id"]: item for item in installed_catalog_v2() if not item.get("legacy")}
    future = _future_catalog(candidates)
    # 1.17.11: the replacement model as it will be after this install (fresh replacements enabled, the modules they
    # replace disabled), so a hard dependency on a replaced module id is judged against what will be honoured.
    try:
        replacement_model = _replacement_install_model(candidates)
        disables = module_replacement.install_disables(replacement_model, ids, installed_ids=installed)
        future_replacement_model = module_replacement._with_enabled(
            replacement_model, {replaced: False for names in disables.values() for replaced in names})
    except (registry_module.RegistryError, ModuleStateError, OSError, ValueError, KeyError):
        replacement_model, disables, future_replacement_model = None, {}, {}
    problems = []
    optional = []
    rename_sources = {}
    for candidate in candidates:
        rename_from = _installed_rename_source(candidate, installed)
        if rename_from and candidate["id"] in installed:
            problems.append({"module": candidate["id"], "type": "rename_destination_exists", "previous_module_id": rename_from})
        elif rename_from:
            rename_sources[candidate["id"]] = rename_from

    # A rename removes the old identity. Existing enabled modules that are not
    # part of this transaction may not continue depending on that old ID.
    candidate_ids_for_rename = {item["id"] for item in candidates}
    for new_id, old_id in rename_sources.items():
        for module_id, item in installed.items():
            if module_id in candidate_ids_for_rename or not item.get("enabled", True):
                continue
            constraint = (item.get("dependencies") or {}).get(old_id)
            if constraint is not None:
                problems.append({"module": module_id, "type": "rename_breaks_dependant", "dependency": old_id, "replacement": new_id, "constraint": constraint})

    if rename_sources:
        try:
            from .module_identity import preflight_identity_migration
            by_candidate_id = {item["id"]: item for item in candidates}
            for new_id, old_id in rename_sources.items():
                try:
                    preflight_identity_migration(
                        old_id=old_id,
                        new_id=new_id,
                        migration=by_candidate_id[new_id].get("migration") or {},
                    )
                except Exception as exc:
                    problems.append({
                        "module": new_id,
                        "type": "identity_migration_preflight",
                        "previous_module_id": old_id,
                        "reason": str(exc),
                    })
        except ImportError:
            problems.append({"type": "identity_migration_unavailable", "reason": "Core identity migration contract is unavailable."})

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
            if not dep.get("enabled", True) and not module_replacement.satisfies_dependency(future_replacement_model, dep_id):
                problems.append({"module": candidate["id"], "type": "disabled_dependency", "dependency": dep_id, "constraint": constraint})
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

    # AD-21: a module whose effective category is test is not installed off a development server.
    development = module_category.is_development_server()
    for candidate in candidates:
        refusal = module_category.refusal_problem(candidate["id"], candidate.get("category"), development=development)
        if refusal:
            problems.append(refusal)

    # AD-20: a replacement installs only next to a disabled core module it covers; never both enabled.
    if replacement_model is None:
        problems.extend(_replacement_install_problems(candidates, installed))
    else:
        problems.extend(module_replacement.install_problems(replacement_model, ids, installed_ids=installed))

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

    # Build ordering constraints only from dependencies that are part of this
    # staged batch.  A dependency declaration is a constraint when present; it
    # is never a prerequisite for participating in a multi-package install.
    #
    # In particular, a batch of completely independent packages is valid and
    # must preserve the operator's upload order.  This also gives us a stable
    # topological order for mixed batches: among packages that are currently
    # dependency-free, retain their original staged order instead of imposing
    # an unrelated alphabetical sequence.
    graph = {item["id"]: set() for item in candidates}
    input_position = {module_id: index for index, module_id in enumerate(ids)}
    for item in candidates:
        for dep_id in item.get("dependencies", {}):
            if dep_id in graph:
                graph[item["id"]].add(dep_id)

    order = []
    remaining = {key: set(value) for key, value in graph.items()}
    while remaining:
        ready = [key for key, deps in remaining.items() if not deps]
        ready.sort(key=lambda module_id: input_position[module_id])
        if not ready:
            problems.append({"type": "dependency_cycle", "modules": sorted(remaining)})
            break
        for module_id in ready:
            order.append(module_id)
            remaining.pop(module_id)
        for deps in remaining.values():
            deps.difference_update(ready)

    by_id = {item["id"]: item for item in candidates}
    actions = []
    for module_id in order:
        candidate = by_id[module_id]
        rename_from = rename_sources.get(module_id)
        action_name = "rename" if rename_from else ("replace" if module_id in installed else "install")
        current = installed.get(rename_from or module_id, {})
        actions.append({
            "id": module_id,
            "version": candidate["extension_version"],
            "action": action_name,
            "previous_module_id": rename_from,
            "current_version": current.get("extension_version"),
            "dependencies": candidate.get("dependencies", {}),
            "migration": candidate.get("migration", {}),
            "will_disable": list(disables.get(module_id, [])),
        })

    return {
        "valid": not problems,
        "problems": problems,
        "optional_dependencies": optional,
        "order": order,
        "actions": actions,
        "will_disable": sorted({replaced for names in disables.values() for replaced in names}),
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

    # A multi-file intake may contain any mixture of normal module packages and
    # Tec-Tac bundles. Bundles are staging containers only: their child module
    # previews are flattened into one dependency plan with the standalone
    # packages so dependency resolution is global across the entire selection.
    artifacts = []
    flattened = []
    try:
        for upload in uploads:
            filename = str(getattr(upload, "name", "package"))
            try:
                stage = stage_uploaded_artifact(upload)
                preview = dict(stage.get("preview") or {})
                kind = str(stage.get("kind") or preview.get("kind") or "package")
                artifact = {**stage, "preview": preview, "kind": kind}
                artifacts.append(artifact)

                if kind == "bundle":
                    children = list(preview.get("packages") or [])
                    if not children:
                        raise ModuleManagerV2Error("Bundle contains no installable module packages.")
                    for child in children:
                        flattened.append({
                            "preview": dict(child),
                            "source_kind": "bundle",
                            "source_upload_id": stage["upload_id"],
                            "source_bundle_id": preview.get("id"),
                            "source_filename": filename,
                        })
                else:
                    if not preview.get("id"):
                        meta = _load_stage(stage["upload_id"])
                        preview = _package_metadata(Path(meta["package_path"]))
                        artifact["preview"] = preview
                    flattened.append({
                        **stage,
                        "preview": preview,
                        "source_kind": "package",
                        "source_upload_id": stage["upload_id"],
                        "source_filename": filename,
                    })
            except (ModuleManagerError, ModuleManagerV2Error) as exc:
                raise ModuleManagerV2Error(f"{filename}: {exc}") from exc

        plan = resolve_install_plan([item["preview"] for item in flattened])
        batch_id = str(uuid.uuid4())
        BATCHES_ROOT.mkdir(parents=True, exist_ok=True)
        payload = {
            "kind": "batch",
            "upload_id": batch_id,
            "created_at": _utcnow(),
            "artifacts": artifacts,
            # packages is intentionally flattened for the UI/install-order
            # contract. One uploaded bundle may therefore contribute many rows.
            "packages": flattened,
            "plan": plan,
        }
        _atomic_json(BATCHES_ROOT / f"{batch_id}.json", payload)
        return payload
    except Exception:
        for artifact in artifacts:
            try:
                discard_v2_stage(artifact["upload_id"])
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
            _enforce_candidate_licensing(preview)
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


class _PathUpload:
    """Replayable upload facade used after v2 intake stages an archive once."""
    def __init__(self, path: Path, name: str):
        self.path = Path(path)
        self.name = str(name or self.path.name)
        self.size = self.path.stat().st_size

    def chunks(self, chunk_size=64 * 1024):
        with self.path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                yield chunk


def _copy_upload(upload, target: Path) -> tuple[int, str]:
    size = int(getattr(upload, "size", 0) or 0)
    if size <= 0 or size > MAX_PACKAGE_BYTES:
        raise ModuleManagerV2Error("Artifact is empty or exceeds the package size limit.")
    digest = hashlib.sha256()
    written = 0
    with target.open("wb") as handle:
        for chunk in upload.chunks():
            written += len(chunk)
            if written > MAX_PACKAGE_BYTES:
                raise ModuleManagerV2Error("Artifact exceeds the package size limit.")
            digest.update(chunk)
            handle.write(chunk)
    os.chmod(target, 0o640)
    return written, digest.hexdigest()


def _bundle_manifest_count(path: Path) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            return sum(
                1 for member in archive.infolist()
                if not member.is_dir() and Path(member.filename).name == BUNDLE_MANIFEST
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ModuleManagerV2Error(f"Unable to inspect ZIP artifact: {exc}") from exc


def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None) -> dict:
    # Classification is structural, never filename-based. Bundle manifests are
    # detected before legacy single-package validation.
    """Classify one upload before applying package-specific validation.

    ZIP bundle detection happens before the legacy single-package parser. This
    prevents a valid bundle from failing with the misleading v1 error
    'exactly one extension manifest; found 0'. The upload is copied once and a
    replayable path-backed facade is used for normal package staging.
    """
    name = str(getattr(upload, "name", "package"))

    if name.lower().endswith(".zip"):
        BUNDLES_ROOT.mkdir(parents=True, exist_ok=True)
        intake_id = str(uuid.uuid4())
        intake_path = BUNDLES_ROOT / f"{intake_id}.zip"
        try:
            written, digest = _copy_upload(upload, intake_path)
            manifest_count = _bundle_manifest_count(intake_path)
            if manifest_count:
                if manifest_count != 1:
                    raise ModuleManagerV2Error(f"Bundle must contain exactly one {BUNDLE_MANIFEST}.")
                preview = _inspect_bundle(intake_path)
                payload = {
                    "kind": "bundle",
                    "upload_id": intake_id,
                    "filename": name,
                    "bundle_path": str(intake_path),
                    "sha256": digest,
                    "size": written,
                    "created_at": _utcnow(),
                    "preview": preview,
                }
                sidecars = []
                try:
                    if signature_upload is not None:
                        sig_path = BUNDLES_ROOT / f"{intake_id}.sig"
                        _copy_sidecar(signature_upload, sig_path)
                        payload["signature_path"] = str(sig_path)
                        payload["signature_filename"] = str(getattr(signature_upload, "name", "bundle.zip.sig"))
                        sidecars.append(sig_path)
                    if metadata_upload is not None:
                        rel_path = BUNDLES_ROOT / f"{intake_id}.release.json"
                        _copy_sidecar(metadata_upload, rel_path)
                        payload["release_metadata_path"] = str(rel_path)
                        payload["release_metadata_filename"] = str(getattr(metadata_upload, "name", "bundle.release.json"))
                        sidecars.append(rel_path)
                    requested_permissions = set()
                    for child in preview.get("packages") or []:
                        requested_permissions.update(child.get("publisher_permissions") or [])
                    payload["publisher_trust"] = _verify_stage_trust({
                        "package_path": payload["bundle_path"],
                        "filename": payload["filename"],
                        "signature_path": payload.get("signature_path"),
                        "signature_filename": payload.get("signature_filename"),
                        "release_metadata_path": payload.get("release_metadata_path"),
                    }, require_signed=bool(requested_permissions - {"module.install"}), required_permissions=tuple(sorted({"module.install", *requested_permissions})))
                except Exception:
                    for path in sidecars:
                        path.unlink(missing_ok=True)
                    raise
                _atomic_json(BUNDLES_ROOT / f"{intake_id}.json", payload)
                return {key: value for key, value in payload.items() if key not in {"bundle_path", "signature_path", "release_metadata_path"}}

            staged = stage_uploaded_package(_PathUpload(intake_path, name), signature_upload=signature_upload, metadata_upload=metadata_upload)
        finally:
            # Valid bundles return before this point and retain their staged ZIP.
            if intake_path.is_file() and not (BUNDLES_ROOT / f"{intake_id}.json").is_file():
                intake_path.unlink(missing_ok=True)
    else:
        staged = stage_uploaded_package(upload, signature_upload=signature_upload, metadata_upload=metadata_upload)

    meta = _load_stage(staged["upload_id"])
    preview = _package_metadata(Path(meta["package_path"]))
    _enforce_candidate_licensing(preview)
    plan = resolve_install_plan([preview])
    staged["preview"] = {
        **preview,
        "kind": "package",
        "plan": plan,
        "installable": bool(preview.get("installable")) and plan["valid"],
        "install_block_reason": preview.get("install_block_reason")
        if not preview.get("installable")
        else (None if plan["valid"] else "Dependency plan is not satisfiable."),
    }
    _atomic_json(STAGED_ROOT / f"{staged['upload_id']}.json", {**meta, "preview": staged["preview"]})
    return staged


def attach_source_provenance(upload_id: str, source: dict) -> None:
    """Attach repository provenance to either a staged package or bundle."""
    try:
        meta = _load_stage(upload_id)
    except ModuleManagerError:
        meta = None
    if meta is not None:
        meta["source_provenance"] = dict(source or {})
        _atomic_json(STAGED_ROOT / f"{upload_id}.json", meta)
        return
    bundle = _load_bundle(upload_id)
    bundle["source_provenance"] = dict(source or {})
    _atomic_json(BUNDLES_ROOT / f"{upload_id}.json", bundle)



def discard_v2_stage(upload_id: str) -> None:
    """Discard any v2 staged artifact and its child v1 package stages."""
    try:
        batch = _load_batch(upload_id)
    except ModuleManagerV2Error:
        batch = None
    if batch is not None:
        children = batch.get("artifacts") or batch.get("packages") or []
        seen = set()
        for artifact in children:
            child_id = str(artifact.get("upload_id") or artifact.get("source_upload_id") or "")
            if not child_id or child_id in seen or child_id == str(upload_id):
                continue
            seen.add(child_id)
            try:
                discard_v2_stage(child_id)
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
        if bundle.get("signature_path"):
            Path(str(bundle.get("signature_path"))).unlink(missing_ok=True)
        if bundle.get("release_metadata_path"):
            Path(str(bundle.get("release_metadata_path"))).unlink(missing_ok=True)
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


def queue_v2_install(upload_id: str, requested_order=None, requested_by: str | None = None, disable_replaced=None, actor=None) -> dict:
    # Individual v1-staged package.
    try:
        meta = _load_stage(upload_id)
    except ModuleManagerError:
        meta = None
    if meta:
        preview = _package_metadata(Path(meta["package_path"]))
        requested_permissions = set(preview.get("publisher_permissions") or [])
        trust = _verify_stage_trust(meta, require_signed=bool(requested_permissions - {"module.install"}), required_permissions=tuple(sorted({"module.install", *requested_permissions})))
        _enforce_candidate_licensing(preview)
        plan = resolve_install_plan([preview])
        plan = _plan_with_requested_order(plan, requested_order)
        if not preview.get("installable") or not plan["valid"]:
            raise ModuleManagerV2Error(preview.get("install_block_reason") or "Package dependency plan is not satisfiable.")
        disable_modules = _confirmed_disables(plan.get("will_disable"), disable_replaced, f"Module {preview['id']!r}")
        replace = bool(preview.get("already_installed"))
        rename_action = next((item for item in plan.get("actions", []) if item.get("action") == "rename"), None)
        source = meta.get("source_provenance")
        if source or rename_action or disable_modules:
            # Online repository packages, identity-renaming upgrades and installs that disable a replaced module
            # (1.17.11) use the v2 worker so provenance/identity state, and the disable, are committed atomically
            # only after a successful lifecycle transaction. Only the v2 worker can disable in the same job.
            action = {
                "id": preview["id"],
                "version": preview["extension_version"],
                "action": "replace" if replace else "install",
                "current_version": preview.get("installed_version"),
                "dependencies": preview.get("dependencies", {}),
                "will_disable": list(disable_modules),
            }
            single_plan = {**plan, "actions": [action]}
            job = _queue_v2({
                "action": "batch_install",
                "plugin_id": preview["id"],
                "batch_id": upload_id,
                "packages": [{
                    "id": preview["id"],
                    "path": meta["package_path"],
                    "upload_id": upload_id,
                    "source": source,
                    "publisher_trust": trust,
                    "package_sha256": meta.get("sha256"),
                    "signature_path": meta.get("signature_path"),
                    "release_metadata_path": meta.get("release_metadata_path"),
                }],
                "plan": single_plan,
                "disable_modules": disable_modules,
                "requested_by": str(requested_by) if requested_by else None,
            })
            _audit_plan_disables(actor, single_plan, job)
            return job
        # Local/offline single-package deployment keeps using the proven v1 worker.
        from .module_manager import queue_install
        return queue_install(upload_id, replace=replace, requested_by=requested_by)

    # Bundle staging.
    bundle = _load_bundle(upload_id)
    fresh_preview = _inspect_bundle(Path(bundle["bundle_path"]))
    bundle_permissions = set()
    for child in fresh_preview.get("packages") or []:
        bundle_permissions.update(child.get("publisher_permissions") or [])
    bundle_trust = _verify_stage_trust({
        "package_path": bundle["bundle_path"],
        "filename": bundle.get("filename"),
        "signature_path": bundle.get("signature_path"),
        "signature_filename": bundle.get("signature_filename"),
        "release_metadata_path": bundle.get("release_metadata_path"),
    }, require_signed=bool(bundle_permissions - {"module.install"}), required_permissions=tuple(sorted({"module.install", *bundle_permissions})))
    plan = fresh_preview.get("plan") or {}
    if not plan.get("valid"):
        raise ModuleManagerV2Error("Bundle dependency plan is not satisfiable.")
    plan = _plan_with_requested_order(plan, requested_order)
    disable_modules = _confirmed_disables(plan.get("will_disable"), disable_replaced, f"Bundle {bundle['preview']['id']!r}")
    job = _queue_v2({
        "action": "bundle_install",
        "plugin_id": bundle["preview"]["id"],
        "upload_id": upload_id,
        "bundle_path": bundle["bundle_path"],
        "plan": plan,
        "bundle": fresh_preview,
        "source": bundle.get("source_provenance"),
        "publisher_trust": bundle_trust,
        "package_sha256": bundle.get("sha256"),
        "signature_path": bundle.get("signature_path"),
        "release_metadata_path": bundle.get("release_metadata_path"),
        "disable_modules": disable_modules,
        "requested_by": str(requested_by) if requested_by else None,
    })
    _audit_plan_disables(actor, plan, job)
    return job


def queue_batch_install(batch_id: str, requested_order=None, requested_by: str | None = None, disable_replaced=None, actor=None) -> dict:
    batch = _load_batch(batch_id)
    job_artifacts = []
    candidates = []

    artifacts = batch.get("artifacts")
    if not isinstance(artifacts, list):
        # Compatibility with batches staged by 1.15.7 and older.
        artifacts = [{**item, "kind": "package"} for item in (batch.get("packages") or [])]

    for artifact in artifacts:
        kind = str(artifact.get("kind") or (artifact.get("preview") or {}).get("kind") or "package")
        upload_id = str(artifact.get("upload_id") or "")
        if kind == "bundle":
            bundle = _load_bundle(upload_id)
            fresh = _inspect_bundle(Path(bundle["bundle_path"]))
            bundle_permissions = set()
            for child in fresh.get("packages") or []:
                bundle_permissions.update(child.get("publisher_permissions") or [])
            bundle_trust = _verify_stage_trust({
                "package_path": bundle["bundle_path"],
                "filename": bundle.get("filename"),
                "signature_path": bundle.get("signature_path"),
                "signature_filename": bundle.get("signature_filename"),
                "release_metadata_path": bundle.get("release_metadata_path"),
            }, require_signed=bool(bundle_permissions - {"module.install"}), required_permissions=tuple(sorted({"module.install", *bundle_permissions})))
            candidates.extend(fresh.get("packages") or [])
            job_artifacts.append({
                "kind": "bundle",
                "upload_id": upload_id,
                "bundle_path": bundle["bundle_path"],
                "bundle_id": fresh.get("id"),
                "package_files": fresh.get("package_files") or [],
                "package_sha256": bundle.get("sha256"),
                "publisher_trust": bundle_trust,
                "signature_path": bundle.get("signature_path"),
                "release_metadata_path": bundle.get("release_metadata_path"),
            })
            continue

        meta = _load_stage(upload_id)
        candidate = _package_metadata(Path(meta["package_path"]))
        requested_permissions = set(candidate.get("publisher_permissions") or [])
        trust = _verify_stage_trust(meta, require_signed=bool(requested_permissions - {"module.install"}), required_permissions=tuple(sorted({"module.install", *requested_permissions})))
        _enforce_candidate_licensing(candidate)
        candidates.append(candidate)
        job_artifacts.append({
            "kind": "package",
            "id": candidate["id"],
            "path": meta["package_path"],
            "upload_id": upload_id,
            "source": meta.get("source_provenance"),
            "publisher_trust": trust,
            "package_sha256": meta.get("sha256"),
            "signature_path": meta.get("signature_path"),
            "release_metadata_path": meta.get("release_metadata_path"),
        })

    # Re-resolve from the freshly inspected child packages immediately before
    # dispatch. This catches changed/corrupt staging and duplicate module IDs
    # across two bundles or a bundle plus a standalone package.
    for candidate in candidates:
        _enforce_candidate_licensing(candidate)
    plan = resolve_install_plan(candidates)
    if not plan.get("valid"):
        raise ModuleManagerV2Error("Batch dependency plan is not satisfiable.")
    plan = _plan_with_requested_order(plan, requested_order)
    disable_modules = _confirmed_disables(plan.get("will_disable"), disable_replaced, "This install")
    job = _queue_v2({
        "action": "batch_install",
        "plugin_id": "batch",
        "batch_id": batch_id,
        "artifacts": job_artifacts,
        "plan": plan,
        "disable_modules": disable_modules,
        "requested_by": str(requested_by) if requested_by else None,
    })
    _audit_plan_disables(actor, plan, job)
    return job


def _enabled_dependants(module_id: str) -> list[dict]:
    """Enabled modules that hard-depend on ``module_id``. 1.17.11: when ``module_id`` is an honoured replacement, the
    enabled dependants of the module it replaces count too (the replacement is what satisfies them), marked ``via``."""
    catalog = installed_catalog_v2()
    state = load_state()
    watched = {module_id: None}
    replaced = module_replacement.honoured_replacement(module_id)
    if replaced:
        watched[replaced] = replaced
    result = []
    for item in catalog:
        if item.get("legacy") or not is_enabled(item["id"], state) or item["id"] == module_id:
            continue
        for watched_id, via in watched.items():
            constraint = (item.get("dependencies") or {}).get(watched_id)
            if constraint:
                entry = {"id": item["id"], "constraint": constraint}
                if via:
                    entry["via"] = via
                result.append(entry)
                break
    return result


def _enable_problems(catalog: dict, model: dict, module_id: str, *, hypothetical: bool = False) -> list[dict]:
    """Problems that stop ``module_id`` being enabled, judged against ``model``. With ``hypothetical`` the enabled state of
    a dependency comes from ``model`` (the state after the job), not from the catalogue (the state now)."""
    target = catalog[module_id]
    problems = []
    for dep_id, constraint in (target.get("dependencies") or {}).items():
        dep = catalog.get(dep_id)
        if not dep:
            problems.append({"type": "missing_dependency", "dependency": dep_id, "constraint": constraint})
            continue
        dep_enabled = bool(dep.get("enabled"))
        if hypothetical and dep_id in model:
            dep_enabled = bool(model[dep_id].enabled)
        # 1.17.11: an honoured replacement stands in for a disabled dependency. The version still applies to the dependency.
        if not dep_enabled and not module_replacement.satisfies_dependency(model, dep_id):
            problems.append({"type": "disabled_dependency", "dependency": dep_id, "constraint": constraint})
        if not version_satisfies(dep.get("extension_version") or "0.0.0", constraint):
            problems.append({"type": "dependency_version", "dependency": dep_id, "constraint": constraint, "version": dep.get("extension_version")})
    for check in target.get("runtime_requirements") or []:
        if not check.get("satisfied"):
            problems.append({"type": "runtime", **check})
    # AD-20: enabling a replacement names the module it will disable (1.17.11), and enabling a core or server module names
    # the replacement it will switch off (1.17.12); the other replacement rules still apply.
    problems.extend(module_replacement.enable_problems(model, module_id))
    # AD-21 (1.17.14, CQ38): the category refusal applies at install only. A module already installed can be enabled.
    return problems


def _replacement_dependants(catalog: dict, model: dict, module_id: str, replacements) -> list[dict]:
    """[{replacement, modules[]}]: the enabled modules that name a replacement, which enabling ``module_id`` would switch
    off, directly in their ``dependencies`` (1.17.14, CQ35). It is a warning, never a refusal and never a cascade.

    Modules that depend on ``module_id`` itself are not listed: it is the module coming back, and the replacement's
    contract parity (AD-20 condition 3) keeps the others satisfied."""
    found = []
    for replacement_id in replacements:
        names = []
        for item in sorted(catalog.values(), key=lambda row: row["id"]):
            if item.get("legacy") or item["id"] in (module_id, replacement_id) or replacement_id not in (item.get("dependencies") or {}):
                continue
            node = model.get(item["id"])
            if (node.enabled if node is not None else item.get("enabled")):
                names.append(item["id"])
        if names:
            found.append({"replacement": replacement_id, "modules": names})
    return found


def validate_enable(module_id: str) -> dict:
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if target.get("protected"):
        raise ModuleManagerV2Error("Protected framework modules cannot be enabled/disabled from the UI.")
    # 1.17.9-1: queued enable/disable jobs not yet applied count as done, so two queued jobs cannot both pass.
    model = _model_with_pending_jobs(module_replacement.live_model())
    problems = _enable_problems(catalog, model, module_id)
    will_disable = [] if problems else module_replacement.disable_plan(model, module_id)
    dependants = _replacement_dependants(catalog, model, module_id, will_disable) if will_disable and module_replacement.switches_replacement(model, module_id) else []
    return {"valid": not problems, "problems": problems, "will_disable": will_disable, "replacement_dependants": dependants}


def _hand_back_split(catalog: dict, model: dict, replacement_id: str, will_enable, off) -> tuple[list[str], list[dict]]:
    """(can come back, cannot) for the modules that disabling ``replacement_id`` would switch back on (1.17.14, CQ34).

    Judged on the model as it will be with ``off`` (the replacement and any cascade) disabled. ``cannot`` rows are
    {module, reasons[], required_modules[], problems[]}: plain-English reasons, and the modules whose absence or state
    stops it (taken from the missing, disabled or out-of-range dependency rows)."""
    future = module_replacement._with_enabled(model, {module_id: False for module_id in off})
    can, cannot = [], []
    for back in will_enable:
        item = catalog.get(back)
        if item is None or item.get("protected") or not item.get("managed", True):
            inner = [{"type": "not_manageable", "module": back}]
        else:
            inner = _enable_problems(catalog, future, back, hypothetical=True)
        if not inner:
            can.append(back)
            continue
        required = sorted({str(entry["dependency"]) for entry in inner if entry.get("dependency")})
        cannot.append({"module": back, "reasons": [_problem_text(entry) for entry in inner],
                       "required_modules": required, "problems": inner})
    return can, cannot


def _hand_back_problems(catalog: dict, model: dict, replacement_id: str, will_enable, off) -> list[dict]:
    """Warnings for the modules that disabling ``replacement_id`` switches back on but that cannot come back (1.17.14,
    CQ34). Since 1.17.14 these are warnings that need a confirmation, not refusals. Empty when every one can come back."""
    _, cannot = _hand_back_split(catalog, model, replacement_id, will_enable, off)
    warnings = []
    for row in cannot:
        warnings.append({
            "type": "hand_back_unavailable", "module": replacement_id, "replaced": row["module"], "problems": row["problems"],
            "reasons": row["reasons"], "required_modules": row["required_modules"],
            "message": f"Disabling {replacement_id!r} cannot switch {row['module']!r} back on: {'; '.join(row['reasons'])}. It would stay off.",
        })
    return warnings


def _unavailable_rows(cannot) -> list[dict]:
    return [{"module": row["module"], "reasons": list(row["reasons"]), "required_modules": list(row["required_modules"])} for row in cannot]


def _hand_back_wanted(model: dict, affected) -> list[str]:
    """The replaced modules a disable would switch back on, over every module it switches off, the cascade included
    (1.17.14, CQ36). A replacement disabled as part of a deliberate cascade hands back too.

    Each replacement in ``affected`` is judged with the others already off, so two replacements of one module, both being
    disabled, still hand it back."""
    off = list(dict.fromkeys(affected))
    wanted: list[str] = []
    for module_id in off:
        plan = module_replacement.hand_back_plan(module_replacement._with_enabled(model, {mid: False for mid in off if mid != module_id}), module_id)
        for back in plan:
            if back not in wanted and back not in off:
                wanted.append(back)
    return wanted


def _problem_text(problem: dict) -> str:
    kind = problem.get("type")
    dep = problem.get("dependency")
    if kind == "missing_dependency":
        return f"it needs module {dep!r}, which is not installed"
    if kind == "disabled_dependency":
        return f"it needs module {dep!r}, which is disabled"
    if kind == "dependency_version":
        return f"module {dep!r} is at version {problem.get('version')}, and it needs {problem.get('constraint')}"
    if kind == "runtime":
        return "a runtime requirement is not met"
    if kind == "not_manageable":
        return "it cannot be enabled or disabled from the UI"
    return str(problem.get("message") or kind or "a rule refuses it")


def validate_disable(module_id: str, affected=None) -> dict:
    """What disabling ``module_id`` would also do (1.17.12, CQ33): ``will_enable`` names the replaced modules that come
    back on. 1.17.14 (CQ34): a replaced module that cannot come back is a warning, not a refusal. ``hand_back_unavailable``
    names it, why, and the modules it needs; ``hand_back_confirmation_required`` says the request must confirm. ``problems``
    carries the same warnings. ``affected`` is the cascade list."""
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if target.get("protected"):
        raise ModuleManagerV2Error("Protected framework modules cannot be enabled/disabled from the UI.")
    model = _model_with_pending_jobs(module_replacement.live_model())
    off = list(dict.fromkeys([*(affected or ()), module_id]))
    wanted = _hand_back_wanted(model, off)
    can, cannot = _hand_back_split(catalog, model, module_id, wanted, off) if wanted else ([], [])
    problems = _hand_back_problems(catalog, model, module_id, wanted, off) if cannot else []
    return {"valid": True, "problems": problems, "will_enable": can,
            "hand_back_unavailable": _unavailable_rows(cannot), "hand_back_confirmation_required": bool(cannot)}


def _iter_jobs():
    """Every readable job file, in no particular order."""
    try:
        paths = list(JOBS_ROOT.glob("*.json")) if JOBS_ROOT.is_dir() else []
    except OSError:
        paths = []
    for path in paths:
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(job, dict):
            yield job


def _model_with_pending_jobs(model: dict) -> dict:
    """The live model with queued, dispatched or running jobs applied in creation order: enable and disable jobs, and
    the modules an enable or install job disables (``disable_modules``, 1.17.11) and the modules a disable job switches
    back on (``enable_modules``, 1.17.12)."""
    pending = [
        job for job in _iter_jobs()
        if job.get("action") in ("enable", "disable", "batch_install", "bundle_install")
        and job.get("status") in ("queued", "dispatched", "running")
    ]
    pending.sort(key=lambda item: str(item.get("created_at") or ""))
    out = dict(model)
    for job in pending:
        if job.get("action") in ("enable", "disable"):
            enabled = job.get("action") == "enable"
            for mid in job.get("affected_modules") or [job.get("plugin_id")]:
                node = out.get(str(mid))
                if node is not None and node.enabled != enabled:
                    out[str(mid)] = dataclasses.replace(node, enabled=enabled)
        for mid in job.get("disable_modules") or []:
            node = out.get(str(mid))
            if node is not None and node.enabled:
                out[str(mid)] = dataclasses.replace(node, enabled=False)
        for mid in job.get("enable_modules") or []:  # 1.17.12: the replaced module a disable job hands back
            node = out.get(str(mid))
            if node is not None and not node.enabled:
                out[str(mid)] = dataclasses.replace(node, enabled=True)
    return out


def _recent_reconcile_jobs() -> dict:
    """{replacement id: when its latest reconcile job was created}, whatever became of that job."""
    latest = {}
    for job in _iter_jobs():
        if job.get("reason") != "replacement_conflict":
            continue
        try:
            when = datetime.fromisoformat(str(job.get("created_at")))
        except (TypeError, ValueError):
            continue
        when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
        mid = str(job.get("plugin_id") or "")
        if mid and (mid not in latest or when > latest[mid]):
            latest[mid] = when
    return latest


def queue_replacement_conflict_disable(replacement_id: str, replaced_id: str) -> dict:
    """Queue the system job that disables a replacement found enabled next to the module it replaces (AD-20,
    1.17.11). It goes through the same sudo dispatch as a user job; dependants are not cascaded."""
    return _queue_v2({
        "action": "disable",
        "plugin_id": replacement_id,
        "enabled": False,
        "cascade": False,
        "affected_modules": [replacement_id],
        "reason": "replacement_conflict",
        "replaced_module": replaced_id,
        "requested_by": "system",
    })


def queue_set_enabled(module_id: str, enabled: bool, cascade: bool = False, requested_by: str | None = None,
                      disable_replaced=None, actor=None, confirm_replacement_switch=None,
                      confirm_without_hand_back=None) -> dict:
    catalog = {item["id"]: item for item in installed_catalog_v2()}
    target = catalog.get(module_id)
    if not target:
        raise ModuleManagerV2Error(f"Module {module_id!r} is not installed.")
    if not target.get("managed"):
        raise ModuleManagerV2Error("Protected modules cannot be enabled or disabled from the UI.")
    affected = [module_id]
    disable_modules: list[str] = []
    enable_modules: list[str] = []
    hand_back_skipped: list[str] = []
    replacement_confirmed = False
    if enabled:
        validation = validate_enable(module_id)
        if not validation["valid"]:
            replacement = [item for item in validation["problems"]
                           if item.get("type") in ("replacement_conflict", "replacement_incomplete")]
            if replacement:
                raise ModuleManagerV2Error("Module cannot be enabled. " + " ".join(item["message"] for item in replacement))
            raise ModuleManagerV2Error("Module cannot be enabled until its dependencies and runtime requirements are satisfied.")
        # 1.17.11: enabling a replacement disables the module it replaces in the same job, and only on the exact list
        # the operator confirmed. The root helper re-checks the rules and holds the job to this list.
        disable_modules = _confirmed_disables(validation.get("will_disable"), disable_replaced, f"Module {module_id!r}")
        # 1.17.12 (CQ32): enabling the replaced module switches its replacement off. That needs a second confirmation,
        # after the first (the list). Enabling a replacement keeps its single confirmation.
        if disable_modules and module_replacement.switches_replacement(_model_with_pending_jobs(module_replacement.live_model()), module_id):
            if confirm_replacement_switch is not True:
                raise ModuleReplacementSecondConfirmationRequired(
                    disable_modules, module_id, _replacement_dependants(catalog, _model_with_pending_jobs(module_replacement.live_model()), module_id, disable_modules))
            replacement_confirmed = True
    else:
        # 1.17.12 (CQ33): disabling a replacement switches the module it replaces back on, when it can come back. The
        # dependants of that module stay satisfied throughout, so they do not block the disable. 1.17.14: a replaced
        # module that cannot come back does not stop the disable; it asks for a confirmation and stays off.
        live = _model_with_pending_jobs(module_replacement.live_model())
        first_plan = module_replacement.hand_back_plan(live, module_id)
        coming_back, _ = _hand_back_split(catalog, live, module_id, first_plan, {module_id}) if first_plan else ([], [])

        def dependants_of(mid):
            return [item for item in _enabled_dependants(mid) if not (coming_back and mid == module_id and item.get("via"))]

        dependants = dependants_of(module_id)
        if dependants and not cascade:
            names = ", ".join(item["id"] for item in dependants)
            raise ModuleManagerV2Error(f"Module is required by enabled module(s): {names}. Disable dependants first or request cascade.")
        if cascade:
            # Recursively disable enabled dependants before the requested module.
            seen = set()
            def visit(mid):
                for dep in dependants_of(mid):
                    if dep["id"] not in seen:
                        seen.add(dep["id"])
                        visit(dep["id"])
                        affected.append(dep["id"])
            visit(module_id)
            affected = [mid for mid in affected if mid != module_id] + [module_id]
        # 1.17.14 (CQ36): a deliberate disable always hands back, a replacement disabled in a cascade included.
        wanted = _hand_back_wanted(live, affected)
        if wanted:
            enable_modules, cannot = _hand_back_split(catalog, live, module_id, wanted, set(affected))
            if cannot:
                if confirm_without_hand_back is not True:
                    raise ModuleReplacementHandBackConfirmationRequired(module_id, enable_modules, _unavailable_rows(cannot))
                hand_back_skipped = sorted(row["module"] for row in cannot)
    payload = {
        "action": "enable" if enabled else "disable",
        "plugin_id": module_id,
        "enabled": bool(enabled),
        "cascade": bool(cascade),
        "affected_modules": affected,
        "requested_by": str(requested_by) if requested_by else None,
    }
    if enabled:
        payload["disable_modules"] = disable_modules
        payload["replacement_confirmed"] = replacement_confirmed
    else:
        payload["enable_modules"] = enable_modules
        payload["hand_back_skipped"] = hand_back_skipped
    job = _queue_v2(payload)
    if disable_modules or enable_modules or hand_back_skipped:
        extra = {"skipped": hand_back_skipped} if hand_back_skipped else {}  # 1.17.14: the row names what a confirmed disable left off
        module_replacement.audit_switch_queued(actor, module_id, job.get("id"), disabled=disable_modules, enabled=enable_modules, **extra)
    return job


def queue_set_visibility(module_id: str, visible: bool, requested_by: str | None = None) -> dict:
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
        "requested_by": str(requested_by) if requested_by else None,
    })


def validate_remove(module_id: str) -> dict:
    dependants = _enabled_dependants(module_id)
    return {"valid": not dependants, "dependants": dependants}
