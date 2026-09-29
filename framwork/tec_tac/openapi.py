from __future__ import annotations

from copy import deepcopy

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
DEFAULT_ENUM_HOOK = "drf_spectacular.hooks.postprocess_schema_enums"
GROUP_HOOK = "tec_tac.openapi.postprocess_tec_tac_groups"

# Core groups are classified from the owning tec_tac view module rather than
# from URL prefixes. This keeps module callback ownership authoritative even
# when a module intentionally mounts below a Core-looking prefix such as
# /api/tfd/audit/.
CORE_CALLBACK_GROUPS = {
    "tec_tac.account_self_service_views": "Tec-Tac · My Account",
    "tec_tac.account_security_views": "Tec-Tac · Access & Security",
    "tec_tac.session_security_views": "Tec-Tac · Sessions",
    "tec_tac.mfa_backup_views": "Tec-Tac · Authentication",
    "tec_tac.dashboard_views": "Tec-Tac · Dashboards",
    "tec_tac.contract_views": "Tec-Tac · Developer Contracts",
    "tec_tac.resource_views": "Tec-Tac · Clients, Sites & Agents",
    "tec_tac.audit_views": "Tec-Tac · Audit",
    "tec_tac.capability_views": "Tec-Tac · Capabilities",
    "tec_tac.scheduler_views": "Tec-Tac · Scheduler",
    "tec_tac.preference_views": "Tec-Tac · UI Runtime",
    "tec_tac.notice_views": "Tec-Tac · UI Runtime",
    "tec_tac.diagnostic_views": "Tec-Tac · Diagnostics",
    "tec_tac.server_backup_views": "Tec-Tac · Backup & Restore",
    "tec_tac.housekeeping_views": "Tec-Tac · Storage",
    "tec_tac.server_maintenance_views": "Tec-Tac · Server Maintenance",
    "tec_tac.module_repository_views": "Tec-Tac · Module Repository",
    "tec_tac.module_v2_views": "Tec-Tac · Modules",
    "tec_tac.module_hotfix_views": "Tec-Tac · Module Hotfixes",
}

# tec_tac.views predates the split view modules and still owns several distinct
# Core surfaces. Class-name ownership is explicit; there is deliberately no
# generic Framework catch-all.
CORE_VIEW_CLASS_GROUPS = {
    "TotpEnrollmentView": "Tec-Tac · Authentication",
    "TotpQrView": "Tec-Tac · Authentication",
    "UiContextView": "Tec-Tac · UI Runtime",
    "ExtensionPermissionCatalogView": "Tec-Tac · Access & Security",
    "RoleExtensionPermissionsView": "Tec-Tac · Access & Security",
    "ModuleCatalogView": "Tec-Tac · Modules",
    "ModulePackageInspectView": "Tec-Tac · Modules",
    "ModulePackageStageView": "Tec-Tac · Modules",
    "ModulePackageInstallView": "Tec-Tac · Modules",
    "ModuleRemoveView": "Tec-Tac · Modules",
    "ModuleJobView": "Tec-Tac · Modules",
    "SystemUpdateStatusView": "Tec-Tac · System Updates",
    "SystemUpdatePackageInspectView": "Tec-Tac · System Updates",
    "SystemUpdatePackageStageView": "Tec-Tac · System Updates",
    "SystemUpdatePackageInstallView": "Tec-Tac · System Updates",
    "SystemUpdateJobView": "Tec-Tac · System Updates",
    "SystemUpdateOnlineStatusView": "Tec-Tac · System Updates",
    "SystemUpdateBranchesView": "Tec-Tac · System Updates",
    "SystemUpdateOnlineStageView": "Tec-Tac · System Updates",
    "SystemUpdateTrustPolicyView": "Tec-Tac · System Updates",
}

# Exact path compatibility is used only when spectacular did not provide the
# callback for a Core operation. It is intentionally finite: an unknown future
# path is not silently hidden in a catch-all group.
CORE_PATH_GROUPS = (
    ("/api/tfd/account/", "Tec-Tac · My Account"),
    ("/api/tfd/session/", "Tec-Tac · Sessions"),
    ("/api/tfd/access/", "Tec-Tac · Access & Security"),
    ("/api/tfd/auth/", "Tec-Tac · Authentication"),
    ("/api/tfd/dashboards/", "Tec-Tac · Dashboards"),
    ("/api/tfd/contracts/", "Tec-Tac · Developer Contracts"),
    ("/api/tfd/resources/", "Tec-Tac · Clients, Sites & Agents"),
    ("/api/tfd/audit/", "Tec-Tac · Audit"),
    ("/api/tfd/capabilities/", "Tec-Tac · Capabilities"),
    ("/api/tfd/scheduler/", "Tec-Tac · Scheduler"),
    ("/api/tfd/ui/", "Tec-Tac · UI Runtime"),
    ("/api/tfd/system/diagnostics/", "Tec-Tac · Diagnostics"),
    ("/api/tfd/system/recovery/", "Tec-Tac · Backup & Restore"),
    ("/api/tfd/system/backups/", "Tec-Tac · Backup & Restore"),
    ("/api/tfd/system/storage/", "Tec-Tac · Storage"),
    ("/api/tfd/system/maintenance/", "Tec-Tac · Server Maintenance"),
    ("/api/tfd/system/updates/", "Tec-Tac · System Updates"),
    ("/api/tfd/modules/repositories/", "Tec-Tac · Module Repository"),
    ("/api/tfd/modules/catalog/online/", "Tec-Tac · Module Repository"),
    ("/api/tfd/modules/hotfixes/", "Tec-Tac · Module Hotfixes"),
    # v2 hotfix routes live below /modules/v2/<id>/hotfixes and are classified
    # by callback ownership when spectacular metadata is present.
    ("/api/tfd/modules/", "Tec-Tac · Modules"),
)


def registered_module_specs() -> tuple:
    """Return installed extension specs for OpenAPI ownership classification."""
    try:
        from .registry import get_plugins

        return tuple(
            plugin
            for plugin in get_plugins()
            if getattr(plugin, "plugin_type", None) == "extension"
            and getattr(plugin, "plugin_id", None)
        )
    except Exception:
        return ()


def registered_module_namespaces(module_specs=None) -> dict[str, object]:
    """Map installed Django app namespaces to their owning module spec."""
    specs = tuple(module_specs if module_specs is not None else registered_module_specs())
    owners: dict[str, object] = {}
    for plugin in specs:
        plugin_id = str(getattr(plugin, "plugin_id", "") or "").strip()
        if not plugin_id:
            continue
        for app in tuple(getattr(plugin, "django_apps", ()) or ()):
            namespace = str(app or "").strip().split(".", 1)[0]
            if namespace:
                owners[namespace] = plugin
    return owners


def _callback_candidate(callback):
    for candidate in (
        getattr(callback, "cls", None),
        getattr(callback, "view_class", None),
        callback,
    ):
        if candidate is not None:
            module = str(getattr(candidate, "__module__", "") or "").strip()
            if module:
                return candidate
    return None


def _callback_module(callback) -> str:
    candidate = _callback_candidate(callback)
    return str(getattr(candidate, "__module__", "") or "").strip() if candidate is not None else ""


def _callback_name(callback) -> str:
    candidate = _callback_candidate(callback)
    return str(getattr(candidate, "__name__", "") or "").strip() if candidate is not None else ""


def _module_group(plugin) -> str:
    plugin_id = str(getattr(plugin, "plugin_id", "") or "").strip()
    name = str(getattr(plugin, "name", "") or plugin_id).strip() or plugin_id
    category = str(getattr(plugin, "category", "") or "").strip().lower()
    prefix = "Core module" if category == "core" else "Module"
    return f"{prefix} · {name}"


def endpoint_module_owners(generator, *, namespace_owners=None) -> dict[tuple[str, str], object]:
    """Return ``(path, method) -> PluginSpec`` from spectacular callbacks."""
    if generator is None:
        return {}
    owners = dict(namespace_owners if namespace_owners is not None else registered_module_namespaces())
    if not owners:
        return {}
    endpoints = getattr(generator, "endpoints", ()) or ()
    result: dict[tuple[str, str], object] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, (tuple, list)) or len(endpoint) < 4:
            continue
        path, _path_regex, method, callback = endpoint[:4]
        module = _callback_module(callback)
        if not module:
            continue
        for namespace, plugin in owners.items():
            if module == namespace or module.startswith(namespace + "."):
                result[(str(path), str(method).lower())] = plugin
                break
    return result


def core_group_for_callback(callback) -> str | None:
    module = _callback_module(callback)
    if not module:
        return None
    group = CORE_CALLBACK_GROUPS.get(module)
    if group:
        return group
    if module == "tec_tac.views":
        return CORE_VIEW_CLASS_GROUPS.get(_callback_name(callback))
    return None


def core_group_for_path(path: str) -> str | None:
    text = str(path or "")
    for prefix, group in CORE_PATH_GROUPS:
        if text.startswith(prefix):
            return group
    return None


def postprocess_tec_tac_groups(result, generator=None, request=None, public=False):
    """Group every classified ``/api/tfd/`` operation by its true owner.

    Installed module callback ownership always wins over the URL prefix. Core
    callbacks are then classified by their owning view module/class. There is no
    generic Framework fallback: adding a new Core surface requires an explicit
    group so schema coverage tests can detect drift.
    """
    if not isinstance(result, dict):
        return result
    paths = result.get("paths")
    if not isinstance(paths, dict):
        return result

    groups = set()
    module_specs = registered_module_specs()
    namespace_owners = registered_module_namespaces(module_specs)
    endpoint_modules = endpoint_module_owners(generator, namespace_owners=namespace_owners)

    endpoint_callbacks = {}
    if generator is not None:
        for endpoint in getattr(generator, "endpoints", ()) or ():
            if isinstance(endpoint, (tuple, list)) and len(endpoint) >= 4:
                endpoint_callbacks[(str(endpoint[0]), str(endpoint[2]).lower())] = endpoint[3]

    for path, path_item in paths.items():
        if not str(path).startswith("/api/tfd/") or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_name = str(method).lower()
            if method_name not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            key = (str(path), method_name)
            plugin = endpoint_modules.get(key)
            if plugin is not None:
                group = _module_group(plugin)
            else:
                callback = endpoint_callbacks.get(key)
                group = core_group_for_callback(callback) if callback is not None else None
                if group is None:
                    group = core_group_for_path(str(path))

            if group is None:
                # No catch-all. Leave the operation untouched so the schema
                # coverage regression fails visibly instead of mislabelling it.
                continue

            groups.add(group)
            operation["tags"] = [group]

    if groups:
        existing = result.get("tags") if isinstance(result.get("tags"), list) else []
        managed_prefixes = ("Tec-Tac · ", "Core module · ", "Module · ")
        unmanaged = [
            deepcopy(item)
            for item in existing
            if not (
                isinstance(item, dict)
                and str(item.get("name", "")).startswith(managed_prefixes)
            )
        ]
        result["tags"] = unmanaged + [{"name": name} for name in sorted(groups)]
    return result


def install_openapi_grouping(settings_obj=None) -> None:
    if settings_obj is None:
        from django.conf import settings as settings_obj
    current = dict(getattr(settings_obj, "SPECTACULAR_SETTINGS", {}) or {})
    hooks = list(current.get("POSTPROCESSING_HOOKS") or [DEFAULT_ENUM_HOOK])
    if GROUP_HOOK not in hooks:
        hooks.append(GROUP_HOOK)
    current["POSTPROCESSING_HOOKS"] = hooks
    settings_obj.SPECTACULAR_SETTINGS = current
    try:
        from drf_spectacular.settings import spectacular_settings
        reload_fn = getattr(spectacular_settings, "reload", None)
        if callable(reload_fn):
            reload_fn()
    except Exception:
        pass
