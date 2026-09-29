from __future__ import annotations

from copy import deepcopy

CORE_GROUPS = {
    "account": "Tec-Tac · My Account",
    "access": "Tec-Tac · Access & Security",
    "audit": "Tec-Tac · Audit",
    "auth": "Tec-Tac · Authentication",
    "capabilities": "Tec-Tac · Capabilities",
    "contracts": "Tec-Tac · Developer Contracts",
    "dashboards": "Tec-Tac · Dashboards",
    "modules": "Tec-Tac · Modules",
    "resources": "Tec-Tac · Clients, Sites & Agents",
    "scheduler": "Tec-Tac · Scheduler",
    "session": "Tec-Tac · Sessions",
    "system": "Tec-Tac · System",
    "ui": "Tec-Tac · UI Runtime",
}
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
DEFAULT_ENUM_HOOK = "drf_spectacular.hooks.postprocess_schema_enums"
GROUP_HOOK = "tec_tac.openapi.postprocess_tec_tac_groups"


def registered_module_ids() -> frozenset[str]:
    """Return installed extension IDs for OpenAPI ownership classification.

    Schema grouping is documentation-only and must never become a Tactical
    startup dependency, so registry failures degrade to an empty module set.
    """
    try:
        from .registry import get_plugins

        return frozenset(
            str(plugin.plugin_id)
            for plugin in get_plugins()
            if getattr(plugin, "plugin_type", None) == "extension"
            and getattr(plugin, "plugin_id", None)
        )
    except Exception:
        return frozenset()


def schema_group_for_path(path: str, *, module_ids=None) -> str | None:
    text = str(path or "")
    marker = "/api/tfd/"
    if not text.startswith(marker):
        return None
    tail = text[len(marker):].lstrip("/")
    first = tail.split("/", 1)[0].strip() if tail else ""
    if first in CORE_GROUPS:
        return CORE_GROUPS[first]
    known_modules = frozenset(module_ids if module_ids is not None else registered_module_ids())
    if first and first in known_modules:
        return f"Tec-Tac Module · {first}"
    # A future Core route may introduce a new first path segment before this
    # grouping table is updated. Unknown prefixes are therefore Core-owned by
    # default; only IDs proven by the live extension registry are labelled as
    # modules. This is the real catch-all required by the Swagger contract.
    return "Tec-Tac · Framework"


def postprocess_tec_tac_groups(result, generator=None, request=None, public=False):
    """Group every /api/tfd endpoint in Swagger by Core area or module ID.

    drf-spectacular invokes this after endpoint discovery, so it covers Core
    endpoints and dynamically mounted module URLconfs without requiring module
    authors to repeat @extend_schema(tags=...) on every view.
    """
    if not isinstance(result, dict):
        return result
    paths = result.get("paths")
    if not isinstance(paths, dict):
        return result

    groups = set()
    module_ids = registered_module_ids()
    for path, path_item in paths.items():
        group = schema_group_for_path(path, module_ids=module_ids)
        if not group or not isinstance(path_item, dict):
            continue
        groups.add(group)
        for method, operation in path_item.items():
            if str(method).lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation["tags"] = [group]

    if groups:
        existing = result.get("tags") if isinstance(result.get("tags"), list) else []
        non_tec = [deepcopy(item) for item in existing if not (isinstance(item, dict) and str(item.get("name", "")).startswith("Tec-Tac"))]
        result["tags"] = non_tec + [{"name": name} for name in sorted(groups)]
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
    # If drf-spectacular settings were resolved unusually early, refresh them.
    try:
        from drf_spectacular.settings import spectacular_settings
        reload_fn = getattr(spectacular_settings, "reload", None)
        if callable(reload_fn):
            reload_fn()
    except Exception:
        pass
