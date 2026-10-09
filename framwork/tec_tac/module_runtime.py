"""Lightweight installed/enabled module snapshot for UI runtime discovery.

This intentionally avoids the full Module Manager catalogue: shell startup only
needs stable identity, version and enabled state so optional UI integrations can
degrade cleanly without making extra HTTP requests or scanning Public Contracts.
"""
from __future__ import annotations

import logging

from .module_state import is_enabled, load_state
from .registry import get_plugins

logger = logging.getLogger("tec_tac.module_runtime")

# Warn once per module per process: the snapshot runs on every UI-context request.
_WARNED_MODULES: set[str] = set()


def _conflicted_replacements(source, state) -> set[str]:
    """Ids of the enabled replacements that sit next to their enabled replaced module. Never raises."""
    try:
        from .module_replacement import conflicted_replacements, live_model

        return {replacement for replacement, _ in conflicted_replacements(live_model(source, state))}
    except Exception:
        logger.exception("Could not check for a replacement next to its module; reporting module state as stored.")
        return set()


def _development_server() -> bool:
    from .module_category import is_development_server

    return is_development_server()


def _category_row(plugin, legacy: bool, development: bool) -> dict:
    """AD-21 fields (1.17.13). A legacy plugin has no category, so it is never missing and never refused."""
    if legacy:
        return {"category": None, "effective_category": None, "category_missing": False, "category_refused": False, "category_warning": None}
    from .module_category import describe

    return describe(getattr(plugin, "category", ""), development=development)


def module_runtime_snapshot(plugins=None) -> list[dict]:
    """Return one lightweight row for every installed extension/legacy plugin.

    1.17.11: ``replaces`` is the manifest's declared value (null for a module that declares none and for a legacy
    plugin). 1.17.13 (AD-21): ``category``, ``effective_category``, ``category_missing``, ``category_refused`` and
    ``category_warning`` on every row. A replacement that is enabled next to its enabled replaced module is reported as not enabled and not
    active, because Core does not load its backend (AD-20)."""
    state = load_state()
    source = get_plugins() if plugins is None else plugins
    conflicted = _conflicted_replacements(source, state)
    development = _development_server()
    rows: list[dict] = []
    seen: set[str] = set()
    for plugin in source:
        if plugin.plugin_type not in {"extension", "legacy"}:
            continue
        module_id = str(plugin.plugin_id)
        if module_id in seen:
            continue
        seen.add(module_id)
        legacy = bool(plugin.legacy or plugin.plugin_type == "legacy")
        enabled = True if legacy else bool(is_enabled(module_id, state))
        if module_id in conflicted:
            enabled = False
        if (
            enabled
            and not tuple(plugin.permission_groups or ())
            and not tuple(getattr(plugin, "audit_events", ()) or ())
            and module_id not in _WARNED_MODULES
        ):
            _WARNED_MODULES.add(module_id)
            logger.warning(
                "Tec-Tac module %s has no declared permissions and no audit_events; browser audit POSTs for this module get HTTP 403. "
                "Declare an explicit module permission, or declare the events in audit_events, before exposing a browser audit surface.",
                module_id,
            )
        rows.append({
            "id": module_id,
            "version": str(plugin.version or "0.0.0"),
            "installed": True,
            "enabled": enabled,
            "active": enabled,
            "legacy": legacy,
            "replaces": (str(getattr(plugin, "replaces", "") or "") or None) if not legacy else None,
            **_category_row(plugin, legacy, development),
        })
    rows.sort(key=lambda item: item["id"].lower())
    return rows
