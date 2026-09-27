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


def module_runtime_snapshot(plugins=None) -> list[dict]:
    """Return one lightweight row for every installed extension/legacy plugin."""
    state = load_state()
    source = get_plugins() if plugins is None else plugins
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
        if enabled and not tuple(plugin.permission_groups or ()):
            logger.warning(
                "Tec-Tac module %s has no declared permissions; browser audit POSTs for this module are blocked with HTTP 403. "
                "Declare an explicit module permission before exposing a browser audit surface.",
                module_id,
            )
        rows.append({
            "id": module_id,
            "version": str(plugin.version or "0.0.0"),
            "installed": True,
            "enabled": enabled,
            "active": enabled,
            "legacy": legacy,
        })
    rows.sort(key=lambda item: item["id"].lower())
    return rows
