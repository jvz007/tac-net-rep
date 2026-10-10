"""Mount a module's URLs from its manifest ``routes`` key (1.17.16).

A module that declares ``"routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}`` in ``tec_tac.json`` no
longer has to append to ``tacticalrmm.urls`` or ``tec_tac.urls`` from its own ``AppConfig.ready()``. Core serves the urlconf at
``/api/tfd/<prefix>/``, the same URL shape every module has today.

When it runs: ``bootstrap.py`` calls ``mount_module_routes()`` from its ``Apps.populate`` wrapper, after every
``AppConfig.ready()`` has run. A module's urls are therefore never imported before its own ``ready()``.

What it mounts: only modules whose Django app is actually loaded. A disabled module, and an AD-20 replacement Core dropped
because it was enabled next to the module it replaces, are not loaded and so are not mounted.

How it stays safe (rule 1.15, nothing here may stop Tactical starting):

* Each module is mounted inside its own try/except. A urlconf that cannot be imported is logged and skipped, and nothing else
  is affected. The urlconf is imported here, so a broken one never reaches Django's URL resolver.
* Core's own routes come first in ``tec_tac.urls.urlpatterns``. A module's pattern is appended after them, so Core always wins
  on any overlap (the ``audit`` module's prefix shares a first segment with Core's ``audit/record/``, which stays legal).
* Compatibility path, with no end date: a module that still appends to ``tec_tac.urls`` or ``tacticalrmm.urls`` is untouched.
  A prefix already present in either list is reported as ``compat`` and not mounted again, so a module that adds ``routes``
  but forgets to drop its own append still works.
* Two loaded modules asking for the same prefix: the first by sorted id is mounted, the second is refused with a warning.

``mounted_routes()`` reports what happened, read only.
"""
from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from typing import Any

logger = logging.getLogger("tec_tac.route_mounting")

TACTICAL_ROUTE_ROOT = "api/tfd/"
MARKER = "_tec_tac_module_route"  # set on the URL entry Core appends, so Core's own contract export can skip it
STATE_MOUNTED = "mounted"
STATE_COMPAT = "compat"
STATE_REFUSED = "refused"

_RESULTS: list[dict] = []


def _pattern_text(entry) -> str:
    return str(getattr(entry, "pattern", "") or "")


def _loaded_app_names(app_configs: Iterable) -> set[str]:
    names: set[str] = set()
    for config in app_configs:
        names.add(str(getattr(config, "name", "")))
        cls = type(config)
        names.add(f"{cls.__module__}.{cls.__qualname__}")
    return names


def _is_loaded(plugin, loaded: set[str]) -> bool:
    from .registry import app_packages

    entries = set(plugin.django_apps) | set(app_packages(plugin.django_apps))
    return bool(entries & loaded)


def _record(results: list, prefix: str, module: str, state: str, reason: str) -> None:
    results.append({"prefix": prefix, "module": module, "state": state, "reason": reason})


def mount_module_routes(plugins: Iterable | None = None, *, app_configs: Iterable | None = None,
                        tec_tac_patterns: list | None = None, tactical_patterns: list | None = None) -> list[dict]:
    """Mount every loaded module's declared ``routes``. Never raises. Returns what ``mounted_routes()`` reports.

    The keyword arguments let a test pass its own lists; the server passes none."""
    results: list[dict] = []
    try:
        _mount(results, plugins, app_configs, tec_tac_patterns, tactical_patterns)
    except Exception:
        logger.exception("Tec-Tac could not mount module routes; Tactical starts regardless")
    _RESULTS[:] = results
    return mounted_routes()


def _mount(results: list, plugins, app_configs, tec_tac_patterns, tactical_patterns) -> None:
    if plugins is None:
        from .registry import get_plugins

        plugins = get_plugins()
    candidates = sorted(
        (p for p in plugins if p.plugin_type == "extension" and getattr(p, "route_urlconf", "")), key=lambda p: p.plugin_id,
    )
    if not candidates:
        return  # nothing declares routes: do not even import tec_tac.urls
    if app_configs is None:
        from django.apps import apps

        app_configs = apps.get_app_configs()
    loaded = _loaded_app_names(app_configs)
    if tec_tac_patterns is None:
        from . import urls as tec_tac_urls

        tec_tac_patterns = tec_tac_urls.urlpatterns
    if tactical_patterns is None:
        from tacticalrmm import urls as tactical_urls

        tactical_patterns = tactical_urls.urlpatterns

    taken: dict[str, str] = {}  # prefix -> module that mounted it in this run
    for plugin in candidates:
        prefix = plugin.route_prefix or plugin.plugin_id
        try:
            if not _is_loaded(plugin, loaded):
                continue  # disabled, or a replacement Core dropped: not loaded, so not mounted
            if prefix in taken:
                reason = f"Prefix {prefix!r} is already mounted for module {taken[prefix]!r}."
                logger.warning("Module %s asks for route prefix %s, which module %s already uses. Core does not mount it.", plugin.plugin_id, prefix, taken[prefix])
                _record(results, prefix, plugin.plugin_id, STATE_REFUSED, reason)
                continue
            own = f"{prefix}/"
            existing = [entry for entry in tec_tac_patterns if _pattern_text(entry) == own]
            if existing:
                if all(getattr(entry, MARKER, None) == plugin.plugin_id for entry in existing):
                    taken[prefix] = plugin.plugin_id
                    _record(results, prefix, plugin.plugin_id, STATE_MOUNTED, "Mounted by Core from the manifest routes key.")
                else:
                    taken[prefix] = plugin.plugin_id
                    _record(results, prefix, plugin.plugin_id, STATE_COMPAT, "The module already adds this prefix to tec_tac.urls itself.")
                continue
            if any(_pattern_text(entry) == TACTICAL_ROUTE_ROOT + own for entry in tactical_patterns):
                taken[prefix] = plugin.plugin_id
                _record(results, prefix, plugin.plugin_id, STATE_COMPAT, "The module already adds this prefix to Tactical's urls itself.")
                continue
            from django.urls import include, path

            urlconf = importlib.import_module(plugin.route_urlconf)
            if not isinstance(getattr(urlconf, "urlpatterns", None), (list, tuple)):
                raise ImportError(f"{plugin.route_urlconf} has no urlpatterns list")
            entry = path(own, include(urlconf))
            setattr(entry, MARKER, plugin.plugin_id)
            tec_tac_patterns.append(entry)
            taken[prefix] = plugin.plugin_id
            _record(results, prefix, plugin.plugin_id, STATE_MOUNTED, "Mounted by Core from the manifest routes key.")
        except Exception as exc:
            logger.exception("Tec-Tac could not mount the routes of module %s; the module is skipped", plugin.plugin_id)
            _record(results, prefix, plugin.plugin_id, STATE_REFUSED, f"The urlconf could not be loaded ({exc.__class__.__name__}).")


def mounted_routes() -> list[dict[str, Any]]:
    """Read-only status of module route mounting in this process: ``[{prefix, module, state, reason}]``, ordered by prefix then
    module. ``state`` is ``mounted`` (Core mounted it), ``compat`` (the module adds it itself, the old way) or ``refused``
    (a duplicate prefix, or a urlconf that could not be loaded). A module whose app is not loaded is not listed."""
    return [dict(row) for row in sorted(_RESULTS, key=lambda row: (row["prefix"], row["module"]))]
