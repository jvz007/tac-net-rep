"""Tec-Tac plugin registry.

The framework has two first-class plugin types:

* extensions/<extension-id>/
* reportsets/<extension-id>/

The directory name is the stable extension ID. A reportset uses the same ID as
its owning extension. Each plugin directory may contain a ``tec_tac.json``
manifest. The manifest can expose Python import paths and Django app configs.

The 0.5.x reporting POC predates this convention and remains registered as a
legacy plugin until it is migrated alongside the first named extension.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
TEC_TAC_ROOT = FRAMEWORK_ROOT.parent
EXTENSIONS_ROOT = TEC_TAC_ROOT / "extensions"
REPORTSETS_ROOT = TEC_TAC_ROOT / "reportsets"
MANIFEST_NAME = "tec_tac.json"


class RegistryError(RuntimeError):
    """Raised when Tec-Tac plugin metadata is invalid."""


@dataclass(frozen=True)
class PluginSpec:
    plugin_id: str
    plugin_type: str
    root: Path
    python_paths: tuple[Path, ...] = ()
    django_apps: tuple[str, ...] = ()
    legacy: bool = False


def _safe_plugin_id(value: str) -> str:
    value = value.strip()
    if not value:
        raise RegistryError("Plugin ID must not be blank.")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_"
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if any(ch not in allowed for ch in value):
        raise RegistryError(f"Invalid plugin ID: {value!r}")
    return value


def _load_manifest(plugin_type: str, plugin_dir: Path) -> PluginSpec | None:
    manifest_path = plugin_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return None

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Unable to read {manifest_path}: {exc}") from exc

    plugin_id = _safe_plugin_id(str(payload.get("id", plugin_dir.name)))
    if plugin_id != plugin_dir.name:
        raise RegistryError(
            f"Plugin manifest ID {plugin_id!r} must match directory name "
            f"{plugin_dir.name!r}: {manifest_path}"
        )

    declared_type = str(payload.get("type", plugin_type)).strip()
    if declared_type != plugin_type:
        raise RegistryError(
            f"Plugin {plugin_id!r} declares type {declared_type!r}; expected "
            f"{plugin_type!r}."
        )

    python_paths: list[Path] = []
    for item in payload.get("python_paths", ["."]):
        path = (plugin_dir / str(item)).resolve()
        try:
            path.relative_to(plugin_dir.resolve())
        except ValueError as exc:
            raise RegistryError(
                f"Plugin {plugin_id!r} python path escapes its plugin root: {item!r}"
            ) from exc
        if not path.exists():
            raise RegistryError(
                f"Plugin {plugin_id!r} python path does not exist: {path}"
            )
        python_paths.append(path)

    django_apps = tuple(str(item).strip() for item in payload.get("django_apps", ()))
    if any(not item for item in django_apps):
        raise RegistryError(f"Plugin {plugin_id!r} contains a blank Django app entry.")

    return PluginSpec(
        plugin_id=plugin_id,
        plugin_type=plugin_type,
        root=plugin_dir.resolve(),
        python_paths=tuple(python_paths),
        django_apps=django_apps,
    )


def _discover_root(plugin_type: str, root: Path) -> list[PluginSpec]:
    if not root.exists():
        return []
    if not root.is_dir():
        raise RegistryError(f"Tec-Tac {plugin_type} root is not a directory: {root}")

    plugins: list[PluginSpec] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.name.startswith("."):
            continue
        spec = _load_manifest(plugin_type, child)
        if spec is not None:
            plugins.append(spec)
    return plugins


def discover_plugins() -> tuple[PluginSpec, ...]:
    """Discover convention-based extension and reportset plugins."""
    extensions = _discover_root("extension", EXTENSIONS_ROOT)
    reportsets = _discover_root("reportset", REPORTSETS_ROOT)

    extension_ids = {plugin.plugin_id for plugin in extensions}
    for reportset in reportsets:
        if reportset.plugin_id not in extension_ids:
            raise RegistryError(
                f"Reportset {reportset.plugin_id!r} has no matching extension at "
                f"extensions/{reportset.plugin_id}/."
            )

    return tuple([*extensions, *reportsets])


def legacy_plugins() -> tuple[PluginSpec, ...]:
    """Return compatibility registrations for pre-foundation POC modules."""
    legacy_root = EXTENSIONS_ROOT / "reporting"
    legacy_app = legacy_root / "tfdreporting"
    if not (legacy_app / "apps.py").is_file():
        return ()

    return (
        PluginSpec(
            plugin_id="legacy-reporting-poc",
            plugin_type="legacy",
            root=legacy_root.resolve(),
            python_paths=(legacy_root.resolve(),),
            django_apps=("tfdreporting.apps.TfdreportingConfig",),
            legacy=True,
        ),
    )


def get_plugins() -> tuple[PluginSpec, ...]:
    """Return all plugins in deterministic load order."""
    plugins = [*discover_plugins(), *legacy_plugins()]

    seen_apps: dict[str, str] = {}
    for plugin in plugins:
        for app in plugin.django_apps:
            previous = seen_apps.get(app)
            if previous:
                raise RegistryError(
                    f"Django app {app!r} is registered by both {previous!r} and "
                    f"{plugin.plugin_id!r}."
                )
            seen_apps[app] = plugin.plugin_id

    return tuple(plugins)


def iter_python_paths(plugins: Iterable[PluginSpec]) -> Iterable[Path]:
    for plugin in plugins:
        yield from plugin.python_paths
