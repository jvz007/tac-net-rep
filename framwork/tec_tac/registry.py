"""Tec-Tac plugin registry.

First-class plugin types use a shared extension ID:

* extensions/<extension-id>/
* reportsets/<extension-id>/

Each plugin directory contains a ``tec_tac.json`` manifest. The directory name
is the stable extension ID and the matching reportset must use the same ID.

Extensions may declare role-based permission groups in their manifest. Reportsets
do not own permissions.

The 0.5.x reporting POC predates this contract and remains registered as a
legacy compatibility plugin until its real extension ID is chosen.
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
SUPPORTED_TYPES = frozenset({"extension", "reportset"})
SUPPORTED_KEYS = frozenset({
    "id", "type", "version", "python_paths", "django_apps", "permission_groups",
    "dependencies", "optional_dependencies", "requires", "licensing",
})

class RegistryError(RuntimeError):
    """Raised when Tec-Tac plugin metadata is invalid."""

@dataclass(frozen=True)
class PluginSpec:
    plugin_id: str
    plugin_type: str
    root: Path
    version: str = "0.0.0"
    python_paths: tuple[Path, ...] = ()
    django_apps: tuple[str, ...] = ()
    permission_groups: tuple[tuple[str, tuple[str, ...]], ...] = ()
    legacy: bool = False

    def permission_group_map(self) -> dict[str, tuple[str, ...]]:
        return dict(self.permission_groups)

def _safe_name(value: str, label: str) -> str:
    value = value.strip()
    if not value:
        raise RegistryError(f"{label} must not be blank.")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if any(ch not in allowed for ch in value):
        raise RegistryError(f"Invalid {label.lower()}: {value!r}")
    return value

def _safe_plugin_id(value: str) -> str:
    return _safe_name(value, "Plugin ID")

def _string_list(payload: dict, key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    value = payload.get(key, list(default))
    if not isinstance(value, list):
        raise RegistryError(f"Manifest key {key!r} must be a JSON array.")
    result = tuple(str(item).strip() for item in value)
    if any(not item for item in result):
        raise RegistryError(f"Manifest key {key!r} contains a blank entry.")
    return result

def _permission_groups(payload: dict, plugin_type: str, plugin_id: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    raw = payload.get("permission_groups", {})
    if not isinstance(raw, dict):
        raise RegistryError("Manifest key 'permission_groups' must be a JSON object.")
    if plugin_type != "extension" and raw:
        raise RegistryError(f"Reportset {plugin_id!r} may not declare permission_groups; permissions belong to the extension.")
    groups = []
    for group_name, permissions in raw.items():
        name = _safe_name(str(group_name), "Permission group")
        if not isinstance(permissions, list) or not permissions:
            raise RegistryError(f"Permission group {name!r} must contain a non-empty JSON array.")
        values = tuple(str(item).strip() for item in permissions)
        if any(not item for item in values):
            raise RegistryError(f"Permission group {name!r} contains a blank permission.")
        if len(set(values)) != len(values):
            raise RegistryError(f"Permission group {name!r} contains duplicate permissions.")
        for codename in values:
            if len(codename) > 150:
                raise RegistryError(f"Permission codename exceeds 150 characters: {codename!r}")
            if not codename.startswith(plugin_id + "."):
                raise RegistryError(f"Permission {codename!r} must begin with the extension ID prefix {plugin_id + '.'!r}.")
        groups.append((name, values))
    return tuple(groups)

def _load_manifest(plugin_type: str, plugin_dir: Path) -> PluginSpec | None:
    if plugin_type not in SUPPORTED_TYPES:
        raise RegistryError(f"Unsupported plugin type: {plugin_type!r}")
    manifest_path = plugin_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Unable to read {manifest_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RegistryError(f"Plugin manifest must contain a JSON object: {manifest_path}")
    unknown = sorted(set(payload) - SUPPORTED_KEYS)
    if unknown:
        raise RegistryError(f"Plugin manifest contains unsupported keys {unknown!r}: {manifest_path}")
    plugin_id = _safe_plugin_id(str(payload.get("id", plugin_dir.name)))
    if plugin_id != plugin_dir.name:
        raise RegistryError(f"Plugin manifest ID {plugin_id!r} must match directory name {plugin_dir.name!r}: {manifest_path}")
    declared_type = str(payload.get("type", plugin_type)).strip()
    if declared_type != plugin_type:
        raise RegistryError(f"Plugin {plugin_id!r} declares type {declared_type!r}; expected {plugin_type!r}.")
    version = str(payload.get("version", "0.0.0")).strip()
    if not version:
        raise RegistryError(f"Plugin {plugin_id!r} version must not be blank.")
    raw_python_paths = _string_list(payload, "python_paths", (".",))
    python_paths = []
    plugin_root = plugin_dir.resolve()
    for item in raw_python_paths:
        path = (plugin_dir / item).resolve()
        try:
            path.relative_to(plugin_root)
        except ValueError as exc:
            raise RegistryError(f"Plugin {plugin_id!r} python path escapes its plugin root: {item!r}") from exc
        if not path.exists():
            raise RegistryError(f"Plugin {plugin_id!r} python path does not exist: {path}")
        python_paths.append(path)
    django_apps = _string_list(payload, "django_apps")
    permission_groups = _permission_groups(payload, plugin_type, plugin_id)
    return PluginSpec(plugin_id=plugin_id, plugin_type=plugin_type, root=plugin_root, version=version, python_paths=tuple(python_paths), django_apps=django_apps, permission_groups=permission_groups)

def _discover_root(plugin_type: str, root: Path) -> list[PluginSpec]:
    if not root.exists():
        return []
    if not root.is_dir():
        raise RegistryError(f"Tec-Tac {plugin_type} root is not a directory: {root}")
    plugins = []
    seen_ids = set()
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir() or child.name.startswith("."):
            continue
        spec = _load_manifest(plugin_type, child)
        if spec is None:
            continue
        if spec.plugin_id in seen_ids:
            raise RegistryError(f"Duplicate {plugin_type} ID discovered: {spec.plugin_id!r}.")
        seen_ids.add(spec.plugin_id)
        plugins.append(spec)
    return plugins

def _validate_pairs(extensions: Iterable[PluginSpec], reportsets: Iterable[PluginSpec]) -> None:
    extension_ids = {plugin.plugin_id for plugin in extensions}
    reportset_ids = {plugin.plugin_id for plugin in reportsets}
    orphan_reportsets = sorted(reportset_ids - extension_ids)
    if orphan_reportsets:
        raise RegistryError("Reportset(s) without matching extension: " + ", ".join(orphan_reportsets))
    missing_reportsets = sorted(extension_ids - reportset_ids)
    if missing_reportsets:
        raise RegistryError("Extension(s) without matching reportset: " + ", ".join(missing_reportsets))

def discover_plugins(extensions_root: Path | None = None, reportsets_root: Path | None = None) -> tuple[PluginSpec, ...]:
    extensions = _discover_root("extension", extensions_root or EXTENSIONS_ROOT)
    reportsets = _discover_root("reportset", reportsets_root or REPORTSETS_ROOT)
    _validate_pairs(extensions, reportsets)
    return tuple([*extensions, *reportsets])

def legacy_plugins() -> tuple[PluginSpec, ...]:
    legacy_root = EXTENSIONS_ROOT / "reporting"
    legacy_app = legacy_root / "tfdreporting"
    if not (legacy_app / "apps.py").is_file():
        return ()
    return (PluginSpec(plugin_id="legacy-reporting-poc", plugin_type="legacy", root=legacy_root.resolve(), version="0.5.x", python_paths=(legacy_root.resolve(),), django_apps=("tfdreporting.apps.TfdreportingConfig",), legacy=True),)

def get_plugins() -> tuple[PluginSpec, ...]:
    plugins = [*discover_plugins(), *legacy_plugins()]
    seen_apps = {}
    seen_identity = set()
    seen_permissions = {}
    for plugin in plugins:
        identity = (plugin.plugin_type, plugin.plugin_id)
        if identity in seen_identity:
            raise RegistryError(f"Duplicate plugin registration: {identity!r}")
        seen_identity.add(identity)
        for app in plugin.django_apps:
            previous = seen_apps.get(app)
            if previous:
                raise RegistryError(f"Django app {app!r} is registered by both {previous!r} and {plugin.plugin_id!r}.")
            seen_apps[app] = plugin.plugin_id
        if plugin.plugin_type == "extension":
            for _, permissions in plugin.permission_groups:
                for codename in permissions:
                    previous = seen_permissions.get(codename)
                    if previous and previous != plugin.plugin_id:
                        raise RegistryError(f"Permission {codename!r} is declared by both {previous!r} and {plugin.plugin_id!r}.")
                    seen_permissions[codename] = plugin.plugin_id
    return tuple(plugins)

def get_plugin(plugin_id: str, plugin_type: str | None = None) -> PluginSpec:
    matches = [plugin for plugin in get_plugins() if plugin.plugin_id == plugin_id and (plugin_type is None or plugin.plugin_type == plugin_type)]
    if not matches:
        qualifier = f" type={plugin_type!r}" if plugin_type else ""
        raise RegistryError(f"Plugin {plugin_id!r}{qualifier} was not found.")
    if len(matches) > 1:
        raise RegistryError(f"Plugin ID {plugin_id!r} matches multiple plugin types; specify a type.")
    return matches[0]

def iter_python_paths(plugins: Iterable[PluginSpec]) -> Iterable[Path]:
    for plugin in plugins:
        yield from plugin.python_paths
