"""Tec-Tac plugin registry.

First-class plugin types use a shared extension ID:

* extensions/<extension-id>/
* reportsets/<extension-id>/

Each plugin directory contains a ``tec_tac.json`` manifest. The directory name
is the stable extension ID. A reportset is optional; when present it must use the same ID.

Extensions may declare role-based permission groups in their manifest. Reportsets
do not own permissions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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
    "dependencies", "optional_dependencies", "requires", "licensing", "migration",
    "publisher_permissions", "name", "category", "audit_events", "replaces", "capabilities",
    # 1.17.16: ``routes`` {prefix, urlconf} lets Core serve a module's urls at /api/tfd/<prefix>/; ``description`` is a short plain text.
    "routes", "description",
    # 1.17.17: ``server_maintenance_actions`` lets a signed module register its own Core server-maintenance actions on install.
    "server_maintenance_actions",
})
# Object types core.resources can scope-check for the browser audit writer. Any other
# lowercase slug may be declared since 1.17.0, but carries no scope check (see docs/module-audit.md).
SCOPE_CHECKED_OBJECT_TYPES = ("client", "site", "agent")
AUDIT_EVENT_OBJECT_TYPES = SCOPE_CHECKED_OBJECT_TYPES  # alias kept for importers of the 1.16.0 name
AUDIT_EVENT_MAX_ENTRIES = 20
AUDIT_EVENT_MAX_ACTIONS = 20
CAPABILITY_MAX_ENTRIES = 200
_CAPABILITY_ID_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$")
ROUTE_PREFIX_MAX = 64
DESCRIPTION_MAX = 500
_ROUTE_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_URLCONF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_CAPABILITY_VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")

# 1.17.17: manifest key ``server_maintenance_actions`` (see docs/server-maintenance-capability.md, 'Registering from a module manifest').
SERVER_MAINTENANCE_ACTIONS_MAX = 16
SERVER_MAINTENANCE_EXECUTABLE_PREFIX = "server_maintenance/actions/"
SERVER_MAINTENANCE_REGISTER_PERMISSION = "server_maintenance.register"
_SM_ACTION_KEYS = frozenset({
    "id", "description", "permission", "executable", "argv", "parameters", "timeout_seconds", "success_exit_codes", "revision", "protected",
})
_SM_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SM_PARAMETER_TYPES = frozenset({"string", "integer", "boolean", "enum"})
_SM_MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60

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
    publisher_permissions: tuple[str, ...] = ()
    name: str = ""
    category: str = ""
    legacy: bool = False
    audit_events: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # AD-20 (1.17.9): the one core module this module replaces, and the public contracts it declares (id, X.Y.Z).
    # ``capabilities_declared`` tells an absent key from an empty one, so a core module cannot hide a contract.
    replaces: str = ""
    capabilities: tuple[tuple[str, str], ...] = ()
    capabilities_declared: bool = False
    # 1.17.16: the optional ``routes`` key (both empty when absent) and ``description`` (empty when absent).
    route_prefix: str = ""
    route_urlconf: str = ""
    description: str = ""
    # 1.17.17: the validated ``server_maintenance_actions`` entries (plain dicts, see ``_server_maintenance_actions``). Left out of
    # equality and hashing so a spec stays comparable and hashable.
    server_maintenance_actions: tuple = field(default=(), compare=False, repr=False)

    def capability_map(self) -> dict[str, str]:
        return dict(self.capabilities)

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



def _audit_events(payload: dict, plugin_type: str, plugin_id: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Parse the optional ``audit_events`` key: browser audit events a permissionless module declares."""
    if "audit_events" not in payload:
        return ()
    raw = payload["audit_events"]
    if plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare audit_events; audit events belong to the extension.")
    if not isinstance(raw, list):
        raise RegistryError("Manifest key 'audit_events' must be a JSON array.")
    if len(raw) > AUDIT_EVENT_MAX_ENTRIES:
        raise RegistryError(f"Manifest audit_events may not contain more than {AUDIT_EVENT_MAX_ENTRIES} entries.")
    from .audit import _CUSTOM_ACTION_RE, _OBJECT_TYPE_RE, STANDARD_ACTIONS
    entries = []
    seen_types = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise RegistryError("Manifest audit_events entries must be JSON objects.")
        unknown = sorted(set(entry) - {"object_type", "actions"})
        if unknown:
            raise RegistryError(f"Manifest audit_events entry contains unsupported keys {unknown!r}.")
        object_type = entry.get("object_type")
        if not isinstance(object_type, str) or not _OBJECT_TYPE_RE.fullmatch(object_type):
            raise RegistryError("Manifest audit_events object_type must be a lowercase slug up to 100 characters.")
        if object_type in seen_types:
            raise RegistryError(f"Manifest audit_events declares object_type {object_type!r} more than once.")
        seen_types.add(object_type)
        actions = entry.get("actions")
        if not isinstance(actions, list) or not actions:
            raise RegistryError(f"Manifest audit_events actions for {object_type!r} must be a non-empty JSON array.")
        if len(actions) > AUDIT_EVENT_MAX_ACTIONS:
            raise RegistryError(f"Manifest audit_events actions for {object_type!r} may not exceed {AUDIT_EVENT_MAX_ACTIONS}.")
        for action in actions:
            if not isinstance(action, str) or not (action in STANDARD_ACTIONS or _CUSTOM_ACTION_RE.fullmatch(action)):
                raise RegistryError(
                    f"Manifest audit_events action {action!r} must be a standard Tec-Tac audit action or custom:<slug>."
                )
        if len(set(actions)) != len(actions):
            raise RegistryError(f"Manifest audit_events actions for {object_type!r} contain duplicates.")
        entries.append((object_type, tuple(actions)))
    return tuple(entries)


def _publisher_permissions(payload: dict, plugin_type: str, plugin_id: str) -> tuple[str, ...]:
    raw = payload.get("publisher_permissions") or []
    if not isinstance(raw, list) or any(not isinstance(value, str) or not value.strip() for value in raw):
        raise RegistryError("Manifest publisher_permissions must be an array of non-empty strings.")
    if plugin_type != "extension" and raw:
        raise RegistryError(f"Reportset {plugin_id!r} may not declare publisher_permissions.")
    values = tuple(value.strip() for value in raw)
    if len(set(values)) != len(values):
        raise RegistryError("Manifest publisher_permissions contains duplicates.")
    allowed = {"module.install", "server_maintenance.register"}
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise RegistryError(f"Manifest publisher_permissions contains unsupported permission(s): {unknown!r}.")
    return values


def _sm_parameters(schema, label: str) -> dict:
    """The typed parameter schema of one server-maintenance action: the rules the root helper applies again (validate_manifest)."""
    if not isinstance(schema, dict) or len(schema) > 64:
        raise RegistryError(f"{label} parameters must be an object with at most 64 entries.")
    for name, spec in schema.items():
        if not isinstance(name, str) or not _SM_ACTION_ID_RE.fullmatch(name):
            raise RegistryError(f"{label} parameter name {name!r} is invalid.")
        if not isinstance(spec, dict):
            raise RegistryError(f"{label} parameter {name!r} schema must be an object.")
        ptype = spec.get("type", "string")
        if ptype not in _SM_PARAMETER_TYPES:
            raise RegistryError(f"{label} parameter {name!r} has an unsupported type (string, integer, boolean or enum).")
        if ptype == "enum" and (not isinstance(spec.get("choices"), list) or not spec["choices"]):
            raise RegistryError(f"{label} enum parameter {name!r} requires choices.")
        if "pattern" in spec:
            try:
                re.compile(str(spec["pattern"]))
            except re.error as exc:
                raise RegistryError(f"{label} parameter {name!r} has an invalid pattern.") from exc
    return schema


def _server_maintenance_actions(payload: dict, plugin_type: str, plugin_id: str, plugin_dir: Path,
                                permission_groups, publisher_permissions) -> tuple[dict, ...]:
    """Parse the optional ``server_maintenance_actions`` key (1.17.17): the Core server-maintenance actions a signed module registers.

    Each entry is ``{id, description, permission, executable, argv, parameters, timeout_seconds, success_exit_codes, revision}``
    (and ``protected``: true, which keeps an action out of automatic registration). Extensions only, at most 16 entries. Rules:
    ``id`` starts with ``<module_id>.`` and is unique; ``permission`` is required and is one the same module declares in
    ``permission_groups``; ``executable`` is a path below the module's ``server_maintenance/actions/`` folder (relative, no ``..``,
    no symlink, an existing file); ``argv`` and ``parameters`` follow the root helper's typed rules (no shell text: argv entries are
    literal strings or ``{"param": name}``); the module must also declare publisher_permissions ``server_maintenance.register``,
    the AD-10 gate. The root helper checks the same rules again from the root-owned installed manifest. Returns plain dicts, or ``()``
    when the key is absent."""
    if "server_maintenance_actions" not in payload:
        return ()
    raw = payload["server_maintenance_actions"]
    if plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare server_maintenance_actions; they belong to the extension.")
    if not isinstance(raw, list):
        raise RegistryError("Manifest key 'server_maintenance_actions' must be a JSON array.")
    if len(raw) > SERVER_MAINTENANCE_ACTIONS_MAX:
        raise RegistryError(f"Manifest server_maintenance_actions may not contain more than {SERVER_MAINTENANCE_ACTIONS_MAX} entries.")
    if not raw:
        return ()
    if SERVER_MAINTENANCE_REGISTER_PERMISSION not in publisher_permissions:
        raise RegistryError(
            f"Module {plugin_id!r} declares server_maintenance_actions and must also declare publisher_permissions "
            f"{SERVER_MAINTENANCE_REGISTER_PERMISSION!r}: the publisher that signs it must hold that permission (AD-10)."
        )
    declared_permissions = {code for _, codes in permission_groups for code in codes}
    entries, seen = [], set()
    for index, entry in enumerate(raw):
        label = f"Manifest server_maintenance_actions entry {index + 1}"
        if not isinstance(entry, dict):
            raise RegistryError(f"{label} must be a JSON object.")
        unknown = sorted(set(entry) - _SM_ACTION_KEYS)
        if unknown:
            raise RegistryError(f"{label} contains unsupported keys {unknown!r}.")
        action_id = entry.get("id")
        if not isinstance(action_id, str) or not _SM_ACTION_ID_RE.fullmatch(action_id):
            raise RegistryError(f"{label} id must be letters, digits, '.', '_' or '-' (1 to 128 characters).")
        if not action_id.startswith(plugin_id + ".") or action_id == plugin_id + ".":
            raise RegistryError(f"Server-maintenance action id {action_id!r} must begin with the module ID prefix {plugin_id + '.'!r}.")
        if action_id in seen:
            raise RegistryError(f"Manifest server_maintenance_actions declares {action_id!r} more than once.")
        seen.add(action_id)
        label = f"Server-maintenance action {action_id!r}"
        permission = entry.get("permission")
        if not isinstance(permission, str) or permission not in declared_permissions:
            raise RegistryError(f"{label} needs a permission that this module declares in permission_groups.")
        executable = entry.get("executable")
        if not isinstance(executable, str) or not executable or "\x00" in executable or "\\" in executable or executable.startswith("/"):
            raise RegistryError(f"{label} executable must be a relative path inside the module folder.")
        parts = executable.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise RegistryError(f"{label} executable may not contain empty, '.' or '..' path parts.")
        if not executable.startswith(SERVER_MAINTENANCE_EXECUTABLE_PREFIX) or len(parts) < 3:
            raise RegistryError(f"{label} executable must be a file below {SERVER_MAINTENANCE_EXECUTABLE_PREFIX!r} in the module folder.")
        current = plugin_dir
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise RegistryError(f"{label} executable may not use a symlink.")
        if not current.is_file():
            raise RegistryError(f"{label} executable {executable!r} does not exist in the module folder.")
        schema = _sm_parameters(entry.get("parameters", {}), label)
        argv = entry.get("argv", [])
        if not isinstance(argv, list) or len(argv) > 64:
            raise RegistryError(f"{label} argv must be an array with at most 64 entries.")
        for item in argv:
            if isinstance(item, str):
                if "\x00" in item or len(item) > 4096:
                    raise RegistryError(f"{label} has an invalid literal argv entry.")
            elif not (isinstance(item, dict) and set(item) == {"param"} and isinstance(item["param"], str) and item["param"] in schema):
                raise RegistryError(f"{label} argv entries must be literal strings or {{'param': '<declared parameter>'}}; no shell text.")
        timeout = entry.get("timeout_seconds", 3600)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1 or timeout > _SM_MAX_TIMEOUT_SECONDS:
            raise RegistryError(f"{label} timeout_seconds must be a whole number from 1 to {_SM_MAX_TIMEOUT_SECONDS}.")
        codes = entry.get("success_exit_codes", [0])
        if not isinstance(codes, list) or not codes or any(isinstance(code, bool) or not isinstance(code, int) for code in codes):
            raise RegistryError(f"{label} success_exit_codes must be a non-empty array of whole numbers.")
        description = entry.get("description", "")
        if not isinstance(description, str) or len(description) > DESCRIPTION_MAX or any(ord(ch) < 32 or ord(ch) == 127 for ch in description):
            raise RegistryError(f"{label} description must be plain text of up to {DESCRIPTION_MAX} characters.")
        revision = entry.get("revision", "1")
        if isinstance(revision, bool) or not isinstance(revision, (str, int)) or not str(revision).strip() or len(str(revision)) > 64:
            raise RegistryError(f"{label} revision must be a short text or whole number.")
        protected = entry.get("protected", False)
        if not isinstance(protected, bool):
            raise RegistryError(f"{label} protected must be true or false.")
        entries.append({
            "id": action_id, "description": description.strip(), "permission": permission, "executable": executable, "argv": list(argv),
            "parameters": dict(schema), "timeout_seconds": timeout, "success_exit_codes": list(codes), "revision": str(revision).strip(),
            "protected": protected,
        })
    return tuple(entries)


def _replacement_keys(payload: dict, plugin_type: str, plugin_id: str, category: str) -> tuple[str, tuple[tuple[str, str], ...], bool]:
    """Parse the optional AD-20 keys ``replaces`` and ``capabilities`` (extensions only).

    ``replaces`` names one core or server module (1.17.11). It is refused on a core or server module and on the module
    itself. Whether the target is installed and is a core or server module is checked where the installed set is known
    (module_replacement.py), not here.
    ``capabilities`` maps a capability id to an X.Y.Z version: the public contracts the module publishes, declared
    statically because a disabled module's code is never loaded.
    """
    has_replaces, has_caps = "replaces" in payload, "capabilities" in payload
    if not (has_replaces or has_caps):
        return "", (), False
    if plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare replaces or capabilities; they belong to the extension.")
    replaces = ""
    if has_replaces:
        raw = payload["replaces"]
        if not isinstance(raw, str) or not raw.strip():
            raise RegistryError("Manifest key 'replaces' must be the ID of one core module.")
        replaces = _safe_plugin_id(raw)
        if replaces == plugin_id:
            raise RegistryError(f"Plugin {plugin_id!r} may not replace itself.")
        if category in ("core", "server"):
            raise RegistryError(f"Module {plugin_id!r} is a {category} module and may not declare replaces; only a module that is neither a core nor a server module can replace one.")
        if category == "test":
            raise RegistryError(f"Module {plugin_id!r} is a test module and may not declare replaces. A replacement is a premium module (AD-21).")
    capabilities: list[tuple[str, str]] = []
    if has_caps:
        raw = payload["capabilities"]
        if not isinstance(raw, dict):
            raise RegistryError("Manifest key 'capabilities' must be a JSON object of capability id to X.Y.Z version.")
        if len(raw) > CAPABILITY_MAX_ENTRIES:
            raise RegistryError(f"Manifest capabilities may not contain more than {CAPABILITY_MAX_ENTRIES} entries.")
        for cap_id, cap_version in raw.items():
            if not isinstance(cap_id, str) or not _CAPABILITY_ID_RE.match(cap_id):
                raise RegistryError(f"Manifest capabilities id {cap_id!r} must be a namespaced id such as patching.windows.")
            if not isinstance(cap_version, str) or not _CAPABILITY_VERSION_RE.match(cap_version):
                raise RegistryError(f"Manifest capabilities version for {cap_id!r} must look like 1.0.0.")
            if category in ("core", "server") and not cap_id.startswith(plugin_id + "."):
                raise RegistryError(f"Capability {cap_id!r} must begin with the {category} module ID prefix {plugin_id + '.'!r}.")
            capabilities.append((cap_id, cap_version))
    return replaces, tuple(sorted(capabilities)), has_caps


def app_packages(django_apps: Iterable[str]) -> tuple[str, ...]:
    """The Python package each ``django_apps`` entry lives in: ``pkg.apps.PkgConfig`` and ``pkg.apps`` give ``pkg``; a plain
    ``pkg`` gives ``pkg``. Used to keep a module's ``routes.urlconf`` inside its own code."""
    packages = []
    for entry in django_apps:
        parts = str(entry).split(".")
        if len(parts) > 1 and parts[-1][:1].isupper():
            parts = parts[:-1]
        if len(parts) > 1 and parts[-1] == "apps":
            parts = parts[:-1]
        if parts and all(parts):
            packages.append(".".join(parts))
    return tuple(packages)


def _route_keys(payload: dict, plugin_type: str, plugin_id: str, django_apps: Iterable[str] = ()) -> tuple[str, str]:
    """Parse the optional ``routes`` key (1.17.16): ``{"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}``.

    Core serves the urlconf at /api/tfd/<prefix>/. ``prefix`` is one lowercase slug (letters a-z, digits, ``_`` and ``-``) and
    defaults to the module id. ``urlconf`` is required and must sit inside one of the module's own ``django_apps`` packages,
    never tacticalrmm, tec_tac or another module. Extensions only. Returns ``(prefix, urlconf)``, or ``("", "")`` when the key
    is absent. Whether two modules ask for the same prefix is judged where the loaded set is known (route_mounting.py)."""
    if "routes" not in payload:
        return "", ""
    raw = payload["routes"]
    if plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare routes; routes belong to the extension.")
    if not isinstance(raw, dict):
        raise RegistryError("Manifest key 'routes' must be a JSON object with 'prefix' and 'urlconf'.")
    unknown = sorted(set(raw) - {"prefix", "urlconf"})
    if unknown:
        raise RegistryError(f"Manifest routes contains unsupported keys {unknown!r}.")
    urlconf = raw.get("urlconf")
    if not isinstance(urlconf, str) or not _URLCONF_RE.fullmatch(urlconf):
        raise RegistryError("Manifest routes.urlconf must be a dotted Python module path such as tec_tac_patching.urls.")
    prefix = raw.get("prefix")
    if prefix is None:
        # The module id is the default prefix, as the modules that add their own routes use it today.
        prefix = plugin_id
    elif not isinstance(prefix, str) or not _ROUTE_PREFIX_RE.fullmatch(prefix):
        raise RegistryError(
            "Manifest routes.prefix must be one lowercase slug of up to 64 characters (a-z, 0-9, '_' and '-'), with no slash."
        )
    first = urlconf.split(".")[0]
    if first in ("tacticalrmm", "tec_tac") or urlconf.startswith("tec_tac."):
        raise RegistryError("Manifest routes.urlconf may not point into tacticalrmm or tec_tac.")
    packages = app_packages(django_apps)
    if not packages:
        raise RegistryError("Manifest routes needs django_apps: the urlconf must sit inside one of the module's own Django apps.")
    if not any(urlconf == package or urlconf.startswith(package + ".") for package in packages):
        raise RegistryError(
            f"Manifest routes.urlconf {urlconf!r} must sit inside one of the module's own django_apps packages ({', '.join(packages)})."
        )
    return prefix, urlconf


def _description(payload: dict, plugin_id: str) -> str:
    """Parse the optional ``description`` key (1.17.16): a plain string of 1 to 500 characters with no control characters."""
    if "description" not in payload:
        return ""
    raw = payload["description"]
    if not isinstance(raw, str) or not raw.strip():
        raise RegistryError(f"Plugin {plugin_id!r} description must be a non-empty string.")
    text = raw.strip()
    if len(text) > DESCRIPTION_MAX:
        raise RegistryError(f"Plugin {plugin_id!r} description may not be longer than {DESCRIPTION_MAX} characters.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise RegistryError(f"Plugin {plugin_id!r} description may not contain control characters.")
    return text


def _identity_migration(payload: dict, plugin_type: str, plugin_id: str) -> dict:
    raw = payload.get("migration")
    if raw in (None, {}):
        return {}
    if plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare migration metadata; identity migration belongs to the extension.")
    if not isinstance(raw, dict):
        raise RegistryError("Manifest key 'migration' must be a JSON object.")
    allowed = {"previous_module_ids", "permissions", "scheduler_actions", "ui_routes", "dashboard_widgets"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RegistryError(f"Manifest migration contains unsupported keys {unknown!r}.")
    previous = raw.get("previous_module_ids") or []
    if not isinstance(previous, list) or not previous:
        raise RegistryError("Manifest migration.previous_module_ids must be a non-empty JSON array.")
    values = tuple(_safe_plugin_id(str(item)) for item in previous)
    if len(set(values)) != len(values):
        raise RegistryError("Manifest migration.previous_module_ids contains duplicates.")
    if plugin_id in values:
        raise RegistryError("Manifest migration.previous_module_ids may not contain the current module ID.")
    for key in ("permissions", "scheduler_actions", "ui_routes", "dashboard_widgets"):
        mapping = raw.get(key) or {}
        if not isinstance(mapping, dict):
            raise RegistryError(f"Manifest migration.{key} must be a JSON object.")
        for old, new in mapping.items():
            if not isinstance(old, str) or not old.strip() or not isinstance(new, str) or not new.strip():
                raise RegistryError(f"Manifest migration.{key} must map non-empty strings to non-empty strings.")
    return raw

def _load_manifest(plugin_type: str, plugin_dir: Path) -> PluginSpec | None:
    if plugin_type not in SUPPORTED_TYPES:
        raise RegistryError(f"Unsupported plugin type: {plugin_type!r}")
    manifest_path = plugin_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return None
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    _identity_migration(payload, plugin_type, plugin_id)
    version = str(payload.get("version", "0.0.0")).strip()
    if not version:
        raise RegistryError(f"Plugin {plugin_id!r} version must not be blank.")
    raw_name = payload.get("name", plugin_id)
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise RegistryError(f"Plugin {plugin_id!r} name must be a non-empty string.")
    name = raw_name.strip()
    raw_category = payload.get("category", "")
    if not isinstance(raw_category, str):
        raise RegistryError(f"Plugin {plugin_id!r} category must be a string.")
    category = raw_category.strip().lower()
    if category and plugin_type != "extension":
        raise RegistryError(f"Reportset {plugin_id!r} may not declare category metadata.")
    if category not in {"", "core", "server", "premium", "test"}:
        raise RegistryError(f"Plugin {plugin_id!r} category must be 'core', 'server', 'premium' or 'test' when provided.")
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
    publisher_permissions = _publisher_permissions(payload, plugin_type, plugin_id)
    audit_events = _audit_events(payload, plugin_type, plugin_id)
    replaces, capabilities, capabilities_declared = _replacement_keys(payload, plugin_type, plugin_id, category)
    route_prefix, route_urlconf = _route_keys(payload, plugin_type, plugin_id, django_apps)
    description = _description(payload, plugin_id)
    server_maintenance_actions = _server_maintenance_actions(payload, plugin_type, plugin_id, plugin_dir, permission_groups, publisher_permissions)
    return PluginSpec(plugin_id=plugin_id, plugin_type=plugin_type, root=plugin_root, version=version, python_paths=tuple(python_paths), django_apps=django_apps, permission_groups=permission_groups, publisher_permissions=publisher_permissions, name=name, category=category, audit_events=audit_events, replaces=replaces, capabilities=capabilities, capabilities_declared=capabilities_declared, route_prefix=route_prefix, route_urlconf=route_urlconf, description=description, server_maintenance_actions=server_maintenance_actions)

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
    """Validate optional reportset ownership.

    Every reportset must belong to an installed extension, but an extension does
    not need a reportset. This keeps reporting optional for operational modules
    such as Notifications while still rejecting orphan reportset code.
    """
    extension_ids = {plugin.plugin_id for plugin in extensions}
    reportset_ids = {plugin.plugin_id for plugin in reportsets}
    orphan_reportsets = sorted(reportset_ids - extension_ids)
    if orphan_reportsets:
        raise RegistryError("Reportset(s) without matching extension: " + ", ".join(orphan_reportsets))

def discover_plugins(extensions_root: Path | None = None, reportsets_root: Path | None = None) -> tuple[PluginSpec, ...]:
    extensions = _discover_root("extension", extensions_root or EXTENSIONS_ROOT)
    reportsets = _discover_root("reportset", reportsets_root or REPORTSETS_ROOT)
    _validate_pairs(extensions, reportsets)
    return tuple([*extensions, *reportsets])

def get_plugins() -> tuple[PluginSpec, ...]:
    plugins = [*discover_plugins()]
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
