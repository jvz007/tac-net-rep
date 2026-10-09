#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import ast
import json
import tempfile
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


api = load_module("openapi178", ROOT / "framwork" / "tec_tac" / "openapi.py")
registry = load_module("registry178", ROOT / "framwork" / "tec_tac" / "registry.py")


def must(value, message):
    if not value:
        raise AssertionError(message)


# Registry accepts the F11 identity metadata and keeps backward compatibility.
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "demo"
    root.mkdir()
    (root / "tec_tac.json").write_text(json.dumps({
        "id": "demo",
        "type": "extension",
        "version": "1.0.0",
        "name": "Demo Core",
        "category": "core",
        "python_paths": ["."],
        "django_apps": ["demo_app.apps.DemoConfig"],
    }), encoding="utf-8")
    spec = registry._load_manifest("extension", root)
    must(spec.name == "Demo Core", "manifest display name not retained")
    must(spec.category == "core", "manifest category not retained")

    (root / "tec_tac.json").write_text(json.dumps({
        "id": "demo", "type": "extension", "version": "1.0.0", "python_paths": ["."]
    }), encoding="utf-8")
    legacy = registry._load_manifest("extension", root)
    must(legacy.name == "demo" and legacy.category == "", "legacy manifest compatibility broke")

    bad = json.loads((root / "tec_tac.json").read_text())
    bad["category"] = "bogus"  # premium and test are accepted since 1.17.13
    (root / "tec_tac.json").write_text(json.dumps(bad), encoding="utf-8")
    try:
        registry._load_manifest("extension", root)
    except registry.RegistryError:
        pass
    else:
        raise AssertionError("unsupported manifest category was accepted")


core_module = SimpleNamespace(
    plugin_id="globalsettings",
    plugin_type="extension",
    name="Global Settings",
    category="core",
    django_apps=("tec_tac_globalsettings.apps.GlobalSettingsConfig",),
)
audit_module = SimpleNamespace(
    plugin_id="audit",
    plugin_type="extension",
    name="Audit",
    category="",
    django_apps=("tec_tac_audit.apps.AuditConfig",),
)
normal_module = SimpleNamespace(
    plugin_id="serverhealth",
    plugin_type="extension",
    name="Server Health",
    category="",
    django_apps=("tec_tac_serverhealth.apps.ServerHealthConfig",),
)


def callback(module, name):
    cls = type(name, (), {})
    cls.__module__ = module
    return SimpleNamespace(cls=cls)


# Every Core route currently mounted by tec_tac.urls has an explicit callback
# classification. This is the no-catch-all coverage guard: adding a new Core
# view without assigning a group fails this test.
urls_source = (ROOT / "framwork" / "tec_tac" / "urls.py").read_text(encoding="utf-8")
urls_tree = ast.parse(urls_source)
class_modules = {}
for node in urls_tree.body:
    if isinstance(node, ast.ImportFrom) and node.module:
        module_name = "tec_tac." + node.module.lstrip(".")
        for alias in node.names:
            class_modules[alias.asname or alias.name] = module_name
route_classes = []
for node in ast.walk(urls_tree):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "path" or len(node.args) < 2:
        continue
    view = node.args[1]
    if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == "as_view" and isinstance(view.func.value, ast.Name):
        route_classes.append(view.func.value.id)
missing = []
for class_name in sorted(set(route_classes)):
    module_name = class_modules.get(class_name)
    if not module_name:
        missing.append(f"{class_name}: import owner unknown")
        continue
    cb = callback(module_name, class_name)
    if api.core_group_for_callback(cb) is None:
        missing.append(f"{class_name}: {module_name}")
must(not missing, "unclassified current Core route callback(s): " + ", ".join(missing))

generator = SimpleNamespace(endpoints=[
    ("/api/tfd/audit/events/", "", "GET", callback("tec_tac_audit.views", "AuditEventView")),
    ("/api/tfd/globalsettings/sso/", "", "GET", callback("tec_tac_globalsettings.views", "SsoView")),
    ("/api/tfd/server-health/", "", "GET", callback("tec_tac_serverhealth.views", "ServerHealthView")),
    ("/api/tfd/system/updates/", "", "GET", callback("tec_tac.views", "SystemUpdateStatusView")),
    ("/api/tfd/system/backups/restore/", "", "POST", callback("tec_tac.server_backup_views", "BackupRestoreView")),
    ("/api/tfd/system/maintenance/actions/", "", "GET", callback("tec_tac.server_maintenance_views", "ServerMaintenanceActionListView")),
    ("/api/tfd/system/storage/", "", "GET", callback("tec_tac.housekeeping_views", "HousekeepingStatusView")),
    ("/api/tfd/modules/repositories/", "", "GET", callback("tec_tac.module_repository_views", "ModuleRepositoryListView")),
    ("/api/tfd/modules/hotfixes/inspect/", "", "POST", callback("tec_tac.module_hotfix_views", "ModuleHotfixInspectView")),
    ("/api/tfd/account/", "", "GET", callback("tec_tac.account_self_service_views", "MyAccountView")),
    ("/api/tfd/future-core/", "", "GET", callback("tec_tac.future_views", "FutureView")),
])

api.registered_module_specs = lambda: (core_module, audit_module, normal_module)
schema = {
    "tags": [{"name": "Agents"}, {"name": "Tec-Tac · Framework"}],
    "paths": {
        "/api/tfd/audit/events/": {"get": {"tags": ["old"]}},
        "/api/tfd/globalsettings/sso/": {"get": {"tags": ["old"]}},
        "/api/tfd/server-health/": {"get": {"tags": ["old"]}},
        "/api/tfd/system/updates/": {"get": {"tags": ["old"]}},
        "/api/tfd/system/backups/restore/": {"post": {"tags": ["old"]}},
        "/api/tfd/system/maintenance/actions/": {"get": {"tags": ["old"]}},
        "/api/tfd/system/storage/": {"get": {"tags": ["old"]}},
        "/api/tfd/modules/repositories/": {"get": {"tags": ["old"]}},
        "/api/tfd/modules/hotfixes/inspect/": {"post": {"tags": ["old"]}},
        "/api/tfd/account/": {"get": {"tags": ["old"]}},
        "/api/tfd/future-core/": {"get": {"tags": ["old"]}},
        "/api/v3/agents/": {"get": {"tags": ["Agents"]}},
    },
}
out = api.postprocess_tec_tac_groups(schema, generator=generator)

expected = {
    ("/api/tfd/audit/events/", "get"): "Module · Audit",
    ("/api/tfd/globalsettings/sso/", "get"): "Core module · Global Settings",
    ("/api/tfd/server-health/", "get"): "Module · Server Health",
    ("/api/tfd/system/updates/", "get"): "Tec-Tac · System Updates",
    ("/api/tfd/system/backups/restore/", "post"): "Tec-Tac · Backup & Restore",
    ("/api/tfd/system/maintenance/actions/", "get"): "Tec-Tac · Server Maintenance",
    ("/api/tfd/system/storage/", "get"): "Tec-Tac · Storage",
    ("/api/tfd/modules/repositories/", "get"): "Tec-Tac · Module Repository",
    ("/api/tfd/modules/hotfixes/inspect/", "post"): "Tec-Tac · Module Hotfixes",
    ("/api/tfd/account/", "get"): "Tec-Tac · My Account",
}
for (path, method), group in expected.items():
    must(out["paths"][path][method]["tags"] == [group], f"wrong group for {method.upper()} {path}")

# Unknown future Core callbacks are NOT silently sent to a Framework bucket.
must(out["paths"]["/api/tfd/future-core/"]["get"]["tags"] == ["old"], "unknown Core route was hidden in a catch-all")

# Native Tactical is untouched and stale managed tags are rebuilt.
must(out["paths"]["/api/v3/agents/"]["get"]["tags"] == ["Agents"], "native Tactical tags changed")
tag_names = {row["name"] for row in out["tags"]}
must("Tec-Tac · Framework" not in tag_names, "Framework catch-all survived")
must("Agents" in tag_names, "native Tactical top-level tag disappeared")
for group in expected.values():
    must(group in tag_names, f"missing top-level group {group}")

print("[TEST] PASS F11 final OpenAPI ownership/grouping and manifest metadata")
