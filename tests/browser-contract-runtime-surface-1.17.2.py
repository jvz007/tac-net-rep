#!/usr/bin/env python3
"""1.17.2: the browser contract catalog lists everything register(context) provides."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
source = PATH.read_text(encoding="utf-8")
tree = ast.parse(source)

assignment = next(
    node for node in tree.body
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BROWSER_CONTRACTS" for t in node.targets)
)
rows = ast.literal_eval(assignment.value)
by_id = {row["id"]: row for row in rows}
ids = [row["id"] for row in rows]
assert len(ids) == len(set(ids)), "duplicate browser contract ids"
for new in ("ui.authenticated.navigation", "ui.authenticated.router", "ui.authenticated.permissions"):
    assert new in by_id, new
for row in rows:
    assert row["docs"].startswith("tec-tac-ui/docs/"), row["id"]
    assert "details" not in row or (isinstance(row["details"], list) and all(isinstance(x, str) and x for x in row["details"])), row["id"]


def details(row_id):
    return " ".join(by_id[row_id].get("details", []))


transport = details("ui.authenticated.transport")
for needle in ("status", "is 0 when no response arrived", "401", "payload", "no body alias", "code", "rejectErrorPayload", "apiRaw, apiBlob and apiText never do", "204", "publicApi"):
    assert needle in transport, f"transport details lack {needle!r}"

runtime = by_id["ui.authenticated.runtime-context"]
assert "server_url" in runtime["operations"] and "module_register_timeout_seconds" in runtime["operations"]
runtime_text = details("ui.authenticated.runtime-context")
assert "server_url" in runtime_text and "trailing slash" in runtime_text and "module_register_timeout_seconds" in runtime_text
assert "5 to 300" in runtime_text and "default 30" in runtime_text and "entry file" in runtime_text

navigation = details("ui.authenticated.navigation")
assert "permission" in navigation and "permissions" in navigation and "Superusers always see it" in navigation and "display rule only" in navigation.lower()
assert "abandoned" in navigation and "backend supplied no context" in navigation and "gated item is hidden" in navigation

router = details("ui.authenticated.router")
assert "addRoute(route)" in router and "addRoute(parentName, route)" in router and "meta.dynamicModule" in router and "remover" in router and "abandoned" in router and "through unchanged" in router

permissions = details("ui.authenticated.permissions")
assert "superuser" in permissions and "effective permission set" in permissions and "Display only" in permissions
assert by_id["ui.authenticated.permissions"]["operations"] == ["hasPermission"]

assert {"openContext", "list"} <= set(by_id["ui.authenticated.help"]["operations"])
assert "languages" in by_id["ui.authenticated.code-editor"]["operations"]
assert {"has", "isActive", "version", "satisfies"} <= set(by_id["ui.authenticated.module-status"]["operations"])

functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only extraction of the renderers
catalog = {
    "framework_version": "1.17.2", "generated_at": "2026-10-08T00:00:00+00:00", "rules": [], "core": [],
    "browser": list(rows), "resource_directory": {}, "capabilities": [], "scheduler_actions": [],
    "permissions": [], "reporting_models": [], "http": [],
}
md = ns["render_markdown"](catalog)
txt = ns["render_text"](catalog)
for row in rows:
    for line in row.get("details", []):
        assert line in md, (row["id"], line)
        assert line in txt, (row["id"], line)
# A catalog without details still renders.
plain = dict(catalog, browser=[{k: v for k, v in r.items() if k != "details"} for r in rows])
assert "rejectErrorPayload" not in ns["render_markdown"](plain)
print("[TEST] PASS 1.17.2 browser contract catalog lists the module runtime surface")
