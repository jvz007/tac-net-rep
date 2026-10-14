#!/usr/bin/env python3
"""1.17.32: browser contract rows owed to the UI (reviews/requests/core.md, UI 0.12.97 to 0.12.102), documentation only.

Adds ui.authenticated.websocket (Tactical terminal socket, UI 0.12.102) and ui.authenticated.services (UI 0.12.101 and 0.12.102), and
extends the rows header (popoverTarget, UI 0.12.101), runtime-context (user.id, UI 0.12.101), popup (popupPublishers, the route-path rule,
the console warnings and forModule, UI 0.12.97), navigation (tacticalPermission, UI 0.12.99) and context-actions (the right-click menu,
UI 0.12.99). The wording is taken from workspace/ui/docs. No row changes a value that a module consumes.

Covered: ids are unique; every docs value is a plain tec-tac-ui/docs/*.md path; the websocket row names every operation, event, close code
with its message, the ticket route with its body and answer, every refusal code, the 30 second single-use ticket, the bound-module rule,
UI 0.12.102 and Core 1.17.31; the services row names provide, has, call and list, the name rule, the permission rules, the one-permission
rule with its text, and the refusal codes; the other rows name the new keys; the real render_markdown and render_text carry every row and
no docs cell holds a space or a parenthesis. contracts.py needs Django, so the tables are read with ast and the two render functions are
exec'd from the same tree, as in tests/browser-contract-popup-confirm-1.17.23.py. The existing contract tests run unchanged.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))
PATTERN = re.compile(r"^tec-tac-ui/docs/[A-Za-z0-9._-]+\.md$")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
by_id = {r["id"]: r for r in BROWSER}
must(len(by_id) == len(BROWSER), "ids are unique")


def details(row_id):
    must(row_id in by_id, f"row {row_id} exists")
    return " ".join(by_id[row_id].get("details", []))


def check(row_id, needles):
    text = details(row_id) + " " + by_id[row_id].get("purpose", "") + " " + " ".join(by_id[row_id].get("operations", []))
    for needle in needles:
        must(needle in text, f"{row_id} names {needle!r}")


for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")

# ------------------------------------------------------------------------------------------------ the websocket row
websocket = by_id.get("ui.authenticated.websocket", {})
must(websocket.get("phase") == "authenticated" and websocket.get("service") == "tacticalWebSocket", "websocket row is authenticated tacticalWebSocket")
must(websocket.get("docs") == "tec-tac-ui/docs/module-tactical-websocket.md", "websocket docs path")
check("ui.authenticated.websocket", [
    "open", "session.start", "session.input", "session.resize", "session.kill", "session.close", "session.on",
    "output", "error", "info", "close", "trmmcli.output", "terminal_error", "terminal_info", "unknown_action",
    "4401", "signin-ended", "Your terminal session ended. Open the terminal again.",
    "4003", "not-allowed", "You are not allowed to use the terminal on this endpoint.",
    "4503", "unavailable", "Tactical's terminal is not available right now. Try again later.",
    "1000", "normal", "The terminal closed.", "unexpected", "The terminal connection closed unexpectedly.",
    "POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/", "{agent_id}",
    "{ticket, path, session_id, expires_in, kind}", "/ws/tfd/agent-terminal/<ticket>/",
    "invalid_agent_id", "authenticated_request_required", "tactical_session_required", "websocket_owner_required",
    "tactical_permission_denied", "can_use_terminal", "object_not_found", "websocket_kind_not_found", "throttle",
    "websocket_unavailable", "30 seconds", "works once", "is asked for each terminal tab",
    "Bound-module rule", "AD-20", "registerPublic", "8 terminals", "no reconnect",
    "0.12.102", "1.17.31",
])
must("0.12.102" in websocket["purpose"] and "1.17.31" in websocket["purpose"], "websocket purpose names UI 0.12.102 and Core 1.17.31")

# ------------------------------------------------------------------------------------------------ the services row
services = by_id.get("ui.authenticated.services", {})
must(services.get("phase") == "authenticated" and services.get("service") == "services", "services row is authenticated services")
must(services.get("operations") == ["provide", "has", "call", "list"], "services row lists provide, has, call and list")
must(services.get("docs") == "tec-tac-ui/docs/module-services.md", "services docs path")
check("ui.authenticated.services", [
    "provide(name, handler, {label, permission, permissions, tacticalPermission})", "module id and a dot", "120 characters",
    "letters, digits, '.', '_' and '-'", "permission or permissions can only narrow", "strictly true", "caller",
    "at least one permission", "Service <name> needs at least one permission: declare one for the module or for this service.",
    "registers nothing", "AD-12", "service_denied", "service_unavailable", "from <provider> failed",
    "removed when its register() fails", "UI 0.12.101", "UI 0.12.102",
])

# ------------------------------------------------------------------------------------------------ the other rows
check("ui.authenticated.header", ["popoverTarget", "#tec-tac-popover-layer", "UI 0.12.101", "Teleport", "not rendered in a popup window"])
check("ui.authenticated.runtime-context", ["user.id", "whole number of at least 1", "Tactical's own user primary key", "UI 0.12.101"])
check("ui.authenticated.popup", [
    "route.meta.popupPublishers", "true, or an array of module ids", "UI 0.12.97", "forModule(moduleId, { isAbandoned })",
    "isAbandoned", "failed or timed-out register()", "':name'", "optional '(...)' group", "'?', '*' or '+'",
    "console.warn", "'#'", "whitespace", "'..'", "backslash", "zero-width",
])
check("ui.authenticated.navigation", ["tacticalPermission", "strictly true", "context.tactical_permissions", "UI 0.12.99", "no superuser shortcut"])
check("ui.authenticated.context-actions", ["right-click", "client.context-menu", "site.context-menu", "Shift+F10", "UI 0.12.99"])
must(by_id["ui.authenticated.header"]["docs"] == "tec-tac-ui/docs/module-header.md", "header docs path")
must(by_id["ui.authenticated.runtime-context"]["docs"] == "tec-tac-ui/docs/module-runtime-api.md", "runtime-context docs path")
must(by_id["ui.authenticated.navigation"]["docs"] == "tec-tac-ui/docs/module-runtime-api.md", "navigation docs path")
must(by_id["ui.authenticated.context-actions"]["docs"] == "tec-tac-ui/docs/context-actions.md", "context-actions docs path")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.32", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
cells = []
for line in md.splitlines():
    if line.startswith("| `ui.") and line.count("|") >= 8:
        parts = [p.strip() for p in line.strip().strip("|").split(" | ")]
        cells.append(parts[5])
must(len(cells) == len(BROWSER), (len(cells), len(BROWSER)))
for cell in cells:
    must(re.fullmatch(r"`tec-tac-ui/docs/[A-Za-z0-9._-]+\.md`", cell), f"markdown docs cell: {cell!r}")
for row in BROWSER:
    must(f"`{row['id']}`" in md and row["id"] in text, f"{row['id']} is rendered")
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")
print("[TEST] PASS browser contract rows 1.17.32")
