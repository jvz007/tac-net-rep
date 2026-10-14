#!/usr/bin/env python3
"""1.17.35: browser contract rows owed to the UI (reviews/requests/core.md, UI 0.12.104 and 0.12.105), documentation only.

Adds ui.authenticated.terminal (the shared terminal widget, UI 0.12.104, after ui.authenticated.websocket) and extends
ui.authenticated.websocket with the server-terminal facts of UI 0.12.105 in place of the 1.17.34 sentence that said the helper did not
open the kind yet. The wording is taken from workspace/ui/docs (module-terminal.md, module-tactical-websocket.md and
module-runtime-api.md). No row changes a value that a module consumes, and no capability or contract version moves.

Covered: ids are unique; every docs value is a plain tec-tac-ui/docs/*.md path; the terminal row lists all 19 operations and every
option, the three limits, the handle rules, 'registerPublic', 'bound to the calling module', 'needs no Core API' and UI 0.12.104; the
websocket row names the server-terminal path, the frames, the close codes, the refusals, UI 0.12.105 and no longer the 1.17.34 sentence;
the real render_markdown and render_text carry both rows and no docs cell holds a space or a parenthesis. When workspace/ui is beside
this repository, docs/module-terminal.md and docs/module-tactical-websocket.md exist there. contracts.py needs Django, so the tables are
read with ast and the two render functions are exec'd from the same tree, as in tests/browser-contract-rows-1.17.33.py.
tests/browser-contract-rows-1.17.32.py, 1.17.33.py and tests/browser-contract-catalog-1.15.170.py run unchanged.
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
ids = [r["id"] for r in BROWSER]
must(ids.index("ui.authenticated.terminal") == ids.index("ui.authenticated.websocket") + 1, "the terminal row follows the websocket row")


def check(row_id, needles):
    row = by_id[row_id]
    text = " ".join(row.get("details", [])) + " " + row.get("purpose", "") + " " + " ".join(row.get("operations", []))
    for needle in needles:
        must(needle in text, f"{row_id} names {needle!r}")


for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")

# ------------------------------------------------------------------------------------------------ the terminal row
terminal = by_id.get("ui.authenticated.terminal", {})
must(terminal.get("phase") == "authenticated" and terminal.get("service") == "terminal", "terminal row is authenticated terminal")
must(terminal.get("audience") == "module/browser", "terminal row audience")
must(terminal.get("docs") == "tec-tac-ui/docs/module-terminal.md", "terminal docs path")
must(terminal.get("operations") == [
    "create", "write", "writeln", "clear", "reset", "focus", "blur", "fit", "size", "getText", "getSelection", "hasSelection",
    "copy", "paste", "setTheme", "setOptions", "onInput", "onResize", "dispose",
], "terminal row lists the 19 operations in order")
must(len(terminal["operations"]) == 19, "19 operations")
check("ui.authenticated.terminal", [
    "theme", "fontFamily", "fontSize", "cursorBlink", "scrollback", "convertEol", "focus", "rows", "cols", "ariaLabel", "onInput", "onResize",
    "50000", "8 live", "ninth", "1 to 1000", "text only", "HTML", "OSC 8", "clipboard", "web-links",
    "registerPublic", "bound to the calling module", "needs no Core API", "UI 0.12.104", "ui.authenticated.websocket",
    "fontFamily", "#", "rgb()", "url(", "300 characters", "200 characters",
])

# ------------------------------------------------------------------------------------------------ the websocket row (server terminal)
websocket = by_id.get("ui.authenticated.websocket", {})
must(websocket.get("docs") == "tec-tac-ui/docs/module-tactical-websocket.md", "websocket docs path unchanged")
must("does not open this kind yet" not in " ".join(websocket.get("details", [])), "the 1.17.34 'does not open this kind yet' sentence is gone")
check("ui.authenticated.websocket", [
    "server-terminal", "open('globalsettings', 'server-terminal', {signal})", "agentId", "/ws/tfd/server-terminal/<ticket>/",
    "session.start()", "throws and sends nothing", "trmmcli.input", "{data:{input}}", "trmmcli.resize", "{data:{rows, cols}}",
    "trmmcli.disconnect", "trmmcli.output", "{data:{output, messageId}}", "4502", "audit-unavailable", "4003",
    "no reconnect", "superuser_required", "server_terminal_disabled", "error.status", "error.code",
    "no AD-20 replacement", "UI 0.12.105", "Core 1.17.34", "agent-terminal",
])
must("0.12.105" in " ".join(websocket["details"]) and "1.17.34" in " ".join(websocket["details"]), "the websocket row names UI 0.12.105 and Core 1.17.34")

# ------------------------------------------------------------------------------------------------ the browser docs really exist (read only)
UI_DOCS = ROOT.parent / "ui" / "docs"
if UI_DOCS.is_dir():
    must((UI_DOCS / "module-terminal.md").is_file(), "workspace/ui/docs/module-terminal.md exists")
    must((UI_DOCS / "module-tactical-websocket.md").is_file(), "workspace/ui/docs/module-tactical-websocket.md exists")
    terminal_doc = (UI_DOCS / "module-terminal.md").read_text(encoding="utf-8")
    for op in terminal["operations"]:
        must(f"{op}(" in terminal_doc or f"`{op}`" in terminal_doc, f"the UI terminal doc names {op}")
    must("registerPublic" in terminal_doc and "8 live" in terminal_doc, "the UI terminal doc says registerPublic and 8 live")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.35", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(RULES),
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
for needle in ("ui.authenticated.terminal", "/ws/tfd/server-terminal/<ticket>/", "registerPublic"):
    must(needle in md and needle in text, f"{needle} is rendered")
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")
print("[TEST] PASS browser contract rows 1.17.35")
