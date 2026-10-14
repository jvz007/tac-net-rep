#!/usr/bin/env python3
"""1.17.37: the browser contract row ui.authenticated.modulePreferences (UI 0.12.106), documentation only.

Adds the row for context.modulePreferences (get, getAll, set and remove) after ui.authenticated.terminal, with the wording taken from
workspace/ui/docs/module-preferences.md and module-runtime-api.md. No row changes a value that a module consumes, and no capability or
contract version moves in the browser rows.

Covered: ids are unique; the new row follows ui.authenticated.terminal; its four operations; its docs value is a plain path; the own-id rule,
no AD-20 exception, the 4 KiB, 5 level and 50 name limits, the refusals invalid_name, invalid_value, preference_limit, module_not_found, 401 and
429, 'registerPublic', 'localStorage', UI 0.12.106 and Core 1.17.35; the real render_markdown and render_text carry the row. The terminal and
websocket rows from 1.17.35 are still present (confirmation only). contracts.py needs Django, so the tables are read with ast and the two
render functions are exec'd from the same tree, as in tests/browser-contract-rows-1.17.35.py.
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
must(ids.count("ui.authenticated.modulePreferences") == 1, "the new row is there once")
must(ids.index("ui.authenticated.modulePreferences") == ids.index("ui.authenticated.terminal") + 1,
     "the new row follows ui.authenticated.terminal")

for row in BROWSER:
    must(PATTERN.match(str(row.get("docs", ""))), f"{row['id']}: docs is not a plain path: {row.get('docs')!r}")


def check(row_id, needles):
    row = by_id[row_id]
    text = " ".join(row.get("details", [])) + " " + row.get("purpose", "") + " " + " ".join(row.get("operations", []))
    for needle in needles:
        must(needle in text, f"{row_id} names {needle!r}")


# ------------------------------------------------------------------------------------------------ the new row
row = by_id["ui.authenticated.modulePreferences"]
must(row.get("phase") == "authenticated" and row.get("service") == "modulePreferences", "phase and service")
must(row.get("audience") == "module/browser", "audience is module/browser")
must(row.get("docs") == "tec-tac-ui/docs/module-preferences.md", "docs path")
must(row.get("operations") == ["get", "getAll", "set", "remove", "flush"], "the four 1.17.37 operations in order, then flush (added 1.17.39)")
check("ui.authenticated.modulePreferences", [
    "get(name, fallback)", "getAll()", "set(name, value)", "remove(name)", "async",
    "Own id only", "bound to the loader's descriptor id", "no module id is passed",
    "no AD-20 replaced-module exception", "cannot reach the module it replaces",
    "/api/tfd/module-preferences/", "decoded first",
    "registerPublic", "localStorage", "sessionStorage", "nothing is cached",
    "[a-z0-9][a-z0-9._-]{0,63}", "4 KiB", "5 levels", "50 names",
    "invalid_name", "invalid_value", "status 400", "preference_limit", "module_not_found", "404",
    "401", "signed_out", "429",
    "module_not_allowed", "status 403", "audit_failed", "status 503", "Core 1.17.38",
    "UI 0.12.106", "Core 1.17.35",
])
for needle in ("UI 0.12.106", "Core 1.17.35"):
    must(needle in row["purpose"] or needle in " ".join(row["details"]), f"the row names {needle}")

# the row says what it is not: a public page has no module preference
must("registerPublic does not get modulePreferences" in " ".join(row["details"]), "registerPublic is refused in words")

# ------------------------------------------------------------------------------------------------ 1.17.35 rows still present (confirmation)
terminal = by_id.get("ui.authenticated.terminal", {})
must(terminal.get("docs") == "tec-tac-ui/docs/module-terminal.md", "terminal row still present")
must(terminal.get("operations") and len(terminal["operations"]) == 19, "terminal row still lists 19 operations")
websocket = by_id.get("ui.authenticated.websocket", {})
must(websocket.get("docs") == "tec-tac-ui/docs/module-tactical-websocket.md", "websocket row still present")
must("server-terminal" in " ".join(websocket.get("details", [])), "websocket row still names the server terminal")

# ------------------------------------------------------------------------------------------------ the UI doc, when it sits beside this repository
UI_DOCS = ROOT.parent / "ui" / "docs"
if UI_DOCS.is_dir():
    doc = (UI_DOCS / "module-preferences.md").read_text(encoding="utf-8")
    for op in row["operations"]:
        must("context.modulePreferences" in doc and (f"`{op}`" in doc or f"{op}(" in doc), f"the UI doc names {op}")
    must("registerPublic" in doc and "UI 0.12.106" in doc, "the UI doc says registerPublic and UI 0.12.106")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.37", "generated_at": "2026-10-14T00:00:00+00:00", "rules": list(RULES),
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
must("`ui.authenticated.modulePreferences`" in md and "ui.authenticated.modulePreferences" in text, "the row is rendered")
for needle in ("ui.authenticated.modulePreferences", "tec-tac-ui/docs/module-preferences.md", "registerPublic", "preference_limit"):
    must(needle in md and needle in text, f"{needle} is rendered in both exports")
docs_cells = re.findall(r"\| docs=(.*?) - ", text)
must(len(docs_cells) == len(BROWSER), (len(docs_cells), len(BROWSER)))
for cell in docs_cells:
    must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", cell), f"text export docs cell: {cell!r}")
print("[TEST] PASS browser contract rows 1.17.37")
