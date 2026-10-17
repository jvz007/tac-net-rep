#!/usr/bin/env python3
"""1.17.50: the UI 0.12.114 browser contract rows.

ui.authenticated.components gains DataTable, FormRow, EditorWindow and Stepper and the SearchSelect props required, invalid and
describedBy. A new row, ui.authenticated.styleTokens, lists the eleven size and density tokens and the opt-in class tt-ws.
registerPublic still gets no components. Documentation only: no endpoint, capability or version moves for these rows.

contracts.py needs Django, so the tables are read with ast and the render functions are exec'd from the same tree, as in
tests/browser-contract-rows-1.17.44.py.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def literal(name):
    node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


BROWSER = literal("BROWSER_CONTRACTS")
ids = [r["id"] for r in BROWSER]
rows = {r["id"]: r for r in BROWSER}
must(len(ids) == len(set(ids)), "no browser row id is duplicated")

# (1) the components row
comp = rows["ui.authenticated.components"]
must(comp["operations"][:6] == ["SearchSelect", "TagEditor", "DataTable", "FormRow", "EditorWindow", "Stepper"], comp["operations"])
must(comp["operations"][-1] == "FilterEditor", comp["operations"])  # 1.17.53 appends FilterEditor last
must(comp["phase"] == "authenticated" and comp["service"] == "components" and comp["audience"] == "module/browser", comp)
must(comp["docs"] == "tec-tac-ui/docs/module-components.md", comp["docs"])
comp_text = " ".join(comp["details"]) + " " + comp["purpose"]
NEEDLES = (
    # SearchSelect accessibility props
    "required (sets aria-required", "invalid (sets aria-invalid", "describedBy (sets aria-describedby", "separated by spaces", "all off by default", "UI 0.12.114",
    # the kit
    "DataTable", "FormRow", "EditorWindow", "Stepper", "context.Vue.h(Component, props)", "keeps no value of its own", "as text", "tt-ws",
    "context.confirm", "No component confirms or discards anything",
    "columns ([{ key, label, sortable, align, width }]", "align left, right or center", "at most 40 columns", "rows (at most 2000 are drawn)", "rowKey",
    "selectedKey", "sortKey", "sortDir (ascending or descending)", "loading", "emptyTitle", "emptyText", "footer", "ariaLabel", "cell(row, column)",
    "sort (key, dir: ascending, then descending, then null)", "select (row)", "rowmenu (row, event)", "activate (row)",
    "label, hint, help, error and forId", "title, dirty, canSave, saving and status", "save, discard and close",
    "steps ([{ key, label, state }]", "state done or error", "at most 12 steps", "current and ariaLabel", "select (key)",
    "A module that does not use them behaves as before",
    # the earlier rows still hold
    "serverSearch", "selectedLabel", "Showing the first 300", "Needs UI 0.12.111 and Core 1.17.41 or later", "registerPublic gets no components",
    "no endpoint, capability or version moves",
)
for needle in NEEDLES:
    must(needle in comp_text, f"the components row names {needle!r}")

# (2) the style tokens row
TOKENS = ["--text-body", "--text-ws", "--text-sm", "--text-xs", "--cell-y", "--cell-x", "--ctl-y", "--ctl-x",
          "--radius-control", "--radius-panel", "--label-track-ws"]
style = rows["ui.authenticated.styleTokens"]
must(style["operations"] == TOKENS + ["tt-ws"] and len(TOKENS) == 11, style["operations"])
must(style["phase"] == "authenticated" and style["service"] == "styleTokens" and style["audience"] == "module/browser", style)
must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", style["docs"]) and style["docs"] == "tec-tac-ui/docs/ui-design-standards.md", style["docs"])
style_text = " ".join(style["details"]) + " " + style["purpose"]
for needle in ("UI 0.12.114", "additive", "Documentation only", "no endpoint, capability or version moves", "15.5px scaled", "12.1px scaled", "11px scaled",
               "10.5px scaled", "7px and 8px", "6px and 8px", "2px", "3px", ".08em", "calc(Npx * var(--font-scale))", "never a raw px value",
               "opt-in scope class tt-ws", "Outside tt-ws nothing changes", "--label, --label-track and --font-scale keep their values",
               "dialog host panel", "four kit components", "registerPublic gets no components"):
    must(needle in style_text, f"the style tokens row names {needle!r}")
for token in TOKENS:
    must(token in style_text, f"{token} is described")

# (3) the public row is unchanged: registerPublic gets no components
public = rows["ui.public.module-runtime"]
must(public["operations"] == ["publicApi", "addPublicRoute", "ssoProviders"], public["operations"])
must("components" not in " ".join(public["operations"]) and "components" not in public["purpose"].lower(), public)
must(rows["ui.public.sso-providers"]["operations"] == ["register", "list", "begin", "clear"])

# (4) the exports carry the rows
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.50", "generated_at": "2026-10-17T00:00:00+00:00", "rules": literal("RULES"),
           "core": [dict(r, signature="()") for r in literal("CORE_CONTRACTS")], "browser": [dict(r) for r in BROWSER],
           "resource_directory": {}, "capabilities": [], "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
for needle in ["DataTable", "FormRow", "EditorWindow", "Stepper", "aria-required", "aria-invalid", "aria-describedby", "ui.authenticated.styleTokens", "tt-ws", *TOKENS]:
    must(needle in md, f"the Markdown export carries {needle!r}")
    must(needle in text, f"the text export carries {needle!r}")
must("### `ui.authenticated.styleTokens` details" in md, "the style tokens row has its details section")

# (5) the UI docs, when they sit beside this repository, state the same facts
UI_DOCS = ROOT.parent / "ui" / "docs"
if (UI_DOCS / "module-components.md").is_file():
    doc = (UI_DOCS / "module-components.md").read_text(encoding="utf-8")
    for needle in ("DataTable", "FormRow", "EditorWindow", "Stepper", "`required`", "`invalid`", "`describedBy`", "At most 40 columns", "At most 2000", "At most 12 steps"):
        must(needle in doc, f"module-components.md has {needle!r}")
    standards = (UI_DOCS / "ui-design-standards.md").read_text(encoding="utf-8")
    for token in TOKENS + ["tt-ws"]:
        must(token in standards, f"ui-design-standards.md has {token!r}")
    runtime = (UI_DOCS / "module-runtime-api.md").read_text(encoding="utf-8")
    must("Contract row addition (UI 0.12.114" in runtime and "registerPublic(context)` still gets no components" in runtime)

print("browser contract rows 1.17.50 ok")
