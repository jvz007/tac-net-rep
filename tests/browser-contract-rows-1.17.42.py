#!/usr/bin/env python3
"""1.17.42: the browser contract row ui.authenticated.components (SearchSelect and TagEditor, UI 0.12.111), documentation only.

Closes the held Low from the UI 0.12.111 review: the row was not in the public contract export. No endpoint, capability or version
moves. contracts.py needs Django, so the tables are read with ast and the render functions are exec'd from the same tree, as in
tests/browser-contract-rows-1.17.40.py.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

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
RULES = literal("RULES")
CORE = literal("CORE_CONTRACTS")
ids = [r["id"] for r in BROWSER]

# the row exists once, between modulePreferences and services (the 1.17.40 order stays true)
must(ids.count("ui.authenticated.components") == 1, "the row is there once")
must(len(ids) == len(set(ids)), "no browser row id is duplicated")
must(ids.index("ui.authenticated.components") == ids.index("ui.authenticated.modulePreferences") + 1, "the row follows modulePreferences")
must(ids.index("ui.authenticated.modulePreferences") == ids.index("ui.authenticated.terminal") + 1, "modulePreferences still follows terminal")
row = BROWSER[ids.index("ui.authenticated.components")]

# shape
must(row["phase"] == "authenticated" and row["service"] == "components", (row["phase"], row["service"]))
must(row["operations"][:2] == ["SearchSelect", "TagEditor"], row["operations"])  # 1.17.50: the kit (DataTable, FormRow, EditorWindow, Stepper) follows these two
must(row["audience"] == "module/browser", row["audience"])
must(re.fullmatch(r"tec-tac-ui/docs/[A-Za-z0-9._-]+\.md", row["docs"]), f"docs is a plain path: {row['docs']!r}")
must(row["docs"] == "tec-tac-ui/docs/module-components.md", row["docs"])
text_all = " ".join(row["details"]) + " " + row["purpose"]

# the details name every prop, both events and the limits
for needle in (
    "modelValue", "options", "placeholder", "inputId", "ariaLabel", "disabled", "clearable", "emptyText", "favouriteLabel", "allLabel",
    "update:modelValue", "select", "value, label, description, favourite, chip, chipTone, disabled, searchText",
    "300", "Showing the first 300", "combobox", "listbox",
    "commaAdds", "maxItems", "maxLength", "200", "500", "validate", "reject", "reason", "readonly",
    "registerPublic", "UI 0.12.111", "Core 1.17.41", "frozen", "as text", "context.Vue.h(SearchSelect",
    "context.Vue.h(TagEditor", "trims", "control characters",
):
    must(needle in text_all, f"the row names {needle!r}")
must("Documentation only" in text_all and "no endpoint, capability or version moves" in text_all, "the row says it is documentation only")
must("value stays with the module" in row["purpose"] or "The value stays with the module" in row["purpose"], "the value rule is in the purpose")
must("Needs UI 0.12.111 and Core 1.17.41 or later" in row["purpose"], "the purpose names both requirements")

# the export renderers carry the row
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.42", "generated_at": "2026-10-15T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
must("ui.authenticated.components" in md and "ui.authenticated.components" in text, "the row is rendered in both exports")
must(md.count("ui.authenticated.components") >= 1 and "tec-tac-ui/docs/module-components.md" in md, "the docs path is rendered")

# the UI doc, when it sits beside this repository, carries the same numbers
UI_DOC = ROOT.parent / "ui" / "docs" / "module-components.md"
if UI_DOC.is_file():
    ui = UI_DOC.read_text(encoding="utf-8")
    for needle in ("Showing the first 300", "300", "200", "500", "commaAdds", "registerPublic", "UI 0.12.111", "Core 1.17.41"):
        must(needle in ui, f"the UI doc has {needle!r}")
    print("       UI doc cross-check passed")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

print("[TEST] PASS browser contract row ui.authenticated.components 1.17.42")
