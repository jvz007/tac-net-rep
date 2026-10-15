#!/usr/bin/env python3
"""1.17.40: the browser contract row ui.authenticated.modulePreferences, the merged-result wording (UI 0.12.109), documentation only.

The row now says what each call of a merged set() and remove() resolves, instead of 'Every call whose write was merged gets the same
outcome' (which was wrong: the earlier helper gave a result of the wrong type). No number, operation, refusal or capability version moved:
400 ms, 2 seconds and flush() stay. contracts.py needs Django, so the tables are read with ast and the two render functions are exec'd from
the same tree, as in tests/browser-contract-rows-1.17.37.py.
"""
from __future__ import annotations

import ast
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
must(ids.count("ui.authenticated.modulePreferences") == 1, "the row is there once")
must(ids.index("ui.authenticated.modulePreferences") == ids.index("ui.authenticated.terminal") + 1, "the row still follows the terminal row")
row = BROWSER[ids.index("ui.authenticated.modulePreferences")]
must(row["operations"] == ["get", "getAll", "set", "remove", "flush"], "operations unchanged")
details = " ".join(row["details"])
text_all = details + " " + row["purpose"]

for needle in ("resolves undefined", "resolves false", "the last operation", "same rejection", "400 ms", "2 seconds", "flush()",
               "Core 1.17.38", "UI 0.12.108"):
    must(needle in text_all, f"the row names {needle!r}")
must("UI 0.12.109" in row["purpose"], "the purpose names UI 0.12.109")
must("gets the same outcome" not in text_all, "the old phrase is gone")
must("every set() resolves the value Core stored" in details and "every remove() resolves false" in details, "last op set")
must("every remove() resolves true or false as Core answered" in details and "every set() resolves undefined" in details, "last op remove")
must("superseded resolves undefined" in details and "superseded resolves false" in details, "the two superseded results")

# ------------------------------------------------------------------------------------------------ the doc
doc = (ROOT / "docs/module-preferences.md").read_text(encoding="utf-8")
must("Since UI 0.12.109" in doc and "`undefined`" in doc and "same rejection" in doc, "docs/module-preferences.md carries the per-caller rule")

# ------------------------------------------------------------------------------------------------ the UI doc, when it sits beside this repository
UI_DOC = ROOT.parent / "ui" / "docs" / "module-preferences.md"
if UI_DOC.is_file():
    ui = UI_DOC.read_text(encoding="utf-8")
    must("400 ms" in ui and "2 seconds" in ui, "the UI doc has the two numbers")
    must("resolves `false`" in ui and "resolves `undefined`" in ui, "the UI doc has the two superseded results")
    must("same rejection" in ui, "the UI doc has the rejection rule")
else:
    print("       UI cross-check skipped: workspace/ui is not beside this repository")

# ------------------------------------------------------------------------------------------------ the renderers
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"render_markdown", "render_text"}]
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)
ns: dict = {}
exec(compile(module, str(PATH), "exec"), ns)  # noqa: S102 - test-only: the real render functions of contracts.py
catalog = {"framework_version": "1.17.40", "generated_at": "2026-10-15T00:00:00+00:00", "rules": list(RULES),
           "core": [dict(r, signature="()") for r in CORE], "browser": [dict(r) for r in BROWSER], "resource_directory": {}, "capabilities": [],
           "scheduler_actions": [], "permissions": [], "reporting_models": [], "http": []}
md = ns["render_markdown"](catalog)
text = ns["render_text"](catalog)
for needle in ("resolves undefined", "same rejection", "UI 0.12.109"):
    must(needle in md and needle in text, f"{needle} is rendered in both exports")
must("gets the same outcome" not in md and "gets the same outcome" not in text, "the old phrase is not rendered")
print("[TEST] PASS browser contract rows 1.17.40")
