#!/usr/bin/env python3
"""1.17.51: the UI kit details that 1.17.50 left out of ui.authenticated.components.

Adds the EditorWindow areas (actions, properties, content, footer and where each draws), the FormRow default slot and the two ids
(forId + '-hint', forId + '-error'), and the DataTable column width unit, the 2000 row footer, the throwing cell and the keys. Documentation
only: the operations list is unchanged and no endpoint, capability or version moves. The 1.17.50 needles still pass (that test is run too).

contracts.py needs Django, so the tables are read with ast, as in tests/browser-contract-rows-1.17.50.py.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "framwork/tec_tac/contracts.py"
tree = ast.parse(PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


node = next(n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
            and any(isinstance(t, ast.Name) and t.id == "BROWSER_CONTRACTS" for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
rows = {r["id"]: r for r in ast.literal_eval(node.value)}
comp = rows["ui.authenticated.components"]
must(comp["operations"] == ["SearchSelect", "TagEditor", "DataTable", "FormRow", "EditorWindow", "Stepper"], comp["operations"])
text = " ".join(comp["details"]) + " " + comp["purpose"]
for needle in (
    "actions (slot)", "properties (slot)", "content (slot", "footer (slot)", "left of the close button", "the left column",
    "the default slot", "forId + '-hint'", "forId + '-error'", "-hint", "-error", "aria-describedby",
    "px or %", "Showing the first 2000 rows", "a cell(row, column) that throws shows an empty cell",
    "ArrowUp and ArrowDown", "Home and End", "Tab reaches the selected row",
    "Documentation only: no endpoint, capability or version moves",
):
    must(needle in text, f"the components row names {needle!r}")
must(rows["ui.authenticated.styleTokens"]["operations"][-1] == "tt-ws", "the style tokens row is unchanged")

# the facts agree with the UI docs when they sit beside this repository
UI_DOC = ROOT.parent / "ui" / "docs" / "module-components.md"
if UI_DOC.is_file():
    doc = UI_DOC.read_text(encoding="utf-8")
    for needle in ("`actions` (slot)", "`properties` (slot)", "`footer` (slot)", "number with `px` or `%`", "Showing the first 2000 rows.", "A function that throws shows an empty cell"):
        must(needle in doc, f"module-components.md has {needle!r}")

# the earlier rows still hold
done = subprocess.run([sys.executable, str(ROOT / "tests" / "browser-contract-rows-1.17.50.py")], capture_output=True, text=True)
must(done.returncode == 0, done.stdout + done.stderr)
print("browser contract rows 1.17.51 ok")
