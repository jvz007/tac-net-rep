#!/usr/bin/env python3
"""1.17.66 regression (UI 0.12.118 request): the ui.authenticated.components row lists the 0.12.118 kit props, all off by default.

contracts.py needs Django, so it is read as source (ast.literal_eval of BROWSER_CONTRACTS). Covered: the operations list and the docs path of the
row are unchanged; one detail line names EditorWindow floating and readOnly, FormRow stacked, TagEditor inputId and describedBy, the kit layer
1050 and its place among the other layers, 'UI 0.12.118' and 'off by default'; the earlier detail lines are all still there; the layer numbers
agree with docs/module-dialogs.md of the UI when that folder is on this PC; every browser row still has a plain docs path.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "BROWSER_CONTRACTS")
row = next(r for r in rows if r["id"] == "ui.authenticated.components")
must(row["operations"] == ["SearchSelect", "TagEditor", "DataTable", "FormRow", "EditorWindow", "Stepper", "FilterEditor"], row["operations"])
must(row["docs"] == "tec-tac-ui/docs/module-components.md" and row["audience"] == "module/browser" and row["phase"] == "authenticated", row)
print("       the operations, docs path, audience and phase of the row are unchanged")

details = row["details"]
line = next((d for d in details if d.startswith("UI 0.12.118 props")), None)
must(line is not None, "a detail line for the 0.12.118 props")
for needle in ("EditorWindow floating", "readOnly", "FormRow stacked", "TagEditor inputId and describedBy", "aria-describedby", "layer 1050", "1100", "1400", "off by default",
               "UI 0.12.118", "Core 1.17.66", "documentation only", "takes the focus when it opens and gives it back", "hides Save and Discard"):
    must(needle in line, f"the 0.12.118 line does not say {needle!r}")
for earlier in ("SearchSelect props:", "TagEditor props:", "DataTable props:", "FormRow props:", "FilterEditor (UI 0.12.116", "FilterEditor binding and reads"):
    must(any(d.startswith(earlier) for d in details), f"an earlier detail line is gone: {earlier}")
print("       one detail line names floating, readOnly, stacked, inputId, describedBy and the layer 1050 order; the earlier lines stay")

docs = ROOT.parents[1] / "workspace" / "ui" / "docs" / "module-dialogs.md"
if docs.is_file():
    text = docs.read_text(encoding="utf-8")
    for layer in ("1050", "1100", "1200", "1300", "1400"):  # module-dialogs.md's table; 1000 and 1150 are in module-components.md
        must(layer in text, f"the UI layer table names {layer}")
    for layer in ("1000", "1050", "1100", "1150", "1200", "1300", "1400"):
        must(layer in line, f"the contract names layer {layer}")
    print("       the layer numbers agree with the UI's module-dialogs.md")
else:
    print("       the UI docs are not on this PC: the layer comparison was skipped")

for r in rows:
    must(isinstance(r.get("docs"), str) and r["docs"].startswith("tec-tac-ui/docs/") and r["docs"].endswith(".md"), f"{r['id']} keeps a plain docs path")
print("PASS browser contract rows 1.17.66")
