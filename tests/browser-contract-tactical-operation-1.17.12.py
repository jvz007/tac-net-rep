#!/usr/bin/env python3
"""1.17.12: the ui.authenticated.tactical-operation row states what UI 0.12.89 does, and says no more than it does.

Wording only, no behaviour change. The row and docs/tactical-operations.md carry the same sentence. The control-character fix is not
promised: a path hidden behind tab, CR, LF or other control characters is a finding held for the UI.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
assignment = next(
    node for node in tree.body
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BROWSER_CONTRACTS" for t in node.targets)
)
rows = ast.literal_eval(assignment.value)
by_id = {row["id"]: row for row in rows}
row = by_id["ui.authenticated.tactical-operation"]
text = " ".join(row["details"])


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


must("scoped only from the UI release that closes" not in text, "the old 'scoped only from the UI release that closes' wording is still in the row")
must("held 0.12.88 review finding" not in text, "the stale 0.12.88 finding is still named")
for needle in ("From UI 0.12.89", "api, apiRaw, apiBlob and apiText", "refuse a tactical-operations path", "own id or the one it replaces",
               "snapshot taken before any register() runs", "helper-level guard", "not a sandbox", "calls fetch itself",
               "Core's own checks stay the authority", "declared by the module id in the URL", "Tactical permission and role scope",
               "the route is owned", "the replacement is honoured", "tab, CR, LF or other control characters", "finding held for the UI"):
    must(needle in text, f"the row lacks {needle!r}")
# It promises nothing about the control-character fix.
for promise in ("is refused", "are refused", "will be refused", "strips", "stripped", "closes the finding"):
    must(promise not in text.split("A path hidden behind")[-1], f"the row promises the control-character fix: {promise!r}")
must(text.index("not a sandbox") < text.index("Core's own checks stay the authority"), "the limit comes before the authority")

doc = (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8")
must("scoped only from the UI release that closes" not in doc, "the old wording is still in the doc")
sentence = ("From UI 0.12.89 `api`, `apiRaw`, `apiBlob` and `apiText` refuse a tactical-operations path for an id other than the module's own id or the one it replaces. "
            "The replaced id is a snapshot taken before any `register()` runs. The guard is a helper-level guard, not a sandbox: a module that calls `fetch` itself is not stopped by it. "
            "Core's own checks stay the authority: the operation is declared by the module id in the URL, the user holds the Tactical permission and the role scope, the route is owned, and the replacement is honoured. "
            "A path hidden behind tab, CR, LF or other control characters is a finding held for the UI.")
must(doc.count(sentence) == 1, "docs/tactical-operations.md carries the same sentence once")
# The row and the doc agree on every fact (the doc uses code spans and 'the role scope').
plain = sentence.replace("`", "")
for fact in ("From UI 0.12.89", "api, apiRaw, apiBlob and apiText", "snapshot taken before any register() runs", "helper-level guard, not a sandbox", "calls fetch itself", "tab, CR, LF or other control characters"):
    must(fact in plain and fact in text, fact)

print("[TEST] PASS browser contract tactical-operation row 1.17.12")
