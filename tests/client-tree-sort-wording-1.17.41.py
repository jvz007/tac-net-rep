#!/usr/bin/env python3
"""1.17.41: the wording of Tactical's client_tree_sort setting in Core's public contract and docs (documentation only).

alphafail is Tactical's 'Move failing clients to the top', alpha is A to Z. Core publishes the person's setting and the failing state
(failing_checks) and never sorts. Pins the wording in contracts.py, docs/my-account.md and docs/resource-directory.md, and that the
runtime context still carries client_tree_sort.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
for needle in ("alphafail is Tactical's 'Move failing clients to the top'", "alpha is A to Z", "failing_checks", "Core never sorts"):
    must(needle in contracts, f"contracts.py lacks {needle!r}")
must("client_tree_sort (alphafail or alpha): alphafail" in contracts, "the runtime-context row carries the explanation")
for name in ("docs/my-account.md", "docs/resource-directory.md"):
    text = (ROOT / name).read_text(encoding="utf-8")
    for needle in ("Move failing clients to the top", "A to Z", "failing_checks", "never sorts"):
        must(needle in text, f"{name} lacks {needle!r}")
context = (ROOT / "framwork/tec_tac/account_self_service.py").read_text(encoding="utf-8")
must("client_tree_sort" in context and "tactical_ui_context" in context, "tactical_ui_context still carries client_tree_sort")
print("[TEST] PASS client_tree_sort wording 1.17.41")
