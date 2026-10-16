#!/usr/bin/env python3
"""1.17.45 documentation pin: the Reporting shim is the supported path for a module whose ready() can run before Report Manager's.

Closes the 'Reporting: replay path for direct registry callers' entries of alerts 0.6.0, checks 0.11.0 and cyberhoot 0.8.0 (Johan's
CQ13 to CQ16 answers of 9 October 2026, confirmed as built). No code changed. The test checks that docs/module-reporting.md and
docs/developer-contracts.md both say it, and that framwork/tec_tac/reporting.py still does what the sentence says: it holds a
registration pending, replays pending registrations in id order (sorted ids), and does so after every ready() has run (bootstrap calls
settle_reporting_bridge once, and a later registration replays older pending ones first). Plain Python, no Django.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


PHRASES = (
    "`tec_tac.reporting.register_reporting_model` (the shim) stays the supported path",
    "`AppConfig.ready()` can run before Report Manager's",
    "pending registrations in id order after every `ready()` has run",
    "no ordering between `ready()` calls is needed",
    "The shim is removed only after the last module in `modules/` has switched, with no date",
)
for name in ("docs/module-reporting.md", "docs/developer-contracts.md"):
    text = (ROOT / name).read_text(encoding="utf-8")
    for phrase in PHRASES:
        must(phrase in text, f"{name} is missing: {phrase}")
    must(text.count("stays the supported path") == 1, f"{name} says it once")
print("       both documents carry the supported-path sentence")

source = (ROOT / "framwork" / "tec_tac" / "reporting.py").read_text(encoding="utf-8")
tree = ast.parse(source)
funcs = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
forward = ast.get_source_segment(source, funcs["_forward_pending"])
must("sorted(_PENDING)" in forward and "in id order" in forward, "pending registrations are replayed in id order")
register = ast.get_source_segment(source, funcs["register_reporting_model"])
must("_forward_pending(raise_for=public_id)" in register, "a later registration replays older pending ones first")
must("STATE_PENDING" in register or "_PENDING" in register, "an early registration is held pending")
settle = ast.get_source_segment(source, funcs["settle_reporting_bridge"])
must("_forward_pending()" in settle, "settle replays pending registrations")
boot = (ROOT / "framwork" / "tec_tac" / "bootstrap.py").read_text(encoding="utf-8")
must("settle_reporting_bridge()" in boot, "bootstrap settles the bridge after the modules' ready() calls")
print("       reporting.py holds pending, replays in id order, and bootstrap settles it")
print("[TEST] PASS reporting supported path 1.17.45")
