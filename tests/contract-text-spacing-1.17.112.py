#!/usr/bin/env python3
"""1.17.112 regression: contract purpose texts no longer run a sentence into 'Since 1.17.x' (held Low of the Core 1.17.111 review).

Several purpose strings in framwork/tec_tac/contracts.py are built from adjacent string literals. Three rows (describe_delegation,
register_delegation_grant, start_delegated_run) ended a piece with a full stop and no space, so the published export read
'...Delegation.Since 1.17.111'. The test parses contracts.py (no Django needed), joins the literals of every purpose the way Python
does, and checks that no text has a letter, closing bracket or full stop directly in front of 'Since 1.17.', and that the three named
rows now read '. Since 1.17.111'.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "framwork" / "tec_tac" / "contracts.py"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
rows = []
for node in ast.walk(tree):
    if isinstance(node, ast.Dict):
        keys = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if "purpose" in keys and "name" in keys and isinstance(keys["name"], ast.Constant):
            try:
                text = ast.literal_eval(keys["purpose"])
            except (ValueError, SyntaxError):
                continue
            rows.append((keys["name"].value, text))
must(len(rows) > 100, f"found only {len(rows)} contract rows")

BAD = re.compile(r"[A-Za-z0-9)\].]Since 1\.17\.")
bad = [(name, m.group(0)) for name, text in rows for m in BAD.finditer(text)]
must(not bad, f"purpose texts that run into 'Since 1.17.': {bad}")

by_name = {}
for name, text in rows:
    by_name.setdefault(name, []).append(text)
for name in ("describe_delegation", "register_delegation_grant", "start_delegated_run"):
    texts = by_name.get(name)
    must(texts, f"row {name} not found")
    must(any(". Since 1.17.111" in text for text in texts), f"{name} reads '. Since 1.17.111'")

# the new text of this release is in the export, and reads cleanly too
server = " ".join(by_name["get_server_maintenance_provider"])
for needle in ("now 1.3.0", "(1.2.0 since 1.17.112", "send_signal(*, job_id, name, context, user=None)", "job_not_running", "signal_not_accepted", "waits_for_person",
               "TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR", "TEC_TAC_SERVER_MAINTENANCE_LOCK", "Since 1.17.112"):
    must(needle in server, f"get_server_maintenance_provider names {needle}")
source = SOURCE.read_text(encoding="utf-8")
must("signals, a list of at most 2 different names from continue and abort" in source and "sudo rule reached only --dispatch and --cancel until 1.17.111" in source, "the manifest-key text")

print("[TEST] PASS contract text spacing 1.17.112")
