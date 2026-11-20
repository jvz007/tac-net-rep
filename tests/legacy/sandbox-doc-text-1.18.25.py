#!/usr/bin/env python3
"""1.18.25 regression (held Low): the sandbox text no longer describes the removed network rule.

Django-free. Covered:

* docs/sandbox-capability.md no longer says 'Public HTTPS stays open', 'There is no host list and no proxy' or mentions resolv.conf;
* it names PrivateNetwork, the egress proxy, allowed_hosts and 'requires.framework >=1.18.24', and says a run without allowed_hosts has no network at all;
* the status route entry in framwork/tec_tac/contracts.py names network_private_ok and egress_ok in its response text, carries the 1.18.25 note, and every
  key that tec_tac.sandbox.status() returns (read from the source with ast) appears in that response text;
* the same stale sentences are not in the newest contract text of the sandbox (contracts.py) or in the docs folder's sandbox pages;
* the capability stays core.sandbox 1.0.0 (text only).

The contract export test needs Django and cannot run here (it runs on the dev server: tec_tac_check_contract_export).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


doc = (ROOT / "docs" / "sandbox-capability.md").read_text(encoding="utf-8")
for stale in ("Public HTTPS stays open", "There is no host list and no proxy", "resolv.conf"):
    must(stale not in doc, f"the doc still says {stale!r}")
for needed in ("PrivateNetwork", "egress proxy", "allowed_hosts", "requires.framework >=1.18.24", "no network at all"):
    must(needed in doc, f"the doc does not name {needed!r}")

contracts_text = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for stale in ("Public HTTPS stays open", "There is no host list and no proxy"):
    must(stale not in contracts_text, f"contracts.py still says {stale!r}")
tree = ast.parse(contracts_text)
entry = None
for node in ast.walk(tree):
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value == "/api/tfd/system/sandbox/status/":
                entry = ast.literal_eval(value)
must(entry is not None, "the status route entry exists")
get = entry["GET"]
response = get["response"]
must("network_private_ok" in response and "egress_ok" in response, response)
must(any("Added in 1.18.25 text only" in note and "since 1.18.24" in note for note in get["notes"]), get["notes"])
must(any("1.17.118" in note for note in get["notes"]), "the earlier note stays")

# every key status() returns is in the response text
source = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
module = ast.parse(source)
keys = set()
for func in module.body:
    if isinstance(func, ast.FunctionDef) and func.name == "status":
        for node in ast.walk(func):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "answer" and isinstance(node.value, ast.Dict):
                keys |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "answer" and isinstance(node.slice, ast.Constant):
                keys.add(node.slice.value)
must(len(keys) >= 12, keys)
missing = sorted(key for key in keys if not re.search(r"\b" + re.escape(key) + r"\b", response))
must(not missing, f"status() returns keys the route text does not name: {missing}")

# the capability version did not change
must("core.sandbox 1.0.0" in contracts_text, "core.sandbox stays 1.0.0")
must(re.search(r'core\.sandbox["\']?\s*[:,]\s*["\']?1\.0\.0', contracts_text) or "core.sandbox 1.0.0" in contracts_text, "version pin")

# no other doc repeats the stale sentences (release notes are history and may)
for path in (ROOT / "docs").glob("*.md"):
    body = path.read_text(encoding="utf-8", errors="replace")
    must("Public HTTPS stays open" not in body, f"{path.name} still says the old rule")
print("[TEST] PASS sandbox doc text 1.18.25")
