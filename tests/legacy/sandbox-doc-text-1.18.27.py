#!/usr/bin/env python3
"""1.18.27 regression (from 1.18.26) (AD-65 Patch C, item 2): the contract and the doc say a returned credential is untrusted.

Django-free. Covered:

* the start() and run() purposes in framwork/tec_tac/contracts.py and the 'Credential return' part of docs/sandbox-capability.md carry the same
  sentence, and it matches the needle the canary row pc-returned-credential-untrusted uses;
* the sentence says to check the returned credential against the account of the credential handed in;
* the text says pattern is not a runner parameter field and names max_length, minimum and maximum as whole numbers;
* contracts.py still parses and keeps its CRLF line endings; the doc keeps its LF endings;
* the capability is core.sandbox 1.1.0 since 1.18.27 (additive), and the stale 1.18.25 sentences are still gone.

The contract export test needs Django and cannot run here (the dev server runs tec_tac_check_contract_export).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SENTENCE = ("A returned credential is untrusted: credentials_out comes from a program that ran in the sandbox, so before you store it, "
            "check that it is for the same account as the credential you handed in.")
NEEDLE = re.compile(r"returned credential[^.]{0,120}untrusted|untrusted[^.]{0,120}returned credential", re.IGNORECASE)


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


raw = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes()
must(raw.count(b"\r\n") == raw.count(b"\n") and raw.count(b"\r\n") > 1000, "contracts.py keeps CRLF")
contracts = raw.decode("utf-8")
ast.parse(contracts)
doc_raw = (ROOT / "docs" / "sandbox-capability.md").read_bytes()
must(b"\r" not in doc_raw, "the doc keeps LF")
doc = doc_raw.decode("utf-8")

for name in ("start", "run"):
    start = contracts.index(f'"name": "{name}"', contracts.index('"import_path": "tec_tac.sandbox"') - 400 if name == "start" else contracts.index('"name": "start"'))
    purpose = contracts[start:contracts.index('"audience"', start)]
    must(SENTENCE in purpose, f"the {name}() purpose carries the sentence")
    must(NEEDLE.search(purpose), f"the {name}() purpose matches the canary needle")
must(SENTENCE in doc and NEEDLE.search(doc), "the doc carries the sentence")
must(contracts.count(SENTENCE) == 2 and doc.count(SENTENCE) == 1, "the same wording in both places, once per place")

must("pattern is not a parameter field of a sandbox runner" in contracts and "max_length, minimum and maximum must be whole numbers" in contracts, "the contract names the parameter rule")
must("`pattern` is not a parameter field" in doc and "`max_length` (1 to 65536)" in doc, "the doc names the parameter rule")
must("kills every other process of the run before it reads the file" in doc, "the doc names the launcher's leftover kill")
for stale in ("Public HTTPS stays open", "There is no host list and no proxy", "resolv.conf"):
    must(stale not in doc and stale not in contracts.split("sandbox_runners (extensions only")[1][:6000], stale)
must("capability core.sandbox 1.1.0" in contracts and not re.search(r"core\.sandbox 1\.(?!1\.0)\d+\.\d+", contracts.replace("core.sandbox 1.0.0 then", "")), "the capability is 1.1.0")
caps = (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8")
caps = caps[caps.index("## Core sandbox"):caps.index("## Core server maintenance")]
must("`core.sandbox` 1.1.0" in caps and "1.0.0" not in caps and "sandbox_not_ready" in caps and "`active`" in caps and "not gated by readiness" in caps, "capabilities.md names 1.1.0")
must("still raise `sandbox_disabled`" not in caps and "kill switch stays off" in caps and "enabled` false" in caps, "capabilities.md says the switch is off, not the old 1.0.0 wording")

# 1.18.27-2: the text must match the shipped constant (the switch is off).
sandbox_src = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
must(any(x.split("#")[0].strip() == "SANDBOX_ENABLED = False" for x in sandbox_src.splitlines()), "the shipped constant is False")
for label, body in (("contracts.py", contracts), ("sandbox-capability.md", doc)):
    for bad in ("kill switch is on", "True since Core 1.18.27", "`True` since 1.18.27", "True since 1.18.27", "never on a 1.18.27 build"):
        must(bad not in body, f"{label} says {bad!r} while SANDBOX_ENABLED is False")
must("stays False until AD-65" in contracts and "sandbox_not_ready applies" in contracts, "contracts.py says the switch is off and when the gate applies")
must("stays `False` until AD-65's condition is met" in doc, "the doc status row says enabled is False")
print("[TEST] PASS sandbox doc text 1.18.27")
