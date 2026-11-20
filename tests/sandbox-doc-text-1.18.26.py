#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 2): the contract and the doc say a returned credential is untrusted.

Django-free. Covered:

* the start() and run() purposes in framwork/tec_tac/contracts.py and the 'Credential return' part of docs/sandbox-capability.md carry the same
  sentence, and it matches the needle the canary row pc-returned-credential-untrusted uses;
* the sentence says to check the returned credential against the account of the credential handed in;
* the text says pattern is not a runner parameter field and names max_length, minimum and maximum as whole numbers;
* contracts.py still parses and keeps its CRLF line endings; the doc keeps its LF endings;
* the capability stays core.sandbox 1.0.0 (wording only), and the stale 1.18.25 sentences are still gone.

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
must("capability core.sandbox 1.0.0" in contracts and not re.search(r"core\.sandbox 1\.(?!0\.0)\d+\.\d+", contracts), "the capability stays 1.0.0")
print("[TEST] PASS sandbox doc text 1.18.26")
