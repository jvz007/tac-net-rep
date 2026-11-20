#!/usr/bin/env python3
"""1.18.28 regression (from 1.18.27) (AD-65 amendment: the switch is on and no text says it is off or held; the held 1.18.27 Low on the start row and sudo-rule bullet; AD-65 Patch C, item 2: the contract and the doc say a returned credential is untrusted.

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
must("still raise `sandbox_disabled`" not in caps and "until AD-65's switch-on condition" not in caps and "`enabled` true" in caps and "since Core 1.18.28" in caps and "canary_ok" in caps, "capabilities.md says the switch is on and active needs canary_ok")

# 1.18.28: the text must match the shipped constant (the switch is on) and carry no stale wording.
sandbox_src = (ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
helper_src = (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must(any(x.split("#")[0].strip() == "SANDBOX_ENABLED = True" for x in sandbox_src.splitlines()), "the shipped constant is True")
must(any(x.split("#")[0].strip() == "SANDBOX_ENABLED = True" for x in helper_src.splitlines()), "the helper constant is True")
must("sandbox_not_ready applies" in contracts and "kill switch is on since Core 1.18.28" in contracts, "contracts.py says the switch is on and when the gate applies")
must("`True` since 1.18.28" in doc and "`sandbox_disabled`" in doc and "since Core 1.18.28" in doc, "the doc status and intro rows say enabled is True")
# the held 1.18.27 Low: the start row and the sudo-rule bullet describe the switched-on state
start_row = next(x for x in doc.splitlines() if x.startswith("| `start(...)`"))
sudo_rule = next(x for x in doc.splitlines() if x.startswith("- One sudo rule for the Tactical service account"))
must("sandbox_not_ready" in start_row and "sandbox_disabled" in start_row, "the start row")
must("sandbox_not_ready" in sudo_rule and "sandbox_disabled" in sudo_rule, "the sudo-rule bullet")

# ---- no stale off/held wording anywhere a module or an administrator reads it (review of the first 1.18.28 build)
STALE = ("stays off in this", "switch stays", "kill switch is off", "is off in ", "switch-on is held", "switch-on built in", "switched off", "shipped-off", "enabled stays False",
         "`enabled` false", "enabled` false", "False in 1.18", "held until", "switch-on was built", "kill switch is held")
SANDBOX_ONLY = {"contracts.py", "apps.py", "install.sh", "capabilities.md"}  # files that also talk about other capabilities: only their sandbox lines count
sources = {
    "contracts.py": contracts, "sandbox.py": sandbox_src, "sandbox-helper.py": helper_src,
    "sandbox-selftest.py": (ROOT / "scripts" / "sandbox-selftest.py").read_text(encoding="utf-8"),
    "apps.py": (ROOT / "framwork" / "tec_tac" / "apps.py").read_text(encoding="utf-8"),
    "install.sh": (ROOT / "install.sh").read_text(encoding="utf-8"),
    "sandbox-capability.md": doc, "capabilities.md": (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8"),
}
HELD_SWITCH = re.compile(r"(?i)kill.switch[^.]{0,80}\bheld\b|\bheld\b[^.]{0,80}kill.switch")
DISABLED_NORMAL = re.compile(r"(?i)sandbox_disabled[^.;]{0,80}(while it is off|shipped state|is the normal state|because the switch is off)")
DEFINES_ACTIVE = re.compile(r"(?i)\bactive\b[^.\n]{0,40}(?:is|means|=)[^.\n]{0,40}enabled|\(enabled and ready[^)]*\)|enabled and ready")
for name, text in sources.items():
    for number, line in enumerate(text.splitlines(), 1):
        if name in SANDBOX_ONLY and "sandbox" not in line.lower():
            continue
        for phrase in STALE:
            must(phrase not in line, f"{name}:{number} still says {phrase!r}")
        must(not HELD_SWITCH.search(line), f"{name}:{number} says the kill switch is held")
        must(not DISABLED_NORMAL.search(line), f"{name}:{number} presents sandbox_disabled as the normal state")
        # every definition of active names canary_ok (the round-1 miss: 'active (enabled and ready)')
        for hit in DEFINES_ACTIVE.finditer(line):
            tail = line[hit.start():hit.end() + 70]
            must("canary_ok" in tail, f"{name}:{number} defines active without canary_ok: {tail!r}")
# the old gate sentence that defined readiness without the canary
must(not re.search(r"kill switch is on[^.]*unless this server's selftest is ready;", contracts), "contracts.py still has the selftest-only gate sentence")
must("selftest is ready and a full canary has passed" in contracts, "the consumer note names the canary")

# the registered notes and description agree with the code constants
for needle in ("the kill switch is on", "enabled is True", "canary_ok", "sandbox_not_ready"):
    must(needle in sandbox_src, "sandbox.py notes carry: " + needle)
must("On since Core 1.18.28" in sandbox_src, "the registered description says on since 1.18.28")
print("[TEST] PASS sandbox doc text 1.18.28")
