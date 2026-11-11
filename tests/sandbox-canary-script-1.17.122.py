#!/usr/bin/env python3
"""1.17.122 regression: static checks of tests/sandbox-canary-1.17.122.sh (core.sandbox canary: ACL guard, credential row, padding-safe patterns).

The script needs root, systemd and Linux, so it did NOT run here. This test reads it as text:

* it keeps every step of the 1.17.121 script (the old script and its static test stay in tests/ untouched) and ends with the same verdict line;
* the installed-helper guard needs the credential ACL decoder (_PROBE_ACL) before any step, besides the older markers;
* step 2 prints the credential row of the selftest on its own line (owner, group, mode and ACL);
* the padding-safe patterns: 4d is grep -Eq 'OK[[:space:]]*$' on the row picked out first by its exact attack text; the three awk counters
  end in [[:space:]]*$; the literal 'OK$' is gone from the code lines;
* it never enables the kill switch, never holds a real secret, and the bash syntax is clean when bash is present.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NEW = (ROOT / "tests" / "sandbox-canary-1.17.122.sh").read_text(encoding="utf-8")
PREV = (ROOT / "tests" / "sandbox-canary-1.17.121.sh").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def code(text):
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


# ---- the old script is kept, and the new one holds all its steps
must("'OK$'" in PREV and "Core 1.17.121" in PREV, "the 1.17.121 script is untouched")
for marker in ("== step 1:", "== step 2:", "== step 2c", "== step 3:", "== step 4:", "== step 5:", "== step 6:"):
    must(marker in NEW, marker)
for check in ("1a", "2a", "2b", "2c", "3a", "3b", "3c", "3d", "3e", "3f", "4a", "4b", "4c", "4d", "5a", "5m"):
    must(f'"{check} ' in NEW, check)
must(NEW.rstrip().endswith('if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi'), "the verdict line")
must(NEW[NEW.index("== step 5:"):] == PREV[PREV.index("== step 5:"):], "step 5 and 6 are word for word the 1.17.121 lines")
must(NEW[NEW.index("== step 2c"):NEW.index("== step 4:")] == PREV[PREV.index("== step 2c"):PREV.index("== step 4:")], "steps 2c and 3 are word for word the 1.17.121 lines")
must("\r" not in NEW, "the shell script keeps LF line endings")

# ---- version strings
must(not [line for line in code(NEW) if "1.17.118" in line and "older than Core 1.17.118 (no --canary)" not in line], "no stale 1.17.118 in a message")
must("is Core 1.17.122 installed?" in NEW and "is it Core 1.17.122?" in NEW and "tests/sandbox-canary-1.17.122.sh" in NEW, "messages name 1.17.122")
must("is Core 1.17.121 installed?" not in NEW and "is it Core 1.17.121?" not in NEW, "no 1.17.121 install message")

# ---- guards (all before step 1)
before = NEW[:NEW.index("== step 1:")]
must("grep -q '127.0.0.0/8' \"$HELPER\"" in before and "_credential_file_ready" in before and "MISSING" in before, "the older guards stay")
must("grep -q '_PROBE_ACL' \"$HELPER\"" in before and "Core 1.17.122 (no credential ACL check)" in before, "the guard needs the ACL decoder")

# ---- step 2 prints the credential row on its own
step2 = NEW[NEW.index("== step 2:"):NEW.index("== step 2c")]
must('checks", {}).get("credential"' in step2 and "owner, group, mode, ACL" in step2 and 'cred.get("detail"' in step2, "step 2 prints the credential detail")
must("bpf_framework" in step2 and "/run/systemd/resolve/resolv.conf" in step2, "the 1.17.120 information stays")

# ---- step 4: padding-safe patterns
step4 = NEW[NEW.index("== step 4:"):NEW.index("== step 5:")]
d4 = [line for line in step4.splitlines() if '"4d ' in line]
must(len(d4) == 1, d4)
line4d = d4[0]
must("grep -F 'another dynamic user reads the credential file' \"$CANARY_OUT\" | grep -Eq 'OK[[:space:]]*$'" in line4d, line4d)
must(line4d.index("grep -F") < line4d.index("grep -Eq"), "the row is selected by its attack text first")
must("NOT RUN" in line4d and "ATTACK SUCCEEDED" in line4d, "the failure text still names the two bad verdicts")
for word in ("ATTACK SUCCEEDED", "SKIPPED", "WARN"):
    must(f"/{word}[[:space:]]*$/" in step4, word)
must(not [line for line in code(NEW) if "OK$" in line.replace("[[:space:]]*$", "")] , "the literal OK$ is not used in a code line")
must(not re.search(r"(ATTACK SUCCEEDED|SKIPPED|WARN)\$/", step4), "no unpadded counter pattern")
must("'^CANARY PASSED$'" in step4, "4a matches a print() line, which has no padding")

# ---- safety
must("SANDBOX_ENABLED = False" in NEW and not re.search(r"sed[^\n]*SANDBOX_ENABLED", NEW), "the kill switch is checked, never changed")
must("SANDBOX_ENABLED = True" not in NEW, "never enables the switch")
must(not re.search(r"\b[0-9a-f]{40,}\b", NEW) and not re.search(r"(?i)(password|api[_-]?key|BEGIN [A-Z ]*PRIVATE)", NEW), "no real secret")

# ---- shell syntax through bash when it is present
bash = shutil.which("bash")
if bash:
    run = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.17.122.sh")], capture_output=True, text=True, check=False)
    must(run.returncode == 0, run.stderr[-500:])

print("[TEST] PASS sandbox canary script 1.17.122")
