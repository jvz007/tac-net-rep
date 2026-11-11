#!/usr/bin/env python3
"""1.17.121 regression: static checks of tests/sandbox-canary-1.17.121.sh (core.sandbox canary: the credential pre-check guard and check 4d).

The script needs root, systemd and Linux, so it did NOT run here. This test reads it as text:

* it keeps every step of the 1.17.118 script (the old script stays as it is) and ends with ALL CANARY STEPS PASSED and the failure count;
* the installed-helper guard needs the numeric address list, so an older helper stops with a plain message;
* step 2 prints the upstream resolvers and points at the dns and bpf_framework rows; step 4 needs the foreign-reader row;
* step 2c loads the installed helper's own ``_exec_escape``, escapes four words, runs them through systemd-run with a dynamic user, compares
  each printed line with the original and calls fail() on a mismatch; the control with an unescaped word and the '%h' / '%%h' lines are
  NOTE lines only (no pass, no fail);
* it never enables the kill switch (no sed on SANDBOX_ENABLED), never holds a real secret, and the bash syntax is clean when bash is present.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NEW = (ROOT / "tests" / "sandbox-canary-1.17.121.sh").read_text(encoding="utf-8")
OLD = (ROOT / "tests" / "sandbox-canary-1.17.118.sh").read_text(encoding="utf-8")
PREV = (ROOT / "tests" / "sandbox-canary-1.17.120.sh").read_text(encoding="utf-8")


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


# ---- the old script is kept, and the new one holds all its steps
must(OLD.count("== step ") == 6 and "Core 1.17.118" in OLD, "the 1.17.118 script is untouched")
for marker in ("== step 1:", "== step 2:", "== step 3:", "== step 4:", "== step 5:", "== step 6:"):
    must(marker in NEW, marker)
old_step5 = OLD[OLD.index("== step 5"):OLD.index("== step 6")].replace("1.17.118", "1.17.121")
must(old_step5 in NEW, "the step 5 lines of the old script are kept word for word")
for check in ("2c", "3a", "3b", "3c", "3d", "3e", "3f", "4d", "5m"):
    must(f'"{check} ' in NEW, check)
must(NEW.rstrip().endswith('if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi'), "the verdict line")
code_lines = [line for line in NEW.splitlines() if not line.lstrip().startswith("#")]
must(not [line for line in code_lines if "1.17.118" in line and "older than Core 1.17.118 (no --canary)" not in line], "the version in every message is 1.17.121")
must("Core 1.17.120 (its address filter" in NEW and "Core 1.17.121 (no credential file pre-check)" in NEW, "guard messages")
must(PREV.count("== step ") == 7 and "Core 1.17.120" in PREV and "4d" not in PREV and "_credential_file_ready" not in PREV, "the 1.17.120 script is untouched")
must("is Core 1.17.121 installed?" in NEW and "tests/sandbox-canary-1.17.121.sh" in NEW, "messages name 1.17.121")

# ---- guards
must("grep -q '127.0.0.0/8' \"$HELPER\"" in NEW and "numeric list" in NEW, "the helper guard needs the numeric string")
must(NEW.index("127.0.0.0/8") < NEW.index("== step 1:"), "the guard runs before any step")

# ---- steps 2 and 4
step2 = NEW[NEW.index("== step 2:"):NEW.index("== step 2c")]
must("/run/systemd/resolve/resolv.conf" in step2 and "bpf_framework" in step2 and "dns" in step2, "step 2 shows the upstream resolvers and the two rows")
step4 = NEW[NEW.index("== step 4:"):NEW.index("== step 5:")]
must("another dynamic user reads the credential file" in step4 and "4c" in step4, "step 4 needs the foreign-reader row")
must("4d" in step4 and "ends with OK" in step4 and "OK$" in step4, "step 4d needs the row to end with OK")
must("_credential_file_ready" in NEW[:NEW.index("== step 1:")] and "MISSING" in NEW[:NEW.index("== step 1:")], "the guard needs the pre-check marker before any step")

# ---- step 2c
step = NEW[NEW.index("== step 2c"):NEW.index("== step 3:")]
must(NEW.index("== step 2:") < NEW.index("== step 2c") < NEW.index("== step 3:"), "2c sits after the selftest step")
must("SourceFileLoader" in step and "_exec_escape" in step and '"$HELPER"' in step, "it loads the installed helper's own escape")
for word in ("plain", "a$HOME b${X} $$", "$$", "$1x"):
    must(f'"{word}"' in step and f"'{word}'" in step, ("the four words", word))
must("systemd-run --pipe --wait --collect --quiet -p DynamicUser=yes" in step, "real systemd-run, dynamic user")
must('"${GOT[$i]-}" = "${WORDS[$i]}"' in step, "each printed line is compared with the original word")
must(re.search(r'else fail "2c word', step), "a mismatch calls fail()")
must('fail "2c the helper' in step, "a broken escape (wrong word count) calls fail()")
must("-E TECTAC_X=probe" in step and "NOTE an unescaped" in step, "the control is information")
must("'%h' '%%h'" in step and "NOTE the unescaped word" in step, "the '%' lines are information")
# the information lines never pass or fail
control = step[step.index("CONTROL="):]
must(not re.search(r"(^|[;&|]\s*|then\s+|else\s+)(pass|fail) \"", control, re.MULTILINE), "the control and '%' lines never call pass or fail")
# the words travel to a python printer: no printf format and no specifier in the program text
must("PRINT_WORDS='import sys;print(*sys.argv[1:],sep=chr(10))'" in step, "no specifier or variable in the printer")

# ---- safety
must("SANDBOX_ENABLED = False" in NEW and not re.search(r"sed[^\n]*SANDBOX_ENABLED", NEW), "the kill switch is checked, never changed")
must("SANDBOX_ENABLED = True" not in NEW, "never enables the switch")
must(not re.search(r"\b[0-9a-f]{40,}\b", NEW) and not re.search(r"(?i)(password|api[_-]?key|BEGIN [A-Z ]*PRIVATE)", NEW), "no real secret")

# ---- shell syntax through bash when it is present (the repo's integrity test also gates every .sh)
bash = shutil.which("bash")
if bash:
    run = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.17.121.sh")], capture_output=True, text=True, check=False)
    must(run.returncode == 0, run.stderr[-500:])

print("[TEST] PASS sandbox canary script 1.17.121")
