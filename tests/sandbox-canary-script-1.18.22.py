#!/usr/bin/env python3
"""1.18.22 regression: static checks of tests/sandbox-canary-1.18.22.sh (step 4u reads the DETAIL line of the memory row).

The script needs root and systemd, so it did NOT run here. This test reads it as text, compares its step labels with the 1.18.17 script and runs the
4u lines in bash against sample outputs (skipped, and said so, where bash is not usable).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


NEW = (ROOT / "tests" / "sandbox-canary-1.18.22.sh").read_text(encoding="utf-8")
OLD = (ROOT / "tests" / "sandbox-canary-1.18.17.sh").read_text(encoding="utf-8")
must(b"\r" not in (ROOT / "tests" / "sandbox-canary-1.18.22.sh").read_bytes(), "LF only")
must("ALL CANARY STEPS PASSED" in NEW, "verdict line")
must("copy tests/sandbox-canary-1.18.22.sh" in NEW or "1.18.22" in NEW, "version")
must(NEW.count("sandbox-canary-1.18.17.sh") == 0, "old script name gone")


def step_ids(text):
    return set(re.findall(r'(?:pass|fail) "([0-9][0-9a-z]*) ', text))


must(step_ids(OLD) <= step_ids(NEW), step_ids(OLD) - step_ids(NEW))
changed = [l for l in OLD.splitlines() if l not in NEW.splitlines() and ('pass "' in l or 'fail "' in l)]
must(len(changed) == 1 and "4u" in changed[0], changed)
must("^DETAIL memory-beyond-memorymax " in NEW, "reads the DETAIL line")
for counter in ("ATTACKS=", "NOTRUN=", "SKIPPED_SECURITY="):
    line = next(l for l in NEW.splitlines() if l.startswith(counter))
    must("$0 !~ /^DETAIL /" in line, counter)
must("detail_lines" in NEW, "guard marker")
must("detail_lines" in (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8"), "marker is real")

bash = shutil.which("bash")
usable = False
if bash:
    probe = subprocess.run([bash, "-c", "echo ok"], capture_output=True, text=True, check=False)
    usable = probe.returncode == 0 and probe.stdout.strip() == "ok"
    done = subprocess.run([bash, "-n", str(ROOT / "tests" / "sandbox-canary-1.18.22.sh")], capture_output=True, text=True, check=False)
    must(done.returncode == 0, done.stderr)
if not usable:
    print("[SKIP] bash is not usable here: the 4u run part was not made")
else:
    lines = NEW.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("MEMDETAIL="))
    block = "\n".join(lines[start:start + 2])
    must('pass "4u' in block and 'fail "4u' in block, "block holds 4u")
    PROOF = ("DETAIL memory-beyond-memorymax allocated 112 MiB, ended oom, killed by signal 9, unit result oom-kill, oom_kills 0, peak 127.9 MiB, "
             "evidence unit_result, memory.events max 1; proof: systemd unit result oom-kill")
    NOPROOF = ("DETAIL memory-beyond-memorymax allocated 112 MiB, ended oom, killed by signal 9, unit result oom-kill, oom_kills 0, peak 127.9 MiB, "
               "evidence unit_result, memory.events max 0")
    BAD = "DETAIL memory-beyond-memorymax allocated 112 MiB, ended exited (exit 1), oom_kills 0, no peak; no evidence of how it ended"
    TABLE = "Limits  memory beyond MemoryMax  stopped  allocated 112 MiB, ended oom, evidence unit_result, memory.events max  OK"

    def run(sample):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.txt"
            out.write_text(sample, encoding="utf-8")
            script = 'pass() { echo "PASS $1"; }\nfail() { echo "FAIL $1"; }\nCANARY_OUT="$1"\n' + block + "\n"
            done = subprocess.run([bash, "-c", script, "x", out.as_posix()], capture_output=True, text=True, check=False)
            return done.stdout

    must(run("ROW memory-beyond-memorymax OK\n" + PROOF + "\n").startswith("PASS 4u"), "proof")
    must(run("ROW memory-beyond-memorymax OK\n" + NOPROOF + "\n").startswith("PASS 4u"), "combination without the proof text")
    must(run("ROW memory-beyond-memorymax OK\n" + BAD + "\n").startswith("FAIL 4u"), "no evidence")
    must(run("ROW memory-beyond-memorymax OK\n").startswith("FAIL 4u"), "no DETAIL line")
    must(run(TABLE + "\nROW memory-beyond-memorymax OK\n").startswith("FAIL 4u"), "a table line alone (no proof, no unit result) fails")
    print("bash part ran: 5 samples")
print("[TEST] PASS sandbox canary script 1.18.22")
