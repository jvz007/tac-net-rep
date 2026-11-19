#!/usr/bin/env python3
"""1.18.23 regression: static checks of tests/sandbox-canary-1.18.23.sh (the 1.18.22 script plus step 5t, the Patch B network rows).

The script needs root and systemd, so it did NOT run here. This test reads it as text, compares its step ids with the 1.18.22 script, and runs the
step 5t function and the final verdict function in bash against a fake driver (skipped, and said so, where bash is not usable).
"""
from __future__ import annotations

import importlib.util
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


SCRIPT = ROOT / "tests" / "sandbox-canary-1.18.23.sh"
NEW = SCRIPT.read_text(encoding="utf-8")
OLD = (ROOT / "tests" / "sandbox-canary-1.18.22.sh").read_text(encoding="utf-8")
must(b"\r" not in SCRIPT.read_bytes(), "LF only")
must("ALL CANARY STEPS PASSED" in NEW and "STEP(S) FAILED" in NEW, "verdict line")
must("1.18.23" in NEW and NEW.count("sandbox-canary-1.18.22") == 0 and NEW.count("sandbox-canary-1.18.17.sh") == 0, "version and old script names")
spec = importlib.util.spec_from_file_location("canary_network_driver_for_script", ROOT / "tests" / "sandbox-canary-network-1.18.23.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def step_ids(text):
    return set(re.findall(r'(?:pass|fail) "([0-9][0-9a-z]*) ', text))


must(step_ids(OLD) <= step_ids(NEW), step_ids(OLD) - step_ids(NEW))
must("5t" in step_ids(NEW) and "5t" not in step_ids(OLD), "step 5t is new")
version_only = OLD.replace("1.18.22", "1.18.23")
changed = [line for line in OLD.splitlines() if line not in NEW.splitlines() and ('pass "' in line or 'fail "' in line)
           and version_only.splitlines()[OLD.splitlines().index(line)] not in NEW.splitlines()]
must(not changed, changed)
for text in ("4k", "4l", "4m", "5s", "5r", "4u"):
    must(text in step_ids(NEW), text)

# the new parts exist
must('[ "$MODE" != "network" ]' in NEW and 'if [ "$MODE" = "network" ]; then network_step_5t; finish; fi' in NEW, "network mode")
must("grep -q 'patchb_network' \"$LIB/canary/sandbox-canary-runner.py\"" in NEW and "update Core first" in NEW, "runner guard")
must("grep -q 'PrivateNetwork=yes' \"$HELPER\"" in NEW, "Patch B guard")
must("expected before Patch B:" in NEW, "the expected list line")
must("must all be OK, with 0 NOT RUN, in the Patch B canary." in NEW, "exit list wording")
for rid in D.EXPECTED_ATTACK_TODAY + D.EXPECTED_NOT_RUN_TODAY + D.EITHER_TODAY:
    must(rid in NEW, rid)
line = next(item for item in NEW.splitlines() if 'echo "expected before Patch B:' in item)
must(", ".join(D.EXPECTED_ATTACK_TODAY) in line and ", ".join(D.EXPECTED_NOT_RUN_TODAY) in line, "the lists in the script are the driver's lists")
lines = NEW.splitlines()
must(lines.index('if [ "$MODE" = "network" ]; then network_step_5t; finish; fi') < lines.index('echo "== step 2c: the helper\'s own \'\\$\' escape against real systemd (a wrong escape fails the canary)"'),
     "network mode ends before step 2c")
call = max(i for i, item in enumerate(lines) if item == "network_step_5t")
must(lines.index(next(item for item in lines if item.startswith('echo "== step 5s'))) < call < lines.index('echo "== step 6: YOURS (not scripted)"'), "5t sits between 5s and 6")
must(lines[-1] == "finish", "the script ends in the verdict function")
for counter in ("ATTACKS=", "NOTRUN=", "SKIPPED_SECURITY="):
    counter_line = next(item for item in lines if item.startswith(counter))
    must("$0 !~ /^DETAIL /" in counter_line and "NET_OUT" not in counter_line and '"$CANARY_OUT"' in counter_line, counter)
must("NET_OUT" not in "\n".join(item for item in lines if "CANARY_OUT" in item), "the network output never mixes with the canary output")
for helper_text in ("patchb_network",):
    must(helper_text in (ROOT / "scripts" / "sandbox-canary-runner.py").read_text(encoding="utf-8"), "the marker is real")

bash = shutil.which("bash")
usable = False
if bash:
    probe = subprocess.run([bash, "-c", "echo ok"], capture_output=True, text=True, check=False)
    usable = probe.returncode == 0 and probe.stdout.strip() == "ok"
    done = subprocess.run([bash, "-n", SCRIPT.as_posix()], capture_output=True, text=True, check=False)
    must(done.returncode == 0, done.stderr)
if not usable:
    print("[SKIP] bash is not usable here: the 5t and verdict functions were not run")
else:
    def function(name):
        start = lines.index(name + "() {")
        end = start + 1
        while lines[end] != "}":
            end += 1
        return "\n".join(lines[start:end + 1])

    python = Path(sys.executable).as_posix()
    prelude = ('pass() { echo "PASS $1"; }\nfail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }\nFAILS=0\n'
               f'python3() {{ "{python}" "$@"; }}\n')

    def run_5t(driver_body, with_driver=True):
        with tempfile.TemporaryDirectory() as tmp:
            if with_driver:
                (Path(tmp) / "sandbox-canary-network-1.18.23.py").write_text(driver_body, encoding="utf-8")
            script = prelude + f'SCRIPT_DIR="{Path(tmp).as_posix()}"\n' + function("network_step_5t") + '\nnetwork_step_5t\necho "FAILS=$FAILS"\n'
            done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
            return done.stdout

    good = run_5t('import sys\nprint("ROW pb-public-tcp-443-1-1-1-1 ATTACK SUCCEEDED")\nprint("ok   pb-public-tcp-443-1-1-1-1: ATTACK SUCCEEDED: as expected")\nsys.exit(0)\n')
    must("PASS 5t" in good and "FAILS=0" in good and "ATTACK SUCCEEDED" in good, good)
    hole = run_5t('import sys\nprint("FAIL pb-own-address: ATTACK SUCCEEDED: UNEXPECTED (a real hole today)")\nsys.exit(1)\n')
    must("FAIL 5t" in hole and "FAILS=1" in hole and "a real hole today" in hole, hole)
    nothing = run_5t('import sys\nprint("FAIL pb-proc-net-tcp: OK: proves nothing")\nsys.exit(1)\n')
    must("FAIL 5t" in nothing and "FAILS=1" in nothing, nothing)
    no_start = run_5t('import sys\nsys.exit(2)\n')
    must("FAIL 5t" in no_start and "driver exit 2" in no_start, no_start)
    missing = run_5t("", with_driver=False)
    must("FAIL 5t" in missing and "not next to this script" in missing, missing)

    def run_finish(fails):
        script = prelude + f"FAILS={fails}\n" + function("finish") + "\nfinish\n"
        done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
        return done.returncode, done.stdout.splitlines()

    code, out = run_finish(0)
    must(code == 0 and out[1] == "ALL CANARY STEPS PASSED" and out[2].startswith("expected before Patch B: ATTACK SUCCEEDED rows "), out)
    code, out = run_finish(2)
    must(code == 1 and out[1] == "2 STEP(S) FAILED" and out[2].startswith("expected before Patch B:"), out)
    print("bash part ran: 5 step 5t samples and 2 verdict samples")
print("[TEST] PASS sandbox canary script 1.18.23")
