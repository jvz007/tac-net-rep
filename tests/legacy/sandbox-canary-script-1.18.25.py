#!/usr/bin/env python3
"""1.18.25 regression: static checks of tests/sandbox-canary-1.18.25.sh (the 1.18.24 script with 8 proxy rows in step 5t, step 5v listing /run/private, and the new step 5w and mode patchc).

The script needs root and systemd, so it did NOT run here. This test reads it as text, compares its step ids with the 1.18.24 script (every id is kept,
5w is new), checks the guards, the exit list text (all 22 named Patch B rows and the nine Patch C rows), 5t to 5v text intact, and runs the 5t/5u/5v function, the 5w function and
the final verdict function in bash against a fake driver and a fake audit file (skipped, and said so, where bash is not usable).
"""
from __future__ import annotations

import importlib.util
import json
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


SCRIPT = ROOT / "tests" / "sandbox-canary-1.18.25.sh"
NEW = SCRIPT.read_text(encoding="utf-8")
OLD = (ROOT / "tests" / "sandbox-canary-1.18.24.sh").read_text(encoding="utf-8")
must(b"\r" not in SCRIPT.read_bytes(), "LF only")
must("ALL CANARY STEPS PASSED" in NEW and "STEP(S) FAILED" in NEW, "verdict line")
must("1.18.25" in NEW and "sandbox-canary-1.18.24" not in NEW and "sandbox-canary-1.18.23" not in NEW.replace("changes from the 1.18.23 script", "") and "sandbox-canary-1.18.22" not in NEW, "version and old script names")
spec = importlib.util.spec_from_file_location("canary_network_driver_for_script_125", ROOT / "tests" / "sandbox-canary-network-1.18.25.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
spec = importlib.util.spec_from_file_location("canary_patchc_driver_for_script_125", ROOT / "tests" / "sandbox-canary-patchc-1.18.25.py")
PC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PC)


def step_ids(text):
    return set(re.findall(r'(?:pass|fail) "([0-9][0-9a-z]*) ', text))


must(step_ids(OLD) <= step_ids(NEW), step_ids(OLD) - step_ids(NEW))
must({"5t", "5u", "5v", "5w"} <= step_ids(NEW) and "5w" not in step_ids(OLD) and {"5t", "5u", "5v"} <= step_ids(OLD), "5w is new; 5t, 5u and 5v stay")
for text in ("4k", "4l", "4m", "4n", "4o", "4p", "5s", "5r", "4u", "5t"):
    must(text in step_ids(NEW), text)

# ---- the guards
must("grep -q 'PrivateNetwork=yes' \"$HELPER\" ||" in NEW and "update Core first" in NEW, "Patch B guard: PrivateNetwork=yes is required")
must("grep -q 'PrivateNetwork=yes' \"$HELPER\" &&" not in NEW, "the 'refuse a helper with PrivateNetwork=yes' guard of 1.18.23 is gone")
must("grep -q 'AF_INET AF_UNIX' \"$HELPER\" ||" in NEW and "grep -q 'AF_INET AF_UNIX' \"$HELPER\" &&" not in NEW, "the AF_UNIX guard is turned around")
must("grep -q 'door_row' \"$LIB/canary/sandbox-canary-runner.py\"" in NEW and "no door_row" in NEW, "an older installed runner is refused")
must("egress_remove_state" in NEW and "own_server_names" in NEW and "patchc_syscalls" in NEW and "no patchc_syscalls or own_name" in NEW, "the 1.18.25 guards")
must("$LIB/sandbox-egress.py" in NEW and "tec-tac-sandbox-egress@.socket" in NEW and "tec-tac-sandbox-egress@.service" in NEW, "the installed egress program and both template units are required")
must("parse_abstract_sockets resolv_conf_bind" not in NEW and "parse_abstract_sockets egress_start" in NEW, "the removed marker is no longer required")

# ---- the exit list: all 22 Patch B rows, no 'expected before' list
line = next(item for item in NEW.splitlines() if item.lstrip().startswith('echo "Patch B exit list'))
for rid in (*D.EXIT_LIST_FORMER_ATTACK, *D.EXIT_LIST_PROXY, *D.EXIT_LIST_ALSO):
    must(rid in line, ("the exit list text names", rid))
must(len(D.EXIT_LIST_FORMER_ATTACK) + len(D.EXIT_LIST_PROXY) + len(D.EXIT_LIST_ALSO) == 22 and len(D.EXIT_LIST_PROXY) == 8 and "pb-proxy-refuse-own-domain" in D.EXIT_LIST_PROXY, "12 + 8 + 2 named rows")
must("the 8 proxy rows" in line and "the 7 proxy rows" not in line, "the exit text says 8 proxy rows")
must("0 NOT RUN" in line and "0 ATTACK SUCCEEDED" in line and "pb-tcp-443-ipv6" in line, "the exit wording and the one allowed SKIPPED row")
must("expected before Patch B" not in NEW.split("# 1.18.23 changes from the 1.18.22 script")[0] and 'echo "expected before Patch B' not in NEW, "the old list is not printed")
must('"$SCRIPT_DIR/sandbox-canary-network-1.18.25.py"' in NEW and '"$SCRIPT_DIR/sandbox-canary-network-1.18.24.py"' not in NEW, "step 5t starts the new driver")
must((ROOT / "tests" / "legacy" / "sandbox-canary-1.18.23.sh").is_file() or (ROOT / "tests" / "sandbox-canary-1.18.24.sh").is_file(), "the 1.18.24 script stays in tests/ or legacy/")
# ---- 5t, 5u, 5v text intact (only the proxy row count and the 5v failure listing changed)
for text in ('pass "5u run.egress was written before run.ended for the run with a door, with numbers only"', 'pass "5v no egress unit, door folder, configuration or audit state is left"',
             'fail "5v something of the egress door is left (listed above)"', 'echo "== step 5t: the Patch B exit list: the 12 former ATTACK rows OK, the 8 proxy rows OK (positive control 200), 0 NOT RUN, 0 ATTACK SUCCEEDED"'):
    must(text in NEW, text)
must("/run/private/tec-tac-sbx-egress" in NEW and "ls -A /run/tec-tac-sbx-egress" in NEW, "5v keeps its condition and lists the private target on failure")
# ---- 5w: every Patch C row named, patchc mode, the summary the step greps
patchc_text = "\n".join(item for item in NEW.splitlines() if item.lstrip().startswith(('echo "== step 5w', 'echo "Patch C rows')))
for rid in PC.ROW_IDS:
    must(rid in patchc_text, ("the Patch C text names", rid))
must("PATCH C ROWS" in NEW and "NOT RUN \\(reason\\), 0 OK" in NEW and 'pass "5w' in NEW and 'fail "5w' in NEW, "5w greps the driver's summary and requires 0 OK")
must('"$SCRIPT_DIR/sandbox-canary-patchc-1.18.25.py"' in NEW, "step 5w starts the Patch C driver")

# ---- structure
lines = NEW.splitlines()
must('[ "$MODE" != "network" ]' in NEW and 'if [ "$MODE" = "network" ]; then network_step_5t; finish; fi' in NEW, "network mode")
must('if [ "$MODE" = "patchc" ]; then patchc_step_5w; finish; fi' in NEW and '"$MODE" != "patchc"' in NEW and "before, network, patchc" in NEW, "patchc mode")
step_2c = next(i for i, item in enumerate(lines) if item.startswith('echo "== step 2c'))
must(lines.index('if [ "$MODE" = "network" ]; then network_step_5t; finish; fi') < step_2c and lines.index('if [ "$MODE" = "patchc" ]; then patchc_step_5w; finish; fi') < step_2c, "both modes end before step 2c")
call = max(i for i, item in enumerate(lines) if item == "network_step_5t")
must(next(i for i, item in enumerate(lines) if item.startswith('echo "== step 5s')) < call < lines.index('echo "== step 6: YOURS (not scripted)"'), "5t sits between 5s and 6")
call_w = max(i for i, item in enumerate(lines) if item == "patchc_step_5w")
must(call < call_w < lines.index('echo "== step 6: YOURS (not scripted)"'), "5w runs right after 5t (and so after 5v)")
must(lines[-1] == "finish", "the script ends in the verdict function")
for counter in ("ATTACKS=", "NOTRUN=", "SKIPPED_SECURITY="):
    counter_line = next(item for item in lines if item.startswith(counter))
    must("$0 !~ /^DETAIL /" in counter_line and "NET_OUT" not in counter_line and '"$CANARY_OUT"' in counter_line, counter)
skipped_line = next(item for item in lines if item.startswith("SKIPPED_SECURITY="))
must("public tcp 443" not in skipped_line, "no row of the normal table may be SKIPPED any more")
for retired in ("unix socket creation refused", "unix pathname socket refused", "allowed resolver answers", "other resolver"):
    must(retired not in "\n".join(item for item in lines if item.startswith(("row_ok", "for ", "  row_ok", "[ "))), ("a retired row is still required", retired))
must("unix door path without a door" in NEW, "the new door row is required")
must("egress_allowed" in NEW and "run.egress" in NEW, "the audit check knows the egress keys and the new event")

bash = shutil.which("bash")
usable = False
if bash:
    probe = subprocess.run([bash, "-c", "echo ok"], capture_output=True, text=True, check=False)
    usable = probe.returncode == 0 and probe.stdout.strip() == "ok"
    done = subprocess.run([bash, "-n", SCRIPT.as_posix()], capture_output=True, text=True, check=False)
    must(done.returncode == 0, done.stderr)
if not usable:
    print("[SKIP] bash is not usable here: the 5t, 5u, 5v and verdict functions were not run")
else:
    def function(name):
        start = lines.index(name + "() {")
        end = start + 1
        while lines[end] != "}":
            end += 1
        return "\n".join(lines[start:end + 1])

    python = Path(sys.executable).as_posix()
    prelude = ('pass() { echo "PASS $1"; }\nfail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }\nFAILS=0\n'
               f'python3() {{ "{python}" "$@"; }}\nsystemctl() {{ true; }}\n')
    EVENTS_GOOD = [("run.started", {}), ("run.egress", {"allowed": 1, "refused": 7, "bytes": 99, "rows": []}),
                   ("run.ended", {"egress_allowed": 1, "egress_refused": 7, "egress_bytes": 99})]

    def run_5t(driver_body, events=None, with_driver=True, left=False):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audit = tmp_path / "audit.jsonl"
            audit.write_text(json.dumps({"event": "sweep", "detail": {}}) + "\n", encoding="utf-8")
            (tmp_path / "rows.json").write_text(json.dumps([{"event": e, "detail": d} for e, d in (events if events is not None else EVENTS_GOOD)]), encoding="utf-8")
            if left:
                (tmp_path / "egress-door").mkdir()
                (tmp_path / "egress-door" / "left").write_text("x", encoding="utf-8")
            if with_driver:
                body = ("import json, sys\n"
                        f"rows = json.load(open({str(tmp_path / 'rows.json')!r}))\n"
                        f"with open({str(audit)!r}, 'a') as h:\n"
                        "    for r in rows:\n"
                        "        h.write(json.dumps(r) + chr(10))\n") + driver_body
                (tmp_path / "sandbox-canary-network-1.18.25.py").write_text(body, encoding="utf-8")
            script = (prelude + f'SCRIPT_DIR="{tmp_path.as_posix()}"\nSTATE="{tmp_path.as_posix()}"\nRUN="{tmp_path.as_posix()}"\n'
                      + function("network_step_5t") + '\nnetwork_step_5t\necho "FAILS=$FAILS"\n')
            done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
            return done.stdout

    good = run_5t('print("ok   pb-public-tcp-443-1-1-1-1: OK: OK")\nsys.exit(0)\n')
    must("PASS 5t" in good and "PASS 5u" in good and "PASS 5v" in good and "FAILS=0" in good, good)
    hole = run_5t('print("FAIL pb-own-address: ATTACK SUCCEEDED: ATTACK SUCCEEDED (a real hole)")\nsys.exit(1)\n')
    must("FAIL 5t" in hole and "a real hole" in hole and "PASS 5u" in hole, hole)
    notrun = run_5t('print("FAIL pb-proxy-allowed-443: NOT RUN: NOT RUN (the probe did not run)")\nsys.exit(1)\n')
    must("FAIL 5t" in notrun and "FAILS=1" in notrun, notrun)
    no_start = run_5t('sys.exit(2)\n')
    must("FAIL 5t" in no_start and "driver exit 2" in no_start, no_start)
    missing = run_5t("", with_driver=False)
    must("FAIL 5t" in missing and "not next to this script" in missing, missing)
    late = run_5t('sys.exit(0)\n', events=[("run.started", {}), ("run.ended", {"egress_allowed": 0, "egress_refused": 0, "egress_bytes": 0}),
                                           ("run.egress", {"allowed": 0, "refused": 7, "bytes": 0})])
    must("FAIL 5u" in late and "no run.ended after run.egress" in late, late)
    few = run_5t('sys.exit(0)\n', events=[("run.started", {}), ("run.egress", {"allowed": 1, "refused": 2, "bytes": 3}),
                                          ("run.ended", {"egress_allowed": 1, "egress_refused": 2, "egress_bytes": 3})])
    must("FAIL 5u" in few and "counts look wrong" in few, few)
    absent = run_5t('sys.exit(0)\n', events=[("run.started", {}), ("run.ended", {})])
    must("FAIL 5u" in absent and "no run.egress row" in absent, absent)
    leaky = run_5t('sys.exit(0)\n', events=[("run.started", {}), ("run.egress", {"allowed": 1, "refused": 7, "bytes": 9, "rows": [{"host": "Bearer abc"}]}),
                                            ("run.ended", {"egress_allowed": 1, "egress_refused": 7, "egress_bytes": 9})])
    must("FAIL 5u" in leaky and "holds a header" in leaky, leaky)
    left = run_5t('sys.exit(0)\n', left=True)
    must("FAIL 5v" in left and "PASS 5u" in left, left)

    def run_5w(driver_body, with_driver=True):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            if with_driver:
                (tmp_path / "sandbox-canary-patchc-1.18.25.py").write_text("import sys\n" + driver_body, encoding="utf-8")
            script = (prelude + f'SCRIPT_DIR="{tmp_path.as_posix()}"\n' + function("patchc_step_5w") + '\npatchc_step_5w\necho "FAILS=$FAILS"\n')
            return subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False).stdout

    summary_ok = 'print("PATCH C ROWS: 9 ATTACK SUCCEEDED, 0 NOT RUN (reason), 0 OK; expected: x")\n'
    good = run_5w(summary_ok + "sys.exit(0)\n")
    must("PASS 5w" in good and "FAILS=0" in good, good)
    good = run_5w('print("PATCH C ROWS: 6 ATTACK SUCCEEDED, 3 NOT RUN (reason), 0 OK; expected: x")\nsys.exit(0)\n')
    must("PASS 5w" in good, good)
    ok_row = run_5w('print("PATCH C ROWS: 8 ATTACK SUCCEEDED, 0 NOT RUN (reason), 1 OK; expected: x")\nsys.exit(1)\n')
    must("FAIL 5w" in ok_row and "FAILS=1" in ok_row and "proves nothing" in ok_row, ok_row)
    sneaky = run_5w('print("PATCH C ROWS: 8 ATTACK SUCCEEDED, 0 NOT RUN (reason), 1 OK; expected: x")\nsys.exit(0)\n')
    must("FAIL 5w" in sneaky, "an OK row fails the step even when the driver exits 0")
    silent = run_5w("sys.exit(0)\n")
    must("FAIL 5w" in silent, "a driver that prints no summary fails")
    no_unit = run_5w("sys.exit(2)\n")
    must("FAIL 5w" in no_unit and "driver exit 2" in no_unit, no_unit)
    missing_w = run_5w("", with_driver=False)
    must("FAIL 5w" in missing_w and "not next to this script" in missing_w, missing_w)

    def run_finish(fails):
        script = prelude + f"FAILS={fails}\n" + function("finish") + "\nfinish\n"
        done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
        return done.returncode, done.stdout.splitlines()

    code, out = run_finish(0)
    must(code == 0 and out[1] == "ALL CANARY STEPS PASSED" and out[2].startswith("Patch B exit list (all must be OK, 0 NOT RUN, 0 ATTACK SUCCEEDED)") and "pb-proxy-refuse-own-domain" in out[2], out)
    must(out[3].startswith("Patch C rows (step 5w") and all(rid in out[3] for rid in PC.ROW_IDS), out)
    code, out = run_finish(2)
    must(code == 1 and out[1] == "2 STEP(S) FAILED" and out[2].startswith("Patch B exit list"), out)
    print("bash part ran: 9 step 5t/5u/5v samples, 7 step 5w samples and 2 verdict samples")
print("[TEST] PASS sandbox canary script 1.18.25")
