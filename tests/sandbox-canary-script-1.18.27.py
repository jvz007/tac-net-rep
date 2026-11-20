#!/usr/bin/env python3
"""1.18.27 regression (from the 1.18.26 test): static checks of tests/sandbox-canary-1.18.27.sh (the 1.18.26 script flipped for the switch-on: no OFF expectation left, the new step 6 with 6a to 6d, the trap that restores status.json).

The 1.18.26 checks below are kept (guards, exit lists, 5t/5u/5v, 5w, structure); the changed ones say so.

The script needs root and systemd, so it did NOT run here. This test reads it as text, compares its step ids with the 1.18.25 script (every id is kept, 3g, 3h and 3i are
new), checks the guards (installed helper, selftest file, launcher, egress program and canary runner equal the source by SHA-256; selftest file root:root 0700; the -I shebang; the
sudoers line unchanged and without the selftest file), the exit list text (all 23 named Patch B rows and the nine Patch C rows), the selftest commands, 5t to 5v text intact, and
runs the 5t/5u/5v function, the 5w function (OK expected now: an ATTACK SUCCEEDED row or a NOT RUN without a reason fails) and the final verdict function in bash against a fake
driver and a fake audit file (skipped, and said so, where bash is not usable). No listener on 0.0.0.0 anywhere in the script.
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


SCRIPT = ROOT / "tests" / "sandbox-canary-1.18.27.sh"
NEW = SCRIPT.read_text(encoding="utf-8")
OLD = (ROOT / "tests" / "sandbox-canary-1.18.26.sh").read_text(encoding="utf-8")
must(b"\r" not in SCRIPT.read_bytes(), "LF only")
must("ALL CANARY STEPS PASSED" in NEW and "STEP(S) FAILED" in NEW, "verdict line")
must("1.18.27" in NEW and "sandbox-canary-1.18.26" not in NEW and "sandbox-canary-1.18.25" not in NEW.replace("changes from the 1.18.25 script", "") and "sandbox-canary-1.18.24" not in NEW and "sandbox-canary-1.18.22" not in NEW, "version and script names point at 1.18.27")
spec = importlib.util.spec_from_file_location("canary_network_driver_for_script_127", ROOT / "tests" / "sandbox-canary-network-1.18.27.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
spec = importlib.util.spec_from_file_location("canary_patchc_driver_for_script_127", ROOT / "tests" / "sandbox-canary-patchc-1.18.27.py")
PC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PC)


def step_ids(text):
    return set(re.findall(r'(?:pass|fail) "([0-9][0-9a-z]*) ', text))


must(step_ids(OLD) <= step_ids(NEW), step_ids(OLD) - step_ids(NEW))
must({"5t", "5u", "5v", "5w"} <= step_ids(NEW) and {"5t", "5u", "5v", "5w"} <= step_ids(OLD) and {"3g", "3h", "3i"} <= step_ids(NEW) and {"6a", "6b", "6c", "6d"} <= step_ids(NEW) - step_ids(OLD), "every id is kept; 6a to 6d are new")
for text in ("4k", "4l", "4m", "4n", "4o", "4p", "5s", "5r", "4u", "5t"):
    must(text in step_ids(NEW), text)

# ---- the guards
must("grep -q 'PrivateNetwork=yes' \"$HELPER\" \"$SELFTEST\" ||" in NEW and "update Core first" in NEW, "Patch B guard: PrivateNetwork=yes is required (searched in the helper and the selftest file)")
must("grep -q 'PrivateNetwork=yes' \"$HELPER\" \"$SELFTEST\" &&" not in NEW, "the 'refuse a helper with PrivateNetwork=yes' guard of 1.18.23 is gone")
must("grep -q 'AF_INET AF_UNIX' \"$HELPER\" \"$SELFTEST\" ||" in NEW and "grep -q 'AF_INET AF_UNIX' \"$HELPER\" \"$SELFTEST\" &&" not in NEW, "the AF_UNIX guard is turned around")
must("grep -q 'door_row' \"$LIB/canary/sandbox-canary-runner.py\"" in NEW and "no door_row" in NEW, "an older installed runner is refused")
must("egress_remove_state" in NEW and "own_server_names" in NEW and "patchc_syscalls" in NEW and "no patchc_syscalls or own_name" in NEW, "the 1.18.25 guards")
# 1.18.26 guards: the five installed files equal the source (SHA-256), the selftest file is private, the shebang, the sudoers line, the moved code is gone from the helper
for needle in ("sha256sum", "sandbox-selftest.py", "root:root 700", "'#!/usr/bin/python3 -I'", "R_PROXY_OWN_PUBLIC"):
    must(needle in NEW, ("a 1.18.26 guard is missing", needle))
for what in ("helper", "selftest file", "launcher", "egress program", "canary runner"):
    must(f"|{what}\"" in NEW, ("the hash guard covers", what))
must("--start, /usr/local/sbin/tec-tac-sandbox --stop, /usr/local/sbin/tec-tac-sandbox --status$" in NEW and "grep -q 'sandbox-selftest'" in NEW, "the sudoers line is exactly the three commands and never names the selftest file")
must("\"--selftest\"|\"--canary\"|def selftest" in NEW and "canary_row" in NEW, "the helper must hold no selftest or canary code")
must('SELFTEST_CMD=(/usr/bin/python3 -I "$SELFTEST")' in NEW and '"${SELFTEST_CMD[@]}" --selftest >"$SELFTEST_OUT"' in NEW and '"${SELFTEST_CMD[@]}" --selftest --canary >"$CANARY_OUT"' in NEW, "the selftest and the canary run the new file")
must('"$HELPER" --selftest >' not in NEW and '"$HELPER" --selftest --canary >' not in NEW.replace('sudo -n "$HELPER" --selftest --canary >', ""), "no command runs the old helper modes except the sudo refusal checks")
must("3g" in NEW and "3h" in NEW and "3i" in NEW, "the sudo and helper refusal steps")
must("0.0.0.0" not in NEW and "nc -l" not in NEW and "socat" not in NEW, "no listener on 0.0.0.0 in the script")
# 1.18.27: no OFF expectation is left
for gone in ("enabled false", "still says enabled", "refuses with sandbox_disabled\"", "the switch stays OFF", "SANDBOX_ENABLED = False' \"$HELPER\""):
    must(gone not in NEW, ("an OFF expectation is still in the script", gone))
must('= \'{"t":"refused","code":"sandbox_disabled"}\'' not in NEW, "no exact sandbox_disabled match is left")
must('jget status.enabled)" = "True"' in NEW and "5l --status says enabled true and ready true" in NEW and "3c as $TACTICAL_USER, --start refuses a garbage header" in NEW and "5m after the canary, --start still refuses a garbage header" in NEW, "3c, 5l and 5m are flipped")
# the latency row stays a WARN row; its limit is not changed by the script
must("WARN rows (latency target missed is a warning, not a failure)" in NEW and "p95 403 ms" in NEW or "measured p95 403 ms" in NEW, "the latency row stays a WARN")
selftest_text = (ROOT / "scripts" / "sandbox-selftest.py").read_text(encoding="utf-8")
must(re.search(r"^CANARY_LATENCY_TARGET_MS = 400$", selftest_text, re.MULTILINE) and '"OK" if p95 <= CANARY_LATENCY_TARGET_MS else "WARN"' in selftest_text, "the 400 ms limit and the WARN verdict are unchanged")
# 1.18.27: step 6, the switch-on proofs
for text in ("switch_on_step_6", "switchon_run", "switchon_django_status", "switchon_audit_events", "restore_status_json", 'trap \'restore_status_json\' EXIT', "trap 'restore_status_json; exit 130' INT TERM HUP",
             "cp -p --", "sha256sum \"$SWITCH_STATUS\"", "SHA_BEFORE", "SHA_AFTER", '[ "$SHA_BEFORE" = "$SHA_AFTER" ]', "sandbox_not_ready", "--canary-launch", "run.started,run.ended", "start.refused:sandbox_not_ready",
             'pass "6a ', 'fail "6a ', 'pass "6b ', 'fail "6b ', 'pass "6c ', 'fail "6c ', 'pass "6d ', 'fail "6d '):
    must(text in NEW, ("step 6 text", text))
must(NEW.index("restore_status_json\n  trap - EXIT INT TERM HUP") > NEW.index("STATUS_FORCED=1\n"), "the restore comes after the force")
must("echo \"== step 7: YOURS (not scripted)\"" in NEW and "echo \"== step 6: YOURS" not in NEW, "the old step 6 is step 7 now")
must("Switch-on (step 6, all must PASS)" in NEW, "the verdict text names step 6")
guard_at = NEW.index("grep -q 'SANDBOX_ENABLED = True' \"$HELPER\"")
must(guard_at < NEW.index('[ -f "$SELFTEST" ]') < NEW.index("grep -q -- '--canary' \"$HELPER\" \"$SELFTEST\""), "the selftest file guard comes before the greps that search it")
must("$LIB/sandbox-egress.py" in NEW and "tec-tac-sandbox-egress@.socket" in NEW and "tec-tac-sandbox-egress@.service" in NEW, "the installed egress program and both template units are required")
must("parse_abstract_sockets resolv_conf_bind" not in NEW and "parse_abstract_sockets egress_start" in NEW, "the removed marker is no longer required")

# ---- the exit list: all 22 Patch B rows, no 'expected before' list
line = next(item for item in NEW.splitlines() if item.lstrip().startswith('echo "Patch B exit list'))
for rid in (*D.EXIT_LIST_FORMER_ATTACK, *D.EXIT_LIST_PROXY, *D.EXIT_LIST_ALSO):
    must(rid in line, ("the exit list text names", rid))
must(len(D.EXIT_LIST_FORMER_ATTACK) + len(D.EXIT_LIST_PROXY) + len(D.EXIT_LIST_ALSO) == 23 and len(D.EXIT_LIST_PROXY) == 9 and "pb-proxy-refuse-own-domain" in D.EXIT_LIST_PROXY and "pb-proxy-refuse-own-public-address" in D.EXIT_LIST_PROXY, "12 + 9 + 2 named rows")
must("the 9 proxy rows" in line and "the 8 proxy rows" not in line, "the exit text says 9 proxy rows")
must("0 NOT RUN" in line and "0 ATTACK SUCCEEDED" in line and "pb-tcp-443-ipv6" in line, "the exit wording and the one allowed SKIPPED row")
must("expected before Patch B" not in NEW.split("# 1.18.23 changes from the 1.18.22 script")[0] and 'echo "expected before Patch B' not in NEW, "the old list is not printed")
must('"$SCRIPT_DIR/sandbox-canary-network-1.18.27.py"' in NEW and '"$SCRIPT_DIR/sandbox-canary-network-1.18.25.py"' not in NEW, "step 5t starts the new driver")
must((ROOT / "tests" / "sandbox-canary-1.18.25.sh").is_file(), "the 1.18.25 script stays in tests/")
# ---- 5t, 5u, 5v text intact (only the proxy row count and the 5v failure listing changed)
for text in ('pass "5u run.egress was written before run.ended for the run with a door, with numbers only"', 'pass "5v no egress unit, door folder, configuration or audit state is left"',
             'fail "5v something of the egress door is left (listed above)"', 'echo "== step 5t: the Patch B exit list: the 12 former ATTACK rows OK, the 9 proxy rows OK (positive control 200), 0 NOT RUN, 0 ATTACK SUCCEEDED"'):
    must(text in NEW, text)
must("/run/private/tec-tac-sbx-egress" in NEW and "ls -A /run/tec-tac-sbx-egress" in NEW, "5v keeps its condition and lists the private target on failure")
# ---- 5w: every Patch C row named, patchc mode, the summary the step greps
patchc_text = "\n".join(item for item in NEW.splitlines() if item.lstrip().startswith(('echo "== step 5w', 'echo "Patch C rows')))
for rid in PC.ROW_IDS:
    must(rid in patchc_text, ("the Patch C text names", rid))
must("PATCH C ROWS" in NEW and "[0-9]+ OK, 0 ATTACK SUCCEEDED, [0-9]+ NOT RUN \\(reason\\)" in NEW and 'pass "5w' in NEW and 'fail "5w' in NEW, "5w greps the driver's summary and requires 0 ATTACK SUCCEEDED")
must("all nine must read OK" in NEW and "ATTACK SUCCEEDED expected" not in NEW.split("# 1.18.26: step 5w")[1].split("# 1.18.26: the verdict line first")[0], "5w is flipped")
must('"$SCRIPT_DIR/sandbox-canary-patchc-1.18.27.py"' in NEW, "step 5w starts the Patch C driver")

# ---- structure
lines = NEW.splitlines()
must('[ "$MODE" != "network" ]' in NEW and 'if [ "$MODE" = "network" ]; then network_step_5t; finish; fi' in NEW, "network mode")
must('if [ "$MODE" = "patchc" ]; then patchc_step_5w; finish; fi' in NEW and '"$MODE" != "patchc"' in NEW and "before, network, patchc" in NEW, "patchc mode")
step_2c = next(i for i, item in enumerate(lines) if item.startswith('echo "== step 2c'))
must(lines.index('if [ "$MODE" = "network" ]; then network_step_5t; finish; fi') < step_2c and lines.index('if [ "$MODE" = "patchc" ]; then patchc_step_5w; finish; fi') < step_2c, "both modes end before step 2c")
call = max(i for i, item in enumerate(lines) if item == "network_step_5t")
must(next(i for i, item in enumerate(lines) if item.startswith('echo "== step 5s')) < call < lines.index('echo "== step 7: YOURS (not scripted)"'), "5t sits between 5s and 7")
call_w = max(i for i, item in enumerate(lines) if item == "patchc_step_5w")
call_6 = max(i for i, item in enumerate(lines) if item == "switch_on_step_6")
must(call < call_w < call_6 < lines.index('echo "== step 7: YOURS (not scripted)"'), "5w runs right after 5t (and so after 5v); step 6 runs after 5w")
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
                (tmp_path / "sandbox-canary-network-1.18.27.py").write_text(body, encoding="utf-8")
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
                (tmp_path / "sandbox-canary-patchc-1.18.27.py").write_text("import sys\n" + driver_body, encoding="utf-8")
            script = (prelude + f'SCRIPT_DIR="{tmp_path.as_posix()}"\n' + function("patchc_step_5w") + '\npatchc_step_5w\necho "FAILS=$FAILS"\n')
            return subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False).stdout

    summary_ok = 'print("PATCH C ROWS: 9 OK, 0 ATTACK SUCCEEDED, 0 NOT RUN (reason); expected: x")\n'
    good = run_5w(summary_ok + "sys.exit(0)\n")
    must("PASS 5w" in good and "FAILS=0" in good, good)
    good = run_5w('print("PATCH C ROWS: 6 OK, 0 ATTACK SUCCEEDED, 3 NOT RUN (reason); expected: x")\nsys.exit(0)\n')
    must("PASS 5w" in good, good)
    hole_row = run_5w('print("PATCH C ROWS: 8 OK, 1 ATTACK SUCCEEDED, 0 NOT RUN (reason); expected: x")\nsys.exit(1)\n')
    must("FAIL 5w" in hole_row and "FAILS=1" in hole_row and "real hole" in hole_row, hole_row)
    sneaky = run_5w('print("PATCH C ROWS: 8 OK, 1 ATTACK SUCCEEDED, 0 NOT RUN (reason); expected: x")\nsys.exit(0)\n')
    must("FAIL 5w" in sneaky, "an ATTACK SUCCEEDED row fails the step even when the driver exits 0")
    old_summary = run_5w('print("PATCH C ROWS: 9 ATTACK SUCCEEDED, 0 NOT RUN (reason), 0 OK; expected: x")\nsys.exit(0)\n')
    must("FAIL 5w" in old_summary, "the 1.18.25 expectation (all ATTACK SUCCEEDED) no longer passes")
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
    must(code == 0 and out[1] == "ALL CANARY STEPS PASSED" and out[2].startswith("Patch B exit list (all must be OK, 0 NOT RUN, 0 ATTACK SUCCEEDED)") and "pb-proxy-refuse-own-domain" in out[2] and "pb-proxy-refuse-own-public-address" in out[2], out)
    must(out[3].startswith("Patch C rows (step 5w") and all(rid in out[3] for rid in PC.ROW_IDS), out)
    must(out[4].startswith("Switch-on (step 6, all must PASS)") and "sandbox_not_ready" in out[4], out)
    code, out = run_finish(2)
    must(code == 1 and out[1] == "2 STEP(S) FAILED" and out[2].startswith("Patch B exit list"), out)
    print("bash part ran: 9 step 5t/5u/5v samples, 7 step 5w samples and 2 verdict samples")

    # ---- step 6 (1.18.27): the switch-on proofs, run in bash against stand-ins for the helper, sudo, systemd and the launch (nothing real is started)
    def run_step6(mode="good", ready_after_force=False):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            status = tmp_path / "status.json"
            status.write_text(json.dumps({"ready": True, "reason": "ready", "enabled": True, "slots_total": 3}), encoding="utf-8")
            audit = tmp_path / "audit.jsonl"
            audit.write_text(json.dumps({"event": "sweep", "detail": {}}) + "\n", encoding="utf-8")
            (tmp_path / "framwork" / "tec_tac").mkdir(parents=True)
            (tmp_path / "framwork" / "tec_tac" / "sandbox.py").write_text("# stand-in\n", encoding="utf-8")
            sim = (
                "import json, sys\n"
                f"status = {str(status)!r}\naudit = {str(audit)!r}\n"
                "what = sys.argv[1]\n"
                "ready = json.load(open(status))['ready']\n"
                "if what == 'django':\n"
                "    print(json.dumps({'enabled': True, 'ready': ready, 'active': ready, 'reason': json.load(open(status))['reason']}))\n"
                "elif what == 'helper':\n"
                "    print(json.dumps({'status': {'enabled': True, 'ready': ready}}))\n"
                "elif what == 'run':\n"
                "    run_id = 'ab' * 16\n"
                f"    mode = {mode!r}\n"
                "    refuse = (not ready) and mode != 'ignores_not_ready'\n"
                "    rows = [{'event': 'start.refused', 'detail': {'code': 'sandbox_not_ready'}}] if refuse else [{'event': 'run.started', 'detail': {'run_id': run_id}}, {'event': 'run.ended', 'detail': {'run_id': run_id}}]\n"
                "    with open(audit, 'a') as h:\n"
                "        for r in rows:\n"
                "            h.write(json.dumps(r) + chr(10))\n"
                "    print(json.dumps({'run_id': run_id, 'frames': ['refused'] if refuse else ['started', 'end'], 'refused': 'sandbox_not_ready' if refuse else None, 'reason': None if refuse else 'exited'}))\n"
            )
            (tmp_path / "sim.py").write_text(sim, encoding="utf-8")
            jget_at = lines.index("jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); k=sys.argv[1].split(\".\");")
            jget = "\n".join(lines[jget_at:jget_at + 3])
            stubs = (f'python3() {{ "{python}" "$@"; }}\nsystemctl() {{ true; }}\nSIM="{(tmp_path / "sim.py").as_posix()}"\n'
                     'switchon_run() { python3 "$SIM" run; }\nswitchon_django_status() { python3 "$SIM" django; }\n'
                     'runuser() { python3 "$SIM" helper; }\nTACTICAL_USER=tactical\nHELPER=helper\n'
                     f'STATE="{tmp_path.as_posix()}"\nSOURCE_DIR="{tmp_path.as_posix()}"\n')
            script = (prelude.replace("systemctl() { true; }\n", "") + jget + "\n" + stubs + 'STATUS_SAVED=""\nSTATUS_FORCED=0\nSWITCH_STATUS="$STATE/status.json"\n'
                      + function("restore_status_json") + "\n" + function("switchon_audit_events") + "\n" + function("switch_on_step_6")
                      + '\nswitch_on_step_6\necho "FAILS=$FAILS"\n')
            done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
            return done.stdout + done.stderr, json.loads(status.read_text(encoding="utf-8")), status.read_bytes()

    out6, after, _ = run_step6()
    must("FAILS=0" in out6 and all(f"PASS {i}" in out6 for i in ("6a Core status()", "6a the helper", "6b the inert run", "6b the helper's log", "6b no run unit", "6c Core status()",
                                                                  "6c the helper's --status", "6c the start was refused", "6c the refusal is in", "6c no run unit", "6c status.json is back byte for byte", "6d after the restore")), out6)
    must(after["ready"] is True and after["reason"] == "ready", "status.json is back after a passing step 6")
    bad6, after_bad, _ = run_step6(mode="ignores_not_ready")  # a server that would start a run while not ready: the step must FAIL and still put status.json back
    must("FAIL 6c the start was refused with sandbox_not_ready" in bad6 and "FAILS=" in bad6 and "FAILS=0" not in bad6, bad6)
    must(after_bad["ready"] is True and after_bad["reason"] == "ready" and "PASS 6c status.json is back byte for byte" in bad6, "status.json is put back even when the step fails")
    # the trap: a killed script puts status.json back (the restore function is what the trap runs)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        status = tmp_path / "status.json"
        original = json.dumps({"ready": True, "reason": "ready"})
        status.write_text(original, encoding="utf-8")
        saved = tmp_path / "saved.json"
        shutil.copyfile(status, saved)
        status.write_text(json.dumps({"ready": False, "reason": "forced"}), encoding="utf-8")
        script = (f'STATUS_FORCED=1\nSTATUS_SAVED="{saved.as_posix()}"\nSWITCH_STATUS="{status.as_posix()}"\n' + function("restore_status_json")
                  + "\ntrap 'restore_status_json' EXIT\nexit 3\n")
        done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)
        must(done.returncode == 3 and status.read_text(encoding="utf-8") == original, ("the EXIT trap restores status.json", done.stderr))
    print("bash part ran: step 6 passing, step 6 failing (status.json restored) and the EXIT trap")
print("[TEST] PASS sandbox canary script 1.18.27")
