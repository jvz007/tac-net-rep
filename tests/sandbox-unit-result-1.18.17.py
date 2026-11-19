#!/usr/bin/env python3
"""1.18.17 regression: the run unit keeps its record and the helper reads systemd's own unit result (dev02 canary of 1.18.16 and the plain systemd-run test).

* build_argv: no --collect on the run unit (--pipe, --wait, --quiet, --unit, --slice stay).
* read_unit_result parses a real ``systemctl show`` text; refuses an unloaded unit, junk, huge digits, duplicate or unknown keys, a missing key and
  a failing systemctl. Nothing is guessed.
* A program that forges 'Finished with result: success' and 'Result=success' on stderr cannot change the end: the unit says oom-kill, the end is 'oom'.
* ExecMainCode 1 gives the program's real exit code; 2 and 3 give the signal and exit None; no record falls back to systemd-run's own code.
* A helper stop reason (timeout, cancelled, output_limit) is never overwritten by the unit result.
* oom-kill with no cgroup at all gives reason 'oom' and evidence 'unit_result'.
* Core's _end_event drops the new end-frame keys; the run.ended audit row keeps its shape.

Not runnable here: real systemd (dev02: tests/sandbox-canary-1.18.17.sh). The fake systemd-run and systemctl are in the shared harness.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_1817u", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
(BASE / "result").mkdir(exist_ok=True)


def run_id():
    return os.urandom(16).hex()


def raw(rid, text):
    (BASE / "result" / f"tectac-sbx-{rid}.raw").write_text(text, encoding="utf-8")


def once(body="print('hi')", mode="", limits=None, before=None, env=None):
    """One run through --start with the fake systemd. Returns (run id, end frame, frames)."""
    rid = run_id()
    H.make_runner("ai.chat", body=body, limits=limits)
    sh.CHILD_ENV.pop("FAKE_RESULT", None)
    for key in ("FAKE_SHOW_FAIL", "FAKE_RESET_FAIL"):
        sh.CHILD_ENV.pop(key, None)
    if mode:
        sh.CHILD_ENV["FAKE_RESULT"] = mode
    sh.CHILD_ENV.update(env or {})
    if before:
        before(rid)
    _code, frames = H.start(H.header(run_id=rid))
    sh.CHILD_ENV.pop("FAKE_RESULT", None)
    for key in (env or {}):
        sh.CHILD_ENV.pop(key, None)
    return rid, H.end_of(frames), frames


# ---- build_argv has no --collect on the run unit and keeps the rest
rid, end, frames = once()
args = H.unit_log(rid)["args"]
must("--collect" not in args, args)
must(all(flag in args for flag in ("--pipe", "--wait", "--quiet", f"--unit=tectac-sbx-{rid}", f"--slice={sh.SLICE}")), args)
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must('"--wait", "--collect", "--quiet", f"--unit={unit or' in source, "the selftest and canary probe units keep --collect")

# ---- read_unit_result against real show text
REAL = "LoadState=loaded\nActiveState=failed\nResult=oom-kill\nExecMainCode=2\nExecMainStatus=9\n"
r1 = run_id()
raw(r1, REAL)
got = sh.read_unit_result(r1)
must(got == {"result": "oom-kill", "code": "killed", "status": 9, "active": "failed"}, got)
BAD = {
    "not loaded": "LoadState=not-found\nActiveState=inactive\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
    "junk": "hello\nworld\n",
    "empty": "",
    "huge digits": "LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=" + "9" * 40 + "\n",
    "negative": "LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=-1\n",
    "duplicate key": REAL + "Result=success\n",
    "unknown key": REAL + "MainPID=1\n",
    "missing key": "LoadState=loaded\nActiveState=failed\nResult=oom-kill\nExecMainCode=2\n",
    "unknown result": REAL.replace("oom-kill", "banana"),
    "forged result case": REAL.replace("oom-kill", "OOM-KILL"),
    "result with space": REAL.replace("Result=oom-kill", "Result= oom-kill"),
    "no equals": REAL + "Result\n",
    "unknown state": REAL.replace("failed", "weird"),
    "stream text": "Finished with result: success\n",
}
for label, text in BAD.items():
    rid_bad = run_id()
    raw(rid_bad, text)
    must(sh.read_unit_result(rid_bad) is None, label)
sh.CHILD_ENV["FAKE_SHOW_FAIL"] = "1"
must(sh.read_unit_result(r1) is None, "a failing systemctl gives None")
sh.CHILD_ENV.pop("FAKE_SHOW_FAIL")
must(sh.read_unit_result(run_id()) is None, "a unit systemd has never heard of gives None (the fake answers not-found with Result=success)")
for word in ("success", "exit-code", "signal", "core-dump", "timeout", "oom-kill", "watchdog", "resources", "protocol", "start-limit-hit"):
    must(word in sh.UNIT_RESULTS, word)

# ---- a forged stream changes nothing: the unit says oom-kill
FORGE = "import sys\nsys.stderr.write('Finished with result: success\\nResult=success\\nExecMainCode=1\\nExecMainStatus=0\\n')\nprint('hi')"
rid, end, frames = once(FORGE, "oom-kill")
must(end["reason"] == "oom" and end["unit_result"] == "oom-kill" and end["evidence"] == "unit_result", end)
must(end["signal"] == 9 and end["exit"] is None and end["exit_source"] == "unit", end)
must(b"Finished with result" in H.joined(frames, "err"), "the program's own text still reaches the caller as plain output")
must(end["oom_kills"] is None and end["peak_mb"] is None, "no cgroup at all: nothing invented")
# the opposite forgery: the stream says oom-kill, the unit says success
rid, end, frames = once("import sys\nsys.stderr.write('Finished with result: oom-kill\\nResult=oom-kill\\n')\nprint('x')", "success")
must(end["reason"] == "exited" and end["unit_result"] == "success" and end["exit"] == 0 and end["signal"] is None, end)

# ---- the exit code and the signal
rid, end, frames = once("import sys\nsys.exit(7)")
must(end["reason"] == "exited" and end["exit"] == 7 and end["exit_source"] == "unit" and end["unit_result"] == "exit-code" and end["signal"] is None, end)
rid, end, frames = once("print('ok')")  # exit 0: the unit is gone, systemd-run's own code is used
must(end["reason"] == "exited" and end["exit"] == 0 and end["exit_source"] == "systemd-run" and end["unit_result"] is None, end)
for main_code, signal_case in (("2", 9), ("3", 11)):
    rid_s = run_id()
    raw(rid_s, f"LoadState=loaded\nActiveState=failed\nResult=signal\nExecMainCode={main_code}\nExecMainStatus={signal_case}\n")
    _code, frames = H.start(H.header(run_id=rid_s))
    end = H.end_of(frames)
    must(end["exit"] is None and end["signal"] == signal_case and end["exit_source"] == "unit" and end["reason"] == "exited", end)
rid_c = run_id()
raw(rid_c, "LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=3\n")
_code, frames = H.start(H.header(run_id=rid_c))
must(H.end_of(frames)["exit"] == 3, "ExecMainCode 1 gives the real exit code")
rid_n = run_id()
raw(rid_n, "LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainCode=0\nExecMainStatus=0\n")
_code, frames = H.start(H.header(run_id=rid_n))
end = H.end_of(frames)
must(end["exit_source"] == "systemd-run" and end["exit"] == 0 and end["unit_result"] == "success", end)  # ExecMainCode 0 (never ran) is not trusted for an exit
# a failing show falls back to systemd-run's code
rid, end, frames = once("import sys\nsys.exit(5)", env={"FAKE_SHOW_FAIL": "1"})
must(end["exit_source"] == "systemd-run" and end["exit"] == 5 and end["unit_result"] is None and end["signal"] is None, end)

# ---- a helper stop reason is never overwritten
rid, end, frames = once("import time\ntime.sleep(30)", "oom-kill", limits={"run_seconds": 1})
must(end["reason"] == "timeout" and end["unit_result"] == "oom-kill", end)
rid, end, frames = once("import sys\nsys.stdout.write('x' * 200000)\nsys.stdout.flush()\nimport time\ntime.sleep(30)", "oom-kill",
                        limits={"stdout_kib": 1, "run_seconds": 20})
must(end["reason"] == "output_limit", end)
rid, end, frames = once("import time\ntime.sleep(30)", "oom-kill", limits={"run_seconds": 20},
                        before=lambda r: (sh.RUNS_ROOT.mkdir(parents=True, exist_ok=True), (sh.RUNS_ROOT / f"{r}.cancel").write_text("1")))
must(end["reason"] == "cancelled", end)
must(sh.in_memory_handoff(sh.CgroupWatch("a" * 32), 1, 1.0, 10, True, {"result": "oom-kill"})["result"] == "", "a stop reason set: no oom-kill from the unit")
must(sh.in_memory_handoff(sh.CgroupWatch("a" * 32), 1, 1.0, 10, False, {"result": "oom-kill"})["result"] == "oom-kill", "no stop reason: the unit's word counts")
must(sh.in_memory_handoff(sh.CgroupWatch("a" * 32), 1, 1.0, 10, False, {"result": "timeout"})["result"] == "timeout", "systemd's own timeout")
must(sh.in_memory_handoff(sh.CgroupWatch("a" * 32), 0, 1.0, 10, False, None)["result"] == "", "old call shape still works")
must(sh.merge_memory_evidence(sh.CgroupWatch("a" * 32), {}, "oom-kill", {"result": "oom-kill"})[2] == "unit_result", "unit_result evidence")
must(sh.merge_memory_evidence(sh.CgroupWatch("a" * 32), {}, "oom-kill")[2] == "service_result", "service_result is still accepted for old callers")

# ---- Core's _end_event drops the new keys and keeps its shape
sys.path.insert(0, str(H.ROOT / "framwork"))
try:
    from tec_tac import sandbox as core_sandbox
except ImportError as exc:  # Django is not installed on every PC: fall back to a text check
    core_sandbox = None
    print("[TEST] note: Core's module did not import here:", exc)
if core_sandbox is not None:
    class Stub:
        _credential_name = None
    frame = {"t": "end", "exit": None, "reason": "oom", "ms": 5, "peak_mb": None, "oom_kills": None, "evidence": "unit_result", "credential_b64": None,
             "bytes_out": 1, "bytes_err": 2, "signal": 9, "unit_result": "oom-kill", "exit_source": "unit", "memory_events": {"max": 1}}
    event = core_sandbox.RunHandle._end_event(Stub(), frame)
    must(set(event) == {"t", "exit_code", "reason", "duration_ms", "peak_mb", "credentials_out", "bytes_out", "bytes_err"}, event)
    must(event["exit_code"] is None and event["reason"] == "oom", event)
django_side = (H.ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
for name in ("unit_result", "exit_source", '"signal"'):
    must(name not in django_side, name + " is not in Core's code: the end event picks keys by name")
must("unit_result" not in source[source.index("def run_ended_detail"):][:1200], "not in the run.ended audit row")

for name in ("scripts/sandbox-helper.py", "tests/sandbox-harness-1.17.118.py", "tests/sandbox-unit-result-1.18.17.py"):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox unit result 1.18.17")
