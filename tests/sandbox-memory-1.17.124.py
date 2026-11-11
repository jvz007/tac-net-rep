#!/usr/bin/env python3
"""1.17.124 regression: the memory row is judged on the peak and on how the run ended (core.sandbox canary, fix 2).

dev02 (Core 1.17.123) showed 'allocated 112 MiB, ended exited (exit 1)' with MemoryMax 128: no peak (MemoryPeak was empty) and the launcher
exit was 1 (systemd-run --wait returns 1 for a unit ended by a signal). The 1.17.123 row read that as an attack; the 1.17.123 Low (OK with no
evidence at all) was the opposite hole. The rule now:

* OK only when the kernel stopped the run (end reason 'oom', or the end frame's oom_kills >= 1) or the probe itself reported a refused
  allocation (CANARYEND memoryerror or enomem), AND the allocated MiB and the peak, where known, are at or below MemoryMax (no slack) and at
  least one of them is known;
* ATTACK SUCCEEDED when allocated or peak is above MemoryMax, the probe finished (CANARYEND done) or the run exited 0;
* NOT RUN, never OK, when there is no evidence or the end is unexplained (exit 1 or 137 with no oom_kills and no CANARYEND).

finish_run (root, ExecStopPost=+) now reads memory.events (oom_kill) and memory.peak from the unit's cgroup while it exists and writes
oom_kills and a peak fallback to the handoff file; launch() adds oom_kills to the end frame (additive).

Not runnable here: the real cgroup and OOM kill (dev02).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_124m", "sandbox-harness-1.17.118.py")
sh, must, make_runner, start, header = H.sh, H.must, H.make_runner, H.start, H.header
spec = importlib.util.spec_from_file_location("canary_runner_124m", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
TAB, NL = chr(9), chr(10)

LIMIT = 128


def progress(mib):
    return "".join(f"CANARYMEM{TAB}{n}{NL}" for n in range(16, mib + 1, 16))


def case(mib, reason, exit_code=None, peak=None, oom_kills=None, word=None, stderr=b"", refused=None, end=True):
    out = progress(mib) + (f"CANARYEND{TAB}{word}{NL}" if word else "")
    frame = {"reason": reason, "exit": exit_code, "peak_mb": peak, "oom_kills": oom_kills}
    return sh.memory_row({"stdout": out.encode(), "stderr": stderr, "refused": refused, "end": frame if end else None}, LIMIT)


def verdict(row):
    return row["verdict"]


# ---- the table of cases
dev02 = case(112, "exited", 1, peak=None)
must(verdict(dev02) == "NOT RUN" and "allocated 112 MiB" in dev02["actual"] and "no evidence" in dev02["actual"], dev02)  # 1.17.123: ATTACK SUCCEEDED
with_err = case(112, "exited", 1, stderr=b"Traceback\nSomeError: boom\n")
must(verdict(with_err) == "NOT RUN" and "stderr: Traceback" in with_err["actual"], with_err)
must(verdict(case(112, "oom", 137, peak=127.9, oom_kills=1)) == "OK", "oom_kills 1, 112 MiB, peak 127.9")
must(verdict(case(112, "exited", 137, peak=127.9, oom_kills=1)) == "OK", "the kernel counter is enough even when the label is exit-code")
must(verdict(case(112, "exited", 1, oom_kills=1)) == "OK", "the dev02 shape with the kernel counter present")
must(verdict(case(112, "oom", 137, peak=128.0)) == "OK", "the reason oom with allocated and peak inside the limit")
must(verdict(case(112, "exited", 1, word="memoryerror")) == "OK", "a refused allocation reported by the probe")
must(verdict(case(112, "exited", 1, word="enomem")) == "OK", "ENOMEM reported by the probe")
over = case(144, "oom", 137, peak=128.0, oom_kills=1)
must(verdict(over) == "ATTACK SUCCEEDED" and "allocated 144 MiB" in over["actual"], over)  # no 16 MiB block tolerance
must(verdict(case(128, "oom", 137, oom_kills=1)) == "OK", "exactly MemoryMax is inside the rule")
full = case(592, "exited", 0, word="done")
must(verdict(full) == "ATTACK SUCCEEDED" and "allocated 592 MiB" in full["actual"], full)
must(verdict(case(592, "exited", 0)) == "ATTACK SUCCEEDED", "a normal exit 0")
must(verdict(case(112, "exited", 0, oom_kills=1)) == "ATTACK SUCCEEDED", "exit 0 is never excused by a counter")
must(verdict(case(112, "exited", 137)) == "NOT RUN", "exit 137 with no oom evidence")
must(verdict(case(112, "timeout")) == "NOT RUN" and verdict(case(112, "cancelled")) == "NOT RUN", "stopped by something else")
low = case(0, "oom", 137)
must(verdict(low) == "NOT RUN" and "no allocation" in low["actual"] and "no peak" in low["actual"], low)  # the 1.17.123 Low: OK with no evidence
must(verdict(case(0, "exited", 137, oom_kills=3)) == "NOT RUN", "a counter with no allocation and no peak has nothing to check the limit against")
must(verdict(case(0, "oom", 137, peak=100.0)) == "OK", "a known peak alone is enough to check against")
big = case(112, "oom", 137, peak=300.0, oom_kills=1)
must(verdict(big) == "ATTACK SUCCEEDED" and "peak 300.0 MiB" in big["actual"], big)
must(verdict(case(112, "oom", 137, peak=128.1, oom_kills=1)) == "ATTACK SUCCEEDED", "no tolerance on the peak either")
missing = case(0, "oom", end=False)
must(verdict(missing) == "NOT RUN" and "no end frame" in missing["actual"], missing)
refused = case(0, "oom", refused="sandbox_unavailable", end=False)
must(verdict(refused) == "NOT RUN" and "refused: sandbox_unavailable" in refused["actual"], refused)
for item in (dev02, full, big, low):
    must(item["wall"] == "Limits" and item["attack"] == "memory beyond MemoryMax", item)
# a bool or text in the frame is not evidence
must(verdict(case(112, "exited", 1, oom_kills=True)) == "NOT RUN", "True is not a count")
# the actual column names how it ended, the counter and the peak
ok = case(112, "oom", 137, peak=127.9, oom_kills=1)
must("allocated 112 MiB" in ok["actual"] and "ended oom" in ok["actual"] and "oom_kills 1" in ok["actual"] and "peak 127.9 MiB" in ok["actual"], ok)

# ---- the end-of-run word: exact line only, never a table row
P = sh.parse_end_word
must(P(f"CANARYEND{TAB}done{NL}") == "done" and P(b"") is None and P(f"CANARYEND{TAB}memoryerror{NL}CANARYEND{TAB}done{NL}") == "done", "last wins")
must(P(f"CANARYROW{TAB}x{TAB}OK{TAB}CANARYEND{TAB}done{NL}") is None, "only a line that is exactly the marker counts")
must(P(f"CANARYEND{TAB}bad word{NL}") is None and P(f"CANARYEND{TAB}other:ValueError{NL}") == "other:ValueError", "the word is checked")
must(sh.parse_runner_rows(f"CANARYEND{TAB}done{NL}".encode()) == [], "the end marker never becomes a table row")

# ---- g_mem prints the end word on MemoryError, on another exception and on completion
rows = []
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))


def run_mem(plan, fake=None):
    out = io.StringIO()
    error = None
    saved = runner.bytearray if hasattr(runner, "bytearray") else None
    if fake is not None:
        runner.bytearray = fake
    try:
        with contextlib.redirect_stdout(out):
            try:
                runner.g_mem(plan)
            except BaseException as exc:  # g_mem re-raises everything except MemoryError
                error = exc
    finally:
        if fake is not None:
            if saved is None:
                del runner.bytearray
            else:
                runner.bytearray = saved
    return out.getvalue().splitlines(), error


lines, error = run_mem({"alloc_mb": 32})
must(lines == [f"CANARYMEM{TAB}16", f"CANARYMEM{TAB}32", f"CANARYEND{TAB}done"] and error is None, lines)


class Boom:
    """A stand-in for bytearray: the second block fails."""
    count = 0

    def __init__(self, error):
        self.error = error

    def __call__(self, *args):
        Boom.count += 1
        if Boom.count > 1:
            raise self.error
        return bytearray(1)


Boom.count = 0
lines, error = run_mem({"alloc_mb": 64}, Boom(MemoryError()))
must(lines == [f"CANARYMEM{TAB}16", f"CANARYEND{TAB}memoryerror"] and error is None, lines)
Boom.count = 0
lines, error = run_mem({"alloc_mb": 64}, Boom(OSError(12, "Cannot allocate memory")))
must(lines[-1] == f"CANARYEND{TAB}enomem" and isinstance(error, OSError), (lines, error))
Boom.count = 0
lines, error = run_mem({"alloc_mb": 64}, Boom(ValueError("x")))
must(lines[-1] == f"CANARYEND{TAB}other:ValueError" and isinstance(error, ValueError), (lines, error))
Boom.count = 0
lines, error = run_mem({"alloc_mb": 64}, Boom(KeyboardInterrupt()))
must(lines[-1] == f"CANARYEND{TAB}other:KeyboardInterrupt" and isinstance(error, KeyboardInterrupt), (lines, error))

# ---- finish_run reads the unit's cgroup: oom_kill from memory.events and memory.peak, and tolerates a missing file
CG = H.BASE / "cgroup"
sh.CGROUP_ROOT = CG
unit_dir = CG / "system.slice" / "tectac-sbx-test.service"
unit_dir.mkdir(parents=True)
state = {"group": "/system.slice/tectac-sbx-test.service", "peak": ""}


def fake_systemctl(*args, timeout=15):
    if "ControlGroup" in args:
        return 0, state["group"] + NL, ""
    if "MemoryPeak" in args:
        return 0, f"{state['peak']}{NL}1000{NL}", ""
    return 0, "", ""


sh.systemctl = fake_systemctl
rid = os.urandom(16).hex()
(unit_dir / "memory.events").write_text("low 0\nhigh 0\nmax 214\noom 1\noom_kill 3\noom_group_kill 0\n", encoding="ascii")
(unit_dir / "memory.peak").write_text("134217728\n", encoding="ascii")
must(sh.finish_run(rid, {"SERVICE_RESULT": "exit-code"}) == 0, "")
handoff = json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))
must(handoff["oom_kills"] == 3 and handoff["memory_peak"] == 134217728 and handoff["result"] == "exit-code", handoff)  # MemoryPeak was empty: the cgroup's value is used
state["peak"] = "52428800"
sh.finish_run(rid, {})
must(json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))["memory_peak"] == 52428800, "systemd's MemoryPeak wins when it has a number")
(unit_dir / "memory.events").unlink()
(unit_dir / "memory.peak").unlink()
state["peak"] = ""
sh.finish_run(rid, {})
handoff = json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))
must(handoff["oom_kills"] is None and handoff["memory_peak"] is None, "a missing file is tolerated and reported as unknown")
(unit_dir / "memory.events").write_text("oom_kill notanumber\n", encoding="ascii")
sh.finish_run(rid, {})
must(json.loads((sh.HANDOFF_ROOT / f"{rid}.json").read_text(encoding="utf-8"))["oom_kills"] is None, "garbage is unknown, never an error")
for bad in ("/../etc", "relative/path", "/a/../../b", "", "/x\x00y"):
    state["group"] = bad
    must(sh.read_cgroup_memory(rid) == (None, None), bad)
sh.finish_run(rid, {})
(sh.HANDOFF_ROOT / f"{rid}.json").unlink()

# ---- the end frame carries oom_kills (additive) and a peak from the handoff
make_runner("ai.chat", body="print('hello')")
H.write_ready_status()
sh.read_handoff = lambda run_id: {"oom_kills": 2, "memory_peak": 100 * 1048576, "result": "exit-code"}
code, frames = start(header("ai.chat"))
end = [f for f in frames if f["t"] == "end"][0]
must(end["oom_kills"] == 2 and end["peak_mb"] == 100.0, end)
sh.read_handoff = lambda run_id: {"oom_kills": True, "result": "exit-code"}
code, frames = start(header("ai.chat"))
end = [f for f in frames if f["t"] == "end"][0]
must(end["oom_kills"] is None and end["peak_mb"] is None, end)
# Core's own reader of end frames takes known keys only, so an extra key is ignored
core_source = (H.ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
must('frame.get("peak_mb")' in core_source and "oom_kills" not in core_source, "Core reads named keys of the end frame, so oom_kills passes through unseen")

# ---- through _limit_rows with the new frame
calls = []


def collect(group, plan, **kwargs):
    calls.append((group, plan, kwargs))
    base = {"stdout": b"", "stderr": b"", "refused": None, "run_id": "r"}
    if group == "mem":
        return {**base, "stdout": (progress(112) + f"CANARYEND{TAB}done{NL}").encode(), "end": {"reason": "exited", "exit": 0}}
    if group == "loop":
        return {**base, "end": {"reason": "timeout", "exit": None}}
    if group == "flood":
        return {**base, "end": {"reason": "output_limit", "exit": None}}
    return {**base, "end": {"reason": "exited", "exit": 0}}


rows_out = sh._limit_rows(collect, {"ready": True})
must(rows_out[0]["verdict"] == "ATTACK SUCCEEDED" and calls[0][2]["memory_mb"] == 128, rows_out[0])
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must("memory_mb + block" not in source, "the block tolerance is gone from the row")

print("[TEST] PASS sandbox memory 1.17.124")
