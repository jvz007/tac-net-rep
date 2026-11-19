#!/usr/bin/env python3
"""1.18.15 regression: the memory canary row (dev02 canary of 1.18.14, item 2).

* The probe allocates in 4 MiB steps with every page written, up to twice MemoryMax, prints CANARYMEM after each step, pauses a moment
  between steps, and says why it stopped: a refused allocation is the row 'MemoryError at <N> MiB' (or 'enomem at <N> MiB') and an end word,
  never a silent stop.
* The helper asks for 2 x MemoryMax (256 MiB for the 128 MiB row) instead of the fixed 600.
* CgroupWatch takes an interval: 0.2 s for a normal run (production cost unchanged), 0.02 s for a canary run, so a kill just before the
  cgroup of a --collect unit goes away is still seen. The supervise loop wakes as fast as that for a canary run only.
* memory_row keeps its rules (the 1.17.124 test still passes).

Not runnable here: the real cgroup and the kernel's OOM kill (dev02).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_1815m", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
runner = load("canary_runner_1815m", H.ROOT / "scripts" / "sandbox-canary-runner.py")
TAB, NL = chr(9), chr(10)

# ---- the probe
must(runner.MEM_STEP_MIB == 4 and 0 < runner.MEM_STEP_SLEEP <= 0.05, (runner.MEM_STEP_MIB, runner.MEM_STEP_SLEEP))
runner.MEM_STEP_SLEEP = 0
rows = []
runner.row = lambda attack, tag, actual: rows.append((attack, tag, actual))
REAL_ALLOCATE = runner.allocate_block


def run_mem(plan, allocate):
    out = io.StringIO()
    error = None
    steps = []
    runner.allocate_block = lambda mib: steps.append(mib) or allocate(len(steps))
    try:
        with contextlib.redirect_stdout(out):
            try:
                runner.g_mem(plan)
            except BaseException as exc:  # noqa: BLE001 - g_mem re-raises everything it does not explain
                error = exc
    finally:
        runner.allocate_block = REAL_ALLOCATE
    return out.getvalue().splitlines(), error, steps


def refuse_at(n, error):
    def allocate(count):
        if count >= n:
            raise error
        return bytearray(1)
    return allocate


lines, error, steps = run_mem({"alloc_mb": 256}, refuse_at(3, MemoryError()))
must(lines == [f"CANARYMEM{TAB}4", f"CANARYMEM{TAB}8", f"CANARYEND{TAB}memoryerror"] and error is None, lines)
must(rows == [("memory beyond MemoryMax", "OK", "MemoryError at 8 MiB")], rows)
must(steps == [4, 4, 4], steps)
rows.clear()
lines, error, steps = run_mem({"alloc_mb": 256}, refuse_at(2, OSError(12, "Cannot allocate memory")))
must(lines == [f"CANARYMEM{TAB}4", f"CANARYEND{TAB}enomem"] and error is None and rows == [("memory beyond MemoryMax", "OK", "enomem at 4 MiB")], (lines, error, rows))
rows.clear()
lines, error, steps = run_mem({"alloc_mb": 256}, refuse_at(2, ValueError("x")))
must(lines[-1] == f"CANARYEND{TAB}other:ValueError" and isinstance(error, ValueError) and not rows, (lines, error))
lines, error, steps = run_mem({"alloc_mb": 256}, refuse_at(2, OSError(5, "io")))
must(lines[-1] == f"CANARYEND{TAB}other:OSError" and isinstance(error, OSError), (lines, error))
# the whole plan: 256 MiB is 64 steps of 4 MiB, the last number printed is 256, then the SUCCEEDED row and 'done'
rows.clear()
lines, error, steps = run_mem({"alloc_mb": 256}, lambda count: bytearray(1))
must(len(steps) == 64 and lines[-2:] == [f"CANARYMEM{TAB}256", f"CANARYEND{TAB}done"] or lines[-1] == f"CANARYEND{TAB}done", lines[-3:])
must(len(steps) == 64 and rows == [("memory beyond MemoryMax", "SUCCEEDED", "allocated 256 MiB")], (len(steps), rows))
# the real allocator touches every page: a block of the right size with a non-zero byte
block = runner.allocate_block(1)
must(len(block) == 1024 * 1024 and block[0] == 1 and block[-1] == 1, "pages are written")
# the probe's lines are still not table rows
must(sh.parse_runner_rows(f"CANARYMEM{TAB}4{NL}CANARYEND{TAB}memoryerror{NL}".encode()) == [], "no table row from progress lines")

# ---- the helper asks for twice MemoryMax
calls = []


def collect(group, plan, **kw):
    calls.append((group, plan, kw))
    return {"stdout": b"", "stderr": b"", "end": None, "refused": None}


sh._limit_rows(collect, {"ready": True})
must(calls[0][0] == "mem" and calls[0][1] == {"alloc_mb": 2 * 128} and calls[0][2]["memory_mb"] == 128, calls[0])
must(sh.CANARY_MEMORY_MB == 128 and sh.MEMORY_ALLOC_FACTOR == 2, "constants")

# ---- CgroupWatch: the interval
must(sh.CgroupWatch.INTERVAL == 0.2 and sh.CgroupWatch.CANARY_INTERVAL == 0.02, "constants")
rid = os.urandom(16).hex()
must(sh.CgroupWatch(rid).interval == 0.2 and sh.CgroupWatch(rid, 0.02).interval == 0.02, "default and given")
CG = BASE / "cgroup"
CG.mkdir()
sh.CGROUP_ROOT = CG
folder = CG / "tec.slice" / "tec-tac.slice" / "tec-tac-sandbox.slice" / f"tectac-sbx-{rid}.service"
folder.mkdir(parents=True)
(folder / "memory.events").write_text("oom_kill 0\n", encoding="ascii")
slow, fast = sh.CgroupWatch(rid), sh.CgroupWatch(rid, sh.CgroupWatch.CANARY_INTERVAL)
for watch in (slow, fast):
    watch.sample(1.00)
(folder / "memory.events").write_text("oom_kill 1\n", encoding="ascii")
for watch in (slow, fast):
    watch.sample(1.03)  # 30 ms later: only the fast watch reads again
must(slow.oom_kill == 0 and fast.oom_kill == 1, (slow.oom_kill, fast.oom_kill))
# the cgroup disappears after the second sample: the fast watch has the kill, a later sample and a forced one tolerate the missing folder
(folder / "memory.events").unlink()
folder.rmdir()
fast.sample(1.06)
fast.sample(force=True)
must(fast.oom_kill == 1, vars(fast))

# ---- _supervise: a canary run uses the fast watch and wake-up, a normal run does not
seen = []


class Spy(sh.CgroupWatch):
    def __init__(self, run_id, interval=None):
        super().__init__(run_id, interval)
        seen.append(self.interval)


waits = []
real_watch, real_get = sh.CgroupWatch, sh.queue_module.Queue.get


def spying_get(self, block=True, timeout=None):
    waits.append(timeout)
    return real_get(self, block, timeout)


def supervise(canary):
    seen.clear()
    waits.clear()
    process = subprocess.Popen([sys.executable, "-c", "pass"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    row = {"limits": {"stdout_kib": 4, "stderr_kib": 4, "run_seconds": 20}}
    sh.CgroupWatch = Spy
    sh.queue_module.Queue.get = spying_get
    try:
        sh._supervise(process, row, os.urandom(16).hex(), b"", lambda frame: None, None, sh.time.monotonic(), sh.time.monotonic, canary=canary)
    finally:
        sh.CgroupWatch = real_watch
        sh.queue_module.Queue.get = real_get


supervise(False)
must(seen == [0.2] and waits and all(w == sh.FLUSH_SECONDS for w in waits), (seen, waits))
supervise(True)
must(seen == [0.02] and waits and all(w == 0.02 for w in waits), (seen, waits))
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must("progress=progress, canary=canary)" in source, "launch passes the canary flag")
must('"--wait", "--collect", "--quiet", f"--unit={unit or' in source and '"--wait", "--quiet", f"--unit={unit_name(run_id)}"' in source, "1.18.17: --collect stays on the probe units and is gone from the run unit")

# ---- the table row names a refused allocation with the size held, and keeps its verdict rules
refused = sh.memory_row({"stdout": f"CANARYMEM{TAB}4{NL}CANARYMEM{TAB}8{NL}CANARYEND{TAB}memoryerror{NL}".encode(), "stderr": b"", "refused": None,
                         "end": {"reason": "exited", "exit": 0, "peak_mb": 9.0, "oom_kills": 0}}, 128)
must(refused["verdict"] == "ATTACK SUCCEEDED", "exit 0 is still an attack that succeeded")  # a clean exit 0 is not a refusal by the kernel
refused = sh.memory_row({"stdout": f"CANARYMEM{TAB}4{NL}CANARYMEM{TAB}8{NL}CANARYEND{TAB}memoryerror{NL}".encode(), "stderr": b"", "refused": None,
                         "end": {"reason": "exited", "exit": 1, "peak_mb": 9.0, "oom_kills": 0}}, 128)
must(refused["verdict"] == "OK" and "MemoryError at 8 MiB" in refused["actual"], refused)
killed = sh.memory_row({"stdout": f"CANARYMEM{TAB}124{NL}".encode(), "stderr": b"", "refused": None,
                        "end": {"reason": "oom", "exit": 137, "peak_mb": 127.9, "oom_kills": 1, "evidence": "poll"}}, 128)
must(killed["verdict"] == "OK" and "oom_kills 1" in killed["actual"] and "MemoryError" not in killed["actual"], killed)

# ---- the memory row's rules are unchanged: the 1.17.124 test still passes
done = subprocess.run([sys.executable, str(HERE / "sandbox-memory-1.17.124.py")], capture_output=True, text=True, check=False)
must(done.returncode == 0, done.stdout[-500:] + done.stderr[-500:])
for name in ("scripts/sandbox-helper.py", "scripts/sandbox-canary-runner.py"):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox memory 1.18.15")
