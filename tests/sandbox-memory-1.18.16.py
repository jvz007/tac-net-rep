#!/usr/bin/env python3
"""1.18.16 regression: the memory canary row proves the limit with the kernel's own counters (dev02 canary of 1.18.15, last Patch A row).

* parse_memory_counters reads max, high, oom and oom_kill from memory.events (same exact-line rule); parse_memory_events stays a wrapper.
* CgroupWatch keeps the highest value of each counter across samples and tolerates a vanished cgroup.
* The end frame carries one additive key, memory_events, that Core's _end_event drops (it is not in the run.ended audit row).
* memory_row: OK on oom_kill >= 1, on memory.events max >= 1 with a known peak at or below MemoryMax and a probe that did not finish, or on a
  probe MemoryError; ATTACK SUCCEEDED when allocated or peak is above the limit or the probe finished; NOT RUN with nothing to show. The row
  names its proof ("proof: ...") and always shows the probe's first stderr line.

Not runnable here: the real cgroup and the kernel's OOM kill (dev02: tests/sandbox-canary-1.18.16.sh).
"""
from __future__ import annotations

import importlib.util
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


H = load("sandbox_harness_1816m", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
MB = 128

# ---- parse_memory_counters
REAL = "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n"
must(sh.parse_memory_counters(REAL) == {"high": 0, "max": 3, "oom": 1, "oom_kill": 1}, sh.parse_memory_counters(REAL))
JUNK = "junk\nmax x\nmax -1\nmax 1 2\nMAX 4\nmax ٣\n"
must(sh.parse_memory_counters("") == {} and sh.parse_memory_counters(JUNK) == {}, "junk")
must(sh.parse_memory_counters("max " + "9" * 40 + "\nhigh 2\n") == {"high": 2}, "a huge number is ignored")
must(sh.parse_memory_counters("oom_kill 2\n") == {"oom_kill": 2}, "a missing line stays missing")
must(sh.parse_memory_events(REAL) == (1, 1) and sh.parse_memory_events("max 3\n") == (None, None), "the wrapper keeps its old answer")

# ---- CgroupWatch keeps the highest of each counter
CG = BASE / "cgroup"
CG.mkdir()
sh.CGROUP_ROOT = CG
SLICE = ("tec.slice", "tec-tac.slice", "tec-tac-sandbox.slice")
rid = os.urandom(16).hex()
folder = CG.joinpath(*SLICE) / f"tectac-sbx-{rid}.service"
folder.mkdir(parents=True)
events = folder / "memory.events"
events.write_text("max 1\nhigh 0\noom 0\noom_kill 0\n", encoding="ascii")
watch = sh.CgroupWatch(rid)
must(watch.events == {}, "nothing before the first sample")
watch.sample(1.0)
must(watch.events == {"max": 1, "high": 0, "oom": 0, "oom_kill": 0}, watch.events)
events.write_text("max 5\nhigh 2\noom 1\noom_kill 1\n", encoding="ascii")
watch.sample(2.0)
events.write_text("max 2\nhigh 1\noom 0\noom_kill 0\n", encoding="ascii")  # lower later values never lower the kept maximum
watch.sample(3.0)
must(watch.events == {"max": 5, "high": 2, "oom": 1, "oom_kill": 1} and watch.oom_kill == 1, watch.events)
events.unlink()
folder.rmdir()
watch.sample(4.0)
watch.sample(force=True)
must(watch.events == {"max": 5, "high": 2, "oom": 1, "oom_kill": 1}, "a vanished cgroup keeps what was seen")

# ---- the end frame carries memory_events (only counters that were read)
sh.in_memory_handoff = lambda *a, **k: {"memory_peak": None, "oom_kills": None, "result": ""}
rid2 = os.urandom(16).hex()
folder2 = CG.joinpath(*SLICE) / f"tectac-sbx-{rid2}.service"
folder2.mkdir(parents=True)
(folder2 / "memory.events").write_text("max 3\nhigh 0\noom 0\n", encoding="ascii")
limits = {"stdout_kib": 4, "stderr_kib": 4, "run_seconds": 20}


def supervised(run_id):
    process = subprocess.Popen([sys.executable, "-c", "pass"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return sh._supervise(process, {"limits": limits}, run_id, b"", lambda frame: None, None, sh.time.monotonic(), sh.time.monotonic)


end = supervised(rid2)
must(end["memory_events"] == {"max": 3, "high": 0, "oom": 0}, end)  # no oom_kill line: not invented
end = supervised(os.urandom(16).hex())
must("memory_events" not in end, "no cgroup, no key")
django_side = (H.ROOT / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
must("memory_events" not in django_side, "Core's _end_event picks keys by name: the new key is dropped, the module-facing result is unchanged")
helper_source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must('"run.ended"' in helper_source and "memory_events" not in helper_source[helper_source.index('"run.ended", {'):][:700], "not in the run.ended audit row")


# ---- the memory row
def result(allocated, end, word=None, stderr=b""):
    out = b"CANARYMEM" + chr(9).encode() + str(allocated).encode() + b"\n" if allocated is not None else b""
    if word:
        out += b"CANARYEND" + chr(9).encode() + word.encode() + b"\n"
    return {"stdout": out, "stderr": stderr, "end": end, "refused": None}


def end_of(**kw):
    base = {"reason": "exited", "exit": 1, "oom_kills": 0, "peak_mb": 127.9, "evidence": None}
    base.update(kw)
    return base


EV = {"max": 3, "high": 0, "oom": 0, "oom_kill": 0}
row = sh.memory_row(result(124, end_of(reason="oom", exit=137, oom_kills=1, evidence="poll")), MB)
must(row["verdict"] == "OK" and row["actual"].endswith("proof: oom_kill 1 (memory.events)"), row)
row = sh.memory_row(result(112, end_of(memory_events=EV)), MB)  # the dev02 case
must(row["verdict"] == "OK" and row["actual"].endswith("proof: memory.events max 3, peak 127.9 MiB <= 128 MiB"), row)
must("max 3, high 0, oom 0, oom_kill 0" in row["actual"], "the other counters are printed")
row = sh.memory_row(result(112, end_of(memory_events=EV, peak_mb=None)), MB)
must(row["verdict"] == "NOT RUN" and "proof:" not in row["actual"], row)
row = sh.memory_row(result(None, end_of(memory_events=EV)), MB)
must(row["verdict"] == "NOT RUN", "no allocation reported: nothing to check against the limit")
must(sh.memory_row(result(112, end_of(memory_events=EV, peak_mb=130.0)), MB)["verdict"] == "ATTACK SUCCEEDED", "peak above")
must(sh.memory_row(result(130, end_of(memory_events=EV)), MB)["verdict"] == "ATTACK SUCCEEDED", "allocated above")
must(sh.memory_row(result(112, end_of(memory_events=EV), word="done"), MB)["verdict"] == "ATTACK SUCCEEDED", "probe finished")
must(sh.memory_row(result(112, end_of(memory_events=EV, exit=0)), MB)["verdict"] == "ATTACK SUCCEEDED", "exit 0")
for none in ({"max": 0, "high": 0, "oom": 0, "oom_kill": 0}, {}, None, "junk", {"max": True}, {"max": -1}):
    row = sh.memory_row(result(112, end_of(memory_events=none)), MB)
    must(row["verdict"] == "NOT RUN" and "proof:" not in row["actual"], (none, row))  # the 1.17.123 hole stays closed
row = sh.memory_row(result(112, end_of(), word="memoryerror"), MB)
must(row["verdict"] == "OK" and row["actual"].endswith("proof: probe MemoryError at 112 MiB"), row)
row = sh.memory_row(result(112, end_of(), word="enomem"), MB)
must(row["verdict"] == "OK" and "proof: probe enomem at 112 MiB" in row["actual"], row)
# stderr: shown whenever there is a line, on OK too, and before the proof
row = sh.memory_row(result(112, end_of(memory_events=EV), stderr=b"\nBoom happened\nsecond\n"), MB)
must(row["verdict"] == "OK" and "; stderr: Boom happened; proof:" in row["actual"] and "second" not in row["actual"], row)
row = sh.memory_row(result(112, end_of(), stderr=b"Killed"), MB)
must(row["verdict"] == "NOT RUN" and "stderr: Killed" in row["actual"], row)
# every proof names itself
for res in (result(124, end_of(reason="oom", exit=137, oom_kills=2)), result(112, end_of(memory_events=EV)), result(112, end_of(), word="memoryerror")):
    must(sh.memory_row(res, MB)["actual"].rsplit("proof: ", 1)[1].split()[0] in ("oom_kill", "memory.events", "probe"), res)
for name in ("scripts/sandbox-helper.py", "scripts/sandbox-canary-runner.py", "tests/sandbox-memory-1.18.16.py"):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox memory 1.18.16")
