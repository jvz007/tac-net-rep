#!/usr/bin/env python3
"""1.18.17 regression: the memory canary row judges on systemd's unit result and reports the program's real exit or signal (dev02 canary of 1.18.16).

* dev02's exact end (reason oom from the unit result, allocated 112, no peak, memory.events all 0, unit_result oom-kill, signal 9) is OK, proof
  'systemd unit result oom-kill'.
* unit_result oom-kill with allocated or peak above MemoryMax is ATTACK SUCCEEDED; a forged unit_result (outside the whitelist, not a string) is ignored.
* Held Low of 1.18.14: the memory.events max proof counts only for end reason 'oom' or 'exited'. On timeout, cancelled, output_limit or
  start_failed the row is NOT RUN, 'ended by <reason>, not by the memory limit'.
* The row shows 'killed by signal 9' and 'unit result oom-kill', never systemd-run's 'exit 1'.
* The 1.17.123, 1.17.124, 1.18.8, 1.18.15 and 1.18.16 row tests run unchanged next to this one (release-integrity runs them all).

Not runnable here: the real unit result (dev02: tests/sandbox-canary-1.18.17.sh).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sandbox_harness_1817m", HERE / "sandbox-harness-1.17.118.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
sh, must = H.sh, H.must
MB = 128
ZERO = {"max": 0, "high": 0, "oom": 0, "oom_kill": 0}


def result(allocated, end, word=None, stderr=b""):
    out = b"CANARYMEM" + chr(9).encode() + str(allocated).encode() + b"\n" if allocated is not None else b""
    if word:
        out += b"CANARYEND" + chr(9).encode() + word.encode() + b"\n"
    return {"stdout": out, "stderr": stderr, "end": end, "refused": None}


def end_of(**kw):
    base = {"reason": "oom", "exit": None, "signal": 9, "unit_result": "oom-kill", "exit_source": "unit", "oom_kills": None, "peak_mb": None,
            "evidence": "unit_result", "memory_events": dict(ZERO)}
    base.update(kw)
    return base


# ---- dev02's exact end
row = sh.memory_row(result(112, end_of()), MB)
must(row["verdict"] == "OK" and row["actual"].endswith("proof: systemd unit result oom-kill"), row)
must("killed by signal 9" in row["actual"] and "unit result oom-kill" in row["actual"] and "exit 1" not in row["actual"], row)
must("allocated 112 MiB" in row["actual"] and "evidence unit_result" in row["actual"] and "memory.events max 0" in row["actual"], row)
# a peak alone is enough, and a known peak at or below the limit passes too
must(sh.memory_row(result(None, end_of(peak_mb=127.5)), MB)["verdict"] == "OK", "peak only")
must(sh.memory_row(result(124, end_of(peak_mb=127.5)), MB)["verdict"] == "OK", "both known")
must(sh.memory_row(result(None, end_of()), MB)["verdict"] == "NOT RUN", "neither known: nothing to check against the limit")
# above the limit, or a finished probe, is the attack succeeding
must(sh.memory_row(result(130, end_of()), MB)["verdict"] == "ATTACK SUCCEEDED", "allocated above")
must(sh.memory_row(result(112, end_of(peak_mb=130.0)), MB)["verdict"] == "ATTACK SUCCEEDED", "peak above")
must(sh.memory_row(result(112, end_of(), word="done"), MB)["verdict"] == "ATTACK SUCCEEDED", "probe finished")
must(sh.memory_row(result(112, end_of(reason="exited", exit=0, signal=None, unit_result="success")), MB)["verdict"] == "ATTACK SUCCEEDED", "normal exit 0")
# a unit result alone, with a reason that is not oom, is no proof
row = sh.memory_row(result(112, end_of(reason="exited", exit=1, signal=None, unit_result="oom-kill", memory_events=None)), MB)
must(row["verdict"] == "NOT RUN" and "proof:" not in row["actual"], row)
# forged values are ignored
for forged in ("banana", "OOM-KILL", 7, True, None, ["oom-kill"], {"a": 1}, "oom-kill\nOK"):
    row = sh.memory_row(result(112, end_of(reason="exited", exit=1, signal=None, unit_result=forged, memory_events=None)), MB)
    must(row["verdict"] == "NOT RUN" and "unit result" not in row["actual"], (forged, row))
for forged in (0, 65, -9, "9", True, 9.0, None):
    row = sh.memory_row(result(112, end_of(signal=forged)), MB)
    must("killed by signal" not in row["actual"] and row["verdict"] == "OK", (forged, row))

# ---- held Low: max proof only when the kernel ended the run
EV = {"max": 3, "high": 0, "oom": 0, "oom_kill": 0}
for reason in ("timeout", "cancelled", "output_limit", "start_failed"):
    row = sh.memory_row(result(112, end_of(reason=reason, exit=None, signal=None, unit_result=None, peak_mb=127.9, memory_events=EV, evidence=None)), MB)
    must(row["verdict"] == "NOT RUN" and f"ended by {reason}, not by the memory limit" in row["actual"] and "proof:" not in row["actual"], (reason, row))
for reason in ("exited", "oom"):
    row = sh.memory_row(result(112, end_of(reason=reason, exit=1, signal=None, unit_result=None, peak_mb=127.9, memory_events=EV, evidence=None)), MB)
    must(row["verdict"] == "OK" and "proof: " in row["actual"], (reason, row))
# the exited case keeps the 1.18.16 proof text; the oom case names the end reason
row = sh.memory_row(result(112, end_of(reason="exited", exit=1, signal=None, unit_result=None, peak_mb=127.9, memory_events=EV, evidence=None)), MB)
must(row["actual"].endswith("proof: memory.events max 3, peak 127.9 MiB <= 128 MiB"), row)
# ATTACK SUCCEEDED is not softened by a bad reason
must(sh.memory_row(result(130, end_of(reason="timeout", unit_result=None, signal=None, memory_events=EV)), MB)["verdict"] == "ATTACK SUCCEEDED", "over limit on timeout")

# ---- the older row shapes (no new keys) behave as before
old = {"reason": "oom", "exit": 137, "oom_kills": 1, "peak_mb": 124.0, "evidence": "poll"}
row = sh.memory_row(result(124, old), MB)
must(row["verdict"] == "OK" and row["actual"].endswith("proof: oom_kill 1 (memory.events)") and "signal" not in row["actual"], row)
row = sh.memory_row(result(112, {"reason": "exited", "exit": 1, "oom_kills": 0, "peak_mb": 100.0}), MB)
must(row["verdict"] == "NOT RUN" and "exit 1" in row["actual"], row)

for name in ("tests/sandbox-memory-1.18.17.py",):
    must(b"\r" not in (H.ROOT / name).read_bytes(), name + " is LF")
print("[TEST] PASS sandbox memory 1.18.17")
