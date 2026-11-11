#!/usr/bin/env python3
"""1.17.123 regression: the memory-beyond-MemoryMax row is judged on what happened, not on systemd's label (core.sandbox canary, fix 3).

dev02 (Core 1.17.122) reported 'exited' for the 600 MiB allocation under MemoryMax=128M. MemorySwapMax=0 was already set, so swap alone does
not explain it. The likely cause: the kernel kills only the runner child, the launcher survives and exits 137 (128 + SIGKILL), and systemd
then records 'exit-code', not 'oom-kill', so the helper reported 'exited' and the 1.17.122 row called every non-oom reason an attack.

* the unit gets MemorySwapMax=0 and OOMPolicy=kill always, and MemoryZSwapMax=0 only from systemd 255 (an unknown property must not make
  every start fail); the selftest records the choice as information;
* the in-unit probe prints a flushed progress line after every 16 MiB block; the helper keeps the last one;
* the row is OK only when the run was stopped (reason oom, or exited with 137) and the last reported allocation and the memory peak are at or
  below MemoryMax plus one block; allocating past it, or finishing normally, is ATTACK SUCCEEDED; no end frame is NOT RUN; the actual
  column always names the MiB and how the run ended.

1.17.124 UPDATE: the row rule below ("stopped = oom or exit 137, plus one block of slack") is superseded; the expectations in the row section
of this file were changed to the new rule (OK only with kernel evidence or a refused allocation, no slack, NOT RUN for an unexplained end such
as exit 137 or exit 1 with no oom_kills). tests/sandbox-memory-1.17.124.py has the full table. The unit properties and the progress line
checks here are unchanged.

Not runnable here: the real kernel kill (dev02 runs tests/sandbox-canary-1.17.123.sh).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load("sandbox_harness_123c", "sandbox-harness-1.17.118.py")
F = load("sandbox_fake_123c", "sandbox-fake-runner-1.17.120.py")
sh, must, make_runner, start, header, unit_log = H.sh, H.must, H.make_runner, H.start, H.header, H.unit_log

# ---- the unit properties, end to end through a start with each systemd version
make_runner("ai.chat", body="print('hello')")
for version, zswap in ((255, True), (256, True), (254, False), (252, False), (249, False)):
    H.write_ready_status(systemd_version=version)
    code, frames = start(header("ai.chat"))
    props = unit_log(frames[0]["run_id"])["props"]
    must("MemorySwapMax=0" in props and "OOMPolicy=kill" in props, (version, props))
    must(("MemoryZSwapMax=0" in props) is zswap, (version, [p for p in props if "Swap" in p]))
H.write_ready_status(systemd_version=None)
code, frames = start(header("ai.chat"))
must("MemoryZSwapMax=0" not in unit_log(frames[0]["run_id"])["props"], "an unknown version never adds the property")
H.write_ready_status()
# the selftest records the choice as information, never as a failure
for version, text in ((255, "is set"), (252, "is not set")):
    fake = F.Fake(systemctl=(0, f"systemd {version} ({version}.1)\n+PAM +BPF_FRAMEWORK\n"))
    status = F.run_selftest(sh, H.RUN, H.BASE, fake)
    check = status["checks"]["memory_zswap"]
    must(status["ready"] is True and check["ok"] is True and text in check["detail"], check)
must("older than 255" in check["detail"] and "information only" in check["detail"], check)

# ---- the progress line from the in-unit probe
spec = importlib.util.spec_from_file_location("canary_runner_123c", H.ROOT / "scripts" / "sandbox-canary-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
out = io.StringIO()
with contextlib.redirect_stdout(out):
    runner.g_mem({"alloc_mb": 48})
lines = out.getvalue().splitlines()
must(lines[:3] == ["CANARYMEM\t16", "CANARYMEM\t32", "CANARYMEM\t48"], lines)
must(lines[3].startswith("CANARYROW\tmemory beyond MemoryMax\tSUCCEEDED\tallocated 48 MiB") and lines[4] == "CANARYEND\tdone", lines)
P = sh.parse_progress
must(P(out.getvalue().encode()) == 48 and P(b"CANARYMEM\t16\nCANARYMEM\t32\n") == 32 and P(b"") is None and P(b"CANARYMEM\tx\n") is None, "last number wins")
must(P(b"CANARYROW\tx\tOK\tCANARYMEM\t99\nCANARYMEM\t5\n") == 5, "only a line that is exactly the progress line counts")
# a row printed by the program is not a table row: the progress line is ignored by parse_runner_rows
must(sh.parse_runner_rows(b"CANARYMEM\t16\nCANARYMEM\t32\n") == [], "progress lines never become rows")

# ---- the row: judged on the MiB and how the run ended
LIMIT = 128


def stdout_for(mib):
    return "".join(f"CANARYMEM\t{n}\n" for n in range(16, mib + 1, 16)).encode()


def row(mib, reason, exit_code=None, peak=None, refused=None, end=True):
    result = {"stdout": stdout_for(mib), "refused": refused, "end": {"reason": reason, "exit": exit_code, "peak_mb": peak} if end else None}
    return sh.memory_row(result, LIMIT)


killed = row(112, "exited", 137, peak=127.9)
must(killed["verdict"] == "NOT RUN" and "allocated 112 MiB" in killed["actual"] and "ended exited (exit 137)" in killed["actual"], killed)  # 1.17.124: no oom evidence, so not OK
oom = row(112, "oom", 137, peak=128.0)
must(oom["verdict"] == "OK" and "allocated 112 MiB, ended oom" in oom["actual"], oom)
at_limit = row(128 + 16, "exited", 137)
must(at_limit["verdict"] == "ATTACK SUCCEEDED" and "allocated 144 MiB" in at_limit["actual"], "1.17.124: no slack above MemoryMax any more")
none_yet = sh.memory_row({"stdout": b"", "refused": None, "end": {"reason": "oom", "exit": 137, "peak_mb": 10.0}}, LIMIT)
must(none_yet["verdict"] == "OK" and "no allocation reported" in none_yet["actual"], none_yet)
past = row(600, "exited", 0)
must(past["verdict"] == "ATTACK SUCCEEDED" and "allocated 592 MiB, ended exited (exit 0)" in past["actual"], past)  # the 1.17.122 logic said OK for 'oom' and attack for the rest
past_killed = row(160, "exited", 137)
must(past_killed["verdict"] == "ATTACK SUCCEEDED" and "allocated 160 MiB" in past_killed["actual"], "killed, but only after going past the limit")
past_oom = row(600, "oom", 137)
must(past_oom["verdict"] == "ATTACK SUCCEEDED", "an oom label does not excuse a 592 MiB allocation")
normal = row(128, "exited", 0)
must(normal["verdict"] == "ATTACK SUCCEEDED", "finishing normally is an attack that succeeded, whatever it allocated")
must(row(112, "timeout")["verdict"] == "NOT RUN" and row(112, "cancelled")["verdict"] == "NOT RUN", "stopped by something else is not the memory wall (1.17.124: unexplained, NOT RUN)")
must(row(112, "exited", 1)["verdict"] == "NOT RUN", "1.17.124: dev02's exit 1 with no evidence is NOT RUN, neither OK nor an attack")
big_peak = row(112, "exited", 137, peak=300.0)
must(big_peak["verdict"] == "ATTACK SUCCEEDED" and "peak 300.0 MiB" in big_peak["actual"], "the handoff memory peak is over the limit")
must(row(112, "oom", 137, peak=None)["verdict"] == "OK", "no peak reported: the allocation alone decides")
missing = row(0, "oom", end=False)
must(missing["verdict"] == "NOT RUN" and "no end frame" in missing["actual"], missing)
refused = row(0, "oom", refused="sandbox_unavailable", end=False)
must(refused["verdict"] == "NOT RUN" and "refused: sandbox_unavailable" in refused["actual"], refused)
for case in (killed, oom, past, normal, big_peak):
    must("MiB" in case["actual"] and case["wall"] == "Limits" and case["attack"] == "memory beyond MemoryMax", case)

# ---- through _limit_rows with a fake collect: the memory row first, the other limit rows unchanged
calls = []


def collect(group, plan, **kwargs):
    calls.append((group, plan, kwargs))
    base = {"stdout": b"", "stderr": b"", "refused": None, "run_id": "r"}
    if group == "mem":
        return {**base, "stdout": stdout_for(112), "end": {"reason": "exited", "exit": 137, "peak_mb": 127.0, "oom_kills": 1}}
    if group == "loop":
        return {**base, "end": {"reason": "timeout", "exit": None}}
    if group == "flood":
        return {**base, "end": {"reason": "output_limit", "exit": None}}
    return {**base, "end": {"reason": "exited", "exit": 0}}


rows = sh._limit_rows(collect, {"ready": True})
must(calls[0][0] == "mem" and calls[0][1] == {"alloc_mb": 600} and calls[0][2]["memory_mb"] == 128, calls[0])
must(rows[0]["verdict"] == "OK" and rows[0]["actual"].startswith("allocated 112 MiB"), rows[0])
must([r["attack"] for r in rows if r["verdict"] == "OK"].count("infinite loop") == 1 and any(r["attack"] == "stdout past its cap" and r["verdict"] == "OK" for r in rows), rows)
# the old logic compared the reason with 'oom'; the source no longer does
source = (H.ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8")
must('one("memory beyond MemoryMax"' not in source, "the label-only comparison is gone")

print("[TEST] PASS sandbox memory 1.17.123")
