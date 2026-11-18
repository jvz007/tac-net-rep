#!/usr/bin/env python3
"""1.18.8 regression: memory evidence from memory.events and memory.peak, read from a fixed path and polled while the run lives (core.sandbox Patch A, part 3).

* the cgroup path of a run is built from constants and the hex run id only (``unit_cgroup_folders``): systemd's nested slice path first
  (``tec.slice/tec-tac.slice/tec-tac-sandbox.slice``, a dash in a slice name is nesting), the flat one second; a non-hex run id is refused;
* ``CgroupWatch`` keeps the maximum of oom_kill and memory.peak, falls back to the highest memory.current when memory.peak is missing (kernel older
  than 5.19), and tolerates a missing or vanished folder or file (never an error, never a guess);
* through ``--start``: a run whose cgroup shows an oom kill gives oom_kills >= 1 with evidence 'poll' even when the ExecStopPost handoff is empty,
  a run with no cgroup folder gives None for both, the handoff and SERVICE_RESULT=oom-kill name their own evidence;
* the memory row (the judge): OK with poll-only evidence, OK with service_result oom-kill, NOT RUN with no evidence, ATTACK SUCCEEDED when the
  allocation or the peak is above MemoryMax or the probe finished; the actual text names the evidence source.

Not runnable here: the real cgroup and the kernel's OOM kill (dev02: the memory row of tests/sandbox-canary-1.18.8.sh).
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


H = load("sandbox_harness_188g", HERE / "sandbox-harness-1.17.118.py")
sh, must, BASE = H.sh, H.must, H.BASE
CG = BASE / "cgroup"
CG.mkdir()
sh.CGROUP_ROOT = CG
NL = chr(10)

# ---- the path
RID = os.urandom(16).hex()
folders = sh.unit_cgroup_folders(RID)
must(folders == [CG / "tec.slice" / "tec-tac.slice" / "tec-tac-sandbox.slice" / f"tectac-sbx-{RID}.service", CG / "tec-tac-sandbox.slice" / f"tectac-sbx-{RID}.service"], folders)
must(sh.slice_cgroup_folders("a-b-c.slice")[0] == CG / "a.slice" / "a-b.slice" / "a-b-c.slice" and sh.slice_cgroup_folders("plain.slice") == [CG / "plain.slice", CG / "plain.slice"], "nesting from the dashes")
for bad in ("../" + "a" * 29, "AB" * 16, "ab" * 15, "", "ab" * 16 + "/", None, "a" * 31 + "\x00"):
    try:
        sh.unit_cgroup_folders(bad)
        raise AssertionError(f"run id {bad!r} was accepted")
    except RuntimeError:
        pass
must(all(".." not in str(f.relative_to(CG)) for f in folders), "no '..'")

# ---- the parser
must(sh.parse_memory_events("low 0\nhigh 0\nmax 214\noom 1\noom_kill 3\noom_group_kill 0\n") == (3, 1), "kernel text")
must(sh.parse_memory_events("oom_kill notanumber\noom_kill\nxyz 5 6\n") == (None, None) and sh.parse_memory_events("") == (None, None), "junk")
must(sh.parse_memory_events("oom_kill 2\noom_kill 4\n") == (4, None), "the last value of a repeated key")


# ---- the watch
def make_group(run_id, *, events=None, peak=None, current=None, nested=True):
    base = (CG / "tec.slice" / "tec-tac.slice" / "tec-tac-sandbox.slice") if nested else (CG / "tec-tac-sandbox.slice")
    folder = base / f"tectac-sbx-{run_id}.service"
    folder.mkdir(parents=True, exist_ok=True)
    if events is not None:
        (folder / "memory.events").write_text(events, encoding="ascii")
    if peak is not None:
        (folder / "memory.peak").write_text(f"{peak}\n", encoding="ascii")
    if current is not None:
        (folder / "memory.current").write_text(f"{current}\n", encoding="ascii")
    return folder


rid = os.urandom(16).hex()
watch = sh.CgroupWatch(rid)
watch.sample(force=True)
must(watch.oom_kill is None and watch.peak is None and watch.peak_bytes() is None, "no folder: nothing known, nothing guessed")
folder = make_group(rid, events="oom 1\noom_kill 2\n", peak=134217728)
watch.sample(10.0)
must(watch.oom_kill == 2 and watch.oom == 1 and watch.peak == 134217728 and watch.peak_bytes() == 134217728, vars(watch))
(folder / "memory.events").write_text("oom 0\noom_kill 1\n", encoding="ascii")
(folder / "memory.peak").write_text("1000\n", encoding="ascii")
watch.sample(11.0)
must(watch.oom_kill == 2 and watch.peak == 134217728, "the maximum is kept")
(folder / "memory.events").write_text("oom_kill 5\n", encoding="ascii")
watch.sample(12.0)
must(watch.oom_kill == 5, "a higher value replaces it")
# rate limit: a sample less than 0.2 s after the last is skipped, a forced one is not
(folder / "memory.events").write_text("oom_kill 9\n", encoding="ascii")
watch.sample(12.1)
must(watch.oom_kill == 5, "inside the interval: skipped")
watch.sample(12.3)
must(watch.oom_kill == 9, "after the interval")
(folder / "memory.events").write_text("oom_kill 10\n", encoding="ascii")
watch.sample(12.31, force=True)
must(watch.oom_kill == 10, "forced")
# the folder vanishes mid-run: tolerated, the values stay
for name in ("memory.events", "memory.peak"):
    (folder / name).unlink()
folder.rmdir()
watch.sample(20.0)
must(watch.oom_kill == 10 and watch.peak == 134217728, "a vanished folder keeps what was seen")
# memory.peak missing: the highest memory.current seen
rid2 = os.urandom(16).hex()
folder2 = make_group(rid2, events="oom_kill 0\n", current=50 * 1048576)
watch2 = sh.CgroupWatch(rid2)
watch2.sample(1.0)
(folder2 / "memory.current").write_text(f"{90 * 1048576}\n", encoding="ascii")
watch2.sample(2.0)
(folder2 / "memory.current").write_text(f"{30 * 1048576}\n", encoding="ascii")
watch2.sample(3.0)
must(watch2.peak is None and watch2.peak_bytes() == 90 * 1048576 and watch2.oom_kill == 0, vars(watch2))
# the flat path is used when the nested one does not exist; a junk file is ignored
rid3 = os.urandom(16).hex()
folder3 = make_group(rid3, events="oom_kill 4\n", peak="not a number", nested=False)
watch3 = sh.CgroupWatch(rid3)
watch3.sample(1.0)
must(watch3.oom_kill == 4 and watch3.peak is None, vars(watch3))

# ---- read_cgroup_memory: the fixed path first, no systemctl when it finds something
calls = []
real_systemctl = sh.systemctl
sh.systemctl = lambda *a, **k: calls.append(a) or (1, "", "")
rid4 = os.urandom(16).hex()
make_group(rid4, events="oom_kill 3\n", peak=7 * 1048576)
must(sh.read_cgroup_memory(rid4) == (3, 7 * 1048576) and not calls, (calls,))
must(sh.read_cgroup_memory(os.urandom(16).hex()) == (None, None) and calls, "nothing at the fixed path: the 1.17.124 lookup runs, and finds nothing here")
sh.systemctl = real_systemctl

# ---- merge_memory_evidence
W = sh.CgroupWatch(os.urandom(16).hex())
must(sh.merge_memory_evidence(W, {}, "") == (None, None, None), "nothing")
W.oom_kill, W.peak = 1, 100 * 1048576
must(sh.merge_memory_evidence(W, {"memory_peak": 50 * 1048576}, "") == (100 * 1048576, 1, "poll"), "the poll wins the evidence, the larger peak wins")
W.oom_kill, W.peak = None, None
must(sh.merge_memory_evidence(W, {"oom_kills": 2, "memory_peak": 5}, "") == (5, 2, "finish"), "the handoff alone")
must(sh.merge_memory_evidence(W, {}, "oom-kill") == (None, None, "service_result"), "SERVICE_RESULT alone names itself and invents no count")
W.oom_kill = 0
must(sh.merge_memory_evidence(W, {"oom_kills": True, "memory_peak": True}, "success") == (None, 0, None), "bool is not a number; zero kills is no evidence of a kill")
W.oom_kill, W.peak = 3, None
W.current_max = 10
must(sh.merge_memory_evidence(W, {"memory_peak": 4}, "") == (10, 3, "poll"), "the memory.current maximum stands in for a missing peak")

# ---- through --start
H.write_ready_status()
H.make_runner("ai.mem", body="time.sleep(1.2)\nprint('done')")
rid5 = os.urandom(16).hex()
make_group(rid5, events="oom 1\noom_kill 1\n", peak=100 * 1048576)
code, frames = H.start(H.header("ai.mem", run_id=rid5))
end = H.end_of(frames)
must(end["oom_kills"] == 1 and end["evidence"] == "poll" and end["peak_mb"] == 100.0, end)  # the fake systemd's handoff says 50 MiB and no oom_kills
rid6 = os.urandom(16).hex()
code, frames = H.start(H.header("ai.mem", run_id=rid6))
end = H.end_of(frames)
must(end["oom_kills"] is None and end["evidence"] is None and end["peak_mb"] == 50.0 and end["reason"] == "exited", end)
real_read = sh.read_handoff
sh.read_handoff = lambda run_id: {"oom_kills": 2, "memory_peak": 60 * 1048576, "result": "exit-code"}
end = H.end_of(H.start(H.header("ai.mem", run_id=os.urandom(16).hex()))[1])
must(end["oom_kills"] == 2 and end["evidence"] == "finish" and end["peak_mb"] == 60.0, end)
sh.read_handoff = lambda run_id: {"result": "oom-kill"}
end = H.end_of(H.start(H.header("ai.mem", run_id=os.urandom(16).hex()))[1])
must(end["reason"] == "oom" and end["evidence"] == "service_result" and end["oom_kills"] is None, end)
sh.read_handoff = real_read
must(H.leftovers() == [] or not H.leftovers(), H.leftovers())
# the frame is still valid json with the known keys (the Django side reads known keys only: the new key is additive)
must({"t", "exit", "reason", "ms", "peak_mb", "oom_kills", "credential_b64", "bytes_out", "bytes_err", "evidence"} == set(end), sorted(end))
django_side = (HERE.parent / "framwork" / "tec_tac" / "sandbox.py").read_text(encoding="utf-8")
must("evidence" not in django_side, "the Django side does not read the new key, so adding it changes no contract")

# ---- the memory row (the judge)
MB = 128


def result(allocated, end, word=None, stderr=b""):
    out = b"CANARYMEM" + chr(9).encode() + str(allocated).encode() + b"\n" if allocated is not None else b""
    if word:
        out += b"CANARYEND" + chr(9).encode() + word.encode() + b"\n"
    return {"stdout": out, "stderr": stderr, "end": end, "refused": None}


row = sh.memory_row(result(112, {"reason": "exited", "exit": 1, "oom_kills": 1, "peak_mb": 120.0, "evidence": "poll"}), MB)
must(row["verdict"] == "OK" and "evidence poll" in row["actual"] and "oom_kills 1" in row["actual"] and "allocated 112 MiB" in row["actual"], row)
row = sh.memory_row(result(112, {"reason": "oom", "exit": 137, "oom_kills": None, "peak_mb": None, "evidence": "service_result"}), MB)
must(row["verdict"] == "OK" and "evidence service_result" in row["actual"], row)
row = sh.memory_row(result(112, {"reason": "exited", "exit": 1, "oom_kills": None, "peak_mb": None, "evidence": None}), MB)
must(row["verdict"] == "NOT RUN" and "no evidence of how it ended" in row["actual"] and "evidence" not in row["actual"].split(";")[0], row)
row = sh.memory_row(result(None, {"reason": "exited", "exit": 1, "oom_kills": 1, "peak_mb": None, "evidence": "poll"}), MB)
must(row["verdict"] == "NOT RUN", "a kill with no allocation and no peak to check against the limit is not enough")
for label, res in (("allocation above the limit", result(200, {"reason": "oom", "exit": 137, "oom_kills": 1, "peak_mb": 100.0, "evidence": "poll"})),
                   ("peak above the limit", result(100, {"reason": "oom", "exit": 137, "oom_kills": 1, "peak_mb": 130.0, "evidence": "poll"})),
                   ("the probe finished", result(112, {"reason": "exited", "exit": 0, "oom_kills": 1, "peak_mb": 100.0, "evidence": "poll"}, word="done")),
                   ("a clean exit", result(112, {"reason": "exited", "exit": 0, "oom_kills": None, "peak_mb": 100.0, "evidence": None}))):
    must(sh.memory_row(res, MB)["verdict"] == "ATTACK SUCCEEDED", label)
row = sh.memory_row(result(112, {"reason": "exited", "exit": 1, "oom_kills": None, "peak_mb": 100.0, "evidence": None}, word="memoryerror"), MB)
must(row["verdict"] == "OK" and "evidence" not in row["actual"], row)
must(sh.memory_row({"stdout": b"", "end": None, "refused": None}, MB)["verdict"] == "NOT RUN" and sh.memory_row({"refused": "busy", "end": None}, MB)["verdict"] == "NOT RUN", "no end frame")
bogus = sh.memory_row(result(112, {"reason": "exited", "exit": 1, "oom_kills": 1, "peak_mb": 100.0, "evidence": "../etc/passwd"}), MB)
must("passwd" not in bogus["actual"] and "evidence" not in bogus["actual"], "only the three known words are ever printed")

print("[TEST] PASS sandbox cgroup evidence 1.18.8")
