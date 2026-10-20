#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.64 regression (the held Low of the 1.17.63 review): the unfinished-job skip cache no longer trusts the mtime alone.

Before, a job file read as not finished was skipped with no read for as long as its mtime was equal. A rewrite that restored the mtime
(a copy that keeps times, a clock step) hid a finished job for good. Now the stamp is (st_mtime_ns, st_size) from the same stat, and an entry
is skipped only while it is young: after WAITING_TICKS ticks it is read once more and remembered again.

The setup is the first part of tests/server-job-finished-hook-1.17.62.py, read from that file. Covered: a same-mtime, same-size rewrite to
succeeded is still skipped on the very next tick (cost control holds) and is read and delivered exactly once after WAITING_TICKS ticks; a
size-only change is read at once; an expired entry for a still-running file is read once and remembered again; entries outside the window
are dropped; 60 unfinished files do not starve a finished job; a delivered job leaves the memory.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE = Path(__file__).resolve().parent / "server-job-finished-hook-1.17.62.py"
text = BASE.read_text(encoding="utf-8")
exec(compile(text[: text.index("# ---- (1) a job finishes with no page open")], str(BASE), "exec"), globals())  # noqa: S102 - the shared setup of the 1.17.62 test

real_read = sm._read_job
READS = []
sm._read_job = lambda job_id: READS.append(job_id) or real_read(job_id)


def fresh():
    reset()
    hooks._WAITING.clear()
    del READS[:]
    register("certificatemanagement")


def counted_tick():
    del READS[:]
    return tick()


def pad_to(path, size):
    data = path.read_bytes()
    must(len(data) <= size, (len(data), size))
    path.write_bytes(data + b" " * (size - len(data)))


must(hooks.WAITING_TICKS == 5, hooks.WAITING_TICKS)

# ---- (1) a same-mtime, same-size rewrite is skipped while young, read again once the entry has expired
fresh()
jid = new_id()
job_file(jid, status="succeeded", age=100)
final_size = (JOBS_ROOT / f"{jid}.json").stat().st_size
job_file(jid, status="running", age=100)
path = JOBS_ROOT / f"{jid}.json"
pad_to(path, final_size)
before = path.stat()
must(before.st_size == final_size, "padded to the size the finished file will have")
counts = counted_tick()
must(READS == [jid] and counts["waiting"] == 1 and not STORED, (counts, READS))
stamp, _tick_no = hooks._WAITING[jid]
must(stamp == (before.st_mtime_ns, before.st_size), (stamp, before.st_mtime_ns))
job_file(jid, status="succeeded", age=100)  # finished now, same size
os.utime(path, ns=(before.st_mtime_ns, before.st_mtime_ns))
after = path.stat()
must((after.st_mtime_ns, after.st_size) == stamp, "the rewrite kept both mtime and size")
counts = counted_tick()
must(READS == [] and counts["waiting"] == 1 and counts["checked"] == 0 and not STORED, (counts, READS))
for _ in range(hooks.WAITING_TICKS - 2):
    counts = counted_tick()
    must(READS == [] and not STORED, (counts, READS))
counts = counted_tick()
must(READS == [jid] and counts["delivered"] == 1 and len(STORED) == 1 and STORED[0][1] == f"server-job:{jid}", (counts, READS, STORED))
must(jid not in hooks._WAITING, "a delivered job leaves the memory")
for _ in range(hooks.WAITING_TICKS + 2):
    counted_tick()
must(len(STORED) == 1, "delivered exactly once")
print("       a same-mtime, same-size rewrite is skipped while young, then read and delivered exactly once after WAITING_TICKS ticks")

# ---- (2) a size-only change (same mtime) is read at once
fresh()
jid = new_id()
job_file(jid, status="running", age=100)
path = JOBS_ROOT / f"{jid}.json"
mtime_ns = path.stat().st_mtime_ns
counted_tick()
job_file(jid, status="succeeded", age=100)
os.utime(path, ns=(mtime_ns, mtime_ns))
must(path.stat().st_mtime_ns == mtime_ns, "same mtime")
counts = counted_tick()
must(READS == [jid] and counts["delivered"] == 1, (counts, READS))
print("       a rewrite that changes only the size is read on the next tick")

# ---- (3) an expired entry for a still-running file is read once and remembered again
fresh()
jid = new_id()
job_file(jid, status="running", age=100)
counted_tick()
for _ in range(hooks.WAITING_TICKS - 2):
    counted_tick()
    must(READS == [], READS)
reads = []
for _ in range(3 * hooks.WAITING_TICKS):
    counted_tick()
    reads.append(len(READS))
must(sum(reads) == 3 and all(n in (0, 1) for n in reads), reads)  # one read every few ticks, no more
must(jid in hooks._WAITING and not STORED, "still remembered, not delivered")
print("       a stuck running file costs one read every few ticks, not one a tick")

# ---- (4) entries outside the window are dropped
fresh()
for n in range(10):
    job_file(new_id(), status="running", age=100 + n)
counted_tick()
must(len(hooks._WAITING) == 10, len(hooks._WAITING))
NOW[0] += timedelta(hours=7)
counts = counted_tick()
must(counts["checked"] == 0 and not hooks._WAITING, (counts, len(hooks._WAITING)))
print("       entries outside the six-hour window are dropped")

# ---- (5) 60 unfinished files older than one finished job: the starvation protection of 1.17.63 stays
fresh()
for n in range(60):
    job_file(new_id(), status="running", age=5000 - n)
done = new_id()
job_file(done, status="succeeded", age=10)
counts = counted_tick()
must(counts["delivered"] == 1 and len(STORED) == 1 and counts["waiting"] == 60, (counts, STORED))
counts = counted_tick()
must(READS == [] and counts["waiting"] == 60, (counts, READS))
must(all(isinstance(v, tuple) and len(v) == 2 and len(v[0]) == 2 for v in hooks._WAITING.values()), "entries are (stamp, tick)")
print("       60 unfinished files still cost no read on the next tick and do not starve a finished job")
print("PASS server job hook skip cache 1.17.64")
