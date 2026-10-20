#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.63 regression (the held Medium of the 1.17.62 review): unfinished job files cannot use the whole 50-per-tick batch of the server job hook.

Before, a tick read the 50 oldest job files that had no hook row yet. A job file that is not finished never gets a row, so 50 stuck files
(oldest first) were read again every minute and a finished job behind them was never reached. Now READ_BUDGET (200) caps the files READ in one
tick and BATCH (50) caps only the FINISHED jobs handed over; a file read as not finished is remembered with its mtime and skipped with no read
until the file changes (a status change rewrites the file and so changes its mtime); entries outside the six-hour window are dropped.

The setup is the first part of tests/server-job-finished-hook-1.17.62.py, read from that file. Covered: 60 unfinished files older than one finished
job: the finished job is handed over in ONE tick, and a second tick reads none of the 60; a job that later turns finished is delivered; 120
unfinished files plus one finished job are delivered in one tick; 250 unfinished files use the whole READ_BUDGET in the first tick (stated), and
the next tick reaches the finished job; more than 50 finished jobs still hand over 50 a tick; a touched file is read again once; an unreadable
file is NOT remembered (it is tried every tick); a briefly missing file is remembered like an unfinished one; the memory is bounded and cleared
outside the window; the counts keys and the at-most-once rule are as in 1.17.62.
"""
from __future__ import annotations

from pathlib import Path

BASE = Path(__file__).resolve().parent / "server-job-finished-hook-1.17.62.py"
text = BASE.read_text(encoding="utf-8")
exec(compile(text[: text.index("# ---- (1) a job finishes with no page open")], str(BASE), "exec"), globals())  # noqa: S102 - the shared setup of the 1.17.62 test

KEYS = {"checked", "delivered", "waiting", "skipped", "ignored", "duplicate", "retry", "abandoned", "unreadable", "errors"}
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


# ---- (1) the budget is stated and the memory exists
must(hooks.BATCH == 50 and hooks.READ_BUDGET == 200 and hooks.CANDIDATE_CAP == 2000, (hooks.BATCH, hooks.READ_BUDGET, hooks.CANDIDATE_CAP))
must(isinstance(hooks._WAITING, dict), "a small in-process memory")

# ---- (2) 60 unfinished files older than one finished job
fresh()
stuck = [new_id() for _ in range(60)]
for n, jid in enumerate(stuck):
    job_file(jid, status="running", age=5000 - n)  # all older than the finished job
done = new_id()
job_file(done, status="succeeded", age=10)
counts = counted_tick()
must(counts["delivered"] == 1 and len(STORED) == 1 and STORED[0][1] == f"server-job:{done}" and HOOKS[done]["state"] == "queued", (counts, STORED))
must(counts["waiting"] == 60 and counts["checked"] == 61 and len(READS) == 61 and counts["errors"] == 0, (counts, len(READS)))
must(set(counts) == KEYS, "the counts keys are those of 1.17.62")
counts = counted_tick()
must(READS == [] and counts["waiting"] == 60 and counts["checked"] == 0 and counts["delivered"] == 0 and len(STORED) == 1, (counts, READS))
must(len(hooks._WAITING) == 60, "60 files are remembered")
print("       60 unfinished files older than one finished job: the finished job is delivered in ONE tick and the next tick reads none of the 60")

# a job that later turns finished is delivered: its file is rewritten, so its mtime changes
later = stuck[7]
job_file(later, status="failed", exit_code=1, classification="script_failed", age=0)
counts = counted_tick()
must(READS == [later] and counts["delivered"] == 1 and len(STORED) == 2 and STORED[1][2]["status"] == "failed", (counts, READS, STORED))
must(later not in hooks._WAITING and len(hooks._WAITING) == 59, "a delivered job leaves the memory")
# a file that is touched but still unfinished is read once more, then remembered again
touched = stuck[9]
job_file(touched, status="running", age=1)
counts = counted_tick()
must(READS == [touched] and counts["delivered"] == 0 and counts["waiting"] == 59, (counts, READS))
counts = counted_tick()
must(READS == [], "and not read again")
print("       a job that later turns finished is delivered; a touched but unfinished file is read once more and remembered again")

# ---- (3) 120 unfinished files plus one finished job are delivered within one tick
fresh()
for n in range(120):
    job_file(new_id(), status="running", age=5000 - n)
done = new_id()
job_file(done, status="succeeded", age=10)
counts = counted_tick()
must(counts["delivered"] == 1 and len(READS) == 121 and counts["waiting"] == 120, (counts, len(READS)))
print("       120 unfinished files and one finished job: delivered within one tick (121 reads, under the budget of 200)")

# ---- (4) the read budget is the bound: 250 unfinished files use all 200 reads of the first tick, the next tick reaches the finished job
fresh()
for n in range(250):
    job_file(new_id(), status="running", age=5500 - n)
done = new_id()
job_file(done, status="succeeded", age=10)
counts = counted_tick()
must(len(READS) == hooks.READ_BUDGET == 200 and counts["delivered"] == 0 and counts["checked"] == 200 and not STORED, (counts, len(READS)))
counts = counted_tick()
must(len(READS) == 51 and counts["delivered"] == 1 and len(STORED) == 1 and STORED[0][1] == f"server-job:{done}", (counts, len(READS)))
counts = counted_tick()
must(READS == [] and len(STORED) == 1, "after that every stuck file is remembered: a tick costs no read")
print("       250 unfinished files use the whole READ_BUDGET of 200 in the first tick; the second tick reads only the 51 not yet seen and delivers the finished job")

# ---- (5) more than 50 finished jobs still hand over 50 a tick, oldest first, each read once
fresh()
ids = [new_id() for _ in range(120)]
for n, jid in enumerate(ids):
    job_file(jid, status="succeeded", age=3000 - n * 10)
counts = counted_tick()
must(counts["delivered"] == 50 and counts["checked"] == 50 and len(READS) == 50 and READS == ids[:50] and len(STORED) == 50, (counts, len(READS)))
counted_tick()
counted_tick()
must(len(STORED) == 120 and len({s[1] for s in STORED}) == 120, "the rest follow, each exactly once")
counts = counted_tick()
must(counts["checked"] == 0 and len(STORED) == 120, "at most once: a later tick hands nothing over again")
print("       more than 50 finished jobs: 50 handed over a tick, oldest first, each exactly once")

# unfinished files do not take handed-over places: 30 unfinished (older) and 70 finished
fresh()
for n in range(30):
    job_file(new_id(), status="queued", age=5000 - n)
fin = [new_id() for _ in range(70)]
for n, jid in enumerate(fin):
    job_file(jid, status="succeeded", age=3000 - n)
counts = counted_tick()
must(counts["delivered"] == 50 and counts["waiting"] == 30 and len(READS) == 80, (counts, len(READS)))
counts = counted_tick()
must(counts["delivered"] == 20 and len(READS) == 20 and len(STORED) == 70, (counts, len(READS)))
print("       unfinished files take no place in the 50: 30 unfinished and 70 finished deliver 50, then 20")

# ---- (6) an unreadable file is not remembered; a briefly missing file is
fresh()
(JOBS_ROOT / f"{new_id()}.json").write_text("{not json", encoding="utf-8")
counts = counted_tick()
must(counts["unreadable"] == 1 and len(READS) == 1 and not hooks._WAITING, (counts, hooks._WAITING))
counts = counted_tick()
must(counts["unreadable"] == 1 and len(READS) == 1, "an unreadable file is tried every tick (a transient fault must not hide a job)")
fresh()
ghost = new_id()
job_file(ghost, status="succeeded")
real = sm._read_job
sm._read_job = lambda job_id: READS.append(job_id) or (_ for _ in ()).throw(sm.ServerMaintenanceNotFound("gone"))
counts = counted_tick()
must(counts["waiting"] == 1 and READS == [ghost] and ghost in hooks._WAITING, (counts, READS))
counts = counted_tick()
must(READS == [] and counts["waiting"] == 1, "a briefly missing file is remembered like an unfinished one")
sm._read_job = lambda job_id: READS.append(job_id) or real_read(job_id)
job_file(ghost, status="succeeded", age=0)  # it came back, rewritten
counts = counted_tick()
must(counts["delivered"] == 1 and READS == [ghost], (counts, READS))
print("       an unreadable file is tried every tick; a briefly missing file is remembered like an unfinished one and read again once it changes")

# ---- (7) the memory is bounded and cleared outside the window
fresh()
for n in range(30):
    job_file(new_id(), status="running", age=100 + n)
counted_tick()
must(len(hooks._WAITING) == 30, len(hooks._WAITING))
NOW[0] += timedelta(hours=7)  # every file is now outside the six-hour window
counts = counted_tick()
must(counts["checked"] == 0 and not hooks._WAITING, (counts, len(hooks._WAITING)))
fresh()
for n in range(30):
    job_file(new_id(), status="running", age=100 + n)
must(hooks.CANDIDATE_CAP == 2000, "at most 2000 candidates are listed, so the memory holds at most 2000 entries")
for path in JOBS_ROOT.glob("*.json"):
    path.unlink()
counted_tick()
must(not hooks._WAITING, "a file that is gone leaves the memory on the next tick")
print("       the memory is bounded by the 2000-candidate cap and forgets a file that left the window or the folder")

# ---- (8) nothing else changed: the claim, the at-most-once row and the tick's output line
fresh()
job_file(new_id(), status="succeeded")
counts = counted_tick()
must(counts["delivered"] == 1 and len(STORED) == 1, counts)
counts = counted_tick()
must(counts["delivered"] == 0 and len(STORED) == 1 and counts["checked"] == 0, "a handled job is never handed over twice")
src = (APP / "server_job_hooks.py").read_text(encoding="utf-8")
must(src.index("if not _claim(job_id, **common):") < src.index("events.publish_for_core(hook_job_id(owner)"), "the claim is still written before the event is stored")
tick_src = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup}" in tick_src, "the tick's own output line is unchanged")
must("def _settled_ids(job_ids: list[str]) -> set[str]:" in src and "TecTacServerJobHook.objects.filter(job_id__in=chunk, state__in=SETTLED_STATES)" in src, "settled ids still come from the database")
print("       the claim comes before the event, a handled job is never handed over twice, the counts keys and the tick's output line are unchanged")
print("PASS server job hook starvation 1.17.63")
