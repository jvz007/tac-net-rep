#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-22, the Core-owned half): a Scheduler run awaits a finished server-maintenance job.

Real scheduler.py, scheduler_completion.py and tasks.py on the stub harness; the job store is a dict that stands in for
server_maintenance._read_job (the real file's names are pinned by source below). Covered: a handler that starts a job returns
pending_completion('server_maintenance_job', job_id); Core refuses the pending state at return unless the job exists and names this
module and this run; the tick step settles each terminal state once (succeeded, failed, dispatch_failed, cancelled), leaves a running job
pending, fails a missing job record after 10 minutes, is idempotent across ticks, never raises, looks at 50 runs a tick, ignores
module-kind runs; the result and error carry no job output or parameter; the tick's own output line is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

MARKER = "SECRET-MARKER-91c2"
alice = User("alice")
plugin("certificatemanagement")
plugin("backups")


def job_record(job_id, *, module, run_id, status="queued", exit_code=None, classification=None):
    return {
        "id": job_id, "action": "x.renew", "status": status,
        "context": {"source_module": module, "source_action": "renew", "source_run_id": str(run_id), "requested_by": "alice"},
        "parameters": {"password": MARKER}, "public_parameters": {"password": "<redacted>"},
        "exit_result": {"success": status == "succeeded", "exit_code": exit_code, "signal": None, "timed_out": False},
        "failure": {"classification": classification, "message": f"failed with {MARKER}"} if classification else None,
    }


STARTED = {}


def starting_handler(module, bind_to):
    def handler(context):
        job_id = str(uuid.uuid4())
        run_id = str(uuid.uuid4()) if bind_to == "other-run" else context["run_id"]
        if bind_to != "missing":
            JOBS[job_id] = job_record(job_id, module=module, run_id=run_id)
        STARTED["job_id"] = job_id
        return sched.pending_completion("server_maintenance_job", job_id, note="Waiting for the server job.")
    return handler


for aid, module, bind in (("certificatemanagement.renew", "certificatemanagement", "this"), ("certificatemanagement.wrongrun", "certificatemanagement", "other-run"),
                          ("certificatemanagement.wrongmod", "backups", "this"), ("certificatemanagement.nojob", "certificatemanagement", "missing")):
    sched.register_scheduled_action(id=aid, module_id="certificatemanagement", label=aid, handler=starting_handler(module, bind), target_types=("none",), timeout_seconds=3600)


def park(action="certificatemanagement.renew"):
    run = make_run(action, "certificatemanagement", user=alice)
    out = go(run)
    return run, out


def settle(**kw):
    return completion.settle_server_job_runs(**kw)


# ---- the job is checked when the handler returns
reset()
run, out = park()
must(out == "pending completion" and run.status == "running" and run.completion_state == "pending", (out, run.__dict__))
must(run.completion_ref == {"kind": "server_maintenance_job", "external_job_id": STARTED["job_id"], "note": "Waiting for the server job."}, run.completion_ref)
print("       a handler that started its own job for this run is parked")

for action, why in (("certificatemanagement.wrongrun", "the job names another run"), ("certificatemanagement.wrongmod", "the job names another module"),
                    ("certificatemanagement.nojob", "the job does not exist")):
    reset()
    run, out = park(action)
    must(run.status == "failed" and run.error_type == "PendingRefused" and run.completion_state == "" and run.schedule.last_run_at is not None, (why, run.__dict__))
    must(MARKER not in repr(run.__dict__), why)
print("       at return Core refuses a missing job, another module's job and another run's job (PendingRefused)")

reset()
JOB_FAULT["unreadable"] = True
run, out = park()
must(run.status == "failed" and run.error_type == "PendingRefused", "an unreadable job fails closed at return")
JOB_FAULT["unreadable"] = False

# ---- each terminal state settles the run once
cases = (("succeeded", "succeeded", "", 0, None), ("failed", "failed", "ExternalFailed", 3, "script_failed"),
         ("dispatch_failed", "failed", "ExternalFailed", None, "dispatch_failed"), ("cancelled", "failed", "ExternalCancelled", None, "cancelled"))
for job_status, run_status, etype, exit_code, classification in cases:
    reset()
    run, _ = park()
    jid = STARTED["job_id"]
    must(settle()["waiting"] == 1 and run.status == "running", "a queued job leaves the run pending")
    JOBS[jid] = job_record(jid, module="certificatemanagement", run_id=run.id, status="running")
    must(settle()["waiting"] == 1 and run.status == "running", "a running job leaves the run pending")
    JOBS[jid] = job_record(jid, module="certificatemanagement", run_id=run.id, status=job_status, exit_code=exit_code, classification=classification)
    counts = settle()
    must(counts["settled"] == 1 and counts["errors"] == 0, counts)
    must(run.status == run_status and run.error_type == etype and run.completion_state == "completed", (job_status, run.__dict__))
    must(run.result["job_id"] == jid and run.result["status"] == job_status and run.result["exit_code"] == exit_code, run.result)
    must(set(run.result) <= {"job_id", "status", "exit_code", "classification"}, run.result)
    must(run.finished_at == NOW[0] and run.schedule.last_run_at == NOW[0], run.__dict__)
    rows = [a for a in AUDITS if a["action"] == "custom:scheduler-completion"]
    must(len(rows) == 1 and rows[0]["metadata"]["caller_module"] == "core", AUDITS)
    # idempotent: a second tick changes nothing and writes nothing
    finished, n = run.finished_at, len(AUDITS)
    NOW[0] += timedelta(minutes=1)
    must(settle()["checked"] == 0 and run.finished_at == finished and len(AUDITS) == n, "the settled run is no longer listed")
    must(MARKER not in repr(run.__dict__) and MARKER not in repr(AUDITS), "no job output or parameter in the run or the audit trail")
print("       each terminal state settles the run once; a queued or running job leaves it pending; a second tick does nothing")

# ---- two ticks racing on the same run: the row lock re-check settles once
reset()
run, _ = park()
jid = STARTED["job_id"]
code1, _r = completion._apply_outcome(run.pk, external_job_id=jid, outcome="succeeded", result={"job_id": jid}, error="")
code2, _r = completion._apply_outcome(run.pk, external_job_id=jid, outcome="succeeded", result={"job_id": jid}, error="")
must((code1, code2) == ("applied", "duplicate"), (code1, code2))
print("       a second settler that raced the first finds the run done under the lock")

# ---- a job that belongs to another run, found at settle time
reset()
run, _ = park()
jid = STARTED["job_id"]
JOBS[jid] = job_record(jid, module="certificatemanagement", run_id=uuid.uuid4(), status="succeeded", exit_code=0)
settle()
must(run.status == "failed" and run.error_type == "PendingRefused", run.__dict__)
print("       a job whose context no longer names this run fails the run at settle time (PendingRefused)")

# ---- a missing record: fails only after 10 minutes
reset()
run, _ = park()
jid = STARTED["job_id"]
del JOBS[jid]
NOW[0] += timedelta(minutes=9, seconds=59)
must(settle()["waiting"] == 1 and run.status == "running")
NOW[0] += timedelta(seconds=2)
must(settle()["settled"] == 1 and run.status == "failed" and run.error_type == "ExternalFailed" and run.result["status"] == "missing", run.__dict__)
print("       a missing job record fails the run only after 10 minutes")

# ---- an unreadable job store is not a decision
reset()
run, _ = park()
JOB_FAULT["unreadable"] = True
counts = settle()
must(counts["unreadable"] == 1 and run.status == "running" and run.completion_state == "pending", (counts, run.__dict__))
JOB_FAULT["unreadable"] = False
print("       an unreadable job leaves the run pending for the next tick")

# ---- module-kind runs are left alone, and the step never raises
reset()
module_run = make_run("certificatemanagement.renew", "certificatemanagement", user=alice, status="running")
module_run.completion_state, module_run.completion_ref, module_run.completion_started_at = "pending", {"kind": "module", "external_job_id": "x"}, NOW[0]
must(settle()["checked"] == 0 and module_run.status == "running", "a module-kind pending run is not the tick's business")
real_filter = Run.objects.filter
Run.objects.filter = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("database down"))
counts = settle()
Run.objects.filter = real_filter
must(counts["errors"] == 1 and counts["settled"] == 0, counts)
reset()
runs = []
for _ in range(3):
    r, _ = park()
    runs.append((r, STARTED["job_id"]))
real_apply = completion._apply_outcome
calls = {"n": 0}


def exploding(*a, **k):
    calls["n"] += 1
    if calls["n"] == 1:
        raise RuntimeError("one run fails")
    return real_apply(*a, **k)


completion._apply_outcome = exploding
for r, jid in runs:
    JOBS[jid] = job_record(jid, module="certificatemanagement", run_id=r.id, status="succeeded", exit_code=0)
counts = settle()
completion._apply_outcome = real_apply
must(counts["errors"] == 1 and counts["settled"] == 2, counts)
print("       a database fault or one failing run never raises; the other runs are still settled")

# ---- at most 50 runs a tick
reset()
for _ in range(55):
    r, _ = park()
    JOBS[STARTED["job_id"]] = job_record(STARTED["job_id"], module="certificatemanagement", run_id=r.id, status="succeeded", exit_code=0)
first = settle()
second = settle()
must(first["checked"] == 50 and first["settled"] == 50 and second["checked"] == 5 and second["settled"] == 5, (first, second))
must(settle(limit=500)["checked"] == 0)
reset()
for _ in range(60):
    r, _ = park()
must(settle(limit=500)["checked"] == 50, "the limit argument cannot raise the bound")
print("       a tick looks at 50 runs at most")

# ---- the tick command wraps the step and its output line is unchanged; the real server_maintenance names are pinned
tick = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("from tec_tac.scheduler_completion import settle_server_job_runs" in tick, "the tick calls the settle step")
at = tick.index("settle_server_job_runs()")
block = tick[at - 900: at + 400]
must("try:" in block and "except Exception:" in block and 'logging.getLogger("tec_tac.scheduler_completion")' in block, "the step has its own try/except and logs")
after = tick[at: tick.index("sweep_state = ")]
must("self.stdout" not in after and "self.stderr" not in after, "the step writes nothing to the output")
LINE = ("TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} "
        "session_expiry_sweep={sweep_state} sweep_revoked={sweep_revoked} sweep_skipped_no_digest={sweep_skipped} sweep_orphan_tokens={sweep_orphans} "
        "now={now} replacement_conflicts_queued={replacement_queued} replacement_audit_rows={replacement_audit} module_failure_notices={failure_notices} "
        "module_failure_skipped_old={failure_old} module_failure_already_notified={failure_known} module_failure_emails={failure_emails} "
        "repository_defaults_seeded={repo_seeded} repository_sync_schedule_created={repo_schedule_created}")
must(LINE in tick, "the tick's own output line is unchanged")

sm_src = (APP / "server_maintenance.py").read_text(encoding="utf-8")
must(re.search(r"^def _read_job\(job_id: str\) -> dict:", sm_src, re.M) and "class ServerMaintenanceNotFound(ServerMaintenanceError)" in sm_src, "the helper the settle step reads")
must('TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "dispatch_failed"})' in sm_src, "terminal states")
must('"context": operation_context,' in sm_src and 'source_run_id=raw.get("source_run_id")' in sm_src and 'source_module=str(raw.get("source_module")' in sm_src,
     "the job context carries source_module and source_run_id")
must(set(completion._JOB_OUTCOME) == {"succeeded", "failed", "dispatch_failed", "cancelled"})
print("       the tick wraps the step, its output line is unchanged, and the server_maintenance names it reads exist")

print("PASS scheduler server job await 1.17.61")
