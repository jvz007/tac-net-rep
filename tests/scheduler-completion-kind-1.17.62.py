#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.62 regression (held Low from the 1.17.61 review): complete_pending_run cannot settle a run parked as server_maintenance_job.

Before 1.17.62 the module that owned a run waiting for a server-maintenance job could end it with complete_pending_run, before the job had
finished, because _apply_outcome did not look at the pending kind. Now _apply_outcome takes the kind the caller may settle:
complete_pending_run passes ``module`` and the tick passes ``server_maintenance_job``. A run parked as the other kind is refused as
``wrong_kind`` and left untouched.

Covered: the owning module cannot complete a server-job run (the run stays running and pending, the schedule's last_run_at stays unset, one
refusal audit row carries the reason code only, and the rate limit still allows one row per run and reason); the tick still settles the same
run when the job finishes; a module-kind run completes exactly as in 1.17.61 (success, idempotent duplicate, conflict, late, wrong_job,
not_pending); the new reason has text, is in the refusal texts and is described in the contract catalog and docs/scheduler.md; a completed
server-job run answers wrong_kind for a module too (no duplicate no-op path through the module door).
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

alice = User("alice")
roots = {name: plugin(name) for name in ("patching", "certificatemanagement")}
SRC = (
    "def complete(sched, run_id, ext, outcome='succeeded'):\n"
    "    return sched.complete_pending_run(run_id, external_job_id=ext, outcome=outcome, result={'ok': True})\n"
)
patching = compile_as(roots["patching"] / "jobs.py", SRC)
certs = compile_as(roots["certificatemanagement"] / "jobs.py", SRC)
STARTED = {}


def job_record(job_id, *, run_id, status="queued"):
    return {
        "id": job_id, "action": "certificatemanagement.renew", "status": status, "owner_module": "certificatemanagement",
        "context": {"source_module": "certificatemanagement", "source_action": "renew", "requested_by": "alice", "source_run_id": str(run_id)},
        "exit_result": {"exit_code": 0} if status == "succeeded" else None, "failure": None,
    }


def server_handler(context):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = job_record(job_id, run_id=context["run_id"])
    STARTED["job_id"] = job_id
    return sched.pending_completion("server_maintenance_job", job_id)


sched.register_scheduled_action(id="certificatemanagement.renew", module_id="certificatemanagement", label="Renew", handler=server_handler,
                                target_types=("none",), timeout_seconds=3600)
sched.register_scheduled_action(id="patching.wait", module_id="patching", label="Wait", target_types=("none",), timeout_seconds=600,
                                handler=lambda context: sched.pending_completion("module", "job-1"))


def refusal(fn, run, ext):
    try:
        fn(sched, run.id, ext)
    except sched.SchedulerCompletionRefused as exc:
        return exc.reason
    return "accepted"


def refusal_rows():
    return [a for a in AUDITS if a["action"] == "custom:scheduler-completion-refused"]


# ---- a module cannot settle a run that waits for a server job
reset()
run = make_run("certificatemanagement.renew", "certificatemanagement", user=alice)
must(go(run) == "pending completion", run.__dict__)
jid = STARTED["job_id"]
must(refusal(certs["complete"], run, jid) == "wrong_kind", "the owning module is refused: Core settles this run from the job file")
must(run.status == "running" and run.completion_state == "pending" and not run.result and not run.schedule.last_run_at and not run.finished_at, run.__dict__)
rows = refusal_rows()
must(len(rows) == 1 and rows[0]["metadata"]["reason"] == "wrong_kind" and "result" not in repr(rows[0]["metadata"]), AUDITS)
must(refusal(certs["complete"], run, jid) == "wrong_kind" and len(refusal_rows()) == 1, "the rate limit holds: one row per run and reason")
must(refusal(certs["complete"], run, "some-other-id") == "wrong_kind" and run.status == "running", "the kind is judged before the job id")
for outcome in ("failed", "cancelled", "timed_out"):
    try:
        certs["complete"](sched, run.id, jid, outcome)
        raise AssertionError("a module ended a server-job run")
    except sched.SchedulerCompletionRefused as exc:
        must(exc.reason == "wrong_kind" and run.status == "running", outcome)
print("       the owning module cannot end a server-job run with any outcome; the run is untouched and one reason-code row is written")

# ---- the tick still settles it
JOBS[jid] = job_record(jid, run_id=run.id, status="succeeded")
counts = completion.settle_server_job_runs()
must(counts["settled"] == 1 and run.status == "succeeded" and run.completion_state == "completed", (counts, run.__dict__))
must(refusal(certs["complete"], run, jid) == "wrong_kind", "a settled server-job run is still not the module's to complete or confirm")
print("       the tick settles the same run when the job finishes")

# ---- a module-kind run behaves exactly as in 1.17.61
reset()
run = make_run("patching.wait", "patching", user=alice)
must(go(run) == "pending completion")
must(refusal(patching["complete"], run, "other-job") == "wrong_job" and run.status == "running", "wrong_job")
must(refusal(patching["complete"], run, "job-1") == "accepted" and run.status == "succeeded", "completes")
must(patching["complete"](sched, run.id, "job-1")["duplicate"] is True, "an identical second completion is an idempotent no-op")
must(refusal(lambda s, r, e: patching["complete"](s, r, e, "failed"), run, "job-1") == "conflict", "conflict")
reset()
run = make_run("patching.wait", "patching", user=alice)
go(run)
run.completion_state = "expired"
run.status = "failed"
must(refusal(patching["complete"], run, "job-1") == "late", "late")
reset()
run = make_run("patching.wait", "patching", user=alice)
must(refusal(patching["complete"], run, "job-1") == "not_pending", "not_pending: a run that never parked has no kind and keeps the old answer")
print("       a module-kind run still answers accepted, duplicate, conflict, late, wrong_job and not_pending as in 1.17.61")

# ---- the reason is documented
must("wrong_kind" in completion.REFUSAL_TEXT and completion.REFUSAL_TEXT["wrong_kind"].endswith("A module cannot complete it."), completion.REFUSAL_TEXT.get("wrong_kind"))
src = (APP / "scheduler_completion.py").read_text(encoding="utf-8")
must("allowed_kind=KIND_MODULE" in src and src.count("allowed_kind=KIND_SERVER_JOB") == 3, "the module door passes module; the three tick paths pass the server job kind")
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
catalog = next(ast.literal_eval(n.value) for n in contracts.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "CORE_CONTRACTS")
purpose = next(r["purpose"] for r in catalog if r["name"] == "SchedulerCompletionRefused")
must("wrong_kind" in purpose and "1.17.62" in purpose, "the contract row names the new reason and the release")
docs = (ROOT / "docs" / "scheduler.md").read_text(encoding="utf-8")
must("wrong_kind" in docs, "docs/scheduler.md names the reason")
print("       the reason has plain text, the code passes the right kind at every call, and the contract row and the docs describe it")

print("PASS scheduler completion kind 1.17.62")
