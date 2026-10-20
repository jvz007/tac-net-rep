#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.61 regression (R-21): a Scheduler handler may return "pending, finished later", and only the owning module completes the run.

The real scheduler.py, scheduler_completion.py, tasks.py and caller_identity.py run on the stub harness of
scheduler-completion-harness-1.17.61.py. Covered: a plain dict result is unchanged; a PendingCompletion keeps the run RUNNING, stores
the reference, leaves last_run_at alone and never retries; a dict with the same keys is NOT a pending completion; completion
succeeded, failed, cancelled and timed_out; the duplicate completion is a no-op; a conflicting second outcome, a wrong job id, a late
completion after stale recovery and a completion by another module are refused with one audit row of a reason code only; bad
payloads raise SchedulerError and change nothing; no secret marker reaches an audit row; recover_stale_runs fails a waiting run as
CompletionTimeout; serialize_run gains the additive completion key. Django, Celery and the database are dev-server only.
"""
from __future__ import annotations

from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

MARKER = "SECRET-MARKER-7f3a"
alice = User("alice")
patching_root = plugin("patching")
other_root = plugin("other")
JOBS_SRC = (
    "def complete(sched, run_id, ext, outcome, **kw):\n"
    "    return sched.complete_pending_run(run_id, external_job_id=ext, outcome=outcome, **kw)\n"
)
patching = compile_as(patching_root / "jobs.py", JOBS_SRC)
other = compile_as(other_root / "jobs.py", JOBS_SRC)

CALLS = []


def pending_handler(context):
    CALLS.append(context["attempt"])
    return sched.pending_completion("module", "job-1", note="Waiting for the module's own job.")


def dict_handler(context):
    return {"pending": True, "external_job_id": "job-1", "kind": "module", "completion_state": "pending"}


def plain_handler(context):
    return {"ok": True}


def mutated_handler(context):
    value = sched.pending_completion("module", "job-1")
    object.__setattr__(value, "kind", "bogus")  # a frozen object can still be changed by force: Core re-checks when it parks
    return value


for aid, fn in (("patching.pending", pending_handler), ("patching.dict", dict_handler), ("patching.plain", plain_handler), ("patching.mutated", mutated_handler)):
    sched.register_scheduled_action(id=aid, module_id="patching", label=aid, handler=fn, target_types=("none",), timeout_seconds=600)


def pending_run(retries=0):
    reset()
    run = make_run("patching.pending", "patching", user=alice, retries=retries)
    out = go(run, retries=0)
    return run, out


def done(who, run, ext="job-1", outcome="succeeded", **kw):
    return who["complete"](sched, run.id, ext, outcome, **kw)


def refused(who, run, reason, ext="job-1", outcome="succeeded", **kw):
    try:
        done(who, run, ext, outcome, **kw)
    except sched.SchedulerCompletionRefused as exc:
        must(exc.reason == reason, (exc.reason, reason))
        must(isinstance(exc, sched.SchedulerError))
        return exc
    raise AssertionError(f"accepted, wanted {reason}")


def refusal_rows():
    return [a for a in AUDITS if a["action"] == "custom:scheduler-completion-refused"]


# ---- a handler that returns a plain dict behaves exactly as before
reset()
run = make_run("patching.plain", "patching", user=alice)
out = go(run)
must(out == {"ok": True} and run.status == "succeeded" and run.completion_state == "" and run.schedule.last_run_at is not None, (out, run.__dict__))
must(sched.serialize_run(run)["completion"] is None, "a run that never parked has completion null")
print("       a plain result is unchanged: succeeded, last_run_at set, completion null")

# ---- a dict with the same keys is not a pending completion (no magic dict)
reset()
run = make_run("patching.dict", "patching", user=alice)
out = go(run)
must(run.status == "succeeded" and run.completion_state == "" and run.completion_ref == {}, run.__dict__)
print("       a dict that looks like a pending completion is just a result")

# ---- pending: RUNNING, reference stored, last_run_at untouched, no retry
run, out = pending_run(retries=3)
must(out == "pending completion", out)
must(run.status == "running" and run.completion_state == "pending" and run.finished_at is None, run.__dict__)
must(run.completion_ref == {"kind": "module", "external_job_id": "job-1", "note": "Waiting for the module's own job."}, run.completion_ref)
must(run.completion_started_at == NOW[0] and run.schedule.last_run_at is None and run.result == {} and run.error == "", run.__dict__)
must(CALLS[-1] == 1 and run.attempt == 1, "the handler ran once and the run was not re-queued")
view = sched.serialize_run(run)
must(view["status"] == "running" and view["completion"] == {"state": "pending", "kind": "module", "since": NOW[0].isoformat()}, view["completion"])
old_keys = {"id", "schedule_id", "schedule_name", "module_id", "action_id", "owner_type", "owner_module", "owner_key", "status", "scheduled_for", "manual",
            "targets_snapshot", "target_mode_snapshot", "parameters_snapshot", "result", "error", "error_type", "attempt", "celery_task_id", "created_at",
            "started_at", "finished_at"}
must(old_keys <= set(view) and set(view) - old_keys == {"completion"}, "serialize_run only gains the completion key")
must(go(run) == "run already running", "a duplicate delivery does not run the handler again")
print("       pending keeps the run running, stores the reference, sets no last_run_at, never retries; serialize_run gains completion")

# ---- the pending state is saved with real field names only (the harness checks every update_fields name)
must(("Run", ("completion_state", "completion_ref", "completion_started_at")) in SAVES, SAVES)

# ---- a handler that changes the frozen object by force: PendingRefused
reset()
run = make_run("patching.mutated", "patching", user=alice)
out = go(run)
must(run.status == "failed" and run.error_type == "PendingRefused" and run.completion_state == "" and run.schedule.last_run_at is not None, run.__dict__)
print("       a pending completion changed after it was built is refused as PendingRefused")

# ---- completion: every outcome
run, _ = pending_run()
r = done(patching, run, result={"updated": 3}, warnings=["one agent was offline"])
must(r == {"run_id": str(run.id), "status": "succeeded", "duplicate": False}, r)
must(run.status == "succeeded" and run.error == "" and run.error_type == "" and run.completion_state == "completed", run.__dict__)
must(run.result == {"updated": 3, "warnings": ["one agent was offline"]}, run.result)
must(run.finished_at == NOW[0] and run.schedule.last_run_at == NOW[0] and run.completion_ref["outcome"] == "succeeded", run.__dict__)
rows = [a for a in AUDITS if a["action"] == "custom:scheduler-completion"]
must(len(rows) == 1 and rows[0]["metadata"]["outcome"] == "succeeded" and rows[0]["metadata"]["caller_module"] == "patching", AUDITS)
must(sched.serialize_run(run)["completion"]["state"] == "completed")
print("       succeeded: run succeeded, warnings kept as metadata, last_run_at set, one audit row")

for outcome, etype in (("failed", "ExternalFailed"), ("cancelled", "ExternalCancelled"), ("timed_out", "ExternalTimedOut")):
    run, _ = pending_run()
    done(patching, run, outcome=outcome, error="It stopped.", result={"step": 2}, warnings=["ignored on failure"])
    must(run.status == "failed" and run.error_type == etype and run.error == "It stopped." and run.completion_state == "completed", (outcome, run.__dict__))
    must(run.result == {"step": 2} and run.schedule.last_run_at == NOW[0], run.result)
    run2, _ = pending_run()
    done(patching, run2, outcome=outcome)
    must(run2.error and run2.error_type == etype, "a default plain error text is set when the module gives none")
print("       failed, cancelled and timed_out end the run failed with ExternalFailed, ExternalCancelled, ExternalTimedOut")

# ---- the duplicate: same job id, same outcome
run, _ = pending_run()
done(patching, run)
finished, rows_before = run.finished_at, len(AUDITS)
NOW[0] += timedelta(minutes=5)
r = done(patching, run)
must(r["duplicate"] is True and run.finished_at == finished and len(AUDITS) == rows_before, (r, AUDITS))
print("       a duplicate completion is a no-op: no second audit row, finished_at unchanged")

# ---- a conflicting second outcome
refused(patching, run, "conflict", outcome="failed")
must(run.status == "succeeded" and run.error_type == "" and len(refusal_rows()) == 1, (run.__dict__, AUDITS))
must(refusal_rows()[0]["metadata"]["reason"] == "conflict" and "result" not in refusal_rows()[0]["metadata"], refusal_rows())
refused(patching, run, "conflict", ext="job-2")  # another job id after completion is a conflict too
print("       a different second outcome is refused (conflict), one audit row with the reason code only")

# ---- a wrong job id
run, _ = pending_run()
refused(patching, run, "wrong_job", ext="job-2")
must(run.status == "running" and run.completion_state == "pending" and run.completion_ref["external_job_id"] == "job-1", run.__dict__)
must(len(refusal_rows()) == 1 and "job-2" not in repr(AUDITS), AUDITS)
print("       a wrong external_job_id is refused and the run keeps waiting; the wrong id is not audited")

# ---- another module
run, _ = pending_run()
refused(other, run, "wrong_module", result={"leak": MARKER}, error=MARKER)
must(run.status == "running" and run.result == {} and run.error == "" and MARKER not in repr(run.__dict__), run.__dict__)
must(MARKER not in repr(AUDITS), "the refused payload never reaches the audit row")
rows = refusal_rows()
must(len(rows) == 1 and rows[0]["metadata"]["caller_module"] == "other" and rows[0]["metadata"]["reason"] == "wrong_module", rows)
must(not run.schedule.last_run_at, "a refused completion changes nothing")
print("       another module's completion is refused (wrong_module); its payload is stored and audited nowhere")

# ---- a looping caller cannot fill the audit trail
for _ in range(6):
    refused(other, run, "wrong_module")
must(len(refusal_rows()) == 1, f"one row per run and reason in a window, got {len(refusal_rows())}")
completion._clock = lambda: 10_000.0
refused(other, run, "wrong_module")
must(len(refusal_rows()) == 2, "a new window writes a new row")
completion._clock = __import__("time").monotonic
print("       a refusal row is throttled to one per run and reason in a five minute window")

# ---- a run that is not waiting
reset()
run = make_run("patching.plain", "patching", user=alice)
go(run)
refused(patching, run, "not_pending")
reset()
try:
    patching["complete"](sched, "not-a-uuid", "job-1", "succeeded")
    raise AssertionError("a malformed run id was accepted")
except sched.SchedulerCompletionRefused as exc:
    must(exc.reason == "unknown_run" and not refusal_rows(), exc.reason)
try:
    patching["complete"](sched, uuid.uuid4(), "job-1", "succeeded")
    raise AssertionError("an unknown run was accepted")
except sched.SchedulerCompletionRefused as exc:
    must(exc.reason == "unknown_run" and not refusal_rows(), "an unknown run id writes no row")
print("       a run that never parked, a malformed id and an unknown run are refused")

# ---- stale recovery: a waiting run fails as CompletionTimeout and the late completion is refused
run, _ = pending_run()
NOW[0] += timedelta(seconds=600 + 120)  # inside timeout + grace (300 s): not stale yet
must(sched.recover_stale_runs() == {"queued": 0, "running": 0} and run.status == "running", run.__dict__)
NOW[0] += timedelta(seconds=600)
must(sched.recover_stale_runs() == {"queued": 0, "running": 1}, run.__dict__)
must(run.status == "failed" and run.error_type == "CompletionTimeout" and run.completion_state == "expired" and run.finished_at == NOW[0], run.__dict__)
refused(patching, run, "late", result={"x": 1})
must(run.status == "failed" and run.error_type == "CompletionTimeout" and run.result == {}, "the stale decision stands")
print("       a waiting run past its action timeout fails as CompletionTimeout; the late completion is refused")

# ---- an ordinary stale run still reads Stale
reset()
run = make_run("patching.plain", "patching", user=alice, status="running")
NOW[0] += timedelta(hours=3)
sched.recover_stale_runs()
must(run.status == "failed" and run.error_type == "Stale", run.__dict__)
print("       an ordinary stale run is still Stale")

# ---- bad payloads raise SchedulerError and change nothing
run, _ = pending_run()
before = (dict(run.__dict__), len(AUDITS))
bad = [
    dict(outcome="done"), dict(outcome=None), dict(outcome="SUCCEEDED"),
    dict(result={"blob": "x" * (16 * 1024 + 1)}), dict(result={"n": float("nan")}), dict(result={"o": object()}),
    dict(error="x" * 501), dict(error="line one\nline two"), dict(error=5), dict(outcome="failed", error="bell\x07"),
    dict(warnings=["w"] * 11), dict(warnings="not a list"), dict(warnings=["x" * 201]),
]
for kw in bad:
    kw = {"outcome": "succeeded", **kw}
    try:
        done(patching, run, **kw)
        raise AssertionError(f"accepted {list(kw)}")
    except sched.SchedulerCompletionRefused as refusal:
        raise AssertionError(f"a bad payload is a SchedulerError, not a refusal: {list(kw)}") from refusal
    except sched.SchedulerError:
        pass
must(run.__dict__ == before[0] and len(AUDITS) == before[1], "a bad payload changes nothing and writes no row")
for ext in ("", "a b", "x" * 129, None, 7):
    try:
        patching["complete"](sched, run.id, ext, "succeeded")
        raise AssertionError(f"accepted external id {ext!r}")
    except sched.SchedulerError:
        pass
done(patching, run, result={"blob": "x" * (16 * 1024 - 64)})  # just under the limit is accepted
must(run.status == "succeeded")
print("       an oversize or non-JSON result, a long or unprintable error and bad warnings raise SchedulerError and change nothing")

# ---- PendingCompletion validation
for args in (("bogus", "j"), ("module", ""), ("module", "a b"), ("module", "x" * 129), ("module", "j", "x" * 201), ("module", "j", "bad\nnote"),
             ("module", 5), ("server_maintenance_job", "not-a-uuid"), ("server_maintenance_job", str(uuid.uuid4()).upper()), (None, "j")):
    try:
        sched.pending_completion(*args)
        raise AssertionError(f"accepted {args}")
    except sched.SchedulerError:
        pass
good = sched.pending_completion("server_maintenance_job", str(uuid.uuid4()), "Waiting for the server job.")
must(good.kind == "server_maintenance_job" and sched.PendingCompletion is type(good))
try:
    good.kind = "module"
    raise AssertionError("PendingCompletion must be frozen")
except Exception as exc:
    must(type(exc).__name__ == "FrozenInstanceError", exc)
print("       PendingCompletion validates kind, id, note and is frozen")

# ---- a pending run keeps blocking: it is still status running (concurrency skip, once-cleanup and remove_owned_schedule read the status)
run, _ = pending_run()
must(run.status == sched.TecTacScheduleRun.Status.RUNNING, "a pending run stays running")
must(sched.complete_pending_run is completion.complete_pending_run, "complete_pending_run is exported as a plain alias, with no wrapper frame")
must(sched.PendingCompletion is completion.PendingCompletion and sched.pending_completion is completion.pending_completion)

# ---- the diagnostic action
action = sched.get_scheduled_action("tec-tac.scheduler-test-pending")
must(action.module_id == "tec-tac" and action.permission is None and action.timeout_seconds == 120 and action.target_types == ("none",), action)
reset()
run = make_run("tec-tac.scheduler-test-pending", "tec-tac", user=alice)
must(go(run) == "pending completion" and run.status == "running" and run.completion_state == "pending", run.__dict__)
try:
    patching["complete"](sched, run.id, run.completion_ref["external_job_id"], "succeeded")
    raise AssertionError("a module completed the diagnostic run")
except sched.SchedulerCompletionRefused as exc:
    must(exc.reason == "wrong_module", exc.reason)
NOW[0] += timedelta(seconds=120 + 300 + 1)
sched.recover_stale_runs()
must(run.status == "failed" and run.error_type == "CompletionTimeout", run.__dict__)
print("       the diagnostic action parks, no module can complete it, and it fails as CompletionTimeout")

print("PASS scheduler async completion 1.17.61")
