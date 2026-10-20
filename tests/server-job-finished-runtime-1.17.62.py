"""Runtime check for Core 1.17.62 R-22 part 2: Core hands a finished server-maintenance job to its module. It did NOT run on the development PC
(it needs Django, PostgreSQL, Celery and a real job folder). DEV SERVER ONLY.

What you need first: Core 1.17.62 installed, `manage.py migrate tec_tac` run (migration 0035_server_job_hook), Core and the Celery workers restarted.
Step 6 also needs one installed module that has adopted the hook (registered the event job ``<module id>.server_job_finished``). Until a module
has, step 6 prints SKIP, which is not a failure.

Run it from the Tactical backend folder as the user that runs Core (so the job files it writes can be read by Core):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/server-job-finished-runtime-1.17.62.py

It writes a few throw-away job files and rows, and removes them at the end. It prints PASS, FAIL or SKIP for each step and exits with status 1 when
any step fails. What to send back after a FAIL: the whole output.
"""
import io
import json
import sys
import uuid
from datetime import timedelta
from pathlib import Path

from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.utils import timezone
from tec_tac import event_jobs, server_job_hooks, server_maintenance
from tec_tac.models import TecTacEventJob, TecTacServerJobHook

RESULTS = []
CREATED_FILES = []
CREATED_IDS = []
PROBE_MODULE = "smhookprobe"  # a module id nobody has registered a hook for


def step(name, fn):
    try:
        outcome = fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        if outcome == "SKIP":
            print(f"SKIP {name}")
            return
        RESULTS.append(True)
        print(f"PASS {name}")


def need(cond, text="check failed"):
    if not cond:
        raise AssertionError(text)


def job_file(*, owner, status="succeeded", action="smhookprobe.run", exit_code=0):
    job_id = str(uuid.uuid4())
    record = {
        "schema": 1, "id": job_id, "action": action, "owner_module": owner, "status": status, "stage": "done",
        "created_at": timezone.now().isoformat(), "finished_at": timezone.now().isoformat(),
        "context": {"source_module": owner or "smhookprobe", "source_action": "probe", "requested_by": "runtime-check"},
        "parameters": {"secret": "RUNTIME-SECRET-62"}, "public_parameters": {"secret": "<redacted>"},
        "exit_result": {"success": status == "succeeded", "exit_code": exit_code, "signal": None, "timed_out": False},
        "failure": None,
    }
    root = Path(server_maintenance._jobs_root())
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{job_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    CREATED_FILES.append(path)
    CREATED_IDS.append(job_id)
    return job_id


def table_and_unique_job_id():
    table = TecTacServerJobHook._meta.db_table
    with connection.cursor() as cursor:
        columns = {c.name for c in connection.introspection.get_table_description(cursor, table)}
        need({"job_id", "module_id", "action_id", "job_status", "state", "reason", "attempts", "created_at", "updated_at"} <= columns, columns)
        constraints = connection.introspection.get_constraints(cursor, table)
    need(any(c["unique"] and c["columns"] == ["job_id"] for c in constraints.values()), "job_id is unique")
    need(any(c["index"] and c["columns"] == ["created_at"] for c in constraints.values()), "created_at is indexed")
    job_id = str(uuid.uuid4())
    CREATED_IDS.append(job_id)
    TecTacServerJobHook.objects.create(job_id=job_id, state="claiming")
    try:
        with transaction.atomic():
            TecTacServerJobHook.objects.create(job_id=job_id, state="claiming")
        raise AssertionError("a second row for one job id was accepted")
    except IntegrityError:
        pass


def claim_semantics():
    job_id = str(uuid.uuid4())
    CREATED_IDS.append(job_id)
    need(server_job_hooks._claim(job_id, module_id="x", action_id="a", job_status="failed") is True, "first claim")
    need(server_job_hooks._claim(job_id, module_id="x", action_id="a", job_status="failed") is False, "second claim")
    server_job_hooks._set_state(job_id, "retry", reason="rate")
    need(job_id not in server_job_hooks._settled_ids([job_id]), "a retry row is not settled")
    need(server_job_hooks._claim(job_id, module_id="x", action_id="a", job_status="failed") is True, "a retry row is taken once")
    need(server_job_hooks._claim(job_id, module_id="x", action_id="a", job_status="failed") is False, "and only once")
    need(server_job_hooks._attempts(job_id) == 2, server_job_hooks._attempts(job_id))
    server_job_hooks._set_state(job_id, "queued")
    need(job_id in server_job_hooks._settled_ids([job_id]), "a queued row is settled")


def ignored_jobs():
    no_owner = job_file(owner=None)
    no_hook = job_file(owner=PROBE_MODULE)
    running = job_file(owner=PROBE_MODULE, status="running")
    counts = server_job_hooks.deliver_finished_server_jobs()
    need(counts["errors"] == 0, counts)
    need(TecTacServerJobHook.objects.get(job_id=no_owner).state == "ignored", "a job with no owner is ignored")
    need(TecTacServerJobHook.objects.get(job_id=no_hook).state == "ignored", "a module with no hook is ignored")
    need(not TecTacServerJobHook.objects.filter(job_id=running).exists(), "a running job has no row yet")
    again = server_job_hooks.deliver_finished_server_jobs()
    need(again["errors"] == 0 and not TecTacServerJobHook.objects.filter(job_id=running).exists(), again)
    need(TecTacServerJobHook.objects.filter(job_id__in=[no_owner, no_hook]).count() == 2, "handled once, not duplicated")
    need("RUNTIME-SECRET-62" not in repr(list(TecTacServerJobHook.objects.filter(job_id__in=[no_owner, no_hook]).values())), "no parameter in the table")


def stale_claim_and_prune():
    stale = str(uuid.uuid4())
    old = str(uuid.uuid4())
    CREATED_IDS.extend([stale, old])
    TecTacServerJobHook.objects.create(job_id=stale, state="claiming")
    TecTacServerJobHook.objects.filter(job_id=stale).update(updated_at=timezone.now() - timedelta(minutes=20))
    TecTacServerJobHook.objects.create(job_id=old, state="queued")
    TecTacServerJobHook.objects.filter(job_id=old).update(created_at=timezone.now() - timedelta(days=31))
    server_job_hooks.deliver_finished_server_jobs()
    row = TecTacServerJobHook.objects.get(job_id=stale)
    need(row.state == "abandoned" and row.reason == "claim_stale", (row.state, row.reason))
    need(not TecTacServerJobHook.objects.filter(job_id=old).exists(), "a handled row older than 30 days is pruned")


def tick_line_unchanged():
    out = io.StringIO()
    call_command("tec_tac_scheduler_tick", stdout=out)
    line = out.getvalue().strip().splitlines()[-1]
    fields = [part.split("=")[0] for part in line.split(" ")[3:] if "=" in part]
    need(line.startswith("TEC-TAC scheduler tick: checked="), line)
    need(fields[:6] == ["checked", "queued", "skipped", "cleaned", "session_history_cleanup", "session_expiry_sweep"] and fields[-1] == "repository_sync_schedule_created", fields)
    need(len(fields) == 18, f"the tick line has {len(fields)} fields, expected 18: {line}")


def end_to_end():
    hooked = [row for row in event_jobs.registered_event_jobs() if row["id"].endswith("." + server_job_hooks.HOOK_JOB_NAME)]
    if not hooked:
        return "SKIP"
    module_id = hooked[0]["module_id"]
    job_id = job_file(owner=module_id, status="failed", exit_code=2, action=f"{module_id}.runtime-check")
    counts = server_job_hooks.deliver_finished_server_jobs()
    need(counts["errors"] == 0, counts)
    hook = TecTacServerJobHook.objects.get(job_id=job_id)
    need(hook.state in ("queued", "skipped"), (hook.state, hook.reason))
    if hook.state == "queued":
        rows = TecTacEventJob.objects.filter(module_id=module_id, job_id=hooked[0]["id"], key=f"server-job:{job_id}")
        need(rows.count() == 1, f"one event job row for the job, got {rows.count()}")
        payload = rows.get().payload
        need(set(payload) <= {"job_id", "action_id", "status", "exit_code", "classification"} and payload["status"] == "failed", payload)
        need("RUNTIME-SECRET-62" not in json.dumps(payload), "no parameter in the event payload")
        rows.delete()
    again = server_job_hooks.deliver_finished_server_jobs()
    need(again["delivered"] == 0 and TecTacEventJob.objects.filter(key=f"server-job:{job_id}").count() == 0, "a second tick hands over nothing")


try:
    step("1 migration 0035: the table, its columns, the unique job id and the created_at index exist", table_and_unique_job_id)
    step("2 the claim is taken once; a retry row is taken once more; settled states are skipped", claim_semantics)
    step("3 a job with no owner and a module with no hook are ignored once; a running job waits", ignored_jobs)
    step("4 a claim left claiming is abandoned; a handled row older than 30 days is pruned", stale_claim_and_prune)
    step("5 the scheduler tick still prints its one line with the same 18 fields", tick_line_unchanged)
    step("6 (needs a module that registered <id>.server_job_finished) a finished job is stored once for it and a second tick stores nothing", end_to_end)
finally:
    for path in CREATED_FILES:
        path.unlink(missing_ok=True)
    TecTacServerJobHook.objects.filter(job_id__in=CREATED_IDS).delete()
    TecTacEventJob.objects.filter(key__in=[f"server-job:{i}" for i in CREATED_IDS]).delete()

failed = RESULTS.count(False)
print(f"{RESULTS.count(True)} passed, {failed} failed")
if failed:
    print("Send back the whole output above.")
    sys.exit(1)
