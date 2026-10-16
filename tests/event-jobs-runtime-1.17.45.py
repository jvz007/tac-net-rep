"""Runtime check for Core 1.17.45 ``core.event_jobs``. It did NOT run on the development PC (Django, PostgreSQL and Celery are not
installed there).

Run it on the dev server through Tactical's manage.py shell, after migration 0032_event_jobs has run (Celery's broker and a worker must be
running for step 9):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/event-jobs-runtime-1.17.45.py

It proves what the stub test (tests/event-jobs-1.17.45.py) cannot: the migration and the partial unique constraint on real PostgreSQL,
the row lock claim, the real transaction.on_commit hook, the real audit rows, the Scheduler tick's recovery, and one message through the
real broker to the real worker.

The probe job is registered in this shell only, under the id of an installed, enabled extension module (the probe skips the owner check
of register_event_job, because this script does not lie inside a module's folder; the check itself is covered by the stub test). The
handler runs in this process (``run_event_job`` is called here), so a real worker does not know the probe handler: in step 9 the worker
finds the handler unregistered and ends the row ``skipped``, which proves the broker path, the claim, the re-check and the audit row.

Everything the probe creates has a key that starts with ``probe-`` and is deleted at the end (event job rows and the probe stat row). The
Core audit rows it provokes (``custom:event-job-failed``, ``custom:event-job-skipped``, ``custom:event-job-expired``, ``run``) stay: audit rows
are not deleted. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import time
import uuid
from datetime import timedelta

from django.db import IntegrityError, connection, transaction
from django.utils import timezone
from tec_tac import event_jobs as ej
from tec_tac import registry
from tec_tac.models import TecTacEventJob, TecTacEventJobStat
from tec_tac.scheduler import SchedulerPermanentError

RESULTS = []
CALLS = []


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


MODULE = next((p.plugin_id for p in registry.discover_plugins() if p.plugin_type == "extension" and not p.legacy), None)
if MODULE is None:
    print("SKIP: no installed extension module to register the probe job under")
    sys.exit(0)
JOB = f"{MODULE}.probe-event-job"
original_verify = ej._verify_owner
ej._verify_owner = lambda module_id, handler: None  # this script is not inside the module's folder (see the header)
ej._clear_for_tests()


def good(context):
    CALLS.append(context)
    return {"ok": True}


def bad(context):
    CALLS.append(context)
    raise RuntimeError("probe failure")


def permanent(context):
    CALLS.append(context)
    raise SchedulerPermanentError("probe permanent")


def cleanup():
    TecTacEventJob.objects.filter(job_id=JOB).delete()
    TecTacEventJobStat.objects.filter(job_id=JOB).delete()


def rows():
    return TecTacEventJob.objects.filter(job_id=JOB).order_by("created_at")


def register(handler, **limits):
    ej._clear_for_tests()
    return ej.register_event_job(id=JOB, module_id=MODULE, label="Probe", handler=handler, **limits)


def run(row, **kw):
    return ej.run_event_job(row.pk, celery_task_id="probe", **kw)


def probe_breaker_open():
    """Keep the publish off the broker for the steps that run the job here."""
    ej._BREAKER.failure()


cleanup()


def s1_tables():
    check(connection.vendor == "postgresql", f"this probe is for PostgreSQL, not {connection.vendor}")
    check(TecTacEventJob.objects.count() >= 0 and TecTacEventJobStat.objects.count() >= 0, "the tables exist")
    with connection.cursor() as cursor:
        cursor.execute("select indexname from pg_indexes where tablename = 'tec_tac_tectaceventjob'")
        names = {r[0] for r in cursor.fetchall()}
    for name in ("tectac_evjob_due_idx", "tectac_evjob_job_idx", "tectac_evjob_active_key"):
        check(name in names, f"index {name} is missing: {sorted(names)}")


def s2_unique_constraint():
    now = timezone.now()
    base = dict(module_id=MODULE, job_id=JOB, key="probe-unique", expires_at=now + timedelta(hours=1), next_attempt_at=now)
    first = TecTacEventJob.objects.create(**base)
    try:
        with transaction.atomic():
            TecTacEventJob.objects.create(**base)
    except IntegrityError:
        pass
    else:
        raise AssertionError("two pending rows with the same key were stored")
    first.status = "running"
    first.save()
    try:
        with transaction.atomic():
            TecTacEventJob.objects.create(**base)
    except IntegrityError:
        pass
    else:
        raise AssertionError("a pending row next to a running one with the same key was stored")
    first.status = "succeeded"
    first.save()
    TecTacEventJob.objects.create(**base)  # a finished row does not hold the key
    cleanup()


def s3_publish_and_claim():
    publisher = register(good)
    probe_breaker_open()
    result = publisher.publish("probe-claim", {"alert_id": 1})
    check(result.outcome == "queued", result)
    row = rows().get()
    check(row.status == "pending" and row.last_enqueued_at is None, "the broker was skipped, so the row waits for the tick")
    check(run(row) == "job succeeded" and len(CALLS) == 1, "ran once")
    check(run(row) == "job already succeeded" and len(CALLS) == 1, "a second delivery runs nothing")
    row.refresh_from_db()
    check(row.status == "succeeded" and row.attempt == 1 and row.result == {"ok": True}, row.__dict__)
    check(not CALLS[0].get("user") and "owner_username" not in CALLS[0], "no user field in the context")


def s4_duplicate_and_commit_hook():
    publisher = register(good)
    probe_breaker_open()
    with transaction.atomic():
        result = publisher.publish("probe-commit")
        check(result.outcome == "queued" and not rows().filter(key="probe-commit").exists(), "nothing is stored before the commit")
    check(rows().filter(key="probe-commit").count() == 1, "stored when the transaction committed")
    ej._RECENT._seen.clear()
    check(publisher.publish("probe-commit").outcome == "duplicate", "the unique constraint collapses it")
    try:
        with transaction.atomic():
            publisher.publish("probe-rollback")
            raise RuntimeError("roll back")
    except RuntimeError:
        pass
    check(not rows().filter(key="probe-rollback").exists(), "a rolled-back transaction publishes nothing")


def s5_retry_then_give_up():
    publisher = register(bad, max_attempts=2, backoff_seconds=5)
    probe_breaker_open()
    publisher.publish("probe-retry")
    row = rows().get(key="probe-retry")
    check(run(row) == "job will retry", "first failure retries")
    row.refresh_from_db()
    check(row.status == "pending" and row.attempt == 1 and row.next_attempt_at > timezone.now(), row.__dict__)
    check(run(row) == "job not due", "an early delivery waits")
    check(run(row, now=timezone.now() + timedelta(seconds=60)) == "job failed", "the last attempt gives up")
    row.refresh_from_db()
    check(row.status == "failed" and row.attempt == 2 and "probe failure" in row.error, row.__dict__)
    stat = TecTacEventJobStat.objects.get(job_id=JOB)
    check(stat.failed == 1 and stat.last_failure_at is not None, stat.__dict__)
    from logs.models import AuditLog

    check(AuditLog.objects.filter(object_type="event_job", action="custom:event-job-failed", debug_info__object_id=JOB).exists(),
          "a Core audit row for the give-up exists")


def s6_permanent():
    publisher = register(permanent, max_attempts=5)
    probe_breaker_open()
    publisher.publish("probe-permanent")
    row = rows().get(key="probe-permanent")
    check(run(row) == "job failed" and run(row) == "job already failed", "a permanent error gives up at once")


def s7_kill_and_recover():
    publisher = register(good)
    probe_breaker_open()
    publisher.publish("probe-kill")
    row = rows().get(key="probe-kill")
    TecTacEventJob.objects.filter(pk=row.pk).update(status="running", attempt=1, started_at=timezone.now() - timedelta(hours=1))
    out = ej.recover_event_jobs(timezone.now())
    check(out["stale_recovered"] >= 1, out)
    row.refresh_from_db()
    check(row.status == "pending" and row.error_type == "EventJobLost", row.__dict__)
    TecTacEventJob.objects.filter(pk=row.pk).update(status="running", attempt=3, started_at=timezone.now() - timedelta(hours=1))
    ej.recover_event_jobs(timezone.now())
    row.refresh_from_db()
    check(row.status == "failed", "a lost last attempt gives up")


def s8_expiry_and_module_gate():
    publisher = register(good, expires_seconds=60)
    probe_breaker_open()
    publisher.publish("probe-expire")
    row = rows().get(key="probe-expire")
    check(run(row, now=timezone.now() + timedelta(seconds=120)) == "job expired" and not CALLS, "expired and never called")
    publisher.publish("probe-expire-tick")
    TecTacEventJob.objects.filter(key="probe-expire-tick").update(expires_at=timezone.now() - timedelta(seconds=1))
    out = ej.recover_event_jobs(timezone.now())
    check(out["expired"] >= 1 and rows().get(key="probe-expire-tick").status == "expired", out)


def s9_real_broker_and_worker():
    publisher = register(good)
    ej._BREAKER.success()
    result = publisher.publish("probe-broker")
    check(result.outcome == "queued", result)
    row = rows().get(key="probe-broker")
    check(row.last_enqueued_at is not None, "the message was sent (the stamp was not cleared)")
    deadline = time.time() + 45
    while time.time() < deadline:
        row.refresh_from_db()
        if row.status != "pending":
            break
        time.sleep(1)
    # This shell's handler is not registered in the worker process, so the worker ends the row skipped. That is the expected proof.
    check(row.status in ("skipped", "succeeded"), f"the worker did not take the message within 45 seconds: {row.status}")
    print(f"     the real worker ended the row {row.status} ({row.error_type or 'ran'})")


def s10_lost_message_and_recycled_worker():
    publisher = register(good)
    probe_breaker_open()
    publisher.publish("probe-lost")
    row = rows().get(key="probe-lost")
    check(row.last_enqueued_at is None, "no message was sent")
    ej._clear_for_tests()  # a recycled worker process: nothing in memory
    register(good)
    ej._BREAKER.success()
    out = ej.recover_event_jobs(timezone.now())
    check(out["enqueued"] >= 1, out)
    row.refresh_from_db()
    check(row.last_enqueued_at is not None, "the tick enqueued the row")


def s11_health_and_list():
    from tec_tac.scheduler import scheduler_health

    block = scheduler_health()["event_jobs"]
    check({"registered", "pending", "running", "failed_last_24h", "dropped_last_24h", "oldest_pending_age_seconds"} <= set(block), block)
    listing = ej.list_event_jobs()
    check(any(item["job_id"] == JOB for item in listing["jobs"]), listing["jobs"][:3])
    check("payload" not in repr(listing).replace("payload_max", ""), "no payload in the listing")


try:
    for number, (name, fn) in enumerate((
        ("tables, indexes and the partial unique index exist on PostgreSQL", s1_tables),
        ("the partial unique constraint holds for pending and running rows only", s2_unique_constraint),
        ("publish stores a row, the worker claims it once, the context has no user", s3_publish_and_claim),
        ("a duplicate key collapses, the row is stored at commit, a rollback publishes nothing", s4_duplicate_and_commit_hook),
        ("retry with back-off, then give up with an audit row", s5_retry_then_give_up),
        ("a permanent error gives up at once", s6_permanent),
        ("a killed attempt is recovered by the tick (retry, then give up)", s7_kill_and_recover),
        ("expiry at the worker and at the tick", s8_expiry_and_module_gate),
        ("one message through the real broker to the real worker", s9_real_broker_and_worker),
        ("a lost message and a recycled worker: the tick enqueues the row", s10_lost_message_and_recycled_worker),
        ("scheduler health and the listing", s11_health_and_list),
    ), start=1):
        CALLS.clear()
        step(f"{number}. {name}", fn)
finally:
    ej._verify_owner = original_verify
    ej._clear_for_tests()
    cleanup()

failed = RESULTS.count(False)
print(f"{len(RESULTS) - failed} of {len(RESULTS)} steps passed")
if failed:
    sys.exit(1)
