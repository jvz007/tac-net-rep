"""Runtime check for Core 1.17.61 pending completion (R-21) and the server-job wait (R-22). It did NOT run on the development PC
(Django, the database and Celery are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/scheduler-completion-runtime-1.17.61.py

It proves what the stub tests (tests/scheduler-async-completion-1.17.61.py and tests/scheduler-server-job-await-1.17.61.py) cannot: the
four new columns of migration 0034 on the real table, the real Postgres JSON lookup the tick step uses (`completion_ref__kind`), the real
row locks, a refusal from a caller that is not a module (this shell), Tactical's AuditLog row for that refusal, `recover_stale_runs` on a
waiting run, and a real server-maintenance job file read and settled by `settle_server_job_runs`.

Everything database-side runs inside one transaction that is rolled back at the end. The Celery task that each start queues finds no
committed run and ends harmlessly. The task body runs in this process (`execute_schedule_run.run`). The one thing that is NOT rolled back is
the synthetic job file the last step writes under the server-maintenance jobs folder: it is removed in a `finally` block. If this shell
cannot write there, that step says FAIL with the reason, and the other steps still stand.

It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import uuid
from datetime import timedelta

from accounts.models import User
from django.db import transaction
from django.utils import timezone
from tec_tac import audit, scheduler
from tec_tac import scheduler_completion as completion
from tec_tac import server_maintenance as sm
from tec_tac.models import TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
MODULE = "tec-tac"  # the framework's own module id: its actions are registered here, and no module can complete them
JOB_FILES = []


class Rollback(Exception):
    pass


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def module_handler(context):
    return scheduler.pending_completion("module", f"probe-{MARK}", note="Probe: waits for nobody.")


def job_handler(context):
    job_id = str(uuid.uuid4())
    root = sm._jobs_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{job_id}.json"
    JOB_FILES.append(path)
    sm._atomic_job(path, {
        "schema": 1, "id": job_id, "action": "probe.noop", "status": "running", "stage": "running",
        "context": {"source_module": MODULE, "source_action": "probe", "source_run_id": str(context["run_id"]), "requested_by": "system"},
        "parameters": {}, "public_parameters": {}, "exit_result": None, "failure": None,
    })
    return scheduler.pending_completion("server_maintenance_job", job_id, note="Probe: waits for a synthetic job file.")


scheduler.register_scheduled_action(id=f"tec-tac.{MARK}-module", module_id=MODULE, label="Pending probe (module)", handler=module_handler, target_types=("none",), permission=None)
scheduler.register_scheduled_action(id=f"tec-tac.{MARK}-job", module_id=MODULE, label="Pending probe (server job)", handler=job_handler, target_types=("none",), permission=None)


def execute(run):
    return execute_schedule_run.run(str(run.id))  # the task body, in this process


def start(manager, action_suffix):
    queued = scheduler.start_one_off_run(user=manager, owner_module=MODULE, action_id=f"tec-tac.{MARK}-{action_suffix}")
    TecTacScheduleRun.objects.filter(pk=queued.pk).update(status="queued")
    return queued


def reload(run):
    return TecTacScheduleRun.objects.get(pk=run.pk)


def run():
    manager = User(username=f"{MARK}-manager", is_superuser=True)
    manager.set_password(uuid.uuid4().hex)
    manager.save()
    state = {}

    def the_new_columns_exist_and_default_blank():
        names = {f.name for f in TecTacScheduleRun._meta.get_fields()}
        assert {"completion_state", "completion_ref", "completion_started_at", "system_action_marks"} <= names, names
        fresh = start(manager, "module")
        row = reload(fresh)
        assert row.completion_state == "" and row.completion_ref == {} and row.completion_started_at is None and row.system_action_marks == [], row.__dict__
        state["run"] = fresh

    def a_handler_can_park_a_run():
        queued = state["run"]
        out = execute(queued)
        assert out == "pending completion", out
        row = reload(queued)
        assert row.status == "running" and row.completion_state == "pending" and row.finished_at is None, (row.status, row.completion_state)
        assert row.completion_ref == {"kind": "module", "external_job_id": f"probe-{MARK}", "note": "Probe: waits for nobody."}, row.completion_ref
        assert row.completion_started_at is not None and row.schedule.last_run_at is None, "last_run_at must stay empty"
        view = scheduler.serialize_run(row)
        assert view["status"] == "running" and view["completion"]["state"] == "pending" and view["completion"]["kind"] == "module", view["completion"]

    def a_caller_that_is_not_a_module_is_refused_and_audited():
        queued = state["run"]
        try:
            scheduler.complete_pending_run(queued.id, external_job_id=f"probe-{MARK}", outcome="succeeded", result={"x": 1})
            raise AssertionError("a shell completed the run")
        except scheduler.SchedulerCompletionRefused as exc:
            assert exc.reason == "caller_unverified", exc.reason
        row = reload(queued)
        assert row.status == "running" and row.completion_state == "pending" and row.result == {}, row.__dict__
        rows = audit._auditlog_model().objects.filter(action="custom:scheduler-completion-refused", object_type="scheduler_run")
        assert any(str(queued.id) in str(getattr(r, "debug_info", "")) for r in rows), "no refusal row was written"

    def a_waiting_run_past_its_timeout_fails_as_completion_timeout():
        queued = state["run"]
        TecTacScheduleRun.objects.filter(pk=queued.pk).update(started_at=timezone.now() - timedelta(days=2))
        counts = scheduler.recover_stale_runs()
        assert counts["running"] >= 1, counts
        row = reload(queued)
        assert row.status == "failed" and row.error_type == "CompletionTimeout" and row.completion_state == "expired", (row.status, row.error_type, row.completion_state)
        try:
            scheduler.complete_pending_run(queued.id, external_job_id=f"probe-{MARK}", outcome="succeeded")
            raise AssertionError("a late completion was accepted")
        except scheduler.SchedulerCompletionRefused:
            pass

    def a_server_job_settles_a_waiting_run():
        queued = start(manager, "job")
        assert execute(queued) == "pending completion"
        row = reload(queued)
        job_id = row.completion_ref["external_job_id"]
        counts = completion.settle_server_job_runs()
        assert counts["checked"] >= 1 and counts["waiting"] >= 1, counts  # the real JSON key lookup found it, the job is still running
        assert reload(queued).status == "running"
        path = sm._jobs_root() / f"{job_id}.json"
        payload = sm._read_job(job_id)
        payload.update(status="succeeded", stage="done", exit_result={"success": True, "exit_code": 0, "signal": None, "timed_out": False})
        sm._atomic_job(path, payload)
        counts = completion.settle_server_job_runs()
        assert counts["settled"] >= 1, counts
        row = reload(queued)
        assert row.status == "succeeded" and row.completion_state == "completed" and row.result.get("job_id") == job_id and row.result.get("exit_code") == 0, (row.status, row.result)
        again = completion.settle_server_job_runs()
        assert reload(queued).finished_at == row.finished_at and again["settled"] == 0, "a second tick changes nothing"

    step("migration 0034: the four columns exist and default blank", the_new_columns_exist_and_default_blank)
    step("a handler's PendingCompletion keeps the run running", a_handler_can_park_a_run)
    step("a shell is refused (caller_unverified) and Tactical's audit log has the row", a_caller_that_is_not_a_module_is_refused_and_audited)
    step("a waiting run past its timeout fails as CompletionTimeout; the late completion is refused", a_waiting_run_past_its_timeout_fails_as_completion_timeout)
    step("a real server-maintenance job file settles a waiting run once", a_server_job_settles_a_waiting_run)
    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass
finally:
    for path in JOB_FILES:
        try:
            path.unlink()
        except OSError:
            pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
