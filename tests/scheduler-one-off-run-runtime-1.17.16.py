"""Runtime check for Core 1.17.16 ``start_one_off_run``, ``get_one_off_run`` and ``get_owned_schedule``. It did NOT run on the development PC
(Django, the database and Celery are not installed there).

Run it on the dev server through Tactical's manage.py shell, (Celery's broker must be reachable, because a start queues a task):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/scheduler-one-off-run-runtime-1.17.16.py

It proves what the stub test (tests/scheduler-one-off-run-1.17.16.py) cannot: the real ``TecTacSchedule`` and ``TecTacScheduleRun`` rows
(a disabled ``once`` schedule owned by the module with ``one-off:<uuid>`` and ``created_by`` the user), real Celery dispatch and
execution (the handler context carries the owner keys and ``one_off``), the real scope and permission helpers of the browser path, and
the AD-13 re-check (a user deactivated after the start gets a ``skipped`` run and an audit row, and the handler never runs).

The probe action is registered in this shell only. Everything runs inside one database transaction that is rolled back at the end, so
the Celery task that each start queues finds no committed run and ends harmlessly. The steps run the task body in this process
(``execute_schedule_run.run``) so the handler runs here. A Celery worker is not needed. It prints PASS or FAIL for each step and exits
with status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import User
from django.db import transaction
from tec_tac import scheduler
from tec_tac.models import TecTacSchedule, TecTacScheduleRun
from tec_tac.tasks import execute_schedule_run

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
MODULE = "tec-tac"  # the framework's own module id: its test actions are registered in scheduler.py
ACTION_ID = f"tec-tac.{MARK}"
CONTEXTS = []


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


def handler(context):
    CONTEXTS.append(context)
    return {"ok": True}


scheduler.register_scheduled_action(id=ACTION_ID, module_id=MODULE, label="One-off probe", handler=handler, target_types=("none",), permission=None)


def make_user(suffix, **fields):
    user = User(username=f"{MARK}-{suffix}", **fields)
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def execute(run):
    return execute_schedule_run.run(str(run.id))  # the task body, in this process


def run():
    manager = make_user("manager", is_superuser=True)  # a native scheduler manager may start an action that has no permission
    plain = make_user("plain")
    inactive = make_user("inactive", is_active=False)

    def refuses_the_wrong_people():
        for who in (inactive, None):
            try:
                scheduler.start_one_off_run(user=who, owner_module=MODULE, action_id=ACTION_ID)
                raise AssertionError("accepted")
            except scheduler.SchedulerNotAllowed:
                pass
        try:
            scheduler.start_one_off_run(user=plain, owner_module=MODULE, action_id=ACTION_ID)
            raise AssertionError("an action with no permission is for managers only")
        except scheduler.SchedulerNotAllowed:
            pass
        try:
            scheduler.start_one_off_run(user=manager, owner_module="not-the-owner", action_id=ACTION_ID)
            raise AssertionError("another module's action")
        except scheduler.SchedulerError:
            pass
        assert not TecTacSchedule.objects.filter(owner_key__startswith="one-off:", created_by__in=[plain, inactive]).exists()

    state = {}

    def creates_a_disabled_once_schedule_and_one_run():
        queued = scheduler.start_one_off_run(user=manager, owner_module=MODULE, action_id=ACTION_ID, parameters={"probe": True}, name=f"{MARK} probe")
        schedule = queued.schedule
        assert schedule.owner_type == "module" and schedule.owner_module == MODULE and schedule.owner_key.startswith("one-off:"), schedule
        assert schedule.enabled is False and schedule.schedule_type == "once" and schedule.created_by_id == manager.pk, schedule
        assert queued.manual is True and queued.status == "queued" and schedule.runs.count() == 1, queued
        info = scheduler.get_one_off_run(queued.id, owner_module=MODULE)
        assert info["id"] == str(queued.id) and info["owner_key"] == schedule.owner_key, info
        owned = scheduler.get_owned_schedule(MODULE, schedule.owner_key)
        assert owned["enabled"] is False and owned["next_run_at"] is None and owned["schedule_type"] == "once", owned
        assert scheduler.get_owned_schedule("some-other-module", schedule.owner_key) is None
        state["run"] = queued

    def the_handler_sees_the_owner():
        queued = state["run"]
        TecTacScheduleRun.objects.filter(pk=queued.pk).update(status="queued")
        result = execute(queued)
        assert result == {"ok": True}, result
        context = CONTEXTS[-1]
        assert context["one_off"] is True and context["owner_user_id"] == manager.pk and context["owner_username"] == manager.username, context
        assert context["owner_module"] == MODULE and context["owner_key"].startswith("one-off:") and context["manual"] is True, context
        assert TecTacScheduleRun.objects.get(pk=queued.pk).status == "succeeded"

    def a_deactivated_owner_is_skipped_and_the_handler_never_runs():
        second = scheduler.start_one_off_run(user=manager, owner_module=MODULE, action_id=ACTION_ID)
        TecTacScheduleRun.objects.filter(pk=second.pk).update(status="queued")
        User.objects.filter(pk=manager.pk).update(is_active=False)
        before = len(CONTEXTS)
        outcome = execute(second)
        row = TecTacScheduleRun.objects.get(pk=second.pk)
        assert row.status == "skipped" and row.error_type == "AuthorizationRevoked" and "inactive" in row.error, (outcome, row.status, row.error)
        assert len(CONTEXTS) == before, "the handler must not run"
        User.objects.filter(pk=manager.pk).update(is_active=True)

    def cleanup_removes_the_one_off_schedule_after_the_retention():
        from datetime import timedelta
        from django.utils import timezone

        schedule = state["run"].schedule
        TecTacScheduleRun.objects.filter(schedule=schedule).update(finished_at=timezone.now() - timedelta(hours=100), status="succeeded")
        TecTacSchedule.objects.filter(pk=schedule.pk).update(last_run_at=timezone.now() - timedelta(hours=100))
        removed = scheduler.cleanup_once_schedules(timezone.now())
        assert removed >= 1 and not TecTacSchedule.objects.filter(pk=schedule.pk).exists(), removed
        assert scheduler.get_one_off_run(state["run"].id, owner_module=MODULE)["status"] == "succeeded", "the run history stays"

    step("an inactive user, no user, no permission and another module's action are refused", refuses_the_wrong_people)
    step("a start creates a disabled once schedule and one queued run", creates_a_disabled_once_schedule_and_one_run)
    step("the handler context carries the owner and one_off", the_handler_sees_the_owner)
    step("a deactivated owner ends the run skipped, audited, handler not run", a_deactivated_owner_is_skipped_and_the_handler_never_runs)
    step("the once cleanup removes the schedule and keeps the run", cleanup_removes_the_one_off_schedule_after_the_retention)
    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
