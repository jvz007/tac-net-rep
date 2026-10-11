#!/usr/bin/env python3
"""1.17.18 regression: retry settings on a one-off Scheduler run (ends the AD-22 worker exception).

Same stub harness as scheduler-one-off-run-1.17.16.py. Covered: defaults equal the old behaviour (0 and 60), explicit settings
stored on the disabled ONCE schedule and snapshotted onto the run, out-of-range and wrongly typed values refused before anything
is created, a transient handler error re-queued with the countdown, the AD-13 owner re-check on every attempt, and a permission
lost before attempt 2 ending the run skipped. Celery and the database are dev-server only.
"""
from __future__ import annotations

import importlib.util
import itertools
import sys
import types
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

import logging

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


NOW = [datetime(2026, 10, 10, 12, 0, tzinfo=dt_timezone.utc)]
COUNTER = itertools.count(1)
mods = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    return m


# ------------------------------------------------------------------------------------------------ in-memory models
class Choices:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        self.values = list(kw.values())


class Query(list):
    def first(self):
        return self[0] if self else None

    def exists(self):
        return bool(self)

    def filter(self, **kw):
        return Query(r for r in self if match(r, kw))

    def select_for_update(self):
        return self

    def select_related(self, *a):
        return self

    def order_by(self, *fields):
        key = fields[0].lstrip("-") if fields else "created_at"
        return Query(sorted(self, key=lambda r: (getattr(r, key) is None, getattr(r, key) or 0), reverse=bool(fields and fields[0].startswith("-"))))

    def get(self, pk):
        for item in self:
            if str(item.pk) == str(pk):
                return item
        raise Run.DoesNotExist(pk)


def match(row, kw):
    for key, value in kw.items():
        if key.endswith("__in"):
            if getattr(row, key[:-4]) not in value:
                return False
        elif getattr(row, key) != value:
            return False
    return True


class Manager:
    def __init__(self):
        self.rows = []

    def filter(self, **kw):
        return Query(r for r in self.rows if match(r, kw))

    def select_for_update(self):
        return Query(self.rows)

    def create(self, **kw):
        row = self.model(**kw)
        self.rows.append(row)
        return row


class Model:
    def __init__(self, **kw):
        self.pk = self.id = uuid.uuid4()
        self.created_at = NOW[0] - timedelta(days=1) + timedelta(seconds=next(COUNTER))
        self.__dict__.update(self.defaults)
        self.__dict__.update(kw)

    def save(self, update_fields=None):
        pass


class Schedule(Model):
    OwnerType = Choices(USER="user", MODULE="module")
    ScheduleType = Choices(ONCE="once", DAILY="daily", WEEKLY="weekly", MONTHLY="monthly", INTERVAL="interval")
    TargetMode = Choices(SNAPSHOT="snapshot", DYNAMIC="dynamic")
    MissedPolicy = Choices(SKIP="skip", RUN_ON_RECOVERY="run_on_recovery", EXPIRE="expire")
    ConcurrencyPolicy = Choices(SKIP="skip", QUEUE="queue", ALLOW="allow")
    defaults = dict(owner_type="user", owner_module="", owner_key="", enabled=True, run_at=None, run_time=None, weekdays=[], day_of_month=None,
                    interval_seconds=None, interval_anchor_at=None, last_run_at=None, last_due_key="", created_by=None, updated_by=None,
                    parameters={}, targets={}, target_mode="snapshot", retry_count=0, retry_delay_seconds=60, timezone="UTC",
                    missed_policy="skip", missed_grace_minutes=60, concurrency_policy="skip", target_state="valid", target_state_detail="",
                    updated_at=None, schedule_type="once")

    @property
    def runs(self):
        return Query(r for r in Run.objects.rows if r.schedule is self)

    def delete(self):
        Schedule.objects.rows.remove(self)
        for run in Run.objects.rows:
            if run.schedule is self:
                run.schedule = None


class Run(Model):
    DoesNotExist = type("DoesNotExist", (Exception,), {})
    Status = Choices(QUEUED="queued", RUNNING="running", SUCCEEDED="succeeded", FAILED="failed", SKIPPED="skipped")
    defaults = dict(status="queued", manual=False, result={}, error="", error_type="", celery_task_id="", attempt=0, started_at=None,
                    finished_at=None, schedule=None, schedule_snapshot_id=None, schedule_name="", module_id="", action_id="",
                    owner_type="user", owner_module="", owner_key="", targets_snapshot={}, parameters_snapshot={},
                    target_mode_snapshot="snapshot", retry_count_snapshot=0, retry_delay_seconds_snapshot=60, last_queued_at=None,
                    scheduled_for=None)


Run.schedule_id = property(lambda self: self.schedule.pk if self.schedule is not None else None)
Schedule.objects = Manager()
Schedule.objects.model = Schedule
Run.objects = Manager()
Run.objects.model = Run


class State:
    def current(self=None):
        return State()

    def save(self, update_fields=None):
        pass


class Config:
    once_retention_hours = 48
    run_retention_days = 90
    queued_stale_minutes = 10

    @classmethod
    def current(cls):
        return cls()


QUEUED = []


class FakeTask:
    def apply_async(self, *, args, time_limit):
        if FAIL_QUEUE[0]:
            raise RuntimeError("broker down")
        QUEUED.append(args[0])
        return SimpleNamespace(id="celery-1")


FAIL_QUEUE = [False]
AUDITS = []


class ValidationError(Exception):
    pass


class _Atomic:
    def __call__(self):
        return nullcontext()


mod("django")
mod("django.core")
mod("django.core.exceptions", ValidationError=ValidationError)
mod("django.db", transaction=SimpleNamespace(atomic=_Atomic()))
mod("django.db.models", Q=lambda *a, **k: None)
mod("django.utils")
mod("django.utils.timezone", now=lambda: NOW[0], is_naive=lambda v: v.tzinfo is None)
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.models", TecTacSchedule=Schedule, TecTacScheduleRun=Run, TecTacSchedulerConfig=Config, TecTacSchedulerState=State)
mod("tec_tac.tasks", execute_schedule_run=FakeTask())
mod("tec_tac.capabilities", capability_status=None, CapabilityDisabled=type("CD", (Exception,), {}), CapabilityUnavailable=type("CU", (Exception,), {}),
    CapabilityVersionMismatch=type("CV", (Exception,), {}), CapabilityUnhealthy=type("CH", (Exception,), {}))
mod("tacticalrmm")
mod("tacticalrmm.celery", app=SimpleNamespace(task=lambda *a, **k: (lambda fn: fn)))

PERMS = {}  # username -> set of action permissions
SCOPE = {}  # username -> set of client ids the user may see
MANAGERS = set()


def _can_use_action(user, action):
    if user.username in MANAGERS:
        return True
    return bool(action.permission) and action.permission in PERMS.get(user.username, set())


def _can_access_target_scope(user, targets):
    if user.username in MANAGERS:
        return True
    if targets.get("type") in ("none", "module"):
        return True  # a user with unrestricted Tactical scope; the restricted case is the real helper's, not this test's
    ids = set(targets.get("ids") or [])
    return bool(ids) and ids <= SCOPE.get(user.username, set())


mod("tec_tac.scheduler_views", _can_use_action=_can_use_action, _can_access_target_scope=_can_access_target_scope,
    _canonicalize_endpoint_targets_for_user=lambda user, targets: targets)
audit_stub = mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True},
                 service_audit_actor=lambda **kw: {"service": kw})
pkg.audit = audit_stub
sys.modules.update(mods)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


sched_targets = load("tec_tac.scheduler_targets", "scheduler_targets.py")
load("tec_tac.scheduler_timing", "scheduler_timing.py")
sched = load("tec_tac.scheduler", "scheduler.py")
sched._zone = lambda value: None  # no tz database is needed for UTC
tasks = load("tec_tac.tasks_real", "tasks.py")


class User:
    def __init__(self, username, *, active=True, installer=False):
        self.pk, self.username, self.is_active, self.is_installer_user = len(username), username, active, installer


alice = User("alice")
PERMS["alice"] = {"patching.run"}
SCOPE["alice"] = {1, 2}
CONTEXTS = []


def handler(context):
    CONTEXTS.append(context)
    return {"ok": True}


def legacy_handler(context):
    # an existing handler that reads only the keys it always read
    return {"run": context["run_id"], "manual": context["manual"], "params": context["parameters"]}


sched.register_scheduled_action(id="patching.scan", module_id="patching", label="Patch scan", handler=handler, target_types=("endpoint", "client", "none"), permission="patching.run")
sched.register_scheduled_action(id="patching.open", module_id="patching", label="No permission action", handler=handler, target_types=("none",))
sched.register_scheduled_action(id="patching.legacy", module_id="patching", label="Legacy", handler=legacy_handler, target_types=("none",), permission="patching.run")
sched.register_scheduled_action(id="other.scan", module_id="other", label="Other module", handler=handler, target_types=("none",), permission="patching.run")
TARGETS = {"type": "client", "ids": [1]}


def reset():
    del Schedule.objects.rows[:], Run.objects.rows[:], QUEUED[:], AUDITS[:], CONTEXTS[:]
    FAIL_QUEUE[0] = False


def counts():
    return len(Schedule.objects.rows), len(Run.objects.rows), len(QUEUED)


base = dict(user=alice, owner_module="patching", action_id="patching.scan", targets=TARGETS)


def refused_value(**kw):
    before = counts()
    try:
        sched.start_one_off_run(**base, **kw)
    except sched.SchedulerError:
        must(counts() == before, f"a refused start creates nothing: {kw}")
        return
    raise AssertionError(f"accepted: {kw}")


# defaults equal the behaviour before 1.17.18
reset()
run = sched.start_one_off_run(**base)
must(Schedule.objects.rows[0].retry_count == 0 and Schedule.objects.rows[0].retry_delay_seconds == 60, Schedule.objects.rows[0].__dict__)
must(run.retry_count_snapshot == 0 and run.retry_delay_seconds_snapshot == 60, run.__dict__)

# explicit settings
reset()
run = sched.start_one_off_run(**base, retry_count=3, retry_delay_seconds=5)
must(Schedule.objects.rows[0].retry_count == 3 and Schedule.objects.rows[0].retry_delay_seconds == 5, Schedule.objects.rows[0].__dict__)
must(run.retry_count_snapshot == 3 and run.retry_delay_seconds_snapshot == 5, run.__dict__)
for count, delay in ((10, 86400), (0, 1)):
    reset()
    r = sched.start_one_off_run(**base, retry_count=count, retry_delay_seconds=delay)
    must(r.retry_count_snapshot == count and r.retry_delay_seconds_snapshot == delay)

# refusals
reset()
for kw in ({"retry_count": 11}, {"retry_count": -1}, {"retry_delay_seconds": 0}, {"retry_delay_seconds": 86401},
           {"retry_count": True}, {"retry_count": "3"}, {"retry_count": 2.5}, {"retry_delay_seconds": True},
           {"retry_delay_seconds": "60"}, {"retry_delay_seconds": 1.5}, {"retry_count": None}):
    refused_value(**kw)
must(counts() == (0, 0, 0))
try:
    sched.start_one_off_run(base["user"], "patching", "patching.scan")
    raise AssertionError("positional arguments must stay refused")
except TypeError:
    pass


# worker retry
class Retry(Exception):
    pass


class Task:
    def __init__(self, retries):
        self.request = SimpleNamespace(retries=retries)
        self.retry_args = None

    def retry(self, *, exc, countdown, max_retries):
        self.retry_args = (countdown, max_retries)
        return Retry()


FLAKY = [1]
ATTEMPTS = []


def flaky(context):
    ATTEMPTS.append(context["attempt"])
    if FLAKY[0] > 0:
        FLAKY[0] -= 1
        raise sched.SchedulerTransientError("Tactical was busy.")
    return {"ok": True}


sched.register_scheduled_action(id="patching.flaky", module_id="patching", label="Flaky", handler=flaky, target_types=("none",), permission="patching.run")
flaky_base = dict(user=alice, owner_module="patching", action_id="patching.flaky", targets=None)


def attempt(r, retries):
    task = Task(retries)
    try:
        return tasks.execute_schedule_run(task, str(r.id)), task
    except Retry:
        return "retried", task
    except Exception as exc:
        return exc, task


reset(); FLAKY[0] = 1; del ATTEMPTS[:]
r = sched.start_one_off_run(**flaky_base, retry_count=2, retry_delay_seconds=7)
out, task = attempt(r, 0)
must(out == "retried" and task.retry_args == (7, 2), (out, task.retry_args))
must(r.status == "queued" and r.error_type == "SchedulerTransientError" and r.finished_at is None, r.__dict__)
out, task = attempt(r, 1)
must(out == {"ok": True} and r.status == "succeeded" and ATTEMPTS == [1, 2], (out, ATTEMPTS))

# retries used up: failed
reset(); FLAKY[0] = 5
r = sched.start_one_off_run(**flaky_base, retry_count=1, retry_delay_seconds=3)
out, task = attempt(r, 0)
must(out == "retried")
out, task = attempt(r, 1)
must(isinstance(out, sched.SchedulerTransientError) and r.status == "failed", (out, r.__dict__))

# the default (no retries): a transient error fails at once
reset(); FLAKY[0] = 1
r = sched.start_one_off_run(**flaky_base)
out, task = attempt(r, 0)
must(isinstance(out, sched.SchedulerTransientError) and r.status == "failed" and task.retry_args is None, (out, r.__dict__))

# the owner re-check runs again on attempt 2: a lost permission skips the run
reset(); FLAKY[0] = 1; del ATTEMPTS[:], CONTEXTS[:]
r = sched.start_one_off_run(**flaky_base, retry_count=3, retry_delay_seconds=2)
out, task = attempt(r, 0)
must(out == "retried" and r.status == "queued")
PERMS["alice"] = set()
out, task = attempt(r, 1)
must(isinstance(out, str) and out.startswith("run skipped") and r.status == "skipped" and r.error_type == "AuthorizationRevoked", (out, r.__dict__))
must(ATTEMPTS == [1], "the handler did not run on attempt 2")
PERMS["alice"] = {"patching.run"}

print("PASS one-off retry settings")
