#!/usr/bin/env python3
"""1.17.16 regression: a module starts a one-off run of one of its registered Scheduler actions for a user, and reads a
module-owned schedule (AD-13 condition 2; cyberhoot, patching and scoutdns requests).

The real scheduler.py, scheduler_targets.py and tasks.py run against stubs for Django, the models (an in-memory store), Celery
dispatch, the browser-path permission helpers and the audit writer. Covered: refusals (inactive or installer user, an action of
another module, an unregistered action, a user without the action permission, targets outside scope, a bad target type), the
disabled ONCE module-owned schedule with ``created_by`` and exactly one queued manual run, the handler context owner keys and
``one_off``, a run whose owner was deactivated before execution ending skipped and audited, cleanup of the one-off schedule, handlers
that ignore the new keys, and ``get_owned_schedule``. Celery, the database and the real dispatch are
tests/scheduler-one-off-run-runtime-1.17.16.py (a dev-server script).
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


def refused(exc_type, **kw):
    try:
        sched.start_one_off_run(**kw)
    except exc_type as exc:
        return exc
    raise AssertionError(f"start_one_off_run was accepted: {kw}")


def reset():
    del Schedule.objects.rows[:], Run.objects.rows[:], QUEUED[:], AUDITS[:], CONTEXTS[:]
    FAIL_QUEUE[0] = False


def counts():
    return len(Schedule.objects.rows), len(Run.objects.rows), len(QUEUED)


# ------------------------------------------------------------------------------------------------ refusals
reset()
base = dict(user=alice, owner_module="patching", action_id="patching.scan", targets=TARGETS)
for who in (User("gone", active=False), User("installer", installer=True), None):
    refused(sched.SchedulerNotAllowed, **{**base, "user": who})
refused(sched.SchedulerError, **{**base, "action_id": "other.scan"})  # another module's action
refused(sched.SchedulerError, **{**base, "owner_module": "other"})  # patching's action, claimed by another module
refused(sched.SchedulerError, **{**base, "action_id": "patching.nope"})  # unregistered
refused(sched.SchedulerError, **{**base, "owner_module": ""})
refused(sched.SchedulerError, **{**base, "targets": ["not", "a", "dict"]})
refused(sched.SchedulerError, **{**base, "targets": {"type": "site", "ids": [1]}})  # a type the action does not take
refused(sched.SchedulerError, **{**base, "parameters": ["x"]})
refused(sched.SchedulerError, **{**base, "parameters": {"x": object()}})
refused(sched.SchedulerNotAllowed, **{**base, "user": User("bob")})  # no action permission
refused(sched.SchedulerNotAllowed, **{**base, "user": User("bob"), "action_id": "patching.open", "targets": None})  # no permission set on the action: managers only
refused(sched.SchedulerNotAllowed, **{**base, "targets": {"type": "client", "ids": [3]}})  # outside the user's scope
refused(sched.SchedulerNotAllowed, **{**base, "targets": {"type": "client", "ids": [1, 3]}})  # one id outside is enough
must(counts() == (0, 0, 0), "a refused start creates no schedule, run or queue entry")
must(all(isinstance(refused(sched.SchedulerNotAllowed, **{**base, "user": User("bob")}), sched.SchedulerError) for _ in range(1)), "a refusal is a SchedulerError")

# ------------------------------------------------------------------------------------------------ a good start
run = sched.start_one_off_run(**base, parameters={"mode": "scan"}, name="Scan for Acme")
must(counts() == (1, 1, 1), counts())
schedule = Schedule.objects.rows[0]
must(schedule.owner_type == "module" and schedule.owner_module == "patching" and schedule.owner_key.startswith("one-off:"), schedule.__dict__)
uuid.UUID(schedule.owner_key[len("one-off:"):])
must(schedule.enabled is False and schedule.schedule_type == "once" and schedule.run_at == NOW[0], "disabled, ONCE, run_at now: the ticker never dispatches it")
must(schedule.created_by is alice and schedule.module_id == "patching" and schedule.action_id == "patching.scan", schedule.__dict__)
must(schedule.name == "Scan for Acme" and schedule.parameters == {"mode": "scan"} and schedule.targets == {"type": "client", "ids": [1]}, schedule.__dict__)
must(run.manual is True and run.status == "queued" and run.schedule is schedule and run.owner_key == schedule.owner_key, run.__dict__)
must(QUEUED == [str(run.id)], QUEUED)
# one audit row, best effort
must(len(AUDITS) == 1 and AUDITS[0]["actor"] is alice and AUDITS[0]["module_id"] == "core" and AUDITS[0]["object_type"] == "scheduler_run", AUDITS)
must(AUDITS[0]["action"] == "add" and AUDITS[0]["object_id"] == str(run.id), AUDITS[0])
must(AUDITS[0]["metadata"] == {"owner_module": "patching", "action_id": "patching.scan", "requested_by": "scheduler"}, AUDITS[0]["metadata"])
# a second start is a second schedule with its own key
second = sched.start_one_off_run(**base)
must(counts() == (2, 2, 2) and Schedule.objects.rows[1].owner_key != schedule.owner_key, counts())
# a failing audit writer never stops the start
audit_stub.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))
third = sched.start_one_off_run(**base)
must(third.status == "queued", "the audit row is best effort")
audit_stub.record = lambda **kw: AUDITS.append(kw) or {"recorded": True}
# a manager may start an action with no permission, and a default target is the action's first type
manager = User("root")
MANAGERS.add("root")
opened = sched.start_one_off_run(user=manager, owner_module="patching", action_id="patching.open")
must(Schedule.objects.rows[-1].targets == {"type": "none"} and opened.status == "queued", Schedule.objects.rows[-1].targets)
# a broker failure removes the schedule and raises a transient error
reset()
FAIL_QUEUE[0] = True
before = counts()
try:
    sched.start_one_off_run(**base)
    raise AssertionError("a broker failure must raise")
except sched.SchedulerTransientError:
    pass
must(Schedule.objects.rows == [], "no orphan one-off schedule is left")
FAIL_QUEUE[0] = False

# ------------------------------------------------------------------------------------------------ get_one_off_run
reset()
run = sched.start_one_off_run(**base)
info = sched.get_one_off_run(run.id, owner_module="patching")
must(info["id"] == str(run.id) and info["status"] == "queued" and info["owner_module"] == "patching" and info["manual"] is True, info)
for bad in (str(uuid.uuid4()), "not-a-uuid", None):
    try:
        sched.get_one_off_run(bad, owner_module="patching")
        raise AssertionError("an unknown run must be refused")
    except sched.SchedulerError:
        pass
try:
    sched.get_one_off_run(run.id, owner_module="other")
    raise AssertionError("another module may not read it")
except sched.SchedulerError:
    pass
# an ordinary manual run of a module schedule is not a one-off run
ordinary = Schedule.objects.create(name="n", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching", owner_key="nightly")
ordinary_run = Run.objects.create(schedule=ordinary, owner_type="module", owner_module="patching", owner_key="nightly", action_id="patching.scan")
try:
    sched.get_one_off_run(ordinary_run.id, owner_module="patching")
    raise AssertionError("not a one-off run")
except sched.SchedulerError:
    pass

# ------------------------------------------------------------------------------------------------ execution: the handler context
Run.objects.rows.remove(ordinary_run)
ordinary.delete()


def execute(r):
    return tasks.execute_schedule_run(SimpleNamespace(request=SimpleNamespace(retries=0)), str(r.id))


reset()
run = sched.start_one_off_run(**base, parameters={"mode": "scan"})
result = execute(run)
must(result == {"ok": True} and run.status == "succeeded", (result, run.__dict__))
context = CONTEXTS[0]
for key, want in (("owner_type", "module"), ("owner_module", "patching"), ("owner_user_id", alice.pk), ("owner_username", "alice"), ("one_off", True),
                  ("manual", True), ("module_id", "patching"), ("action_id", "patching.scan"), ("parameters", {"mode": "scan"})):
    must(context[key] == want, (key, context[key]))
must(context["owner_key"].startswith("one-off:") and context["targets"] == {"type": "client", "ids": [1]}, context)
# the earlier context keys are all still there
for key in ("schedule_id", "run_id", "module_id", "action_id", "target_mode", "targets", "parameters", "scheduled_for", "manual", "attempt"):
    must(key in context, key)

# a user-owned schedule's context carries the owner too; a plain module schedule's has no user
user_sched = Schedule.objects.create(name="u", module_id="patching", action_id="patching.scan", owner_type="user", created_by=alice, targets={"type": "client", "ids": [1]})
user_run = Run.objects.create(schedule=user_sched, schedule_snapshot_id=user_sched.id, owner_type="user", action_id="patching.scan", module_id="patching", targets_snapshot=user_sched.targets)
del CONTEXTS[:]
execute(user_run)
must(CONTEXTS[0]["owner_user_id"] == alice.pk and CONTEXTS[0]["owner_username"] == "alice" and CONTEXTS[0]["one_off"] is False and CONTEXTS[0]["owner_type"] == "user", CONTEXTS[0])
mod_sched = Schedule.objects.create(name="m", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching", owner_key="nightly", created_by=alice)
mod_run = Run.objects.create(schedule=mod_sched, schedule_snapshot_id=mod_sched.id, owner_type="module", owner_module="patching", owner_key="nightly", action_id="patching.scan", module_id="patching")
del CONTEXTS[:]
execute(mod_run)
must(CONTEXTS[0]["owner_user_id"] is None and CONTEXTS[0]["owner_username"] is None and CONTEXTS[0]["one_off"] is False and CONTEXTS[0]["owner_key"] == "nightly", CONTEXTS[0])
# a handler that ignores the new keys is unaffected
legacy = sched.start_one_off_run(user=alice, owner_module="patching", action_id="patching.legacy", targets=None, parameters={"a": 1})
must(execute(legacy) == {"run": str(legacy.id), "manual": True, "params": {"a": 1}} and legacy.status == "succeeded", legacy.__dict__)

# ------------------------------------------------------------------------------------------------ AD-13: re-check before the handler
def revoked_case(label, mutate, reason_part):
    reset()
    r = sched.start_one_off_run(**base)
    del AUDITS[:]
    mutate()
    out = execute(r)
    must(r.status == "skipped" and r.error_type == "AuthorizationRevoked" and reason_part in r.error and r.finished_at == NOW[0], (label, r.__dict__))
    must(not CONTEXTS, f"{label}: the handler never ran")
    must(isinstance(out, str) and out.startswith("run skipped"), (label, out))
    must(len(AUDITS) == 1 and AUDITS[0]["action"] == "deny" and AUDITS[0]["object_id"] == str(r.id) and reason_part in AUDITS[0]["message"], (label, AUDITS))
    return r


revoked_case("deactivated", lambda: setattr(alice, "is_active", False), "missing or inactive")
alice.is_active = True
revoked_case("permission removed", lambda: PERMS.__setitem__("alice", set()), "no longer has permission")
PERMS["alice"] = {"patching.run"}
revoked_case("scope narrowed", lambda: SCOPE.__setitem__("alice", {2}), "no longer within")
SCOPE["alice"] = {1, 2}
revoked_case("became an installer user", lambda: setattr(alice, "is_installer_user", True), "missing or inactive")
alice.is_installer_user = False
revoked_case("schedule removed", lambda: Schedule.objects.rows[0].delete(), "no longer exists")
# a check that cannot be made counts as a refusal and never raises
def boom(user, action):
    raise RuntimeError("lookup failed")
saved = sys.modules["tec_tac.scheduler_views"]._can_use_action
revoked_case("check failed", lambda: setattr(sys.modules["tec_tac.scheduler_views"], "_can_use_action", boom), "could not be verified")
refused(sched.SchedulerNotAllowed, **base)  # and at the start the same failure is a refusal, not a crash
sys.modules["tec_tac.scheduler_views"]._can_use_action = saved
# a failing audit writer never raises into Celery
reset()
r = sched.start_one_off_run(**base)
alice.is_active = False
audit_stub.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))
must(execute(r).startswith("run skipped") and r.status == "skipped", r.__dict__)
audit_stub.record = lambda **kw: AUDITS.append(kw) or {"recorded": True}
alice.is_active = True
# a one-off run that was already claimed is not skipped twice
must(execute(r) == "run already skipped", "a duplicate delivery does nothing")
# a module schedule that is not a one-off is not re-checked (its owner is the module)
reset()
mod_sched = Schedule.objects.create(name="m", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching", owner_key="nightly", created_by=alice)
mod_run = Run.objects.create(schedule=mod_sched, schedule_snapshot_id=mod_sched.id, owner_type="module", owner_module="patching", owner_key="nightly", action_id="patching.scan", module_id="patching")
alice.is_active = False
execute(mod_run)
must(mod_run.status == "succeeded", "only one-off runs are re-checked against created_by")
alice.is_active = True
must(sched._runtime_authorization_error(mod_sched) is None, "a plain module schedule has no user check")
one = Schedule.objects.create(name="o", module_id="patching", action_id="patching.scan", owner_type="module", owner_module="patching", owner_key="one-off:x", created_by=None)
must(sched._runtime_authorization_error(one) == "Schedule owner is missing or inactive.", "a one-off with no owner is refused")
user_s = Schedule.objects.create(name="u", module_id="patching", action_id="patching.scan", owner_type="user", created_by=None)
must(sched._runtime_authorization_error(user_s) == "Schedule owner is missing or inactive.", "the user-owned check is unchanged")

# ------------------------------------------------------------------------------------------------ cleanup
reset()
run = sched.start_one_off_run(**base)
schedule = Schedule.objects.rows[0]
must(sched.cleanup_once_schedules(NOW[0]) == 0 and Schedule.objects.rows, "a queued run keeps its schedule")
execute(run)
schedule.last_run_at = NOW[0]
must(sched.cleanup_once_schedules(NOW[0] + timedelta(hours=47)) == 0 and Schedule.objects.rows, "kept for the retention")
must(sched.cleanup_once_schedules(NOW[0] + timedelta(hours=49)) == 1 and not Schedule.objects.rows, "removed after the 48 hours")
must(sched.get_one_off_run(run.id, owner_module="patching")["status"] == "succeeded", "the run stays readable after its schedule is gone")

# ------------------------------------------------------------------------------------------------ get_owned_schedule
reset()
anchor = NOW[0] - timedelta(minutes=10)
Schedule.objects.create(name="iv", module_id="cyberhoot", action_id="x.y", owner_type="module", owner_module="cyberhoot", owner_key="sync",
                        schedule_type="interval", interval_seconds=3600, interval_anchor_at=anchor, enabled=True, last_run_at=NOW[0] - timedelta(minutes=70))
info = sched.get_owned_schedule("cyberhoot", "sync")
must(info["enabled"] is True and info["schedule_type"] == "interval" and info["next_run_at"] == (anchor + timedelta(hours=1)).isoformat(), info)
must(info["last_run_at"] == (NOW[0] - timedelta(minutes=70)).isoformat() and info["last_run_status"] is None and info["last_run_finished_at"] is None, info)
must(set(info) == {"enabled", "schedule_type", "next_run_at", "last_run_at", "last_run_status", "last_run_finished_at"}, "the model is not exposed")
iv = Schedule.objects.rows[0]
Run.objects.create(schedule=iv, status="failed", finished_at=NOW[0] - timedelta(minutes=5))
info = sched.get_owned_schedule("cyberhoot", "sync")
must(info["last_run_status"] == "failed" and info["last_run_finished_at"] == (NOW[0] - timedelta(minutes=5)).isoformat(), info)
Schedule.objects.create(name="once", module_id="scoutdns", action_id="x.y", owner_type="module", owner_module="scoutdns", owner_key="weekly-once",
                        schedule_type="once", run_at=NOW[0] + timedelta(days=1), enabled=True)
must(sched.get_owned_schedule("scoutdns", "weekly-once")["next_run_at"] == (NOW[0] + timedelta(days=1)).isoformat(), "once")
Schedule.objects.create(name="off", module_id="cyberhoot", action_id="x.y", owner_type="module", owner_module="cyberhoot", owner_key="off",
                        schedule_type="interval", interval_seconds=3600, interval_anchor_at=anchor, enabled=False)
off = sched.get_owned_schedule("cyberhoot", "off")
must(off["enabled"] is False and off["next_run_at"] is None, off)
must(sched.get_owned_schedule("cyberhoot", "missing") is None, "None when there is no such tuple")
must(sched.get_owned_schedule("scoutdns", "sync") is None, "a module reads only its own tuple")
for args in (("", "sync"), ("cyberhoot", ""), ("cyberhoot", "k" * 256)):
    try:
        sched.get_owned_schedule(*args)
        raise AssertionError(f"bad owner tuple accepted: {args}")
    except sched.SchedulerError:
        pass
# a one-off schedule is not returned for a different owner_module
reset()
sched.start_one_off_run(**base)
key = Schedule.objects.rows[0].owner_key
must(sched.get_owned_schedule("patching", key)["enabled"] is False, "its own module can read it")
must(sched.get_owned_schedule("cyberhoot", key) is None, "another module cannot")

print("[TEST] PASS scheduler one-off run 1.17.16")
