#!/usr/bin/env python3
"""1.17.46 core.event_jobs: the tick keeps a module's pending rows when its state cannot be read.

Same stubs as tests/event-jobs-1.17.45.py (an in-memory ORM, no Django). Covered: an unreadable registry, a corrupt module state and a
raising state read leave the rows pending and are counted in module_state_unread; the read that recovers, then confirms the module
disabled, expires the rows; a confirmed disabled, absent or legacy module still expires them; a failing read for one module neither expires
its rows nor spends the budget of another module; the strict paths (worker, publish, registration) still fail closed.
"""
from __future__ import annotations

import ast
import copy
import importlib.util
import itertools
import pickle
import sys
import types
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as dt_timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import logging

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
HERE = Path(__file__).resolve().parent


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


NOW = [datetime(2026, 10, 16, 12, 0, tzinfo=dt_timezone.utc)]
MONO = [1000.0]
COUNTER = itertools.count(1)
mods = {}


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    mods[name] = m
    return m


def advance(seconds):
    NOW[0] += timedelta(seconds=seconds)
    MONO[0] += seconds


# ------------------------------------------------------------------------------------------------ an in-memory ORM
class IntegrityError(Exception):
    pass


OPS = ("in", "lt", "lte", "gt", "gte", "isnull")


def field_value(row, name):
    return row.pk if name == "pk" else getattr(row, name)


def matches(row, key, expected):
    field, op = key, "exact"
    if "__" in key and key.rsplit("__", 1)[1] in OPS:
        field, op = key.rsplit("__", 1)
    actual = field_value(row, field)
    if field == "pk":  # Django accepts the text of a UUID for a primary key lookup
        actual, expected = str(actual), ([str(v) for v in expected] if op == "in" else str(expected))
    if op == "exact":
        return actual == expected
    if op == "in":
        return actual in expected
    if op == "isnull":
        return (actual is None) is bool(expected)
    if actual is None:
        return False
    return {"lt": actual < expected, "lte": actual <= expected, "gt": actual > expected, "gte": actual >= expected}[op]


class QS(list):
    def __init__(self, items=(), manager=None):
        super().__init__(items)
        self.manager = manager

    def _new(self, items):
        return QS(items, self.manager)

    def filter(self, **kw):
        return self._new(r for r in self if all(matches(r, k, v) for k, v in kw.items()))

    def all(self):
        return self._new(self)

    def select_for_update(self):
        return self

    def order_by(self, *fields):
        items = list(self)
        for field in reversed(fields):
            name = field.lstrip("-")
            items.sort(key=lambda r: (field_value(r, name) is None, field_value(r, name) or 0), reverse=field.startswith("-"))
        return self._new(items)

    def get(self, **kw):
        found = self.filter(**kw)
        if not found:
            raise self.manager.model.DoesNotExist(kw)
        return found[0]

    def first(self):
        return self[0] if len(self) else None

    def exists(self):
        return len(self) > 0

    def count(self):
        return len(self)

    def values_list(self, name, flat=False):
        return self._new(field_value(r, name) for r in self)

    def update(self, **kw):
        for row in self:
            row.__dict__.update(kw)
        return len(self)

    def delete(self):
        for row in list(self):
            self.manager.rows.remove(row)
        return len(self), {}

    def __getitem__(self, item):
        result = super().__getitem__(item)
        return self._new(result) if isinstance(item, slice) else result


class Manager:
    QUERIES = [0]

    def __init__(self, model):
        self.model, self.rows = model, []

    def _qs(self):
        Manager.QUERIES[0] += 1
        return QS(self.rows, self)

    def filter(self, **kw):
        return self._qs().filter(**kw)

    def all(self):
        return self._qs()

    def select_for_update(self):
        return self._qs()

    def create(self, **kw):
        Manager.QUERIES[0] += 1
        row = self.model(**kw)
        self.model.check_unique(self.rows, row)
        self.rows.append(row)
        return row


class Model:
    defaults: dict = {}

    def __init__(self, **kw):
        self.__dict__.update(self.defaults)
        self.__dict__.update(kw)
        self.pk = self.id = kw.get("id") or uuid.uuid4()
        self.created_at = NOW[0] + timedelta(microseconds=next(COUNTER))

    @classmethod
    def check_unique(cls, rows, row):
        pass

    def save(self):
        pass


class Choices:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Job(Model):
    DoesNotExist = type("DoesNotExist", (Exception,), {})
    Status = Choices(PENDING="pending", RUNNING="running")
    defaults = dict(payload={}, policy={}, status="pending", attempt=0, max_attempts=3, next_attempt_at=None, expires_at=None, last_enqueued_at=None,
                    started_at=None, finished_at=None, error_type="", error="", result={}, celery_task_id="")

    @classmethod
    def check_unique(cls, rows, row):
        if row.status in ("pending", "running") and any(
            r.module_id == row.module_id and r.job_id == row.job_id and r.key == row.key and r.status in ("pending", "running") for r in rows
        ):
            raise IntegrityError("tectac_evjob_active_key")


class Stat(Model):
    DoesNotExist = type("DoesNotExist", (Exception,), {})
    defaults = dict(published=0, duplicate=0, dropped=0, dropped_reported=0, dropped_day=0, dropped_day_started=None, succeeded=0, failed=0,
                    expired=0, skipped=0, last_failure_at=None, last_error="")

    @classmethod
    def check_unique(cls, rows, row):
        if any(r.module_id == row.module_id and r.job_id == row.job_id for r in rows):
            raise IntegrityError("tectac_evjobstat_unique")


class Config(Model):
    run_retention_days = 90

    @classmethod
    def current(cls):
        return cls()


for model in (Job, Stat):
    model.objects = Manager(model)

# ------------------------------------------------------------------------------------------------ Django, Celery, registry and audit stubs
CONNECTION = SimpleNamespace(in_atomic_block=False, vendor="sqlite")
COMMIT_HOOKS = []
ATOMIC_ENTERED = [0]


@contextmanager
def atomic():
    ATOMIC_ENTERED[0] += 1
    yield


def on_commit(callback):
    COMMIT_HOOKS.append(callback)


def commit():
    """The caller's transaction commits: run what was registered with on_commit, outside the atomic block."""
    CONNECTION.in_atomic_block = False
    hooks, COMMIT_HOOKS[:] = list(COMMIT_HOOKS), []
    for hook in hooks:
        hook()


mod("django")
mod("django.db", IntegrityError=IntegrityError, connection=CONNECTION, transaction=SimpleNamespace(atomic=atomic, on_commit=on_commit))
mod("django.utils")
mod("django.utils.timezone", now=lambda: NOW[0], is_naive=lambda value: value.tzinfo is None)

SENT = []  # (args, options) of every message sent
BROKER = []  # the broker options of every connection opened
BROKER_DOWN = [False]


class FakeTask:
    class app:
        @staticmethod
        @contextmanager
        def connection_for_write(transport_options=None, connect_timeout=None):
            BROKER.append({"transport_options": transport_options, "connect_timeout": connect_timeout})
            yield SimpleNamespace(name="broker")

    @staticmethod
    def apply_async(*, args, connection=None, **options):
        if BROKER_DOWN[0]:
            raise ConnectionError("broker down")
        SENT.append({"args": args, "options": options, "connection": connection})
        return SimpleNamespace(id="celery-task")


AUDITS = []


def audit_record(**kw):
    AUDITS.append(kw)
    return {"recorded": True}


PLUGINS = {}  # module id -> plugin
ENABLED = {}  # module id -> bool
REGISTRY_FAIL = [False]
STATE_FAIL = [False]


def discover_plugins():
    if REGISTRY_FAIL[0]:
        raise OSError("registry unreadable")
    return list(PLUGINS.values())


CORRUPT = [False]
FAIL_FOR = set()  # module ids whose state read fails


def load_state():
    if STATE_FAIL[0]:
        raise OSError("state unreadable")
    if CORRUPT[0]:
        return {"schema": 1, "modules": {}, "_corrupt": True}  # like the real file reader
    return {"schema": 1, "modules": {}}


def is_enabled(module_id, state=None):
    if module_id in FAIL_FOR or STATE_FAIL[0]:
        raise OSError("state unreadable")
    if state is not None and state.get("_corrupt"):
        return False  # the real is_enabled answers False on a corrupt state
    return ENABLED.get(module_id, True)


CAPS = []
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.models", TecTacEventJob=Job, TecTacEventJobStat=Stat, TecTacSchedulerConfig=Config)
mod("tec_tac.tasks", execute_event_job=FakeTask)
mod("tec_tac.registry", discover_plugins=discover_plugins)
mod("tec_tac.module_state", load_state=load_state, is_enabled=is_enabled)
audit_stub = mod("tec_tac.audit", record=audit_record, service_audit_actor=lambda **kw: {"service": kw})
mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or SimpleNamespace(**kw))
pkg.audit = audit_stub
sys.modules.update(mods)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


policy = load("tec_tac.event_jobs_policy", "event_jobs_policy.py")
ej = load("tec_tac.event_jobs", "event_jobs.py")
for clocked in (ej._RECENT, ej._RATE, ej._BREAKER, ej._GAUGES, ej._ENABLED):
    clocked.clock = lambda: MONO[0]
ej._rand = lambda: 0.0  # no jitter unless a test asks for it


def plugin(module_id, root, *, kind="extension", legacy=False):
    return SimpleNamespace(plugin_id=module_id, plugin_type=kind, legacy=legacy, root=str(root), version="1.0.0")


OTHER_ROOT = ROOT / "no-such-folder-other-module"  # outside this tests folder, which stands in for the alerts module
CALLS = []  # context of every handler call
SENTINEL = "SENTINEL-PAYLOAD-VALUE-5d1"


def handler(context):
    CALLS.append(context)
    return {"ok": True}


def failing_handler(context):
    CALLS.append(context)
    raise RuntimeError(f"upstream refused {context['key']}")


def reset():
    ej._clear_for_tests()
    for model in (Job, Stat):
        del model.objects.rows[:]
    del SENT[:], BROKER[:], AUDITS[:], CALLS[:], COMMIT_HOOKS[:], CAPS[:]
    BROKER_DOWN[0] = REGISTRY_FAIL[0] = STATE_FAIL[0] = CORRUPT[0] = False
    FAIL_FOR.clear()
    CONNECTION.in_atomic_block = False
    ATOMIC_ENTERED[0] = 0
    ENABLED.clear()
    PLUGINS.clear()
    PLUGINS["alerts"] = plugin("alerts", HERE)  # this file lies in the "alerts" module's folder
    PLUGINS["other"] = plugin("other", OTHER_ROOT)
    NOW[0] = datetime(2026, 10, 16, 12, 0, tzinfo=dt_timezone.utc)


def register(handler_fn=handler, **over):
    spec = dict(id="alerts.deliver", module_id="alerts", label="Send an alert notice", handler=handler_fn)
    spec.update(over)
    return ej.register_event_job(**spec)


def refused(**over):
    try:
        register(**over)
    except ej.EventJobRegistrationError as exc:
        must(isinstance(exc, ValueError), "a registration refusal is a ValueError")
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def jobs():
    return Job.objects.rows


def stat(job_id="alerts.deliver"):
    return next((s for s in Stat.objects.rows if s.job_id == job_id), None)


def one_row():
    must(len(jobs()) == 1, len(jobs()))
    return jobs()[0]


def run(row=None, task_id="task-1"):
    return ej.run_event_job((row or one_row()).pk, celery_task_id=task_id, now=NOW[0])


def tick():
    return ej.recover_event_jobs(NOW[0])


def pending():
    return sum(1 for j in jobs() if j.status == "pending")


def seed(n=3):
    reset()
    handle = register()
    for i in range(n):
        handle.publish(f"g{i}")
    must(pending() == n, "seeded")
    return handle


# (a) the registry cannot be read
seed()
REGISTRY_FAIL[0] = True
out = tick()
must(pending() == 3 and out["module_unavailable"] == 0 and out["module_state_unread"] == 1, out)
must(not AUDITS and stat().expired == 0 and stat().skipped == 0, "no audit row, no stat change")
REGISTRY_FAIL[0] = False
out = tick()
must(pending() == 3 and out["module_unavailable"] == 0 and out["module_state_unread"] == 0, out)
must(all(j.last_enqueued_at is not None for j in jobs()), "a healthy tick still enqueues them")
print("       tick: an unreadable registry leaves every row pending; the next healthy tick carries on")

# (b) the module state is flagged corrupt
seed()
CORRUPT[0] = True
out = tick()
must(pending() == 3 and out["module_unavailable"] == 0 and out["module_state_unread"] == 1 and not AUDITS, out)
must(ej._module_status_now("alerts") == "unknown" and ej._module_runnable_now("alerts") is False, "strict wrapper fails closed")
print("       tick: a corrupt module state leaves rows pending")

# (c) the state read raises
seed()
STATE_FAIL[0] = True
out = tick()
must(pending() == 3 and out["module_unavailable"] == 0 and out["module_state_unread"] == 1 and not AUDITS, out)
print("       tick: a raising module state read leaves rows pending")

# (d) the read recovers and the module is confirmed disabled
STATE_FAIL[0] = False
ENABLED["alerts"] = False
out = tick()
must(out["module_unavailable"] == 3 and out["module_state_unread"] == 0, out)
must(all(j.status == "expired" and j.error_type == "ModuleUnavailable" for j in jobs()), "expired")
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-skipped" and AUDITS[0]["metadata"]["count"] == 3, AUDITS)
print("       tick: once the read succeeds and shows the module disabled, the rows expire with one audit row")

# (e) confirmed disabled, absent, legacy, not an extension
seed()
ENABLED["alerts"] = False
out = tick()
must(out["module_unavailable"] == 3 and out["module_state_unread"] == 0 and pending() == 0, out)
seed()
del PLUGINS["alerts"]
out = tick()
must(out["module_unavailable"] == 3 and pending() == 0, out)
seed()
PLUGINS["alerts"] = plugin("alerts", HERE, legacy=True)
out = tick()
must(out["module_unavailable"] == 3 and pending() == 0, out)
seed()
PLUGINS["alerts"] = plugin("alerts", HERE, kind="theme")
out = tick()
must(out["module_unavailable"] == 3 and pending() == 0, out)
print("       tick: a confirmed disabled, absent, legacy or non-extension module still has its rows expired")

# (f) mixed: one module unreadable, another confirmed disabled
reset()
PLUGINS["beta"] = plugin("beta", HERE)
alerts_handle = register()
alerts_handle.publish("a1")
alerts_handle.publish("a2")
beta = ej.register_event_job(id="beta.deliver", module_id="beta", label="Beta", handler=handler)
beta.publish("b1")
beta.publish("b2")
FAIL_FOR.add("alerts")
ENABLED["beta"] = False
orig_limit = policy.TICK_ROW_LIMIT
policy.TICK_ROW_LIMIT = 2  # a budget the unreadable module must not spend
try:
    out = tick()
finally:
    policy.TICK_ROW_LIMIT = orig_limit
by_module = {}
for j in jobs():
    by_module.setdefault(j.module_id, []).append(j.status)
must(by_module["alerts"] == ["pending", "pending"], by_module)
must(by_module["beta"] == ["expired", "expired"], by_module)
must(out["module_unavailable"] == 2 and out["module_state_unread"] == 1, out)
print("       tick: a failing read for one module keeps its rows and does not spend another module's budget")

# (g) the strict paths still fail closed
seed(1)
REGISTRY_FAIL[0] = True
must(ej._module_runnable_now("alerts") is False, "runnable is False on a registry fault")
REGISTRY_FAIL[0] = False
STATE_FAIL[0] = True
must(ej._module_runnable_now("alerts") is False, "runnable is False on a state fault")
must(run() == "job deferred" and not CALLS, "an unreadable state keeps the single row, no handler call")
must(pending() == 1 and jobs()[0].status == "pending" and jobs()[0].attempt == 0, "the deferred row is pending, no attempt used")
STATE_FAIL[0] = False
must(ej._module_status_now("alerts") == "runnable", "readable again")
STATE_FAIL[0] = True
reset()
handle = register()
STATE_FAIL[0] = True
ej._ENABLED.clear()
must(handle.publish("k-fault").outcome == "disabled" and not jobs(), "publish answers disabled on a state fault")
reset()
CORRUPT[0] = True
must("could not read" in refused(), "(h) registration is refused on a corrupt state")
reset()
must(ej._module_runnable_now("alerts") is True and ej._module_status_now("alerts") == "runnable", "healthy: runnable")
print("       fail-closed paths are unchanged: strict check, the worker, publish and registration")
print("[TEST] PASS event jobs module gate 1.17.46")
