#!/usr/bin/env python3
"""1.17.47 core.event_jobs: a deferred row (the worker could not read the module state) is due at once, so the first tick more than 60 s later resends it.

Same stubs as tests/event-jobs-module-gate-1.17.46.py (an in-memory ORM, no Django). Covered: the worker with an unreadable state answers
'job deferred' and keeps the row pending with the attempt unchanged and no audit row; ``recover_event_jobs`` at +59 s enqueues nothing and
at +61 s enqueues exactly one message, so the retry comes after one to two minutes and not two to three (1.17.46 said 60 seconds); once the
state reads again the resent row runs the handler once; ``policy.is_overdue_pending`` agrees at the same boundaries; a failed attempt
keeps its own countdown (unchanged); the old UNREAD_RETRY_SECONDS constant is gone so the two numbers cannot drift.
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


def _fake_caller(*, provider_file, cache_seconds=0):
    """1.17.47: the verified-caller seam. A test file is not a module's code, so the real helper would refuse every publish here. This
    stand-in answers as the owning module (read from the publishing frame), the way the real helper does for the owner's own code.
    The real helper is exercised with real frames in tests/event-jobs-caller-1.17.47.py."""
    definition = sys._getframe(1).f_locals["definition"]
    identity = SimpleNamespace(module_id=definition.module_id, kind="module", module_version="1.0.0")
    return SimpleNamespace(identity=identity, unverifiable=False)  # 1.17.48: the private helper answers identity and unverifiable


mod("tec_tac.caller_identity", core_provider_caller_checked=_fake_caller, clear_snapshot_for_tests=lambda: None)
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



source_text = (APP / "event_jobs.py").read_text(encoding="utf-8")
must("UNREAD_RETRY_SECONDS =" not in source_text, "the separate 60 second constant is gone; policy.OVERDUE_SECONDS is the one number")


def sent():
    return len(SENT)


# (a) a deferred row is due at once
seed(1)
STATE_FAIL[0] = True
ej._ENABLED.clear()
before_audits = len(AUDITS)
t0 = NOW[0]
must(run() == "job deferred" and not CALLS, "deferred, no handler call")
row = one_row()
must(row.status == "pending" and row.attempt == 0 and len(AUDITS) == before_audits, "pending, attempt unchanged, no audit row")
must(row.next_attempt_at == t0 and row.last_enqueued_at == t0, (row.next_attempt_at, row.last_enqueued_at))
print("       a deferred row is due at once (next_attempt_at = now) and was enqueued now")

# (b) the tick boundaries
del SENT[:]
advance(59)
out = tick()
must(sent() == 0 and out["enqueued"] == 0, (sent(), out))
must(not policy.is_overdue_pending(NOW[0], row.last_enqueued_at, row.next_attempt_at), "+59 s is not overdue")
advance(2)  # +61 s
must(policy.is_overdue_pending(NOW[0], row.last_enqueued_at, row.next_attempt_at), "+61 s is overdue")
out = tick()
must(sent() == 1 and out["enqueued"] == 1, (sent(), out))
must(one_row().status == "pending" and one_row().attempt == 0, "still pending until a worker runs it")
print("       the tick resends nothing at +59 s and exactly one message at +61 s")

# (c) the state reads again: the resent row runs once
STATE_FAIL[0] = False
ej._ENABLED.clear()
must(run(task_id="task-2") == "job succeeded", one_row().status)
must(len(CALLS) == 1 and one_row().status == "succeeded", (len(CALLS), one_row().status))
must(run(task_id="task-3") == "job already succeeded" and len(CALLS) == 1, "a second delivery runs nothing")
print("       once the state reads again the resent row runs the handler once")

# (d) the old wording: a two-to-three minute wait is gone. At +119 s a row deferred at t0 must already have been resent once
seed(1)
STATE_FAIL[0] = True
ej._ENABLED.clear()
run()
del SENT[:]
advance(61)
tick()
must(sent() == 1, "resent by the first tick after 60 s")

# (e) a failed attempt keeps its own countdown
STATE_FAIL[0] = False
ej._ENABLED.clear()
seed(1)
handle = ej._HANDLES["alerts.deliver"]
ej._JOBS["alerts.deliver"] = ej.EventJobDefinition(ej._JOBS["alerts.deliver"].spec, failing_handler)
run()
row = one_row()
must(row.status == "pending" and row.attempt == 1 and row.next_attempt_at > NOW[0], (row.status, row.attempt, row.next_attempt_at))
print("       a failed attempt still carries its own back-off countdown")
print("[TEST] PASS event jobs deferred retry 1.17.47")
