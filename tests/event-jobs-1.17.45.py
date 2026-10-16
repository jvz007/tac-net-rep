#!/usr/bin/env python3
"""1.17.45 core.event_jobs 1.0.0: the real event_jobs.py, event_jobs_policy.py and scheduler.py against stubs.

Stubbed: Django (a small in-memory ORM that enforces the partial unique constraint, transactions and on_commit), the registry and module
state, the audit writer, Celery (a fake task that records the broker options and message) and the scheduler models. Django, Celery,
PostgreSQL and the real worker are tests/event-jobs-runtime-1.17.45.py (a dev-server script).

Covered: registration (another module's handler file, another module's id, a partial, a disabled or legacy module, every limit, identical
re-register returns the same handle, a different definition is refused, a handle cannot be built, copied or pickled); a foreign handle
cannot publish; publish never raises when the registry, cache, database or broker fails; a duplicate key collapses (in process, at the
unique constraint, and inside the dedupe window); the backlog gauge and the rate cap drop without a query; the commit-time path; a row
is claimed exactly once; retry with back-off then give up with one audit row; a permanent error gives up at once; a disabled module or an
unregistered handler skips with no handler call; expiry; stale running recovery; a lost broker message is enqueued by the tick; the
context has no user fields and verify_event_job_context accepts only Core-issued contexts for the right module and job; audit rows carry
no payload; the tick's trim, prune and drop reporting; the scheduler_health block; the read route; the tick hook failing leaves
schedules running.
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


def load_state():
    if STATE_FAIL[0]:
        raise OSError("state unreadable")
    return {"schema": 1, "modules": {}}


def is_enabled(module_id, state=None):
    if STATE_FAIL[0]:
        raise OSError("state unreadable")
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
    BROKER_DOWN[0] = REGISTRY_FAIL[0] = STATE_FAIL[0] = False
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


# ------------------------------------------------------------------------------------------------ (1) registration
reset()
handle = register()
must(type(handle).__name__ == "EventJobPublisher" and handle.job_id == "alerts.deliver" and handle.module_id == "alerts", handle)
must(register() is handle, "registering the identical definition returns the same handle")
must(CALLS == [] and not jobs() and not SENT, "registration touches memory only: no row, no message, no handler call")
must("different definition" in refused(label="Another label"), "a different definition under the same id is refused")
must("different definition" in refused(handler_fn=failing_handler), "a different handler under the same id is refused")
must("different definition" in refused(max_attempts=5), "different limits are refused")
must(register() is handle, "the first registration still stands")
print("       registration: returned a handle; identical returns the same handle; a different definition is refused; memory only")

reset()
must("another module" in refused(id="other.deliver"), "an id of another module is refused (module_id alerts)")
must("module's own folder" in refused(id="other.deliver", module_id="other"), "another module's id with this handler file is refused")
must("module's own folder" in refused(module_id="alerts", id="alerts.x", handler_fn=types.FunctionType((lambda: 0).__code__.replace(co_filename=str(OTHER_ROOT / "x.py")), {})), "code in another folder")
must("not an installed extension" in refused(id="ghost.deliver", module_id="ghost"), "an unknown module")
PLUGINS["legacy"] = plugin("legacy", HERE, legacy=True)
must("not an installed extension" in refused(id="legacy.deliver", module_id="legacy"), "a legacy module")
PLUGINS["theme"] = plugin("theme", HERE, kind="theme")
must("not an installed extension" in refused(id="theme.deliver", module_id="theme"), "a module that is not an extension")
ENABLED["alerts"] = False
must("not enabled" in refused(), "a disabled module")
ENABLED["alerts"] = True
must("generated code" in refused(handler_fn=partial(handler, 1)), "a functools.partial has no code of its own")
must("generated code" in refused(handler_fn=print), "a built-in function")
must("generated code" in refused(handler_fn=eval("lambda c: None")), "generated code (a file name in angle brackets)")
must("callable" in refused(handler_fn="not callable"), "a handler that is not callable")
for name, value in (("soft_time_limit_seconds", 4), ("soft_time_limit_seconds", 601), ("max_attempts", 0), ("max_attempts", 11), ("backoff_seconds", 4),
                    ("backoff_seconds", 3601), ("expires_seconds", 59), ("expires_seconds", 86401), ("max_backlog", 0), ("max_backlog", 5001),
                    ("dedupe_seconds", -1), ("dedupe_seconds", 3601), ("max_backoff_seconds", 3601), ("audit_success", "yes")):
    refused(**{name: value})
must(not ej._JOBS, "a refused registration leaves nothing registered")
REGISTRY_FAIL[0] = True
must("could not read the installed modules" in refused(), "a registry fault is a plain refusal, never another exception")
REGISTRY_FAIL[0] = False
STATE_FAIL[0] = True
must("could not read" in refused(), "a module-state fault is a plain refusal")
STATE_FAIL[0] = False
must(isinstance(register(), ej.EventJobPublisher), "and registration works again")
class Holder:
    def method(self, context):
        return None
must(register(id="alerts.method", handler_fn=Holder().method).job_id == "alerts.method", "a bound method defined in the module is accepted")
print("       registration: refused for another module's id, folder, a partial, a built-in, generated code, a disabled or legacy module, each limit and a registry fault")

reset()
handle = register(soft_time_limit_seconds=600, max_attempts=10, backoff_seconds=3600, max_backoff_seconds=3600, expires_seconds=86400, max_backlog=5000, dedupe_seconds=3600, audit_success=True)
row = ej.registered_event_jobs()[0]
must(row["hard_time_limit_seconds"] == 615 and row["max_attempts"] == 10 and row["audit_success"] is True and "handler" not in row, row)
for attempt in (lambda: ej.EventJobPublisher(object(), "alerts.deliver", "alerts"), lambda: ej.EventJobPublisher(None, "x.y", "x")):
    try:
        attempt()
    except TypeError:
        pass
    else:
        raise AssertionError("a handle was built by hand")
for attempt in (lambda: copy.copy(handle), lambda: copy.deepcopy(handle), lambda: pickle.dumps(handle)):
    try:
        attempt()
    except TypeError:
        pass
    else:
        raise AssertionError("a handle was copied or pickled")
try:
    handle._job_id = "other.deliver"
except AttributeError:
    pass
else:
    raise AssertionError("a handle was changed")
must("alerts.deliver" in repr(handle), "repr names the job only")
print("       the handle cannot be built, copied, pickled or changed; the registered row shows no handler")

# ------------------------------------------------------------------------------------------------ (2) a foreign handle cannot publish
reset()
real = register()
forged = ej.EventJobPublisher.__new__(ej.EventJobPublisher)  # skips __init__: no id, no token
must(forged.publish("k1").outcome == "error", "a handle made without Core's token cannot publish")
must(forged.status() == {}, "and has no status")
object_with_publish = SimpleNamespace(publish=ej.EventJobPublisher.publish)
must(ej.EventJobPublisher.publish(object_with_publish, "k1").outcome == "error", "publish called on a stand-in object")
must(not jobs() and not SENT, "nothing was stored or sent")
ej._clear_for_tests()
register()
must(real.publish("k1").outcome == "error", "a handle from before a re-registration is not the registered one")
must(not jobs(), "no row")
print("       a forged, stand-in or stale handle cannot publish and has no status")

# ------------------------------------------------------------------------------------------------ (3) publish: the happy path and the hot path
reset()
handle = register()
result = handle.publish("alert:1:resolved", {"alert_id": 1, "state": "resolved"})
must(result.outcome == "queued" and isinstance(result, ej.PublishResult), result)
row = one_row()
must(row.status == "pending" and row.key == "alert:1:resolved" and row.payload == {"alert_id": 1, "state": "resolved"}, row.__dict__)
must(row.module_id == "alerts" and row.job_id == "alerts.deliver" and row.max_attempts == 3 and row.attempt == 0, row.__dict__)
must(row.expires_at == NOW[0] + timedelta(seconds=1800) and row.next_attempt_at == NOW[0] and row.last_enqueued_at == NOW[0], "expiry and stamps")
must(row.policy == {"soft": 30, "hard": 45, "backoff": 60, "max_backoff": 3600, "audit_success": False, "dedupe": 0}, row.policy)
must(len(SENT) == 1 and SENT[0]["args"] == [str(row.pk)], SENT)
options = SENT[0]["options"]
must(options["retry"] is False and options["ignore_result"] is True and options["soft_time_limit"] == 30 and options["time_limit"] == 45, options)
must(1790 <= options["expires"] <= 1800 and options["countdown"] == 0, options)
must(BROKER[0]["connect_timeout"] == 2 and BROKER[0]["transport_options"] == {"socket_timeout": 2, "socket_connect_timeout": 2}, BROKER)
must(SENT[0]["connection"].name == "broker", "the message goes over the bounded connection")
must(not CALLS, "the handler does not run in the publish")
must(SENTINEL not in repr(AUDITS), "no audit row for a publish")
print("       publish: one row, one message with the 2 second broker timeout, per-job time limits and expiry; the handler does not run")

# invalid input and a disabled module never raise
for key, payload in (("bad key", None), ("", None), ("x" * 129, None), (5, None), ("k", [1]), ("k", {"a": object()}), ("k", {"k": "x" * 3000})):
    r = handle.publish(key, payload)
    must(r.outcome == "error" and SENTINEL not in r.reason, (key, r))
must(len(jobs()) == 1 and len(SENT) == 1, "an invalid publish stores and sends nothing")
ENABLED["alerts"] = False
ej._ENABLED.clear()
must(handle.publish("k-disabled").outcome == "disabled" and len(jobs()) == 1, "a disabled module: disabled, nothing stored")
STATE_FAIL[0] = True
ej._ENABLED.clear()
must(handle.publish("k-fault").outcome == "disabled", "a module-state fault fails closed and does not raise")
STATE_FAIL[0] = False
ENABLED["alerts"] = True
advance(6)
must(handle.publish("k-enabled").outcome == "queued", "the five second cache ended and the module is enabled again")
print("       publish: invalid key or payload is an error result, a disabled module or a state fault is 'disabled', none raise")

# the five second enabled cache
reset()
handle = register()
reads = []
orig_enabled = ej._enabled_now
ej._enabled_now = lambda module_id: reads.append(module_id) or True
for i in range(5):
    handle.publish(f"c{i}")
must(len(reads) == 1, f"the module state is read once in five seconds, not per publish ({len(reads)})")
advance(5.1)
handle.publish("c-later")
must(len(reads) == 2, "and again after the cache ended")
ej._enabled_now = orig_enabled
print("       the module-enabled state is cached for five seconds")

# ------------------------------------------------------------------------------------------------ (4) publish never raises
reset()
handle = register()
orig = (ej._plugins, ej._module_enabled_cached, Job.objects.create)
Job.objects.create = lambda **kw: (_ for _ in ()).throw(RuntimeError("db down"))
r = handle.publish("db-fault")
must(r.outcome == "error" and not jobs() and not SENT, "a database fault gives an error result, no message")
Job.objects.create = orig[2]
ej._module_enabled_cached = lambda module_id: (_ for _ in ()).throw(RuntimeError("cache fault"))
must(handle.publish("cache-fault").outcome == "error", "a cache fault gives an error result")
ej._module_enabled_cached = orig[1]
ej._RECENT.seen = lambda name: (_ for _ in ()).throw(RuntimeError("memory fault"))
must(handle.publish("memory-fault").outcome == "error", "a fault in the in-process memory gives an error result")
del ej._RECENT.seen
BROKER_DOWN[0] = True
r = handle.publish("broker-fault")
must(r.outcome == "queued" and len(jobs()) == 1 and not SENT, "a broker fault: the row is stored, the answer is queued, no message")
row = one_row()
must(row.status == "pending" and row.last_enqueued_at is None, "the row waits for the tick (the enqueue stamp is cleared)")
BROKER_DOWN[0] = False
r = handle.publish("breaker-open")
must(r.outcome == "queued" and len(BROKER) == 1 and not SENT, "the circuit breaker skips the broker for 30 seconds: no new connection")
must(len(jobs()) == 2 and all(j.last_enqueued_at is None for j in jobs()), "both rows wait for the tick")
advance(31)
handle.publish("breaker-closed")
must(len(SENT) == 1 and SENT[0]["args"] == [str(jobs()[2].pk)], "after 30 seconds the broker is tried again")
print("       publish never raises: database, cache, memory and broker faults give a result; a broker fault keeps the row and opens a 30 second breaker")

# ------------------------------------------------------------------------------------------------ (5) duplicates
reset()
handle = register()
must(handle.publish("dup").outcome == "queued", "first")
must(handle.publish("dup").outcome == "duplicate" and len(jobs()) == 1, "the same key inside three seconds is answered from memory")
queries = Manager.QUERIES[0]
must(handle.publish("dup").outcome == "duplicate" and Manager.QUERIES[0] == queries, "with no database query")
advance(4)
r = handle.publish("dup")
must(r.outcome == "duplicate" and len(jobs()) == 1 and len(SENT) == 1, "after three seconds the unique constraint still collapses it while the first is pending")
must(stat() is None or stat().duplicate == 0, "the counters are flushed later, not per publish")
ej.flush_counters(force=True)
must(stat().duplicate == 3 and stat().published == 1, (stat().duplicate, stat().published))
run()
must(one_row().status == "succeeded", "ran")
advance(4)
must(handle.publish("dup").outcome == "queued" and len(jobs()) == 2, "once the first finished, the same key is a new job (dedupe_seconds is 0)")
print("       duplicate key: collapsed in memory, then by the partial unique constraint; allowed again after the first finished")

reset()
handle = register(dedupe_seconds=60)
handle.publish("w")
run()
advance(4)
must(handle.publish("w").outcome == "duplicate" and len(jobs()) == 1, "a succeeded run with that key inside the window is a duplicate")
advance(70)
must(handle.publish("w").outcome == "queued" and len(jobs()) == 2, "outside the window it is queued")
reset()
handle = register(dedupe_seconds=60)
handle.publish("f")
CALLS.clear()
ej._JOBS["alerts.deliver"] = ej.EventJobDefinition(ej._JOBS["alerts.deliver"].spec, failing_handler)
for _ in range(3):
    run()
    advance(400)
    jobs()[0].next_attempt_at = NOW[0]
must(one_row().status == "failed", one_row().status)
must(handle.publish("f").outcome == "queued", "a failed run does not start the dedupe window")
print("       dedupe_seconds: a succeeded run inside the window is a duplicate; outside it, or after a failure, it is queued")

# ------------------------------------------------------------------------------------------------ (6) backlog gauge and rate cap
reset()
handle = register(max_backlog=2)
must(handle.publish("b1").outcome == "queued" and handle.publish("b2").outcome == "queued", "two fit")
creates = Manager.QUERIES[0]
r = handle.publish("b3")
must(r.outcome == "dropped" and r.reason == "backlog" and len(jobs()) == 2 and Manager.QUERIES[0] == creates, "at the backlog: dropped with no database query")
for i in range(4, 8):
    must(handle.publish(f"b{i}").outcome == "dropped", "still dropped")
must(Manager.QUERIES[0] == creates and len(jobs()) == 2, "no query for any drop")
ej.flush_counters(force=True)
must(stat().dropped == 5 and stat().dropped_day == 5 and stat().published == 2, (stat().dropped, stat().published))
run(jobs()[0])
advance(31)
ej._tick_gauges(NOW[0], {})
must(handle.publish("b-after").outcome == "queued" and len(jobs()) == 3, "after a job ran and the gauge was refreshed, publishing works again")
ej._GAUGES.clear()
reset()
handle = register(max_backlog=1)
must(handle.publish("g1").outcome == "queued", "absent gauge is open")
ej._GAUGES.clear()
must(handle.publish("g2").outcome == "queued" and len(jobs()) == 2, "a gauge older than 120 seconds counts as absent (the gate is open; the tick trims)")
print("       backlog gauge: a job at its backlog drops without a query; an absent or old gauge is open")

reset()
handle = register()
ej._RATE.limit = 3
for i in range(3):
    must(handle.publish(f"r{i}").outcome == "queued", i)
before = Manager.QUERIES[0]
r = handle.publish("r3")
must(r.outcome == "dropped" and r.reason == "rate" and Manager.QUERIES[0] == before, "the per-process rate cap drops with no query")
advance(60)
must(handle.publish("r4").outcome == "queued", "a new minute")
ej._RATE.limit = policy.RATE_PER_MINUTE
print("       rate cap: drops over the per-minute cap with no query")

# a publish inside a transaction stores the row at commit
reset()
handle = register()
CONNECTION.in_atomic_block = True
r = handle.publish("tx-1", {"a": 1})
must(r.outcome == "queued" and not jobs() and not SENT and len(COMMIT_HOOKS) == 1, "inside a transaction nothing is stored before the commit")
commit()
must(len(jobs()) == 1 and len(SENT) == 1, "at the commit the row is stored and the message sent")
CONNECTION.in_atomic_block = True
handle.publish("tx-2")
COMMIT_HOOKS.clear()  # the transaction rolled back: on_commit hooks never run
CONNECTION.in_atomic_block = False
must(len(jobs()) == 1, "a rolled-back transaction publishes nothing")
CONNECTION.in_atomic_block = True
Manager.QUERIES[0] = 0
handle.publish("tx-3")
handle.publish("tx-3")
must(Manager.QUERIES[0] == 0, "the publish itself makes no query inside a transaction")
CONNECTION.in_atomic_block = False
print("       inside a transaction the row is stored at commit; a rollback publishes nothing; no query inside the caller's transaction")

# counters are never flushed inside the caller's transaction
reset()
handle = register(max_backlog=1)
handle.publish("one")
ej._GAUGES.set("alerts.deliver", 1)
CONNECTION.in_atomic_block = True
ej._LAST_FLUSH[0] = 0.0
handle.publish("two")
must(stat() is None or stat().dropped == 0, "a drop inside a transaction does not touch the stat row (it would hold its lock until the commit)")
CONNECTION.in_atomic_block = False
ej.flush_counters(force=True)
must(stat().dropped == 1, "the drop is written once the caller's transaction is over")
print("       the stat row is not written inside a caller's transaction")

# ------------------------------------------------------------------------------------------------ (7) the worker: claim exactly once
reset()
handle = register()
handle.publish("claim", {"alert_id": 9, "who": SENTINEL})
row = one_row()
must(run() == "job succeeded" and CALLS and len(CALLS) == 1, "ran once")
must(row.status == "succeeded" and row.attempt == 1 and row.result == {"ok": True} and row.finished_at == NOW[0] and row.celery_task_id == "task-1", row.__dict__)
must(run() == "job already succeeded" and len(CALLS) == 1, "a duplicate delivery runs nothing")
must(ej.run_event_job(uuid.uuid4(), now=NOW[0]) == "job missing", "a missing row")
handle.publish("claim-2")
second = jobs()[1]
second.status = "running"
must(ej.run_event_job(second.pk, now=NOW[0]) == "job already running" and len(CALLS) == 1, "a redelivery while another worker runs it runs nothing")
second.status, second.next_attempt_at = "pending", NOW[0] + timedelta(seconds=300)
must(ej.run_event_job(second.pk, now=NOW[0]) == "job not due" and second.status == "pending" and len(CALLS) == 1, "a message that arrives early waits for its time")
must(stat().succeeded == 1, stat().succeeded)
print("       worker: claims exactly once; a duplicate, an early or a concurrent delivery runs nothing")

# the context
context = CALLS[0]
must(type(context).__name__ == "EventJobContext" and isinstance(context, dict), type(context))
must(set(context) == {"job_id", "module_id", "key", "payload", "attempt", "max_attempts", "final_attempt", "enqueued_at", "run_id"}, sorted(context))
must(context["payload"] == {"alert_id": 9, "who": SENTINEL} and context["payload"] is not row.payload, "the payload is a copy")
must(context["attempt"] == 1 and context["max_attempts"] == 3 and context["final_attempt"] is False and context["run_id"] == str(row.pk), dict(context))
for name in ("user", "owner_user_id", "owner_username", "owner_type", "owner_module", "user_id", "username", "request"):
    must(name not in context, f"no user field {name}")
context["payload"]["who"] = "changed"
must(row.payload["who"] == SENTINEL, "changing the context's payload does not change the stored row")
print("       the context has the documented keys, a payload copy, and no user fields")

# verify_event_job_context
reset()
seen = []


def verifying_handler(context):
    seen.append(context)
    v = ej.verify_event_job_context(context, expected_module_id="alerts", expected_job_id="alerts.deliver")
    seen.append(v)
    for bad in (dict(context), copy.copy(context), {**context}, "text", None, 5):
        try:
            ej.verify_event_job_context(bad, expected_module_id="alerts", expected_job_id="alerts.deliver")
        except ej.EventJobContextInvalid:
            pass
        else:
            raise AssertionError("a context Core did not issue was accepted")
    for module_id, job_id in (("other", "alerts.deliver"), ("alerts", "alerts.other"), ("", "alerts.deliver"), ("alerts", ""), (None, None), (5, 5), ("alerts", None)):
        try:
            ej.verify_event_job_context(context, expected_module_id=module_id, expected_job_id=job_id)
        except ej.EventJobContextInvalid as exc:
            must("alerts" not in str(exc) or "another" in str(exc) or "required" in str(exc), str(exc))
        else:
            raise AssertionError("a wrong expected id was accepted")
    return None


handle = register(verifying_handler)
handle.publish("verify")
status = run()
must(len(seen) == 2, (status, one_row().__dict__, len(seen)))
v = seen[1]
must(isinstance(v, ej.VerifiedEventJob) and v.module_id == "alerts" and v.job_id == "alerts.deliver" and v.key == "verify" and v.attempt == 1 and v.final_attempt is False, v)
must(one_row().status == "succeeded", "the handler's checks all passed")
try:
    ej.verify_event_job_context(seen[0], expected_module_id="alerts", expected_job_id="alerts.deliver")
except ej.EventJobContextInvalid:
    pass
else:
    raise AssertionError("a context of a finished job verified")
must(ej.is_core_issued_event_job_context(seen[0]) and not ej.is_core_issued_event_job_context(dict(seen[0])), "is_core_issued")
print("       verify_event_job_context: accepts only Core's own context for the right module and job while it runs")

# ------------------------------------------------------------------------------------------------ (8) retry, then give up
reset()
handle = register(failing_handler, max_attempts=3, backoff_seconds=60)
handle.publish("retry-me", {"alert_id": 4})
row = one_row()
del SENT[:]
must(run() == "job will retry", "first failure")
must(row.status == "pending" and row.attempt == 1 and row.next_attempt_at == NOW[0] + timedelta(seconds=60) and row.finished_at is None, row.__dict__)
must(row.error_type == "RuntimeError" and row.error.startswith("RuntimeError: upstream refused retry-me"), row.error)
must(len(SENT) == 1 and SENT[0]["options"]["countdown"] == 60 and SENT[0]["args"] == [str(row.pk)], "Core enqueued the retry with its back-off as the countdown")
must(not AUDITS, "a retry writes no audit row")
must(stat().last_failure_at == NOW[0] and stat().failed == 0, "recorded in the counters, not as a failure yet")
must(run() == "job not due" and len(CALLS) == 1, "an early message waits")
advance(60)
must(run() == "job will retry" and row.attempt == 2 and row.next_attempt_at == NOW[0] + timedelta(seconds=120), "the back-off doubles")
must(SENT[-1]["options"]["countdown"] == 120 and not AUDITS, "second retry")
advance(120)
must(run() == "job failed", "the last attempt gives up")
must(row.status == "failed" and row.attempt == 3 and row.finished_at == NOW[0], row.__dict__)
must(len(AUDITS) == 1, f"one audit row for the give-up ({len(AUDITS)})")
a = AUDITS[0]
must(a["action"] == "custom:event-job-failed" and a["module_id"] == "core" and a["object_type"] == "event_job" and a["object_id"] == "alerts.deliver", a)
must(a["actor"] == {"service": {"module_id": "core", "service": "event-jobs", "identity": "alerts.deliver"}}, a["actor"])
must(a["metadata"]["owner_module"] == "alerts" and a["metadata"]["job_id"] == "alerts.deliver" and a["metadata"]["key"] == "retry-me", a["metadata"])
must(a["metadata"]["attempt"] == 3 and a["metadata"]["error_type"] == "RuntimeError" and a["metadata"]["requested_by"] == "event-job", a["metadata"])
must(len(a["metadata"]["error"]) <= 200 and "\n" not in a["metadata"]["error"], a["metadata"]["error"])
must("payload" not in a["metadata"] and "alert_id" not in repr(a), "no payload in the audit row")
must(stat().failed == 1 and stat().last_error.startswith("RuntimeError"), stat().__dict__)
must(run() == "job already failed" and len(CALLS) == 3, "no fourth attempt (a poison job is bounded by max_attempts)")
print("       retry: Core's back-off doubles, no audit row per retry; after the last attempt the row ends failed with one audit row")

# jitter
reset()
ej._rand = lambda: 1.0
handle = register(failing_handler, backoff_seconds=100)
handle.publish("jitter")
run()
must(one_row().next_attempt_at == NOW[0] + timedelta(seconds=120), "up to 20 percent jitter")
ej._rand = lambda: 0.0

# permanent error gives up at once
for label, exc in (("ValueError", ValueError("bad")), ("TypeError", TypeError("bad")), ("SchedulerPermanentError", type("SchedulerPermanentError", (RuntimeError,), {})("bad"))):
    reset()

    def permanent(context, exc=exc):
        CALLS.append(context)
        raise exc

    handle = register(permanent, max_attempts=5)
    handle.publish("perm")
    must(run() == "job failed" and one_row().status == "failed" and one_row().attempt == 1 and len(CALLS) == 1, label)
    must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-failed", label)
print("       a permanent error (ValueError, TypeError, SchedulerPermanentError) gives up at once with one audit row")

# a soft time limit retries; an exception that is not an Exception subclass leaves the row running for the tick
reset()


class SoftTimeLimitExceeded(Exception):
    pass


def slow(context):
    raise SoftTimeLimitExceeded()


handle = register(slow)
handle.publish("slow")
must(run() == "job will retry" and one_row().status == "pending", "a soft time limit is retried")
reset()


def killed(context):
    raise KeyboardInterrupt()


handle = register(killed)
handle.publish("killed")
try:
    run()
except KeyboardInterrupt:
    pass
must(one_row().status == "running" and not AUDITS, "a kill leaves the row running for the tick to recover")
print("       a soft time limit retries; a worker kill leaves the row running for the tick")

# audit_success
reset()
handle = register(audit_success=True)
handle.publish("loud", {"alert_id": 1})
run()
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "run" and "alert_id" not in repr(AUDITS), AUDITS)
reset()
handle = register()
handle.publish("quiet")
run()
must(not AUDITS, "a success writes a row only when the job registered audit_success")
print("       audit_success: a row per success only when asked for")

# ------------------------------------------------------------------------------------------------ (9) the worker's own checks
reset()
handle = register()
handle.publish("gate")
ENABLED["alerts"] = False
must(run() == "job skipped" and not CALLS, "a disabled module: skipped and the handler is never called")
must(one_row().status == "skipped" and one_row().error_type == "ModuleUnavailable", one_row().__dict__)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-skipped" and "gate" == AUDITS[0]["metadata"]["key"], AUDITS)
must(stat().skipped == 1, "counted")
reset()
handle = register()
handle.publish("gate2")
del PLUGINS["alerts"]
must(run() == "job skipped" and not CALLS and one_row().error_type == "ModuleUnavailable", "an uninstalled module is skipped too")
reset()
handle = register()
handle.publish("gate3")
STATE_FAIL[0] = True
must(run() == "job deferred" and not CALLS and one_row().status == "pending", "an unreadable module state runs no handler and keeps the row (1.17.46)")
reset()
handle = register()
handle.publish("gate4")
ENABLED["alerts"] = False
ej._ENABLED.set("alerts", True)  # a stale cached 'enabled': the worker never trusts the publish-time check
must(run() == "job skipped" and not CALLS, "the worker re-checks uncached")
reset()
handle = register()
handle.publish("nohandler")
ej._JOBS.clear()
ej._HANDLES.clear()
must(run() == "job skipped" and one_row().error_type == "HandlerNotRegistered" and not CALLS, "a handler that is not registered in this process: skipped")
must(AUDITS and AUDITS[0]["action"] == "custom:event-job-skipped", AUDITS)
print("       worker: a disabled, uninstalled or unreadable module, or an unregistered handler, skips with an audit row and no handler call")

reset()
handle = register(expires_seconds=60)
handle.publish("late")
advance(61)
must(run() == "job expired" and not CALLS and one_row().status == "expired" and one_row().error_type == "Expired", one_row().__dict__)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-expired" and stat().expired == 1, AUDITS)
print("       worker: a job not started before its expiry ends expired, with an audit row, and the handler is never called")

reset()
handle = register(failing_handler, expires_seconds=60, backoff_seconds=30, max_attempts=5)
handle.publish("expiring")
run()
advance(65)
one_row().status = "running"
must(ej._finish_failure(one_row().pk, RuntimeError("late"), now=NOW[0]) == "job failed", "a job that expired while running is not retried")
print("       a failed attempt past the expiry is not retried")

# ------------------------------------------------------------------------------------------------ (10) the tick
reset()
handle = register()
handle.publish("stale")
row = one_row()
row.status, row.started_at, row.attempt = "running", NOW[0] - timedelta(seconds=45 + 301), 1
out = ej.recover_event_jobs(NOW[0])
must(out["stale_recovered"] == 1 and row.status == "pending" and row.error_type == "EventJobLost", (out, row.__dict__))
must(SENT and SENT[-1]["options"]["countdown"] == 60, "the lost attempt is retried with the back-off")
row.status, row.started_at, row.attempt = "running", NOW[0] - timedelta(seconds=45 + 100), 1
must(ej.recover_event_jobs(NOW[0])["stale_recovered"] == 0 and row.status == "running", "a running row inside the hard limit plus five minutes is left alone")
row.started_at, row.attempt = NOW[0] - timedelta(seconds=3600), 3
out = ej.recover_event_jobs(NOW[0])
must(out["stale_recovered"] == 1 and row.status == "failed", "a lost last attempt gives up")
must(AUDITS and AUDITS[-1]["action"] == "custom:event-job-failed", AUDITS)
print("       tick: a running row older than the hard limit plus five minutes is a failed attempt (retry or give up)")

# a lost broker message is enqueued by the tick
reset()
handle = register()
BROKER_DOWN[0] = True
handle.publish("lost-1")
BROKER_DOWN[0] = False
advance(31)
del SENT[:]
out = ej.recover_event_jobs(NOW[0])
must(out["enqueued"] == 1 and len(SENT) == 1 and one_row().last_enqueued_at == NOW[0], (out, SENT))
advance(10)
del SENT[:]
must(ej.recover_event_jobs(NOW[0])["enqueued"] == 0 and not SENT, "a row enqueued a moment ago is not enqueued again")
advance(61)
must(ej.recover_event_jobs(NOW[0])["enqueued"] == 1, "a pending row whose message was lost, 60 seconds past due, is enqueued again")
row = one_row()
row.next_attempt_at, row.last_enqueued_at = NOW[0] + timedelta(seconds=600), NOW[0] - timedelta(seconds=300)
del SENT[:]
must(ej.recover_event_jobs(NOW[0])["enqueued"] == 0, "a retry waiting for its countdown is left alone")
BROKER_DOWN[0] = True
row.next_attempt_at, row.last_enqueued_at = None, None
out = ej.recover_event_jobs(NOW[0])
must(out["enqueued"] == 0 and len(BROKER) < 50, "a broker outage: no loop and no crash")
print("       tick: a never-enqueued or overdue pending row is enqueued; a fresh or waiting one is not; a broker outage is survived")

# tick bounds, expiry, module gate, trim, drops, prune
reset()
handle = register(expires_seconds=60, max_backlog=5)
other_handle = None
for i in range(5):
    handle.publish(f"e{i}")
advance(120)
out = ej.recover_event_jobs(NOW[0])
must(out["expired"] == 5 and all(j.status == "expired" for j in jobs()), out)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-expired" and AUDITS[0]["metadata"]["count"] == 5, "one audit row per job with the count")
must(stat().expired == 5, "counted")
reset()
handle = register()
for i in range(3):
    handle.publish(f"m{i}")
ENABLED["alerts"] = False
out = ej.recover_event_jobs(NOW[0])
must(out["module_unavailable"] == 3 and all(j.status == "expired" and j.error_type == "ModuleUnavailable" for j in jobs()), out)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-skipped" and AUDITS[0]["metadata"]["count"] == 3, AUDITS)
print("       tick: expires pending rows past their expiry and the rows of a disabled module, one audit row per job")

reset()
handle = register(max_backlog=3)
for i in range(8):
    ej._GAUGES.clear()  # no gauge: the gate is open, so a burst across processes can overshoot the backlog
    must(handle.publish(f"t{i}").outcome == "queued", i)
must(len(jobs()) == 8, len(jobs()))
out = ej.recover_event_jobs(NOW[0])
pending = [j for j in jobs() if j.status == "pending"]
trimmed = [j for j in jobs() if j.status == "expired"]
must(len(pending) == 3 and out["trimmed"] == 5 and len(trimmed) == 5, (len(pending), out))
must(all(j.error_type == "Dropped" for j in trimmed), "trimmed rows say so")
must(min(j.created_at for j in pending) > max(j.created_at for j in trimmed), "oldest first")
must(stat().dropped == 5 and stat().dropped_day == 5 and stat().expired == 0, "counted as dropped, not as expired")
reset()
handle = register(max_backlog=2)
for i in range(6):
    jobs_before = len(jobs())
    Job.objects.create(module_id="alerts", job_id="alerts.deliver", key=f"direct{i}", payload={}, policy={}, status="pending", max_attempts=3,
                       next_attempt_at=NOW[0], expires_at=NOW[0] + timedelta(seconds=1800), last_enqueued_at=NOW[0])
out = ej.recover_event_jobs(NOW[0])
must(out["trimmed"] == 4 and len([j for j in jobs() if j.status == "pending"]) == 2, out)
must([j.key for j in jobs() if j.status == "pending"] == ["direct4", "direct5"], "the newest two stay")
must(stat().dropped == 4 and stat().dropped_day == 4 and stat().dropped_reported == 4, stat().__dict__)
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:event-job-dropped" and AUDITS[0]["metadata"]["count"] == 4 and AUDITS[0]["metadata"]["job_id"] == "alerts.deliver", AUDITS)
ej.recover_event_jobs(NOW[0])
must(len(AUDITS) == 1, "a drop is reported once")
print("       tick: trims a backlog over its limit (oldest first), counts the drops and writes one audit row per job")

# the hot-path drop counters reach the audit row through the tick
reset()
handle = register(max_backlog=1)
handle.publish("h1")
for i in range(3):
    handle.publish(f"h-drop{i}")
out = ej.recover_event_jobs(NOW[0])
must(stat().dropped == 3 and out["dropped_reported"] == 1, (stat().__dict__, out))
must(AUDITS[-1]["action"] == "custom:event-job-dropped" and AUDITS[-1]["metadata"]["count"] == 3, AUDITS)
print("       tick: publishes dropped at the gate are flushed into the stat row and audited once")

# prune
reset()
handle = register()
for i in range(3):
    Job.objects.create(module_id="alerts", job_id="alerts.deliver", key=f"p{i}", status="succeeded", finished_at=NOW[0] - timedelta(days=100 + i), expires_at=NOW[0])
Job.objects.create(module_id="alerts", job_id="alerts.deliver", key="young", status="succeeded", finished_at=NOW[0] - timedelta(days=1), expires_at=NOW[0])
Job.objects.create(module_id="alerts", job_id="alerts.deliver", key="live", status="pending", expires_at=NOW[0] + timedelta(days=1), next_attempt_at=NOW[0], last_enqueued_at=NOW[0])
out = ej.recover_event_jobs(NOW[0])
must(out["pruned"] == 3 and sorted(j.key for j in jobs()) == ["live", "young"], (out, [j.key for j in jobs()]))
for i in range(20005):
    Job.objects.rows.append(Job(module_id="alerts", job_id="alerts.deliver", key=f"cap{i}", status="succeeded", finished_at=NOW[0] - timedelta(seconds=i), expires_at=NOW[0]))
before = len(jobs())
out = ej.recover_event_jobs(NOW[0])
must(out["pruned"] == 6 and len(jobs()) == before - 6, "over the 20000 row cap the oldest finished rows go")
print("       tick: prunes finished rows after the retention days and over the 20000 row cap, never a live row")

# a step that fails does not stop the others
reset()
handle = register()
handle.publish("steps")
advance(31)
BROKER_DOWN[0] = True
orig_step = ej._tick_expire
ej._tick_expire = lambda now, out: (_ for _ in ()).throw(RuntimeError("step fault"))
out = ej.recover_event_jobs(NOW[0])
must(out["errors"] == 1, out)
ej._tick_expire = orig_step
BROKER_DOWN[0] = False
print("       a fault in one tick step is counted and the other steps still run")

# ------------------------------------------------------------------------------------------------ (11) status, health and the route
reset()
handle = register()
handle.publish("s1", {"secret": SENTINEL})
handle.publish("s2")
run(jobs()[0])
st = handle.status()
must(st["pending"] == 1 and st["succeeded"] == 1 and st["module_id"] == "alerts" and st["job_id"] == "alerts.deliver" and st["registered"] is True, st)
must(st["oldest_pending_age_seconds"] == 0 and st["last_error"] == "" and st["last_failure_at"] is None, st)
must(SENTINEL not in repr(st) and "s1" not in repr(st) and "payload" not in st and "key" not in st, "no payload, no key")
register(id="alerts.other", handler_fn=failing_handler, max_attempts=1)
other = ej._HANDLES["alerts.other"]
other.publish("o1")
run([j for j in jobs() if j.job_id == "alerts.other"][0])
must(handle.status()["job_id"] == "alerts.deliver" and other.status()["failed"] == 1 and handle.status()["failed"] == 0, "status is the job's own")
listing = ej.list_event_jobs(NOW[0])
must([j["job_id"] for j in listing["jobs"]] == ["alerts.deliver", "alerts.other"], listing["jobs"])
must(listing["totals"]["failed"] == 1 and listing["totals"]["succeeded"] == 1 and listing["totals"]["pending"] == 1, listing["totals"])
must(SENTINEL not in repr(listing) and "payload" not in repr(listing).replace("payload_max", "") and "'key'" not in repr(listing), "the listing never carries a payload or key")
must(listing["limits"]["max_attempts"] == {"minimum": 1, "default": 3, "maximum": 10}, listing["limits"])
must(any("upstream refused" in j["last_error"] for j in listing["jobs"]), "the last error text is listed")
print("       status and listing: counts, ages and the last error of each job; never a payload or key")

health = ej.event_jobs_health(NOW[0])
must(set(health) == {"registered", "pending", "running", "failed_last_24h", "dropped_last_24h", "oldest_pending_age_seconds"}, health)
must(health["registered"] == 2 and health["pending"] == 1 and health["failed_last_24h"] == 1, health)
Job.objects.rows[0].status = "running"
Stat.objects.rows[0].dropped_day, Stat.objects.rows[0].dropped_day_started = 7, NOW[0] - timedelta(hours=2)
Stat.objects.rows[1].dropped_day, Stat.objects.rows[1].dropped_day_started = 9, NOW[0] - timedelta(hours=30)
health = ej.event_jobs_health(NOW[0])
must(health["running"] == 1 and health["dropped_last_24h"] == 7, health)
orig_filter = Job.objects.filter
Job.objects.filter = lambda **kw: (_ for _ in ()).throw(RuntimeError("db down"))
health = ej.event_jobs_health(NOW[0])
must(health["error"] == "RuntimeError" and health["pending"] == 0 and health["registered"] == 2, "a fault gives the zero block, never an exception")
Job.objects.filter = orig_filter
print("       the event_jobs health block: registered, pending, running, failed and dropped in 24 hours, oldest pending age")

# the read route: extract the view class from scheduler_views.py and run it with stubs
source = (APP / "scheduler_views.py").read_text(encoding="utf-8")
tree = ast.parse(source)
view_node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SchedulerEventJobsView")
MANAGERS = {"manager"}


class PermissionDenied(Exception):
    pass


ns = {"__name__": "tec_tac.scheduler_views", "__package__": "tec_tac", "APIView": object, "SessionAuthenticated": object, "PermissionDenied": PermissionDenied, "Response": lambda data: SimpleNamespace(data=data, status_code=200),
      "_native_scheduler_manager": lambda user: user in MANAGERS}
exec(compile(ast.Module([view_node], []), "scheduler_views_view", "exec"), ns)  # noqa: S102 - test-only: the real class source with stubs
View = ns["SchedulerEventJobsView"]
for who in ("tech", "viewer", None):
    try:
        View().get(SimpleNamespace(user=who))
    except PermissionDenied:
        pass
    else:
        raise AssertionError("a person without server-maintenance authority read the event jobs")
answer = View().get(SimpleNamespace(user="manager"))
must(answer.status_code == 200 and "jobs" in answer.data and "totals" in answer.data, answer.data.keys())
must(SENTINEL not in repr(answer.data) and "payload" not in repr(answer.data).replace("payload_max", ""), "the route never returns a payload")
print("       the read route denies a person without server-maintenance authority and returns counts only")

# ------------------------------------------------------------------------------------------------ (12) the real scheduler: health block and the tick hook
sched_models = {}


class SchedModel(Model):
    DoesNotExist = type("DoesNotExist", (Exception,), {})


class Schedule(SchedModel):
    OwnerType = Choices(USER="user", MODULE="module")
    ScheduleType = Choices(ONCE="once", DAILY="daily", WEEKLY="weekly", MONTHLY="monthly", INTERVAL="interval")
    TargetMode = Choices(SNAPSHOT="snapshot", DYNAMIC="dynamic")
    MissedPolicy = Choices(SKIP="skip", RUN_ON_RECOVERY="run_on_recovery", EXPIRE="expire")
    ConcurrencyPolicy = Choices(SKIP="skip", QUEUE="queue", ALLOW="allow")


class Run(SchedModel):
    Status = Choices(QUEUED="queued", RUNNING="running", SUCCEEDED="succeeded", FAILED="failed", SKIPPED="skipped")
    defaults = dict(status="queued", error_type="", schedule=None, schedule_snapshot_id=None, schedule_name="", error="")


class SchedState:
    last_tick_at = last_tick_completed_at = last_dispatch_at = None
    last_tick_error = last_dispatch_error = ""
    last_checked = last_queued = last_skipped = last_cleaned = 0

    @classmethod
    def current(cls):
        return STATE

    def save(self, update_fields=None):
        pass


STATE = SchedState()
Schedule.objects = Manager(Schedule)
Run.objects = Manager(Run)
mod("django.core")
mod("django.core.exceptions", ValidationError=type("ValidationError", (Exception,), {}))
mod("django.db.models", Q=lambda *a, **k: None)
sys.modules.update({k: v for k, v in mods.items() if k.startswith("django.core") or k == "django.db.models"})
sys.modules["django.db"].models = sys.modules["django.db.models"]
mod("tec_tac.models", TecTacEventJob=Job, TecTacEventJobStat=Stat, TecTacSchedulerConfig=Config, TecTacSchedule=Schedule, TecTacScheduleRun=Run,
    TecTacSchedulerState=SchedState)
sys.modules["tec_tac.models"] = mods["tec_tac.models"]
for helper in ("scheduler_targets", "scheduler_timing", "scheduler_run_context"):
    load(f"tec_tac.{helper}", f"{helper}.py")
sched = load("tec_tac.scheduler", "scheduler.py")
sched.cleanup_once_schedules = lambda now: 0
sched.cleanup_run_history = lambda now: 0
sched.recover_stale_runs = lambda now: {"queued": 0, "running": 0}

reset()
handle = register()
handle.publish("tick-1")
advance(31)
health = sched.scheduler_health(NOW[0])
block = health["event_jobs"]
must(set(block) == {"registered", "pending", "running", "failed_last_24h", "dropped_last_24h", "oldest_pending_age_seconds"}, block)
must(block["registered"] == 1 and block["pending"] == 1 and block["oldest_pending_age_seconds"] in (30, 31), block)
must({"tick_health", "queued_runs", "running_runs", "failed_last_24h", "authorization_revoked_last_24h"} <= set(health), "the existing keys are all still there")
orig_events = ej.event_jobs_health
ej.event_jobs_health = lambda now: (_ for _ in ()).throw(RuntimeError("health fault"))
health = sched.scheduler_health(NOW[0])
must(health["event_jobs"]["error"] == "unavailable" and "tick_health" in health, "a fault in the event job block never breaks scheduler health")
ej.event_jobs_health = orig_events
print("       scheduler_health carries the additive event_jobs block and survives a fault in it")

must(sys.modules["tec_tac.event_jobs"] is ej, "the scheduler uses the loaded module")
result = sched.dispatch_due_schedules(NOW[0])
must("event_jobs" in result and result["event_jobs"]["enqueued"] >= 0 and "errors" in result["event_jobs"], result)
must(result["checked"] == 0 and result["queued"] == [] and STATE.last_tick_error == "", "the tick ran")
orig_recover = ej.recover_event_jobs
ej.recover_event_jobs = lambda now: (_ for _ in ()).throw(RuntimeError("event job fault"))
result = sched.dispatch_due_schedules(NOW[0])
must(result["event_jobs"] == {"error": True} and result["checked"] == 0 and STATE.last_tick_error == "" and STATE.last_tick_completed_at is not None, result)
ej.recover_event_jobs = orig_recover
print("       the tick runs the event job step, and a fault there leaves the schedules running")

# the tick source: the hook sits after recover_stale_runs and before the schedules are read
tree = ast.parse((APP / "scheduler.py").read_text(encoding="utf-8"))
dispatch = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "dispatch_due_schedules")
calls = [n.func.id for n in ast.walk(dispatch) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
must(calls.index("recover_stale_runs") < calls.index("_recover_event_jobs_safely") < calls.index("cleanup_once_schedules"), calls)
print("       the hook runs after recover_stale_runs and before the schedules")

# ------------------------------------------------------------------------------------------------ (13) the capability
reset()
cap = ej.register_core_event_jobs_capability()
must(CAPS and CAPS[0]["id"] == "core.event_jobs" and CAPS[0]["module_id"] == "core" and CAPS[0]["version"] == "1.0.0", CAPS)
must(CAPS[0]["operations"] == ("register_event_job", "verify_event_job_context"), CAPS[0]["operations"])
meta = CAPS[0]["metadata"]
must(meta["limits"]["soft_time_limit_seconds"] == {"minimum": 5, "default": 30, "maximum": 600} and meta["payload_max_bytes"] == 2048, meta["limits"])
must(meta["handler_context_has_user"] is False and meta["tactical_write_from_handler"] is False and meta["delivery"] == "at least once", meta)
must(meta["requires_framework"] == ">=1.17.45" and meta["http"].startswith("GET /api/tfd/scheduler/event-jobs/"), meta)
must(CAPS[0]["provider"].register_event_job is ej.register_event_job and CAPS[0]["provider"].verify_event_job_context is ej.verify_event_job_context, "provider")
print("       the capability core.event_jobs 1.0.0 is registered with its limits")
print("[TEST] PASS event jobs 1.17.45")
