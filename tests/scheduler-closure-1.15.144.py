#!/usr/bin/env python3
from __future__ import annotations

import ast
import datetime as dt
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "framwork/tec_tac/scheduler_targets.py"
SCHED = ROOT / "framwork/tec_tac/scheduler.py"
VIEWS = ROOT / "framwork/tec_tac/scheduler_views.py"
TASKS = ROOT / "framwork/tec_tac/tasks.py"


def function_node(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} missing from {path}")


def method_node(path: Path, class_name: str, method_name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name)


def compile_functions(path: Path, names: tuple[str, ...], namespace: dict):
    nodes = [function_node(path, name) for name in names]
    mod = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(mod)
    exec(compile(mod, str(path), "exec"), namespace)
    return namespace


# M13: executable target normalization must reject equivalent explicit field
# selector spellings, including Django lookup suffixes and pk aliases, without
# rejecting ordinary module-owned paths such as ticket.client.
spec = importlib.util.spec_from_file_location("scheduler_targets_115144", TARGETS)
targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(targets)
blocked = (
    "site_id__in",
    "payload__clientIds__exact",
    "site.pk",
    "selector/site_id",
    "payload.clientIds",
    "endpoint__pk__isnull",
    "agent.id",
)
for token in blocked:
    try:
        targets.normalize_scheduler_targets({
            "type": "dynamic",
            "scope": {"type": "client", "ids": [1]},
            "filter": {"field": token, "value": 9},
        })
    except targets.SchedulerTargetShapeError:
        pass
    else:
        raise AssertionError(f"scope selector escaped filter guard: {token}")
for token in ("ticket.client", "ticket.pk", "Main Site", "windows_agent"):
    out = targets.normalize_scheduler_targets({
        "type": "dynamic",
        "scope": {"type": "client", "ids": [1]},
        "filter": {"field": token},
    })
    assert out["filter"]["field"] == token


# L18: managers can delete an orphaned schedule whose action is no longer
# registered; non-managers and ordinary calls still fail closed.
class SchedulerError(RuntimeError):
    pass
class NotFound(RuntimeError):
    pass
class PermissionDenied(RuntimeError):
    pass

def missing_action(_action_id):
    raise SchedulerError("action is unavailable")

ns = {
    "SchedulerError": SchedulerError,
    "NotFound": NotFound,
    "PermissionDenied": PermissionDenied,
    "get_scheduled_action": missing_action,
    "_native_scheduler_manager": lambda user: bool(getattr(user, "manager", False)),
    "_can_use_action": lambda user, action: False,
}
compile_functions(VIEWS, ("_require_action",), ns)
manager = SimpleNamespace(manager=True)
assert ns["_require_action"](manager, "gone.action", allow_unregistered_manager=True) is None
for user, allow in ((manager, False), (SimpleNamespace(manager=False), True)):
    try:
        ns["_require_action"](user, "gone.action", allow_unregistered_manager=allow)
    except NotFound:
        pass
    else:
        raise AssertionError("unregistered action delete authorization failed open")


# L19/L22: exercise the real revision-baseline and retry fallback helpers.
class FakeScheduleType:
    ONCE = "once"
class FakeTecTacSchedule:
    ScheduleType = FakeScheduleType

sched_ns = {
    "TecTacSchedule": FakeTecTacSchedule,
    "datetime": dt.datetime,
    "_as_utc": lambda v: v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc),
    "DEFAULT_RETRY_DELAY_SECONDS": 60,
}
compile_functions(
    SCHED,
    ("effective_retry_delay_seconds", "_occurrence_predates_schedule_revision", "_consume_revision_baseline"),
    sched_ns,
)
assert sched_ns["effective_retry_delay_seconds"](None) == 60
assert sched_ns["effective_retry_delay_seconds"](0) == 60
assert sched_ns["effective_retry_delay_seconds"]("0") == 60
assert sched_ns["effective_retry_delay_seconds"](15) == 15
revision = dt.datetime(2026, 9, 28, 7, 0, tzinfo=dt.timezone.utc)
class BaselineSchedule:
    schedule_type = "daily"
    last_due_key = ""
    updated_at = revision
    enabled = True
    saved = None
    def save(self, update_fields):
        self.saved = tuple(update_fields)
base = BaselineSchedule()
old_occurrence = revision - dt.timedelta(minutes=1)
assert sched_ns["_consume_revision_baseline"](base, old_occurrence, "old-key") is True
assert base.last_due_key == "old-key"
assert base.saved == ("last_due_key", "enabled", "updated_at")

sched_source = SCHED.read_text(encoding="utf-8")
dispatch_start = sched_source.index("def dispatch_due_schedules")
dispatch_text = sched_source[dispatch_start:]
baseline_pos = dispatch_text.index("_consume_revision_baseline(schedule, occurrence, key)")
should_run_pos = dispatch_text.index("_should_run_occurrence(schedule, occurrence, now)")
assert baseline_pos < should_run_pos, "revision baseline must be consumed before due/missed evaluation"
tasks_source = TASKS.read_text(encoding="utf-8")
assert "effective_retry_delay_seconds(run.retry_delay_seconds_snapshot)" in tasks_source
assert "effective_retry_delay_seconds(run.retry_delay_seconds_snapshot)" in sched_source


# L21: execute recover_stale_runs with a fake ORM. The queued row-lock query
# must receive a stale prefilter before it is materialized; the running query is
# separate and intentionally empty in this test.
class Q:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.children = []
        self.op = None
    def _combine(self, other, op):
        out = Q(); out.children = [self, other]; out.op = op; return out
    def __and__(self, other): return self._combine(other, "AND")
    def __or__(self, other): return self._combine(other, "OR")

def flatten_q(q):
    out = dict(q.kwargs)
    for child in q.children:
        out.update(flatten_q(child))
    return out

class EmptyQS:
    def __iter__(self): return iter(())
    def only(self, *args): return self

class LockedQS:
    def __init__(self, manager): self.manager = manager
    def filter(self, *args, **kwargs):
        self.manager.locked_filter_args.append((args, kwargs))
        return EmptyQS()
    def get(self, **kwargs):
        raise AssertionError("no running rows should be locked in this regression")

class RunManager:
    def __init__(self): self.locked_filter_args = []
    def select_for_update(self): return LockedQS(self)
    def filter(self, *args, **kwargs): return EmptyQS()

class RunStatus:
    QUEUED = "queued"; RUNNING = "running"; FAILED = "failed"
class FakeRun:
    Status = RunStatus
    objects = RunManager()
class FakeConfig:
    queued_stale_minutes = 10
class FakeSchedulerConfig:
    @staticmethod
    def current(): return FakeConfig()
class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
class Transaction:
    @staticmethod
    def atomic(): return Atomic()

recover_ns = {
    "datetime": dt.datetime,
    "TecTacSchedulerConfig": FakeSchedulerConfig,
    "TecTacScheduleRun": FakeRun,
    "transaction": Transaction,
    "Q": Q,
    "timedelta": dt.timedelta,
    "timezone": SimpleNamespace(now=lambda: revision),
    "_as_utc": lambda v: v,
    "queued_stale_deadline": lambda **kw: revision,
    "effective_retry_delay_seconds": sched_ns["effective_retry_delay_seconds"],
    "DEFAULT_RUNNING_STALE_GRACE": dt.timedelta(minutes=5),
    "_ACTIONS": {},
}
compile_functions(SCHED, ("recover_stale_runs",), recover_ns)
result = recover_ns["recover_stale_runs"](revision)
assert result == {"queued": 0, "running": 0}
assert len(FakeRun.objects.locked_filter_args) == 1
args, kwargs = FakeRun.objects.locked_filter_args[0]
assert not kwargs and len(args) == 1
keys = flatten_q(args[0])
assert "status" in keys
assert "last_queued_at__lt" in keys
assert "last_queued_at__isnull" in keys
assert "created_at__lt" in keys


# L20: execute the real DELETE method with fake model/transaction machinery.
# If strict audit fails, the schedule must not be deleted; on success the audit
# must be strict and precede deletion.
class FakeRuns:
    def select_for_update(self): return self
    def filter(self, **kwargs): return []
class FakeSchedule:
    pk = "sched-1"
    action_id = "gone.action"
    targets = {"type": "none"}
    runs = FakeRuns()
    deleted = False
    def delete(self): self.deleted = True
class FakeScheduleManager:
    def select_for_update(self): return self
    def select_related(self, *args): return self
class ScheduleModel:
    objects = FakeScheduleManager()
class RunModel:
    Status = RunStatus
class QueryParams(dict):
    pass
class Response:
    def __init__(self, data=None, status=None): self.data=data; self.status=status

def get_object_or_404(_qs, pk): return active_schedule

def noop(*args, **kwargs): return None

audit_calls = []
audit_mod = types.ModuleType("framwork.tec_tac.audit")
def audit_fail(**kwargs):
    audit_calls.append(kwargs)
    raise RuntimeError("audit unavailable")
audit_mod.record = audit_fail
sys.modules.setdefault("framwork", types.ModuleType("framwork"))
sys.modules.setdefault("framwork.tec_tac", types.ModuleType("framwork.tec_tac"))
sys.modules["framwork.tec_tac.audit"] = audit_mod

delete_node = method_node(VIEWS, "SchedulerDetailView", "delete")
mod = ast.Module(body=[delete_node], type_ignores=[]); ast.fix_missing_locations(mod)
delete_ns = {
    "__package__": "framwork.tec_tac",
    "transaction": Transaction,
    "get_object_or_404": get_object_or_404,
    "TecTacSchedule": ScheduleModel,
    "TecTacScheduleRun": RunModel,
    "_require_user_managed": noop,
    "_require_action": noop,
    "_require_schedule_owner_or_manager": noop,
    "_require_target_scope": noop,
    "Response": Response,
    "serialize_schedule": lambda schedule, include_runs=False: {"id": str(schedule.pk)},
    "timezone": SimpleNamespace(now=lambda: revision),
}
exec(compile(mod, str(VIEWS), "exec"), delete_ns)
request = SimpleNamespace(query_params=QueryParams(force="true"), user=SimpleNamespace(username="admin"))
active_schedule = FakeSchedule()
try:
    delete_ns["delete"](object(), request, "sched-1")
except RuntimeError as exc:
    assert str(exc) == "audit unavailable"
else:
    raise AssertionError("force delete ignored strict audit failure")
assert active_schedule.deleted is False
assert audit_calls and audit_calls[-1]["strict"] is True
assert audit_calls[-1]["metadata"] == {"force": True, "active_runs_failed": 0}

def audit_ok(**kwargs): audit_calls.append(kwargs)
audit_mod.record = audit_ok
active_schedule = FakeSchedule()
resp = delete_ns["delete"](object(), request, "sched-1")
assert resp.status == 204 and active_schedule.deleted is True

print("scheduler closure 1.15.144: PASS")
