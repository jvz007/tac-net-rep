#!/usr/bin/env python3
from __future__ import annotations

import ast
import datetime as dt
import pathlib
import sys
import types
from contextlib import nullcontext

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "framwork/tec_tac/scheduler.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
WANTED = {"recover_stale_runs", "_queue_run"}
NODES = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in WANTED]
assert {node.name for node in NODES} == WANTED
MODULE = ast.Module(body=NODES, type_ignores=[])
ast.fix_missing_locations(MODULE)

class Status:
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    FAILED = "FAILED"

class RunModel:
    Status = Status
    objects = None

class Config:
    queued_stale_minutes = 10
    @classmethod
    def current(cls):
        return cls()

class State:
    last_dispatch_at = None
    last_dispatch_error = ""
    saved = []
    @classmethod
    def current(cls):
        cls.saved = []
        return cls()
    def save(self, update_fields=None):
        self.__class__.saved.append(tuple(update_fields or ()))

class QS:
    def __init__(self, items):
        self.items = list(items)
    def filter(self, **kwargs):
        status = kwargs.get("status")
        started_not_null = kwargs.get("started_at__isnull")
        rows = self.items
        if status is not None:
            rows = [x for x in rows if x.status == status]
        if started_not_null is False:
            rows = [x for x in rows if x.started_at is not None]
        return QS(rows)
    def select_for_update(self):
        return self
    def only(self, *fields):
        return self
    def get(self, pk):
        for item in self.items:
            if item.pk == pk:
                return item
        raise KeyError(pk)
    def __iter__(self):
        return iter(self.items)

class Run:
    def __init__(self, pk, started_at, task_id="task-123", action_id="test.action"):
        self.pk = pk
        self.id = pk
        self.status = Status.RUNNING
        self.started_at = started_at
        self.celery_task_id = task_id
        self.action_id = action_id
        self.error_type = ""
        self.error = ""
        self.finished_at = None
        self.saved = []
    def save(self, update_fields=None):
        self.saved.append(tuple(update_fields or ()))

class Action:
    timeout_seconds = 60

class Control:
    def __init__(self):
        self.calls = []
        self.fail = False
    def revoke(self, task_id, **kwargs):
        self.calls.append((task_id, kwargs))
        if self.fail:
            raise RuntimeError("broker unavailable")

control = Control()
celery_mod = types.ModuleType("tacticalrmm.celery")
celery_mod.app = types.SimpleNamespace(control=control)
sys.modules.setdefault("tacticalrmm", types.ModuleType("tacticalrmm"))
sys.modules["tacticalrmm.celery"] = celery_mod

class AsyncTask:
    def __init__(self):
        self.calls = []
    def apply_async(self, *, args, time_limit):
        self.calls.append((list(args), time_limit))
        return types.SimpleNamespace(id="celery-456")

async_task = AsyncTask()
tasks_mod = types.ModuleType("tec_tac.tasks")
tasks_mod.execute_schedule_run = async_task
sys.modules.setdefault("tec_tac", types.ModuleType("tec_tac"))
sys.modules["tec_tac.tasks"] = tasks_mod

now = dt.datetime(2026, 9, 27, 12, 0, tzinfo=dt.timezone.utc)

def as_utc(value):
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)

def queued_deadline(**kwargs):
    return kwargs["queued_at"] + dt.timedelta(minutes=kwargs["queued_stale_minutes"])

ns = {
    "__name__": "tec_tac.scheduler_test",
    "__package__": "tec_tac",
    "datetime": dt.datetime,
    "timedelta": dt.timedelta,
    "timezone": types.SimpleNamespace(now=lambda: now),
    "transaction": types.SimpleNamespace(atomic=lambda: nullcontext()),
    "TecTacScheduleRun": RunModel,
    "TecTacSchedulerConfig": Config,
    "TecTacSchedulerState": State,
    "DEFAULT_RUNNING_STALE_GRACE": dt.timedelta(minutes=5),
    "MAX_ACTION_TIMEOUT_SECONDS": 604800,
    "_ACTIONS": {"test.action": Action()},
    "_as_utc": as_utc,
    "queued_stale_deadline": queued_deadline,
}
exec(compile(MODULE, str(SOURCE), "exec"), ns)

# Stale RUNNING: revoke the exact Celery task with terminate=True before releasing
# the DB concurrency lock by changing the run to FAILED.
run = Run("run-1", now - dt.timedelta(minutes=7))
RunModel.objects = QS([run])
result = ns["recover_stale_runs"](now)
assert result == {"queued": 0, "running": 1}, result
assert control.calls == [("task-123", {"terminate": True, "signal": "SIGTERM"})], control.calls
assert run.status == Status.FAILED
assert run.error_type == "Stale"
assert run.finished_at == now

# If Celery revocation cannot be requested, keep the run RUNNING so SKIP
# concurrency cannot launch an overlapping replacement. The next tick retries.
control.calls.clear(); control.fail = True
run2 = Run("run-2", now - dt.timedelta(minutes=7), task_id="task-789")
RunModel.objects = QS([run2])
result = ns["recover_stale_runs"](now)
assert result == {"queued": 0, "running": 0}, result
assert control.calls == [("task-789", {"terminate": True, "signal": "SIGTERM"})]
assert run2.status == Status.RUNNING
assert run2.finished_at is None
control.fail = False

# Queue dispatch must carry an action-specific hard Celery limit: declared action
# timeout plus the same five-minute stale grace. The task stores its broker id.
queue_run = Run("run-3", now, task_id="")
queue_run.action_id = "test.action"
queue_run.celery_task_id = ""
RunModel.objects = QS([queue_run])
ns["_queue_run"](queue_run)
assert async_task.calls == [(["run-3"], 360)], async_task.calls
assert queue_run.celery_task_id == "celery-456"

# The actual task declaration retains a framework-level hard ceiling as a second
# worker-side backstop even if a future dispatch path forgets the dynamic limit.
tasks_source = (ROOT / "framwork/tec_tac/tasks.py").read_text(encoding="utf-8")
tasks_tree = ast.parse(tasks_source)
fn = next(n for n in tasks_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "execute_schedule_run")
assert fn.decorator_list
call = next(d for d in fn.decorator_list if isinstance(d, ast.Call))
kw = {item.arg: item.value for item in call.keywords}
assert isinstance(kw.get("time_limit"), ast.Constant) and kw["time_limit"].value == 605100

print("scheduler stale Celery revocation/time limit: PASS")
