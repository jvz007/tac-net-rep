#!/usr/bin/env python3
from __future__ import annotations

import ast
import datetime as dt
import importlib.util
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location("scheduler_targets_compat", ROOT / "framwork/tec_tac/scheduler_targets.py")
targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(targets)
normalize = targets.normalize_scheduler_targets

# Review blocker: ordinary descriptive module filter values are data, not scope aliases.
for value in ("Main Site", "Johannesburg site", "ssh agent", "backup-client", "windows_agent", "ticket.client"):
    normalized = normalize({
        "type": "dynamic",
        "scope": {"type": "client", "ids": [1]},
        "filter": {"name": value},
    })
    assert normalized["filter"]["name"] == value, value

# Explicit field-reference spellings still cannot create an alternate Tactical scope channel.
for value in ("site.id", "site__id", "siteId", "payload.clientIds", "agent.id"):
    try:
        normalize({
            "type": "dynamic",
            "scope": {"type": "client", "ids": [1]},
            "filter": {"field": value},
        })
    except targets.SchedulerTargetShapeError:
        pass
    else:
        raise AssertionError(f"scope field reference was accepted: {value}")

# Exercise the real dispatch_due_schedules control flow with a saved dynamic
# schedule containing name='Main Site'. The schedule must stay enabled and queue.
scheduler_path = ROOT / "framwork/tec_tac/scheduler.py"
tree = ast.parse(scheduler_path.read_text(encoding="utf-8"))
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "dispatch_due_schedules")
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)

class State:
    def save(self, **kwargs):
        pass

class StateModel:
    @classmethod
    def current(cls):
        return State()

class Query:
    def values_list(self, *args, **kwargs):
        return [1]

class ScheduleManager:
    def __init__(self, schedule):
        self.schedule = schedule
    def filter(self, **kwargs):
        assert kwargs == {"enabled": True}
        return Query()
    def select_for_update(self):
        return self
    def get(self, **kwargs):
        assert kwargs == {"pk": 1}
        return self.schedule

class Runs:
    def filter(self, **kwargs):
        return self
    def exists(self):
        return False

class ScheduleModel:
    class DoesNotExist(Exception):
        pass
    class ScheduleType:
        INTERVAL = "interval"
        ONCE = "once"
    class ConcurrencyPolicy:
        SKIP = "skip"

class RunStatus:
    QUEUED = "queued"
    RUNNING = "running"
    SKIPPED = "skipped"

class RunModel:
    class Status(RunStatus):
        pass
    created = []
    class objects:
        @classmethod
        def create(cls, **kwargs):
            run = SimpleNamespace(id=f"run-{len(RunModel.created)+1}", status=kwargs.get("status", RunStatus.QUEUED))
            RunModel.created.append((run, kwargs))
            return run

schedule = SimpleNamespace(
    id=1,
    enabled=True,
    targets={
        "type": "dynamic",
        "scope": {"type": "client", "ids": [1]},
        "filter": {"name": "Main Site"},
    },
    target_state="valid",
    target_state_detail="",
    schedule_type=ScheduleModel.ScheduleType.INTERVAL,
    last_due_key="",
    missed_policy="skip",
    concurrency_policy="allow",
    action_id="demo.action",
    runs=Runs(),
    save=lambda **kwargs: None,
)
ScheduleModel.objects = ScheduleManager(schedule)

now = dt.datetime(2026, 9, 27, 18, 0, tzinfo=dt.timezone.utc)
occurrence = now

ns = {
    "datetime": dt.datetime,
    "timezone": SimpleNamespace(now=lambda: now),
    "TecTacSchedulerState": StateModel,
    "TecTacSchedule": ScheduleModel,
    "TecTacScheduleRun": RunModel,
    "transaction": SimpleNamespace(atomic=lambda: nullcontext()),
    "_as_utc": lambda value: value,
    "recover_stale_runs": lambda value: 0,
    "normalize_scheduler_targets": normalize,
    "_canonicalize_persisted_endpoint_identity": lambda value: dict(value),
    "SchedulerTargetShapeError": targets.SchedulerTargetShapeError,
    "_runtime_authorization_error": lambda sched: None,
    "latest_occurrence": lambda sched, value: occurrence,
    "due_key": lambda occurrence, exact=False: "due-1",
    "_should_run_occurrence": lambda sched, occurrence, value: True,
    "_occurrence_predates_schedule_revision": lambda *args: False,
    "_consume_revision_baseline": lambda *args: False,
    "get_scheduled_action": lambda action_id: object(),
    "SchedulerError": RuntimeError,
    "_run_kwargs": lambda sched, **kwargs: kwargs,
    "_queue_run": lambda run: None,
    "cleanup_once_schedules": lambda value: 0,
    "cleanup_run_history": lambda value: 0,
}
exec(compile(module, str(scheduler_path), "exec"), ns)
result = ns["dispatch_due_schedules"](now)
assert schedule.enabled is True
assert schedule.target_state == "valid"
assert result["skipped"] == []
assert result["queued"] == ["run-1"]
assert RunModel.created[0][1].get("error_type") is None

print("scheduler filter value compatibility 1.15.134-2: PASS")
