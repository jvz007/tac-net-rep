#!/usr/bin/env python3
from __future__ import annotations

import ast
import datetime as dt
import importlib.util
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCHED = ROOT / "framwork/tec_tac/scheduler.py"
MIG15 = ROOT / "framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py"
MIG19 = ROOT / "framwork/tec_tac/migrations/0019_scheduler_endpoint_identity.py"
TARGETS = ROOT / "framwork/tec_tac/scheduler_targets.py"


def function_node(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def compile_functions(path: Path, names: tuple[str, ...], namespace: dict):
    nodes = [function_node(path, name) for name in names]
    mod = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(mod)
    exec(compile(mod, str(path), "exec"), namespace)
    return namespace


# L19: execute the real dispatch function with an occurrence that predates the
# schedule revision. It must be consumed before missed/grace evaluation and no
# run row may be created.
class FakeScheduleType:
    INTERVAL = "interval"
    ONCE = "once"

class FakeMissedPolicy:
    EXPIRE = "expire"
    RUN_ON_RECOVERY = "run_on_recovery"
    SKIP = "skip"

class FakeConcurrencyPolicy:
    SKIP = "skip"

class FakeOwnerType:
    USER = "user"

class FakeScheduleModel:
    ScheduleType = FakeScheduleType
    MissedPolicy = FakeMissedPolicy
    ConcurrencyPolicy = FakeConcurrencyPolicy
    OwnerType = FakeOwnerType
    class DoesNotExist(Exception):
        pass

class FakeRunStatus:
    SKIPPED = "skipped"
    QUEUED = "queued"
    RUNNING = "running"

class FakeRunModel:
    Status = FakeRunStatus

class RunManager:
    def __init__(self):
        self.created = []
    def create(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(id=len(self.created))

FakeRunModel.objects = RunManager()

class ScheduleRuns:
    def filter(self, **kwargs):
        return self
    def exists(self):
        return False

now = dt.datetime(2026, 9, 28, 9, 0, tzinfo=dt.timezone.utc)
occurrence = now - dt.timedelta(hours=1)
schedule = SimpleNamespace(
    id=1,
    enabled=True,
    targets={"type": "none"},
    owner_type="module",
    created_by=None,
    action_id="module.action",
    schedule_type=FakeScheduleType.INTERVAL,
    missed_policy=FakeMissedPolicy.SKIP,
    missed_grace_minutes=0,
    concurrency_policy=FakeConcurrencyPolicy.SKIP,
    last_due_key="",
    updated_at=now - dt.timedelta(minutes=5),
    runs=ScheduleRuns(),
)
schedule.saved = []
def schedule_save(update_fields=None):
    schedule.saved.append(tuple(update_fields or ()))
schedule.save = schedule_save

class ScheduleQuery:
    def filter(self, **kwargs):
        return self
    def values_list(self, *args, **kwargs):
        return [1]
    def select_for_update(self):
        return self
    def get(self, pk):
        assert pk == 1
        return schedule
FakeScheduleModel.objects = ScheduleQuery()

class State:
    def save(self, update_fields=None):
        pass
state = State()
class StateModel:
    @staticmethod
    def current():
        return state

@contextmanager
def atomic():
    yield

class Timezone:
    @staticmethod
    def now():
        return now

class SchedulerTargetShapeError(ValueError):
    pass
class SchedulerError(RuntimeError):
    pass

sched_ns = {
    "datetime": dt.datetime,
    "TecTacSchedule": FakeScheduleModel,
    "TecTacScheduleRun": FakeRunModel,
    "TecTacSchedulerState": StateModel,
    "timezone": Timezone,
    "transaction": SimpleNamespace(atomic=atomic),
    "SchedulerTargetShapeError": SchedulerTargetShapeError,
    "SchedulerError": SchedulerError,
    "_as_utc": lambda value: value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc),
    "recover_stale_runs": lambda current: [],
    "normalize_scheduler_targets": lambda targets: dict(targets),
    "_runtime_authorization_error": lambda sched: None,
    "latest_occurrence": lambda sched, current: occurrence,
    "due_key": lambda value, exact=False: "old-key",
    "_should_run_occurrence": lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("missed evaluation ran before revision baseline")),
    "_run_kwargs": lambda *args, **kwargs: kwargs,
    "get_scheduled_action": lambda action_id: object(),
    "_queue_run": lambda run: (_ for _ in ()).throw(AssertionError("pre-revision occurrence was queued")),
    "cleanup_once_schedules": lambda current: 0,
    "cleanup_run_history": lambda current: 0,
}
compile_functions(SCHED, ("_occurrence_predates_schedule_revision", "_consume_revision_baseline", "dispatch_due_schedules"), sched_ns)
result = sched_ns["dispatch_due_schedules"](now)
assert result["queued"] == []
assert result["skipped"] == []
assert FakeRunModel.objects.created == []
assert schedule.last_due_key == "old-key"


# L24/L25: migration 0015 and the upgrade repair migration 0019 must persist
# endpoint targets using agent_id, while ambiguous numeric aliases fail closed.
def migration_namespace(path: Path, names: set[str]):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            nodes.append(node)
    ns = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), ns)
    return ns

ns15 = migration_namespace(MIG15, {
    "_NATIVE", "_ALIASES", "_values", "_ids", "_extract_native", "_legacy_normalize",
    "_canonical_endpoint_ids", "_canonicalize_endpoint_identity",
})
rows = [(42, "agent-42"), (77, "agent-77"), (88, "77")]
static = ns15["_legacy_normalize"]({"type": "endpoint", "ids": ["42"]})
assert ns15["_canonicalize_endpoint_identity"](static, rows) == {"type": "endpoint", "ids": ["agent-42"]}
dynamic = ns15["_legacy_normalize"]({"type": "dynamic", "scope": {"type": "endpoint", "ids": ["42"]}, "filter": {"os": "windows"}})
assert ns15["_canonicalize_endpoint_identity"](dynamic, rows)["scope"] == {"type": "endpoint", "ids": ["agent-42"]}
try:
    ns15["_canonical_endpoint_ids"](["77"], rows)
except ValueError as exc:
    assert "ambiguous" in str(exc)
else:
    raise AssertionError("ambiguous endpoint PK/agent_id token did not fail closed")

ns19 = migration_namespace(MIG19, {
    "_NATIVE", "_values", "_canonical_endpoint_ids", "_canonicalize_endpoint_identity",
})
assert ns19["_canonicalize_endpoint_identity"]({"type": "agents", "ids": [42]}, rows) == {"type": "agents", "ids": ["agent-42"]}
assert ns19["_canonicalize_endpoint_identity"]({"type": "dynamic", "scope": {"type": "agent", "ids": [42]}}, rows) == {
    "type": "dynamic", "scope": {"type": "endpoint", "ids": ["agent-42"]}
}

# Runtime target-shape normalization remains compatible with the final migrated
# representation, and migration history never rewrites run snapshots.
spec = importlib.util.spec_from_file_location("scheduler_targets_115149", TARGETS)
target_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target_mod)
assert target_mod.normalize_scheduler_targets({"type": "endpoint", "ids": ["agent-42"]}) == {"type": "endpoint", "ids": ["agent-42"]}
assert target_mod.normalize_scheduler_targets({"type": "dynamic", "scope": {"type": "endpoint", "ids": ["agent-42"]}}) == {
    "type": "dynamic", "scope": {"type": "endpoint", "ids": ["agent-42"]}
}
assert "targets_snapshot" not in MIG19.read_text(encoding="utf-8")
assert "Never rewrite targets_snapshot" in MIG15.read_text(encoding="utf-8")

print("scheduler closure 1.15.149: PASS")
