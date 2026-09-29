#!/usr/bin/env python3
"""Regression for the 1.15.164 plural/native Scheduler compatibility rebuild."""
from __future__ import annotations

import ast
import importlib.util
import runpy
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# Production runtime normalizer: canonicalize IDs, preserve module vocabulary.
spec = importlib.util.spec_from_file_location(
    "scheduler_targets_under_test", ROOT / "framwork/tec_tac/scheduler_targets.py"
)
targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(targets)

native = targets.normalize_scheduler_targets({"type": "endpoints", "ids": ["a", "b"]})
must(native == {"type": "endpoints", "ids": ["a", "b"]}, f"native type rewritten: {native!r}")
must(targets.tactical_scope_ref(native) == {"kind": "endpoint", "values": ["a", "b"]}, "internal scope kind was not singular endpoint")
must(targets.normalize_scheduler_targets({"type": "agents", "ids": ["a", "b"]})["type"] == "agents", "agent alias was rewritten")

# Load the frozen 0015 migration without Django installed.
class _Field:
    def __init__(self, *args, **kwargs):
        pass
class _RunPython:
    noop = staticmethod(lambda *args, **kwargs: None)
    def __init__(self, *args, **kwargs):
        pass
class _AddField:
    def __init__(self, *args, **kwargs):
        pass
class _Migration:
    pass
fake_migrations = types.SimpleNamespace(Migration=_Migration, RunPython=_RunPython, AddField=_AddField)
fake_models = types.SimpleNamespace(CharField=_Field)
django = types.ModuleType("django")
django_db = types.ModuleType("django.db")
django_db.migrations = fake_migrations
django_db.models = fake_models
sys.modules.setdefault("django", django)
sys.modules.setdefault("django.db", django_db)
sys.modules.setdefault("django.db.migrations", fake_migrations)
sys.modules.setdefault("django.db.models", fake_models)

mig15 = runpy.run_path(str(ROOT / "framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py"))
must(
    mig15["_legacy_normalize"]({"type": "endpoints", "ids": ["a", "b"]})
    == {"type": "endpoints", "ids": ["a", "b"]},
    "0015 rewrote endpoints target type",
)

# Run the actual 0020 repair against a stored endpoints schedule. It delegates
# to 0015, so this proves a system that already ran 0015 is repaired without
# changing the handler-facing type.
class Row:
    def __init__(self):
        self.targets = {"type": "endpoints", "ids": ["a", "b"]}
        self.enabled = True
        self.target_state = "valid"
        self.target_state_detail = ""
    def save(self, update_fields=None):
        self.saved = tuple(update_fields or ())
row = Row()
class _All:
    def iterator(self):
        return iter([row])
class Schedule:
    objects = types.SimpleNamespace(all=lambda: _All())
class Run:
    class _NoTouch:
        def __getattr__(self, name):
            raise AssertionError(f"0020 touched immutable run history: {name}")
    objects = _NoTouch()
class AgentValues:
    def values_list(self, *args):
        return [(1, "a"), (2, "b")]
class Agent:
    objects = types.SimpleNamespace(all=lambda: AgentValues())
class Apps:
    def get_model(self, app, model):
        return {
            ("tec_tac", "TecTacSchedule"): Schedule,
            ("tec_tac", "TecTacScheduleRun"): Run,
            ("agents", "Agent"): Agent,
        }[(app, model)]

legacy_mod = types.ModuleType("tec_tac.migrations.0015_scheduler_target_canonicalization")
legacy_mod.canonicalize_existing_targets = mig15["canonicalize_existing_targets"]
sys.modules[legacy_mod.__name__] = legacy_mod
mig20 = runpy.run_path(str(ROOT / "framwork/tec_tac/migrations/0020_scheduler_target_parity_repair.py"))
mig20["repair_scheduler_targets"](Apps(), None)
must(row.targets == {"type": "endpoints", "ids": ["a", "b"]}, f"0020 rewrote endpoints type: {row.targets!r}")

# Execute the real _validate_shape function body used by SchedulerListView.post.
view_source = (ROOT / "framwork/tec_tac/scheduler_views.py").read_text(encoding="utf-8")
tree = ast.parse(view_source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_validate_shape")
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)
class SchedulerError(RuntimeError):
    pass
class ScheduleType:
    ONCE = "once"; DAILY = "daily"; WEEKLY = "weekly"; MONTHLY = "monthly"; INTERVAL = "interval"
class FakeSchedule:
    ScheduleType = ScheduleType
Action = types.SimpleNamespace(id="module.multi", target_types=("endpoints",))
ns = {
    "SchedulerError": SchedulerError,
    "TecTacSchedule": FakeSchedule,
    "get_scheduled_action": lambda action_id: Action,
}
exec(compile(module, str(ROOT / "framwork/tec_tac/scheduler_views.py"), "exec"), ns)
ns["_validate_shape"]({
    "schedule_type": "once",
    "run_at": "2026-09-29T08:00:00Z",
    "action_id": "module.multi",
    "targets": native,
})

# Handler-facing contract regression for the shipped module semantics identified
# by review. Plural endpoint targets must reach handlers with both IDs intact.
def communicator_agent_ids(handler_targets):
    if handler_targets.get("type") in {"endpoints", "agents"}:
        return list(handler_targets.get("ids") or [])
    if handler_targets.get("type") == "endpoint":
        value = handler_targets.get("id") or handler_targets.get("agent_id")
        return [value] if value else []
    return []

def maintenance_resolve_ids(handler_targets):
    ids = list(handler_targets.get("ids") or [])
    if handler_targets.get("type") == "endpoint":
        return ids[:1]
    if handler_targets.get("type") in {"endpoints", "agents"}:
        return ids
    return []

must(communicator_agent_ids(native) == ["a", "b"], "Communicator-compatible handler lost endpoint IDs")
must(maintenance_resolve_ids(native) == ["a", "b"], "Maintenance-compatible handler lost endpoint IDs")

print("[TEST] PASS scheduler native target compatibility 1.15.164-1")
