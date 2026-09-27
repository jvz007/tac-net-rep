#!/usr/bin/env python3
"""M12 behavioral regression: run-now canonicalises like scheduled dispatch."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "framwork" / "tec_tac" / "scheduler_targets.py"
VIEWS = ROOT / "framwork" / "tec_tac" / "scheduler_views.py"

spec = importlib.util.spec_from_file_location("scheduler_targets", TARGETS)
target_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target_mod)

class SchedulerError(Exception):
    pass

class APIView:
    pass

class SessionAuthenticated:
    pass

class Response:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status

class _ScheduleModel:
    pass

TecTacSchedule = _ScheduleModel

class FakeSchedule:
    def __init__(self, targets):
        self.action_id = "module.action"
        self.targets = targets
        self.enabled = True
        self.target_state = "valid"
        self.target_state_detail = ""
        self.saved = []

    def save(self, update_fields=None):
        self.saved.append(tuple(update_fields or ()))

current_schedule = None
scope_seen = []
queue_seen = []

def get_object_or_404(_model, **_kwargs):
    return current_schedule

def _require_action(_user, _action_id):
    return None

def _require_schedule_owner_or_manager(_user, _schedule):
    return None

def _normalize_targets(targets):
    try:
        return target_mod.normalize_scheduler_targets(targets)
    except target_mod.SchedulerTargetShapeError as exc:
        raise SchedulerError(str(exc)) from exc

def _require_target_scope(_user, targets, payload=False):
    assert payload is False
    scope_seen.append(targets)

def queue_manual_run(schedule):
    queue_seen.append(dict(schedule.targets))
    return SimpleNamespace(id="run-1")

def serialize_run(run):
    return {"id": run.id}

# Compile only the production class under test so Django is not required in
# the release-review environment.
tree = ast.parse(VIEWS.read_text(encoding="utf-8"), filename=str(VIEWS))
klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SchedulerRunNowView")
module = ast.Module(body=[klass], type_ignores=[])
ns = globals()
exec(compile(module, str(VIEWS), "exec"), ns)
RunNow = ns["SchedulerRunNowView"]
request = SimpleNamespace(user=SimpleNamespace(id=7, username="operator"))

# Legacy dynamic scope alias must be canonicalised, persisted, authorized and
# snapshotted in canonical form before a manual run is queued.
current_schedule = FakeSchedule({
    "type": "dynamic",
    "scope": {"client_id": 17},
    "filter": {"os": "windows"},
})
response = RunNow().post(request, "schedule-1")
expected = {
    "type": "dynamic",
    "scope": {"type": "client", "ids": [17]},
    "filter": {"os": "windows"},
}
assert response.status_code == 202
assert current_schedule.targets == expected
assert scope_seen[-1] == expected
assert queue_seen[-1] == expected
assert current_schedule.target_state == "valid"
assert current_schedule.target_state_detail == ""
assert ("targets", "target_state", "target_state_detail", "updated_at") in current_schedule.saved

# Already-canonical targets must not cause an unnecessary persistence write.
scope_seen.clear(); queue_seen.clear()
current_schedule = FakeSchedule({"type": "endpoints", "ids": ["agent-a"]})
response = RunNow().post(request, "schedule-2")
assert response.status_code == 202
assert current_schedule.saved == []
assert scope_seen == [{"type": "endpoints", "ids": ["agent-a"]}]
assert queue_seen == [{"type": "endpoints", "ids": ["agent-a"]}]

# Invalid saved targets follow scheduled-dispatch quarantine semantics: disable,
# mark invalid, return 400, and never authorize or queue a manual run.
scope_seen.clear(); queue_seen.clear()
current_schedule = FakeSchedule({"type": "endpoints", "agent_ids": ["legacy"]})
response = RunNow().post(request, "schedule-3")
assert response.status_code == 400
assert current_schedule.enabled is False
assert current_schedule.target_state == "invalid"
assert current_schedule.target_state_detail
assert scope_seen == []
assert queue_seen == []
assert ("enabled", "target_state", "target_state_detail", "updated_at") in current_schedule.saved

print("scheduler run-now canonicalization: PASS")
