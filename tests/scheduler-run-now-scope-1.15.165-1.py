#!/usr/bin/env python3
"""Regression: out-of-scope run-now callers must not mutate schedules."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "framwork" / "tec_tac" / "scheduler_views.py"

class SchedulerError(Exception):
    pass

class PermissionDenied(Exception):
    pass

class APIView:
    def dispatch(self, request, schedule_id):
        try:
            return self.post(request, schedule_id)
        except PermissionDenied as exc:
            return Response({"detail": str(exc)}, status=403)

class SessionAuthenticated:
    pass

class Response:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status

class _ScheduleModel:
    pass
TecTacSchedule = _ScheduleModel

class TacticalResourceAdapterError(Exception):
    pass

class _ResourcesAdapter:
    TacticalResourceAdapterError = TacticalResourceAdapterError

    @staticmethod
    def canonical_agent_target_ids(*, identifiers):
        # Global identity repair has no caller-scope decision.
        return [str(value).strip() for value in identifiers]

resources_adapter = _ResourcesAdapter()

class FakeSchedule:
    def __init__(self, *, owner_type, created_by, targets):
        self.owner_type = owner_type
        self.created_by = created_by
        self.action_id = "module.patch"
        self.targets = dict(targets)
        self.enabled = True
        self.target_state = "valid"
        self.target_state_detail = ""
        self.saved = []

    def save(self, update_fields=None):
        self.saved.append(tuple(update_fields or ()))

current_schedule = None
queued = []

def get_object_or_404(_model, **_kwargs):
    return current_schedule

def _require_action(_user, _action_id):
    return SimpleNamespace(id=_action_id)

def _require_schedule_owner_or_manager(_user, _schedule):
    # These two scenarios are intentionally permitted through this ownership
    # gate by production policy: module-owned action user; server-maint manager.
    return None

def _normalize_targets(targets):
    return dict(targets)

def _require_target_scope(user, targets, payload=False):
    assert payload is False
    assert targets == {"type": "endpoints", "ids": ["agent-X"]}
    if user.username in {"module-tech", "restricted-manager"}:
        raise PermissionDenied("Schedule target is outside your Tactical access scope.")

def is_one_off_schedule(_schedule):
    # 1.17.17: run-now refuses one-off schedules first; these schedules are ordinary ones (see tests/scheduler-one-off-run-now-1.17.17.py)
    return False

def queue_manual_run(schedule):
    queued.append(schedule)
    return SimpleNamespace(id="run-1")

def serialize_run(run):
    return {"id": run.id}

# Execute the production global repair helper and RunNow class.
tree = ast.parse(VIEWS.read_text(encoding="utf-8"), filename=str(VIEWS))
selected = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "_canonicalize_endpoint_targets_globally":
        selected.append(node)
    if isinstance(node, ast.ClassDef) and node.name == "SchedulerRunNowView":
        selected.append(node)
module = ast.Module(body=selected, type_ignores=[])
exec(compile(module, str(VIEWS), "exec"), globals())
RunNow = globals()["SchedulerRunNowView"]

# Module-owned schedule: action permission is sufficient to reach target scope,
# but an out-of-scope technician must get 403 and mutate nothing.
module_tech = SimpleNamespace(username="module-tech")
module_owner = SimpleNamespace(username="module")
current_schedule = FakeSchedule(
    owner_type="module",
    created_by=module_owner,
    targets={"type": "endpoints", "ids": ["agent-X"]},
)
before = (current_schedule.enabled, current_schedule.target_state, dict(current_schedule.targets))
response = RunNow().dispatch(SimpleNamespace(user=module_tech), "schedule-module")
assert response.status_code == 403
assert (current_schedule.enabled, current_schedule.target_state, current_schedule.targets) == before
assert current_schedule.saved == []
assert queued == []

# Scope-restricted can_do_server_maint manager on another user's schedule must
# also get 403 with absolutely no schedule mutation.
restricted_manager = SimpleNamespace(username="restricted-manager")
other_user = SimpleNamespace(username="owner")
current_schedule = FakeSchedule(
    owner_type="user",
    created_by=other_user,
    targets={"type": "endpoints", "ids": ["agent-X"]},
)
before = (current_schedule.enabled, current_schedule.target_state, dict(current_schedule.targets))
response = RunNow().dispatch(SimpleNamespace(user=restricted_manager), "schedule-user")
assert response.status_code == 403
assert (current_schedule.enabled, current_schedule.target_state, current_schedule.targets) == before
assert current_schedule.saved == []
assert queued == []

print("scheduler run-now out-of-scope no-mutation 1.15.165-1: PASS")
