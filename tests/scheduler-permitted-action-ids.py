#!/usr/bin/env python3
"""Behavioural regression for review blocker in Core 1.15.112-1."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import UUID

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()


def extract_class(path: Path, name: str, namespace: dict):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace[name]


# Use the real ScheduledAction dataclass definition so this regression catches
# field-name drift between the scheduler registry and its history view.
scheduler_ns = {'dataclass': dataclass}
ScheduledAction = extract_class(root / 'framwork/tec_tac/scheduler.py', 'ScheduledAction', scheduler_ns)

allowed = ScheduledAction('alpha.allowed', 'alpha', 'Allowed', lambda ctx: None, permission='alpha.use')
denied = ScheduledAction('beta.denied', 'beta', 'Denied', lambda ctx: None, permission='beta.use')
actions = [allowed, denied]

class APIView:
    pass
class SessionAuthenticated:
    pass
class SchedulerError(RuntimeError):
    pass
class Response:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status
class Q:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
    def __or__(self, other):
        return Q(self, other)
class DummyConnection:
    vendor = 'sqlite'
connection = DummyConnection()

class DummyResources:
    @staticmethod
    def scheduler_scope_snapshot(*, user):
        return {'unrestricted': True, 'client_ids': set(), 'site_ids': set(), 'endpoint_ids': set()}
resources_adapter = DummyResources()

def tactical_scope_ref(targets):
    return {'kind': 'none', 'values': []}
class SchedulerTargetShapeError(ValueError):
    pass

def scheduled_actions():
    return actions

def _can_use_action(user, action):
    return action.id == allowed.id

def _native_scheduler_manager(user):
    return False

def _owner_type_filter(request):
    return 'all'

def serialize_run(run):
    return {'action_id': run.action_id}

view_ns = {
    'APIView': APIView,
    'SessionAuthenticated': SessionAuthenticated,
    'SchedulerError': SchedulerError,
    'Response': Response,
    'Q': Q,
    'UUID': UUID,
    'connection': connection,
    'resources_adapter': resources_adapter,
    'SchedulerTargetShapeError': SchedulerTargetShapeError,
    'tactical_scope_ref': tactical_scope_ref,
    'scheduled_actions': scheduled_actions,
    '_can_use_action': _can_use_action,
    '_native_scheduler_manager': _native_scheduler_manager,
    '_owner_type_filter': _owner_type_filter,
    'serialize_run': serialize_run,
    # Only referenced by the class's unused methods in this focused test.
    'datetime': __import__('datetime').datetime,
}
SchedulerRunListView = extract_class(root / 'framwork/tec_tac/scheduler_views.py', 'SchedulerRunListView', view_ns)

# Review done-condition 1: two ScheduledAction objects, one permitted.
assert SchedulerRunListView._permitted_action_ids(object()) == {allowed.id}

class DummyRun:
    def __init__(self, action_id):
        self.action_id = action_id
        self.targets_snapshot = {'type': 'none'}
        self.schedule = None

class DummyQS:
    def __init__(self, rows):
        self.rows = list(rows)
    def filter(self, *args, **kwargs):
        # The production query narrows by the same permitted-action set. Mimic
        # that database effect so the view's rest of behavior is exercised.
        return DummyQS([r for r in self.rows if r.action_id == allowed.id])
    def iterator(self, chunk_size=200):
        return iter(self.rows)
    def count(self):
        return len(self.rows)
    def __getitem__(self, item):
        if isinstance(item, slice):
            return self.rows[item]
        return self.rows[item]

class TestView(SchedulerRunListView):
    def _base_queryset(self, request, owner_type):
        return DummyQS([DummyRun(allowed.id), DummyRun(denied.id)])

class Request:
    def __init__(self, query_params):
        self.user = object()
        self.query_params = query_params

view = TestView()

# Review done-condition 2: restricted paged history returns 200.
paged = view.get(Request({'page': '1', 'page_size': '50'}))
assert paged.status_code == 200, paged.status_code
assert paged.data['count'] == 1, paged.data
assert paged.data['runs'] == [{'action_id': allowed.id}], paged.data

# Review done-condition 3: restricted legacy/unpaged history returns 200.
unpaged = view.get(Request({}))
assert unpaged.status_code == 200, unpaged.status_code
assert unpaged.data['count'] == 1, unpaged.data
assert unpaged.data['runs'] == [{'action_id': allowed.id}], unpaged.data

print('scheduler permitted action ids regression: PASS')
