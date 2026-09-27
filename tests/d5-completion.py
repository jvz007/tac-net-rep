#!/usr/bin/env python3
from __future__ import annotations

import ast
import pathlib
import types
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PermissionDenied(Exception):
    pass


class SchedulerError(Exception):
    pass


def load_functions(path: pathlib.Path, names: set[str], namespace: dict):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    found = {node.name for node in nodes}
    missing = names - found
    assert not missing, f'missing functions: {sorted(missing)}'
    module = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace


# Exercise the real Scheduler scope functions with controlled collaborators.
class ResourceAdapter:
    @staticmethod
    def tactical_scope_unrestricted(*, user):
        return bool(user.unrestricted)

    @staticmethod
    def explicit_client_target_ids_in_scope(*, user, client_ids):
        return set(client_ids)

    @staticmethod
    def site_target_ids_in_scope(*, user, site_ids):
        return set(site_ids)

    @staticmethod
    def agent_target_identifiers_in_scope(*, user, identifiers):
        return {str(v) for v in identifiers}


scope_ns = {
    'PermissionDenied': PermissionDenied,
    'SchedulerError': SchedulerError,
    'resources_adapter': ResourceAdapter,
    '_native_scheduler_manager': lambda user: False,
    '_scope_target_refs': lambda targets: [targets],
}
load_functions(
    ROOT / 'framwork/tec_tac/scheduler_views.py',
    {'_require_target_scope', '_can_access_target_scope'},
    scope_ns,
)

unrestricted = types.SimpleNamespace(unrestricted=True)
restricted = types.SimpleNamespace(unrestricted=False)
dynamic = {'kind': 'dynamic_unscoped', 'values': []}

# D5: both Tactical scope relations empty means full resource scope, including
# dynamic targets that intentionally have no explicit client/site/endpoint IDs.
scope_ns['_require_target_scope'](unrestricted, dynamic, payload=True)
assert scope_ns['_can_access_target_scope'](unrestricted, dynamic) is True

try:
    scope_ns['_require_target_scope'](restricted, dynamic, payload=True)
except PermissionDenied:
    pass
else:
    raise AssertionError('restricted role accepted dynamic_unscoped target')
assert scope_ns['_can_access_target_scope'](restricted, dynamic) is False

# Exercise the actual health-field builder, not source strings.
health_ns = {}
load_functions(
    ROOT / 'framwork/tec_tac/scheduler.py',
    {'_authorization_revoked_health'},
    health_ns,
)

class FakeQuery:
    def __init__(self, rows):
        self.rows = list(rows)
    def order_by(self, *fields):
        assert fields == ('-created_at',)
        return FakeQuery(sorted(self.rows, key=lambda r: r.created_at, reverse=True))
    def first(self):
        return self.rows[0] if self.rows else None
    def count(self):
        return len(self.rows)

older = types.SimpleNamespace(
    schedule_id='sched-old',
    schedule=types.SimpleNamespace(name='Old schedule'),
    created_at=datetime(2026, 9, 27, 7, 0, tzinfo=timezone.utc),
    error='old scope failure',
)
latest = types.SimpleNamespace(
    schedule_id='sched-new',
    schedule=types.SimpleNamespace(name='Patch approval'),
    created_at=datetime(2026, 9, 27, 8, 0, tzinfo=timezone.utc),
    error='Schedule targets are no longer within the owner scope.',
)
result = health_ns['_authorization_revoked_health'](FakeQuery([older, latest]))
assert result['authorization_revoked_last_24h'] == 2
assert result['last_authorization_revoked'] == {
    'schedule_id': 'sched-new',
    'schedule_name': 'Patch approval',
    'created_at': '2026-09-27T08:00:00+00:00',
    'error': 'Schedule targets are no longer within the owner scope.',
}
assert health_ns['_authorization_revoked_health'](FakeQuery([])) == {
    'authorization_revoked_last_24h': 0,
    'last_authorization_revoked': None,
}

print('D5 completion: PASS')
