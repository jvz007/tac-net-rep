#!/usr/bin/env python3
"""1.15.134-1 regression: legacy saved endpoint PKs remain authorized/visible."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "framwork/tec_tac/resources_adapter.py"
VIEWS = ROOT / "framwork/tec_tac/scheduler_views.py"

class AdapterError(RuntimeError):
    pass

class Q:
    def __init__(self, *args, **kwargs):
        pass
    def __or__(self, other):
        return self

class QS:
    def __init__(self, rows):
        self.rows = list(rows)
    def filter(self, *args, **kwargs):
        return self
    def values_list(self, *fields, **kwargs):
        if fields == ("pk", "agent_id"):
            return list(self.rows)
        raise AssertionError(fields)

class AgentManager:
    def __init__(self, rows):
        self.rows = rows
    def all(self):
        return QS(self.rows)

class Agent:
    pass

Agent.objects = AgentManager([(42, "agent-42")])

# Exercise the real adapter helper used by _require_target_scope.
tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
keep = {"agent_target_identifiers_in_scope", "canonical_agent_target_ids_in_scope"}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in keep]
ns = {
    "TacticalResourceAdapterError": AdapterError,
    "Q": Q,
    "_models": lambda: (None, None, Agent),
    "_scope_queryset": lambda qs, **kwargs: qs,
}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ADAPTER), "exec"), ns)
assert ns["agent_target_identifiers_in_scope"](user=object(), identifiers=["42"]) == {"42"}
assert ns["agent_target_identifiers_in_scope"](user=object(), identifiers=["agent-42"]) == {"agent-42"}
assert ns["canonical_agent_target_ids_in_scope"](user=object(), identifiers=["42"]) == ["agent-42"]

# Exercise the real _require_target_scope authorization path with a legacy
# endpoint PK. This is the common gate used by GET/PATCH/list/runtime dispatch.
views_tree = ast.parse(VIEWS.read_text(encoding="utf-8"))
req_node = next(n for n in views_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_require_target_scope")

class PermissionDenied(RuntimeError):
    pass
class SchedulerError(RuntimeError):
    pass

resources_adapter = SimpleNamespace(
    tactical_scope_unrestricted=lambda **kwargs: False,
    explicit_client_target_ids_in_scope=lambda **kwargs: set(),
    site_target_ids_in_scope=lambda **kwargs: set(),
    agent_target_identifiers_in_scope=lambda **kwargs: ns["agent_target_identifiers_in_scope"](**kwargs),
)

def _native_scheduler_manager(user):
    return False

def _scope_target_refs(targets):
    assert targets == {"type": "endpoints", "ids": ["42"]}
    return [{"kind": "endpoint", "values": ["42"]}]

vns = {
    "PermissionDenied": PermissionDenied,
    "SchedulerError": SchedulerError,
    "resources_adapter": resources_adapter,
    "_native_scheduler_manager": _native_scheduler_manager,
    "_scope_target_refs": _scope_target_refs,
}
exec(compile(ast.Module(body=[req_node], type_ignores=[]), str(VIEWS), "exec"), vns)
vns["_require_target_scope"](object(), {"type": "endpoints", "ids": ["42"]}, payload=False)

# History visibility must include both the legacy PK and canonical agent_id.
adapter_source = ADAPTER.read_text(encoding="utf-8")
assert 'endpoint_ids.add(str(agent_id))' in adapter_source
assert 'endpoint_ids.add(str(pk))' in adapter_source

# PATCH/create still canonicalize persistence to agent_id after the legacy row
# passes get_object authorization.
views_source = VIEWS.read_text(encoding="utf-8")
assert 'data["targets"] = _canonicalize_endpoint_targets_for_user(request.user, data["targets"])' in views_source
assert 'resolved = resources_adapter.canonical_agent_target_ids_in_scope' in views_source

# Runtime dispatch uses the same _can_access_target_scope -> _require_target_scope
# path, so a valid legacy PK schedule is not marked AuthorizationRevoked.
scheduler_source = (ROOT / "framwork/tec_tac/scheduler.py").read_text(encoding="utf-8")
assert 'if not _can_access_target_scope(actor, schedule.targets or {})' in scheduler_source

print("scheduler legacy endpoint PK compatibility: PASS")
