#!/usr/bin/env python3
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
module_path = ROOT / "framwork" / "tec_tac" / "scheduler_targets.py"
spec = importlib.util.spec_from_file_location("scheduler_targets", module_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Static aliases stay strict, but the documented dynamic scope shape remains
# backwards-compatible and normalises before persistence/dispatch.
try:
    mod.normalize_scheduler_targets({"type": "endpoints", "agent_ids": ["x"]})
except mod.SchedulerTargetShapeError:
    pass
else:
    raise AssertionError("static legacy aliases must not bypass canonical static target shape")

legacy_dynamic = {"type": "dynamic", "scope": {"client_id": 17}, "filter": {"os": "windows"}}
assert mod.normalize_scheduler_targets(legacy_dynamic) == {
    "type": "dynamic", "scope": {"type": "client", "ids": [17]}, "filter": {"os": "windows"}
}

# Filter scope protection is top-level only; nested module-domain keys survive.
assert mod.normalize_scheduler_targets({
    "type": "dynamic", "scope": {"site_id": 3}, "filter": {"rule": {"id": 4, "site_id": 5}}
})["filter"] == {"rule": {"id": 4, "site_id": 5}}

views = (ROOT / "framwork" / "tec_tac" / "scheduler_views.py").read_text()
manager_pos = views.index("if _native_scheduler_manager(user):", views.index("def _require_target_scope"))
refs_pos = views.index("refs = _scope_target_refs(targets)", views.index("def _require_target_scope"))
assert manager_pos < refs_pos, "manager bypass must occur before saved-target normalization"
assert 'raise PermissionDenied("The saved scheduler target definition is not in the supported canonical format.")' in views

scheduler = (ROOT / "framwork" / "tec_tac" / "scheduler.py").read_text()
reconcile = scheduler[scheduler.index("def reconcile_schedule"):scheduler.index("def disable_owned_schedule")]
assert 'data["targets"] = normalize_scheduler_targets(data.get("targets"))' in reconcile
assert 'error_type="InvalidTargetShape"' in scheduler

# Migration 0015 must preserve the documented dynamic scope and mark it valid
# after canonicalisation rather than disabling it. Extract only the pure helper
# nodes so this regression does not require Django to be installed.
import ast
migration_path = ROOT / "framwork" / "tec_tac" / "migrations" / "0015_scheduler_target_canonicalization.py"
tree = ast.parse(migration_path.read_text())
keep_names = {"_NATIVE", "_ALIASES"}
keep_funcs = {"_values", "_ids", "_extract_native", "_legacy_normalize", "canonicalize_existing_targets"}
nodes = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in keep_names for t in node.targets):
        nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in keep_funcs:
        nodes.append(node)
ns = {}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(migration_path), "exec"), ns)
assert ns["_legacy_normalize"](legacy_dynamic) == {
    "type": "dynamic", "scope": {"type": "client", "ids": [17]}, "filter": {"os": "windows"}
}

class _Rows:
    def __init__(self, rows): self.rows = rows
    def all(self): return self
    def iterator(self): return iter(self.rows)

class _Model:
    def __init__(self, rows): self.objects = _Rows(rows)

class _Row:
    def __init__(self, targets):
        self.targets = targets
        self.enabled = True
        self.target_state = "valid"
        self.target_state_detail = ""
        self.saved = []
    def save(self, update_fields=None): self.saved.append(tuple(update_fields or ()))

legacy_row = _Row(dict(legacy_dynamic))
class _Apps:
    def get_model(self, app, name):
        return _Model([legacy_row]) if name == "TecTacSchedule" else _Model([])

ns["canonicalize_existing_targets"](_Apps(), None)
assert legacy_row.enabled is True
assert legacy_row.target_state == "valid"
assert legacy_row.target_state_detail == ""
assert legacy_row.targets == {
    "type": "dynamic", "scope": {"type": "client", "ids": [17]}, "filter": {"os": "windows"}
}

print("scheduler legacy target regression: PASS")
