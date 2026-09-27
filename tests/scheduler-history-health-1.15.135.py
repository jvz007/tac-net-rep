#!/usr/bin/env python3
"""Behavioral regressions for M14 and L79."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

# ---- M14: exercise the real _paged_response method with a PostgreSQL-like queryset.
view_path = ROOT / "framwork/tec_tac/scheduler_views.py"
view_tree = ast.parse(view_path.read_text(encoding="utf-8"), filename=str(view_path))
view_cls = next(n for n in view_tree.body if isinstance(n, ast.ClassDef) and n.name == "SchedulerRunListView")
keep = {"_positive_int", "_paged_response"}
methods = [n for n in view_cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in keep]
mini_cls = ast.ClassDef(
    name="SchedulerRunListView",
    bases=[],
    keywords=[],
    body=[ast.Assign(targets=[ast.Name(id="FALLBACK_SCOPE_SCAN_LIMIT", ctx=ast.Store())], value=ast.Constant(5000)), *methods],
    decorator_list=[],
)
module = ast.Module(body=[mini_cls], type_ignores=[])
ast.fix_missing_locations(module)

class FakeQ:
    def __init__(self, **kwargs): self.kwargs = kwargs
    def __or__(self, other): return self

class FakeQS:
    def __init__(self, rows):
        self.rows = list(rows)
        self.filter_calls = 0
        self.extra_calls = 0
    def filter(self, *args, **kwargs):
        self.filter_calls += 1
        return self
    def count(self): return len(self.rows)
    def __getitem__(self, item): return self.rows[item]

scope_calls = 0
class ResourcesAdapter:
    @staticmethod
    def scheduler_scope_snapshot(*, user):
        global scope_calls
        scope_calls += 1
        return {"unrestricted": False, "client_ids": frozenset({1}), "site_ids": frozenset({2}), "endpoint_ids": frozenset({"agent-3"})}

class Response(dict):
    def __init__(self, payload, status=None):
        super().__init__(payload)
        self.status_code = status or 200

ns = {
    "SchedulerError": RuntimeError,
    "Q": FakeQ,
    "resources_adapter": ResourcesAdapter,
    "connection": SimpleNamespace(vendor="postgresql"),
    "_native_scheduler_manager": lambda user: False,
    "Response": Response,
    "serialize_run": lambda run: {"id": run.id},
}
exec(compile(module, str(view_path), "exec"), ns)
View = ns["SchedulerRunListView"]
view = View()
view._permitted_action_ids = lambda user: {"module.action"}
prefilter_calls = 0
def prefilter(qs, scope_snapshot):
    global prefilter_calls
    prefilter_calls += 1
    return qs
view._sql_scope_prefilter = prefilter
view._row_visible = lambda *a, **k: (_ for _ in ()).throw(AssertionError("PostgreSQL paging must not fall back to per-row scope checks"))
request = SimpleNamespace(user=object(), query_params={"page": "1", "page_size": "50"})
qs = FakeQS([SimpleNamespace(id=str(i)) for i in range(100)])
response = view._paged_response(request, qs, "user")
assert response.status_code == 200
assert response["count"] == 100
assert len(response["runs"]) == 50
assert scope_calls == 1, f"scope snapshot resolved {scope_calls} times"
assert prefilter_calls == 1, f"SQL scope prefilter called {prefilter_calls} times"
assert qs.filter_calls == 1, f"action permission filter called {qs.filter_calls} times"

# Alternate/test backends may need bounded Python row evaluation, but the
# Tactical scope itself must still be resolved once for the whole request.
ns["connection"].vendor = "sqlite"
row_checks = 0
def row_visible(*args, **kwargs):
    global row_checks
    row_checks += 1
    return True
view._row_visible = row_visible
qs2 = FakeQS([SimpleNamespace(id=f"s{i}") for i in range(100)])
response2 = view._paged_response(request, qs2, "user")
assert response2["count"] == 100
assert row_checks == 100
assert scope_calls == 2, f"fallback resolved scope per row: {scope_calls} total calls"
assert prefilter_calls == 2

# ---- L79: deleted schedule health uses immutable run snapshots.
scheduler_path = ROOT / "framwork/tec_tac/scheduler.py"
scheduler_tree = ast.parse(scheduler_path.read_text(encoding="utf-8"), filename=str(scheduler_path))
health_fn = next(n for n in scheduler_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_authorization_revoked_health")
health_mod = ast.Module(body=[health_fn], type_ignores=[])
ast.fix_missing_locations(health_mod)
health_ns = {}
exec(compile(health_mod, str(scheduler_path), "exec"), health_ns)

class RevokedQS:
    def __init__(self, row): self.row = row
    def order_by(self, *args): return self
    def first(self): return self.row
    def count(self): return 1

created = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
run = SimpleNamespace(
    schedule_id=None,
    schedule=None,
    schedule_snapshot_id="12345678-1234-5678-1234-567812345678",
    schedule_name="Deleted nightly scan",
    created_at=created,
    error="permission revoked",
)
health = health_ns["_authorization_revoked_health"](RevokedQS(run))
last = health["last_authorization_revoked"]
assert last["schedule_id"] == "12345678-1234-5678-1234-567812345678"
assert last["schedule_name"] == "Deleted nightly scan"
assert last["schedule_id"] != "None"

run.schedule_name = ""
health = health_ns["_authorization_revoked_health"](RevokedQS(run))
assert health["last_authorization_revoked"]["schedule_name"] == "Deleted schedule"

print("scheduler-history-health-1.15.135: PASS")
