#!/usr/bin/env python3
from __future__ import annotations

import ast
import datetime as dt
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

# M13: field-reference spellings that mean a Tactical scope identifier are
# blocked even when encoded as dotted, Django-style, camelCase, or path values.
spec = importlib.util.spec_from_file_location("scheduler_targets", ROOT / "framwork/tec_tac/scheduler_targets.py")
targets = importlib.util.module_from_spec(spec); spec.loader.exec_module(targets)
for token in ("site.id", "site__id", "siteId", "selector/site_id", "payload.clientIds", "agent.id"):
    try:
        targets.normalize_scheduler_targets({
            "type": "dynamic",
            "scope": {"type": "client", "ids": [1]},
            "filter": {"field": token, "value": 9},
        })
    except targets.SchedulerTargetShapeError:
        pass
    else:
        raise AssertionError(f"scope alias value escaped filter guard: {token}")
# Ordinary module-owned identifiers must remain valid filter values.
assert targets.normalize_scheduler_targets({
    "type": "dynamic", "scope": {"type": "client", "ids": [1]},
    "filter": {"field": "ticket.id", "value": "device_id"},
})["filter"]["field"] == "ticket.id"
for value in ("Main Site", "Johannesburg site", "ssh agent", "backup-client", "windows_agent", "ticket.client"):
    assert targets.normalize_scheduler_targets({
        "type": "dynamic", "scope": {"type": "client", "ids": [1]},
        "filter": {"name": value},
    })["filter"]["name"] == value

scheduler_path = ROOT / "framwork/tec_tac/scheduler.py"
scheduler_source = scheduler_path.read_text(encoding="utf-8")

# L19: exercise the revision-baseline predicate directly. A historical
# occurrence before a newly saved/edited definition is not a missed execution.
tree = ast.parse(scheduler_source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_occurrence_predates_schedule_revision")
mod = ast.Module(body=[node], type_ignores=[]); ast.fix_missing_locations(mod)
ns = {"TecTacSchedule": object, "datetime": dt.datetime, "_as_utc": lambda v: v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)}
exec(compile(mod, str(scheduler_path), "exec"), ns)
revision = dt.datetime(2026, 9, 27, 12, 0, tzinfo=dt.timezone.utc)
schedule = SimpleNamespace(last_due_key="", updated_at=revision)
assert ns["_occurrence_predates_schedule_revision"](schedule, revision - dt.timedelta(hours=1)) is True
assert ns["_occurrence_predates_schedule_revision"](schedule, revision + dt.timedelta(minutes=1)) is False
schedule.last_due_key = "already-consumed"
assert ns["_occurrence_predates_schedule_revision"](schedule, revision - dt.timedelta(hours=1)) is False

# L21: the queued recovery query must prefilter stale candidates in SQL before
# select_for_update locks are materialized.
assert "last_queued_at__lt=queued_cutoff" in scheduler_source
assert "created_at__lt=queued_cutoff" in scheduler_source
assert "select_for_update().filter" in scheduler_source

# L22: scheduler recovery and worker retry execution share the tested retry
# fallback helper rather than maintaining independent 0/60 fallbacks.
tasks_source = (ROOT / "framwork/tec_tac/tasks.py").read_text(encoding="utf-8")
assert "DEFAULT_RETRY_DELAY_SECONDS = 60" in scheduler_source
assert "effective_retry_delay_seconds" in tasks_source
assert "effective_retry_delay_seconds(run.retry_delay_seconds_snapshot)" in tasks_source
assert "retry_delay_seconds_snapshot or 0" not in scheduler_source

# L24: migration 0015 must not rewrite immutable run history and its aliases
# must not accept generic id as a widening shortcut.
migration_source = (ROOT / "framwork/tec_tac/migrations/0015_scheduler_target_canonicalization.py").read_text(encoding="utf-8")
assert "Run.objects" not in migration_source
assert '"client": ("client_ids", "client_id", "clients", "client")' in migration_source
assert '"site": ("site_ids", "site_id", "sites", "site")' in migration_source
assert "Never rewrite targets_snapshot" in migration_source

# L25: resolve endpoint PK/agent_id references to canonical agent_id and reject
# a numeric token that identifies two different visible Agent rows.
adapter_path = ROOT / "framwork/tec_tac/resources_adapter.py"
adapter_tree = ast.parse(adapter_path.read_text(encoding="utf-8"))
wanted = {"canonical_agent_target_ids_in_scope"}
nodes = [n for n in adapter_tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
assert len(nodes) == 1
m = ast.Module(body=nodes, type_ignores=[]); ast.fix_missing_locations(m)
class AdapterError(RuntimeError): pass
class Q:
    def __init__(self, *a, **kw): pass
    def __or__(self, other): return self
class QS:
    def __init__(self, rows): self.rows = rows
    def filter(self, *a, **kw): return self
    def values_list(self, *a, **kw): return list(self.rows)
class AgentManager:
    def __init__(self, rows): self.rows = rows
    def all(self): return QS(self.rows)
class Agent: pass
Agent.objects = AgentManager([(42, "agent-42"), (77, "agent-77"), (88, "77")])
ns2 = {
    "TacticalResourceAdapterError": AdapterError,
    "Q": Q,
    "_models": lambda: (None, None, Agent),
    "_scope_queryset": lambda qs, **kw: qs,
}
exec(compile(m, str(adapter_path), "exec"), ns2)
resolve = ns2["canonical_agent_target_ids_in_scope"]
assert resolve(user=object(), identifiers=["42"]) == ["agent-42"]
assert resolve(user=object(), identifiers=["agent-42"]) == ["agent-42"]
try:
    resolve(user=object(), identifiers=["77"])
except AdapterError:
    pass
else:
    raise AssertionError("ambiguous endpoint token did not fail closed")

print("scheduler hardening 1.15.134: PASS")
