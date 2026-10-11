#!/usr/bin/env python3
"""1.17.18 regression: the route owner table homes agents/{id}/tasks/ with Tasks and agents/{id}/checks/ with Checks
(Johan, 10 October 2026).

Builds on the stubs of tests/tactical-operations-1.17.7.py. Covered: Tasks and Checks may declare their agent sub-routes, Agents
and every other module may not, an untyped parameter under agents/ is judged against the new rules too, and every Tactical route
that a module under modules/ declares today is judged exactly as it was before the two rules existed (a compatibility check
that reads the declarations as data; it is skipped when modules/ is not beside this repository).
"""
from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("fresh()\nmust(ops.list_operations() == []")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, PLUGINS, declare, refused, fresh, must = (G[k] for k in ("ops", "PLUGINS", "declare", "refused", "fresh", "must"))

for name in ("tasks", "checks", "agent-management", "remote-background", "take-control", "scriptexecution"):
    PLUGINS[name] = SimpleNamespace(plugin_id=name, plugin_type="extension", version="1.0.0", permission_groups=(), legacy=False,
                                    audit_events=(), category="core")

FLAG = ["can_reboot_agents"]
NOSCOPE = dict(scope=[], body_fields=[], audit={"action": "view", "object_type": "agent", "audit_fields": []})


def spec(module, op, route, method, over):
    out = dict(id=op, module_id=module, method=method, route=route, permissions=FLAG, **NOSCOPE)
    out.update(over)
    return out


def ok(module, op, route, method="GET", **over):
    return declare(**spec(module, op, route, method, over))


def no(module, op, route, method="GET", **over):
    return refused(**spec(module, op, route, method, over))


fresh()
# ---- the two new rules
must(ops.ROUTE_OWNERS[("agents", "{}", "tasks")] == frozenset({"tasks"}) and ops.ROUTE_OWNERS[("agents", "{}", "checks")] == frozenset({"checks"}), "rules in the table")
ok("tasks", "agent-tasks", "agents/{agent_id:agent}/tasks/")
ok("tasks", "agent-tasks-post", "agents/{agent_id:agent}/tasks/", "POST")
ok("tasks", "agent-tasks-deep", "agents/{agent_id:agent}/tasks/{pk:int}/", "DELETE")
ok("checks", "agent-checks", "agents/{agent_id:agent}/checks/")
ok("checks", "agent-checks-post", "agents/{agent_id:agent}/checks/", "POST")
for module in ("agents", "checks", "agent-management", "remote-background", "reportmanager"):
    must("does not own route" in no(module, "t-" + module, "agents/{agent_id:agent}/tasks/", "PUT"), module)
for module in ("agents", "tasks", "agent-management", "take-control", "reportmanager"):
    must("does not own route" in no(module, "c-" + module, "agents/{agent_id:agent}/checks/", "PUT"), module)
no("tasks", "tasks-checks", "agents/{agent_id:agent}/checks/", "DELETE")
no("checks", "checks-tasks", "agents/{agent_id:agent}/tasks/", "DELETE")
# the rest of agents/ is still Agents'
ok("agents", "ping", "agents/{agent_id:agent}/ping/")
ok("agents", "agent-one", "agents/{agent_id:agent}/", "DELETE")
no("tasks", "tasks-ping", "agents/{agent_id:agent}/ping/")
no("checks", "checks-agent", "agents/{agent_id:agent}/", "PUT")
# an untyped parameter can hold the route word, so Agents is refused for it, and Tasks too (it would also reach agents/<id>/ping/)
must("does not own route" in no("agents", "untyped-agents", "agents/{x}/{y}/", "POST"), "agents with an untyped second segment reaches tasks/ and checks/")
no("tasks", "untyped-tasks", "agents/{x}/{y}/", "POST")
no("agents", "untyped-agents-2", "agents/{agent_id:agent}/{y}/", "POST")  # {y} can be tasks, checks, cmd, registry ...
ok("agents", "typed-agents", "agents/{agent_id:agent}/{port:int}/", "POST")  # an int segment is never a route word
# the existing homes are unchanged
ok("remote-background", "cmd", "agents/{agent_id:agent}/cmd/", "POST")
ok("take-control", "mesh", "agents/{agent_id:agent}/meshcentral/")
ok("scriptexecution", "run", "agents/{agent_id:agent}/runscript/", "POST")
no("tasks", "cmd-tasks", "agents/{agent_id:agent}/cmd/", "POST")
fresh()
# the dispatch re-check agrees with registration
op = ok("tasks", "agent-tasks", "agents/{agent_id:agent}/tasks/")
ops._recheck_route_owner(op, "/agents/" + "a" * 21 + "/tasks/")
try:
    ops._recheck_route_owner(ops._OPERATIONS[("tasks", "agent-tasks")].__class__(**{**op.__dict__, "module_id": "agents"}), "/agents/" + "a" * 21 + "/tasks/")
    raise AssertionError("agents must not reach the tasks route at dispatch")
except ops.TacticalOperationError as exc:
    must(exc.status == 404 and exc.code == "tactical_operation_not_found", exc.code)

# ---- every declaration found in modules/ is judged as before
MODULES = Path(__file__).resolve().parents[3] / "modules"
GROUPS = {"agents", "alerts", "automation", "checks", "clients", "core", "logs", "reporting", "scripts", "services", "software", "tasks", "winupdate"}
if MODULES.is_dir() and (MODULES / "catalog.toml").is_file():
    catalog = tomllib.loads((MODULES / "catalog.toml").read_text(encoding="utf-8"))
    entries = catalog.get("modules") or catalog.get("module") or []
    if isinstance(entries, dict):
        entries = [{"id": key, **value} for key, value in entries.items()]
    category = {str(e.get("id")): str(e.get("category", "")) for e in entries if isinstance(e, dict)}
    found = []
    for folder in sorted(p for p in MODULES.iterdir() if (p / "package").is_dir()):
        files = [f for f in (folder / "package").rglob("*.py") if f.name in ("operations.py", "apps.py") and "tests" not in f.parts]
        for file in files:
            tree = ast.parse(file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/" in node.value and node.value.split("/")[0] in GROUPS:
                    found.append((folder.name, node.value))
    found = sorted(set(found))
    must(found, "the scan found no declared routes: the extraction is broken")
    rules = {k: v for k, v in ops.ROUTE_OWNERS.items()}
    old_rules = {k: v for k, v in rules.items() if k not in (("agents", "{}", "tasks"), ("agents", "{}", "checks"))}

    def judge(module_id, route):
        try:
            segments, _ = ops._parse_route(route)
        except ops.TacticalOperationRegistrationError:
            return "unparsed"
        try:
            ops._check_route_owner({"id": module_id, "category": category.get(module_id) or "core"}, segments, route)
            return "ok"
        except ops.TacticalOperationRegistrationError as exc:
            return str(exc)

    checked = changed = 0
    for module_id, route in found:
        with_new = judge(module_id, route)
        ops.ROUTE_OWNERS.clear(); ops.ROUTE_OWNERS.update(old_rules)
        try:
            with_old = judge(module_id, route)
        finally:
            ops.ROUTE_OWNERS.clear(); ops.ROUTE_OWNERS.update(rules)
        if with_new == "unparsed":
            continue
        checked += 1
        # a route that the owning module could declare before must still be declarable
        if with_old == "ok":
            must(with_new == "ok", f"{module_id} {route}: accepted before 1.17.18, refused now: {with_new}")
    must(checked >= 20, f"too few routes checked: {checked}")
    print(f"       compatibility: {checked} declared routes of {len({m for m, _ in found})} modules judged unchanged for their owners")
else:
    print("       compatibility check skipped: modules/ is not beside this repository")

print("[TEST] PASS tactical operation route owners 1.17.18")
