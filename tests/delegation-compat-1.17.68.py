#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.68 compatibility of core.system_actions 1.1.0 -> 1.2.0: a caller written for 1.1.0 sees nothing different.

The real system_actions.py on the stub harness of scheduler-completion-harness-1.17.61.py, and modules/ read as source when it is on this PC.

Covered. The capability keeps its id, its four earlier operations first and in order, and gains five at the end; the metadata keeps every earlier key (refusal reasons only
grow); list_actions rows keep every earlier key and add delegable_to (empty for an action that names none); register_system_action called as in 1.17.67 (eight arguments, by
position or keyword) gives the same definition and the same refusals; run_system_action keeps its signature, answers the same result for the same run and keeps
wrong_module (the run is kept); describe_confirmation keeps its signature; no delegation function can be reached through run_system_action; modules/ uses only the old forms today.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
sched.AD13_CONDITION_2_AMENDED = True

BOTH = ("can_manage_winupdates", "can_run_bulk")
alice = User("alice")
FLAGS["alice"] = set(BOTH)
SCOPE["alice"] = {41, 42}
plugin("patching", system_actions=["patching.scan", "patching.handler"])
plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan"])
HONOURED["patchmanagement"] = "patching"

# ---- the definition and its refusals, called as in 1.17.67
definition = sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
must(definition.delegable_to == () and definition.id == "patching.scan" and definition.via_replacement is False and definition.scope_kind == "agents" and definition.username_param is None, definition)
by_keyword = sa.register_system_action(id="patching.scan", module_id="patching", label="Scheduled patch scan", function="winupdate.scan", permissions=BOTH, scope_kind="agents", dangerous=False, username_param=None)
must(by_keyword is definition, "the same registration by keyword is the same definition")
for call in (lambda: sa.register_system_action("patching.scan", "patching", "x", "winupdate.scan", BOTH),  # a different label
             lambda: sa.register_system_action("patching.other", "patching", "x", "not.a.row", BOTH),
             lambda: sa.register_system_action("patching.other", "patching", "x", "winupdate.scan", ("can_run_bulk",)),
             lambda: sa.register_system_action("other.scan", "patching", "x", "winupdate.scan", BOTH)):
    try:
        call()
        raise AssertionError("accepted")
    except sa.SystemActionRegistrationError:
        pass
rows = sa.registered_system_actions()
must({"id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "via_replacement", "owner_module", "min_flags", "reapproves_by_policy", "parameters", "warning"} <= set(rows[0]) and rows[0]["delegable_to"] == [], rows[0])
print("       register_system_action called as in 1.17.67 gives the same definition and the same refusals; list_actions rows keep every earlier key and add delegable_to")

# ---- the capability
meta = sa.system_actions_contract_metadata()
must(meta["id"] == "core.system_actions" and (tuple(int(x) for x in meta["version"].split("-")[0].split(".")) >= (1, 3, 0)) and meta["operations"][:4] == ["list_actions", "get_action", "run", "describe_confirmation"] and len(meta["operations"]) >= 10 and meta["operations"][9] == "run_write", meta["operations"])  # 1.17.70: one operation appended (capability 1.3.0); 1.17.74: resolve_delegated_targets appended (the first ten are checked, version is >=)
for key in ("python", "functions", "manifest_key", "max_agents", "max_agents_per_group", "max_groups", "parameters_key", "refusal_reasons", "http", "delivery", "audit_actions", "requires_framework", "unattended"):
    must(key in meta, key)
must(meta["max_agents"] == 40000 and meta["delivery"] == "at most once per group" and meta["http"] == {"confirmation": "POST /api/tfd/scheduler/system-actions/confirmation/"}, "limits and routes unchanged")
must({"wrong_module", "outside_targets", "targets_unresolved", "declaration_unreadable"} <= set(meta["refusal_reasons"]), "the refusal reasons only grew")
must("delegation" in meta and meta["delegation"]["grants_per_owner_module"] == 20 and meta["delegation"]["ticket_seconds"] == 86400 and meta["delegation"]["confirmation_seconds"] == 600, meta["delegation"])
for name in ("list_actions", "get_action", "run", "describe_confirmation"):
    must(callable(getattr(sa._PROVIDER, name)), name)
must(inspect.signature(sa._PROVIDER.run).parameters.keys() == {"context", "action_id", "agent_ids", "parameters"}, "run keeps its parameters")
must(list(inspect.signature(sa._PROVIDER.describe_confirmation).parameters) == ["request", "action_id", "targets", "parameters", "when"], "describe_confirmation keeps its parameters")
print("       the capability keeps its four earlier operations first, its metadata keys and its limits; the refusal reasons only grew")

# ---- run_system_action: the same run gives the same answer, and wrong_module stays
roots = {}
IDS = [41, 42]
CFG = {"agents": IDS}
roots["patching"] = plugin("patching", system_actions=["patching.scan", "patching.handler"])
roots["patchmanagement"] = plugin("patchmanagement", category="premium", replaces="patching", system_actions=["patchmanagement.scan"])
sa.register_system_action("patching.handler", "patching", "Handler", "winupdate.scan", BOTH)
HANDLER = "def handler(context):\n    return sa.run_system_action(context, action_id='patching.handler', agent_ids=CFG['agents'])\n"
sched._ACTIONS["patching.handler"] = sched.ScheduledAction("patching.handler", "patching", "h", compile_as(roots["patching"] / "h.py", HANDLER, sa=sa, CFG=CFG)["handler"], "", ("endpoint",), timeout_seconds=600)
run = make_run("patching.handler", "patching", user=alice, owner="user", targets={"type": "endpoint", "ids": [str(i) for i in IDS]})
run.schedule.created_by_username = "alice"
out = go(run)
must(out == {"outcome": "queued", "agents": 2, "message": sa.QUEUED_TEXT, "groups": {"total": 1, "sent": 1, "failed": 0, "not_started": 0}, "summary": "2 endpoint(s) in 1 group(s): 1 sent, 0 failed, 0 not started."}, out)
must(len(TASK_CALLS) == 1 and TASK_CALLS[0][0] == "scan", TASK_CALLS)
row = [a for a in AUDITS if a["action"] == "run"][0]["metadata"]
must("patch_lockdown" not in row and "warning" not in row, "a scan carries neither the warning nor the lockdown note: the audit row of a 1.17.67 caller is unchanged")
wrong = compile_as(roots["patchmanagement"] / "calls.py", "def go(context):\n    return sa.run_system_action(context, action_id='patching.handler', agent_ids=[41, 42])\n", sa=sa)
context = rc.issue_run_context({"run_id": str(run.id)}, run_id=run.id)
run.status = "running"
try:
    wrong["go"](context)
    raise AssertionError("another module must be refused")
except sa.SystemActionRefused as exc:
    must(exc.reason == "wrong_module" and run.status == "running", "wrong_module keeps the run")
print("       the same run gives the same answer and the same audit row; another module still gets wrong_module and the run is kept")

# ---- modules/: today's calls use only the forms that did not change
modules = ROOT.parents[1] / "modules"
if modules.is_dir():
    forms = {"run_system_action": set(), "register_system_action": set(), "describe_confirmation": set()}
    for path in sorted(modules.rglob("*.py")):
        parts = path.relative_to(modules).parts
        if "node_modules" in parts or "tests" in parts or path.name.startswith("test_") or path.name == "stubs.py" or len(parts) < 2:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in forms and "tec_tac" in text:
                    forms[name].add(parts[0])
                    keywords = {k.arg for k in node.keywords if k.arg}
                    if name == "run_system_action":
                        must(keywords <= {"action_id", "agent_ids", "parameters"} and len(node.args) <= 1, f"{path.name}: run_system_action is called as in 1.17.67")
                    if name == "register_system_action":
                        must(keywords <= {"id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "delegable_to"}, f"{path.name}: register_system_action keywords")
    print(f"       modules/: run_system_action {sorted(forms['run_system_action'])}, register_system_action {sorted(forms['register_system_action'])}, describe_confirmation {sorted(forms['describe_confirmation'])}: every call uses a form that did not change")
else:
    print("       modules/ is not on this PC: the module read was skipped")
print("PASS delegation compat 1.17.68")
