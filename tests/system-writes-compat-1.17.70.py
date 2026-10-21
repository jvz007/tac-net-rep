#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.70 regression (CQ203): the second kind of system action changes nothing for what already exists.

Covered: run_system_action keeps its name, keyword-only signature and defaults; register_system_action keeps its signature; SystemFunction can still be built
with only the 1.17.68 fields (kind task, replacement_only False, no confirmation line), so an old row and every module keep working; the three earlier rows
keep every earlier field value; the identity of the first nine operations is unchanged; a task row still runs through run_system_action exactly as in
1.17.69 (scan, install and a script run, with the same Tactical calls and audit rows); delegation refuses a write row (not_delegable), by the kind check and by
the empty delegable_to; no module in modules/ calls run_system_write, names winupdate.set_action or reads the new table fields, so nothing outside patchmanagement's
future release is affected; the scheduler is not touched by this release (scheduler.py has no mention of the write kind).
"""
from __future__ import annotations

import inspect
from dataclasses import fields, replace
from pathlib import Path

H = Path(__file__).resolve().parent / "system-writes-harness-1.17.70.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
conf = load("tec_tac.system_action_confirmation", "system_action_confirmation.py")
deleg = load("tec_tac.delegation", "delegation.py")

# ---- signatures
sig = inspect.signature(sa.run_system_action)
must(list(sig.parameters) == ["context", "action_id", "agent_ids", "parameters"], list(sig.parameters))
must(sig.parameters["context"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD and all(sig.parameters[n].kind is inspect.Parameter.KEYWORD_ONLY for n in ("action_id", "agent_ids", "parameters")), sig)
must(sig.parameters["parameters"].default is None and sig.parameters["action_id"].default is inspect.Parameter.empty, sig)
reg = inspect.signature(sa.register_system_action)
must(list(reg.parameters) == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "delegable_to"], list(reg.parameters))
must(reg.parameters["dangerous"].default is False and reg.parameters["scope_kind"].default == "agents" and reg.parameters["delegable_to"].default == (), reg)
wsig = inspect.signature(sa.run_system_write)
must(list(wsig.parameters) == ["context", "action_id", "changes"] and wsig.parameters["action_id"].kind is inspect.Parameter.KEYWORD_ONLY, wsig)
print("       run_system_action and register_system_action keep their signatures; run_system_write is keyword-only after the context")

# ---- the table fields are additive and defaulted
names = [f.name for f in fields(sa.SystemFunction)]
must(names == ["key", "module_path", "function_name", "owner_module", "min_flags", "accepts", "takes_username", "reapproves_by_policy", "result_text", "parameters",
               "validate_parameters", "build_call", "audit_extra", "kind", "replacement_only", "confirmation_line"], names)
old = sa.SystemFunction(key="x.y", module_path="a.b", function_name="c", owner_module="patching", min_flags=("can_run_bulk",), accepts="agent_pks", takes_username=False,
                        reapproves_by_policy=False, result_text="Queued")
must(old.kind == "task" and old.replacement_only is False and old.confirmation_line is None and old.parameters == (), old)
scan = sa.SYSTEM_FUNCTIONS["winupdate.scan"]
must((scan.module_path, scan.function_name, scan.owner_module, tuple(scan.min_flags), scan.accepts, scan.takes_username, scan.reapproves_by_policy, scan.result_text) ==
     ("winupdate.tasks", "bulk_check_for_updates_task", "patching", ("can_manage_winupdates", "can_run_bulk"), "agent_pks", False, False, sa.QUEUED_TEXT), scan)
inst = sa.SYSTEM_FUNCTIONS["winupdate.install"]
must(inst.reapproves_by_policy is True and inst.function_name == "bulk_install_updates_task", inst)
script = sa.SYSTEM_FUNCTIONS["scripts.run"]
must(script.takes_username is True and tuple(script.min_flags) == ("can_run_bulk", "can_run_scripts") and script.owner_module == "scriptexecution", script)
definition_fields = [f.name for f in fields(sa.SystemActionDefinition)]
must(definition_fields == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "via_replacement", "delegable_to"], definition_fields)
print("       SystemFunction gains kind, replacement_only and confirmation_line, all defaulted; the three earlier rows and the definition are unchanged")

# ---- a task row still runs exactly as before
fresh(0, agents=3)
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[WRITE, "patchmanagement.install"])
sa.register_system_action("patchmanagement.install", "patchmanagement", "APM install", "winupdate.install", BOTH)
CFG["action_id"] = "patching.scan"
patch_ns = compile_as(roots["patching"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.run", module_id="patching", label="p", handler=patch_ns["task_handler"], target_types=("none", "endpoint"), timeout_seconds=600)
run, out = start(None, handler="patching.run", module="patching", params=None)
must(out["outcome"] == "queued" and out["agents"] == 3 and out["groups"] == {"total": 1, "sent": 1, "failed": 0, "not_started": 0} and out["message"] == sa.QUEUED_TEXT, out)
must(len(TASK_CALLS) == 1 and TASK_CALLS[0][0] == "scan" and TASK_CALLS[0][1] == ([BASE, BASE + 1, BASE + 2],) and TASK_CALLS[0][2] == {}, TASK_CALLS)
rows = [a for a in AUDITS if a["action"] == "run"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["metadata"]["function"] == "winupdate.scan" and rows[0]["metadata"]["agent_count"] == 3 and "kind" not in rows[0]["metadata"], rows)
must(not SER_CALLS and not closing_rows(), "no write")
print("       a task row (scan) runs through run_system_action exactly as before: one Tactical task call, one strict audit row, no write")

# ---- delegation refuses a write row
fresh(0)
sched.register_scheduled_action(id=WRITE, module_id="patchmanagement", label="w", handler=lambda context: None, target_types=("none", "endpoint"), timeout_seconds=600)
plugin("maintenance", system_actions=[])
try:
    deleg._provider_action("maintenance", "patchmanagement", WRITE)
    raise AssertionError("delegation of a write row was allowed")
except deleg.DelegationRefused as exc:
    must(exc.reason == "not_delegable", exc.reason)
forced = replace(sa._ACTIONS[WRITE], delegable_to=("maintenance",))  # even a definition that somehow named a delegate is refused by the kind check
sa._ACTIONS[WRITE] = forced
del AUDITS[:]
try:
    deleg._provider_action("maintenance", "patchmanagement", WRITE)
    raise AssertionError("delegation of a write row was allowed")
except deleg.DelegationRefused as exc:
    must(exc.reason == "not_delegable", exc.reason)
must([a["metadata"]["reason"] for a in AUDITS if a["action"] == "deny"] == ["not_delegable"], AUDITS)
src = (APP / "delegation.py").read_text(encoding="utf-8")
must("entry.kind != _sa.KIND_TASK" in src, "the kind check is in delegation.py")
print("       delegation refuses a write row (not_delegable), by the empty delegable_to and by the kind check")

# ---- nothing else uses it
MODULES = ROOT.parents[1] / "modules"
if MODULES.is_dir():
    users = []
    for path in MODULES.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(name in text for name in ("run_system_write", "winupdate.set_action", "replacement_only", "KIND_WRITE", ".run_write(")):
            users.append(str(path.relative_to(MODULES)))
    must(not users, f"modules that already use the second kind: {users}")
    must(all("winupdate.set_action" not in p.read_text(encoding="utf-8", errors="ignore") for p in MODULES.rglob("tec_tac*.json")), "no manifest names the row")
    print("       no module in modules/ calls run_system_write, names winupdate.set_action or reads the new fields (patchmanagement 0.13.0 will be the first)")
else:
    print("       modules/ is not beside this folder: the module scan is NOT RUN here")
must("KIND_WRITE" not in (APP / "scheduler.py").read_text(encoding="utf-8") and "system_writes" not in (APP / "scheduler.py").read_text(encoding="utf-8"), "scheduler.py is untouched")
print("PASS system writes compat 1.17.70")
