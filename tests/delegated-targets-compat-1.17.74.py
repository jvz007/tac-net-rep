#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.74 regression (Q-APM21 b): resolve_delegated_targets changes nothing for what already exists.

Covered: run_system_action, register_system_action and run_system_write keep their names, keyword-only signatures and defaults; SystemFunction gains no field, so an older row and
every module keep working; the four rows keep every earlier field value; the first ten operations keep their identity and order, and the one new operation is appended; a caller
written against 1.3.0 still gets the same result shapes: scan and install queue exactly as in 1.17.73 (one Tactical task call, one strict audit row, the same group digests and plan
digest, the same result keys), an install by the honoured replacement keeps its warning, and a write row still refuses in run_system_action; the metadata a 1.3.0 reader looks at is
still there (write.kinds, delegation callers, functions); no module in modules/ names resolve_delegated_targets, so nothing outside the module lanes that asked for it is affected.
"""
from __future__ import annotations

import hashlib
import inspect
from dataclasses import fields
from pathlib import Path

H = Path(__file__).resolve().parent / "delegated-targets-harness-1.17.74.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

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
ssig = inspect.signature(sa.start_delegated_run)
must(list(ssig.parameters) == ["ticket", "action_id", "agent_ids", "name"] and ssig.parameters["name"].default is None, ssig)
rsig = inspect.signature(sa.resolve_delegated_targets)
must(list(rsig.parameters) == ["ticket", "action_id", "endpoint_ids"] and all(rsig.parameters[n].kind is inspect.Parameter.KEYWORD_ONLY for n in ("action_id", "endpoint_ids")), rsig)
print("       the public functions keep their signatures; the new one is keyword-only after the ticket")

# ---- the table and the definition are additive
names = [f.name for f in fields(sa.SystemFunction)]
must(names == ["key", "module_path", "function_name", "owner_module", "min_flags", "accepts", "takes_username", "reapproves_by_policy", "result_text", "parameters",
               "validate_parameters", "build_call", "audit_extra", "kind", "replacement_only", "confirmation_line"], names)
definition_fields = [f.name for f in fields(sa.SystemActionDefinition)]
must(definition_fields == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "via_replacement", "delegable_to"], definition_fields)
scan = sa.SYSTEM_FUNCTIONS["winupdate.scan"]
must((scan.module_path, scan.function_name, scan.owner_module, tuple(scan.min_flags), scan.accepts, scan.takes_username, scan.reapproves_by_policy, scan.result_text, scan.kind) ==
     ("winupdate.tasks", "bulk_check_for_updates_task", "patching", ("can_manage_winupdates", "can_run_bulk"), "agent_pks", False, False, sa.QUEUED_TEXT, "task"), scan)
inst = sa.SYSTEM_FUNCTIONS["winupdate.install"]
must(inst.reapproves_by_policy is True and inst.function_name == "bulk_install_updates_task" and inst.kind == "task", inst)
script = sa.SYSTEM_FUNCTIONS["scripts.run"]
must(script.takes_username is True and tuple(script.min_flags) == ("can_run_bulk", "can_run_scripts") and script.owner_module == "scriptexecution" and script.kind == "task", script)
write = sa.SYSTEM_FUNCTIONS["winupdate.set_action"]
must(write.kind == "write" and write.replacement_only is True and tuple(write.min_flags) == ("can_manage_winupdates",) and write.owner_module == "patching", write)
print("       SystemFunction and the definition gain no field; the four earlier rows keep every field")

# ---- the operations: the ten of 1.3.0 keep their place, one is appended
earlier = ["list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket",
           "start_delegated_run", "run_write"]
must(list(sa.OPERATIONS)[:10] == earlier and list(sa.OPERATIONS)[10:] == ["resolve_delegated_targets"], sa.OPERATIONS)
meta = sa.system_actions_contract_metadata()
must(meta["write"]["kinds"] == ["task", "write"] and meta["write"]["function"] == "winupdate.set_action", "a 1.3.0 reader of write.kinds still finds what it read")
must(set(meta["delegation"]["callers"]) >= {"describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run"}, meta["delegation"])
must({"winupdate.scan", "winupdate.install", "scripts.run", "winupdate.set_action"} <= set(meta["functions"]), sorted(meta["functions"]))
print("       the ten operations keep their order; the metadata a 1.3.0 reader looks at is still there")

# ---- a task row (scan) runs exactly as in 1.17.73
fresh(3)
sa.register_system_action("patching.scan", "patching", "Scheduled patch scan", "winupdate.scan", BOTH)
patch_ns = compile_as(roots["patching"] / "handlers.py", HANDLER_SRC, sa=sa, CFG=CFG)
sched.register_scheduled_action(id="patching.run", module_id="patching", label="p", handler=patch_ns["handler"], target_types=("none", "endpoint"), timeout_seconds=600)
CFG["action_id"] = "patching.scan"
run, out = start(None, handler="patching.run", module="patching")
must(out == {"outcome": "queued", "agents": 3, "message": sa.QUEUED_TEXT, "groups": {"total": 1, "sent": 1, "failed": 0, "not_started": 0},
             "summary": "3 endpoint(s) in 1 group(s): 1 sent, 0 failed, 0 not started."}, out)
must(len(TASK_CALLS) == 1 and TASK_CALLS[0][0] == "scan" and TASK_CALLS[0][1] == ([BASE, BASE + 1, BASE + 2],) and TASK_CALLS[0][2] == {}, TASK_CALLS)
rows = [a for a in AUDITS if a["action"] == "run"]
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["metadata"]["function"] == "winupdate.scan" and rows[0]["metadata"]["agent_count"] == 3, rows)
must("kind" not in rows[0]["metadata"] and True, "a task row's audit row has no kind key")
ids_text = f"{BASE},{BASE + 1},{BASE + 2}"
digest = hashlib.sha256(f"{run.id}|patching.scan|{ids_text}".encode()).hexdigest()[:32]
plan_digest = hashlib.sha256(f"{run.id}|patching.scan|plan|{ids_text}".encode()).hexdigest()[:32]
must([m["targets_digest"] for m in run.system_action_marks if m.get("kind") != "plan"] == [digest] and [m["targets_digest"] for m in run.system_action_marks if m.get("kind") == "plan"] == [plan_digest],
     "the group and plan digests are the formulas of 1.17.73")
print("       a scan runs exactly as in 1.17.73: the same result, one Tactical task call, one strict row with no kind key, the same digests")

# ---- install by the honoured replacement keeps its warning and its result shape
fresh(2)
pm_ns = mods["patchmanagement"]
CFG["action_id"] = "patchmanagement.install"
run, out = start(None, handler="patchmanagement.install", module="patchmanagement")
must(out["outcome"] == "queued" and out["agents"] == 2 and set(out) == {"outcome", "agents", "message", "groups", "summary"}, out)
must(TASK_CALLS and TASK_CALLS[0][0] == "install", TASK_CALLS)
described = sa.get_system_action("patchmanagement.install")
must(described["kind"] == "task" and described["warning"] == sa.REAPPROVE_WARNING and described["delegable_to"] == ["maintenance"], described)
must([a for a in AUDITS if a["action"] == "run"][0]["metadata"]["warning"] == sa.REAPPROVE_WARNING and "kind" not in [a for a in AUDITS if a["action"] == "run"][0]["metadata"], "the warning is in the row")
print("       an install by the honoured replacement queues as before, with the same result keys")

# ---- a write row still refuses in run_system_action
fresh(2)
PLUGINS["patchmanagement"].system_actions = ("patchmanagement.install", "patchmanagement.setaction")
sa.register_system_action("patchmanagement.setaction", "patchmanagement", "APM decisions", "winupdate.set_action", ("can_manage_winupdates",), dangerous=True)
CFG["action_id"] = "patchmanagement.setaction"
run, out = start(None, handler="patchmanagement.install", module="patchmanagement")
must(deny_reasons() == ["wrong_kind"] and not TASK_CALLS, deny_reasons())
print("       a write row still refuses in run_system_action as wrong_kind")

# ---- an unknown id is refused as before
fresh(2)
CFG["action_id"] = "agents.nothing"
run, out = start()
must(run.status == "skipped" and run.error_type == "SystemActionRefused", (run.status, run.error_type))
must(deny_reasons() == ["unknown_action"] , deny_reasons())
print("       an action id that is not registered is refused as unknown_action, as before")

# ---- nothing in modules/ uses the new kind or the new operation yet
MODULES = ROOT.parents[1] / "modules"
if MODULES.is_dir():
    users = []
    for path in MODULES.rglob("*"):
        if path.suffix not in (".py", ".json"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(name in text for name in ("resolve_delegated_targets",)):
            users.append(str(path.relative_to(MODULES)))
    must(not users, f"modules that already use resolve_delegated_targets: {users}")
    print("       no module in modules/ names resolve_delegated_targets")
else:
    print("       modules/ is not beside this folder: the module scan is NOT RUN here")
src_sched = (APP / "scheduler.py").read_text(encoding="utf-8")
must("KIND_COMMAND" not in src_sched and "system_commands" not in src_sched, "scheduler.py is untouched")
tasks_src = (APP / "tasks.py").read_text(encoding="utf-8")
must("for_storage" not in tasks_src, "tasks.py is untouched")
print("delegated-targets-compat-1.17.74: ok")
