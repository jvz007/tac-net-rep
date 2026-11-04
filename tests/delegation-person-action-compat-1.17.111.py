#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.111 regression (AD-43): the person-action path leaves everything that existed alone.

On the stub harness of delegation-person-action-harness-1.17.111.py. Covered. (1) The system-action path (patchmanagement.install, a Tactical function) behaves as before: the same text
(with the group sentence and the re-approve warning, kind system_action), the same grant (parameters stored as passed), the same ticket, run, marker and unattended answer, and the system
checks still apply (a provider that stops naming the owner, a replacement that is no longer honoured). A write row and a command row are still not delegable, and a system action is never
treated as a person action. (2) The signatures of the five delegation functions and of resolve_delegated_targets, and of register_system_action, are unchanged. (3) core.system_actions is 1.6.0
with the same operations in the same order, its metadata describes the person-action rules, and the contract rows and documents say 'Since 1.17.111'.
"""
from __future__ import annotations

import inspect
from pathlib import Path

HARNESS_111 = Path(__file__).resolve().parent / "delegation-person-action-harness-1.17.111.py"
exec(compile(HARNESS_111.read_text(encoding="utf-8"), str(HARNESS_111), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

SYS_TARGETS, SYS_KEY = {"type": "profile", "ids": [7]}, "profile:system"


def sys_save(user=alice):
    request = RealRequest(user)
    base = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=SYS_TARGETS, parameters=None)
    answer = call("maintenance", "describe", request, **base)
    return answer, call("maintenance", "register", request, grant_key=SYS_KEY, confirmation_id=answer["confirmation_id"], **base)


# ---- (1) the system-action path
fresh()
answer, saved = sys_save()
text = answer["text"]
must(answer["kind"] == "system_action" and answer["groups"] == 1 and answer["total"] == 2 and saved == {"grant_key": SYS_KEY, "created": True, "owner_changed": False}, (answer, saved))
for needle in ("Advanced Patch Management install: 2 endpoint(s), sent to Tactical in 1 group(s) of at most 2000.", "maintenance will start this for you later, with nobody signed in",
               "that the replacement is still in place", "Core does not look at your account again", sa.REAPPROVE_WARNING, "Requested by alice. Do you want to continue?"):
    must(needle in text, (needle, text))
must(set(answer) == {"required", "text", "confirmation_id", "total", "groups", "expires_in", "kind"}, sorted(answer))
grant = grants()[0]
must(grant.provider_module == "patchmanagement" and grant.action_id == INSTALL and grant.parameters == {}, grant.__dict__)  # parameters stored as passed (None gives {})
context, _run = live_context()
token = call("maintenance", "issue", context, grant_key=SYS_KEY)
run = call("patchmanagement", "start", token, action_id=INSTALL, agent_ids=[1, 2])
must(run.owner_module == "patchmanagement" and run.schedule.parameters.keys() == {deleg.MARKER_KEY} and deleg.run_is_validly_delegated(run) is True and sched._is_unattended_scheduled_run(run) is True, run.schedule.parameters)
# the system checks still apply
fresh()
sys_save()
sa._ACTIONS[INSTALL] = dataclasses.replace(sa._ACTIONS[INSTALL], delegable_to=())
refused(lambda: call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=SYS_TARGETS), "not_delegable")
fresh()
HONOURED.clear()
refused(lambda: call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=SYS_TARGETS), "replacement_not_honoured")
fresh()
PERSON_LISTED["patchmanagement"] = (INSTALL,)  # listing a system action as a person action changes nothing for it
plugin("patchmanagement", category="premium", replaces="patching", system_actions=[])
refused(lambda: call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=SYS_TARGETS), "action_not_declared")
# a system-action id is never a person action, even when the person-action state would hold
fresh()
deleg.PERSON_ACTION_DELEGATION["maintenance"] = (ACTION, INSTALL)
must(call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id=INSTALL, targets=SYS_TARGETS)["kind"] == "system_action", "the system path decides")
# a write row and a command row are still not delegable
for function, label in (("winupdate.set_action", "write"), ("agent.command", "command")):
    fresh()
    sched.register_scheduled_action(id="patchmanagement.other", module_id="patchmanagement", label="x", handler=lambda c: {}, target_types=("none", "endpoint", "profile"), timeout_seconds=600)
    sa._ACTIONS["patchmanagement.other"] = sa.SystemActionDefinition("patchmanagement.other", "patchmanagement", "x", function, BOTH, "agents", True, None, True, ("maintenance",))
    refused(lambda: call("maintenance", "describe", RealRequest(alice), owner_module="maintenance", provider_module="patchmanagement", action_id="patchmanagement.other", targets=SYS_TARGETS), "not_delegable")
print("       the system-action path answers as before (text, grant, ticket, run, marker); a write and a command row are still not delegable; a system action is never a person action")

# ---- (2) signatures
expect = {
    "describe_delegation": ["request", "owner_module", "provider_module", "action_id", "targets", "parameters"],
    "register_delegation_grant": ["request", "owner_module", "grant_key", "provider_module", "action_id", "targets", "parameters", "confirmation_id"],
    "remove_delegation_grant": ["owner_module", "grant_key"],
    "issue_delegation_ticket": ["context", "grant_key"],
    "start_delegated_run": ["ticket", "action_id", "agent_ids", "name"],
    "resolve_delegated_targets": ["ticket", "action_id", "endpoint_ids"],
}
for name, names in expect.items():
    must(list(inspect.signature(getattr(sa, name)).parameters) == names, (name, list(inspect.signature(getattr(sa, name)).parameters)))
must(list(inspect.signature(sa.register_system_action).parameters) == ["id", "module_id", "label", "function", "permissions", "scope_kind", "dangerous", "username_param", "delegable_to"], "register_system_action")
must(list(inspect.signature(deleg.describe).parameters) == ["request", "owner_module", "provider_module", "action_id", "targets", "parameters"], "delegation.describe")
must(list(inspect.signature(deleg.register).parameters) == ["request", "owner_module", "grant_key", "provider_module", "action_id", "targets", "parameters", "confirmation_id"], "delegation.register")
must(list(inspect.signature(deleg.start).parameters) == ["ticket", "action_id", "agent_ids", "name"] and list(inspect.signature(deleg.resolve_targets).parameters) == ["ticket", "action_id", "endpoint_ids"], "start, resolve_targets")
must(list(inspect.signature(deleg.issue_ticket).parameters) == ["context", "grant_key"] and list(inspect.signature(deleg.remove).parameters) == ["owner_module", "grant_key"], "issue_ticket, remove")
must(list(inspect.signature(sched.register_scheduled_action).parameters)[-2:] == ["unattended", "delegable_to"], "one optional keyword appended")
print("       the signatures of the five delegation functions, resolve_delegated_targets and register_system_action are unchanged; register_scheduled_action gains one optional last keyword")

# ---- (3) capability 1.6.0
must(sa.CAPABILITY_VERSION == "1.6.0", sa.CAPABILITY_VERSION)
must(sa.OPERATIONS == ("list_actions", "get_action", "run", "describe_confirmation", "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket",
                       "start_delegated_run", "run_write", "resolve_delegated_targets", "run_command"), sa.OPERATIONS)
meta = sa.system_actions_contract_metadata()
must(meta["version"] == "1.6.0" and meta["operations"] == list(sa.OPERATIONS), meta["version"])
person = meta["delegation"]["person_actions"]
must(person["since"] == "1.17.111" and person["allowed"] == {"maintenance": [ACTION]} and person["kind"] == "person_action", person)
must(person["parameters"]["key"] == sa.PARAMETERS_KEY and person["parameters"]["max_keys"] == 10 and person["parameters"]["marker_key_refused"] == deleg.MARKER_KEY and "no bypass" in person["permission"], person)
must(meta["delegation"]["grants_per_owner_module"] == 20 and meta["delegation"]["ticket_seconds"] == 86400 and "resolve_delegated_targets" in meta["delegation"]["callers"], "the earlier delegation metadata is kept")
must(">=1.17.111" in meta["requires_framework"] and ">=1.17.74" in meta["requires_framework"], meta["requires_framework"])
rows = {}
import ast  # noqa: E402

for node in ast.walk(ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))):
    if isinstance(node, ast.Dict):
        keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
        if "name" in keys and "purpose" in keys:
            row = {k.value: ast.literal_eval(v) for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value in ("name", "purpose")}
            rows[row["name"]] = row["purpose"]
for name in ("register_scheduled_action", "describe_delegation", "register_delegation_grant", "issue_delegation_ticket", "start_delegated_run", "resolve_delegated_targets", "remove_delegation_grant"):
    must("1.17.111" in rows[name], f"the contract row of {name} says what 1.17.111 changed")
for name in ("register_scheduled_action", "describe_delegation", "register_delegation_grant", "start_delegated_run"):
    must("framework >=1.17.111" in rows[name], f"{name} names the framework it needs")
must("delegable_to" in rows["register_scheduled_action"] and "scheduler_person_actions" in rows["describe_delegation"] and "maintenance" in rows["describe_delegation"] and "wapm.profile-install" in rows["describe_delegation"], "rows name the pair")
overview = [n.value for n in ast.walk(ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("System actions (core.system_actions")]
must(overview and "Since 1.17.111" in overview[0] and "1.6.0" in overview[0], "the system-actions overview row")
DOCS = Path(__file__).resolve().parents[1] / "docs"
for doc in ("system-actions.md", "module-scheduling.md", "capabilities.md"):
    body = (DOCS / doc).read_text(encoding="utf-8")
    must("1.17.111" in body and "wapm.profile-install" in body, f"docs/{doc} says what 1.17.111 added")
must("1.6.0" in (DOCS / "system-actions.md").read_text(encoding="utf-8") and "1.6.0" in (DOCS / "capabilities.md").read_text(encoding="utf-8"), "the capability version is in the documents")
print("       core.system_actions is 1.6.0 with the same operations in the same order; its metadata, the contract rows and the documents describe the person-action rules")
print("PASS delegation person action compat 1.17.111")
