#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.74 regression (AD-43; CQ213 and CQ215 are open): a delegation grant names a task row only, and Core has no command kind or reboot row.

Held on review: a reboot of up to 40 000 endpoints, sent by Core itself or started by Maintenance with nobody signed in, is a safety decision that Johan has not signed. Covered:
the table has the four rows of 1.17.70 and no reboot or command row; register_system_action refuses the function key agents.reboot; there is no KIND_COMMAND, no system_commands
module and no nats_cmd call in the framework; the kind check of delegation.py names the task kind only; a write row is not_delegable (by registration and by the kind check); an
install (a task row) is still delegable and its Yes or No text is the one of 1.17.68; a delegation grant for a function that does not exist is refused.
"""
from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

H = Path(__file__).resolve().parent / "delegated-targets-harness-1.17.74.py"
exec(compile(H.read_text(encoding="utf-8"), str(H), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

# ---- no command kind, no reboot row
must(set(sa.SYSTEM_FUNCTIONS) == {"winupdate.scan", "winupdate.install", "scripts.run", "winupdate.set_action"}, sorted(sa.SYSTEM_FUNCTIONS))
must(not hasattr(sa, "KIND_COMMAND") and not hasattr(sa, "_sent_result") and {row.kind for row in sa.SYSTEM_FUNCTIONS.values()} == {"task", "write"}, "no command kind")
must(not (APP / "system_commands.py").exists(), "no system_commands.py")
for path in APP.glob("*.py"):
    text = path.read_text(encoding="utf-8")
    must("nats_cmd" not in text.replace("nats_cmd is never", "") and "rebootnow" not in text and "KIND_COMMAND" not in text, f"{path.name} sends a command")
fresh(3)
PLUGINS["patchmanagement"].system_actions = (ACTION, "patchmanagement.reboot")
try:
    sa.register_system_action("patchmanagement.reboot", "patchmanagement", "Reboot", "agents.reboot", ("can_reboot_agents", "can_run_bulk"), dangerous=True, delegable_to=("maintenance",))
    raise AssertionError("agents.reboot was registered")
except sa.SystemActionRegistrationError:
    pass
meta = sa.system_actions_contract_metadata()
must("command" not in meta and "kinds" not in meta and "agents.reboot" not in meta["functions"] and "delegable_kinds" not in meta["delegation"], "the metadata names no command")
must(meta["delegation"]["callers"]["resolve_delegated_targets"] == "provider module named by the grant", meta["delegation"])
print("       the table has no reboot or command row; agents.reboot cannot be registered; the framework sends no command")

# ---- the kind check: task only
src = inspect.getsource(deleg._provider_action)
must("entry.kind != _sa.KIND_TASK" in src and "KIND_COMMAND" not in src and "KIND_WRITE" not in src, "the kind check names the task kind only")
delegation_source = (APP / "delegation.py").read_text(encoding="utf-8")
must("KIND_COMMAND" not in delegation_source and "confirmation_line" not in delegation_source and "a command is sent" not in delegation_source, "delegation.py has no command text")

# a write row is never delegated, even for a definition that named a delegate
fresh(3)
PLUGINS["patchmanagement"].system_actions = (ACTION, "patchmanagement.setaction")
sa.register_system_action("patchmanagement.setaction", "patchmanagement", "APM decisions", "winupdate.set_action", ("can_manage_winupdates",), dangerous=True)
sched.register_scheduled_action(id="patchmanagement.setaction", module_id="patchmanagement", label="w", handler=lambda context: None, target_types=("none", "endpoint"), timeout_seconds=600)
try:
    sa.register_system_action("patchmanagement.setaction", "patchmanagement", "APM decisions", "winupdate.set_action", ("can_manage_winupdates",), dangerous=True, delegable_to=["maintenance"])
    raise AssertionError("a write row with delegable_to was registered")
except sa.SystemActionRegistrationError:
    pass
del AUDITS[:]
delegation_refused(lambda: deleg._provider_action("maintenance", "patchmanagement", "patchmanagement.setaction"), "not_delegable")
sa._ACTIONS["patchmanagement.setaction"] = replace(sa._ACTIONS["patchmanagement.setaction"], delegable_to=("maintenance",))
delegation_refused(lambda: deleg._provider_action("maintenance", "patchmanagement", "patchmanagement.setaction"), "not_delegable")
print("       the kind check names the task kind only; a write row is not_delegable by registration and by the kind check")

# ---- an install (a task row) is still delegable, with the text of 1.17.68
fresh(3)
base = dict(owner_module="maintenance", provider_module="patchmanagement", action_id=ACTION, targets=TARGETS, parameters=None)
described = mods["maintenance"]["describe"](sa, RealRequest(alice), **base)
must(described["required"] is True and "sent to Tactical" in described["text"] and "a command is sent" not in described["text"] and "restart at once" not in described["text"], described["text"])
fresh(3, delegable=())
delegation_refused(lambda: mods["maintenance"]["describe"](sa, RealRequest(alice), **base), "not_delegable")
print("       an install row is delegable only when its provider named Maintenance, and its Yes or No text is unchanged")
print("delegated-targets-task-only-1.17.74: ok")
