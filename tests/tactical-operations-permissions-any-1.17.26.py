#!/usr/bin/env python3
"""1.17.26 regression: any-of Tactical permissions for a declared operation (from reportmanager 0.5.0; Tactical's GenerateReportPerms is
view OR manage).

``register_tactical_operation(..., permissions_any=[...])`` needs at least one of the listed flags, combined with the all-of
``permissions``. ``permissions`` may be empty only when ``permissions_any`` is given. Covered: a role with only the second flag passes; a role
with neither gets 403 ``tactical_permission_denied`` naming both flags and one deny row that carries ``needs_one_of``; all-of plus any-of
combine (the missing all-of flag is named with the any-of list); an empty ``permissions`` with no ``permissions_any`` is still refused;
bad flag names, a repeated flag, a flag in both lists, a string, and a flag that is not a boolean Role field are refused; an operation
declared the old way gives the same 403 text and the same row as before (no needs_one_of key); describe() and the contract export show the
list; the old declaration compares equal to itself (idempotent) and a different permissions_any is a different definition; a superuser
passes. Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-before-lists-1.17.23.py does.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, declare, refused, fresh, must = (G[k] for k in ("ops", "declare", "refused", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "Request"))
FakeResponse, refusal, route, User, Roleish = G["FakeResponse"], G["refusal"], G["route"], G["User"], G["Roleish"]

G["Role"].FIELDS.update({"can_view_reports": "BooleanField", "can_manage_reports": "BooleanField", "can_run_reports": "BooleanField"})
PATH = f"/agents/{AGENT}/reboot/"
PARAMS, BODY = {"agent_id": AGENT}, {"mode": "now"}


def person(*flags, **kw):
    user = User("p", Roleish(*flags, **kw))
    user.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}
    return user


def run(user, operation="reboot"):
    del CALLS[:]
    return ops.run_tactical_operation(Request(user), "agents", operation, PARAMS, BODY)


def declare_any(**over):
    spec = dict(permissions=[], permissions_any=["can_view_reports", "can_manage_reports"])
    spec.update(over)
    return declare(**spec)


# ---- the capability
must(ops.CAPABILITY_VERSION == "1.9.0" and ops.tactical_operations_contract_metadata()["version"].split(".")[0] == "1", ops.CAPABILITY_VERSION)
info = ops.tactical_operations_contract_metadata()
must(info["declaration_keys_added_in_1_9_0"] == ["permissions_any", "body_max_bytes"] and info["behaviour_added_in_1_9_0"], info)
must("permissions_any=None" in info["declaration"], "the declaration line shows the keyword")

# ---- any-of alone: either flag passes, neither is refused with both named
fresh()
op = declare_any()
must(op.permissions == () and op.permissions_any == ("can_view_reports", "can_manage_reports"), op)
route(PATH, FakeResponse(200))
must(run(person("can_view_reports")).status == 200, "the first flag")
must(run(person("can_manage_reports")).status == 200, "only the second flag passes")
must(run(person("can_view_reports", "can_manage_reports")).status == 200, "both flags")
del ROWS[:]
exc = refusal(lambda: run(person("can_reboot_agents")), 403, "tactical_permission_denied")
must(exc.message == ops.MESSAGES["permission_denied"] + " It needs one of can_view_reports, can_manage_reports.", exc.message)
must(not CALLS, "Tactical is never reached")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
meta = ROWS[0]["debug_info"]["metadata"]
must(meta["reason"] == "permission_denied" and meta["needs_one_of"] == ["can_view_reports", "can_manage_reports"], meta)
must(ROWS[0]["message"] == ops.DENY_MESSAGES["permission_denied"], "the deny row keeps its fixed wording")
# a person with no role at all is refused the same way
refusal(lambda: run(User("norole", None)), 403, "tactical_permission_denied")

# ---- all-of plus any-of combine
fresh()
declare_any(permissions=["can_reboot_agents"])
route(PATH, FakeResponse(200))
must(run(person("can_reboot_agents", "can_manage_reports")).status == 200, "all-of and one any-of")
exc = refusal(lambda: run(person("can_manage_reports")), 403, "tactical_permission_denied")
must(exc.message.endswith("It needs the Tactical permission can_reboot_agents."), exc.message)  # the any-of is met, only the all-of is named
exc = refusal(lambda: run(person("can_reboot_agents")), 403, "tactical_permission_denied")
must(exc.message.endswith("It needs one of can_view_reports, can_manage_reports."), exc.message)
exc = refusal(lambda: run(person("can_send_wol")), 403, "tactical_permission_denied")
must(exc.message.endswith("It needs the Tactical permission can_reboot_agents and one of can_view_reports, can_manage_reports."), exc.message)
fresh()
declare_any(permissions=["can_reboot_agents", "can_send_wol"])
exc = refusal(lambda: run(person()), 403, "tactical_permission_denied")
must(exc.message.endswith("It needs the Tactical permissions can_reboot_agents, can_send_wol and one of can_view_reports, can_manage_reports."), exc.message)

# ---- registration rules
fresh()
must(refused(permissions=[], permissions_any=None) == "permissions must list at least one Tactical Role flag.", "empty permissions alone is refused")
must(refused(permissions=[], permissions_any=[]) == "permissions must list at least one Tactical Role flag.", "empty both is refused")
for bad in (["reboot"], ["can_nothing"], ["name"], ["is_superuser"], ["can_view_clients"], [""], [None], [5], "can_view_reports", ["can_view_reports", "can_view_reports"],
            ["Can_view_reports"], ["can_x"] * 9):
    refused(permissions=["can_reboot_agents"], permissions_any=bad)
text = refused(permissions=["can_reboot_agents"], permissions_any=["can_reboot_agents", "can_view_reports"])
must("repeats" in text and "can_reboot_agents" in text, text)
must(not ops.list_operations(), "nothing was registered by a refused declaration")
# at most 8 flags, like permissions
declare_any(permissions_any=[f"can_{n}" for n in ("view_reports", "manage_reports", "run_reports", "reboot_agents", "send_wol", "manage_notes", "manage_clients", "list_agents")])
fresh()
refused(permissions_any=["can_view_reports", "can_manage_reports", "can_run_reports", "can_reboot_agents", "can_send_wol", "can_manage_notes",
                         "can_manage_clients", "can_list_agents", "can_code_sign"])

# ---- an old-style declaration is unchanged: same text, same row, no needs_one_of
fresh()
old = declare()
must(old.permissions == ("can_reboot_agents",) and old.permissions_any == () and old.body_max_bytes is None, old)
route(PATH, FakeResponse(200))
del ROWS[:]
exc = refusal(lambda: run(person("can_send_wol")), 403, "tactical_permission_denied")
must(exc.message == ops.MESSAGES["permission_denied"] + " It needs the Tactical permission can_reboot_agents.", exc.message)
meta = ROWS[0]["debug_info"]["metadata"]
must("needs_one_of" not in meta and meta["reason"] == "permission_denied", meta)
must(run(person("can_reboot_agents")).status == 200, "an old declaration still runs")

# ---- the listing and the exported contract show it
fresh()
declare_any()
described = ops.get_operation("agents", "reboot")
must(described["permissions"] == [] and described["permissions_any"] == ["can_view_reports", "can_manage_reports"], described)
must(ops.list_operations()[0]["permissions_any"] == ["can_view_reports", "can_manage_reports"], "list_operations shows it")
fresh()
declare()
must(ops.get_operation("agents", "reboot")["permissions_any"] == [], "an old declaration lists an empty any-of")

# ---- idempotent re-registration and a different any-of is a different definition
fresh()
first = declare_any()
must(declare_any() == first, "the identical declaration is idempotent")
try:
    declare_any(permissions_any=["can_view_reports"])
except ops.TacticalOperationRegistrationError as exc:
    must("already registered with a different definition" in str(exc), exc)
else:
    raise AssertionError("a different permissions_any must not re-register")

# ---- docs and the contract text
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("permissions_any", "needs_one_of", "1.9.0", "GenerateReportPerms"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("capability core.tactical_operations 1.9.0" in contract and "permissions_any" in contract and "needs_one_of" in contract, "contracts.py rule text")

print("[TEST] PASS tactical operations permissions any 1.17.26")
