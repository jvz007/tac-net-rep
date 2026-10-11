#!/usr/bin/env python3
"""1.17.18 regression: ``caller_scope="unrestricted"`` on a Tactical operation (Johan item 3; automation run-task and
agent-management bulk recovery).

An operation declared for callers with no client or site limits is refused 403 ``scope_unrestricted_required`` for a limited
caller, with a Core deny row and no call to Tactical. A superuser and an unrestricted role run it. A failing scope lookup, a
caller with no role and an installer user all fail closed. An invalid value is refused at registration, and an operation
without the keyword behaves as before. Uses the stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, declare, fresh, must, refused = (G[k] for k in ("ops", "declare", "fresh", "must", "refused"))
CALLS, ROWS, AGENT, tech, Request, User, Roleish = (G[k] for k in ("CALLS", "ROWS", "AGENT", "tech", "Request", "User", "Roleish"))
FakeResponse, refusal, route, run, adapter = G["FakeResponse"], G["refusal"], G["route"], G["run"], G["adapter"]

LOOKUPS = []
resources = types.ModuleType("tec_tac.resources")


def scope_unrestricted(context):
    LOOKUPS.append(context.user.username)
    if getattr(context.user, "break_scope", False):
        raise RuntimeError("lookup failed")
    return adapter.role_scope_descriptor(context.user)["unrestricted"]


resources.user_context = lambda user: SimpleNamespace(user=user)
resources.scope_unrestricted = scope_unrestricted
sys.modules["tec_tac.resources"] = resources

fresh()
PATH = f"/agents/{AGENT}/wol/"
route(PATH, FakeResponse(200))
FLAGS = ("can_send_wol",)


def declare_wol(**over):
    spec = dict(id="wol", route="agents/{agent_id:agent}/wol/", permissions=["can_send_wol"], body_fields=[], audit={"action": "run", "object_type": "agent"})
    spec.update(over)
    return declare(**spec)


# ---- registration
for bad in ("limited", "Unrestricted", "", 1, True, ["unrestricted"]):
    refused(id="badscope", route="agents/{agent_id:agent}/wol/", permissions=["can_send_wol"], body_fields=[], audit={"action": "run", "object_type": "agent"}, caller_scope=bad)
op = declare_wol(caller_scope="unrestricted")
must(op.caller_scope == "unrestricted", op)
must(ops.get_operation("agents", "wol")["caller_scope"] == "unrestricted", "describe lists caller_scope")
fresh()
declare_wol()
must(ops.get_operation("agents", "wol")["caller_scope"] is None, "no keyword, no rule")
fresh()
declare_wol(caller_scope="unrestricted")
route(PATH, FakeResponse(200))


def limited(name="limited"):
    role = Roleish(*FLAGS)
    role.can_view_clients = [1]  # a client-limited role
    user = User(name, role)
    user.sees = tech.sees
    return user


def run_wol(user, **kw):
    return run(user=user, params={"agent_id": AGENT}, module="agents", operation="wol", **kw)


# ---- a limited caller is refused, with a deny row, and Tactical is never called
del ROWS[:], LOOKUPS[:]
exc = refusal(lambda: run_wol(limited()), 403, "scope_unrestricted_required")
must(not CALLS, "Tactical is never called")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
info = ROWS[0]["debug_info"]
must(info["metadata"]["reason"] == "scope_unrestricted_required" and info["metadata"]["status"] == 403 and info["object_id"] == AGENT, info)
must(info["metadata"]["refused_action"] == "run", info["metadata"])
must(ROWS[0]["message"] == ops.DENY_MESSAGES["scope_unrestricted_required"], ROWS[0])
must(exc.message == ops.MESSAGES["scope_unrestricted_required"] and "all clients and sites" in exc.message, exc.message)
must(exc.audit == {"recorded": True, "id": 7, "action": "deny"}, exc.audit)

# ---- unrestricted callers run
del ROWS[:]
unrestricted = User("open", Roleish(*FLAGS))  # no client or site relations: Tactical's unrestricted rule
unrestricted.sees = tech.sees
must(run_wol(unrestricted).status == 200 and CALLS, "an unrestricted role runs")
must(run_wol(User("root", None, superuser=True)).status == 200, "a superuser runs")
must(run_wol(User("rolesu", Roleish(superuser=True))).status == 200, "a role superuser runs")

# ---- fail closed
broken = limited("broken")
broken.break_scope = True
open_but_broken = User("openbroken", Roleish(*FLAGS))
open_but_broken.break_scope = True
open_but_broken.sees = tech.sees
for who in (broken, open_but_broken):
    del ROWS[:], CALLS[:]
    refusal(lambda who=who: run_wol(who), 403, "scope_unrestricted_required")
    must(not CALLS and ROWS[0]["action"] == "deny", "a failing scope lookup refuses")
# a caller with no role is refused earlier by the Tactical flag (also fail closed)
refusal(lambda: run_wol(User("norole", None)), 403, "tactical_permission_denied")

# ---- the order: Tactical flag first (no scope lookup), then the rule, before the body is cleaned
del ROWS[:], LOOKUPS[:]
weak = User("weak", Roleish("can_reboot_agents"))
refusal(lambda: run_wol(weak), 403, "tactical_permission_denied")
must(not LOOKUPS, "the scope is read only after the Tactical flag passes")
del ROWS[:]
refusal(lambda: run(user=limited("lim2"), params={"agent_id": "bad id"}, module="agents", operation="wol"), 403, "scope_unrestricted_required")
must(ROWS and ROWS[0]["action"] == "deny", "refused before the params are cleaned")

# ---- an operation without the keyword is unchanged (a limited caller runs it, scope decides)
fresh()
declare_wol(id="wol2", route="agents/{agent_id:agent}/wol/", scope=[{"type": "agent", "source": "path:agent_id"}])
route(PATH, FakeResponse(200))
must(run(user=limited("lim3"), params={"agent_id": AGENT}, module="agents", operation="wol2").status == 200, "no caller_scope: unchanged")

print("[TEST] PASS tactical operations unrestricted caller scope 1.17.18")
