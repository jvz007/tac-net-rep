#!/usr/bin/env python3
"""1.17.18 regression: several operations on one Tactical route inside the owning module (Johan item 6; CQ60).

``body_selector`` is a list of at most 3 conditions on body fields. Two operations may share one (method, route) only when they
belong to the same module, every operation on the route declares a selector, and every pair is provably exclusive. Core proves
that at registration, in either order. At run time a body that does not satisfy the operation's own selector is refused 400
``body_selector_mismatch`` (a refusal row, no Tactical call). Single declarations, the refusal text for another module and
idempotent re-registration are unchanged. Uses the stubs of tests/tactical-operations-1.17.7.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse, refusal, route = G["FakeResponse"], G["refusal"], G["route"]

ROUTE = "agents/{agent_id:agent}/"
PATH = f"/agents/{AGENT}/"
FIELDS = ["maintenance_mode", "policy", "block_policy_inheritance", "mode"]


def declare(op_id, selector, **over):
    spec = dict(
        id=op_id, module_id="agents", method="PUT", route=ROUTE, permissions=["can_reboot_agents"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=FIELDS,
        audit={"action": "modify", "object_type": "agent", "audit_fields": ["maintenance_mode", "policy"]},
    )
    if selector is not None:
        spec["body_selector"] = selector
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(op_id, selector, text="", **over):
    try:
        declare(op_id, selector, **over)
    except ops.TacticalOperationRegistrationError as exc:
        must(isinstance(exc, ValueError) and text in str(exc), str(exc))
        return str(exc)
    raise AssertionError(f"accepted: {op_id} {selector}")


MAINT = [{"field": "maintenance_mode", "present": True}]
POLICY = [{"field": "maintenance_mode", "present": False}, {"field": "policy", "present": True}]

# ---- two exclusive operations register, in either order
fresh()
declare("set-maintenance", MAINT)
declare("set-policy", POLICY)
must([o["id"] for o in ops.list_operations("agents")] == ["set-maintenance", "set-policy"], ops.list_operations())
fresh()
declare("set-policy", POLICY)
declare("set-maintenance", MAINT)
must(len(ops.list_operations("agents")) == 2, "the other order registers too")
described = ops.get_operation("agents", "set-policy")
must(described["body_selector"] == [{"field": "maintenance_mode", "present": False}, {"field": "policy", "present": True}], described)
# idempotent
declare("set-maintenance", MAINT)
must(len(ops.list_operations("agents")) == 2, "the identical operation again is idempotent")
# equals against equals, and equals against present false
fresh()
declare("a", [{"field": "mode", "equals": "on"}])
declare("b", [{"field": "mode", "equals": "off"}])
declare("c", [{"field": "mode", "present": False}])
must(len(ops.list_operations("agents")) == 3, "equals/equals and equals/absent are exclusive")
# True is not 1
fresh()
declare("flag-on", [{"field": "block_policy_inheritance", "equals": True}])
declare("flag-one", [{"field": "block_policy_inheritance", "equals": 1}])
declare("flag-off", [{"field": "block_policy_inheritance", "equals": False}])
declare("flag-zero", [{"field": "block_policy_inheritance", "equals": 0}])
must(len(ops.list_operations("agents")) == 4, "booleans and whole numbers are different values")
# three operations: every pair must be exclusive
fresh()
declare("p1", [{"field": "mode", "equals": "a"}])
declare("p2", [{"field": "mode", "equals": "b"}])
declare("p3", [{"field": "mode", "equals": "c"}])
must(len(ops.list_operations("agents")) == 3, "three exclusive operations")
refused("p4", [{"field": "mode", "equals": "b"}], "already declared by agents/p2")  # equal to the second
must(len(ops.list_operations("agents")) == 3, "a refusal leaves no trace")

# ---- refusals
fresh()
declare("set-maintenance", MAINT)
text = refused("same-selector", MAINT, "agents/set-maintenance")  # equal selectors
must("provably exclusive" in text, text)
refused("overlap", [{"field": "policy", "present": True}], "provably exclusive")  # no shared field
refused("both-present", [{"field": "maintenance_mode", "present": True}, {"field": "policy", "present": True}], "provably exclusive")
refused("equals-vs-present-true", [{"field": "maintenance_mode", "equals": "x"}], "provably exclusive")  # equals can hold when the field is present
refused("no-selector", None, "One caller per Tactical route (AD-6)")  # a missing selector on the new one
refused("empty-selector", [], "One caller per Tactical route (AD-6)")
# a different module stays refused (AD-6 for modules): the route is not its own, and the message is the old one
text = refused("reboot-clone", MAINT, "", module_id="reportmanager")
must("does not own route" in text, text)
fresh()
declare("no-selector-first", None)  # the first has no selector
refused("later", MAINT, "One caller per Tactical route (AD-6)")  # so the later one is refused whatever it declares
must("agents/no-selector-first" in refused("later", MAINT), "the message names the first")
# a second module on the same route: AD-6 stays. reportmanager cannot own agents/, so use a module that may own the route
fresh()
ops.register_tactical_operation(
    id="r1", module_id="reportmanager", method="POST", route="reporting/things/{pk:int}/", permissions=["can_manage_notes"], scope=[],
    body_fields=["mode"], audit={"action": "modify", "object_type": "thing"}, body_selector=[{"field": "mode", "equals": "a"}],
)
try:
    ops.register_tactical_operation(
        id="r2", module_id="agents", method="POST", route="reporting/things/{pk:int}/", permissions=["can_manage_notes"], scope=[],
        body_fields=["mode"], audit={"action": "modify", "object_type": "thing"}, body_selector=[{"field": "mode", "equals": "b"}],
    )
    raise AssertionError("another module accepted")
except ops.TacticalOperationRegistrationError as exc:
    must("does not own route" in str(exc), str(exc))
# a route owned by two modules is impossible, but the sharing check itself refuses a different holder module
fresh()
declare("holder", MAINT)
holder_key = ("PUT", "agents/{}/")
ops._OPERATIONS[("reportmanager", "intruder")] = ops._OPERATIONS[("agents", "holder")].__class__(
    **{**ops._OPERATIONS[("agents", "holder")].__dict__, "id": "intruder", "module_id": "reportmanager"})
ops._ROUTES[holder_key].append(("reportmanager", "intruder"))
refused("third", POLICY, "")  # a holder from another module on the route refuses the new one
ops._clear_operations_for_tests()

# ---- selector shape
fresh()
for bad, part in (
    ("maintenance_mode", "list of conditions"), ({"field": "mode", "present": True}, "list of conditions"),
    ([{"field": "mode"}], "{field, present} or {field, equals}"),
    ([{"field": "mode", "present": True, "equals": "x"}], "{field, present} or {field, equals}"),
    ([{"field": "mode", "present": True, "extra": 1}], "{field, present} or {field, equals}"),
    ([{"present": True}], "{field, present} or {field, equals}"),
    (["mode"], "{field, present} or {field, equals}"),
    ([{"field": "nope", "present": True}], "not one of body_fields"),
    ([{"field": 5, "present": True}], "not one of body_fields"),
    ([{"field": "mode", "present": "yes"}], "true or false"),
    ([{"field": "mode", "present": 1}], "true or false"),
    ([{"field": "mode", "equals": 1.5}], "string, a whole number or a boolean"),
    ([{"field": "mode", "equals": None}], "string, a whole number or a boolean"),
    ([{"field": "mode", "equals": ["a"]}], "string, a whole number or a boolean"),
    ([{"field": "mode", "present": True}, {"field": "mode", "present": False}], "twice"),
    ([{"field": n, "present": True} for n in FIELDS], "more than 3"),
):
    refused("bad", bad, part)
must(ops.list_operations() == [], "bad selectors leave no trace")
declare("three", [{"field": n, "present": True} for n in FIELDS[:3]])  # exactly 3 is fine
fresh()

# ---- run time: a body that does not fit the operation's selector is refused, no Tactical call
declare("set-maintenance", MAINT)
declare("set-policy", POLICY)
route(PATH, FakeResponse(200))


def call(op, body, user=tech):
    del CALLS[:]
    return ops.run_tactical_operation(Request(user), "agents", op, {"agent_id": AGENT}, body)


del ROWS[:]
must(call("set-maintenance", {"maintenance_mode": True}).status == 200 and len(CALLS) == 1, "fits")
must(call("set-policy", {"policy": 3}).status == 200 and len(CALLS) == 1, "fits")
must(call("set-maintenance", {"maintenance_mode": False}).status == 200, "present with a false value is present")
del ROWS[:]
for op, body in (("set-maintenance", {"policy": 3}), ("set-maintenance", {}), ("set-maintenance", {"maintenance_mode": None}),
                 ("set-policy", {"maintenance_mode": True, "policy": 3}), ("set-policy", {}), ("set-policy", {"policy": None})):
    exc = refusal(lambda op=op, body=body: call(op, body), 400, "body_selector_mismatch")
    must(not CALLS, f"{op} {body}: Tactical is not called")
    must(exc.message == ops.MESSAGES["body_selector_mismatch"], exc.message)
must(len(ROWS) == 6 and all(r["action"] == "deny" for r in ROWS), "each mismatch writes a refusal row")
must(ROWS[0]["debug_info"]["metadata"]["reason"] == "body_selector_mismatch" and ROWS[0]["debug_info"]["metadata"]["status"] == 400, ROWS[0]["debug_info"])
must(ROWS[0]["debug_info"]["metadata"]["refused_action"] == "modify" and ROWS[0]["debug_info"]["object_id"] == AGENT, ROWS[0]["debug_info"])
# a call can never run under the wrong operation's scope or verb: the check precedes the scope check
OTHER = G["OTHER"]
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "set-policy", {"agent_id": OTHER}, {"maintenance_mode": True}), 400, "body_selector_mismatch")
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "set-policy", {"agent_id": OTHER}, {"policy": 1}), 404, "object_not_found")
# equals at run time: True is not 1
fresh()
declare("on", [{"field": "block_policy_inheritance", "equals": True}])
declare("off", [{"field": "block_policy_inheritance", "equals": False}])
route(PATH, FakeResponse(200))
must(call("on", {"block_policy_inheritance": True}).status == 200 and call("off", {"block_policy_inheritance": False}).status == 200, "fits")
for op, value in (("on", 1), ("on", "true"), ("off", 0), ("off", None), ("on", False)):
    refusal(lambda op=op, value=value: call(op, {"block_policy_inheritance": value}), 400, "body_selector_mismatch")

# ---- an operation with no selector never checks one, and a single declaration is unchanged
fresh()
declare("plain", None)
route(PATH, FakeResponse(200))
must(call("plain", {}).status == 200 and call("plain", {"policy": 1}).status == 200, "no selector, no check")
must(ops.get_operation("agents", "plain")["body_selector"] == [], "describe lists an empty selector")
refused("clone", None, "agents/plain")  # the 'already declared' refusal for a second caller is unchanged
declare("plain", None)  # and re-registering is idempotent

print("[TEST] PASS tactical operations body selector 1.17.18")
