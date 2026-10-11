#!/usr/bin/env python3
"""1.17.18 regression: ``audit.params`` records named path parameters in the row's after value (Johan item 7; take-control
Web VNC port, remote-background pid).

Covered: the port is recorded on the success row and on no other row kind, an unknown name, a secret-looking name, a name that is
also an audit field and more than 8 names are refused at registration, an operation without ``audit.params`` writes exactly the old
after value, params alone give a dict (no declared audit fields), and params combine with ``audit_fields``. Uses the stubs of
tests/tactical-operations-1.17.7.py.
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

ROUTE = "agents/{agent_id:agent}/vnc/{port:int}/{mode}/"
PATH = f"/agents/{AGENT}/vnc/5900/rdp/"


def declare(op_id="vnc", params=None, fields=("note",), **over):
    audit = {"action": "run", "object_type": "agent", "audit_fields": list(fields)}
    if params is not None:
        audit["params"] = params
    spec = dict(id=op_id, module_id="agents", method="POST", route=ROUTE, permissions=["can_reboot_agents"],
                scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["note", "other"], audit=audit)
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(text, **kw):
    try:
        declare(**kw)
    except ops.TacticalOperationRegistrationError as exc:
        must(text in str(exc), str(exc))
        return
    raise AssertionError(f"accepted: {kw}")


def call(body=None, params=None):
    del ROWS[:], CALLS[:]
    return ops.run_tactical_operation(Request(tech), "agents", "vnc", params or {"agent_id": AGENT, "port": 5900, "mode": "rdp"}, body or {"note": "hi"})


# ---- registration
fresh()
refused("not a parameter of the route", params=["nope"])
refused("invalid name", params=["Port"])  # case matters: names are lower case
refused("invalid name", params=["bad name"])
refused("invalid name", params=[5])
refused("invalid name", params=["x" * 40])
refused("must be a list of names", params="port")
refused("repeats", params=["port", "port"])
for secretive in ("token", "api_key", "password", "secret", "cookie", "auth"):
    refused("looks like a secret", params=[secretive], route=f"agents/{{agent_id:agent}}/vnc/{{{secretive}:int}}/")
try:
    ops.register_tactical_operation(
        id="clash", module_id="agents", method="POST", route="agents/{agent_id:agent}/vnc/{port:int}/", permissions=["can_reboot_agents"],
        scope=[], body_fields=["port"], audit={"action": "run", "object_type": "agent", "audit_fields": ["port"], "params": ["port"]},
    )
    raise AssertionError("a name that is both a body field and a param was accepted")
except ops.TacticalOperationRegistrationError as exc:
    must("also an audit param" in str(exc), str(exc))
# more than 8 names
nine = "agents/{agent_id:agent}/a/{p0}/{p1}/{p2}/{p3}/{p4}/{p5}/{p6}/"
try:
    ops.register_tactical_operation(
        id="nine", module_id="agents", method="POST", route=nine, permissions=["can_reboot_agents"], scope=[], body_fields=[],
        audit={"action": "run", "object_type": "agent", "params": ["agent_id", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"]},
    )
    raise AssertionError("more than 8 params accepted")
except ops.TacticalOperationRegistrationError as exc:
    must("more than 8" in str(exc), str(exc))
ok8 = ops.register_tactical_operation(
    id="eight", module_id="agents", method="POST", route=nine, permissions=["can_reboot_agents"], scope=[], body_fields=[],
    audit={"action": "run", "object_type": "agent", "params": ["agent_id", "p0", "p1", "p2", "p3", "p4", "p5", "p6"]},
)
must(len(ok8.audit_params) == 8, "8 names are accepted")
must(ops.list_operations("agents")[0]["audit"]["params"] == list(ok8.audit_params), "describe lists the params")
fresh()
must(ops.list_operations() == [], "no refused declaration left a trace")

# ---- the port is recorded on success, and on no other row kind
declare(params=["port"])
route(PATH, FakeResponse(200))
call()
must(len(ROWS) == 1 and ROWS[0]["action"] == "run", ROWS)
must(ROWS[0]["after_value"] == {"note": "hi", "port": "5900"}, ROWS[0]["after_value"])
must(ROWS[0]["debug_info"]["metadata"].get("port") is None, "the row metadata does not change")
for response, boom, expected in ((FakeResponse(403, b'"no"'), None, "deny"), (FakeResponse(500, b"x"), None, "custom:outcome-unknown"), (None, RuntimeError("down"), "custom:outcome-unknown")):
    route(PATH, response, boom)
    del ROWS[:]
    try:
        call()
    except ops.TacticalOperationError:
        pass
    must(len(ROWS) == 1 and ROWS[0]["action"] == expected and not ROWS[0].get("after_value"), (expected, ROWS))
route(PATH, FakeResponse(404, b'"missing"'))
call()
must(not ROWS, "another 4xx writes no row")
# a refusal by Core writes no params either
weak = G["User"]("weak", G["Roleish"]("can_send_wol"))
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(Request(weak), "agents", "vnc", {"agent_id": AGENT, "port": 5900, "mode": "rdp"}, {"note": "x"}), 403, "tactical_permission_denied")
must(ROWS and not ROWS[0].get("after_value") and ROWS[0]["action"] == "deny", ROWS)

# ---- params only (no audit_fields): the row still gets a dict
fresh()
declare(params=["port", "mode"], fields=())
route(PATH, FakeResponse(200))
call(body={})
must(ROWS[0]["after_value"] == {"port": "5900", "mode": "rdp"}, ROWS[0]["after_value"])
# the value is the cleaned one (shape-checked, printable)
route("/agents/" + AGENT + "/vnc/7/ssh/", FakeResponse(200))
call(params={"agent_id": AGENT, "port": " 7 ", "mode": "ssh"}, body={})
must(ROWS[0]["after_value"] == {"port": "7", "mode": "ssh"}, ROWS[0]["after_value"])
# a bad value never reaches the row: the call is refused first
refusal(lambda: call(params={"agent_id": AGENT, "port": "5900/../x", "mode": "rdp"}, body={}), 400, "invalid_params")

# ---- no audit.params: exactly the old after value
fresh()
declare(params=None)
route(PATH, FakeResponse(200))
call()
must(ROWS[0]["after_value"] == {"note": "hi"}, ROWS[0]["after_value"])
fresh()
declare(params=None, fields=())
route(PATH, FakeResponse(200))
call(body={})
must(not ROWS[0].get("after_value"), "nothing declared, nothing recorded")
fresh()
declare(params=[], fields=())
route(PATH, FakeResponse(200))
call(body={})
must(not ROWS[0].get("after_value"), "an empty params list records nothing")
must(ops.get_operation("agents", "vnc")["audit"]["params"] == [], "describe lists an empty list")

print("[TEST] PASS tactical operations audit params 1.17.18")
