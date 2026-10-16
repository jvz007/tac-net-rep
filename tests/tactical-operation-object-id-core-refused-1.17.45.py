#!/usr/bin/env python3
"""1.17.45 held Low of the Core 1.17.44 review: a core_refused row names the declared audit.object_id on every refusal code.

1.17.44 said audit.object_id names the object on every row, but a core_refused row for invalid_correlation_id, invalid_audit_before or
invalid_params was written before the path parameters were cleaned and carried no id. It now carries the declared literal, which is
declared text from the module's signed code and never caller input. Covered: each of the three refusals with a literal, the same three
for an operation with a path-sourced scope and a literal (the cleaned path id still wins once the parameters are clean, the literal
before), an operation with no literal still writing no id on those rows, the other core_refused codes unchanged, and no caller value
(correlation id, audit_before value, parameter) in the row.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operation-object-id-1.17.44.py does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, declare, must, fresh = (G[k] for k in ("ops", "declare", "must", "fresh"))
CALLS, ROWS, AGENT, Request, route = (G[k] for k in ("CALLS", "ROWS", "AGENT", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

LITERAL = "tactical-settings"
SENTINEL = "SENTINEL-CALLER-VALUE-77c"
PATH = "/core/codesign/"
signer = User("signer", Roleish("can_code_sign"))
agent_user = G["tech"]


def settings_decl(**over):
    spec = dict(
        id="save-settings", module_id="licensing", method="POST", route="core/codesign/", permissions=["can_code_sign"], scope=[],
        body_fields=["mode", "name"], audit={"action": "modify", "object_type": "setting", "audit_fields": ["mode"], "object_id": LITERAL},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run(params=None, body=None, **extra):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(signer), "licensing", "save-settings", params if params is not None else {}, body if body is not None else {"mode": "x"}, **extra)


def one_refused_row(code):
    must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed", [r["action"] for r in ROWS])
    meta = ROWS[0]["debug_info"]["metadata"]
    must(meta["failure"] == "core_refused" and meta["code"] == code, meta)
    must(not CALLS, "Tactical was never called")
    must(SENTINEL not in json.dumps(ROWS, default=str), "no caller value in the row")
    return ROWS[0]["debug_info"].get("object_id")


CASES = (
    ("invalid_correlation_id", lambda: run(correlation_id=f"bad id {SENTINEL}!")),
    ("invalid_audit_before", lambda: run(audit_before={"mode": {"nested": SENTINEL}})),
    ("invalid_audit_before", lambda: run(audit_before={"api_token": SENTINEL})),
    ("invalid_params", lambda: run(params={SENTINEL: "1"})),
    ("invalid_params", lambda: run(params={"x": SENTINEL})),
)

# (1) an operation with a literal: every early refusal names it
fresh()
settings_decl()
route(PATH, FakeResponse(200, b'{"ok": true}'))
for code, call in CASES:
    refusal(call, 400, code)
    must(one_refused_row(code) == LITERAL, code)
print("       invalid_correlation_id, invalid_audit_before and invalid_params rows carry the declared literal")

# (2) the other core_refused codes still carry it (1.17.44), and a clean call still names it
refusal(lambda: run(body={"mode": "x", SENTINEL: 1}), 400, "body_field_not_allowed")
must(one_refused_row("body_field_not_allowed") == LITERAL, "body_field_not_allowed")
refusal(lambda: run(body=["x"]), 400, "invalid_body")
must(one_refused_row("invalid_body") == LITERAL, "invalid_body")
must(run().status == 200 and ROWS[0]["debug_info"]["object_id"] == LITERAL, "a success row names the literal")
print("       the other core_refused codes and the success row still carry it")

# (3) a path-sourced scope with a literal: the literal before the parameters are clean, the path id after
fresh()
declare(id="reboot-lit", audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"], "object_id": "agent-reboot"})
route(f"/agents/{AGENT}/reboot/", FakeResponse(200, b'{"ok": true}'))


def run_agent(params, body=None, **extra):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(agent_user), "agents", "reboot-lit", params, body if body is not None else {"mode": "now"}, **extra)


refusal(lambda: run_agent({"agent_id": AGENT}, correlation_id="bad id!"), 400, "invalid_correlation_id")
must(one_refused_row("invalid_correlation_id") == "agent-reboot", "an early refusal names the literal")
refusal(lambda: run_agent({"agent_id": "a/b"}), 400, "invalid_params")
must(one_refused_row("invalid_params") == "agent-reboot", "bad parameters name the literal, never the bad value")
refusal(lambda: run_agent({"agent_id": AGENT}, body={SENTINEL: 1}), 400, "body_field_not_allowed")
must(one_refused_row("body_field_not_allowed") == AGENT, "clean parameters: the path-sourced scope names the row, as before")
print("       with a path scope: the literal before the parameters are clean, the path id after")

# (4) no literal: those rows still carry no id, as before
fresh()
settings_decl(id="save-settings", audit={"action": "modify", "object_type": "setting", "audit_fields": ["mode"]})
route(PATH, FakeResponse(200, b'{"ok": true}'))
for code, call in CASES:
    refusal(call, 400, code)
    must(one_refused_row(code) is None, code)
print("       an operation with no audit.object_id writes no id on those rows (unchanged)")
print("[TEST] PASS tactical operation object id on early core_refused rows 1.17.45")
