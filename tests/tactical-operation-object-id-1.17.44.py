#!/usr/bin/env python3
"""1.17.44 (globalsettings 0.3.0 (a), scriptmanager 0.4.4) audit.object_id, and the two held findings of the Core 1.17.43 review.

audit.object_id is a fixed text declared by the module, for an operation with no path parameter that names the object (a settings
save, a test email, the server script test). It is the last fallback for the row's object id and, being declared text and never
caller or body input, it names the object on every row of that operation: success, deny (permission and Tactical), failed,
outcome-unknown and core_refused. Covered: registration (accepted on a POST, refused on a GET, on a secret-looking text, on a
space, a slash, over 64 characters or a non-string, and together with object_param, object_field or object_body_field), every row
kind with the literal, a core_refused row never carrying a body value, an operation with a scope object still naming that id,
describe(), get_operation and list_operations carrying audit.object_id and audit.secret_fields (held Medium of 1.17.43), a secret
field equal to audit.object_field refused (held Low of 1.17.43), and the capability 1.14.0 with its contract metadata.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operation-secret-fields-1.17.43.py does.
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
ops, declare, must, fresh, refused = (G[k] for k in ("ops", "declare", "must", "fresh", "refused"))
ROUTES, CALLS, ROWS, AGENT, Request, route = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

LITERAL = "tactical-settings"
SENTINEL = "SENTINEL-BODY-VALUE-9f3"
PATH = "/core/codesign/"
signer = User("signer", Roleish("can_code_sign"))
weak = User("weak", Roleish())
agent_user = G["tech"]


def settings_decl(**over):
    spec = dict(
        id="save-settings", module_id="licensing", method="POST", route="core/codesign/", permissions=["can_code_sign"], scope=[],
        body_fields=["mode", "name"], audit={"action": "modify", "object_type": "setting", "audit_fields": ["mode"], "object_id": LITERAL},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run(user=signer, body=None, params=None, module="licensing", operation="save-settings"):
    del CALLS[:]
    return ops.run_tactical_operation(Request(user), module, operation, params or {}, body if body is not None else {"mode": "x"})


def object_id_of(row):
    return row["debug_info"]["object_id"]


def one_row(action):
    must(len(ROWS) == 1, [r["action"] for r in ROWS])
    must(ROWS[0]["action"] == action, (action, ROWS[0]["action"]))
    return ROWS[0]


# (1) registration: accepted on a POST, refused for each wrong reason
fresh()
op = settings_decl()
must(op.audit_object_id == LITERAL, op.audit_object_id)
fresh()
settings_decl(id="plain", audit={"action": "modify", "object_type": "setting"})
must(ops.get_operation("licensing", "plain")["audit"]["object_id"] is None, "an old declaration has no literal")
REFUSALS = [
    ("a GET operation changes nothing, so it has no audit.object_id",
     dict(id="g", method="GET", route="core/codesign/status/", body_fields=[], audit={"action": "view", "object_type": "setting", "object_id": LITERAL})),
    ("looks like a secret", dict(id="s1", audit={"action": "modify", "object_type": "setting", "object_id": "secret-store"})),
    ("looks like a secret", dict(id="s2", audit={"action": "modify", "object_type": "setting", "object_id": "api-token"})),
    ("must be a plain text", dict(id="b1", audit={"action": "modify", "object_type": "setting", "object_id": "has space"})),
    ("must be a plain text", dict(id="b2", audit={"action": "modify", "object_type": "setting", "object_id": "a/b"})),
    ("must be a plain text", dict(id="b3", audit={"action": "modify", "object_type": "setting", "object_id": "x" * 65})),
    ("must be a plain text", dict(id="b4", audit={"action": "modify", "object_type": "setting", "object_id": ""})),
    ("must be a plain text", dict(id="b5", audit={"action": "modify", "object_type": "setting", "object_id": 5})),
    ("must be a plain text", dict(id="b6", audit={"action": "modify", "object_type": "setting", "object_id": "-leading"})),
    ("only source of the object id", dict(id="p1", route="agents/{agent_id:agent}/reboot/", module_id="agents", permissions=["can_reboot_agents"],
                                           scope=[{"type": "agent", "source": "path:agent_id"}],
                                           audit={"action": "run", "object_type": "agent", "object_param": "agent_id", "object_id": LITERAL})),
    ("only source of the object id", dict(id="p2", audit={"action": "modify", "object_type": "setting", "object_field": "name", "object_id": LITERAL})),
    ("only source of the object id", dict(id="p3", audit={"action": "modify", "object_type": "setting", "object_body_field": "name", "object_id": LITERAL})),
]
for phrase, over in REFUSALS:
    fresh()
    text = refused(**{"module_id": "licensing", "method": "POST", "route": "core/codesign/", "permissions": ["can_code_sign"], "scope": [],
                      "body_fields": ["mode", "name"], **over})
    must(phrase in text, (phrase, text))
print(f"       registration: accepted on a POST, refused for each of {len(REFUSALS)} wrong cases, each for its own reason")
fresh()
text = refused(module_id="licensing", id="unk", method="POST", route="core/codesign/", permissions=["can_code_sign"], scope=[], body_fields=[],
               audit={"action": "modify", "object_type": "setting", "object_idd": LITERAL})
must("object_id" in text, text)
print("       the unknown audit key message names object_id")

# (2) the success row names the literal
fresh()
settings_decl()
route(PATH, FakeResponse(200, b'{"ok": true}'))
del ROWS[:]
must(run().status == 200, "ran")
row = one_row("modify")
must(object_id_of(row) == LITERAL, row["debug_info"])
print("       success row: object id is the literal")

# (3) a Tactical 403 writes a deny row with the literal
route(PATH, FakeResponse(403, b'{"detail": "no"}'))
del ROWS[:]
run()
row = one_row("deny")
must(object_id_of(row) == LITERAL, row["debug_info"])
print("       Tactical 403: deny row carries the literal")

# (3b) a permission refusal (before Tactical is reached) also names it
del ROWS[:]
refusal(lambda: run(user=weak), 403, "tactical_permission_denied")
row = one_row("deny")
must(object_id_of(row) == LITERAL and not CALLS, (row["debug_info"], len(CALLS)))
print("       permission refusal: deny row carries the literal")

# (4) a 4xx writes a failed row with it
route(PATH, FakeResponse(409, b'{"detail": "conflict"}'))
del ROWS[:]
run()
row = one_row("custom:operation-failed")
must(object_id_of(row) == LITERAL, row["debug_info"])
print("       Tactical 409: failed row carries the literal")

# (5) a 500, a raised call and a refused stream write outcome-unknown rows with it
for label, response, boom in (("500", FakeResponse(500, b"{}"), None), ("raised", None, RuntimeError("boom")),
                              ("stream", FakeResponse(200, b"x", streaming=True), None)):
    route(PATH, response, boom)
    del ROWS[:]
    if label in ("raised", "stream"):
        refusal(lambda: run(), 502, "tactical_call_failed" if label == "raised" else "tactical_response_refused")
    else:
        run()
    row = one_row("custom:outcome-unknown")
    must(object_id_of(row) == LITERAL, (label, row["debug_info"]))
print("       outcome-unknown rows (500, raised call, refused stream): the literal")

# (6) a refused body writes a core_refused row with the literal and never a body value
route(PATH, FakeResponse(200, b'{"ok": true}'))
del ROWS[:]
exc = refusal(lambda: run(body={"mode": "x", "other": SENTINEL, SENTINEL: SENTINEL}), 400, "body_field_not_allowed")
row = one_row("custom:operation-failed")
must(row["debug_info"]["metadata"]["failure"] == "core_refused", row["debug_info"]["metadata"])
must(object_id_of(row) == LITERAL, row["debug_info"])
must(SENTINEL not in json.dumps(ROWS, default=str), "no body key or value in the row")
del ROWS[:]
refusal(lambda: run(body={"mode": {"nested": SENTINEL}, "name": SENTINEL, "extra": 1}), 400, "body_field_not_allowed")
must(object_id_of(one_row("custom:operation-failed")) == LITERAL and SENTINEL not in json.dumps(ROWS, default=str), "second refusal")
print("       core_refused row: the literal, never a body value")

# (7) a scope object or object_param still names that id: the literal never wins
fresh()
declare(id="reboot-lit", audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"], "object_id": "agent-reboot"})
route(f"/agents/{AGENT}/reboot/", FakeResponse(200, b'{"ok": true}'))
del ROWS[:]
run(user=agent_user, module="agents", operation="reboot-lit", params={"agent_id": AGENT}, body={"mode": "now"})
row = one_row("run")
must(object_id_of(row) == AGENT, row["debug_info"])
del ROWS[:]
refusal(lambda: run(user=agent_user, module="agents", operation="reboot-lit", params={"agent_id": AGENT}, body={SENTINEL: 1}), 400, "body_field_not_allowed")
must(object_id_of(one_row("custom:operation-failed")) == AGENT, "the path-sourced scope names the core_refused row, not the literal")
print("       a scope object still names the row (the literal is the last fallback)")

# (8) describe, get_operation and list_operations carry audit.object_id and audit.secret_fields
fresh()
settings_decl(id="with-secret", body_fields=["mode", "name", "token"],
              audit={"action": "modify", "object_type": "setting", "audit_fields": ["mode"], "object_id": LITERAL, "secret_fields": ["token"]})
settings_decl(id="old-style", method="PUT", audit={"action": "modify", "object_type": "setting", "audit_fields": ["mode"]})
got = ops.get_operation("licensing", "with-secret")["audit"]
must(got["object_id"] == LITERAL and got["secret_fields"] == ["token"], got)
listed = {item["id"]: item["audit"] for item in ops.list_operations("licensing")}
must(listed["with-secret"]["secret_fields"] == ["token"] and listed["with-secret"]["object_id"] == LITERAL, listed["with-secret"])
must(listed["old-style"]["secret_fields"] == [] and listed["old-style"]["object_id"] is None, listed["old-style"])
must(all(isinstance(name, str) and "value" not in name for name in got["secret_fields"]), "field names only")
for key in ("action", "object_type", "audit_fields", "object_param", "before", "params", "object_field", "object_body_field", "lists"):
    must(key in got, f"the audit block still has {key}")
print("       describe, get_operation and list_operations: audit.object_id and audit.secret_fields")

# (9) held Low of 1.17.43: a secret field equal to audit.object_field is refused, another object_field is accepted
fresh()
text = refused(module_id="licensing", id="sec-obj", method="PUT", route="core/codesign/", permissions=["can_code_sign"], scope=[],
               body_fields=["value", "name"], audit={"action": "modify", "object_type": "setting", "object_field": "value", "secret_fields": ["value"]})
must("is the object id or a body scope source" in text, text)
fresh()
ok = ops.register_tactical_operation(
    id="sec-obj-ok", module_id="licensing", method="PUT", route="core/codesign/", permissions=["can_code_sign"], scope=[],
    body_fields=["value", "name"], audit={"action": "modify", "object_type": "setting", "object_field": "name", "secret_fields": ["value"]})
must(ok.secret_fields == ("value",) and ok.audit_object_field == "name", ok)
print("       secret field equal to audit.object_field refused; a different object_field accepted")

# (10) the capability and the contract metadata
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.14.0" and meta["version"] == "1.14.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(meta["declaration_keys_added_in_1_13_0"] and "audit.object_id" in meta["declaration_keys_added_in_1_13_0"][0], meta)
text = " ".join(meta["behaviour_added_in_1_13_0"])
for needle in ("every row", "core_refused", "last fallback", "audit.secret_fields", "audit.object_field"):
    must(needle in text, f"the metadata says {needle!r}")
must(G["CAPS"][-1]["version"] == "1.14.0" if G.get("CAPS") and G["CAPS"][-1]["id"] == "core.tactical_operations" else True, "registered version")
print("       capability 1.14.0 and the contract metadata name audit.object_id")

print("[TEST] PASS tactical operation object id 1.17.44")
