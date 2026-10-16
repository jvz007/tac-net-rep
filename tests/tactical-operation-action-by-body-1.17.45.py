#!/usr/bin/env python3
"""1.17.45 audit.action_by_body (reviews/requests/core.md, 'from patching 0.3.0', per-call audit action).

The success row's audit action is chosen from the cleaned value of one body field through a declared map. Covered: registration
(accepted, and refused for a field outside body_fields, a secret field, a GET, an empty map, more than 8 entries, a key that is not text
or is over 40 characters, an action outside the vocabulary, deny, custom:outcome-unknown, custom:operation-failed and an unknown shape),
the success row for a matched value, an unmatched, missing and non-text value, the failed and outcome-unknown rows carrying the chosen
action in metadata.declared_action, a deny row and a core_refused row keeping their own action, an operation without the key writing the
rows it always did, describe(), get_operation, list_operations and the capability 1.14.0.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operation-object-id-1.17.44.py does.
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
ops, must, fresh, refused = (G[k] for k in ("ops", "must", "fresh", "refused"))
CALLS, ROWS, Request, route = (G[k] for k in ("CALLS", "ROWS", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

PATH = "/core/codesign/"
signer = User("signer", Roleish("can_code_sign"))
weak = User("weak", Roleish())
MAP = {"approve": "approve", "ignore": "modify", "later": "custom:patch-later"}


def decl(**over):
    audit = {"action": "run", "object_type": "patch", "audit_fields": ["name"], "action_by_body": {"field": "action", "map": dict(MAP)}}
    spec = dict(id="set-action", module_id="licensing", method="POST", route="core/codesign/", permissions=["can_code_sign"], scope=[],
                body_fields=["action", "name", "token"], audit=audit)
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def bad(phrase, **over):
    fresh()
    text = refused(**{"module_id": "licensing", "method": "POST", "route": "core/codesign/", "permissions": ["can_code_sign"], "scope": [],
                      "body_fields": ["action", "name", "token"], **over})
    must(phrase in text, (phrase, text))


def audit_of(**abb):
    return {"action": "run", "object_type": "patch", "action_by_body": abb}


def run(body, user=signer, operation="set-action"):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(user), "licensing", operation, {}, body)


def meta_of(row):
    return row["debug_info"]["metadata"]


# (1) registration
fresh()
op = decl()
must(op.audit_action_by_body == ("action", (("approve", "approve"), ("ignore", "modify"), ("later", "custom:patch-later"))), op.audit_action_by_body)
bad("is not one of body_fields", id="r1", audit=audit_of(field="nope", map={"a": "approve"}))
bad("is a secret field", id="r2", audit={**audit_of(field="token", map={"a": "approve"}), "secret_fields": ["token"]})
bad("belongs to an operation with a body", id="r3", method="GET", route="core/codesign/status/", body_fields=[],
    audit={"action": "view", "object_type": "patch", "action_by_body": {"field": "action", "map": {"a": "view"}}})
bad("non-empty object", id="r4", audit=audit_of(field="action", map={}))
bad("non-empty object", id="r4b", audit=audit_of(field="action", map=["approve"]))
bad("more than 8 entries", id="r5", audit=audit_of(field="action", map={f"k{i}": "approve" for i in range(9)}))
bad("1 to 40 characters", id="r6", audit=audit_of(field="action", map={"k" * 41: "approve"}))
bad("1 to 40 characters", id="r7", audit=audit_of(field="action", map={5: "approve"}))
bad("1 to 40 characters", id="r7b", audit=audit_of(field="action", map={"": "approve"}))
bad("standard Tec-Tac audit vocabulary", id="r8", audit=audit_of(field="action", map={"a": "bogus"}))
bad("Core writes those only", id="r9", audit=audit_of(field="action", map={"a": "deny"}))
bad("Core writes those only", id="r10", audit=audit_of(field="action", map={"a": "custom:outcome-unknown"}))
bad("Core writes those only", id="r11", audit=audit_of(field="action", map={"a": "custom:operation-failed"}))
bad("is {field, map}", id="r12", audit=audit_of(field="action", map={"a": "approve"}, extra=1))
bad("is {field, map}", id="r13", audit={"action": "run", "object_type": "patch", "action_by_body": "action"})
bad("must be a body field name", id="r14", audit=audit_of(field="bad name", map={"a": "approve"}))
fresh()
decl(audit={"action": "run", "object_type": "patch", "action_by_body": {"field": "action", "map": {f"k{i}": "approve" for i in range(8)}}})
print("       registration: accepted, refused for each of 16 wrong cases (8 entries is the most)")

# (2) the success row follows the body
fresh()
decl()
decl(id="plain", method="PUT", audit={"action": "run", "object_type": "patch", "audit_fields": ["name"]})
route(PATH, FakeResponse(200, b'{"ok": true}'))
for body, want in (({"action": "approve"}, "approve"), ({"action": "ignore"}, "modify"), ({"action": "later"}, "custom:patch-later"),
                   ({"action": "other"}, "run"), ({"name": "x"}, "run"), ({"action": 5}, "run"), ({"action": None}, "run"),
                   ({"action": ["approve"]}, "run"), ({"action": "APPROVE"}, "run")):
    must(run(body).status == 200, body)
    must(len(ROWS) == 1 and ROWS[0]["action"] == want, (body, [r["action"] for r in ROWS]))
run({"action": "approve"}, operation="plain")
must(ROWS[0]["action"] == "run", "an operation without the key keeps audit.action")
print("       success row: mapped action, or audit.action for an unmatched, missing, non-text or other-case value")

# (3) failed and outcome-unknown rows carry the chosen action; deny and core_refused keep their own
route(PATH, FakeResponse(409, b'{"detail": "conflict"}'))
run({"action": "approve"})
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta_of(ROWS[0])["declared_action"] == "approve", ROWS)
run({"action": "bogus"})
must(meta_of(ROWS[0])["declared_action"] == "run", "an unmatched value keeps the default on a failed row")
for label, response, boom in (("500", FakeResponse(500, b"{}"), None), ("raised", None, RuntimeError("boom")),
                              ("stream", FakeResponse(200, b"x", streaming=True), None)):
    route(PATH, response, boom)
    if label == "500":
        run({"action": "ignore"})
    else:
        refusal(lambda: run({"action": "ignore"}), 502, "tactical_call_failed" if label == "raised" else "tactical_response_refused")
    must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown" and meta_of(ROWS[0])["declared_action"] == "modify", (label, ROWS))
route(PATH, FakeResponse(403, b'{"detail": "no"}'))
run({"action": "approve"})
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and "declared_action" not in meta_of(ROWS[0]), ROWS)
del ROWS[:]
refusal(lambda: run({"action": "approve"}, user=weak), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and "declared_action" not in meta_of(ROWS[0]), "a permission deny row keeps deny")
route(PATH, FakeResponse(200, b"{}"))
refusal(lambda: run({"action": "approve", "stray": 1}), 400, "body_field_not_allowed")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta_of(ROWS[0])["failure"] == "core_refused", ROWS)
must(meta_of(ROWS[0])["declared_action"] == "run", "a core_refused row is written before the body is trusted: the default action")
route(PATH, FakeResponse(500, b"{}"))
run({"action": "approve"}, operation="plain")
must(ROWS[0]["action"] == "custom:outcome-unknown" and "declared_action" not in meta_of(ROWS[0]), "no key for an operation without action_by_body")
print("       failed and outcome-unknown rows: metadata.declared_action; deny and core_refused rows keep their own action")

# (4) describe, get_operation, list_operations
got = ops.get_operation("licensing", "set-action")["audit"]
must(got["action_by_body"] == {"field": "action", "map": MAP} and got["action"] == "run", got)
listed = {item["id"]: item["audit"] for item in ops.list_operations("licensing")}
must(listed["set-action"]["action_by_body"] == {"field": "action", "map": MAP} and listed["plain"]["action_by_body"] is None, listed)
print("       describe, get_operation and list_operations show audit.action_by_body")

# (5) the capability
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.14.0" and meta["version"] == "1.14.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(len(meta["declaration_keys_added_in_1_14_0"]) == 2 and "audit.action_by_body" in meta["declaration_keys_added_in_1_14_0"][0], meta)
must(any("action_by_body" in text for text in meta["behaviour_added_in_1_14_0"]), meta)
print("       capability 1.14.0 and the contract metadata name audit.action_by_body")
print("[TEST] PASS tactical operation action_by_body 1.17.45")
