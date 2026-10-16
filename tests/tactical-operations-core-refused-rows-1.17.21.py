#!/usr/bin/env python3
"""1.17.21 regression (globalsettings 0.4.0 build 1, review HIGH; AD-19 condition 4): Core's own pre-dispatch refusal writes one Core row.

Covered, for POST, PUT, PATCH and DELETE and each of the six codes (body_field_not_allowed, invalid_body, invalid_params,
scope_field_required, invalid_correlation_id, invalid_audit_before): exactly one ``custom:operation-failed`` row with the declared
action, ``failure: core_refused``, the code, a fixed Core text, no before or after value, no sentinel from the caller's input anywhere in
the row, the right object id and correlation id, ``core_refusal`` set, and ``error.audit`` as the verdict; Tactical is never dispatched.
Also: a GET refusal writes no row and keeps audit None; the other validation refusals (body_too_large, invalid_upload,
tactical_route_changed) still write none; a caller without the Tactical flag who also sends a bad correlation id gets one deny row that
does not carry the bad id; an unknown operation, a disabled module, a stand-in request and an anonymous user write no row; a failing audit
write returns recorded False and raises nothing else; the view sets X-Tec-Tac-Audit; a module cannot forge the action through
``audit.record``; capability 1.7.0 and its metadata keys; the docs and the contract text carry the behaviour.
Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-failed-rows-1.17.20.py does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, audit, fresh, must = (G[k] for k in ("ops", "audit", "fresh", "must"))
ROWS, CALLS, AGENT, tech, Request, FakeResponse, route, refusal = (G[k] for k in ("ROWS", "CALLS", "AGENT", "tech", "Request", "FakeResponse", "route", "refusal"))
User, Roleish, ENABLED, views, FakeAuditLog = (G[k] for k in ("User", "Roleish", "ENABLED", "views", "FakeAuditLog"))
DRFResponse = G["DRFResponse"]

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "SENTINEL-CALLER-TEXT-7731"
CODES = ("body_field_not_allowed", "invalid_body", "invalid_params", "scope_field_required", "invalid_correlation_id", "invalid_audit_before")
must(tuple(ops.CORE_REFUSAL_ROW_CODES) == CODES, ops.CORE_REFUSAL_ROW_CODES)
must(ops.CORE_REFUSED_MESSAGE == "Core refused this change before sending it to Tactical ({code}); nothing was changed.", ops.CORE_REFUSED_MESSAGE)
PATH = f"/agents/{AGENT}/thing/"
BULK = "/agents/maintenance/bulk/"
manager = User("mgr", Roleish("can_manage_clients"))
manager.sees = {"agents": set(), "clients": {1, 2}, "sites": set()}
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees


def declare_all(method):
    fresh()
    ops.register_tactical_operation(
        id="op", module_id="agents", method=method, route="agents/{agent_id:agent}/thing/", permissions=["can_reboot_agents"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["mode"],
        audit={"action": "modify", "object_type": "agent", "audit_fields": ["mode"]},
    )
    ops.register_tactical_operation(
        id="bulk", module_id="agents", method=method, route="agents/maintenance/bulk/", permissions=["can_manage_clients"],
        scope=[{"type": "client", "source": "body:client_ids"}], body_fields=["client_ids", "action"],
        audit={"action": "modify", "object_type": "client", "audit_fields": ["action"]},
    )
    ops.register_tactical_operation(
        id="note", module_id="agents", method=method, route="agents/{agent_id:agent}/notes/{pk:int}/", permissions=["can_reboot_agents"],
        scope=[], body_fields=["note"], audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk"},
    )
    route(PATH, FakeResponse(200, b'{"ok": true}'))
    route(BULK, FakeResponse(200, b'{"ok": true}'))
    route(f"/agents/{AGENT}/notes/12/", FakeResponse(200, b'{"ok": true}'))


def call(op_id, params=None, body=None, user=tech, **kw):
    del ROWS[:], CALLS[:]
    return ops.run_tactical_operation(Request(user), "agents", op_id, params, body, **kw)


def check_row(code, method, object_id, correlation_id=None, declared="modify"):
    must(len(ROWS) == 1, (method, code, ROWS))
    row = ROWS[0]
    meta = row["debug_info"]["metadata"]
    must(row["action"] == "custom:operation-failed", row)
    must(meta["declared_action"] == declared and meta["result"] == "failed" and meta["failure"] == "core_refused" and meta["code"] == code, meta)
    must(meta["method"] == method and meta["tactical_status"] is None and meta["status"] in (400, 413) and meta["operation"], meta)
    must(row["message"] == ops.CORE_REFUSED_MESSAGE.format(code=code), row["message"])
    must(not row.get("before_value") and not row.get("after_value"), row)
    must(not any(key.startswith("before") for key in meta), meta)
    must(SENTINEL not in json.dumps(row, default=str), "no text from the caller's input is in the row")
    context = row["debug_info"]["operation_context"]
    must(context["core_refusal"] is True and context["server_provenance"] == "tactical-operation", context)
    must(row["debug_info"].get("object_id") == object_id, (code, row["debug_info"]))
    if correlation_id is not None:
        must(row["debug_info"]["correlation_id"] == correlation_id, row["debug_info"])
    must(not CALLS, "Tactical is never dispatched")
    return row


def expect(code, method, run, object_id, correlation_id=None, status=400):
    exc = refusal(run, status, code)
    check_row(code, method, object_id, correlation_id)
    must(exc.audit == {"recorded": True, "id": 7, "action": "custom:operation-failed"}, exc.audit)
    return exc


for method in ("POST", "PUT", "PATCH", "DELETE"):
    declare_all(method)
    P = {"agent_id": AGENT}
    # body_field_not_allowed (the whitelist raise)
    expect("body_field_not_allowed", method, lambda: call("op", P, {"mode": "x", SENTINEL: SENTINEL}), AGENT)
    # invalid_body: not an object, and a body that is not JSON
    expect("invalid_body", method, lambda: call("op", P, [SENTINEL]), AGENT)
    expect("invalid_body", method, lambda: call("op", P, {"mode": object()}), AGENT)
    # invalid_params: an unknown parameter, a bad value, a missing one, not an object. No object id: the parameters are what was refused
    expect("invalid_params", method, lambda: call("op", {"agent_id": AGENT, SENTINEL: "1"}), None)
    expect("invalid_params", method, lambda: call("op", {"agent_id": "a/b" + SENTINEL}), None)
    expect("invalid_params", method, lambda: call("op", {}), None)
    expect("invalid_params", method, lambda: call("op", SENTINEL), None)
    # scope_field_required: a body-sourced scope with the field missing or malformed
    for bad in ({"action": SENTINEL}, {"client_ids": [], "action": SENTINEL}, {"client_ids": [True], "action": SENTINEL}, {"client_ids": ["  "]}):
        expect("scope_field_required", method, lambda bad=bad: call("bulk", {}, bad, user=manager), None)
    # invalid_correlation_id: the row never carries the bad id (it carries the request's own id). 1.17.22: this refusal comes
    # before the path parameters are cleaned, so the row names no object (the raw path value is never used)
    for bad in ("has space", "x" * 129, "new\nline", "ü" + SENTINEL, 5, ["a"]):
        expect("invalid_correlation_id", method, lambda bad=bad: call("op", P, {"mode": SENTINEL}, correlation_id=bad), None, correlation_id="req-1")
        must(not isinstance(bad, str) or bad not in json.dumps(ROWS, default=str), "the bad id is not in the row")
    # invalid_audit_before
    # (1.17.22: this refusal comes before the path parameters are cleaned, so no object id)
    for bad in ("text", {"password": "x"}, {"f": "x" * 257}, {"f": 1.5}, {"nested": {"a": SENTINEL}}):
        expect("invalid_audit_before", method, lambda bad=bad: call("op", P, {"mode": "x"}, audit_before=bad), None)
    # a valid correlation id is carried on the Core row
    expect("invalid_body", method, lambda: call("op", P, [SENTINEL], correlation_id="job-1"), AGENT, correlation_id="job-1")
    # the object id comes from audit.object_param, never from a body field
    expect("invalid_body", method, lambda: call("note", {"agent_id": AGENT, "pk": "12"}, [SENTINEL]), "12")
    must(ROWS[0]["object_type"] == "agent_note", ROWS[0])
    expect("body_field_not_allowed", method, lambda: call("note", {"agent_id": AGENT, "pk": "12"}, {"note": SENTINEL, "other": 1}), "12")
    # the error text is Core's own wording
    exc = refusal(lambda: call("op", P, {SENTINEL: 1}), 400, "body_field_not_allowed")
    must(exc.message.startswith("Body field not allowed"), exc.message)

    # a refusal order: the correlation id is cleaned first at step 5, so it wins over a bad body
    expect("invalid_correlation_id", method, lambda: call("op", P, [SENTINEL], correlation_id="bad id"), None, correlation_id="req-1")

    # 1.17.22 (the held Medium of the 1.17.21 review): a core_refused row never takes its object id from the body, nor from a raw
    # path value that was not cleaned. A bulk operation with a valid body-sourced scope (client 1) gives no object id.
    for bad_body, code in (({"client_ids": ["1"], "action": "x", SENTINEL: 1}, "body_field_not_allowed"),
                           ({"client_ids": ["1", "2"], "action": "x", "extra": 1}, "body_field_not_allowed"),
                           ({"client_ids": ["1"], "action": object()}, "invalid_body")):
        expect(code, method, lambda bad_body=bad_body: call("bulk", {}, bad_body, user=manager), None)
    # a raw path value (a slash and the sentinel) with a bad correlation id gives no object id from the raw value
    expect("invalid_correlation_id", method, lambda: call("op", {"agent_id": "a/b" + SENTINEL}, {"mode": "x"}, correlation_id="bad id"), None, correlation_id="req-1")
    # a valid path parameter and audit.object_param still name the object
    expect("body_field_not_allowed", method, lambda: call("op", P, {SENTINEL: 1}), AGENT)
    expect("invalid_body", method, lambda: call("note", {"agent_id": AGENT, "pk": "12"}, [SENTINEL]), "12")

# ---- a refusal on a GET writes no row and keeps audit None
fresh()
ops.register_tactical_operation(
    id="get", module_id="agents", method="GET", route="agents/{agent_id:agent}/thing/", permissions=["can_reboot_agents"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[], audit={"action": "view", "object_type": "agent"},
)
route(PATH, FakeResponse(200))
for run in (lambda: call("get", {"agent_id": AGENT}, {"x": SENTINEL}), lambda: call("get", {"agent_id": AGENT}, [SENTINEL]),
            lambda: call("get", {"agent_id": "a/b"}), lambda: call("get", {"agent_id": AGENT}, correlation_id="bad id"),
            lambda: call("get", {"agent_id": AGENT}, audit_before=SENTINEL)):
    try:
        run()
        raise AssertionError("a GET refusal was accepted")
    except ops.TacticalOperationError as exc:
        must(exc.audit is None and not ROWS and not CALLS and exc.code in CODES, (exc.code, exc.audit, ROWS))

# ---- the other validation refusals still write none, and keep audit None
declare_all("POST")
ops.register_tactical_operation(
    id="upload", module_id="agents", method="POST", route="agents/{agent_id:agent}/upload/", permissions=["can_reboot_agents"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[], audit={"action": "modify", "object_type": "agent"},
    upload={"field": "file", "max_bytes": 1024, "extensions": ["txt"]},
)
route(f"/agents/{AGENT}/upload/", FakeResponse(200))
exc = refusal(lambda: call("op", {"agent_id": AGENT}, {"mode": "x" * (ops.MAX_BODY_BYTES + 1)}), 413, "body_too_large")
must(exc.audit is None and not ROWS and not CALLS, "body_too_large writes no row")
exc = refusal(lambda: call("upload", {"agent_id": AGENT}, {}), 400, "invalid_upload")
must(exc.audit is None and not ROWS, "invalid_upload writes no row")
G["ROUTES"].clear()
exc = refusal(lambda: call("op", {"agent_id": AGENT}, {"mode": "x"}), 502, "tactical_route_changed")
must(exc.audit is None and not ROWS, "tactical_route_changed writes no row")
declare_all("POST")

# ---- a caller without the Tactical flag who also sends a bad correlation id: one deny row, never the bad id
exc = refusal(lambda: call("op", {"agent_id": AGENT}, {"mode": "x"}, user=weak, correlation_id="bad id" + SENTINEL), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["correlation_id"] == "req-1", ROWS)
must(SENTINEL not in json.dumps(ROWS, default=str) and exc.audit["action"] == "deny" and not CALLS, "no unclean id on the deny row")
exc = refusal(lambda: call("op", {"agent_id": AGENT}, [SENTINEL], user=weak, audit_before="bad"), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", "a permission refusal keeps its one deny row, whatever else is wrong")
# a caller outside the object's scope who also sends a bad body: the scope deny row, not a Core failed row
exc = refusal(lambda: call("op", {"agent_id": "b" * 21}, {"mode": "x"}), 404, "object_not_found")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)

# ---- no row for an unknown operation, a disabled module, a stand-in request or an anonymous user, even with a bad id
for run in (lambda: call("nope", {"agent_id": AGENT}, {"mode": "x"}, correlation_id="bad id"),
            lambda: call("op", {"agent_id": AGENT}, {"mode": "x"}, user=User(anonymous=True, role=tech.role), correlation_id="bad id")):
    del ROWS[:]
    try:
        run()
        raise AssertionError("accepted")
    except ops.TacticalOperationError as exc:
        must(exc.audit is None and not ROWS and exc.code in ("tactical_operation_not_found", "authentication_required"), (exc.code, ROWS))
ENABLED["agents"] = False
exc = refusal(lambda: call("op", {"agent_id": AGENT}, {"mode": "x"}, correlation_id="bad id"), 404, "tactical_operation_not_found")
must(exc.audit is None and not ROWS, "a disabled module writes no row")
ENABLED["agents"] = True
del ROWS[:]
exc = refusal(lambda: ops.run_tactical_operation(SimpleNamespace(user=tech), "agents", "op", {"agent_id": AGENT}, {"mode": "x"}, correlation_id="bad id"), 401, "authenticated_request_required")
must(exc.audit is None and not ROWS, "a stand-in request writes no row")

# ---- a failing audit write: recorded False, and nothing else is raised
FakeAuditLog.objects.fail = True
exc = refusal(lambda: call("op", {"agent_id": AGENT}, [SENTINEL]), 400, "invalid_body")
must(exc.audit["recorded"] is False and exc.audit["action"] == "custom:operation-failed" and not ROWS and not CALLS, exc.audit)  # same verdict shape as every Core row
view = views.TacticalOperationView()
reply = view.post(Request(tech, data={"params": {"agent_id": AGENT}, "body": [SENTINEL]}), "agents", "op")
must(reply.status_code == 400 and reply.data["code"] == "invalid_body" and reply.headers == {"X-Tec-Tac-Audit": "not-recorded"}, reply.__dict__)
FakeAuditLog.objects.fail = False

# ---- the view sets X-Tec-Tac-Audit on the error response
del ROWS[:]
reply = view.post(Request(tech, data={"params": {"agent_id": AGENT}, "body": [SENTINEL]}), "agents", "op")
must(isinstance(reply, DRFResponse) and reply.status_code == 400 and reply.data["code"] == "invalid_body", reply.__dict__)
must(reply.headers == {"X-Tec-Tac-Audit": "recorded"} and len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed", (reply.headers, ROWS))
must(SENTINEL not in json.dumps(reply.data), "the answer repeats no caller text")
del ROWS[:]
reply = view.post(Request(tech, data={"params": {"agent_id": "a/b"}, "body": {"mode": "x"}}), "agents", "op")
must(reply.status_code == 400 and reply.data["code"] == "invalid_params" and reply.headers == {"X-Tec-Tac-Audit": "recorded"}, reply.__dict__)

# ---- the row cannot be forged through audit.record: the action stays Core-only
for spelled in ("custom:operation-failed", " Custom:Operation-Failed "):
    try:
        audit.record(actor=tech, module_id="agents", action=spelled, object_type="agent", metadata={"failure": "core_refused"})
        raise AssertionError("audit.record accepted the Core-only action")
    except audit.AuditContractError as exc:
        must("Core only" in str(exc), str(exc))
try:
    audit.record_browser_declared(actor=tech, module_id="agents", action="custom:operation-failed", object_type="agent")
    raise AssertionError("record_browser_declared accepted the Core-only action")
except audit.AuditContractError:
    pass
# a success still writes the declared action and a 2xx is untouched by the new step order
declare_all("POST")
route(PATH, FakeResponse(200, b'{"ok": true}'))
result = call("op", {"agent_id": AGENT}, {"mode": "now"}, correlation_id="job-2")
must(result.status == 200 and len(ROWS) == 1 and ROWS[0]["action"] == "modify" and ROWS[0]["debug_info"]["correlation_id"] == "job-2", ROWS)

# ---- capability 1.7.0 and its metadata
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.12.0" and meta["version"] == "1.12.0" and meta["version"].split(".")[0] == "1", meta)
must(meta["refusal_row_codes"] == list(CODES) and len(meta["behaviour_added_in_1_7_0"]) == 2, meta)
must(meta["declaration_keys_added_in_1_7_0"] == ["audit.object_field", "audit.object_body_field"], meta)
must("behaviour_added_in_1_6_0" in meta and "custom:operation-failed" in meta["audit_actions_core_only"], "the 1.6.0 keys stay")
json.dumps(meta)

# ---- docs and contract text
docs = (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8")
for needle in ("Added in 1.17.21", "failure: core_refused", "body_field_not_allowed", "invalid_audit_before", "error.audit", "step 5",
               "write no row in this release", "no body, query or upload value", "refusal_row_codes"):
    must(needle in docs, needle)
audit_doc = (ROOT / "docs/module-audit.md").read_text(encoding="utf-8")
must("Core's own refusal row (1.17.21)" in audit_doc and "error.audit" in audit_doc, "module-audit.md")
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
for needle in ("Since 1.17.21 (additive, capability core.tactical_operations 1.7.0)", "core_refused", "error.audit is None", "no deny row carries an invalid correlation id"):
    must(needle in contracts, needle)
print("[TEST] PASS tactical operations core refused rows 1.17.21")
