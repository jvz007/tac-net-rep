#!/usr/bin/env python3
"""1.17.16 regression: one correlation id shared across a request or a job (patching 0.3.0 and 0.4.0 requests).

* ``run_tactical_operation(..., correlation_id=)`` is a server-set, Python-only keyword. Every Core row of that call (success,
  deny, outcome-unknown) carries it. A bad value is refused 400 ``invalid_correlation_id``. The HTTP view still refuses a
  client ``correlation_id`` and never forwards one.
* Core has no middleware entry, so the first audit row of a request mints the id and keeps it on the underlying Django request
  (``tec_tac_request_id``). ``audit.request_correlation_id(request)`` returns it, so a module's own parent row and every
  later operation row of the same request share one id. An explicit id beats the request id.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-object-1.17.13.py does.
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
ops, audit, declare, fresh, must = (G[k] for k in ("ops", "audit", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request, DRFWrapper = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request", "DRFWrapper"))
FakeResponse, refusal, route, views = G["FakeResponse"], G["refusal"], G["route"], G["views"]
User, Roleish = G["User"], G["Roleish"]

PATH = f"/agents/{AGENT}/reboot/"


def new_request(user=tech):
    """A request Core has not yet stamped: no id on it."""
    request = Request(user)
    del request.tec_tac_request_id
    return request


def cid(row):
    return row["debug_info"]["correlation_id"]


fresh()
declare()
route(PATH, FakeResponse(200))
PARAMS, BODY = {"agent_id": AGENT}, {"mode": "now"}

# ---- an explicit correlation id lands on a success row
del ROWS[:]
ops.run_tactical_operation(new_request(), "agents", "reboot", PARAMS, BODY, correlation_id="job-42:step.1")
must(len(ROWS) == 1 and cid(ROWS[0]) == "job-42:step.1", ROWS)

# ... on a deny row (Core's own refusal: a role without the Tactical flag)
weak_user = User("weak", Roleish("can_send_wol"))
weak_user.sees = tech.sees
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(new_request(weak_user), "agents", "reboot", PARAMS, BODY, correlation_id="job-42"), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and cid(ROWS[0]) == "job-42", ROWS)

# ... on a deny row for an object outside scope
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(new_request(), "agents", "reboot", {"agent_id": "b" * 21}, BODY, correlation_id="job-42"), 404, "object_not_found")
must(len(ROWS) == 1 and cid(ROWS[0]) == "job-42", ROWS)

# ... on Tactical's own 403 deny row and on both outcome-unknown rows (a 5xx answer, and a view that raises)
for response, boom, action in ((FakeResponse(403, b'"no"'), None, "deny"), (FakeResponse(502, b"x"), None, "custom:outcome-unknown"), (None, RuntimeError("down"), "custom:outcome-unknown")):
    route(PATH, response, boom)
    del ROWS[:]
    try:
        ops.run_tactical_operation(new_request(), "agents", "reboot", PARAMS, BODY, correlation_id="job-42")
    except ops.TacticalOperationError as exc:
        must(exc.code == "tactical_call_failed", exc.code)
    must(len(ROWS) == 1 and ROWS[0]["action"] == action and cid(ROWS[0]) == "job-42", (action, ROWS))
route(PATH, FakeResponse(200))
route(PATH, FakeResponse(200, b'x' * (ops.MAX_RESPONSE_BYTES + 1)))
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(new_request(), "agents", "reboot", PARAMS, BODY, correlation_id="job-42"), 502, "tactical_response_refused")
must(len(ROWS) == 1 and cid(ROWS[0]) == "job-42", "the oversize answer row carries it")
route(PATH, FakeResponse(200))

# ---- bad ids are refused 400 before anything runs or is written
for bad in ("", "x" * 129, "has space", "new\nline", "slash/slash", "ü", 5, ["a"], b"x", True):
    del ROWS[:], CALLS[:]
    exc = refusal(lambda: ops.run_tactical_operation(new_request(), "agents", "reboot", PARAMS, BODY, correlation_id=bad), 400, "invalid_correlation_id")
    must(not ROWS and not CALLS, f"a bad id {bad!r} writes nothing and reaches nothing")
del ROWS[:]
ops.run_tactical_operation(new_request(), "agents", "reboot", PARAMS, BODY, correlation_id="x" * 128)
must(cid(ROWS[0]) == "x" * 128, "128 characters is the limit")

# ---- the HTTP view never carries one
view = views.TacticalOperationView()
reply = view.post(Request(tech, data={"params": PARAMS, "body": BODY, "correlation_id": "evil"}), "agents", "reboot")
must(reply.status_code == 400 and "correlation_id" in reply.data["detail"], reply.__dict__)
reply = view.post(Request(tech, data={"params": PARAMS, "body": BODY, "audit_before": {"a": 1}}), "agents", "reboot")
must(reply.status_code == 400, reply.__dict__)
view_source = (BASE.parent.parent / "framwork/tec_tac/tactical_operation_views.py").read_text(encoding="utf-8")
must("correlation_id=" not in view_source and "audit_before" not in view_source, "the view passes neither keyword to run_tactical_operation")
reply = view.post(Request(tech, data={"params": PARAMS, "body": BODY}), "agents", "reboot")
must(reply.status_code == 200, reply.__dict__)

# ---- per request: two operations and a module's parent row share one id
request = new_request()
del ROWS[:]
parent_id = audit.request_correlation_id(request)
must(parent_id and parent_id == audit.request_correlation_id(request), "stable for the same request")
must(request.tec_tac_request_id == parent_id, "kept on the request")
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)
audit.record(actor=tech, module_id="agents", action="run", object_type="agent", object_id=AGENT, message="bulk parent", request=request)
must(len(ROWS) == 3 and {cid(r) for r in ROWS} == {parent_id}, [cid(r) for r in ROWS])

# without a prior read, the first row mints it and the later rows share it
request = new_request()
del ROWS[:]
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)
audit.record(actor=tech, module_id="agents", action="run", object_type="agent", object_id=AGENT, message="after", request=request)
must(len({cid(r) for r in ROWS}) == 1 and request.tec_tac_request_id == cid(ROWS[0]), [cid(r) for r in ROWS])
first_id = cid(ROWS[0])
must(audit.request_correlation_id(request) == first_id, "a module reading it afterwards gets the same id")

# a second request gets a different id
other = new_request()
must(audit.request_correlation_id(other) != first_id, "another request, another id")

# an explicit id wins over the request id, and does not replace it
request = new_request()
req_id = audit.request_correlation_id(request)
del ROWS[:]
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY, correlation_id="job-7")
ops.run_tactical_operation(request, "agents", "reboot", PARAMS, BODY)
must([cid(r) for r in ROWS] == ["job-7", req_id], [cid(r) for r in ROWS])
must(request.tec_tac_request_id == req_id, "the explicit id never overwrites the request id")

# a DRF wrapper and the request it wraps agree
inner = new_request()
wrapper = DRFWrapper(inner)
wrapper_id = audit.request_correlation_id(wrapper)
must(inner.tec_tac_request_id == wrapper_id and audit.request_correlation_id(inner) == wrapper_id, "stored on the underlying request")

# a browser header is never read
header_request = new_request()
header_request.META["HTTP_X_REQUEST_ID"] = "from-the-browser"
header_request.META["HTTP_X_CORRELATION_ID"] = "from-the-browser"
must(audit.request_correlation_id(header_request) not in ("from-the-browser",), "never from a header")

# no request: a fresh id each time, and nothing breaks
must(audit.request_correlation_id(None) != audit.request_correlation_id(None), "no request, no sharing")
# a request that refuses attributes still gets an id
class Frozen:
    __slots__ = ()
must(audit._correlation_id(Frozen()), "a request that refuses the attribute still gets an id")

# the capability states it
meta = ops.tactical_operations_contract_metadata()
must(meta["version"] == "1.3.0" and "run(correlation_id=)" in meta["declaration_keys_added_in_1_3_0"], meta)

print("[TEST] PASS audit correlation 1.17.16")
