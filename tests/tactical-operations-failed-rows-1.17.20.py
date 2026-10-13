#!/usr/bin/env python3
"""1.17.20 regression (CQ63 b, AD-19 condition 4 as amended 11 October 2026): a failed attempt on a Tactical change writes one Core row with its own action.

Covered: 400, 404, 409, 422 and 429 on POST, PUT, PATCH and DELETE each write exactly one ``custom:operation-failed`` row with the
declared action in metadata, ``result: failed``, the Tactical status, no before and no after value, no Tactical text, the object id
and the correlation id; a filter on the declared action matches none; a GET 4xx writes none; 401 and 403 still write ``deny``; a 5xx
and a transport error still write ``custom:outcome-unknown``; a failed audit write reports not-recorded and never raises; Core-only
audit actions cannot be declared; the public ``audit.record`` refuses ``custom:operation-failed`` (and still accepts
``custom:outcome-unknown``); the capability is 1.6.0; the docs and the contract text carry the behaviour. Uses the stubs of tests/tactical-operations-1.17.7.py.
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
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROWS, AGENT, tech, Request, FakeResponse, route, refusal = (G[k] for k in ("ROWS", "AGENT", "tech", "Request", "FakeResponse", "route", "refusal"))
FakeAuditLog = G["FakeAuditLog"]

must(ops.FAILED_ACTION == "custom:operation-failed", ops.FAILED_ACTION)
SECRET = b'{"detail": "TACTICAL-SECRET-TEXT agent-hostname"}'
PATH = f"/agents/{AGENT}/thing/"


def declare(op_id, method, action="modify"):
    return ops.register_tactical_operation(
        id=op_id, module_id="agents", method=method, route="agents/{agent_id:agent}/thing/", permissions=["can_reboot_agents"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["mode"] if method != "GET" and method != "DELETE" else [],
        audit={"action": action, "object_type": "agent", "audit_fields": ["mode"] if method not in ("GET", "DELETE") else []},
    )


def call(op_id, method, correlation_id="corr-1"):
    del ROWS[:]
    body = {"mode": "now"} if method not in ("GET", "DELETE") else None
    return ops.run_tactical_operation(Request(tech), "agents", op_id, {"agent_id": AGENT}, body, correlation_id=correlation_id)


for method in ("POST", "PUT", "PATCH", "DELETE"):
    for status in (400, 404, 409, 422, 429):
        fresh()
        declare("op", method)
        route(PATH, FakeResponse(status, SECRET))
        result = call("op", method)
        must(result.status == status, (method, status))
        must(len(ROWS) == 1, (method, status, ROWS))
        row = ROWS[0]
        meta = row["debug_info"]["metadata"]
        must(row["action"] == "custom:operation-failed", row)
        must(meta["declared_action"] == "modify" and meta["result"] == "failed" and meta["failure"] == "tactical_refused", meta)
        must(meta["tactical_status"] == status and meta["operation"] == "op" and meta["method"] == method, meta)
        must(not row.get("before_value") and not row.get("after_value"), row)
        must(not any(key.startswith("before") for key in meta), meta)
        must("TACTICAL-SECRET-TEXT" not in json.dumps(row, default=str) and "hostname" not in json.dumps(row, default=str), "no Tactical text")
        must(row["debug_info"]["object_id"] == AGENT and row["debug_info"]["correlation_id"] == "corr-1", row)
        must(row["message"] == ops.FAILED_MESSAGE.format(status=status), row["message"])
        must(not [r for r in ROWS if r["action"] == "modify"], "a filter on the declared action matches nothing")
        must(result.audit.get("recorded") is True and result.audit.get("action") == "custom:operation-failed", result.audit)

# a GET 4xx writes no row
fresh()
declare("get", "GET")
route(PATH, FakeResponse(404, SECRET))
result = call("get", "GET")
must(result.status == 404 and not ROWS and result.audit == {}, ROWS)

# 401 and 403 are still deny rows; 5xx and a transport error are still outcome-unknown
fresh()
declare("op", "POST")
for response, boom, expected in ((FakeResponse(401, b'"x"'), None, "deny"), (FakeResponse(403, b'"x"'), None, "deny"),
                                 (FakeResponse(500, b'"x"'), None, "custom:outcome-unknown"), (FakeResponse(503, b'"x"'), None, "custom:outcome-unknown"),
                                 (None, RuntimeError("down"), "custom:outcome-unknown")):
    route(PATH, response, boom)
    del ROWS[:]
    try:
        call("op", "POST")
    except ops.TacticalOperationError:
        pass
    must(len(ROWS) == 1 and ROWS[0]["action"] == expected, (expected, ROWS))

# a failed audit write is reported, never raised
route(PATH, FakeResponse(409, b'"x"'))
FakeAuditLog.objects.fail = True
result = call("op", "POST")
must(result.status == 409 and result.audit.get("recorded") is False, result.audit)
FakeAuditLog.objects.fail = False

# a module cannot declare a Core-only audit action
for action in ("deny", "custom:outcome-unknown", "custom:operation-failed"):
    try:
        ops.register_tactical_operation(
            id="bad", module_id="agents", method="POST", route="agents/{agent_id:agent}/bad/", permissions=["can_reboot_agents"],
            scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[], audit={"action": action, "object_type": "agent"},
        )
        raise AssertionError(f"accepted {action}")
    except ops.TacticalOperationRegistrationError as exc:
        must("written by Core only" in str(exc), str(exc))

# the public audit writer refuses Core's failed action, so a module cannot forge it; outcome-unknown stays open to a module
audit = G["audit"] if "audit" in G else __import__("importlib").import_module("tec_tac.audit")
for spelled in ("custom:operation-failed", " Custom:Operation-Failed "):
    try:
        audit.record(actor=tech, module_id="agents", action=spelled, object_type="agent")
        raise AssertionError("record accepted custom:operation-failed")
    except audit.AuditContractError as exc:
        must("Core only" in str(exc), str(exc))
try:
    audit.record_browser_declared(actor=tech, module_id="agents", action="custom:operation-failed", object_type="agent")
    raise AssertionError("record_browser_declared accepted custom:operation-failed")
except audit.AuditContractError:
    pass
del ROWS[:]
accepted = audit.record(actor=tech, module_id="agents", action="custom:outcome-unknown", object_type="agent")
must(accepted.get("recorded") is True and len(ROWS) == 1, accepted)

# capability 1.7.0 (1.17.21; the 1.6.0 behaviour stays), still major 1
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.9.0" and meta["version"] == "1.9.0" and meta["version"].split(".")[0] == "1", meta)  # 1.17.21: 1.7.0
must("custom:operation-failed" in meta["audit_actions_core_only"] and meta["behaviour_added_in_1_6_0"], meta)  # the 1.6.0 keys stay

contracts = (Path(__file__).resolve().parents[1] / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("custom:operation-failed" in contracts and "Any other 4xx: no row." not in contracts and "writes no row (AD-19 condition 4" not in contracts, "contract text")
docs = (Path(__file__).resolve().parents[1] / "docs/tactical-operations.md").read_text(encoding="utf-8")
must("custom:operation-failed" in docs and "declared_action" in docs and "1.8.0" in docs[:400] and "1.6.0" in docs, "the docs describe the failed row")
must("writes nothing (AD-19" not in docs and "Any other 4xx writes nothing" not in docs, "docs no longer say other 4xx write nothing")
print("[TEST] PASS tactical operations failed rows 1.17.20")
