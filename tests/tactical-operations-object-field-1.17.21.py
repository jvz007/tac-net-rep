#!/usr/bin/env python3
"""1.17.21 regression (scriptmanager 0.4.0 and checks 0.14.0; Johan CQ66 b): an object id for a create row.

Two optional keys in the audit declaration: ``object_field`` (a top-level scalar of Tactical's JSON answer) and ``object_body_field`` (a
cleaned body field that must be in body_fields). Covered: object_body_field gives the success row's object id and object_source body;
object_field gives it from a JSON answer and wins over the body field when both are declared; a non-object answer, a missing field, a
bool, a float, a list, a dict or a null falls back to the body field and then to None; a non-JSON answer is not read; object_param and a
scope object still win; a Tactical 4xx row, a deny row, a core_refused row and an outcome-unknown row carry no such id; a long or
control-character value is cleaned and cut; registration refuses a GET operation, a name outside the field pattern, a secret-looking
name, an object_body_field that is not in body_fields and a repeated definition with different keys; an operation declared the 1.17.20
way is unchanged (equality, describe); describe lists both keys; the docs and the contract text carry both; the row carries no body value
beyond the declared audit_fields. Uses the stubs of tests/tactical-operations-1.17.7.py.
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
ROWS, CALLS, AGENT, tech, Request, FakeResponse, route, refusal = (G[k] for k in ("ROWS", "CALLS", "AGENT", "tech", "Request", "FakeResponse", "route", "refusal"))
User, Roleish = G["User"], G["Roleish"]

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "BODY-NAME-SENTINEL"
NEW = "/agents/newthing/"
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees


def declare(op_id="make", route_="agents/newthing/", method="POST", scope=(), audit_extra=None, body_fields=("name", "kind"), **over):
    audit = {"action": "add", "object_type": "agent_thing", "audit_fields": ["kind"]}
    audit.update(audit_extra or {})
    spec = dict(
        id=op_id, module_id="agents", method=method, route=route_, permissions=["can_reboot_agents"], scope=list(scope),
        body_fields=list(body_fields), audit=audit,
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(**kw):
    try:
        declare(**kw)
    except ops.TacticalOperationRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {kw}")


def call(op_id="make", params=None, body=None, user=tech, **kw):
    del ROWS[:], CALLS[:]
    return ops.run_tactical_operation(Request(user), "agents", op_id, params, body, **kw)


def meta(row):
    return row["debug_info"]["metadata"]


def oid(row):
    return row["debug_info"].get("object_id")


BODY = {"name": SENTINEL, "kind": "k"}

# ---- object_body_field alone
fresh()
declare(audit_extra={"object_body_field": "name"})
route(NEW, FakeResponse(200, b'{"detail": "created"}'))
result = call(body=BODY)
must(result.status == 200 and len(ROWS) == 1 and oid(ROWS[0]) == SENTINEL and meta(ROWS[0])["object_source"] == "body", ROWS)
must(ROWS[0]["action"] == "add" and ROWS[0]["after_value"] == {"kind": "k"}, "no body value beyond the declared audit_fields")
must(SENTINEL not in json.dumps(ROWS[0]["after_value"]) and SENTINEL not in ROWS[0]["message"], "the name is the object id and nothing else")
# a missing, null, bool, float, list or dict body value gives no id and no object_source
for bad in ({"kind": "k"}, {"name": None, "kind": "k"}, {"name": True, "kind": "k"}, {"name": 1.5, "kind": "k"}, {"name": ["a"], "kind": "k"},
            {"name": {"a": 1}, "kind": "k"}, {"name": "", "kind": "k"}, {"name": "  ", "kind": "k"}, {"name": "\x01\x02", "kind": "k"}):
    call(body=bad)
    must(len(ROWS) == 1 and oid(ROWS[0]) is None and "object_source" not in meta(ROWS[0]), (bad, ROWS))
# a whole number is read as text
call(body={"name": 77, "kind": "k"})
must(oid(ROWS[0]) == "77" and meta(ROWS[0])["object_source"] == "body", ROWS)
# control characters are dropped and a long value is cut at 255
call(body={"name": "ab\x00c\nd\x7fe", "kind": "k"})
must(oid(ROWS[0]) == "abcde", ROWS[0])
call(body={"name": "x" * 400, "kind": "k"})
must(oid(ROWS[0]) == "x" * 255, len(oid(ROWS[0])))
call(body={"name": "  padded  ", "kind": "k"})
must(oid(ROWS[0]) == "padded", ROWS[0])

# ---- object_field alone: from a JSON answer
fresh()
declare(audit_extra={"object_field": "id"})
for payload, expected in ((b'{"id": 42}', "42"), (b'{"id": "abc-1"}', "abc-1"), (b'{"id": 0}', "0"), (b'{"id": 1.5}', None), (b'{"id": true}', None),
                          (b'{"id": null}', None), (b'{"id": {"a": 1}}', None), (b'{"id": [1]}', None), (b'{"other": 1}', None), (b'[{"id": 1}]', None),
                          (b'"just a string"', None), (b'', None), (b'not json', None), (b'{"nested": {"id": 5}}', None)):
    route(NEW, FakeResponse(200, payload))
    call(body=BODY)
    must(len(ROWS) == 1 and oid(ROWS[0]) == expected, (payload, ROWS[0]["debug_info"]))
    must(("object_source" in meta(ROWS[0])) == (expected is not None) and meta(ROWS[0]).get("object_source", "answer") == "answer", meta(ROWS[0]))
# a non-JSON answer is not read, whatever it looks like
route(NEW, FakeResponse(200, b'{"id": 5}', content_type="text/plain"))
call(body=BODY)
must(oid(ROWS[0]) is None, "a text answer is not parsed")
route(NEW, FakeResponse(200, b'{"id": 5}', content_type="application/problem+json"))
call(body=BODY)
must(oid(ROWS[0]) == "5", "a +json answer is read")
route(NEW, FakeResponse(200, b'{"id": "ab\\u0000c\\n' + b'z' * 400 + b'"}'))
call(body=BODY)
must(oid(ROWS[0]) == "abc" + "z" * 252 and len(oid(ROWS[0])) == 255, "a long or control-character answer value is cleaned and cut")
# the answer the caller gets back is unchanged
route(NEW, FakeResponse(200, b'{"id": 9}'))
result = call(body=BODY)
must(result.data == {"id": 9} and result.content == b'{"id": 9}', result)
# review round 3: an unexpected parse error after Tactical ran the change never drops the success row (a deeply nested answer raises
# RecursionError; a MemoryError is simulated). The row is written without an answer id, and the raw answer is returned.
deep = b"[" * 200000 + b"]" * 200000
route(NEW, FakeResponse(200, deep))
result = call(body=BODY)
must(result.status == 200 and len(ROWS) == 1 and ROWS[0]["action"] == "add" and oid(ROWS[0]) is None and result.data == deep, "RecursionError keeps the row")
real_json = ops.json


class _FailingJson:
    def __getattr__(self, name):
        return getattr(real_json, name)

    @staticmethod
    def loads(*args, **kwargs):
        raise MemoryError("simulated")


ops.json = _FailingJson()
try:
    route(NEW, FakeResponse(200, b'{"id": 3}'))
    result = call(body=BODY)
finally:
    ops.json = real_json
must(result.status == 200 and len(ROWS) == 1 and ROWS[0]["action"] == "add" and oid(ROWS[0]) is None, "MemoryError keeps the row")

# ---- both declared: the answer wins, the body is the fallback
fresh()
declare(audit_extra={"object_field": "id", "object_body_field": "name"})
route(NEW, FakeResponse(200, b'{"id": 5}'))
call(body=BODY)
must(oid(ROWS[0]) == "5" and meta(ROWS[0])["object_source"] == "answer", ROWS[0])
for payload in (b'{}', b'{"id": true}', b'{"id": {"x": 1}}', b'[1]', b'null', b'"x"'):
    route(NEW, FakeResponse(200, payload))
    call(body=BODY)
    must(oid(ROWS[0]) == SENTINEL and meta(ROWS[0])["object_source"] == "body", (payload, ROWS[0]))
route(NEW, FakeResponse(200, b'{}'))
call(body={"kind": "k"})
must(oid(ROWS[0]) is None and "object_source" not in meta(ROWS[0]), "neither gives an id")

# ---- object_param and a scope object still win
fresh()
declare("by-param", route_="agents/newthing/{pk:int}/", method="PUT", audit_extra={"object_param": "pk", "object_field": "id", "object_body_field": "name"})
route("/agents/newthing/12/", FakeResponse(200, b'{"id": 5}'))
call("by-param", {"pk": "12"}, BODY)
must(oid(ROWS[0]) == "12" and "object_source" not in meta(ROWS[0]), ROWS[0])
declare("by-scope", route_="agents/{agent_id:agent}/newthing/", scope=[{"type": "agent", "source": "path:agent_id"}],
        audit_extra={"object_field": "id", "object_body_field": "name"})
route(f"/agents/{AGENT}/newthing/", FakeResponse(200, b'{"id": 5}'))
call("by-scope", {"agent_id": AGENT}, BODY)
must(oid(ROWS[0]) == AGENT and "object_source" not in meta(ROWS[0]), ROWS[0])

# ---- no other row carries the id
fresh()
declare(audit_extra={"object_field": "id", "object_body_field": "name"})
for status in (400, 404, 409, 422, 429):
    route(NEW, FakeResponse(status, b'{"id": 99, "detail": "TACTICAL-TEXT"}'))
    result = call(body=BODY)
    must(result.status == status and len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed", (status, ROWS))
    must(oid(ROWS[0]) is None and "object_source" not in meta(ROWS[0]), ("a failed row carries no such id", ROWS[0]))
    must(SENTINEL not in json.dumps(ROWS, default=str) and "TACTICAL-TEXT" not in json.dumps(ROWS, default=str), "no body value or Tactical text")
route(NEW, FakeResponse(200, b'{"id": 99}'))
refusal(lambda: call(body=BODY, user=weak), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and oid(ROWS[0]) is None and SENTINEL not in json.dumps(ROWS, default=str), ROWS)
refusal(lambda: call(body=[SENTINEL]), 400, "invalid_body")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed" and meta(ROWS[0])["failure"] == "core_refused" and oid(ROWS[0]) is None, ROWS)
refusal(lambda: call(body={"name": SENTINEL, "other": 1}), 400, "body_field_not_allowed")
must(oid(ROWS[0]) is None and SENTINEL not in json.dumps(ROWS, default=str), "a core_refused row never takes the body name")
for response, boom in ((FakeResponse(500, b'{"id": 99}'), None), (FakeResponse(503, b'{"id": 99}'), None), (None, RuntimeError("down"))):
    route(NEW, response, boom)
    try:
        call(body=BODY)
    except ops.TacticalOperationError:
        pass
    must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown" and oid(ROWS[0]) is None, ("outcome-unknown carries no id", ROWS))

# ---- registration refusals
fresh()
must("GET" in refused(id="g1", method="GET", body_fields=(), audit_extra={"object_field": "id"}), "GET object_field")
must("GET" in refused(id="g2", method="GET", body_fields=(), audit_extra={"object_body_field": "name"}), "GET object_body_field")
for name in ("bad name", "1st", "", "a-b", "x" * 65, 5, ["id"], True):
    refused(id="bad1", audit_extra={"object_field": name})
    refused(id="bad2", audit_extra={"object_body_field": name})
for name in ("token", "api_key", "password", "Secret", "auth_id", "cookie", "signature", "credential_id", "passwd"):
    must("secret" in refused(id="sec1", audit_extra={"object_field": name}), name)
    must("secret" in refused(id="sec2", body_fields=("name", name), audit_extra={"object_body_field": name}), name)
must("not one of body_fields" in refused(id="nb", audit_extra={"object_body_field": "missing"}), "object_body_field must be in body_fields")
# an unknown audit key is still refused, and the message names the two new keys
message = refused(id="unk", audit_extra={"object_fields": "id"})
must("object_field" in message and "object_body_field" in message, message)
# a repeated definition with different keys is refused; the identical one is idempotent
first = declare(id="twice", audit_extra={"object_field": "id"})
must(declare(id="twice", audit_extra={"object_field": "id"}) == first, "identical registration is idempotent")
must("different definition" in refused(id="twice", audit_extra={"object_field": "pk"}), "different object_field")
must("different definition" in refused(id="twice", audit_extra={"object_field": "id", "object_body_field": "name"}), "added object_body_field")
must("different definition" in refused(id="twice"), "dropped object_field")
# 'pk' and 'id' are plain names, not secrets
declare(id="plain1", route_="agents/plain1/", audit_extra={"object_field": "pk"})
declare(id="plain2", route_="agents/plain2/", audit_extra={"object_field": "id", "object_body_field": "name"})

# ---- an operation declared the 1.17.20 way is unchanged
fresh()
old = declare(id="old", route_="agents/old/")
must(old.audit_object_field is None and old.audit_object_body_field is None, old)
must(declare(id="old", route_="agents/old/") == old, "the old declaration registers again unchanged")
row = ops.get_operation("agents", "old")
must(row["audit"] == {"action": "add", "object_type": "agent_thing", "audit_fields": ["kind"], "object_param": None, "before": None, "params": [],
                      "object_field": None, "object_body_field": None, "lists": [], "list_masks": {}, "secret_fields": [], "object_id": None, "action_by_body": None}, row["audit"])  # 1.17.45: audit.action_by_body; 1.17.28: audit.lists; 1.17.44: audit.secret_fields and audit.object_id
must(set(row) == {"id", "module_id", "method", "route", "params", "permissions", "scope", "body_fields", "audit", "caller_scope", "server_only",
                  "body_selector", "module_permission", "query_params", "upload", "permissions_any", "body_max_bytes", "file_response"}, set(row))  # 1.17.26 added permissions_any and body_max_bytes, 1.17.41 file_response
route("/agents/old/", FakeResponse(200, b'{"id": 5}'))
call("old", body=BODY)
must(oid(ROWS[0]) is None and "object_source" not in meta(ROWS[0]), "an operation with neither key writes the row it always wrote")
# describe and the exported rows list both keys
declare(id="described", route_="agents/described/", audit_extra={"object_field": "id", "object_body_field": "name"})
described = ops.get_operation("agents", "described")["audit"]
must(described["object_field"] == "id" and described["object_body_field"] == "name", described)
must([r["audit"]["object_field"] for r in ops.list_operations("agents") if r["id"] == "described"] == ["id"], "list_operations carries it")
json.dumps(ops.list_operations())

# ---- capability, docs and contract text
meta_cap = ops.tactical_operations_contract_metadata()
must(meta_cap["version"] == "1.15.0" and meta_cap["declaration_keys_added_in_1_7_0"] == ["audit.object_field", "audit.object_body_field"], meta_cap)
docs = (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8")
for needle in ("audit.object_field", "audit.object_body_field", "object_source", "CQ66 b", "`audit.object_param` and no scope object", "original request asked for one key"):
    must(needle in docs, needle)
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
for needle in ("object_field", "object_body_field", "metadata.object_source answer or body", "never carry the id"):
    must(needle in contracts, needle)
print("[TEST] PASS tactical operations object field 1.17.21")
