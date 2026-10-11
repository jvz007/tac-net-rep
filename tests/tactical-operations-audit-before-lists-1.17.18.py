#!/usr/bin/env python3
"""1.17.18 regression: list values, counts and a list-GET ``select`` in ``audit.before`` (Johan item 5; CQ58 a).

A declared before field whose value is a list of whole numbers or short strings is recorded as a list (capped, with its count and
a truncated marker). A list of objects is never recorded. ``count_fields`` record a length only. ``select`` reads a list GET
in-process and picks the row by the PATH id Core already cleaned, never by anything the browser sends. A paginated answer is read,
a miss or a non-list answer gives ``before unavailable`` and the call still runs. Up to 32 fields are accepted, a secret-looking
name is refused, and the older ``{route, fields}`` declaration behaves as before. Uses the stubs of
tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-before-1.17.16.py does.
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
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROUTES, CALLS, ROWS, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "tech", "Request"))
FakeResponse = G["FakeResponse"]

NOTE_ROUTE = "agents/notes/{pk:int}/"
NOTE = "/agents/notes/5/"


def declare(before, op_id="note-edit", route=NOTE_ROUTE, **over):
    spec = dict(
        id=op_id, module_id="agents", method="PUT", route=route, permissions=["can_manage_notes"], scope=[], body_fields=["note"],
        audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk" if "{pk" in route else None, "before": before},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def refused(before, text="", **over):
    try:
        declare(before, **over)
    except ops.TacticalOperationRegistrationError as exc:
        must(text in str(exc), str(exc))
        return
    raise AssertionError(f"accepted: {before}")


def view_returning(payload, status=200):
    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, method=request.method, path=request.path))
        if request.method == "GET":
            return FakeResponse(status, json.dumps(payload).encode())
        return FakeResponse(200, b'"ok"')
    return view


def serve(path, payload, status=200):
    ROUTES[path] = (view_returning(payload, status), (), {})


def go(pk=5, body=None, op="note-edit", path_params=None):
    del ROWS[:], CALLS[:]
    if op == "sel":
        ROUTES.setdefault(f"/agents/notes/{pk}/", (view_returning({}), (), {}))  # the DELETE target
    return ops.run_tactical_operation(Request(tech), "agents", op, path_params or {"pk": pk}, body if body is not None else {"note": "n"})


def meta(row):
    return row["debug_info"]["metadata"]


# ---- a list of whole numbers or short strings is recorded as a list, with its count
fresh()
declare({"route": NOTE_ROUTE, "fields": ["excluded_clients", "tags", "name"]})
serve(NOTE, {"excluded_clients": [1, 2, 3], "tags": ["a", "b\n" + "x" * 300], "name": "n", "other": [1]})
go()
before = ROWS[0]["before_value"]
must(before["excluded_clients"] == [1, 2, 3] and before["excluded_clients_count"] == 3, before)
must(before["tags"][0] == "a" and len(before["tags"][1]) == 256 and "\n" not in before["tags"][1] and before["tags_count"] == 2, before)
must("excluded_clients_truncated" not in before and before["name"] == "n" and "other" not in before, before)
must(meta(ROWS[0])["before"] == "recorded" and meta(ROWS[0])["before_source"] == "tactical", meta(ROWS[0]))
# an empty list is recorded as an empty list
serve(NOTE, {"excluded_clients": [], "tags": [], "name": "n"})
go()
must(ROWS[0]["before_value"]["excluded_clients"] == [] and ROWS[0]["before_value"]["excluded_clients_count"] == 0, ROWS[0]["before_value"])
# lists that hold anything else are never recorded
for bad in ([{"id": 1}], [1, {"id": 2}], [1.5], [True], [None], [[1]], [1, "a", None]):
    serve(NOTE, {"excluded_clients": bad, "tags": ["ok"], "name": "n"})
    go()
    must("excluded_clients" not in ROWS[0]["before_value"] and "excluded_clients_count" not in ROWS[0]["before_value"], (bad, ROWS[0]["before_value"]))
    must(ROWS[0]["before_value"]["tags"] == ["ok"], "the other fields are unaffected")
# an object after the cap still drops the whole list
serve(NOTE, {"excluded_clients": list(range(1200)) + [{"id": 1}], "name": "n"})
go()
must("excluded_clients" not in ROWS[0]["before_value"], "the whole list is checked, not only the kept part")
# a dict value is still dropped, scalars as before
serve(NOTE, {"excluded_clients": {"a": 1}, "tags": 7, "name": None})
go()
must(ROWS[0]["before_value"] == {"tags": 7, "name": None}, ROWS[0]["before_value"])

# ---- a long list is capped and flagged
serve(NOTE, {"excluded_clients": list(range(1500)), "name": "n"})
go()
before = ROWS[0]["before_value"]
must(before["excluded_clients"] == list(range(1000)) and before["excluded_clients_count"] == 1500 and before["excluded_clients_truncated"] is True, {k: (v if not isinstance(v, list) else len(v)) for k, v in before.items()})
# the text budget also stops a long list of long strings
serve(NOTE, {"tags": ["y" * 256] * 900, "name": "n"})
go()
before = ROWS[0]["before_value"]
must(len(before["tags"]) < 900 and before["tags_count"] == 900 and before["tags_truncated"] is True, len(before["tags"]))
must(sum(len(item) for item in before["tags"]) <= 65536 + 256, "bounded row size")

# ---- count_fields: the length only
fresh()
declare({"route": NOTE_ROUTE, "fields": ["name"], "count_fields": ["packages", "other"]})
serve(NOTE, {"name": "n", "packages": [{"name": "7zip"}, {"name": "git"}, {"name": "vlc"}], "other": "text"})
go()
must(ROWS[0]["before_value"] == {"name": "n", "packages_count": 3}, ROWS[0]["before_value"])
must("7zip" not in json.dumps(ROWS[0], default=str), "contents are never recorded")
fresh()
declare({"route": NOTE_ROUTE, "fields": [], "count_fields": ["packages"]})  # count only is allowed
serve(NOTE, {"packages": [1, 2]})
go()
must(ROWS[0]["before_value"] == {"packages_count": 2}, ROWS[0]["before_value"])

# ---- select: a list GET with no single-row read (CQ58 a)
fresh()
declare({"route": "agents/notes/", "fields": ["agent_id", "username"], "select": {"param": "pk"}}, op_id="sel", method="DELETE", body_fields=[])
LIST = "/agents/notes/"
ROUTES[NOTE] = (view_returning({}), (), {})
rows = [{"id": 4, "agent_id": "x", "username": "other"}, {"id": 5, "agent_id": "a" * 21, "username": "tech"}, {"id": 6, "agent_id": "y", "username": "z"}]
serve(LIST, rows)
go(op="sel", body={})
must(ROWS[0]["before_value"] == {"agent_id": "a" * 21, "username": "tech"}, ROWS[0]["before_value"])
must(meta(ROWS[0])["before"] == "recorded" and meta(ROWS[0])["before_source"] == "tactical", meta(ROWS[0]))
must(any(c.method == "GET" and c.path == LIST for c in CALLS), "Core read the list GET in-process")
# paginated answer
serve(LIST, {"count": 3, "next": None, "results": rows})
go(op="sel", body={})
must(ROWS[0]["before_value"]["username"] == "tech", "paginated results are read")
# the id comes from the cleaned path pk, never from the body; a before the browser sends is refused or ignored
serve(LIST, rows)
try:
    go(op="sel", body={"id": 4, "before": {"username": "forged"}})
    raise AssertionError("a body key outside the whitelist must be refused")
except ops.TacticalOperationError as exc:
    must(exc.code == "body_field_not_allowed", exc.code)
go(pk=6, op="sel", body={})
must(ROWS[0]["before_value"]["agent_id"] == "y", "the path pk picks the row")
# a string key matches too (an int in the list, a string key)
serve(LIST, [{"id": "5", "agent_id": "s", "username": "u"}])
go(op="sel", body={})
must(ROWS[0]["before_value"]["agent_id"] == "s", ROWS[0]["before_value"])
# no match, an object answer, a non-200 answer, a list of non-objects: before unavailable, the call still runs
for payload, status in ((rows, 200), ({"id": 5, "agent_id": "a"}, 200), ({"results": "no"}, 200), ([1, 5, "x"], 200), (rows, 404), ([], 200)):
    serve(LIST, payload, status)
    result = go(pk=99 if payload is rows and status == 200 else 5, op="sel", body={})
    must(result.status == 200 and ROWS[0]["action"] == "modify", (payload, status))
    must(ROWS[0].get("before_value") is None and meta(ROWS[0])["before"] == "unavailable", (payload, status, ROWS[0]))
# rows beyond the first 1000 are not scanned
serve(LIST, [{"id": n, "agent_id": "p", "username": "u"} for n in range(1, 1001)] + [{"id": 5555, "agent_id": "late", "username": "u"}])
go(pk=5, op="sel", body={})
must(ROWS[0]["before_value"]["agent_id"] == "p", "an early row is found")
fresh()
declare({"route": "agents/notes/", "fields": ["agent_id"], "select": {"param": "pk"}}, op_id="sel", method="DELETE", body_fields=[])
serve(LIST, [{"id": n, "agent_id": "p"} for n in range(1000, 2000)] + [{"id": 5, "agent_id": "late"}])
ROUTES[NOTE] = (view_returning({}), (), {})
go(pk=5, op="sel", body={})
must(meta(ROWS[0])["before"] == "unavailable", "the 1001st row is past the cap")

# ---- select registration
fresh()
refused({"route": "agents/notes/", "fields": ["a"], "select": {"param": "nope"}}, "path parameter", op_id="s1", method="DELETE", body_fields=[])
refused({"route": "agents/notes/", "fields": ["a"], "select": {"field": "id"}}, "param, field", op_id="s2", method="DELETE", body_fields=[])
refused({"route": "agents/notes/", "fields": ["a"], "select": {"param": "pk", "field": "bad key"}}, "plain, non-secret", op_id="s3", method="DELETE", body_fields=[])
refused({"route": "agents/notes/", "fields": ["a"], "select": {"param": "pk", "field": "api_token"}}, "non-secret", op_id="s4", method="DELETE", body_fields=[])
refused({"route": "agents/notes/", "fields": ["a"], "select": {"param": "pk", "extra": 1}}, "param, field", op_id="s5", method="DELETE", body_fields=[])
refused({"route": "agents/notes/", "fields": ["a"], "select": "pk"}, "param, field", op_id="s6", method="DELETE", body_fields=[])
refused({"route": "agents/{agent_id:agent}/", "fields": ["a"], "select": {"param": "pk"}}, "own route", op_id="s7", method="DELETE", body_fields=[])  # a before route parameter the operation lacks
refused({"route": "logs/audit/", "fields": ["a"], "select": {"param": "pk"}}, "does not own", op_id="s8", method="DELETE", body_fields=[])  # another module's list route
# a param of kind agent cannot be a select key
refused({"route": "agents/notes/", "fields": ["a"], "select": {"param": "agent_id"}}, "int or str", op_id="s9", route="agents/{agent_id:agent}/notes/", body_fields=["note"])
must(ops.list_operations() == [], "refused declarations left no trace")

# ---- field caps and secret names
fresh()
declare({"route": NOTE_ROUTE, "fields": [f"f{i}" for i in range(32)]})
must(len(ops.get_operation("agents", "note-edit")["audit"]["before"]["fields"]) == 32, "32 fields are accepted")
fresh()
refused({"route": NOTE_ROUTE, "fields": [f"f{i}" for i in range(33)]}, "more than 32")
refused({"route": NOTE_ROUTE, "fields": ["a"], "count_fields": [f"c{i}" for i in range(33)]}, "more than 32")
for secretive in ("password", "api_token", "secret", "auth_header", "cookie", "private_key"):
    refused({"route": NOTE_ROUTE, "fields": ["a", secretive]}, "secret")
    refused({"route": NOTE_ROUTE, "fields": ["a"], "count_fields": [secretive]}, "secret")
refused({"route": NOTE_ROUTE, "fields": []}, "at least one")
refused({"route": NOTE_ROUTE, "fields": ["a"], "count_fields": ["a"]}, "both fields and count_fields")
refused({"route": NOTE_ROUTE, "fields": ["a", "a_count"]}, "written twice")
refused({"route": NOTE_ROUTE, "fields": ["a"], "count_fields": ["a_x", "a"]}, "both fields and count_fields")
refused({"route": NOTE_ROUTE, "fields": ["a_count"], "count_fields": ["a"]}, "written twice")
refused({"route": NOTE_ROUTE, "fields": ["a", "a_truncated"]}, "written twice")
refused({"route": NOTE_ROUTE, "fields": ["a"], "bogus": 1}, "nothing else")
refused({"fields": ["a"]}, "audit.before is")

# ---- the older declaration is unchanged and describes as before
fresh()
declare({"route": NOTE_ROUTE, "fields": ["note", "user"]})
must(ops.get_operation("agents", "note-edit")["audit"]["before"] == {"route": NOTE_ROUTE, "fields": ["note", "user"]}, ops.get_operation("agents", "note-edit"))
serve(NOTE, {"note": "x", "user": "u", "extra": 1})
go()
must(ROWS[0]["before_value"] == {"note": "x", "user": "u"}, ROWS[0]["before_value"])
# a GET operation still cannot declare before
refused({"route": NOTE_ROUTE, "fields": ["a"]}, "changes nothing", op_id="g1", method="GET", body_fields=[])
# the Python-only audit_before stays flat and is unchanged
refused_audit = None
try:
    ops.run_tactical_operation(Request(tech), "agents", "note-edit", {"pk": 5}, {"note": "n"}, audit_before={"list": [1]})
except ops.TacticalOperationError as exc:
    refused_audit = exc.code
must(refused_audit == "invalid_audit_before", "audit_before is still a flat object")

print("[TEST] PASS tactical operations audit before lists 1.17.18")
