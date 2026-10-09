#!/usr/bin/env python3
"""1.17.13 regression: a declared Tactical operation names its audit object, reads a before value, resolves scope from
that read, and takes a scope type from the body (requests from agents 0.3.0 and reportmanager 0.5.0).

Builds on the stubs of tests/tactical-operations-1.17.7.py (the helper section is executed from that file, so the two cannot
drift). The real tactical_operations.py runs against them. Django and Tactical are not installed on the development PC; the
real dispatch and the real AuditLog fields are proven by tests/tactical-operations-runtime-1.17.13.py on the dev server.
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
ops, ENABLED, declare, refused, fresh, must = (G[k] for k in ("ops", "ENABLED", "declare", "refused", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, OTHER, tech, User, Roleish, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "OTHER", "tech", "User", "Roleish", "Request"))
FakeResponse, refusal = G["FakeResponse"], G["refusal"]

NOTE_FIELDS = ["agent_id", "note", "user", "entry_time", "meta", "count"]


def note_spec(**over):
    spec = dict(
        id="note-edit", module_id="agents", method="PUT", route="agents/notes/{pk:int}/", permissions=["can_manage_notes"],
        scope=[{"type": "agent", "source": "before:agent_id"}], body_fields=["note"],
        audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk",
               "before": {"route": "agents/notes/{pk:int}/", "fields": NOTE_FIELDS}},
    )
    spec.update(over)
    return spec


def register(**over):
    return ops.register_tactical_operation(**note_spec(**over))


def refused_spec(**over):
    try:
        register(**over)
    except ops.TacticalOperationRegistrationError as exc:
        must(isinstance(exc, ValueError), "a registration refusal is a ValueError")
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


def audit_with(**extra):
    base = note_spec()["audit"]
    return {**base, **extra}


fresh()
# ------------------------------------------------------------------------------------------------ registration refusals
refused_spec(audit=audit_with(object_param="nope"))  # not a route parameter
refused_spec(audit=audit_with(object_param=5))
refused_spec(audit=audit_with(object_param=["pk"]))
refused_spec(audit=audit_with(before="agents/notes/{pk:int}/"))  # not {route, fields}
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/"}))
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": ["note"], "method": "POST"}))
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": []}))  # nothing to copy
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": ["note", "note"]}))
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": [f"f{i}" for i in range(17)]}))  # more than 16
for secretive in ("password", "api_token", "secret", "auth_header", "cookie", "private_key"):
    refused_spec(audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": ["agent_id", secretive]}))
# the before route is a GET that the same module must own, with the operation's own parameters
must("does not own route" in refused_spec(audit=audit_with(before={"route": "reporting/templates/{pk:int}/", "fields": ["name"]})), "an unowned before route")
refused_spec(audit=audit_with(before={"route": "accounts/users/{pk:int}/", "fields": ["name"]}))  # Core's own route
refused_spec(audit=audit_with(before={"route": "agents/notes/{other:int}/", "fields": ["note"]}))  # a parameter the operation lacks
refused_spec(audit=audit_with(before={"route": "agents/notes/{pk}/", "fields": ["note"]}))  # same name, other kind
refused_spec(method="GET", scope=[], body_fields=[], audit=audit_with(before={"route": "agents/notes/{pk:int}/", "fields": ["note"]}))  # a read has no before value
# a before source needs a declared before field
refused_spec(scope=[{"type": "agent", "source": "before:nope"}])
refused_spec(scope=[{"type": "agent", "source": "before:agent_id"}], audit={"action": "modify", "object_type": "agent_note", "object_param": "pk"})
refused_spec(scope=[{"type": "agent", "source": "before:agent_id", "extra": 1}])
# a body-selected scope type
TYPE_MAP = {"Client": "client", "Site": "site"}
BULK = dict(id="bulk-maintenance", method="POST", route="agents/maintenance/bulk/", permissions=["can_manage_clients"],
            scope=[{"type": "body:type", "source": "body:id", "type_map": TYPE_MAP}], body_fields=["type", "id", "action"],
            audit={"action": "enable", "object_type": "client", "audit_fields": ["action"]})
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id"}]})  # no type_map
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id", "type_map": {}}]})
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id", "type_map": {"Client": "agent"}}]})
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id", "type_map": {"Client": "device"}}]})
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id", "type_map": {"Bad Key": "client"}}]})
refused_spec(**{**BULK, "scope": [{"type": "body:kind", "source": "body:id", "type_map": TYPE_MAP}]})  # kind is not a body field
refused_spec(**{**BULK, "scope": [{"type": "client", "source": "body:id", "type_map": TYPE_MAP}]})  # type_map on a fixed type
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:nope", "type_map": TYPE_MAP}]})
refused_spec(**{**BULK, "scope": [{"type": "body:type", "source": "body:id", "type_map": {f"K{i}": "client" for i in range(9)}}]})
must(ops.list_operations() == [], "a refused declaration left no trace")

# ------------------------------------------------------------------------------------------------ a good declaration
edit = register()
must(edit.audit_object_param == "pk" and edit.before.fields == tuple(NOTE_FIELDS), edit)
must(register() is edit, "the identical declaration is idempotent")
register(id="note-delete", method="DELETE", body_fields=[])
register(id="cancel-pending-action", method="DELETE", route="logs/pendingactions/{pk:int}/", permissions=["can_reboot_agents"], scope=[], body_fields=[],
         audit={"action": "delete", "object_type": "pending_action", "audit_fields": [], "object_param": "pk"})
register(**BULK)
described = ops.get_operation("agents", "note-edit")
must(described["audit"]["object_param"] == "pk" and described["audit"]["before"] == {"route": "agents/notes/{pk:int}/", "fields": NOTE_FIELDS}, described)
must(described["scope"] == [{"type": "agent", "source": "before:agent_id"}], described)
must(ops.get_operation("agents", "bulk-maintenance")["scope"] == [{"type": "body:type", "source": "body:id", "type_map": TYPE_MAP}], ops.get_operation("agents", "bulk-maintenance"))
json.dumps(ops.list_operations())
# a declaration made the 1.17.12 way is unchanged
old = declare()
oldd = ops.get_operation("agents", "reboot")
must(old.audit_object_param is None and old.before is None and old.query_params == () and old.upload is None, old)
must(oldd["audit"]["object_param"] is None and oldd["audit"]["before"] is None and oldd["query_params"] == [] and oldd["upload"] is None, oldd)
# the report manager's template-delete style: an operation on a {pk} route with no Core scope
register(id="template-delete", module_id="reportmanager", method="DELETE", route="reporting/templates/{pk:int}/", permissions=["can_manage_clients"], scope=[],
         body_fields=[], audit={"action": "delete", "object_type": "report_template", "audit_fields": [], "object_param": "pk",
                                "before": {"route": "reporting/templates/{pk:int}/", "fields": ["name", "type", "template_md"]}})

# ------------------------------------------------------------------------------------------------ execution
NOTE = "/agents/notes/5/"
TEMPLATE = "/reporting/templates/8/"


def notes_view(agent=AGENT, read_status=200, read_boom=None, write_status=200, record=None):
    record = {"agent_id": agent, "note": "N" * 400, "user": "tech", "entry_time": "2026-10-09", "meta": {"nested": 1}, "count": 3,
              "password": "never-copied", **(record or {})}

    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, method=request.method))
        if request.method == "GET":
            if read_boom:
                raise read_boom
            return FakeResponse(read_status, json.dumps(record).encode())
        return FakeResponse(write_status, b'"ok"')
    return view


def call(user=tech, module="agents", operation="note-edit", params=None, body=None):
    del CALLS[:]
    return ops.run_tactical_operation(Request(user), module, operation, params, body)


ROUTES[NOTE] = (notes_view(), (), {})
del ROWS[:]
result = call(params={"pk": 5}, body={"note": "changed"})
must(result.status == 200 and [c.method for c in CALLS] == ["GET", "PUT"], [c.method for c in CALLS])
read = CALLS[0].request
must(read.method == "GET" and read._body == b"" and read.path == NOTE and read._force_auth_user is tech, "the read is a GET through Tactical's view as the signed-in user")
must("HTTP_AUTHORIZATION" not in read.META and "HTTP_COOKIE" not in read.META, "no token is forwarded on the read")
must(json.loads(CALLS[1].request._body) == {"note": "changed"}, "the change carries the body")
must(len(ROWS) == 1, ROWS)
row = ROWS[0]
must(row["action"] == "modify" and row["object_type"] == "agent_note" and row["debug_info"]["object_id"] == "5", row)
before = row["before_value"]
must(before["agent_id"] == AGENT and before["note"] == "N" * 256 and before["user"] == "tech" and before["count"] == 3, before)  # strings cut to 256
must("meta" not in before and "password" not in json.dumps(before), before)  # a non-scalar is dropped, a field not listed is never copied
must(row["debug_info"]["metadata"]["before"] == "recorded" and "before_status" not in row["debug_info"]["metadata"], row["debug_info"]["metadata"])
must("N" * 257 not in json.dumps(row, default=str), "the note text is cut")

# scope from the note's agent: an agent outside the role's limits
for agent in (OTHER, "z" * 21):
    del ROWS[:]
    ROUTES[NOTE] = (notes_view(agent=agent), (), {})
    exc = refusal(lambda: call(params={"pk": 5}, body={"note": "x"}), 404, "object_not_found")
    must([c.method for c in CALLS] == ["GET"], "the change never reaches Tactical")
    must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["metadata"]["reason"] == "not_found", ROWS)
    must(ROWS[0]["debug_info"]["object_id"] == "5" and exc.message == ops.MESSAGES["object_not_found"], ROWS[0])
# fails closed: the read does not answer 200, or raises, or answers without the field
for view in (notes_view(read_status=403), notes_view(read_status=404), notes_view(read_status=500), notes_view(read_boom=RuntimeError("down")),
             notes_view(record={"agent_id": None}), notes_view(record={"agent_id": ""}), notes_view(record={"agent_id": ["a"]})):
    del ROWS[:]
    ROUTES[NOTE] = (view, (), {})
    refusal(lambda: call(params={"pk": 5}, body={"note": "x"}), 404, "object_not_found")
    must([c.method for c in CALLS] == ["GET"] and len(ROWS) == 1 and ROWS[0]["action"] == "deny", (CALLS, ROWS))
ROUTES[NOTE] = (lambda request, *a, **k: FakeResponse(200, b"not json"), (), {})
refusal(lambda: call(params={"pk": 5}, body={"note": "x"}), 404, "object_not_found")
ROUTES[NOTE] = (lambda request, *a, **k: FakeResponse(200, b'["a list"]'), (), {})
refusal(lambda: call(params={"pk": 5}, body={"note": "x"}), 404, "object_not_found")

# the read happens after the Tactical flag check: a role without the flag never causes a read
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees
ROUTES[NOTE] = (notes_view(), (), {})
del ROWS[:]
refusal(lambda: call(user=weak, params={"pk": 5}, body={"note": "x"}), 403, "tactical_permission_denied")
must(not CALLS and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["object_id"] == "5", (CALLS, ROWS))  # the pk is the object on a refusal too
# an invalid pk is a 400, nothing is read
for bad in ({"pk": "abc"}, {"pk": None}, {"pk": "5/6"}, {}):
    refusal(lambda: call(params=bad, body={"note": "x"}), 400, "invalid_params")
must(not CALLS, "nothing is read for a bad parameter")

# note delete reads the same way; a body is refused
del ROWS[:]
call(operation="note-delete", params={"pk": 5})
must([c.method for c in CALLS] == ["GET", "PUT"] or [c.method for c in CALLS] == ["GET", "DELETE"], CALLS)
must(ROWS[0]["action"] == "modify" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS)

# a Tactical 5xx on the change: the outcome-unknown row also names the object
ROUTES[NOTE] = (notes_view(write_status=500), (), {})
del ROWS[:]
call(params={"pk": 5}, body={"note": "x"})
must(ROWS[0]["action"] == "custom:outcome-unknown" and ROWS[0]["debug_info"]["object_id"] == "5" and ROWS[0]["before_value"] is None, ROWS[0])
ROUTES[NOTE] = (notes_view(write_status=403), (), {})
del ROWS[:]
call(params={"pk": 5}, body={"note": "x"})
must(ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS[0])

# ---- a report-style operation: no Core scope, a failing read never blocks the change
def template_view(read_status=200, read_boom=None):
    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, method=request.method))
        if request.method == "GET":
            if read_boom:
                raise read_boom
            return FakeResponse(read_status, json.dumps({"name": "Monthly", "type": "html", "template_md": "SECRET TEMPLATE TEXT"}).encode())
        return FakeResponse(204, b"")
    return view


manager = User("mgr", Roleish("can_manage_clients"))
manager.sees = {"agents": set(), "clients": {1}, "sites": {10}}
ROUTES[TEMPLATE] = (template_view(), (), {})
del ROWS[:]
result = call(user=manager, module="reportmanager", operation="template-delete", params={"pk": 8})
must(result.status == 204 and [c.method for c in CALLS] == ["GET", "DELETE"], CALLS)
must(ROWS[0]["debug_info"]["object_id"] == "8" and ROWS[0]["action"] == "delete" and ROWS[0]["before_value"]["name"] == "Monthly", ROWS[0])  # template_delete: object_id equals the pk
for kwargs in (dict(read_status=500), dict(read_status=404), dict(read_boom=RuntimeError("down"))):
    ROUTES[TEMPLATE] = (template_view(**kwargs), (), {})
    del ROWS[:]
    result = call(user=manager, module="reportmanager", operation="template-delete", params={"pk": 8})
    must(result.status == 204 and [c.method for c in CALLS] == ["GET", "DELETE"], "a failing read still lets the change run")
    meta = ROWS[0]["debug_info"]["metadata"]
    must(meta["before"] == "unavailable" and meta["before_status"] == kwargs.get("read_status") and ROWS[0]["before_value"] is None, meta)
    must(ROWS[0]["action"] == "delete" and ROWS[0]["debug_info"]["object_id"] == "8", ROWS[0])
# whatever the template holds, only the listed fields are copied
ROUTES[TEMPLATE] = (template_view(), (), {})
del ROWS[:]
call(user=manager, module="reportmanager", operation="template-delete", params={"pk": 8})
must(ROWS[0]["before_value"] == {"name": "Monthly", "type": "html", "template_md": "SECRET TEMPLATE TEXT"}, "only the declared fields are copied")  # the module chose them
# deny rows from the module permission gate also carry the object
pk_hint_user = User("nogrant", Roleish())
pk_hint_user.sees = manager.sees
del ROWS[:]
refusal(lambda: call(user=pk_hint_user, module="reportmanager", operation="template-delete", params={"pk": 8}), 403, "tactical_permission_denied")
must(ROWS[0]["debug_info"]["object_id"] == "8", ROWS[0])

# ---- cancel a pending action: no Core scope, no read, the pk is the object
PENDING = "/logs/pendingactions/9/"
ROUTES[PENDING] = (lambda request, *a, **k: (CALLS.append(SimpleNamespace(request=request, method=request.method)), FakeResponse(200, b'"ok"'))[1], (), {})
del ROWS[:]
call(operation="cancel-pending-action", params={"pk": 9})
must([c.method for c in CALLS] == ["DELETE"] and ROWS[0]["debug_info"]["object_id"] == "9" and ROWS[0]["before_value"] is None, (CALLS, ROWS))
must("before" not in ROWS[0]["debug_info"]["metadata"], "no before declared, no before metadata")

# ---- a body-selected scope type
BULK_PATH = "/agents/maintenance/bulk/"
ROUTES[BULK_PATH] = (lambda request, *a, **k: (CALLS.append(SimpleNamespace(request=request, method=request.method)), FakeResponse(200, b'"ok"'))[1], (), {})
manager.sees = {"agents": set(), "clients": {1}, "sites": {10}}
del ROWS[:]
call(user=manager, operation="bulk-maintenance", body={"type": "Client", "id": 1, "action": "on"})
must(ROWS[0]["debug_info"]["metadata"]["scope_type"] == "client" and ROWS[0]["debug_info"]["object_id"] == "1", ROWS[0])
call(user=manager, operation="bulk-maintenance", body={"type": "Site", "id": 10, "action": "on"})
must(ROWS[1]["debug_info"]["metadata"]["scope_type"] == "site" and ROWS[1]["debug_info"]["object_id"] == "10", ROWS[1])
# a client id is not a site id, and each type is checked against its own limits
refusal(lambda: call(user=manager, operation="bulk-maintenance", body={"type": "Site", "id": 1}), 404, "object_not_found")  # site 1 does not exist
refusal(lambda: call(user=manager, operation="bulk-maintenance", body={"type": "Client", "id": 2}), 404, "object_not_found")  # client 2 is outside the role
refusal(lambda: call(user=manager, operation="bulk-maintenance", body={"type": "Site", "id": 11}), 404, "object_not_found")  # site 11 is outside the role
for bad in ({"id": 1}, {"type": "Agent", "id": 1}, {"type": "client", "id": 1}, {"type": None, "id": 1}, {"type": ["Client"], "id": 1}, {"type": "Client"}, {"type": "Client", "id": None}):
    refusal(lambda: call(user=manager, operation="bulk-maintenance", body=bad), 400, "scope_field_required")
must(not CALLS, "a bad type never reaches Tactical")

# ---- unchanged behaviour of an operation declared the 1.17.12 way, and of the object id helper
must(ops._object_id([("agent", ["a", "b"]), ("client", ["1"])]) == "a,b" and ops._object_id([]) is None, "_object_id(scope) behaves as before")
ROUTES[f"/agents/{AGENT}/reboot/"] = (lambda request, *a, **k: (CALLS.append(SimpleNamespace(request=request, method=request.method)), FakeResponse(200, b'{"ok": true}'))[1], (), {})
del ROWS[:]
result = call(operation="reboot", params={"agent_id": AGENT}, body={"mode": "now"})
must(result.status == 200 and ROWS[0]["debug_info"]["object_id"] == AGENT and ROWS[0]["before_value"] is None, ROWS[0])
must(set(ROWS[0]["debug_info"]["metadata"]) == {"operation", "method", "route", "tactical_status"}, "no new metadata keys for an old declaration")

# ---- AD-21 condition 3: the module's category, not only its id (the owner table lists `agents`)
G["PLUGINS"]["agents"].category = ""  # a module with no category counts as test
try:
    must("category is test" in refused_spec(id="no-category"), "a module with no category is refused every route")
    must(ops.list_operations("agents") != [], "operations declared earlier exist")
    refusal(lambda: call(operation="reboot", params={"agent_id": AGENT}, body={"mode": "now"}), 404, "tactical_operation_not_found")  # and one already declared is dead at lookup
finally:
    G["PLUGINS"]["agents"].category = "core"
for category in ("premium", "server", "test"):
    G["PLUGINS"]["agents"].category = category
    try:
        must(f"category is {category}" in refused_spec(id=f"cat-{category}"), category)
        refusal(lambda: call(operation="reboot", params={"agent_id": AGENT}, body={"mode": "now"}), 404, "tactical_operation_not_found")
    finally:
        G["PLUGINS"]["agents"].category = "core"
must(call(operation="reboot", params={"agent_id": AGENT}, body={"mode": "now"}).status == 200, "back to core: runs again")
# Licensing keeps core/codesign/ whatever its manifest says (AD-16), and nothing else
G["PLUGINS"]["licensing"].category = "server"
register(id="codesign-probe", module_id="licensing", method="GET", route="core/codesign/", permissions=["can_code_sign"], scope=[], body_fields=[],
         audit={"action": "view", "object_type": "code_signing_token"})
G["PLUGINS"]["licensing"].category = ""
refused_spec(id="lic-agents", module_id="licensing")

print("[TEST] PASS tactical operations audit object 1.17.13")
