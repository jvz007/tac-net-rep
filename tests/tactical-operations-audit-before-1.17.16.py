#!/usr/bin/env python3
"""1.17.16 regression: a caller-supplied before value (``audit_before``) for a route with no single-row GET, plus a lock on the
reportmanager shape of ``audit.object_param`` (object id from a typed {pk:int} path parameter).

``audit_before`` is a Python-only keyword of ``run_tactical_operation``: a flat object of at most 16 scalar fields. It is used as
the row's before value only when the operation declares no ``audit.before`` read, and the row says ``before_source: caller``
(``tactical`` for a read). Refused values give 400 ``invalid_audit_before`` and write nothing. The HTTP view cannot carry it.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-object-1.17.13.py does.
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
ops, declare, fresh, must = (G[k] for k in ("ops", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request, User, Roleish = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request", "User", "Roleish"))
FakeResponse, refusal, route = G["FakeResponse"], G["refusal"], G["route"]

PATH = f"/agents/{AGENT}/reboot/"
PARAMS, BODY = {"agent_id": AGENT}, {"mode": "now"}
fresh()
declare()  # reboot: no audit.before
route(PATH, FakeResponse(200))


def run(before, **kw):
    return ops.run_tactical_operation(Request(tech), "agents", "reboot", PARAMS, BODY, audit_before=before, **kw)


def meta(row):
    return row["debug_info"]["metadata"]


# ---- recorded with before_source caller
del ROWS[:]
run({"update_action": "approve", "count": 3, "reviewed": True, "note": None})
must(len(ROWS) == 1, ROWS)
row = ROWS[0]
must(row["before_value"] == {"update_action": "approve", "count": 3, "reviewed": True, "note": None}, row["before_value"])
must(meta(row)["before"] == "recorded" and meta(row)["before_source"] == "caller", meta(row))
# no before given: the row is as it was before 1.17.16
del ROWS[:]
run(None)
must(ROWS[0].get("before_value") is None and "before" not in meta(ROWS[0]) and "before_source" not in meta(ROWS[0]), ROWS[0])
# an empty dict is a value the caller asserted: it is recorded
del ROWS[:]
run({})
must(ROWS[0]["before_value"] == {} and meta(ROWS[0])["before_source"] == "caller", ROWS[0])

# ---- refusals: 400, nothing written, nothing sent to Tactical
bad_values = [
    "text", ["a"], 5, True, {"nested": {"a": 1}}, {"list": [1]}, {"f": 1.5}, {"f": b"x"}, {"f": "x" * 257}, {"f": "a\nb"},
    {f"f{i}": i for i in range(17)}, {"bad name": 1}, {"1st": 1}, {5: 1}, {"": 1},
    {"password": "x"}, {"api_token": "x"}, {"Secret": "x"}, {"authorization": "x"}, {"cookie": "x"}, {"private_key": "x"}, {"signature": "x"},
]
for bad in bad_values:
    del ROWS[:], CALLS[:]
    refusal(lambda: run(bad), 400, "invalid_audit_before")
    must(not ROWS and not CALLS, f"{bad!r} writes nothing and reaches nothing")
del ROWS[:]
run({f"f{i}": i for i in range(16)})
must(len(ROWS[0]["before_value"]) == 16, "16 fields is the limit")
del ROWS[:]
run({"f": "x" * 256})
must(len(ROWS[0]["before_value"]["f"]) == 256, "256 characters is the limit")

# ---- a refused or failed call keeps no before value on its row
weak = User("weak", Roleish("can_send_wol"))
weak.sees = tech.sees
del ROWS[:]
refusal(lambda: ops.run_tactical_operation(Request(weak), "agents", "reboot", PARAMS, BODY, audit_before={"a": 1}), 403, "tactical_permission_denied")
must(len(ROWS) == 1 and ROWS[0].get("before_value") is None and "before" not in meta(ROWS[0]), ROWS)
for response, boom in ((FakeResponse(403, b'"no"'), None), (FakeResponse(502, b"x"), None), (None, RuntimeError("down"))):
    route(PATH, response, boom)
    del ROWS[:]
    try:
        run({"a": 1})
    except ops.TacticalOperationError:
        pass
    must(len(ROWS) == 1 and ROWS[0].get("before_value") is None and "before_source" not in meta(ROWS[0]), ROWS)
route(PATH, FakeResponse(200))
# a GET operation has no audit row before value to keep
declare(id="reboot-get", method="GET", route="agents/{agent_id:agent}/reboot/", body_fields=[], audit={"action": "view", "object_type": "agent"})
del ROWS[:]
ops.run_tactical_operation(Request(tech), "agents", "reboot-get", PARAMS, None, audit_before={"a": 1})
must(all(r.get("before_value") is None and "before_source" not in meta(r) for r in ROWS), ROWS)

# ---- Tactical's own read wins when the operation declares one
NOTE = "/agents/notes/5/"
ops.register_tactical_operation(
    id="note-edit", module_id="agents", method="PUT", route="agents/notes/{pk:int}/", permissions=["can_manage_notes"], scope=[],
    body_fields=["note"], audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk",
                                 "before": {"route": "agents/notes/{pk:int}/", "fields": ["note", "user"]}},
)


def notes_view(read_status=200):
    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, method=request.method))
        if request.method == "GET":
            return FakeResponse(read_status, json.dumps({"note": "from tactical", "user": "tech"}).encode())
        return FakeResponse(200, b'"ok"')
    return view


ROUTES[NOTE] = (notes_view(), (), {})
del ROWS[:]
ops.run_tactical_operation(Request(tech), "agents", "note-edit", {"pk": 5}, {"note": "n"}, audit_before={"note": "caller says"})
must(ROWS[0]["before_value"] == {"note": "from tactical", "user": "tech"}, ROWS[0]["before_value"])
must(meta(ROWS[0])["before"] == "recorded" and meta(ROWS[0])["before_source"] == "tactical", meta(ROWS[0]))
# and when the Tactical read fails the caller value is still ignored: the row says unavailable, from tactical
ROUTES[NOTE] = (notes_view(404), (), {})
del ROWS[:]
ops.run_tactical_operation(Request(tech), "agents", "note-edit", {"pk": 5}, {"note": "n"}, audit_before={"note": "caller says"})
must(ROWS[0].get("before_value") is None and meta(ROWS[0])["before"] == "unavailable" and meta(ROWS[0])["before_source"] == "tactical", ROWS[0])
# a read-declared operation still validates a bad audit_before
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "note-edit", {"pk": 5}, {"note": "n"}, audit_before={"token": "x"}), 400, "invalid_audit_before")

# ---- the HTTP view cannot carry it
view_source = (BASE.parent.parent / "framwork/tec_tac/tactical_operation_views.py").read_text(encoding="utf-8")
must("audit_before" not in view_source, "the view never passes audit_before")
reply = G["views"].TacticalOperationView().post(Request(tech, data={"params": PARAMS, "body": BODY, "audit_before": {"a": 1}}), "agents", "reboot")
must(reply.status_code == 400 and "audit_before" in reply.data["detail"], reply.__dict__)

# ---- the reportmanager shape (reportmanager 0.5.0 has not adopted object_param yet): typed {pk:int}, no Core scope
for op_id, method, tail in (("template-delete", "DELETE", ""), ("template-edit", "PUT", ""), ("template-copy", "POST", "copy/")):
    ops.register_tactical_operation(
        id=op_id, module_id="reportmanager", method=method, route="reporting/templates/{pk:int}/" + tail, permissions=["can_manage_notes"],
        scope=[], body_fields=["name"] if method == "PUT" else [],
        audit={"action": {"DELETE": "delete", "PUT": "modify", "POST": "add"}[method], "object_type": "report_template", "audit_fields": [], "object_param": "pk"},
    )
TEMPLATE = "/reporting/templates/8/"
for status, expected in ((204, "delete"), (403, "deny"), (500, "custom:outcome-unknown")):
    ROUTES[TEMPLATE] = (lambda request, *a, _s=status, **k: FakeResponse(_s, b'"x"'), (), {})
    del ROWS[:]
    ops.run_tactical_operation(Request(tech), "reportmanager", "template-delete", {"pk": 8}, None)
    must(len(ROWS) == 1 and ROWS[0]["action"] == expected and ROWS[0]["debug_info"]["object_id"] == "8", (status, ROWS))
# 16 operations of the same shape register, each naming its pk
for i in range(13):
    ops.register_tactical_operation(
        id=f"template-op-{i}", module_id="reportmanager", method="POST", route=f"reporting/templates/{{pk:int}}/op{i}/", permissions=["can_manage_notes"],
        scope=[], body_fields=[], audit={"action": "run", "object_type": "report_template", "audit_fields": [], "object_param": "pk"},
    )
must(len([o for o in ops.list_operations("reportmanager") if o["audit"]["object_param"] == "pk"]) == 16, "16 operations")
# a non-int pk never reaches Tactical
del ROWS[:], CALLS[:]
refusal(lambda: ops.run_tactical_operation(Request(tech), "reportmanager", "template-delete", {"pk": "8/../x"}, None), 400, "invalid_params")
must(not ROWS, "a refused path value writes no row")

print("[TEST] PASS tactical operations audit before 1.17.16")
