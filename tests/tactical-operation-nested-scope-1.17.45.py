#!/usr/bin/env python3
"""1.17.45 a nested body scope source, body:<field>.<key> (reviews/requests/core.md, 'from reportmanager 0.5.0', nested scope source).

Report Manager's run, email and schedule bodies carry the client, site and agent one level down (body.dependencies). A scope entry may now
read them, so Core checks the caller's client and site limits before Tactical runs. Covered: registration (accepted; refused for a path
source, a parent outside body_fields, a second level, row_lookup, a parent that is audit.object_body_field or a secret field), a client,
site and agent inside and outside the caller's limits (denied before any Tactical call, with a deny row), optional entries (absent, null
or empty parent, empty list), list values and the 1000 id cap, a required entry with an absent parent, a parent that is not an object
(400 scope_field_required with one core_refused row), the object id of the row, the body Core forwards being the body it checked,
describe(), and a top-level body scope source and a type_map entry behaving as before.

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
ops, must, fresh, refused = (G[k] for k in ("ops", "must", "fresh", "refused"))
CALLS, ROWS, AGENT, OTHER, Request, route = (G[k] for k in ("CALLS", "ROWS", "AGENT", "OTHER", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

PATH = "/reporting/templates/run/"
FLAG = "can_reboot_agents"
person = User("person", Roleish(FLAG))
person.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}  # one client, one site, one agent


def decl(**over):
    spec = dict(
        id="run-template", module_id="reportmanager", method="POST", route="reporting/templates/run/", permissions=[FLAG],
        scope=[{"type": "client", "source": "body:dependencies.client", "optional": True},
               {"type": "site", "source": "body:dependencies.site", "optional": True},
               {"type": "agent", "source": "body:dependencies.agent", "optional": True}],
        body_fields=["format", "dependencies", "title"], audit={"action": "run", "object_type": "report", "audit_fields": ["format"],
                                                                "object_id": "report-run"},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def bad(phrase, **over):
    fresh()
    text = refused(**{"module_id": "reportmanager", "method": "POST", "route": "reporting/templates/run/", "permissions": [FLAG],
                      "body_fields": ["format", "dependencies", "title"], "audit": {"action": "run", "object_type": "report"}, **over})
    must(phrase in text, (phrase, text))


def run(body, user=person, operation="run-template"):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(user), "reportmanager", operation, {}, body)


def meta_of(row):
    return row["debug_info"]["metadata"]


# (1) registration
fresh()
op = decl()
must([s.source for s in op.scope] == ["body:dependencies.client", "body:dependencies.site", "body:dependencies.agent"], op.scope)
bad("only a body source may be nested", id="n1", scope=[{"type": "client", "source": "path:a.b"}])
bad("is not one of body_fields", id="n2", scope=[{"type": "client", "source": "body:other.client"}])
bad("bad scope entry", id="n3", scope=[{"type": "client", "source": "body:dependencies.a.b"}])
bad("bad scope entry", id="n3b", scope=[{"type": "client", "source": "body:dependencies."}])
bad("never a body source", id="n4", scope=[{"type": "agent", "source": "body:dependencies.agent", "row_lookup": "lookup"}])
bad("nested under audit.object_body_field", id="n5", scope=[{"type": "client", "source": "body:dependencies.client"}],
    audit={"action": "run", "object_type": "report", "object_body_field": "dependencies"})
bad("is the object id or a body scope source", id="n6", scope=[{"type": "client", "source": "body:dependencies.client"}],
    audit={"action": "run", "object_type": "report", "secret_fields": ["dependencies"]})
bad("optional belongs to a body source", id="n7", scope=[{"type": "client", "source": "path:x", "optional": True}])
fresh()
decl(id="two", scope=[{"type": "client", "source": "body:dependencies.client"}, {"type": "client", "source": "body:dependencies.client_two"}])
print("       registration: accepted, refused for each of 8 wrong cases")

# (2) inside and outside the caller's limits
fresh()
decl()
route(PATH, FakeResponse(200, b'{"ok": true}'))
must(run({"format": "pdf", "dependencies": {"client": 1, "site": 10, "agent": AGENT}}).status == 200 and len(CALLS) == 1, "inside the limits runs")
must(len(ROWS) == 1 and ROWS[0]["action"] == "run", ROWS)
for label, deps in (("client", {"client": 2}), ("site", {"site": 11}), ("agent", {"agent": OTHER}), ("mixed", {"client": 1, "site": 11}),
                    ("client in a list", {"client": [1, 2]}), ("string client", {"client": "2"})):
    refusal(lambda: run({"format": "pdf", "dependencies": deps}), 404, "object_not_found")
    must(not CALLS and len(ROWS) == 1 and ROWS[0]["action"] == "deny", (label, [r["action"] for r in ROWS]))
    must(meta_of(ROWS[0])["reason"] == "not_found" and meta_of(ROWS[0])["tactical_status"] is None, (label, meta_of(ROWS[0])))
must(run({"format": "pdf", "dependencies": {"client": [1], "site": [10]}}).status == 200, "a list inside the limits runs")
print("       client, site and agent outside the limits: denied before Tactical, one deny row; inside: runs")

# (3) optional entries
for body in ({"format": "pdf"}, {"format": "pdf", "dependencies": None}, {"format": "pdf", "dependencies": {}},
             {"format": "pdf", "dependencies": {"client": None}}, {"format": "pdf", "dependencies": {"client": []}},
             {"format": "pdf", "dependencies": {"unrelated": "x"}}):
    must(run(body).status == 200 and len(CALLS) == 1, body)
print("       optional entries: an absent, null or empty parent, null or empty value add nothing")

# (4) malformed values: 400 scope_field_required with one core_refused row
for label, deps in (("string parent", "client"), ("number parent", 5), ("list parent", [1]), ("bool parent", True)):
    refusal(lambda: run({"format": "pdf", "dependencies": deps}), 400, "scope_field_required")
    must(not CALLS and len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed", (label, ROWS))
    must(meta_of(ROWS[0])["failure"] == "core_refused" and meta_of(ROWS[0])["code"] == "scope_field_required", meta_of(ROWS[0]))
    must(ROWS[0]["debug_info"]["object_id"] == "report-run", ROWS[0]["debug_info"])
for label, deps in (("bool value", {"client": True}), ("dict value", {"client": {"id": 1}}), ("float value", {"client": 1.5}), ("blank value", {"client": "  "}),
                    ("too many ids", {"client": list(range(1001))})):
    refusal(lambda: run({"format": "pdf", "dependencies": deps}), 400, "scope_field_required")
    must(not CALLS, label)
print("       a non-object parent, a bool, dict, float or blank value and over 1000 ids: 400 scope_field_required, Tactical never called")

# (5) a required nested entry with an absent parent is refused as a missing top-level value is
fresh()
decl(scope=[{"type": "client", "source": "body:dependencies.client"}])
route(PATH, FakeResponse(200, b"{}"))
for body in ({"format": "pdf"}, {"format": "pdf", "dependencies": None}, {"format": "pdf", "dependencies": {}}):
    refusal(lambda: run(body), 400, "scope_field_required")
must(run({"format": "pdf", "dependencies": {"client": 1}}).status == 200, "a present value runs")
print("       a required nested entry: an absent parent or key is 400 scope_field_required")

# (6) the body Core forwards is the body it checked
fresh()
decl()
route(PATH, FakeResponse(200, b"{}"))
body = {"format": "pdf", "dependencies": {"client": 1, "site": 10, "extra": "kept"}}
run(body)
forwarded = json.loads(CALLS[0].request._body)
must(forwarded == body, forwarded)
must(ROWS[0]["after_value"] == {"format": "pdf"}, ROWS[0]["after_value"])
must("kept" not in json.dumps(ROWS, default=str), "the nested object is not recorded in the row")
print("       the forwarded body equals the checked body; the row records only audit_fields")

# (7) the object id: with no audit.object_id the first nested id names the row
fresh()
decl(audit={"action": "run", "object_type": "report", "audit_fields": ["format"]})
route(PATH, FakeResponse(200, b"{}"))
run({"format": "pdf", "dependencies": {"client": 1, "site": 10}})
must(ROWS[0]["debug_info"]["object_id"] == "1", ROWS[0]["debug_info"])
print("       the first nested scope id names the row, as a top-level body scope id does")

# (8) describe, and a top-level body source and a type_map entry behave as before
fresh()
decl()
got = ops.get_operation("reportmanager", "run-template")
must([s["source"] for s in got["scope"]] == ["body:dependencies.client", "body:dependencies.site", "body:dependencies.agent"] and got["scope"][0]["optional"], got["scope"])
fresh()
ops.register_tactical_operation(
    id="top", module_id="reportmanager", method="POST", route="reporting/templates/run/", permissions=[FLAG],
    scope=[{"type": "client", "source": "body:client"}], body_fields=["client", "format"], audit={"action": "run", "object_type": "report"})
route(PATH, FakeResponse(200, b"{}"))
must(run({"client": 1}, operation="top").status == 200, "a top-level source still runs")
refusal(lambda: run({"client": 2}, operation="top"), 404, "object_not_found")
refusal(lambda: run({"client": {"id": 1}}, operation="top"), 400, "scope_field_required")
fresh()
ops.register_tactical_operation(
    id="typed", module_id="reportmanager", method="POST", route="reporting/templates/run/", permissions=[FLAG],
    scope=[{"type": "body:kind", "source": "body:dependencies.id", "type_map": {"c": "client", "s": "site"}}],
    body_fields=["kind", "dependencies"], audit={"action": "run", "object_type": "report"})
route(PATH, FakeResponse(200, b"{}"))
must(run({"kind": "c", "dependencies": {"id": 1}}, operation="typed").status == 200, "a nested id with a body-selected type")
refusal(lambda: run({"kind": "s", "dependencies": {"id": 11}}, operation="typed"), 404, "object_not_found")
refusal(lambda: run({"kind": "zzz", "dependencies": {"id": 1}}, operation="typed"), 400, "scope_field_required")
print("       describe shows the nested source; a top-level source and a body-selected type behave as before")

# (9) the capability
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.14.0" and meta["version"] == "1.14.0", meta["version"])
must(any("nested scope source" in text for text in meta["behaviour_added_in_1_14_0"]), meta)
print("       capability 1.14.0 and the contract metadata name the nested source")
print("[TEST] PASS tactical operation nested scope 1.17.45")
