#!/usr/bin/env python3
"""1.17.52 a scope entry that does not name the audit row's object: ``names_object: false`` (reviews/requests/core.md, 'from reportmanager
0.6.2 round 3'; additive and opt-in half of the request).

A create that checks ``body:dependencies.client`` named the client on its success row, so ``audit.object_field`` could never name the
created record. A scope entry may carry ``names_object: false`` (a strict bool, default true). It is resolved and checked exactly as
before, but is left out when Core picks the object id of the row. Covered: a flagged create names the record from Tactical's answer; the
same declaration without the flag names the client as before; the scope check still denies a caller without scope and the deny row is
unchanged; an all-flagged scope with no object source is refused at registration; a non-bool is refused; describe() shows the flag only
when false; a failed and an outcome-unknown row do not name the flagged entry; the 400s are unchanged; a flagged entry does not change
which entries are checked.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operation-nested-scope-1.17.45.py does.
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
CALLS, ROWS, AGENT, Request, route = (G[k] for k in ("CALLS", "ROWS", "AGENT", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

PATH = "/reporting/schedules/"
FLAG = "can_reboot_agents"
person = User("person", Roleish(FLAG))
person.sees = {"agents": {AGENT}, "clients": {1}, "sites": {10}}  # one client, one site, one agent
CLIENT = {"type": "client", "source": "body:dependencies.client", "optional": True}
SITE = {"type": "site", "source": "body:dependencies.site", "optional": True}


def decl(**over):
    spec = dict(
        id="schedule-add", module_id="reportmanager", method="POST", route="reporting/schedules/", permissions=[FLAG],
        scope=[{**CLIENT, "names_object": False}, {**SITE, "names_object": False}],
        body_fields=["title", "dependencies"], audit={"action": "add", "object_type": "report_schedule", "audit_fields": ["title"], "object_field": "id"},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def bad(phrase, **over):
    fresh()
    text = refused(**{"module_id": "reportmanager", "method": "POST", "route": "reporting/schedules/", "permissions": [FLAG],
                      "body_fields": ["title", "dependencies"], "audit": {"action": "add", "object_type": "report_schedule", "object_field": "id"}, **over})
    must(phrase in text, (phrase, text))


def run(body, user=person, operation="schedule-add"):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(user), "reportmanager", operation, {}, body)


def meta_of(row):
    return row["debug_info"]["metadata"]


BODY = {"title": "weekly", "dependencies": {"client": 1, "site": 10}}

# (1) a flagged create names the created record from Tactical's answer
fresh()
op = decl()
must([s.names_object for s in op.scope] == [False, False], op.scope)
route(PATH, FakeResponse(200, b'{"id": 77}'))
result = run(BODY)
must(result.status == 200 and len(CALLS) == 1, result.status)
must(len(ROWS) == 1 and ROWS[0]["action"] == "add", ROWS)
must(ROWS[0]["debug_info"]["object_id"] == "77", ROWS[0]["debug_info"])
must(meta_of(ROWS[0]).get("object_source") == "answer", meta_of(ROWS[0]))
must(ROWS[0]["after_value"] == {"title": "weekly"}, ROWS[0]["after_value"])
print("       a create with flagged scope entries names the record from Tactical's answer")

# (2) the same declaration without the flag names the client, as before
fresh()
decl(scope=[CLIENT, SITE])
route(PATH, FakeResponse(200, b'{"id": 77}'))
run(BODY)
must(ROWS[0]["debug_info"]["object_id"] == "1", ROWS[0]["debug_info"])
must(meta_of(ROWS[0]).get("object_source") is None, "the scope named it, not the answer")
fresh()
decl(scope=[{**CLIENT, "names_object": True}, SITE])
route(PATH, FakeResponse(200, b'{"id": 77}'))
run(BODY)
must(ROWS[0]["debug_info"]["object_id"] == "1", "an explicit true is the default")
# one flagged entry and one not: the entry that names the object still does
fresh()
decl(scope=[{**CLIENT, "names_object": False}, SITE])
route(PATH, FakeResponse(200, b'{"id": 77}'))
run(BODY)
must(ROWS[0]["debug_info"]["object_id"] == "10", ROWS[0]["debug_info"])
print("       without the flag the client names the row as before; with one flag the next entry does")

# (3) the scope check still denies a caller without scope, and the deny row is unchanged
for deps, label in (({"client": 2}, "client"), ({"site": 11}, "site"), ({"client": 1, "site": 11}, "mixed")):
    fresh()
    decl()
    route(PATH, FakeResponse(200, b'{"id": 77}'))
    refusal(lambda: run({"title": "t", "dependencies": deps}), 404, "object_not_found")
    must(not CALLS and len(ROWS) == 1 and ROWS[0]["action"] == "deny", (label, [r["action"] for r in ROWS]))
    flagged_row = (ROWS[0]["debug_info"]["object_id"], meta_of(ROWS[0]))
    fresh()
    decl(scope=[CLIENT, SITE])
    route(PATH, FakeResponse(200, b'{"id": 77}'))
    refusal(lambda: run({"title": "t", "dependencies": deps}), 404, "object_not_found")
    must((ROWS[0]["debug_info"]["object_id"], meta_of(ROWS[0])) == flagged_row, (label, "the deny row is the same with or without the flag"))
    must(flagged_row[0] == (str(deps["client"]) if "client" in deps else str(deps["site"])), (label, flagged_row))
print("       a caller without the client or site is denied before Tactical, and the deny row is unchanged by the flag")

# (4) a failed and an outcome-unknown row do not name the flagged entry; a Tactical denial does not either
for status, action in ((400, "custom:operation-failed"), (500, "custom:outcome-unknown"), (403, "deny")):
    fresh()
    decl()
    route(PATH, FakeResponse(status, b'{"id": 77}'))
    try:
        run(BODY)
    except ops.TacticalOperationError:
        pass
    rows = [r for r in ROWS if r["action"] == action]
    must(len(rows) == 1, (status, [r["action"] for r in ROWS]))
    must(rows[0]["debug_info"].get("object_id") in (None, ""), (status, rows[0]["debug_info"]))
    must("77" not in json.dumps(rows[0], default=str), (status, "no answer value on a row that is not a success"))
print("       a failed, outcome-unknown or Tactical-denied row does not name the flagged client or site")

# (5) the 400s are unchanged: a bad value is still refused, and a required flagged entry is still required
fresh()
decl()
route(PATH, FakeResponse(200, b'{"id": 77}'))
for deps in ("client", {"client": True}, {"client": {"id": 1}}, {"client": 1.5}, {"client": "  "}, {"client": list(range(1001))}):
    refusal(lambda: run({"title": "t", "dependencies": deps}), 400, "scope_field_required")
    must(not CALLS, deps)
fresh()
decl(scope=[{"type": "client", "source": "body:dependencies.client", "names_object": False}])
route(PATH, FakeResponse(200, b'{"id": 77}'))
refusal(lambda: run({"title": "t"}), 400, "scope_field_required")
must(run({"title": "t", "dependencies": {"client": 1}}).status == 200, "a present value runs")
print("       the 400 answers are unchanged")

# (6) registration
fresh()
bad("names_object must be true or false", id="b1", scope=[{**CLIENT, "names_object": "no"}])
bad("names_object must be true or false", id="b2", scope=[{**CLIENT, "names_object": 0}])
bad("names_object must be true or false", id="b3", scope=[{**CLIENT, "names_object": None}])
bad("names_object must be true or false", id="b4", scope=[{**CLIENT, "names_object": 1}])
bad("names_object must be true or false", id="b5", scope=[{**CLIENT, "names_object": []}])
for label, audit in (
    ("no source", {"action": "add", "object_type": "report_schedule"}),
    ("audit_fields only", {"action": "add", "object_type": "report_schedule", "audit_fields": ["title"]}),
):
    bad("nothing would name the audit row's object", id="a1", scope=[{**CLIENT, "names_object": False}], audit=audit)
    bad("nothing would name the audit row's object", id="a2", scope=[{**CLIENT, "names_object": False}, {**SITE, "names_object": False}], audit=audit)
for label, audit in (
    ("object_field", {"action": "add", "object_type": "report_schedule", "object_field": "id"}),
    ("object_body_field", {"action": "add", "object_type": "report_schedule", "object_body_field": "title"}),
    ("object_id", {"action": "add", "object_type": "report_schedule", "object_id": "schedule-add"}),
):
    fresh()
    decl(id=f"ok-{label}".replace("_", "-"), scope=[{**CLIENT, "names_object": False}], audit=audit)
# an unflagged entry alongside makes any audit declaration fine, and a mixed scope needs no extra source
fresh()
decl(id="mixed-ok", scope=[{**CLIENT, "names_object": False}, SITE], audit={"action": "add", "object_type": "report_schedule"})
# a flagged scope with an object_param is fine on a route that has the parameter
fresh()
ops.register_tactical_operation(
    id="edit-schedule", module_id="reportmanager", method="PUT", route="reporting/schedules/{schedule_id:int}/", permissions=[FLAG],
    scope=[{"type": "client", "source": "body:dependencies.client", "optional": True, "names_object": False}],
    body_fields=["title", "dependencies"], audit={"action": "modify", "object_type": "report_schedule", "object_param": "schedule_id"})
# a flagged entry is a different declaration from the unflagged one; identical re-registration is idempotent
fresh()
first = decl()
must(decl() == first, "identical re-registration is idempotent")
try:
    decl(scope=[CLIENT, SITE])
except ops.TacticalOperationRegistrationError:
    pass
else:
    raise AssertionError("the flag is part of the declaration")
print("       registration: a non-bool and an all-flagged scope with no object source are refused; every object source is accepted")

# (7) describe() shows the flag only when false
fresh()
decl(scope=[{**CLIENT, "names_object": False}, SITE])
got = ops.get_operation("reportmanager", "schedule-add")
must(got["scope"][0].get("names_object") is False and "names_object" not in got["scope"][1], got["scope"])
fresh()
decl(scope=[CLIENT, {**SITE, "names_object": True}])
got = ops.get_operation("reportmanager", "schedule-add")
must(all("names_object" not in entry for entry in got["scope"]), got["scope"])
print("       describe() shows names_object only on an entry that does not name the object")

# (8) the flag does not change which entries are checked: an agent entry and a path entry are untouched
fresh()
ops.register_tactical_operation(
    id="agent-op", module_id="agents", method="POST", route="agents/{agent_id:agent}/reboot/", permissions=[FLAG],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[], audit={"action": "run", "object_type": "agent"})
route(f"/agents/{AGENT}/reboot/", FakeResponse(200, b"{}"))
del CALLS[:]
del ROWS[:]
ops.run_tactical_operation(Request(person), "agents", "agent-op", {"agent_id": AGENT}, {})
must(ROWS[0]["debug_info"]["object_id"] == AGENT, ROWS[0]["debug_info"])
print("       an operation that does not use the flag names its object as before")

# (9) the capability and the docs
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.15.0" and meta["version"] == "1.15.0", meta["version"])
must("scope names_object" in " ".join(meta["declaration_keys_added_in_1_15_0"]), meta["declaration_keys_added_in_1_15_0"])
must(any("names_object" in text for text in meta["behaviour_added_in_1_15_0"]), "the rule is exported")
root = Path(__file__).resolve().parents[1]
doc = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("names_object", "audit.object_field", "Not built"):
    must(needle in doc, ("docs/tactical-operations.md", needle))
print("[TEST] PASS tactical operation names_object 1.17.52")
