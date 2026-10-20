#!/usr/bin/env python3
"""1.17.58 held Low (1.17.52): metadata.object_count counts the entries that name the row's object.

A scope entry marked ``names_object: false`` is checked but does not name the audit row's object. Until 1.17.57 the count still came
from the first scope entry, so a row could name one site and count three clients. From 1.17.58 the success, failed, Tactical-denied and
outcome-unknown rows count the entries that name the object; the scope's own refusal rows keep the full-scope count.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operation-names-object-1.17.52.py does.
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
ops, must, fresh = (G[k] for k in ("ops", "must", "fresh"))
CALLS, ROWS, Request, route = (G[k] for k in ("CALLS", "ROWS", "Request", "route"))
FakeResponse, User, Roleish, refusal = (G[k] for k in ("FakeResponse", "User", "Roleish", "refusal"))

PATH = "/reporting/schedules/"
FLAG = "can_reboot_agents"
person = User("person", Roleish(FLAG))
person.sees = {"agents": set(), "clients": {1, 2, 3}, "sites": {10, 11, 12, 13}}
CLIENT = {"type": "client", "source": "body:dependencies.client", "optional": True}
SITE = {"type": "site", "source": "body:dependencies.site", "optional": True}


def decl(**over):
    spec = dict(
        id="schedule-add", module_id="reportmanager", method="POST", route="reporting/schedules/", permissions=[FLAG],
        scope=[{**CLIENT, "names_object": False}, SITE],
        body_fields=["title", "dependencies"], audit={"action": "add", "object_type": "report_schedule", "audit_fields": ["title"]},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run(body):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(person), "reportmanager", "schedule-add", {}, body)


def meta(row):
    return row["debug_info"]["metadata"]


def attempt(body):
    try:
        run(body)
    except ops.TacticalOperationError:
        pass


THREE = {"title": "t", "dependencies": {"client": [1, 2, 3], "site": 10}}

# (1) a flagged three-client list and one named site: the success row names the site and has no object_count
fresh()
decl()
route(PATH, FakeResponse(200, b'{"id": 5}'))
must(run(THREE).status == 200, "runs")
must(ROWS[0]["debug_info"]["object_id"] == "10" and "object_count" not in meta(ROWS[0]), (ROWS[0]["debug_info"], meta(ROWS[0])))
print("       success row: the site names the object, the three flagged clients are not counted")

# (2) the naming entry is a list of two: the success row counts those two, not the three flagged ones
fresh()
decl()
route(PATH, FakeResponse(200, b'{"id": 5}'))
run({"title": "t", "dependencies": {"client": [1, 2, 3], "site": [10, 11]}})
must(meta(ROWS[0]).get("object_count") == 2, meta(ROWS[0]))
print("       success row: the count is the naming entry's")

# (3) failed, Tactical-denied and outcome-unknown rows count what they name
for status, action in ((400, "custom:operation-failed"), (403, "deny"), (500, "custom:outcome-unknown")):
    fresh()
    decl()
    route(PATH, FakeResponse(status, b"{}"))
    attempt(THREE)
    rows = [r for r in ROWS if r["action"] == action]
    must(len(rows) == 1 and "object_count" not in meta(rows[0]), (status, [r["action"] for r in ROWS], rows and meta(rows[0])))
print("       failed, Tactical-denied and outcome-unknown rows follow the same rule")

# (4) the scope's own deny row keeps the full-scope count (client 9 is outside the caller's scope)
fresh()
decl()
route(PATH, FakeResponse(200, b'{"id": 5}'))
refusal(lambda: run({"title": "t", "dependencies": {"client": [1, 2, 9], "site": 10}}), 404, "object_not_found")
must(not CALLS and len(ROWS) == 1 and ROWS[0]["action"] == "deny", [r["action"] for r in ROWS])
must(meta(ROWS[0]).get("object_count") == 3, meta(ROWS[0]))
print("       the scope refusal row still carries the full count")

# (5) an operation with no names_object false entry is the same as 1.17.57: the first entry's count on every row
fresh()
decl(scope=[CLIENT, SITE])
route(PATH, FakeResponse(200, b'{"id": 5}'))
run(THREE)
must(meta(ROWS[0]).get("object_count") == 3 and ROWS[0]["debug_info"]["object_id"], (ROWS[0]["debug_info"], meta(ROWS[0])))
fresh()
decl(scope=[CLIENT, SITE])
route(PATH, FakeResponse(500, b"{}"))
attempt(THREE)
must([meta(r).get("object_count") for r in ROWS if r["action"] == "custom:outcome-unknown"] == [3], ROWS)
print("       an operation without a flagged entry keeps its count")
print("[TEST] PASS tactical operation object_count 1.17.58")
