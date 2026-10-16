#!/usr/bin/env python3
"""1.17.43 (request from agents 0.6.0, optional, low priority): metadata.object_count for a list-valued scope entry.

An operation whose first scope entry names more than one id writes the joined ids as the row's object id, cut at 255 characters. The
same call now also carries metadata.object_count: the number of ids. Covered: a three-id scope writes object_count 3 on the success,
tactical_denied deny, scope-refusal deny, failed and outcome-unknown rows; a one-id scope and an operation with no scope write no count;
the count is an int and never an id; the 255-character object id is unchanged for a 13-id scope; the capability is 1.12.0 and the
contract metadata names the key.

Uses the stubs of tests/tactical-operations-1.17.7.py, as the 1.17.42 test does.
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
ops, declare, must, fresh = (G[k] for k in ("ops", "declare", "must", "fresh"))
CALLS, ROWS, AGENT, Request, ROUTES, WORLD = (G[k] for k in ("CALLS", "ROWS", "AGENT", "Request", "ROUTES", "WORLD"))
FakeResponse, route = G["FakeResponse"], G["route"]

OTHER = "b" * 21
THIRD = "c" * 21
BULK_PATH = "/agents/actions/bulk/"
BULK_ROUTE = "agents/actions/bulk/"

# thirteen more agents, so a long selection's joined ids pass 255 characters
EXTRA = ["d" + str(index).zfill(20) for index in range(13)]
for agent_id in EXTRA:
    WORLD["agents"][agent_id] = 1
# the stub's tech user sees agent a only; this user sees every agent of the stub world, so the list is in scope
wide = G["User"]("wide", G["tech_role"])
wide.sees = {"agents": set(WORLD["agents"]), "clients": {1}, "sites": {10}}


def meta(row):
    return row["debug_info"]["metadata"]


def bulk(scope_ids_field="agents", **over):
    spec = dict(
        id="bulk-reboot", module_id="agents", method="POST", route=BULK_ROUTE, permissions=["can_reboot_agents"],
        scope=[{"type": "agent", "source": f"body:{scope_ids_field}"}], body_fields=["agents", "mode"],
        audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"]},
    )
    spec.update(over)
    return declare(**spec)


def run(agents, mode="now"):
    del CALLS[:]
    del ROWS[:]
    body = {"agents": agents, "mode": mode}
    return ops.run_tactical_operation(Request(wide), "agents", "bulk-reboot", {}, body)


def answer(status, content=b'{"ok": true}'):
    route(BULK_PATH, FakeResponse(status, content))


THREE = [AGENT, OTHER, THIRD]

# (1) success: a three-id scope writes object_count 3, the object id is the joined ids, and the count is a number, never an id
fresh()
bulk()
answer(200)
result = run(THREE)
must(result.status == 200 and len(ROWS) == 1, (result.status, len(ROWS)))
row = ROWS[0]
must(row["action"] == "run", row["action"])
must(meta(row)["object_count"] == 3 and isinstance(meta(row)["object_count"], int), meta(row))
must(not isinstance(meta(row)["object_count"], bool), "a count is not a boolean")
must(row["debug_info"]["object_id"] == ",".join(THREE), row["debug_info"]["object_id"])
must(all(str(value) not in repr(meta(row)["object_count"]) for value in THREE), "the count never holds an id")
print("       success: object_count 3, the object id unchanged, an int")

# (2) a one-id scope writes no count
fresh()
bulk()
answer(200)
run([AGENT])
must("object_count" not in meta(ROWS[0]), meta(ROWS[0]))
print("       one id: no object_count")

# (3) an operation with no scope writes no count
fresh()
bulk(scope=[])
answer(200)
run(THREE)
must("object_count" not in meta(ROWS[0]), meta(ROWS[0]))
print("       no scope: no object_count")

# (4) a Tactical 403 writes a deny row that carries the count
fresh()
bulk()
answer(403, b'{"detail": "denied"}')
result = run(THREE)  # a Tactical answer, whatever its status, comes back as the result
must(result.status == 403 and len(ROWS) == 1, (result.status, ROWS))
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and meta(ROWS[0])["object_count"] == 3, ROWS)
print("       tactical_denied (403): deny row with object_count 3")

# (5) a scope refusal (an agent the caller cannot see) writes a deny row that carries the count
fresh()
bulk()
answer(200)
try:
    run([AGENT, OTHER, "z" * 21])
except ops.TacticalOperationError as error:
    must(error.status == 404, error.status)
else:
    raise AssertionError("an agent outside the world is refused")
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and meta(ROWS[0])["object_count"] == 3, ROWS)
must(CALLS == [], "Tactical is not called for a refused scope")
print("       scope refusal (404): deny row with object_count 3, Tactical not called")

# (6) a Tactical 4xx on a change writes the failed row, which carries the count
fresh()
bulk()
answer(409, b'{"detail": "conflict"}')
result = run(THREE)
must(result.status == 409, result.status)
row = ROWS[0]
must(row["action"] == "custom:operation-failed" and meta(row)["object_count"] == 3, ROWS)
print("       failed (409): custom:operation-failed row with object_count 3")

# (7) a Tactical 5xx writes the outcome-unknown row, which carries the count
fresh()
bulk()
answer(500, b'{"detail": "boom"}')
result = run(THREE)
must(result.status == 500, result.status)
row = ROWS[0]
must(row["action"] == "custom:outcome-unknown" and meta(row)["object_count"] == 3, ROWS)
print("       outcome-unknown (500): custom:outcome-unknown row with object_count 3")

# (8) a long selection: the object id is still cut at 255 characters, and the count is the full number
fresh()
bulk()
answer(200)
long_selection = THREE + EXTRA
run(long_selection)
row = ROWS[0]
must(len(row["debug_info"]["object_id"]) == 255 and row["debug_info"]["object_id"] == ",".join(long_selection)[:255], (len(row["debug_info"]["object_id"]), row["debug_info"]["object_id"][:40]))
must(meta(row)["object_count"] == len(long_selection) == 16, meta(row))
print("       sixteen ids: the object id is cut at 255 characters as before, object_count 16")

# (9) the contract metadata names the key, and the capability is 1.12.0
meta_cap = ops.tactical_operations_contract_metadata()
must(meta_cap["version"] == "1.12.0", meta_cap["version"])
behaviour = " ".join(meta_cap["behaviour_added_in_1_12_0"])
must("object_count" in behaviour and "never an id" in behaviour, behaviour)
print("       contract metadata: object_count described, capability 1.12.0")

print("[TEST] PASS tactical operation object count 1.17.43")
