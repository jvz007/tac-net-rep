#!/usr/bin/env python3
"""1.17.23 regression: list values in the caller's ``audit_before`` (requests: from automation 0.8.1, from Core 1.17.21 review).

``audit_before`` is a Python-only keyword of ``run_tactical_operation``. Since 1.17.23 a field may hold a list of whole numbers or
short strings. It is kept to its first 1000 entries as declared before fields are, with ``<field>_count`` (the full length) and,
when cut, ``<field>_truncated: true``. Anything else in a list, a ``<list>_count`` or ``<list>_truncated`` clash, a tuple, a
secret-looking name or more than 16 caller fields is still refused 400 ``invalid_audit_before`` with one ``core_refused`` row and
no Tactical call. Scalar callers are unchanged. The capability is 1.8.0. Uses the stubs of tests/tactical-operations-1.17.7.py the
way tests/tactical-operations-audit-before-1.17.16.py does. This test fails on 1.17.22.
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
ops, declare, fresh, must = (G[k] for k in ("ops", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request"))
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


def recorded(before):
    del ROWS[:]
    run(before)
    must(len(ROWS) == 1, ROWS)
    must(meta(ROWS[0])["before_source"] == "caller" and meta(ROWS[0])["before"] == "recorded", meta(ROWS[0]))
    return ROWS[0]["before_value"]


# ---- the capability
must(ops.CAPABILITY_VERSION == "1.12.0", ops.CAPABILITY_VERSION)
info = ops.tactical_operations_contract_metadata()
must(info["version"] == "1.12.0" and info["version"].split(".")[0] == "1" and info["behaviour_added_in_1_8_0"], info)

# ---- lists of whole numbers and of short strings are recorded with their count
must(recorded({"ids": [1, 2, 3]}) == {"ids": [1, 2, 3], "ids_count": 3}, "ints")
must(recorded({"names": ["a", "bb", ""]}) == {"names": ["a", "bb", ""], "names_count": 3}, "strings")
must(recorded({"mixed": [1, "two", 3]}) == {"mixed": [1, "two", 3], "mixed_count": 3}, "mixed ints and strings")
must(recorded({"s": ["x" * 256]})["s"] == ["x" * 256], "256 characters is the limit")
# an empty list is recorded with count 0 and no flag
must(recorded({"ids": []}) == {"ids": [], "ids_count": 0}, "empty list")
# a list beside scalars and a second list
value = recorded({"action": "run", "n": 2, "ids": [7], "tags": ["a"]})
must(value == {"action": "run", "n": 2, "ids": [7], "ids_count": 1, "tags": ["a"], "tags_count": 1}, value)

# ---- 1000 entries are all kept; 1001 and 2500 are cut to 1000 with the full count and a flag
value = recorded({"ids": list(range(1000))})
must(len(value["ids"]) == 1000 and value["ids_count"] == 1000 and "ids_truncated" not in value, "1000 kept whole")
for total in (1001, 2500):
    value = recorded({"ids": list(range(total))})
    must(value["ids"] == list(range(1000)) and value["ids_count"] == total and value["ids_truncated"] is True, f"{total} cut to 1000")

# ---- a list caps at 65536 characters like a declared field, and the count and flag say so
value = recorded({"names": ["y" * 200] * 400})
must(len(value["names"]) < 400 and value["names_count"] == 400 and value["names_truncated"] is True, "character cap")
must(sum(len(x) for x in value["names"]) <= 65536 + 200, "kept characters stay near the cap")

# ---- 16 caller fields still the limit; the two Core-written keys do not use it up
value = recorded({**{f"f{i}": i for i in range(15)}, "ids": [1, 2]})
must(len(value) == 17 and value["ids_count"] == 2, value)
refusal_cases = [{f"f{i}": i for i in range(17)}]

# ---- refused: one core_refused row, no Tactical call
refusal_cases += [
    {"ids": [True]}, {"ids": [False, 1]}, {"ids": [1.5]}, {"ids": [None]}, {"ids": [[1]]}, {"ids": [{"a": 1}]}, {"ids": [b"x"]},
    {"ids": ["x" * 257]}, {"ids": ["a\nb"]}, {"ids": ["a\x00b"]}, {"ids": (1, 2)}, {"ids": {1, 2}},
    {"ids": [1], "ids_count": 1}, {"ids": [1], "ids_truncated": False}, {"ids_count": 5, "ids": []},
    {"password": [1]}, {"api_token": ["x"]}, {"secret_ids": [1]},
    {"ids": [1, 2, 3, {"late": 1}]}, {"ids": list(range(2000)) + [1.5]},
]
for bad in refusal_cases:
    del ROWS[:], CALLS[:]
    exc = refusal(lambda bad=bad: run(bad), 400, "invalid_audit_before")
    summary = str(bad)[:80]
    must(not CALLS, f"{summary}: Tactical is never reached")
    must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:operation-failed", f"{summary}: one Core row")
    must(meta(ROWS[0])["code"] == "invalid_audit_before" and not ROWS[0].get("before_value"), ROWS[0])
    must(exc.audit is not None and exc.audit["recorded"] is True, exc.audit)
# a clash on a name that is not next to a list is a plain scalar field and is fine
must(recorded({"ids_count": 5}) == {"ids_count": 5}, "a scalar named like a count is allowed on its own")

# ---- scalar-only callers are byte for byte unchanged
must(recorded({"update_action": "approve", "count": 3, "reviewed": True, "note": None}) == {"update_action": "approve", "count": 3, "reviewed": True, "note": None}, "scalars")
del ROWS[:]
run({})
must(ROWS[0]["before_value"] == {} and meta(ROWS[0])["before_source"] == "caller", ROWS[0])
del ROWS[:]
run(None)
must(ROWS[0].get("before_value") is None and "before_source" not in meta(ROWS[0]), ROWS[0])

# ---- the cleaner does not change the caller's own list
mine = {"ids": list(range(1500))}
run(mine)
must(mine == {"ids": list(range(1500))}, "the caller's object is untouched")

# ---- the message names lists
try:
    run({"ids": [1.5]})
except ops.TacticalOperationError as exc:
    must("list of whole numbers or texts" in exc.message, exc.message)

# ---- the HTTP view still refuses audit_before (source check: the view passes no such keyword)
views_src = (Path(__file__).resolve().parents[1] / "framwork/tec_tac/tactical_operation_views.py")
if views_src.exists():
    must("audit_before" not in views_src.read_text(encoding="utf-8").replace("audit_before is Python only", ""), "the HTTP view never forwards audit_before")

# ---- the docs and the contract text carry it
root = Path(__file__).resolve().parents[1]
doc = (root / "docs/tactical-operations.md").read_text(encoding="utf-8")
for needle in ("1.8.0", "A list in `audit_before`", "<field>_truncated", "<list>_count"):
    must(needle in doc, needle)
contract = (root / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("capability core.tactical_operations 1.8.0" in contract and "since 1.17.23 a list of whole numbers or texts" in contract, "contract text")

print("[TEST] PASS tactical operations audit_before lists 1.17.23")
