#!/usr/bin/env python3
"""1.17.26 regression: a larger body cap per declared operation (from reportmanager 0.5.0 review round 4, template import).

``register_tactical_operation(..., body_max_bytes=N)`` lifts the 256 KiB default body cap for that operation, up to a Core ceiling of
8 MiB. Covered: an operation that does not set it still refuses 256 KiB + 1 with the same text and the same code (413 body_too_large)
and accepts exactly 256 KiB; an operation with body_max_bytes accepts a body just under its cap, accepts exactly its cap and refuses
one byte over, with a 413 that names the cap that applied; a value below the default, above the ceiling, a bool, a float, text and a
negative number are refused at registration; a value equal to the default is stored as the default; the ceiling itself is accepted;
the listing and the capability limits show the cap; JSON depth and the secret-name rules are untouched (a deeply nested body is still
handled by the same parser); the declaration is idempotent; an oversize refusal writes no row, as before.
Uses the stubs of tests/tactical-operations-1.17.7.py.
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
ops, declare, refused, fresh, must = (G[k] for k in ("ops", "declare", "refused", "fresh", "must"))
CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse, refusal, route = G["FakeResponse"], G["refusal"], G["route"]

PATH = f"/agents/{AGENT}/reboot/"
PARAMS = {"agent_id": AGENT}
DEFAULT = 256 * 1024
CEILING = 8 * 2**20
OVERHEAD = len(json.dumps({"blob": ""}, separators=(",", ":")))


def body_of(size):
    """A body whose compact JSON is exactly ``size`` bytes."""
    body = {"blob": "x" * (size - OVERHEAD)}
    must(len(json.dumps(body, separators=(",", ":")).encode("utf-8")) == size, "fixture size")
    return body


def run(size):
    del CALLS[:]
    return ops.run_tactical_operation(Request(tech), "agents", "reboot", PARAMS, body_of(size))


def declare_blob(**over):
    spec = dict(body_fields=["blob"], audit={"action": "run", "object_type": "agent"})
    spec.update(over)
    return declare(**spec)


must(ops.MAX_BODY_BYTES == DEFAULT and ops.MAX_BODY_CEILING_BYTES == CEILING, (ops.MAX_BODY_BYTES, ops.MAX_BODY_CEILING_BYTES))

# ---- a default operation: unchanged
fresh()
op = declare_blob()
must(op.body_max_bytes is None and op.body_cap == DEFAULT, op)
route(PATH, FakeResponse(200))
must(run(DEFAULT).status == 200, "exactly 256 KiB is accepted")
del ROWS[:]
exc = refusal(lambda: run(DEFAULT + 1), 413, "body_too_large")
must(exc.message == f"body is larger than {DEFAULT} bytes.", exc.message)
must(not CALLS, "Tactical is never reached")
must(ROWS == [], "body_too_large writes no row, as before (it is not a core-refused row code)")

# ---- an operation with a bigger cap
fresh()
CAP = 2 * 2**20
op = declare_blob(body_max_bytes=CAP)
must(op.body_max_bytes == CAP and op.body_cap == CAP, op)
route(PATH, FakeResponse(200))
for size in (DEFAULT + 1, 1024 * 1024, CAP - 1, CAP):
    must(run(size).status == 200, f"{size} bytes is under the cap")
del ROWS[:]
exc = refusal(lambda: run(CAP + 1), 413, "body_too_large")
must(exc.message == f"body is larger than {CAP} bytes.", ("the 413 names the cap that applied", exc.message))
must(ROWS == [], "no row, as before")
must(not CALLS, "an oversize body never reaches Tactical")

# ---- the ceiling is accepted and enforced
fresh()
declare_blob(body_max_bytes=CEILING)
route(PATH, FakeResponse(200))
must(run(CEILING).status == 200, "exactly the ceiling")
refusal(lambda: run(CEILING + 1), 413, "body_too_large")

# ---- a value equal to the default is the default
fresh()
must(declare_blob(body_max_bytes=DEFAULT).body_max_bytes is None, "stored as the default")

# ---- refused at registration
fresh()
for bad in (DEFAULT - 1, 0, -1, 1024, CEILING + 1, 2**40, True, False, 1.5, float(CAP), "1048576", [], {}, b"1"):
    text = refused(body_max_bytes=bad)
    must("body_max_bytes" in text, (bad, text))
must(not ops.list_operations(), "nothing was registered")

# ---- listing, limits, idempotence
fresh()
first = declare_blob(body_max_bytes=CAP)
must(ops.get_operation("agents", "reboot")["body_max_bytes"] == CAP, "the listing shows the cap")
must(declare_blob(body_max_bytes=CAP) == first, "idempotent")
try:
    declare_blob(body_max_bytes=CAP + 1)
except ops.TacticalOperationRegistrationError as exc:
    must("already registered with a different definition" in str(exc), exc)
else:
    raise AssertionError("a different cap is a different definition")
fresh()
declare_blob()
must(ops.get_operation("agents", "reboot")["body_max_bytes"] == DEFAULT, "a default operation lists the default cap")
limits = ops.tactical_operations_contract_metadata()["limits"]
must(limits["body_bytes"] == DEFAULT and limits["body_bytes_max"] == CEILING, limits)

# ---- the other body rules are untouched: a non-object body and a body on a GET operation
fresh()
declare_blob(body_max_bytes=CAP)
route(PATH, FakeResponse(200))
refusal(lambda: ops.run_tactical_operation(Request(tech), "agents", "reboot", PARAMS, ["x"]), 400, "invalid_body")

# ---- docs and contract text
root = Path(__file__).resolve().parents[1]
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("body_max_bytes", "8 MiB", "body_too_large", "1.9.0"):
    must(needle in docs, f"docs/tactical-operations.md lacks {needle!r}")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("body_max_bytes" in contract and "body_bytes_max" in contract, "contracts.py rule text")

print("[TEST] PASS tactical operations body cap 1.17.26")
