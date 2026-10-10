#!/usr/bin/env python3
"""1.17.17 regression: names are matched with fullmatch, so a trailing newline is refused (held Low from 1.17.16).

``$`` in a Python pattern also matches just before a final newline, so ``_FIELD_RE.match("action\n")`` passed. The
``audit_before`` names, the declared field names (body_fields, query_params, audit_fields, audit.before fields) and the upload
field name now use ``fullmatch``. Built on the stubs of tests/tactical-operations-1.17.7.py like
tests/tactical-operations-audit-before-1.17.16.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
ops, declare, fresh, must = (G[k] for k in ("ops", "declare", "fresh", "must"))
ROWS, CALLS, AGENT, tech, Request = (G[k] for k in ("ROWS", "CALLS", "AGENT", "tech", "Request"))
FakeResponse, refusal, route, refused = G["FakeResponse"], G["refusal"], G["route"], G["refused"]

PATH = f"/agents/{AGENT}/reboot/"
PARAMS, BODY = {"agent_id": AGENT}, {"mode": "now"}
fresh()
declare()
route(PATH, FakeResponse(200))


def run(before):
    return ops.run_tactical_operation(Request(tech), "agents", "reboot", PARAMS, BODY, audit_before=before)


# ---- audit_before
del ROWS[:], CALLS[:]
refusal(lambda: run({"action\n": "x"}), 400, "invalid_audit_before")
must(not ROWS and not CALLS, "a newline-ended name writes nothing and reaches nothing")
for bad in ({"a\n": 1}, {"\naction": 1}, {"ac\ntion": 1}):
    refusal(lambda bad=bad: run(bad), 400, "invalid_audit_before")
del ROWS[:]
run({"action": "x"})
must(len(ROWS) == 1 and ROWS[0]["before_value"] == {"action": "x"}, ROWS)

# ---- declaration names
for label, over in (
    ("body field", dict(body_fields=["mode\n"], audit={"action": "run", "object_type": "agent", "audit_fields": []})),
    ("audit field", dict(audit={"action": "run", "object_type": "agent", "audit_fields": ["mode\n"]})),
    ("query param", dict(id="q1", method="GET", body_fields=[], query_params=["name\n"], audit={"action": "view", "object_type": "agent"})),
):
    message = refused(**over)
    must("invalid name" in message or "not one of" in message, (label, message))

# the same names without the newline register
declare(id="ok1", route="agents/{agent_id:agent}/ok1/", body_fields=["mode"], audit={"action": "run", "object_type": "agent", "audit_fields": ["mode"]})
declare(id="ok2", method="GET", route="agents/{agent_id:agent}/ok2/", body_fields=[], query_params=["name"], audit={"action": "view", "object_type": "agent"})

# audit.before fields
before_spec = {"route": "agents/notes/{pk:int}/", "fields": ["note\n"]}
common = dict(module_id="agents", method="PUT", route="agents/notes/{pk:int}/", permissions=["can_manage_notes"], scope=[], body_fields=["note"])
try:
    ops.register_tactical_operation(id="note-bad", audit={"action": "modify", "object_type": "agent_note", "audit_fields": [],
                                                           "object_param": "pk", "before": before_spec}, **common)
    raise AssertionError("audit.before field with a newline registered")
except ops.TacticalOperationRegistrationError:
    pass
ops.register_tactical_operation(id="note-ok", audit={"action": "modify", "object_type": "agent_note", "audit_fields": [],
                                                      "object_param": "pk", "before": {"route": "agents/notes/{pk:int}/", "fields": ["note"]}}, **common)

# upload field name
upload_common = dict(module_id="reportmanager", method="POST", route="reporting/assets/upload/", permissions=["can_manage_clients"], scope=[],
                     body_fields=[], audit={"action": "add", "object_type": "report_asset", "audit_fields": []})
for field, good in (("doc\n", False), ("doc", True)):
    try:
        ops.register_tactical_operation(id=f"upl-{int(good)}", upload={"field": field, "max_bytes": 1000, "extensions": ["png"]}, **upload_common)
        must(good, "upload field with a newline registered")
    except ops.TacticalOperationRegistrationError:
        must(not good, "plain upload field refused")
    ops._clear_operations_for_tests()

print("[TEST] PASS tactical operations audit before fullmatch 1.17.17")
