#!/usr/bin/env python3
"""1.17.14 regression: the Core before-read scope check is gone (Johan CQ37, 9 October 2026).

The scope source ``before:<field>`` and the fail-closed 404 ``object_not_found`` that came from a before-read that did not answer 200
are removed. A pk-only operation (Agents note edit and delete: route ``agents/notes/{pk:int}/``, ``audit.object_param`` ``pk``, empty
``scope``) registers and runs with Tactical's own check deciding, as cancel-pending-action already did. ``audit.object_param`` is
unchanged, so the audit row still names the pk. ``audit.before`` stays as a NON-BLOCKING audit before-value (Johan's CQ42 assumption).

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-object-1.17.13.py does. The real
dispatch against Tactical's own note views is in tests/tactical-operations-runtime-1.17.13.py (a dev-server script).
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
ROUTES, CALLS, ROWS, AGENT, OTHER, tech, Request, FakeResponse = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "OTHER", "tech", "Request", "FakeResponse"))

NOTE_FIELDS = ["agent_id", "note", "user"]
BEFORE = {"route": "agents/notes/{pk:int}/", "fields": NOTE_FIELDS}


def spec(**over):
    base = dict(
        id="note-edit", module_id="agents", method="PUT", route="agents/notes/{pk:int}/", permissions=["can_manage_notes"],
        scope=[], body_fields=["note"], audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk"},
    )
    base.update(over)
    return base


def refused_registration(**over):
    try:
        ops.register_tactical_operation(**spec(**over))
    except ops.TacticalOperationRegistrationError as exc:
        return str(exc)
    raise AssertionError(f"registration was accepted: {over}")


fresh()
# ------------------------------------------------------------------------------------------------ registration
for audit in (spec()["audit"], {**spec()["audit"], "before": BEFORE}):
    for source_name in ("before:agent_id", "before:note", "before:nope", "before:"):
        message = refused_registration(scope=[{"type": "agent", "source": source_name}], audit=audit)
        must("removed in Core 1.17.14" in message and "Tactical's own check decides" in message, (source_name, message))
must(not ops.list_operations(), "a refused declaration left no trace")
# the other sources are unchanged: a path source still registers
ops.register_tactical_operation(**spec(id="scoped-by-path", method="POST", route="agents/{agent_id:agent}/wol/", permissions=["can_send_wol"], body_fields=[],
                                       scope=[{"type": "agent", "source": "path:agent_id"}], audit={"action": "modify", "object_type": "agent_wol", "audit_fields": []}))
must(ops.get_operation("agents", "scoped-by-path")["scope"] == [{"type": "agent", "source": "path:agent_id"}], "path source still works")
must("path:<name> or body:<field>" in refused_registration(scope=[{"type": "agent", "source": "query:x"}]), "the refusal lists only the sources that remain")
must(ops._SCOPE_SOURCE_RE.match("before:agent_id") is None and ops._SCOPE_SOURCE_RE.match("path:pk") and ops._SCOPE_SOURCE_RE.match("body:id"), "the pattern")

# a pk-only note edit and delete register: empty scope, object_param pk, no before
edit = ops.register_tactical_operation(**spec(id="note-edit-plain"))
delete = ops.register_tactical_operation(**spec(id="note-delete-plain", method="DELETE", body_fields=[]))
must(edit.scope == () and edit.audit_object_param == "pk" and edit.before is None, edit)
must(ops.get_operation("agents", "note-edit-plain")["scope"] == [] and ops.get_operation("agents", "note-edit-plain")["audit"]["object_param"] == "pk", "described")

# ------------------------------------------------------------------------------------------------ execution
NOTE = "/agents/notes/5/"


def notes_view(agent=AGENT, read_status=200, read_boom=None, write_status=200):
    record = {"agent_id": agent, "note": "N" * 400, "user": "tech", "password": "never-copied"}

    def view(request, *args, **kwargs):
        CALLS.append(SimpleNamespace(request=request, method=request.method))
        if request.method == "GET":
            if read_boom:
                raise read_boom
            return FakeResponse(read_status, json.dumps(record).encode())
        return FakeResponse(write_status, b'"ok"')
    return view


def call(operation, user=tech, params=None, body=None):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(user), "agents", operation, params, body)


# no audit.before: exactly one Tactical call, the change, and the row names the pk
ROUTES[NOTE] = (notes_view(), (), {})
result = call("note-edit-plain", params={"pk": 5}, body={"note": "changed"})
must(result.status == 200 and [c.method for c in CALLS] == ["PUT"], [c.method for c in CALLS])
must(json.loads(CALLS[0].request._body) == {"note": "changed"}, "the body reaches Tactical")
must(len(ROWS) == 1 and ROWS[0]["action"] == "modify" and ROWS[0]["object_type"] == "agent_note" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS)
must(ROWS[0]["before_value"] is None and "before" not in ROWS[0]["debug_info"]["metadata"], "no before declared, no before read")
result = call("note-delete-plain", params={"pk": 5})
must([c.method for c in CALLS] == ["DELETE"] and ROWS[0]["debug_info"]["object_id"] == "5", (CALLS, ROWS))
# a note on an agent the role cannot see: Core refuses nothing of its own. Tactical's own check answers, and Core audits that answer
ROUTES[NOTE] = (notes_view(agent=OTHER, write_status=403), (), {})
result = call("note-edit-plain", params={"pk": 5}, body={"note": "x"})
must(result.status == 403 and [c.method for c in CALLS] == ["PUT"], CALLS)
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["metadata"]["reason"] == "tactical_denied" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS)
# a Tactical 404 (no such note) comes back as the answer; there is no Core object_not_found
ROUTES[NOTE] = (notes_view(write_status=404), (), {})
result = call("note-edit-plain", params={"pk": 5}, body={"note": "x"})
must(result.status == 404, result.status)
must(not any(row["action"] == "deny" and row["debug_info"]["metadata"].get("reason") == "not_found" for row in ROWS), ROWS)
# parameter shape is still checked before anything runs
for bad in ({"pk": "abc"}, {"pk": None}, {}):
    try:
        call("note-edit-plain", params=bad, body={"note": "x"})
    except ops.TacticalOperationError as exc:
        must(exc.status == 400 and exc.code == "invalid_params", (bad, exc.code))
    else:
        raise AssertionError(bad)
must(not CALLS, "nothing runs for a bad parameter")

# audit.before alone still records a before value, and never blocks. One caller per Tactical route, so the plain operations go first.
fresh()
ops.register_tactical_operation(**spec(id="note-edit-before", audit={**spec()["audit"], "before": BEFORE}))
must(ops.get_operation("agents", "note-edit-before")["audit"]["before"] == BEFORE, "audit.before is kept")
ROUTES[NOTE] = (notes_view(), (), {})
result = call("note-edit-before", params={"pk": 5}, body={"note": "x"})
must(result.status == 200 and [c.method for c in CALLS] == ["GET", "PUT"], CALLS)
before = ROWS[0]["before_value"]
must(before["agent_id"] == AGENT and before["note"] == "N" * 256 and "password" not in json.dumps(before), before)
must(ROWS[0]["debug_info"]["metadata"]["before"] == "recorded", ROWS[0]["debug_info"]["metadata"])
# a failed before-read does not block, whatever way it fails
for view, status in ((notes_view(read_status=403), 403), (notes_view(read_status=404), 404), (notes_view(read_status=500), 500), (notes_view(read_boom=RuntimeError("down")), None)):
    ROUTES[NOTE] = (view, (), {})
    result = call("note-edit-before", params={"pk": 5}, body={"note": "x"})
    must(result.status == 200 and [c.method for c in CALLS] == ["GET", "PUT"], (status, CALLS))
    meta = ROWS[0]["debug_info"]["metadata"]
    must(ROWS[0]["action"] == "modify" and ROWS[0]["before_value"] is None and meta["before"] == "unavailable", (status, ROWS[0]))
# a read of an agent the role cannot see does not refuse either: the read is for the audit row only
ROUTES[NOTE] = (notes_view(agent=OTHER), (), {})
result = call("note-edit-before", params={"pk": 5}, body={"note": "x"})
must(result.status == 200 and ROWS[0]["action"] == "modify" and ROWS[0]["before_value"]["agent_id"] == OTHER, ROWS)

# ------------------------------------------------------------------------------------------------ the capability and the docs
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.3.0" and meta["version"] == "1.3.0" and meta["version"].split(".")[0] == "1", "capability 1.3.0, still major 1")
must("scope source before:<field>" in meta["declaration_keys_removed_in_1_2_0"], meta)
must("scope source before:<field>" not in meta["declaration_keys_added_in_1_1_0"], meta)
text = (Path(__file__).resolve().parents[1] / "docs/tactical-operations.md").read_text(encoding="utf-8")
must("removed in 1.17.14" in text and "before:<field>" in text, "docs/tactical-operations.md names the removal")
contracts = (Path(__file__).resolve().parents[1] / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("was removed in 1.17.14" in contracts and "source before:<field> (field listed" not in contracts, "the contract text states the removal")

print("[TEST] PASS tactical operations before scope 1.17.14")
