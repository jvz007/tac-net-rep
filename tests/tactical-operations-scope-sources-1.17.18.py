#!/usr/bin/env python3
"""1.17.18 regression: new scope sources for Tactical operations (Johan item 4; CQ56 a, CQ57).

Optional scope entries (skipped when the body field is absent), client and site id lists, the ``agent_pk`` type, and row
lookups that a core module registers with ``register_tactical_row_lookup`` so Core can apply the role's scope to the agent of the
row a path id loads. A row with no agent is allowed to anyone who holds the Tactical flag (CQ57). Core never reads Tactical
models; the lookup answers wrong, missing or raising fail closed with 404 ``object_not_found``. Uses the stubs of
tests/tactical-operations-1.17.7.py.
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
ops, declare, fresh, must, refused = (G[k] for k in ("ops", "declare", "fresh", "must", "refused"))
CALLS, ROWS, AGENT, OTHER, tech, Request, User, Roleish = (G[k] for k in ("CALLS", "ROWS", "AGENT", "OTHER", "tech", "Request", "User", "Roleish"))
FakeResponse, refusal, route, adapter = G["FakeResponse"], G["refusal"], G["route"], G["adapter"]

# agent numbers: pk 1 is visible to tech, 2 exists, 9 does not
PK_WORLD, PK_VISIBLE = {1, 2, 3}, {1}
adapter.agent_pks_in_role_scope = lambda *, user, pks: bool(pks) and all(int(p) in PK_WORLD and int(p) in getattr(user, "sees_pks", PK_VISIBLE) for p in pks)

fresh()
BULK = "/agents/maintenance/bulk/"
ops.register_tactical_operation(
    id="bulk", module_id="agents", method="POST", route="agents/maintenance/bulk/", permissions=["can_reboot_agents"],
    scope=[{"type": "client", "source": "body:excluded_clients", "optional": True},
           {"type": "site", "source": "body:excluded_sites", "optional": True},
           {"type": "agent_pk", "source": "body:excluded_agents", "optional": True}],
    body_fields=["excluded_clients", "excluded_sites", "excluded_agents", "name"],
    audit={"action": "modify", "object_type": "agent", "audit_fields": ["name"]},
)
route(BULK, FakeResponse(200))


def bulk(body, user=tech):
    del CALLS[:]
    return G["run"](user=user, params={}, body=body, module="agents", operation="bulk")


del ROWS[:]
# optional entries absent, null or an empty list: nothing is checked
for body in ({}, {"name": "x"}, {"excluded_clients": None}, {"excluded_clients": [], "excluded_sites": [], "excluded_agents": []}):
    must(bulk(body).status == 200 and len(CALLS) == 1, body)
must(ROWS and all(r["action"] == "modify" for r in ROWS), "the rows are written")
# the audit object id is empty when no entry was resolved
must(ROWS[-1]["debug_info"].get("object_id") in (None, ""), ROWS[-1]["debug_info"])

# present entries are checked
must(bulk({"excluded_clients": [1]}).status == 200 and bulk({"excluded_sites": [10]}).status == 200 and bulk({"excluded_agents": [1]}).status == 200, "in scope")
must(bulk({"excluded_clients": [1], "excluded_sites": [10], "excluded_agents": ["1"]}).status == 200, "all three")
del ROWS[:]
for body in ({"excluded_clients": [1, 2]}, {"excluded_clients": [2]}, {"excluded_clients": [1, 99]}, {"excluded_sites": [10, 11]}, {"excluded_sites": [11]},
              {"excluded_agents": [1, 2]}, {"excluded_agents": [9]}, {"excluded_agents": [2]}):
    refusal(lambda body=body: bulk(body), 404, "object_not_found")
    must(not CALLS, f"Tactical is not reached for {body}")
must(len(ROWS) == 8 and all(r["action"] == "deny" for r in ROWS), "each refusal writes a deny row")
# malformed values are 400, never a pass
for body in ({"excluded_clients": [True]}, {"excluded_clients": [1.5]}, {"excluded_clients": [None]}, {"excluded_clients": [{"a": 1}]}, {"excluded_clients": [""]},
             {"excluded_agents": ["a1"]}, {"excluded_agents": [0]}, {"excluded_agents": [-1]}, {"excluded_agents": [2 ** 70]}, {"excluded_agents": [3.0]},
             {"excluded_agents": list(range(1, 1002))}):
    refusal(lambda body=body: bulk(body), 400, "scope_field_required")
# a scope entry that is NOT optional is still required
fresh()
ops.register_tactical_operation(
    id="needs", module_id="agents", method="POST", route="agents/maintenance/bulk/", permissions=["can_reboot_agents"],
    scope=[{"type": "client", "source": "body:excluded_clients"}], body_fields=["excluded_clients"], audit={"action": "modify", "object_type": "agent"},
)
route(BULK, FakeResponse(200))
refusal(lambda: G["run"](user=tech, params={}, body={}, module="agents", operation="needs"), 400, "scope_field_required")
refusal(lambda: G["run"](user=tech, params={}, body={"excluded_clients": []}, module="agents", operation="needs"), 400, "scope_field_required")

# ---- registration refusals
fresh()
base = dict(id="o", module_id="agents", method="POST", route="agents/maintenance/bulk/", permissions=["can_reboot_agents"],
            body_fields=["a", "b"], audit={"action": "modify", "object_type": "agent"})


def reg(scope, **over):
    return ops.register_tactical_operation(**{**base, "scope": scope, **over})


def reg_refused(scope, text="", **over):
    try:
        reg(scope, **over)
    except ops.TacticalOperationRegistrationError as exc:
        must(text in str(exc), str(exc))
        return
    raise AssertionError(f"accepted: {scope}")


reg_refused([{"type": "client", "source": "body:a", "optional": "yes"}], "true or false")
reg_refused([{"type": "client", "source": "body:a", "optional": 1}], "true or false")
reg_refused([{"type": "agent_pk", "source": "body:nope", "optional": True}], "not one of body_fields")
reg_refused([{"type": "agent_pk", "source": "path:x"}], "not a parameter", route="agents/maintenance/bulk/")
# optional belongs to a body source
reg_refused([{"type": "agent", "source": "path:agent_id", "optional": True}], "body source", route="agents/{agent_id:agent}/wol/")
# row_lookup: shape and placement
LOOK = dict(route="agents/notes/{pk:int}/", method="PUT", body_fields=["note"])
reg_refused([{"type": "agent", "source": "path:pk", "row_lookup": "Bad Id"}], "lookup id", **LOOK)
reg_refused([{"type": "agent", "source": "path:pk", "row_lookup": 5}], "lookup id", **LOOK)
reg_refused([{"type": "agent", "source": "body:note", "row_lookup": "note-row"}], "never a body source", **LOOK)
reg_refused([{"type": "client", "source": "path:pk", "row_lookup": "note-row"}], "agent entry", **LOOK)
reg_refused([{"type": "agent", "source": "path:agent_id", "row_lookup": "note-row"}], "must be an int", route="agents/{agent_id:agent}/wol/", method="POST", body_fields=[])
reg_refused([{"type": "agent", "source": "path:pk", "row_lookup": "one"}, {"type": "agent", "source": "path:pk", "row_lookup": "two"}], "one row_lookup", **LOOK)
reg_refused([{"type": "agent", "source": "path:pk"}], "string parameter for an agent", **LOOK)  # without a lookup an int agent is still refused
reg_refused([{"type": "agent", "source": "path:pk", "row_lookup": "note-row", "extra": 1}], "nothing else", **LOOK)
must(ops.list_operations() == [], "no refused declaration left a trace")
good = reg([{"type": "agent", "source": "path:pk", "row_lookup": "note-row"}], id="note-edit", **LOOK)
must(good.scope[0].row_lookup == "note-row", good)
described = ops.get_operation("agents", "note-edit")
must(described["scope"] == [{"type": "agent", "source": "path:pk", "row_lookup": "note-row"}], described)
fresh()
reg([{"type": "client", "source": "body:a", "optional": True}], id="opt")
must(ops.get_operation("agents", "opt")["scope"] == [{"type": "client", "source": "body:a", "optional": True}], "describe lists optional")

# ---- register_tactical_row_lookup
fresh()
ROW_ANSWERS = {}


def note_row(pk):
    return ROW_ANSWERS[pk]() if callable(ROW_ANSWERS.get(pk)) else ROW_ANSWERS.get(pk)


def lookup_refused(*args, text=""):
    try:
        ops.register_tactical_row_lookup(*args)
    except ops.TacticalOperationRegistrationError as exc:
        must(isinstance(exc, ValueError) and text in str(exc), str(exc))
        return
    raise AssertionError(f"accepted: {args}")


lookup_refused("agents", "Bad Id", note_row, text="slug")
lookup_refused("agents", "", note_row, text="slug")
lookup_refused("agents", "note-row", "not callable", text="function")
lookup_refused("agents", "note-row", None, text="function")
lookup_refused("nosuchmodule", "note-row", note_row)
lookup_refused("core", "note-row", note_row)
lookup_refused("oldmod", "note-row", note_row)
lookup_refused("premiumdemo", "note-row", note_row, text="not a core module")
lookup_refused("offmod", "note-row", note_row)
must(ops.register_tactical_row_lookup("agents", "note-row", note_row) is note_row)
must(ops.register_tactical_row_lookup("agents", "note-row", note_row) is note_row, "idempotent")
lookup_refused("agents", "note-row", lambda pk: None, text="different function")

# ---- a row lookup at run time
NOTE = "/agents/notes/5/"
reg([{"type": "agent", "source": "path:pk", "row_lookup": "note-row"}], id="note-edit", permissions=["can_manage_notes"],
    audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk"}, **LOOK)
route(NOTE, FakeResponse(200))


def edit(user=tech, pk=5):
    del CALLS[:]
    return G["run"](user=user, params={"pk": pk}, body={"note": "n"}, module="agents", operation="note-edit")


def meta(row):
    return row["debug_info"]["metadata"]


# in-scope agent: allowed, with the row metadata
ROW_ANSWERS["5"] = {"agent_id": AGENT}
del ROWS[:]
must(edit().status == 200 and len(CALLS) == 1, "an in-scope agent is allowed")
must(ROWS[0]["action"] == "modify" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS[0]["debug_info"])
must(meta(ROWS[0])["scope_source"] == "row_lookup" and meta(ROWS[0])["agentless"] is False, meta(ROWS[0]))
# out-of-scope agent
ROW_ANSWERS["5"] = {"agent_id": OTHER}
del ROWS[:]
exc = refusal(lambda: edit(), 404, "object_not_found")
must(not CALLS and ROWS[0]["action"] == "deny" and ROWS[0]["debug_info"]["object_id"] == "5", ROWS)
must(exc.message == ops.MESSAGES["object_not_found"], exc.message)
# an agent that does not exist at all gives the same answer
ROW_ANSWERS["5"] = {"agent_id": "z" * 21}
refusal(lambda: edit(), 404, "object_not_found")
# None: the row does not exist
ROW_ANSWERS["5"] = None
refusal(lambda: edit(), 404, "object_not_found")
must(not CALLS, "Tactical is not called")


# raising lookup
def boom():
    raise RuntimeError("db down")


ROW_ANSWERS["5"] = boom
refusal(lambda: edit(), 404, "object_not_found")
# wrong shapes
for bad in ("agent", ["a"], {"agent": AGENT}, {}, {"agent_id": 5}, {"agent_id": ""}, {"agent_id": "  "}, {"agent_id": [AGENT]}, 7, True):
    ROW_ANSWERS["5"] = bad
    refusal(lambda: edit(), 404, "object_not_found")
    must(not CALLS, f"{bad!r} fails closed")
# a lookup that is not registered (here: removed from the registry), and another module's lookup
ROW_ANSWERS["5"] = {"agent_id": AGENT}
saved = dict(ops._ROW_LOOKUPS)
ops._ROW_LOOKUPS.clear()
refusal(lambda: edit(), 404, "object_not_found")
ops._ROW_LOOKUPS.update(saved)
must(edit().status == 200, "back in place")
reg([{"type": "agent", "source": "path:pk", "row_lookup": "note-row"}], id="rm-edit", module_id="reportmanager", route="reporting/rows/{pk:int}/",
    method="PUT", body_fields=["note"], permissions=["can_manage_notes"], audit={"action": "modify", "object_type": "report"})
route("/reporting/rows/5/", FakeResponse(200))
refusal(lambda: G["run"](user=tech, params={"pk": 5}, body={"note": "n"}, module="reportmanager", operation="rm-edit"), 404, "object_not_found")
# the same lookup id registered by that module is its own and is used
ops.register_tactical_row_lookup("reportmanager", "note-row", lambda pk: {"agent_id": AGENT})
must(G["run"](user=tech, params={"pk": 5}, body={"note": "n"}, module="reportmanager", operation="rm-edit").status == 200, "its own lookup")

# ---- CQ57: a row with no agent is allowed to anyone who holds the Tactical flag
ROW_ANSWERS["5"] = {"agent_id": None}
site_limited = User("sitelim", Roleish("can_manage_notes"))
site_limited.sees = {"agents": set(), "clients": set(), "sites": {10}}
del ROWS[:]
must(edit(user=site_limited).status == 200 and len(CALLS) == 1, "an agentless row is allowed for a site-limited caller")
must(meta(ROWS[0])["agentless"] is True and meta(ROWS[0])["scope_source"] == "row_lookup" and ROWS[0]["debug_info"]["object_id"] == "5", meta(ROWS[0]))
# the Tactical flag is still required
no_flag = User("noflag", Roleish("can_send_wol"))
del ROWS[:]
refusal(lambda: edit(user=no_flag), 403, "tactical_permission_denied")
must(ROWS[0]["action"] == "deny" and not CALLS, "no flag, no call")
# an agent row for the same site-limited caller is held to the role scope
ROW_ANSWERS["5"] = {"agent_id": AGENT}
refusal(lambda: edit(user=site_limited), 404, "object_not_found")
# a malformed path id never reaches the lookup
seen = []
ops._ROW_LOOKUPS[("agents", "note-row")] = lambda pk: seen.append(pk) or {"agent_id": AGENT}
refusal(lambda: edit(pk="5/../x"), 400, "invalid_params")
must(not seen, "the lookup is called with a cleaned id only")
must(edit().status == 200 and seen == ["5"], seen)

print("[TEST] PASS tactical operations scope sources 1.17.18")
