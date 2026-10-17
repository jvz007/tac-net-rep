#!/usr/bin/env python3
"""1.17.28 regression: ``audit_lists`` records a declared list of flat objects in clear (Johan, CQ85 a, 14 October 2026: "do the same as
Tactical"; Tasks' actions before and after).

Tactical's BaseAuditModel records a whole task, script arguments and environment values included, as before and after. Core now lets a
declaration name up to two body or before fields that hold such a list. The success row carries the cleaned body's list as the after
value and, when the operation has a before read, Tactical's own GET answer as the before value. Nothing is masked. The bounds are 50
objects per list, 24 keys per object, text cut at 4096 characters (control characters other than tab and newline removed), one level of
up to 100 scalars, 64 KiB of text per list field. ``<field>_count`` is the full length and ``<field>_truncated`` is true when anything was
cut or dropped. Failed, denied and outcome-unknown rows carry no list. A declaration without ``audit_lists`` behaves exactly as before.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-before-lists-1.17.23.py does. The route is an
agents note (owned by agents), so no other module's stub is needed. This test fails on 1.17.27.
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
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, declare, fresh, must = (G[k] for k in ("ops", "declare", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse = G["FakeResponse"]

NOTE = 5
NOTE_PATH = f"/agents/{AGENT}/notes/{NOTE}/"
NOTE_ROUTE = "agents/{agent_id:agent}/notes/{note_id:int}/"
PARAMS = {"agent_id": AGENT, "note_id": NOTE}
SECRET_LOOKING = "Secret-Value-123"

# Tactical's own GET answer for the note: a task-like object with an actions list of flat objects
OLD_ACTIONS = [
    {"type": "script", "name": "backup", "script_args": ["--token", SECRET_LOOKING], "env_vars": ["PASSWORD=hunter2"], "timeout": 90},
    {"type": "cmd", "command": "echo hello", "shell": "bash"},
]
STATE = {"answer": {"name": "old", "actions": OLD_ACTIONS}, "status": {"PUT": 200, "DELETE": 200}}


def note_view(request, *args, **kwargs):
    """Tactical's route for the note: GET reads the answer, PUT and DELETE answer with the status set in STATE."""
    method = request.META.get("REQUEST_METHOD", "GET")
    CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs, method=method))
    if method == "GET":
        return FakeResponse(200, json.dumps(STATE["answer"]).encode("utf-8"))
    return FakeResponse(STATE["status"][method], b'{"ok": true}')


def reset():
    """Clear the rows, the calls and Tactical's stub answers. The registered declarations stay."""
    ROUTES.clear()
    ROUTES[NOTE_PATH] = (note_view, (), {})
    STATE["status"] = {"PUT": 200, "DELETE": 200}
    STATE["answer"] = {"name": "old", "actions": OLD_ACTIONS}
    del ROWS[:]
    del CALLS[:]


def edit_decl(**over):
    spec = dict(
        id="edit-note", module_id="agents", method="PUT", route=NOTE_ROUTE, permissions=["can_manage_notes"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions"],
        audit={"action": "modify", "object_type": "note", "audit_fields": ["name"],
               "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
        audit_lists=["actions"],
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run_edit(body, operation="edit-note", params=None):
    del CALLS[:]
    return ops.run_tactical_operation(Request(tech), "agents", operation, params or PARAMS, body)


def row_for(action):
    rows = [row for row in ROWS if row.get("action") == action]
    must(len(rows) == 1, (action, [row.get("action") for row in ROWS]))
    return rows[0]


fresh()
reset()
edit_decl()
delete_decl = dict(
    id="delete-note", module_id="agents", method="DELETE", route=NOTE_ROUTE, permissions=["can_manage_notes"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[],
    audit={"action": "delete", "object_type": "note", "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
    audit_lists=["actions"],
)
ops.register_tactical_operation(**delete_decl)

# ---- the capability and the description
must(ops.CAPABILITY_VERSION == "1.15.0", ops.CAPABILITY_VERSION)
info = ops.tactical_operations_contract_metadata()
must(info["version"] == "1.15.0" and info["version"].split(".")[0] == "1" and "behaviour_added_in_1_10_0" in info, info["version"])
must("audit_lists" in info["declaration"], "the declaration names audit_lists")
must(info["limits_added_in_1_10_0"]["audit_list_entries"] == 50 and info["limits_added_in_1_10_0"]["audit_list_keys"] == 24, info["limits_added_in_1_10_0"])
described = ops.get_operation("agents", "edit-note")
must(described["audit"]["lists"] == ["actions"], described["audit"])
must(ops.get_operation("agents", "delete-note")["audit"]["lists"] == ["actions"], "the delete declaration lists it too")

# ---- a clear-text edit: the script's arguments and environment values are recorded as Tactical stores them, before and after
NEW_ACTIONS = [
    {"type": "script", "name": "backup", "script_args": ["--token", SECRET_LOOKING], "env_vars": ["PASSWORD=hunter2"], "timeout": 120},
    {"type": "cmd", "command": "echo hello", "shell": "bash"},
]
reset()
result = run_edit({"name": "new", "actions": NEW_ACTIONS})
must(result.status == 200 and len(CALLS) == 2, (result.status, len(CALLS)))  # the read, then the change
row = row_for("modify")
must(row["after_value"]["actions"] == NEW_ACTIONS and row["after_value"]["actions_count"] == 2 and "actions_truncated" not in row["after_value"],
     row["after_value"])
must(row["before_value"]["actions"] == OLD_ACTIONS and row["before_value"]["actions_count"] == 2, row["before_value"])
must(row["before_value"]["name"] == "old" and row["after_value"]["name"] == "new", (row["before_value"], row["after_value"]))
dumped = json.dumps(ROWS, default=str)
must(SECRET_LOOKING in dumped and "PASSWORD=hunter2" in dumped and "echo hello" in dumped, "values in clear, no masking")

# ---- an edit without the list adds nothing for it
reset()
run_edit({"name": "only-name"})
row = row_for("modify")
must("actions" not in row["after_value"] and "actions_count" not in row["after_value"], row["after_value"])
must(row["before_value"]["actions"] == OLD_ACTIONS, "the before value still carries the list")

# ---- a delete records the before list only
reset()
result = run_edit(None, operation="delete-note")
row = row_for("delete")
must(row["before_value"]["actions"] == OLD_ACTIONS and row["before_value"]["actions_count"] == 2, row["before_value"])
must("actions" not in (row.get("after_value") or {}), row.get("after_value"))  # no list after a delete


# ---- the bounds: each cut or dropped part is flagged and the row and Tactical call still happen
def bounded(actions, before=None):
    reset()
    if before is not None:
        STATE["answer"] = {"name": "old", "actions": before}
    result = run_edit({"name": "n", "actions": actions})
    must(result.status == 200 and len(CALLS) == 2, "the change is still made")
    return row_for("modify")


row = bounded([{"n": i} for i in range(51)])
must(len(row["after_value"]["actions"]) == 50 and row["after_value"]["actions_count"] == 51 and row["after_value"]["actions_truncated"] is True,
     {k: v for k, v in row["after_value"].items() if k != "actions"})
row = bounded([{"n": i} for i in range(50)])
must(len(row["after_value"]["actions"]) == 50 and "actions_truncated" not in row["after_value"], "50 whole")
row = bounded([{f"k{i:02d}": i for i in range(25)}])
entry = row["after_value"]["actions"][0]
must(len(entry) == 24 and "k24" not in entry and row["after_value"]["actions_truncated"] is True, entry)
row = bounded([{"command": "x" * 5000}])
must(row["after_value"]["actions"][0]["command"] == "x" * 4096 and row["after_value"]["actions_truncated"] is True, "cut to 4096")
row = bounded([{"command": "x" * 4096}])
must(row["after_value"]["actions"][0]["command"] == "x" * 4096 and "actions_truncated" not in row["after_value"], "4096 is kept whole")
row = bounded([{"nested": {"a": 1}, "ok": 1}])
must(row["after_value"]["actions"] == [{"ok": 1}] and row["after_value"]["actions_truncated"] is True, "a nested object is dropped")
row = bounded([{"script_args": list(range(101))}])
must(len(row["after_value"]["actions"][0]["script_args"]) == 100 and row["after_value"]["actions_truncated"] is True, "101 items cut to 100")
row = bounded([{"script_args": [{"a": 1}, "ok"]}])
must(row["after_value"]["actions"] == [{"script_args": ["ok"]}] and row["after_value"]["actions_truncated"] is True, "an object inside a list is dropped")
row = bounded([{"ctl": "a\x00b\x07c\td\ne\rf\x7fg"}])
must(row["after_value"]["actions"][0]["ctl"] == "abc\td\nefg", repr(row["after_value"]["actions"][0]["ctl"]))
must("actions_truncated" not in row["after_value"], "control characters removed, not counted as a cut")
row = bounded([{"bad": float("nan"), "good": 2}])
must(row["after_value"]["actions"] == [{"good": 2}] and row["after_value"]["actions_truncated"] is True, "a non-finite number is dropped")
row = bounded([{"bad key": 1, "ok": 2}])
must(row["after_value"]["actions"] == [{"ok": 2}] and row["after_value"]["actions_truncated"] is True, "a key that is not a field name is dropped")
# 64 KiB of text per list field: a list of large texts stops at the cap and says so
row = bounded([{"text": "y" * 4096} for _ in range(20)])
kept = len(row["after_value"]["actions"])
must(kept < 20 and row["after_value"]["actions_count"] == 20 and row["after_value"]["actions_truncated"] is True, kept)
must(kept * 4096 <= 64 * 1024, kept)

# ---- values that are not a list: count 0 or count only, flagged, and never a raise
row = bounded("not a list")
must(row["after_value"]["actions"] == [] and row["after_value"]["actions_count"] == 0 and row["after_value"]["actions_truncated"] is True, row["after_value"])
row = bounded([{"ok": 1}, "a string item"])
must(row["after_value"]["actions"] == [] and row["after_value"]["actions_count"] == 2 and row["after_value"]["actions_truncated"] is True, row["after_value"])
row = bounded({"a": 1})
must(row["after_value"]["actions_count"] == 0 and row["after_value"]["actions_truncated"] is True, row["after_value"])
# a before answer whose list is malformed is recorded as its count only
row = bounded([{"ok": 1}], before=[1, 2, 3])
must(row["before_value"]["actions"] == [] and row["before_value"]["actions_count"] == 3 and row["before_value"]["actions_truncated"] is True, row["before_value"])
row = bounded([{"ok": 1}], before=[{"n": i} for i in range(51)])
must(len(row["before_value"]["actions"]) == 50 and row["before_value"]["actions_count"] == 51, "the before list is bounded too")

# ---- failed, denied and outcome-unknown rows carry no list
for status, action in ((400, "custom:operation-failed"), (403, "deny"), (500, "custom:outcome-unknown")):
    reset()
    STATE["status"]["PUT"] = status
    try:
        run_edit({"name": "n", "actions": NEW_ACTIONS})
    except ops.TacticalOperationError:
        pass
    rows = [r for r in ROWS if r.get("action") == action]
    must(len(rows) == 1, (status, [r.get("action") for r in ROWS]))
    for key in ("after_value", "before_value"):
        must(not rows[0].get(key) or "actions" not in rows[0][key], (status, key, rows[0].get(key)))
    must(SECRET_LOOKING not in json.dumps(rows[0], default=str), (status, "no list values in a refusal row"))

# ---- registration refusals: each case is refused for its own reason
BASE_DECL = dict(
    id="edit-note-x", module_id="agents", method="PUT", route=NOTE_ROUTE, permissions=["can_manage_notes"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions"],
    audit={"action": "modify", "object_type": "note", "audit_fields": ["name"], "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
    audit_lists=["actions"],
)
for reason, over in (
    ("is not one of body_fields", dict(id="c1", method="POST", route="agents/{agent_id:agent}/notes/", body_fields=["name"],
                                       audit={"action": "add", "object_type": "note"})),
    ("changing operation", dict(id="g1", method="GET", route=NOTE_ROUTE, body_fields=[], audit={"action": "modify", "object_type": "note"})),
    ("would write 'actions' twice", dict(id="k1", audit={"action": "modify", "object_type": "note",
                                                        "before": {"route": NOTE_ROUTE, "fields": ["name"], "count_fields": ["actions"]}})),
    ("looks like a secret", dict(id="s1", body_fields=["name", "api_token"], audit_lists=["api_token"])),
    ("invalid name", dict(id="b1", body_fields=["name", "bad-name"], audit_lists=["bad-name"])),
    ("more than 2 entries", dict(id="t1", body_fields=["name", "a", "b", "c"], audit_lists=["a", "b", "c"])),
    ("would write 'actions' twice", dict(id="f1", audit={"action": "modify", "object_type": "note", "audit_fields": ["actions"],
                                                         "before": {"route": NOTE_ROUTE, "fields": ["name"]}})),
    ("would write 'actions' twice", dict(id="f2", audit={"action": "modify", "object_type": "note", "audit_fields": ["name"],
                                                        "before": {"route": NOTE_ROUTE, "fields": ["actions"]}})),
    ("would write 'actions_count' twice", dict(id="f3", body_fields=["name", "actions", "actions_count"],
                                               audit={"action": "modify", "object_type": "note", "audit_fields": ["actions_count"],
                                                      "before": {"route": NOTE_ROUTE, "fields": ["name"]}})),
):
    try:
        ops.register_tactical_operation(**{**BASE_DECL, **over})
    except ops.TacticalOperationRegistrationError as exc:
        must(reason in str(exc), (reason, str(exc)))
    else:
        raise AssertionError(f"registration must be refused: {reason}")

# a second, valid declaration with two lists is accepted; the same declaration again is idempotent
two = ops.register_tactical_operation(
    id="edit-two", module_id="agents", method="PUT", route="agents/{agent_id:agent}/notes/{note_id:int}/both/", permissions=["can_manage_notes"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions", "tags"],
    audit={"action": "modify", "object_type": "note", "audit_fields": ["name"], "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
    audit_lists=["actions", "tags"],
)
must(two.audit_lists == ("actions", "tags"), two.audit_lists)
must(ops.register_tactical_operation(
    id="edit-two", module_id="agents", method="PUT", route="agents/{agent_id:agent}/notes/{note_id:int}/both/", permissions=["can_manage_notes"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions", "tags"],
    audit={"action": "modify", "object_type": "note", "audit_fields": ["name"], "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
    audit_lists=["actions", "tags"],
) == two, "identical re-registration is idempotent")

# ---- the message and the docs: clear text is stated plainly
root = Path(__file__).resolve().parents[1]
doc = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("audit_lists", "in clear", "<field>_truncated", "1.10.0"):
    must(needle in doc, ("docs/tactical-operations.md", needle))
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("audit_lists" in contract and "IN CLEAR" in contract and "core.tactical_operations >= 1.10.0" in contract, "contract text")

# no secret-name filter is applied to list values (case sensitive: a value named PASSWORD is kept as it is)
reset()
row = bounded([{"env": "PASSWORD=SecretTokenX", "Token": "Token-Value"}])
must(row["after_value"]["actions"] == [{"env": "PASSWORD=SecretTokenX", "Token": "Token-Value"}], row["after_value"])

print("[TEST] PASS tactical operations audit lists 1.17.28")
