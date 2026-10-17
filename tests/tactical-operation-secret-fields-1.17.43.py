#!/usr/bin/env python3
"""1.17.43 (tasks 0.5.0 round 2, globalsettings 0.3.0 (b), remote-background fix round 1 (e)): audit.secret_fields.

A declared secret body field is never recorded. Core writes a change marker only: 'changed' on the after side when the body sends
the field; with an audit.before read that holds the field, 'present' before and 'changed' or 'unchanged' after (an in-memory
comparison of SHA-256 digests of the canonical JSON). Covered: unchanged (a list of objects with its keys in another order), changed,
no before read, a read without the field, a read that fails, a field the body does not send (no marker), deny, failed and
outcome-unknown rows (no marker), the value in no row, no metadata and no log record, an operation without secret_fields writing the
rows it wrote before, the registration refusals, and the capability (1.12.0) with the contract metadata naming the key.

Uses the stubs of tests/tactical-operations-1.17.7.py, as tests/tactical-operations-audit-lists-1.17.28.py does.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, declare, must, fresh, refused = (G[k] for k in ("ops", "declare", "must", "fresh", "refused"))
ROUTES, CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse = G["FakeResponse"]

SECRET = "s3cr3t-value-42"
PASSWORD = "hunter2-in-args"
NEW_SECRET = "other-value-99"
NOTE = 5
NOTE_PATH = f"/agents/{AGENT}/notes/{NOTE}/"
NOTE_ROUTE = "agents/{agent_id:agent}/notes/{note_id:int}/"
PARAMS = {"agent_id": AGENT, "note_id": NOTE}
ACTIONS = [
    {"type": "script", "script_args": ["--pw", PASSWORD], "timeout": 90},
    {"type": "cmd", "command": "echo hello", "shell": "bash"},
]
DEFAULT_ANSWER = {"name": "old", "token": SECRET, "actions": ACTIONS}
STATE = {"answer": dict(DEFAULT_ANSWER), "status": {"PUT": 200, "PATCH": 200}, "get": 200}
LOGS: list[str] = []


def note_view(request, *args, **kwargs):
    """Tactical's note: GET reads the answer (or fails with STATE['get']), PUT and PATCH answer with STATE['status']."""
    method = request.META.get("REQUEST_METHOD", "GET")
    CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs, method=method))
    if method == "GET":
        if STATE["get"] != 200:
            return FakeResponse(STATE["get"], b'{"detail": "no"}')
        return FakeResponse(200, json.dumps(STATE["answer"]).encode("utf-8"))
    return FakeResponse(STATE["status"][method], b'{"ok": true}')


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        LOGS.append(self.format(record))


def reset(answer=None, get=200, put=200):
    ROUTES.clear()
    ROUTES[NOTE_PATH] = (note_view, (), {})
    STATE["answer"] = dict(answer if answer is not None else DEFAULT_ANSWER)
    STATE["status"] = {"PUT": put, "PATCH": 200}
    STATE["get"] = get
    del ROWS[:]
    del CALLS[:]
    del LOGS[:]


def meta(row):
    return row["debug_info"]["metadata"]


def edit_decl(**over):
    spec = dict(
        id="edit-note", module_id="agents", method="PUT", route=NOTE_ROUTE, permissions=["can_manage_notes"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "token", "actions"],
        audit={"action": "modify", "object_type": "note", "audit_fields": ["name"],
               "before": {"route": NOTE_ROUTE, "fields": ["name"]}, "secret_fields": ["token", "actions"]},
    )
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run(body, operation="edit-note", params=None):
    del CALLS[:]
    return ops.run_tactical_operation(Request(tech), "agents", operation, params or PARAMS, body)


def same_actions_other_order():
    return [{"timeout": 90, "script_args": ["--pw", PASSWORD], "type": "script"}, {"shell": "bash", "command": "echo hello", "type": "cmd"}]


def secret_keys(row):
    found = {}
    for part in ("after_value", "before_value"):
        for key, value in (row.get(part) or {}).items():
            if key in ("token", "actions"):
                found[(part, key)] = value
    return found


def no_value_anywhere(*values):
    dump = repr(ROWS) + "\n" + "\n".join(LOGS)
    for value in values:
        must(value not in dump, f"a secret value reached a row, the metadata or a log: {value!r}")


fresh()
reset()
edit_decl()
logger = logging.getLogger()
capture = Capture()
logger.addHandler(capture)
previous_level = logger.level
logger.setLevel(logging.DEBUG)

# (1) unchanged: the sent token and the sent actions equal Tactical's read, the actions in another key order
reset()
result = run({"name": "new", "token": SECRET, "actions": same_actions_other_order()})
must(result.status == 200 and len(ROWS) == 1, (result.status, len(ROWS)))
row = ROWS[0]
must(row["action"] == "modify", row["action"])
must(row["after_value"] == {"name": "new", "token": "unchanged", "actions": "unchanged"}, row["after_value"])
must(row["before_value"] == {"name": "old", "token": "present", "actions": "present"}, row["before_value"])
no_value_anywhere(SECRET, PASSWORD)
print("       unchanged: after unchanged, before present, no value in the row, the metadata or a log")

# (2) changed: a new token, the same actions
reset()
run({"name": "new", "token": NEW_SECRET, "actions": ACTIONS})
row = ROWS[0]
must(row["after_value"] == {"name": "new", "token": "changed", "actions": "unchanged"}, row["after_value"])
must(row["before_value"] == {"name": "old", "token": "present", "actions": "present"}, row["before_value"])
no_value_anywhere(SECRET, NEW_SECRET, PASSWORD)
print("       changed: after changed, before present, no value anywhere")

# (3) no before read: the sent fields are 'changed' and the before side is left out (never 'unchanged')
fresh()
edit_decl(id="edit-note-nobefore", method="PATCH", audit={"action": "modify", "object_type": "note", "audit_fields": ["name"],
                                                         "secret_fields": ["token", "actions"]})
reset()
run({"name": "new", "token": SECRET, "actions": ACTIONS}, operation="edit-note-nobefore")
row = ROWS[0]
must(row["after_value"] == {"name": "new", "token": "changed", "actions": "changed"}, row["after_value"])
must(row["before_value"] is None, row["before_value"])
no_value_anywhere(SECRET, PASSWORD)
print("       no before read: changed after, no before side, no value")

# (4) the before read fails: changed after, no before side
fresh()
edit_decl()
reset(get=404)
run({"name": "new", "token": SECRET, "actions": ACTIONS})
row = ROWS[0]
must(row["after_value"] == {"name": "new", "token": "changed", "actions": "changed"}, row["after_value"])
must(row["before_value"] is None, row["before_value"])
no_value_anywhere(SECRET, PASSWORD)
print("       before read answers 404: changed after, no before side")

# (5) the read does not hold the field: changed after, the before side omits it
reset(answer={"name": "old"})
run({"name": "new", "token": SECRET, "actions": ACTIONS})
row = ROWS[0]
must(row["after_value"] == {"name": "new", "token": "changed", "actions": "changed"}, row["after_value"])
must(row["before_value"] == {"name": "old"}, row["before_value"])
no_value_anywhere(SECRET, PASSWORD)
print("       read without the fields: changed after, the before side omits them")

# (6) a field the body does not send gets no marker
reset()
run({"name": "new"})
row = ROWS[0]
must(row["after_value"] == {"name": "new"} and row["before_value"] == {"name": "old"}, (row["after_value"], row["before_value"]))
print("       field not sent: no marker on either side")

# (7) deny, failed and outcome-unknown rows carry no marker
for status, expected in ((403, "deny"), (409, "custom:operation-failed"), (500, "custom:outcome-unknown")):
    reset(put=status)
    run({"name": "new", "token": NEW_SECRET, "actions": ACTIONS})
    row = ROWS[0]
    must(row["action"] == expected, (status, row["action"]))
    must(not secret_keys(row), (status, row.get("after_value"), row.get("before_value")))
    no_value_anywhere(SECRET, NEW_SECRET, PASSWORD)
print("       deny, failed and outcome-unknown rows: no marker, no value")

# (7b) a refusal that raises, with the secret in the body: the exception text never carries the value
reset()
try:
    run({"name": "new", "token": SECRET, "actions": ACTIONS, "not_a_field": 1})
except ops.TacticalOperationError as error:
    must(SECRET not in str(error) and PASSWORD not in str(error), str(error))
    must(error.audit is not None, "the refusal carries the audit verdict")
else:
    raise AssertionError("a body field that is not declared must be refused")
no_value_anywhere(SECRET, PASSWORD)
print("       refusal raised with the secret in the body: the exception text and the row carry no value")

# (8) an operation without secret_fields writes the rows it wrote before (the body's secret is not in the row, since it is not audited)
fresh()
edit_decl(id="edit-note-plain", method="PATCH", audit={"action": "modify", "object_type": "note", "audit_fields": ["name"]})
reset()
run({"name": "new", "token": SECRET}, operation="edit-note-plain")
row = ROWS[0]
must(row["after_value"] == {"name": "new"} and row["before_value"] is None and "token" not in json.dumps(row["after_value"]), row)
print("       no secret_fields: the row is as it was before 1.17.43")

# (9) the registration refusals: each one for its own reason (the default body fields are checked by name, so a wrong refusal shows)
fresh()
reset()
BODY = ["name", "token", "actions"]
REFUSALS = [
    ("is not one of body_fields", dict(body_fields=["name"], audit={"action": "modify", "object_type": "note", "secret_fields": ["token"]})),
    ("repeats 'token'", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note", "secret_fields": ["token", "token"]})),
    ("more than 8 entries", dict(body_fields=BODY + [f"x{i}" for i in range(6)],
                                 audit={"action": "modify", "object_type": "note", "secret_fields": BODY + [f"x{i}" for i in range(6)]})),
    ("invalid name", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note", "secret_fields": ["bad name"]})),
    ("also recorded in clear", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note", "audit_fields": ["name"],
                                                             "secret_fields": ["name"]})),
    ("also recorded in clear", dict(body_fields=BODY, audit_lists=["actions"],
                                    audit={"action": "modify", "object_type": "note", "secret_fields": ["actions"]})),
    ("also an audit.before field", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note", "secret_fields": ["actions"],
                                                                 "before": {"route": NOTE_ROUTE, "fields": ["actions"]}})),
    ("object id or a body scope source", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note",
                                                                       "object_body_field": "name", "secret_fields": ["name"]})),
    ("object id or a body scope source", dict(body_fields=BODY, scope=[{"type": "agent", "source": "body:token"}],
                                              audit={"action": "modify", "object_type": "note", "secret_fields": ["token"]})),
    ("must be a list of names", dict(body_fields=BODY, audit={"action": "modify", "object_type": "note", "secret_fields": "token"})),
]
for index, (phrase, over) in enumerate(REFUSALS):
    text = refused(id=f"secret-refusal-{index}", route=NOTE_ROUTE, **over)
    must(phrase in text, (phrase, text))
print(f"       registration refused, each for its own reason: {len(REFUSALS)} cases")

# (10) the capability and the contract metadata name the key; a valid declaration registers
meta_cap = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.15.0" and meta_cap["version"] == "1.15.0", meta_cap["version"])
must(meta_cap["declaration_keys_added_in_1_12_0"] and "secret_fields" in meta_cap["declaration_keys_added_in_1_12_0"][0], meta_cap)
text = " ".join(meta_cap["behaviour_added_in_1_12_0"])
must("changed" in text and "never recorded in the row" in text, text)
edit_decl()  # the registry was cleared above
must(ops.get_operation("agents", "edit-note") is not None, "the valid declaration is registered")
print("       capability 1.12.0 and the contract metadata name audit.secret_fields")

# (11) the 'secret_fields' key in the declaration never shows the value: the row for an unchanged send names only markers
reset()
run({"name": "new", "token": SECRET, "actions": ACTIONS})
must(all(value in ("changed", "unchanged", "present") for value in secret_keys(ROWS[0]).values()), secret_keys(ROWS[0]))
print("       markers only: every marker value is changed, unchanged or present")

logger.removeHandler(capture)
logger.setLevel(previous_level)
print("[TEST] PASS tactical operation secret fields 1.17.43")
