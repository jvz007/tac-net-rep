#!/usr/bin/env python3
"""1.17.58 regression: a per-list changed or unchanged marker next to ``audit_list_masks`` (core.tactical_operations 1.15.0 -> 1.16.0).

Request "from tasks 0.10.2: a per-list changed or unchanged marker". A masked list shows only names and ``***``, so a change to one
argument's value or to a command's text looked unchanged. The success row now carries ``<list>_changed`` (a bool, never a value) on the
after side. Core compares the canonical-JSON digest of the body's raw list with the digest of Tactical's list from the before read; the
digests live in memory for that comparison only.

Covered: true when only an argument value, an environment value or a command text changes (names identical); false when nothing changed;
true for an added, removed or reordered item; omitted with no before read, with a before read that fails or does not return the list,
and when the body sent no list; never on a failed or Tactical-denied row; no marker without audit_list_masks (the row is the 1.17.57
row); a marker secret in a masked value never reaches any row, the digest, the logs or the result (rule A8); the metadata names it.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operation-audit-list-masks-1.17.52.py does.
"""
from __future__ import annotations

import copy
import hashlib
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
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse = G["FakeResponse"]

NOTE = 5
PARAMS = {"agent_id": AGENT, "note_id": NOTE}
SECRETS = ("tok-abc123", "sekret-one", "positional-secret", "hunter2", "VALUEx9", "P@ssw0rd!", "net user admin", "swordfish", "MARKER-SECRET-7731")

ACTIONS = [
    {"type": "script", "script": 12, "name": "backup", "timeout": 90,
     "script_args": ["--token=tok-abc123", "-Name sekret-one", "positional-secret", "/S", "--flag"],
     "env_vars": ["KEY=VALUEx9", "PASSWORD=hunter2"]},
    {"type": "cmd", "command": "net user admin P@ssw0rd!", "shell": "cmd", "timeout": 30},
]
MASKS = {"actions": {"script_args": "names", "env_vars": "names", "command": "mask"}}
IDS = ["with-marker", "no-before", "no-masks", "bad-before", "two-lists"]


def slug(op_id):
    return op_id.replace("-", "")


def tpl(op_id):
    return f"agents/{{agent_id:agent}}/notes/{{note_id:int}}/{slug(op_id)}/"


def path(op_id):
    return f"/agents/{AGENT}/notes/{NOTE}/{slug(op_id)}/"


STATE = {"answer": {"name": "old", "actions": ACTIONS}, "get": 200, "put": 200}


def note_view(request, *args, **kwargs):
    method = request.META.get("REQUEST_METHOD", "GET")
    CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs, method=method))
    if method == "GET":
        return FakeResponse(STATE["get"], json.dumps(STATE["answer"]).encode("utf-8"))
    return FakeResponse(STATE["put"], b'{"ok": true}')


def reset():
    ROUTES.clear()
    for op_id in IDS:
        ROUTES[path(op_id)] = (note_view, (), {})
    STATE.update(answer={"name": "old", "actions": copy.deepcopy(ACTIONS)}, get=200, put=200)
    del ROWS[:]
    del CALLS[:]


def decl(op_id, masks=MASKS, before=True, **over):
    audit = {"action": "modify", "object_type": "note", "audit_fields": ["name"]}
    if before:
        audit["before"] = {"route": tpl(op_id), "fields": ["name"]}
    spec = dict(
        id=op_id, module_id="agents", method="PUT", route=tpl(op_id), permissions=["can_manage_notes"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions", "extra"],
        audit=audit, audit_lists=["actions"],
    )
    if masks is not None:
        spec["audit_list_masks"] = masks
    spec.update(over)
    return ops.register_tactical_operation(**spec)


def run(op_id, body):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(tech), "agents", op_id, PARAMS, body)


def modify_row():
    rows = [row for row in ROWS if row.get("action") == "modify"]
    must(len(rows) == 1, [row.get("action") for row in ROWS])
    return rows[0]


def marker(row):
    return (row.get("after_value") or {}).get("actions_changed", "absent")


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage() + " " + str(record.args) + " " + (self.format(record) if record.exc_info else ""))


capture = Capture()
logging.getLogger().addHandler(capture)
logging.getLogger().setLevel(logging.DEBUG)

fresh()
reset()
decl("with-marker")
decl("no-before", before=False)
decl("no-masks", masks=None)
decl("bad-before")
decl("two-lists", masks={"actions": {"script_args": "names"}, "steps": {"command": "mask"}}, body_fields=["name", "actions", "steps", "extra"], audit_lists=["actions", "steps"])

# (1) nothing changed: false
result = run("with-marker", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
row = modify_row()
must(result.status == 200 and marker(row) is False, row.get("after_value"))
# the list itself still shows names and *** only
dumped = json.dumps(row, default=str)
must("--token" in dumped and "***" in dumped, "names and *** are still recorded")
print("       an unchanged list reads false")

# (2) one value changes and every name stays: true, for each masked key
CHANGES = {
    "argument value": lambda a: a[0]["script_args"].__setitem__(0, "--token=MARKER-SECRET-7731"),
    "argument value of a switch": lambda a: a[0]["script_args"].__setitem__(1, "-Name MARKER-SECRET-7731"),
    "positional argument": lambda a: a[0]["script_args"].__setitem__(2, "MARKER-SECRET-7731"),
    "environment value": lambda a: a[0]["env_vars"].__setitem__(0, "KEY=MARKER-SECRET-7731"),
    "command text": lambda a: a[1].__setitem__("command", "net user admin MARKER-SECRET-7731"),
    "unmasked field": lambda a: a[0].__setitem__("timeout", 91),
    "item added": lambda a: a.append({"type": "cmd", "command": "MARKER-SECRET-7731", "shell": "cmd"}),
    "item removed": lambda a: a.pop(),
    "items reordered": lambda a: a.reverse(),
    "empty list": lambda a: a.clear(),
}
for label, change in CHANGES.items():
    sent = copy.deepcopy(ACTIONS)
    change(sent)
    run("with-marker", {"name": "old", "actions": sent})
    row = modify_row()
    must(marker(row) is True, (label, row.get("after_value")))
    dumped = json.dumps(ROWS, default=str)
    for secret in SECRETS:
        must(secret not in dumped, (label, secret))
print("       a changed value, command text, added, removed or reordered item reads true (names identical)")

# (3) dict key order never counts as a change
reordered_keys = [dict(reversed(list(item.items()))) for item in ACTIONS]
run("with-marker", {"name": "old", "actions": reordered_keys})
must(marker(modify_row()) is False, "the canonical form sorts keys")

# (4) the marker is a real bool and lives on the after side only
row = modify_row()
must(isinstance(marker(row), bool), type(marker(row)))
must("actions_changed" not in json.dumps(row.get("before_value") or {}), "never on the before side")
print("       a bool on the after side only; key order is not a change")

# (5) omitted: no before read, a before read that fails, a list the read did not return, a body with no list
run("no-before", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
must(marker(modify_row()) == "absent" and not [c for c in CALLS if c.method == "GET"], "no before read declared")
STATE["get"] = 500
run("with-marker", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
must(marker(modify_row()) == "absent", "the before read failed")
STATE["get"] = 200
STATE["answer"] = {"name": "old"}
run("with-marker", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
must(marker(modify_row()) == "absent", "the answer holds no list")
STATE["answer"] = {"name": "old", "actions": "not a list"}
run("with-marker", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
must(marker(modify_row()) == "absent", "the answer's value is not a list")
STATE["answer"] = {"name": "old", "actions": copy.deepcopy(ACTIONS)}
run("with-marker", {"name": "old"})
must(marker(modify_row()) == "absent", "the body sent no list")
run("with-marker", {"name": "old", "actions": "text"})
must(marker(modify_row()) == "absent", "the body's value is not a list")
# a caller-supplied audit_before is not a read: no digest, no marker
reset()
decl("no-before", before=False)
del ROWS[:]
ops.run_tactical_operation(Request(tech), "agents", "no-before", PARAMS, {"name": "old", "actions": copy.deepcopy(ACTIONS)}, audit_before={"name": "old"})
must(marker(modify_row()) == "absent", "audit_before is the caller's own value, not evidence")
print("       omitted with no before read, a failed read, no list in either place, or a caller-supplied before value")

# (6) a declaration without audit_list_masks: no marker, and the row is the row it was
reset()
decl("no-masks", masks=None)
decl("no-before", before=False)
run("no-masks", {"name": "old", "actions": copy.deepcopy(ACTIONS)})
plain = modify_row()
must(marker(plain) == "absent" and set(plain["after_value"]) == {"name", "actions", "actions_count"}, plain["after_value"])
plain_after = json.dumps(plain["after_value"], sort_keys=True)
must("MARKER-SECRET" not in plain_after, "unchanged")
print("       an operation without audit_list_masks writes the rows it wrote before")

# (7) two masked lists get one marker each, only where both sides hold the list
reset()
decl("two-lists", masks={"actions": {"script_args": "names"}, "steps": {"command": "mask"}}, body_fields=["name", "actions", "steps", "extra"], audit_lists=["actions", "steps"])
STATE["answer"] = {"name": "old", "actions": copy.deepcopy(ACTIONS), "steps": [{"command": "a"}]}
run("two-lists", {"name": "old", "actions": copy.deepcopy(ACTIONS), "steps": [{"command": "b"}]})
after = modify_row()["after_value"]
must(after.get("actions_changed") is False and after.get("steps_changed") is True, after)
STATE["answer"] = {"name": "old", "actions": copy.deepcopy(ACTIONS)}
run("two-lists", {"name": "old", "actions": copy.deepcopy(ACTIONS), "steps": [{"command": "b"}]})
after = modify_row()["after_value"]
must(after.get("actions_changed") is False and "steps_changed" not in after, after)
print("       each masked list gets its own marker, left out where the before read has no such list")

# (8) never on a failed, denied or outcome-unknown row
for status, action in ((400, "custom:operation-failed"), (403, "deny"), (500, "custom:outcome-unknown")):
    reset()
    decl("with-marker")
    STATE["put"] = status
    sent = copy.deepcopy(ACTIONS)
    sent[1]["command"] = "MARKER-SECRET-7731"
    try:
        run("with-marker", {"name": "old", "actions": sent})
    except ops.TacticalOperationError:
        pass
    rows = [r for r in ROWS if r.get("action") == action]
    must(len(rows) == 1, (status, [r.get("action") for r in ROWS]))
    must("actions_changed" not in json.dumps(rows[0], default=str), (status, "no marker on a row that is not a success"))
    must("MARKER-SECRET" not in json.dumps(ROWS, default=str), status)
print("       no marker on a failed, denied or outcome-unknown row")

# (9) rule A8: neither a digest nor a masked value is in any row, any log line or the result
reset()
decl("with-marker")
sent = copy.deepcopy(ACTIONS)
sent[0]["script_args"][0] = "--token=MARKER-SECRET-7731"
result = run("with-marker", {"name": "old", "actions": sent})
digests = {hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest() for value in (ACTIONS, sent)}
everything = json.dumps(ROWS, default=str) + repr(result) + "\n".join(capture.lines)
for needle in (*SECRETS, *digests):
    must(needle not in everything, ("leak", needle[:12]))
must(not hasattr(result, "list_digests") and "list_digests" not in repr(result), "the digest is not part of the result")
print("       a marker secret and the digests never reach a row, a log line or the result")

# (10) the contract names it
meta = ops.tactical_operations_contract_metadata()
must(ops.CAPABILITY_VERSION == "1.16.0" and meta["version"] == "1.16.0" and meta["version"].split(".")[0] == "1", meta["version"])
must(meta["declaration_keys_added_in_1_16_0"] == [] and any("_changed" in text for text in meta["behaviour_added_in_1_16_0"]), meta.get("behaviour_added_in_1_16_0"))
docs = (Path(__file__).resolve().parents[1] / "framwork" / "tec_tac" / "tactical_operations.py").read_text(encoding="utf-8")
must("<list>_changed" in docs and "1.17.58" in docs, "module docstring")
print("[TEST] PASS tactical operation list marker 1.17.58")
