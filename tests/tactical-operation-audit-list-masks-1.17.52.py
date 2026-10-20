#!/usr/bin/env python3
"""1.17.52 regression: ``audit_list_masks`` keeps the values of a list's keys out of the audit row (AD-39, Johan, 17 October 2026:
names without values first, *** second; request "From tasks 0.10.1").

``audit_lists`` (1.17.28) records a list of flat objects in clear. A task's actions carry script arguments, environment variables and a
cmd action's command, which can hold secrets. ``audit_list_masks={list: {key: "names"|"mask"}}`` masks those keys on both sides of the
row. ``names`` keeps only the name of each text item, ``mask`` keeps the name and shows ``***`` for the value. A declaration without it
is recorded in clear exactly as in 1.17.28.

Uses the stubs of tests/tactical-operations-1.17.7.py the way tests/tactical-operations-audit-lists-1.17.28.py does. Django is not
installed on the PC that prepares a release.
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
ops, fresh, must = (G[k] for k in ("ops", "fresh", "must"))
ROUTES, CALLS, ROWS, AGENT, tech, Request = (G[k] for k in ("ROUTES", "CALLS", "ROWS", "AGENT", "tech", "Request"))
FakeResponse = G["FakeResponse"]

NOTE = 5
NOTE_PATH = f"/agents/{AGENT}/notes/{NOTE}/"
NOTE_ROUTE = "agents/{agent_id:agent}/notes/{note_id:int}/"
PARAMS = {"agent_id": AGENT, "note_id": NOTE}
# values that must never be found in any audit row
SECRETS = ("tok-abc123", "sekret-one", "positional-secret", "hunter2", "VALUEx9", "P@ssw0rd!", "net user admin", "dG9rZW4", "swordfish")

NEW = [
    {"type": "script", "script": 12, "name": "backup", "timeout": 90,
     "script_args": ["--token=tok-abc123", "-Name sekret-one", "positional-secret", "/S", "--flag"],
     "env_vars": ["KEY=VALUEx9", "PASSWORD=hunter2"]},
    {"type": "cmd", "command": "net user admin P@ssw0rd!", "shell": "cmd", "timeout": 30},
]
OLD = [
    {"type": "script", "script": 11, "name": "old", "timeout": 60, "script_args": ["--old=swordfish", "tok-abc123"], "env_vars": ["OLDKEY=hunter2"]},
    {"type": "cmd", "command": "net user admin P@ssw0rd!", "shell": "cmd"},
]
IDS = ["edit-names", "edit-mask", "edit-clear", "edit-scalar-names"]


def slug(op_id):
    return op_id.replace("-", "")


def tpl(op_id):
    """One Tactical route per declaration (AD-6: one caller per route)."""
    return f"agents/{{agent_id:agent}}/notes/{{note_id:int}}/{slug(op_id)}/"


def path(op_id):
    return f"/agents/{AGENT}/notes/{NOTE}/{slug(op_id)}/"


STATE = {"answer": {"name": "old", "actions": OLD}, "status": {"PUT": 200, "DELETE": 200}}


def note_view(request, *args, **kwargs):
    method = request.META.get("REQUEST_METHOD", "GET")
    CALLS.append(SimpleNamespace(request=request, args=args, kwargs=kwargs, method=method))
    if method == "GET":
        return FakeResponse(200, json.dumps(STATE["answer"]).encode("utf-8"))
    return FakeResponse(STATE["status"][method], b'{"ok": true}')


def reset():
    ROUTES.clear()  # the routes of every declaration are put back below
    for op_id in IDS:
        ROUTES[path(op_id)] = (note_view, (), {})
    STATE["status"] = {"PUT": 200, "DELETE": 200}
    STATE["answer"] = {"name": "old", "actions": OLD}
    del ROWS[:]
    del CALLS[:]


def decl(op_id, masks, **over):
    spec = dict(
        id=op_id, module_id="agents", method="PUT", route=tpl(op_id), permissions=["can_manage_notes"],
        scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions"],
        audit={"action": "modify", "object_type": "note", "audit_fields": ["name"], "before": {"route": tpl(op_id), "fields": ["name"]}},
        audit_lists=["actions"],
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


def no_secret_anywhere(label):
    dumped = json.dumps(ROWS, default=str)
    for secret in SECRETS:
        must(secret not in dumped, (label, secret))


fresh()
reset()
NAMES = {"actions": {"script_args": "names", "env_vars": "names", "command": "mask"}}
decl("edit-names", NAMES)
decl("edit-mask", {"actions": {"script_args": "mask", "env_vars": "mask", "command": "mask"}})
decl("edit-clear", None)

# ---- the capability, the declaration and describe()
must(ops.CAPABILITY_VERSION == "1.16.0", ops.CAPABILITY_VERSION)
meta = ops.tactical_operations_contract_metadata()
must(meta["version"] == "1.16.0" and meta["version"].split(".")[0] == "1", meta["version"])
must("audit_list_masks" in meta["declaration"] and "audit_list_masks" in " ".join(meta["declaration_keys_added_in_1_15_0"]), meta["declaration_keys_added_in_1_15_0"])
must(meta["limits_added_in_1_15_0"] == {"audit_list_mask_keys_per_list": 8, "audit_list_mask_modes": ["names", "mask"], "masked_text": "***"}, meta["limits_added_in_1_15_0"])
must(any("names" in text and "***" in text and "base64" in text for text in meta["behaviour_added_in_1_15_0"]), "the rule text is exported")
must(ops.get_operation("agents", "edit-names")["audit"]["list_masks"] == {"actions": {"script_args": "names", "env_vars": "names", "command": "mask"}},
     ops.get_operation("agents", "edit-names")["audit"])
must(ops.get_operation("agents", "edit-clear")["audit"]["list_masks"] == {}, "an empty object when none, like secret_fields")
must(ops.get_operation("agents", "edit-clear")["audit"]["lists"] == ["actions"], "audit_lists is unchanged")
listed = {item["id"]: item for item in ops.list_operations("agents")}
must(listed["edit-mask"]["audit"]["list_masks"]["actions"]["command"] == "mask", listed["edit-mask"]["audit"])

# ---- names: KEY=VALUE -> KEY, --flag=value -> --flag, -Name value -> -Name, a positional secret -> ***, command -> ***
reset()
result = run("edit-names", {"name": "new", "actions": NEW})
must(result.status == 200 and len(CALLS) == 2, (result.status, len(CALLS)))
row = modify_row()
after = row["after_value"]["actions"]
must(after[0]["script_args"] == ["--token", "-Name", "***", "/S", "--flag"], after[0]["script_args"])
must(after[0]["env_vars"] == ["KEY", "PASSWORD"], after[0]["env_vars"])
must(after[1]["command"] == "***", after[1])
must(after[0]["script"] == 12 and after[0]["name"] == "backup" and after[0]["timeout"] == 90 and after[0]["type"] == "script", "the other keys are recorded as before")
must(after[1]["shell"] == "cmd" and after[1]["timeout"] == 30 and after[1]["type"] == "cmd", after[1])
must(row["after_value"]["actions_count"] == 2 and "actions_truncated" not in row["after_value"], row["after_value"])
no_secret_anywhere("names, whole row")

# ---- the before side from Tactical's own answer is masked the same way
before = row["before_value"]["actions"]
must(before[0]["script_args"] == ["--old", "***"] and before[0]["env_vars"] == ["OLDKEY"] and before[1]["command"] == "***", before)
must(before[0]["script"] == 11 and before[0]["name"] == "old", before[0])
must(row["before_value"]["name"] == "old" and row["after_value"]["name"] == "new", "scalar fields unchanged")

# ---- mask: the name stays, the value is ***
reset()
run("edit-mask", {"name": "new", "actions": NEW})
row = modify_row()
must(row["after_value"]["actions"][0]["script_args"] == ["--token=***", "-Name ***", "***", "/S", "--flag"], row["after_value"]["actions"][0]["script_args"])
must(row["after_value"]["actions"][0]["env_vars"] == ["KEY=***", "PASSWORD=***"], row["after_value"]["actions"][0]["env_vars"])
must(row["after_value"]["actions"][1]["command"] == "***", "a scalar text key is ***")
must(row["before_value"]["actions"][0]["script_args"] == ["--old=***", "***"], row["before_value"]["actions"][0]["script_args"])
no_secret_anywhere("mask, whole row")

# ---- a declaration without audit_list_masks behaves as in 1.17.28: clear text, both sides
reset()
run("edit-clear", {"name": "new", "actions": NEW})
row = modify_row()
must(row["after_value"]["actions"] == NEW and row["before_value"]["actions"] == OLD, "clear, byte for byte")
dumped = json.dumps(ROWS, default=str)
must("hunter2" in dumped and "positional-secret" in dumped and "net user admin" in dumped, "audit_lists alone still records in clear")


# ---- item shapes: a name must look like a name, and anything else is ***
def recorded(op_id, value, key="script_args"):
    reset()
    run(op_id, {"name": "n", "actions": [{key: value, "type": "x"}]})
    return modify_row()["after_value"]["actions"][0][key]


for item, expected_names, expected_mask in (
    ("KEY=VALUE", "KEY", "KEY=***"), ("--flag=value", "--flag", "--flag=***"), ("-f=1", "-f", "-f=***"), ("-Name value", "-Name", "-Name ***"),
    ("-Name   spaced value", "-Name", "-Name ***"), ("--long-flag x", "--long-flag", "--long-flag ***"), ("/S", "/S", "/S"), ("-Force", "-Force", "-Force"),
    ("/Q /N", "/Q", "/Q ***"), ("a.b-c=1", "a.b-c", "a.b-c=***"), ("A_1=x=y", "A_1", "A_1=***"),
    ("plain", "***", "***"), ("positional-secret", "***", "***"), ("", "***", "***"), ("   ", "***", "***"),
    ("dG9rZW4=", "***", "***"), ("dG9rZW4==", "***", "***"), ("KEY=", "***", "***"), ("KEY==", "***", "***"), ("=abc", "***", "***"),
    ("a b=c", "***", "***"), ("-x:value", "***", "***"), ("/etc/shadow", "***", "***"), ("/p/a/t/h", "***", "***"), ("---x=1", "***", "***"),
    ("9KEY=1", "***", "***"), ("K" * 65 + "=1", "***", "***"), ("-" + "k" * 65, "***", "***"), ("-", "***", "***"), ("--", "***", "***"),
    ("é=1", "***", "***"), ("K\x00EY=1", "KEY", "KEY=***"),
):
    must(recorded("edit-names", [item]) == [expected_names], (item, recorded("edit-names", [item])))
    must(recorded("edit-mask", [item]) == [expected_mask], (item, recorded("edit-mask", [item])))
must(recorded("edit-names", ["K" * 64 + "=1"]) == ["K" * 64], "64 characters is a name")
# a non-text item is ***, whatever it is
for odd in (1, 1.5, None, True, False, ["x=y"], {"a": "b"}):
    must(recorded("edit-names", [odd]) == ["***"] and recorded("edit-mask", [odd]) == ["***"], odd)
must(recorded("edit-names", []) == [], "an empty list stays empty")

# ---- fail closed: a masked key whose value is not a list of text
for odd in ("--token=tok-abc123", "plain text", 5, 5.5, True, {"a": "swordfish"}):
    must(recorded("edit-names", odd) == "***" and recorded("edit-mask", odd) == "***", odd)
    no_secret_anywhere("a scalar under a list key")
must(recorded("edit-names", None) is None and recorded("edit-mask", None) is None, "None stays null")
must(recorded("edit-names", "", key="command") == "***", "an empty scalar is still ***")
reset()
run("edit-names", {"name": "n", "actions": [{"type": "cmd", "command": None}, {"type": "cmd"}]})
must(modify_row()["after_value"]["actions"] == [{"type": "cmd", "command": None}, {"type": "cmd"}], "null stays null; an absent key stays absent")
# names on a scalar key records *** (Core cannot tell a scalar key at registration, so it is handled here)
decl("edit-scalar-names", {"actions": {"command": "names"}})
must(recorded("edit-scalar-names", "echo swordfish", key="command") == "***", "names on a scalar key is ***")
# a key that is masked is masked inside every entry, and an unmasked key in the same entry is recorded as before
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": ["--k=v1"], "other_args": ["--k=visible"], "note": "plain"}]})
entry = modify_row()["after_value"]["actions"][0]
must(entry == {"script_args": ["--k"], "other_args": ["--k=visible"], "note": "plain"}, entry)

# ---- counts and truncation still work after masking
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": [f"--a{i}=v" for i in range(101)]}]})
row = modify_row()
must(len(row["after_value"]["actions"][0]["script_args"]) == 100 and row["after_value"]["actions_truncated"] is True, "101 items cut to 100, flagged")
must(row["after_value"]["actions"][0]["script_args"][0] == "--a0" and row["after_value"]["actions"][0]["script_args"][99] == "--a99", "masked, then cut")
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": [f"--a{i}=v" for i in range(100)]}]})
must("actions_truncated" not in modify_row()["after_value"], "100 items are whole")
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": ["--k=v"]} for _ in range(51)]})
row = modify_row()
must(len(row["after_value"]["actions"]) == 50 and row["after_value"]["actions_count"] == 51 and row["after_value"]["actions_truncated"] is True, "51 entries")
reset()
STATE["answer"] = {"name": "old", "actions": [{"script_args": [f"--b{i}=swordfish" for i in range(120)], "env_vars": ["A=hunter2"]}]}
run("edit-names", {"name": "n", "actions": [{"script_args": ["--k=v"]}]})
row = modify_row()
must(len(row["before_value"]["actions"][0]["script_args"]) == 100 and row["before_value"]["actions_truncated"] is True, "the before side is bounded too")
must(row["before_value"]["actions"][0]["env_vars"] == ["A"], row["before_value"])
no_secret_anywhere("before side, many items")
# the text bound still applies after masking: a very long name is not a name, so it is ***
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": ["k" * 5000 + "=v"]}]})
must(modify_row()["after_value"]["actions"][0]["script_args"] == ["***"], "a 5000 character head is not a name")
# a malformed list is still recorded as its count only, with no value
reset()
run("edit-names", {"name": "n", "actions": [{"script_args": ["--k=swordfish"]}, "a string item"]})
row = modify_row()
must(row["after_value"]["actions"] == [] and row["after_value"]["actions_count"] == 2 and row["after_value"]["actions_truncated"] is True, row["after_value"])
no_secret_anywhere("malformed list")

# ---- failed, denied and outcome-unknown rows still carry no list, so no value either
for status, action in ((400, "custom:operation-failed"), (403, "deny"), (500, "custom:outcome-unknown")):
    reset()
    STATE["status"]["PUT"] = status
    try:
        run("edit-names", {"name": "n", "actions": NEW})
    except ops.TacticalOperationError:
        pass
    rows = [r for r in ROWS if r.get("action") == action]
    must(len(rows) == 1, (status, [r.get("action") for r in ROWS]))
    for key in ("after_value", "before_value"):
        must(not rows[0].get(key) or "actions" not in rows[0][key], (status, key, rows[0].get(key)))
    no_secret_anywhere(f"status {status}")

# ---- the masks reach Tactical's call unchanged: only the audit row is masked
reset()
run("edit-names", {"name": "n", "actions": NEW})
sent = [call for call in CALLS if call.method == "PUT"]
must(len(sent) == 1, [c.method for c in CALLS])
body_sent = sent[0].request._body.decode("utf-8")
must("tok-abc123" in body_sent and "hunter2" in body_sent, "Tactical still gets the real values")

# ---- registration refusals
BASE = dict(
    id="edit-x", module_id="agents", method="PUT", route=NOTE_ROUTE, permissions=["can_manage_notes"],
    scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=["name", "actions", "tags"],
    audit={"action": "modify", "object_type": "note", "audit_fields": ["name"], "before": {"route": NOTE_ROUTE, "fields": ["name"]}},
    audit_lists=["actions"],
)
for reason, over in (
    ("is not one of audit_lists", dict(id="r1", audit_list_masks={"tags": {"x": "names"}})),
    ("is not one of audit_lists", dict(id="r2", audit_lists=None, audit_list_masks={"actions": {"x": "names"}})),
    ("is not one of audit_lists", dict(id="r3", audit_list_masks={True: {"x": "names"}})),
    ("is not one of audit_lists", dict(id="r3b", audit_list_masks={1: {"x": "names"}})),
    ("must be a dict of", dict(id="r4", audit_list_masks=["actions"])),
    ("must be a dict of", dict(id="r5", audit_list_masks="actions")),
    ("must be a dict of", dict(id="r6", audit_list_masks=("actions",))),
    ("must be a dict of", dict(id="r6b", audit_list_masks=True)),
    ("must be a dict of", dict(id="r6c", audit_list_masks=0)),
    ("with at least one key", dict(id="r7", audit_list_masks={"actions": ["script_args"]})),
    ("with at least one key", dict(id="r8", audit_list_masks={"actions": "names"})),
    ("with at least one key", dict(id="r9", audit_list_masks={"actions": {}})),
    ("with at least one key", dict(id="r9b", audit_list_masks={"actions": None})),
    ("at most 8 keys", dict(id="r10", audit_list_masks={"actions": {f"k{i}": "names" for i in range(9)}})),
    ("is not a field name", dict(id="r11", audit_list_masks={"actions": {"bad-key": "names"}})),
    ("is not a field name", dict(id="r12", audit_list_masks={"actions": {"": "names"}})),
    ("is not a field name", dict(id="r13", audit_list_masks={"actions": {1: "names"}})),
    ("is not a field name", dict(id="r14", audit_list_masks={"actions": {True: "names"}})),
    ("is not a field name", dict(id="r15", audit_list_masks={"actions": {"a b": "names"}})),
    ("is not a field name", dict(id="r16", audit_list_masks={"actions": {"k" * 65: "names"}})),
    ("the mode is 'names' or 'mask'", dict(id="r17", audit_list_masks={"actions": {"script_args": "clear"}})),
    ("the mode is 'names' or 'mask'", dict(id="r18", audit_list_masks={"actions": {"script_args": True}})),
    ("the mode is 'names' or 'mask'", dict(id="r19", audit_list_masks={"actions": {"script_args": None}})),
    ("the mode is 'names' or 'mask'", dict(id="r20", audit_list_masks={"actions": {"script_args": "NAMES"}})),
    ("the mode is 'names' or 'mask'", dict(id="r21", audit_list_masks={"actions": {"script_args": ["names"]}})),
    ("the mode is 'names' or 'mask'", dict(id="r22", audit_list_masks={"actions": {"script_args": ""}})),
):
    try:
        ops.register_tactical_operation(**{**BASE, **over})
    except ops.TacticalOperationRegistrationError as exc:
        must(reason in str(exc), (reason, str(exc)))
    else:
        raise AssertionError(f"registration must be refused: {reason} ({over['id']})")
# eight keys is allowed; nothing was registered by the refused declarations
def own(op_id, **over):
    """BASE under its own route and before read."""
    return {**BASE, "id": op_id, "route": tpl(op_id), "audit": {**BASE["audit"], "before": {"route": tpl(op_id), "fields": ["name"]}}, **over}


eight = ops.register_tactical_operation(**own("ok8", audit_list_masks={"actions": {f"k{i}": "mask" for i in range(8)}}))
must(len(eight.audit_list_masks[0][1]) == 8 and eight.audit_list_masks[0][0] == "actions", eight.audit_list_masks)
for refused_id in ("r1", "r2", "r4", "r10", "r17"):
    must(ops.get_operation("agents", refused_id) is None, f"{refused_id} must not be registered")
# an empty mapping is no mask at all; two lists may each carry masks; the same declaration again is idempotent
must(ops.register_tactical_operation(**own("empty-mask", audit_list_masks={})).audit_list_masks == (), "an empty mapping is no mask")
two = own("two-lists", audit_lists=["actions", "tags"], audit_list_masks={"actions": {"a": "names"}, "tags": {"b": "mask"}})
registered = ops.register_tactical_operation(**two)
must(dict(registered.audit_list_masks) == {"actions": (("a", "names"),), "tags": (("b", "mask"),)}, registered.audit_list_masks)
must(ops.register_tactical_operation(**two) == registered, "identical re-registration is idempotent")
# the mask is part of the declaration: the same id with another mask is not the same declaration
try:
    ops.register_tactical_operation(**{**two, "audit_list_masks": {"actions": {"a": "mask"}, "tags": {"b": "mask"}}})
except ops.TacticalOperationRegistrationError:
    pass
else:
    raise AssertionError("a different mask under the same id must not silently replace the declaration")

# ---- the docs and the contract text state the rule plainly
root = Path(__file__).resolve().parents[1]
doc = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
for needle in ("audit_list_masks", "names", "***", "AD-39", "base64", "list_masks", "1.15.0", "Added in 1.17.52"):
    must(needle in doc, ("docs/tactical-operations.md", needle))
src = (root / "framwork" / "tec_tac" / "tactical_operations.py").read_text(encoding="utf-8")
must("audit_list_masks" in src.split('from __future__', 1)[0], "the module docstring names audit_list_masks")
contract = (root / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
must("audit_list_masks" in contract and "core.tactical_operations >= 1.15.0" in contract, "contract text")
print("tactical operation audit list masks 1.17.52 ok")
