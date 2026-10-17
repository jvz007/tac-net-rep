#!/usr/bin/env python3
"""Core 1.17.51: saved views with an 'fs-' key from before 1.17.50 are not filter sets (1.17.50 review, LOW).

Runs the real filter_sets and saved_views on the 1.17.50 boundary with its in-memory TecTacSavedView. Covered: a row under 'fs-x' with
payload {'foo': 1} is absent from list_filter_sets, get_filter_set raises FilterSetNotFound, update, delete and resolve refuse it; kind
'filter_set' with version 2 (or True, or a bad match, or rules that are not a list) is skipped; repair_stray_saved_views renames to
'fs_x' and the saved views service then lists it; a collision is skipped and counted; a second run changes nothing; valid filter sets
are untouched; install.sh runs the step after migrate and only warns when it fails.
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

ns = boundary.install(real_capabilities=True)
fs, sv = ns.filter_sets, ns.saved_views
alice, bob = ns.alice, ns.bob
STORE = ns.STORE
FIELDS = [{"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"}]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def refused(call, exc):
    try:
        call()
    except exc:
        return
    raise AssertionError("expected a refusal")


def stray(owner, key, name, payload, module="demo-open"):
    row = ns.MANAGER.create(owner=owner, module_id=module, view_key=key, name=name, payload=payload, readers=[])
    return row


ns.reset()
good = fs.create_filter_set(alice, "demo-open", "endpoints", "Real set", {"version": 1, "match": "all", "rules": []}, None, fields=FIELDS)
row = stray(alice, "fs-x", "Old view", {"foo": 1})
pid = str(row.id)
must([s["name"] for s in fs.list_filter_sets(alice, "demo-open", "x")] == [], "not listed")
refused(lambda: fs.get_filter_set(alice, pid), fs.FilterSetNotFound)
refused(lambda: fs.update_filter_set(alice, pid, name="hijack"), fs.FilterSetNotFound)
refused(lambda: fs.delete_filter_set(alice, pid), fs.FilterSetNotFound)
refused(lambda: fs.resolve_filter_set(alice, "demo-open", pid, FIELDS), fs.FilterSetNotFound)
must(pid in STORE and row.payload == {"foo": 1} and row.name == "Old view", "nothing was changed")

bad_payloads = [
    {"kind": "filter_set", "version": 2, "match": "all", "rules": []},
    {"kind": "filter_set", "version": True, "match": "all", "rules": []},
    {"kind": "filter_set", "version": 1, "match": "some", "rules": []},
    {"kind": "filter_set", "version": 1, "match": "all", "rules": "x"},
    {"kind": "view", "version": 1, "match": "all", "rules": []},
    "text",
]
for i, payload in enumerate(bad_payloads):
    odd = stray(alice, f"fs-odd{i}", "Odd", payload)
    refused(lambda odd=odd: fs.get_filter_set(alice, str(odd.id)), fs.FilterSetNotFound)
must(fs.list_filter_sets(alice, "demo-open", "endpoints")[0]["name"] == "Real set" and fs.get_filter_set(alice, good["id"])["name"] == "Real set")
must(fs._valid_filter_payload(STORE[good["id"]]) is True)

# repair: renames to fs_ + the rest, hands the row back to saved views, never touches a real filter set
before_good = (STORE[good["id"]].view_key, dict(STORE[good["id"]].payload))
result = fs.repair_stray_saved_views()
must(result == {"renamed": 1 + len(bad_payloads), "skipped": 0}, result)
must(row.view_key == "fs_x" and sv.get_view(alice, pid)["name"] == "Old view", "the saved views service now lists it")
must([v["name"] for v in sv.list_views(alice, "demo-open", "fs_x")] == ["Old view"])
must((STORE[good["id"]].view_key, dict(STORE[good["id"]].payload)) == before_good, "a valid filter set is untouched")
refused(lambda: fs.get_filter_set(alice, pid), fs.FilterSetNotFound)
must(fs.repair_stray_saved_views() == {"renamed": 0, "skipped": 0}, "a second run changes nothing")

# a collision is skipped and counted, and nothing is deleted
ns.reset()
a = stray(alice, "fs-dup", "Same name", {"foo": 1})
b = stray(alice, "fs_dup", "Same name", {"bar": 2})
c = stray(bob, "fs-dup", "Same name", {"baz": 3})   # another owner: no collision
count = len(STORE)
result = fs.repair_stray_saved_views()
must(result == {"renamed": 1, "skipped": 1} and len(STORE) == count, result)
must(a.view_key == "fs-dup" and a.payload == {"foo": 1} and c.view_key == "fs_dup" and b.view_key == "fs_dup", "the colliding row is kept as it was")
must(fs.repair_stray_saved_views() == {"renamed": 0, "skipped": 1}, "still skipped, still not deleted")

# a key already at the length limit stays valid: same length
ns.reset()
long_key = "fs-" + "k" * 61
long_row = stray(alice, long_key, "Long", {"foo": 1})
must(fs.repair_stray_saved_views()["renamed"] == 1 and len(long_row.view_key) == 64 and long_row.view_key == "fs_" + "k" * 61)

# install.sh: one non-fatal step after migrate, with the timeout wrapper of the VERIFY steps
text = (ROOT / "install.sh").read_text(encoding="utf-8")
step = re.search(r"VERIFY_STRAY_VIEWS_CODE=.*?\nfi\n", text, re.S)
must(step is not None, "install.sh has the repair step")
block = step.group(0)
must("repair_stray_saved_views" in block and "timeout 45s" in block and "fail " not in block and "WARNING" in block, block)
must(text.index("migrate tec_tac --noinput") < text.index("VERIFY_STRAY_VIEWS_CODE="), "after migrate")
print("filter-sets stray views 1.17.51 ok")
