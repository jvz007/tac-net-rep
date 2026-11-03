#!/usr/bin/env python3
"""1.17.108 (Licensing 0.10.1/0.10.2 requests, handoff v0.1.44 section 4 item 4, AD-21, AD-58): release states in the licensed catalogue.

Covered: licence_policy_unreadable is a known state with its own sentence; it empties the list (not transient) and is attention, not a
sync failure, exactly like licence_grace_expired; every licensed release gets one availability_state (available, entitled_unavailable,
blocked_by_channel, missing_or_dependency, not_in_licence, unclassified); a category that is not core, server or premium is stored as
null and never offered; an unknown availability word is never read as available; only available rows are offered; a 1.17.107 cache
gets the states when it is read; unavailable[] lists the rest with Core's own sentence; a retired or refused mark is never overwritten;
staging a release that is not offered gives its own sentence; the docs, troubleshooting and contract carry the states; line endings.

licensing_catalogue_source.py imports no Django and is loaded as it is (with a stand-in module_state). module_repository.py imports
Django, so its functions are read with ast and run with stubs, the method of tests/licensing-repository-1.17.103.py. No network.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
REPO_PATH = APP / "module_repository.py"
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise ModuleStateError(f"bad version {version!r}")
    return True


pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules["tec_tac"] = pkg
state_mod = types.ModuleType("tec_tac.module_state")
state_mod.ModuleStateError = ModuleStateError
state_mod.version_satisfies = version_satisfies
sys.modules["tec_tac.module_state"] = state_mod
spec = importlib.util.spec_from_file_location("tec_tac.licensing_catalogue_source", APP / "licensing_catalogue_source.py")
lcs = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.licensing_catalogue_source"] = lcs
spec.loader.exec_module(lcs)

# ---------------------------------------------------------------------------------------------- 1. licence_policy_unreadable
P = "licence_policy_unreadable"
must(P in lcs.KNOWN_STATES and P in lcs.ATTENTION_STATES and P not in lcs.TRANSIENT_STATES and P in lcs.AVAILABILITY_STATES, "state lists")
must(lcs.message_for(P) == "This Licensing version cannot read the licence's module policy. Update Licensing, then use Refresh now.", lcs.message_for(P))
must(lcs.LicensingSourceError(P).state == P, "an error keeps the state")
for name in ("licence_grace_expired", P):  # the same fail-closed treatment
    must(name in lcs.ATTENTION_STATES and name not in lcs.TRANSIENT_STATES, name)


class Provider:
    def __init__(self, answer):
        self.answer = answer

    def module_catalogue(self, *, channel=None):
        return self.answer


caps = types.ModuleType("tec_tac.capabilities")
CURRENT = {"obj": None}
caps.get_capability = lambda capability_id, *, version=None, **kw: CURRENT["obj"]
sys.modules["tec_tac.capabilities"] = caps
CURRENT["obj"] = Provider({"ok": False, "state": P, "message": "provider text"})
must(lcs.fetch_catalogue(None) == (P, None), "the provider's licence_policy_unreadable is read as that state, not as invalid_response")
print("       licence_policy_unreadable: known, own sentence, empties the list, attention like licence_grace_expired")

# ---------------------------------------------------------------------------------------------- 2. one state per release
REL = "11111111-1111-4111-8111-111111111111"
SHA = "b" * 64


def entry(module_id="alpha", **over):
    item = {"id": module_id, "name": module_id.title(), "category": "premium", "entitled": True, "entitlement_source": "license",
            "availability": "available", "available_releases": [{"release_id": REL, "version": "1.0.0", "channel": "development", "sha256": SHA}]}
    item.update(over)
    return item


CASES = [
    ({}, "available"),
    ({"availability": None}, "available"),
    ({"availability": "Available"}, "available"),
    ({"category": "Core"}, "available"),
    ({"availability": "unavailable"}, "entitled_unavailable"),
    ({"availability": "withdrawn"}, "entitled_unavailable"),
    ({"availability": "something new"}, "entitled_unavailable"),
    ({"availability": "blocked_by_channel"}, "blocked_by_channel"),
    ({"availability": "channel_blocked"}, "blocked_by_channel"),
    ({"availability": "missing"}, "missing_or_dependency"),
    ({"availability": "dependency_failure"}, "missing_or_dependency"),
    ({"entitled": False}, "not_in_licence"),
    ({"entitled": "yes"}, "not_in_licence"),
    ({"entitled": False, "category": None}, "not_in_licence"),
    ({"category": None}, "unclassified"),
    ({"category": "None"}, "unclassified"),
    ({"category": "tools"}, "unclassified"),
    ({"category": ""}, "unclassified"),
]
for over, expected in CASES:
    rows, skipped = lcs.map_catalogue({"modules": [entry(**over)]})
    must(len(rows) == 1 and not skipped, (over, rows, skipped))
    row = rows[0]
    must(row["availability_state"] == expected, (over, row["availability_state"], expected))
    if expected == "available":
        must(not row.get("download_unavailable") and "download_unavailable_state" not in row, (over, row))
    else:
        must(row["download_unavailable"] is True and row["download_unavailable_state"] == expected, (over, row))
        must(row["download_unavailable_reason"] == lcs.ROW_TEXT[expected], (over, row))
    must(row["category"] in ("core", "server", "premium", None), row["category"])
must(lcs.ROW_TEXT["not_in_licence"] == lcs.TEXT["not_in_licence"], "the 1.17.103 sentence is kept")
must(set(lcs.ROW_STATES) == {"available", "entitled_unavailable", "blocked_by_channel", "missing_or_dependency", "not_in_licence", "unclassified"}, lcs.ROW_STATES)
for text in lcs.ROW_TEXT.values():
    must(text and "\n" not in text and len(text) < 300, text)
# idempotent; never clears or overwrites another rule's mark
row = lcs.apply_availability(lcs.apply_availability({"entitled": True, "category": "core", "availability": "missing"}))
must(row["download_unavailable_state"] == "missing_or_dependency", row)
row = lcs.apply_availability({"entitled": True, "category": "core", "availability": "available", "download_unavailable": True,
                              "download_unavailable_state": "repository_retired", "download_unavailable_reason": "r"})
must(row["download_unavailable"] is True and row["download_unavailable_state"] == "repository_retired", row)
row = lcs.apply_availability({"entitled": False, "download_unavailable": True, "download_unavailable_state": "credentials_rejected", "download_unavailable_reason": "c"})
must(row["download_unavailable_state"] == "credentials_rejected" and row["availability_state"] == "not_in_licence", row)
print("       release states: available only for entitled, classified and available (or no word); an unknown word is never available")

# ---------------------------------------------------------------------------------------------- 3. module_repository: cache read, unavailable[], staging
names = {"_cached_modules", "_unavailable_licensed", "MAX_UNAVAILABLE_ROWS"}
picked = [n for n in REPO_TREE.body if (isinstance(n, ast.FunctionDef) and n.name in names)
          or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))]
must({getattr(n, "name", None) or n.targets[0].id for n in picked} == names, "functions not found")
TMP = Path(tempfile.mkdtemp(prefix="tectac-licensing-avail-"))
CACHE = TMP / "cache"
CACHE.mkdir()
FLAGS = {"retired": False}
ns = {
    "__name__": "tec_tac.module_repository", "json": json, "Path": Path, "CACHE_ROOT": CACHE, "_lcs": lcs,
    "_has_credentials": lambda raw: False, "_repo_raw": lambda rid: {},
    "_cache_retired": lambda payload, credentialed: FLAGS["retired"], "_cache_credentials_rejected": lambda payload, credentialed: False,
    "CREDENTIALS_RELEASE_REASON": "c", "RETIRED_RELEASE_REASON": "r",
}
exec(compile(ast.Module(body=picked, type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only
LIC = {"id": "tec-tac-licensing", "name": "Licensed", "priority": 10, "trust": "official", "kind": "licensing"}
IDX = {"id": "index", "name": "Index", "priority": 20, "trust": "official"}
# a 1.17.107 cache: raw availability and category, no availability_state; an unclassified entitled row was offered then
old_rows = [
    {"id": "alpha", "name": "Alpha", "version": "1.0.0", "entitled": True, "category": "premium", "availability": "available"},
    {"id": "beta", "name": "Beta", "version": "2.0.0", "entitled": True, "category": None, "availability": "available"},
    {"id": "gamma", "name": "Gamma", "version": "3.0.0", "entitled": True, "category": "server", "availability": "blocked_by_channel"},
    {"id": "delta", "name": "Delta", "version": "4.0.0", "entitled": False, "category": "premium", "availability": "available",
     "download_unavailable": True, "download_unavailable_reason": lcs.TEXT["not_in_licence"], "download_unavailable_state": "not_in_licence"},
]
(CACHE / "tec-tac-licensing.json").write_text(json.dumps({"modules": old_rows}), encoding="utf-8")
(CACHE / "index.json").write_text(json.dumps({"modules": [{"id": "beta", "version": "9.0.0"}]}), encoding="utf-8")
rows = {r["id"]: r for r in ns["_cached_modules"](LIC)}
must(rows["alpha"]["availability_state"] == "available" and not rows["alpha"].get("download_unavailable"), rows["alpha"])
must(rows["beta"]["download_unavailable_state"] == "unclassified" and rows["gamma"]["download_unavailable_state"] == "blocked_by_channel", rows)
must(rows["delta"]["download_unavailable_state"] == "not_in_licence", rows["delta"])
idx = ns["_cached_modules"](IDX)
must(idx and "availability_state" not in idx[0] and not idx[0].get("download_unavailable"), "an index repository row is not touched")
offered = [r["id"] for r in ns["_cached_modules"](LIC) if not r.get("download_unavailable")]
must(offered == ["alpha"], offered)
listed = ns["_unavailable_licensed"]([LIC, IDX])
must([(r["id"], r["availability_state"]) for r in listed] == [("beta", "unclassified"), ("delta", "not_in_licence"), ("gamma", "blocked_by_channel")], listed)
for r in listed:
    must(set(r) == {"id", "name", "version", "channel", "category", "repository_id", "repository_name", "availability_state", "reason"}, r)
    must(r["reason"] == lcs.ROW_TEXT[r["availability_state"]] and r["repository_id"] == "tec-tac-licensing", r)
FLAGS["retired"] = True
listed = ns["_unavailable_licensed"]([LIC])
must(listed == [], "a retired mark wins and is not listed as a licence state")
FLAGS["retired"] = False
must(ns["MAX_UNAVAILABLE_ROWS"] == 500, "bounded")
print("       cache: a 1.17.107 cache gets the states on read; only available is offered; unavailable[] lists the rest with Core's sentence")

SRC = REPO_PATH.read_text(encoding="utf-8")
must('"unavailable": _unavailable_licensed(repos),' in SRC, "online_catalog returns unavailable[]")
must("_lcs.ROW_TEXT.get(state) or _lcs.message_for(\"not_in_licence\")" in SRC, "staging names the reason of the release")
print("       online catalog and staging: unavailable[] returned; staging a release that is not offered gives its own sentence")


# ---------------------------------------------------------------------------------------------- 4. docs, contract, version, line endings
def read(path):
    return Path(path).read_text(encoding="utf-8")


DOC = read(ROOT / "docs" / "module-repositories.md")
TS = read(ROOT / "docs" / "troubleshooting-diagnostics.md")
for text, label in ((DOC, "module-repositories.md"), (TS, "troubleshooting")):
    must(f"`{P}`" in text and lcs.TEXT[P] in text, f"{label}: {P}")
    for state_name, sentence in lcs.ROW_TEXT.items():
        must(f"`{state_name}`" in text and sentence in text, f"{label}: {state_name}")
must("1.17.108" in DOC and "Not available" in DOC, "the help section")
CONTRACTS = read(APP / "contracts.py")
must('"unavailable": "array (added 1.17.108)' in CONTRACTS and "licence_policy_unreadable" in CONTRACTS and "availability_state" in CONTRACTS, "contract")
NOTES = read(ROOT / "RELEASE_NOTES_1.17.108.md")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "FAIL"):
    must(heading in NOTES, heading)
must(read(ROOT / "VERSION").strip() == "1.17.108" and json.loads(read(ROOT / "tec_tac_package.json"))["version"] == "1.17.108", "version")
for path in (REPO_PATH, APP / "contracts.py", ROOT / "docs" / "module-repositories.md", ROOT / "docs" / "troubleshooting-diagnostics.md"):
    data = path.read_bytes()
    must(b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b""), f"{path.name} lost its CRLF")
must(b"\r" not in (APP / "licensing_catalogue_source.py").read_bytes(), "licensing_catalogue_source.py must stay LF")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh has CR")
print("       docs, troubleshooting, contract, notes, version, line endings")
print("[TEST] PASS licensing availability 1.17.108")
