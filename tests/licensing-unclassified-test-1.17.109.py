#!/usr/bin/env python3
"""1.17.109 (regression in 1.17.108, AD-21, handoff v0.1.44 section 2): a licensed release with no category is treated as test.

Covered: on a development server, in the development channel, a release with no category is offered with the warning "Unclassified on
the Licensing Server: treated as test"; on a production server, or in the testing or production channel, it stays unclassified and is
never offered; a categorised release is unchanged on both servers; a cache written at sync (marked unclassified) is worked out again on
read; a retired mark is never cleared; the HAR's shape (nine rows, category null, channel development) gives nine offered rows on a
development server and nine unavailable rows on a production server; online_catalog reads each cache once and the development-server
test once; unavailable[].category is normalised; staging with no version names the newest release's reason; the install never reads
the Licensing Server's category; the development-server test is module_category.is_development_server; version and line endings.

licensing_catalogue_source.py imports no Django and is loaded as it is. module_repository.py imports Django, so its functions are read
with ast and run with stubs, the method of tests/licensing-availability-1.17.108.py. No network.
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
SRC = REPO_PATH.read_text(encoding="utf-8")
REPO_TREE = ast.parse(SRC)
WARNING = "Unclassified on the Licensing Server: treated as test"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class ModuleStateError(RuntimeError):
    pass


def _key(version):
    return tuple(int(x) for x in str(version).split("."))


def version_satisfies(version, constraint):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise ModuleStateError(f"bad version {version!r}")
    if constraint.startswith(">"):
        return _key(version) > _key(constraint[1:])
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

# ---------------------------------------------------------------------------------------------- 1. the row rule
must(lcs.UNCLASSIFIED_TEST_WARNING == WARNING, lcs.UNCLASSIFIED_TEST_WARNING)


def row(**over):
    item = {"id": "alpha", "version": "1.0.0", "entitled": True, "category": None, "availability": "available", "channel": "development"}
    item.update(over)
    return item


r = lcs.apply_availability(row(), development=True)
must(r["availability_state"] == "available" and not r.get("download_unavailable") and r["category_warning"] == WARNING, r)
must(r["category"] is None, "the Licensing Server's category is never widened to a value")
for channel in ("testing", "production", None, "", "Development-x"):
    r = lcs.apply_availability(row(channel=channel), development=True)
    must(r["availability_state"] == "unclassified" and r["download_unavailable"] is True and "category_warning" not in r, (channel, r))
must(lcs.apply_availability(row(channel=" Development "), development=True)["availability_state"] == "available", "channel read loosely")
for dev in (False, None, "true", 1):
    r = lcs.apply_availability(row(), development=dev)
    must(r["availability_state"] == "unclassified" and r["download_unavailable_state"] == "unclassified", (dev, r))
r = lcs.apply_availability(row())
must(r["availability_state"] == "unclassified", "the default is not a development server")
# the other rules still come first or still apply
must(lcs.apply_availability(row(entitled=False), development=True)["availability_state"] == "not_in_licence", "licence first")
must(lcs.apply_availability(row(availability="channel_blocked"), development=True)["availability_state"] == "blocked_by_channel", "word")
must("category_warning" not in lcs.apply_availability(row(availability="missing"), development=True), "no warning when not offered")
# a categorised row is unchanged on both servers and in every channel
for dev in (True, False):
    for channel in ("development", "testing", "production"):
        r = lcs.apply_availability(row(category="premium", channel=channel), development=dev)
        must(r["availability_state"] == "available" and "category_warning" not in r and not r.get("download_unavailable"), (dev, channel, r))
# a mark written at sync is worked out again; the warning goes when the row is no longer offered; other marks are never cleared
r = lcs.apply_availability(row(), development=False)
r = lcs.apply_availability(r, development=True)
must(r["availability_state"] == "available" and not r.get("download_unavailable") and "download_unavailable_state" not in r, r)
r = lcs.apply_availability(r, development=False)
must(r["download_unavailable_state"] == "unclassified" and "category_warning" not in r, r)
r = lcs.apply_availability(row(download_unavailable=True, download_unavailable_state="repository_retired", download_unavailable_reason="x"),
                           development=True)
must(r["download_unavailable"] is True and r["download_unavailable_state"] == "repository_retired", r)
must(lcs.category_of("Premium") == "premium" and lcs.category_of("None") is None and lcs.category_of(None) is None, "category_of")
print("       row rule: no category is test, offered on a development server in the development channel only, with the warning")

# ---------------------------------------------------------------------------------------------- 2. module_repository
names = {"_cached_modules", "_unavailable_licensed", "MAX_UNAVAILABLE_ROWS", "online_catalog", "stage_repository_package", "_development_for"}
picked = [n for n in REPO_TREE.body if (isinstance(n, ast.FunctionDef) and n.name in names)
          or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))]
must({getattr(n, "name", None) or n.targets[0].id for n in picked} == names, "functions not found")
TMP = Path(tempfile.mkdtemp(prefix="tectac-licensing-unclassified-"))
CACHE = TMP / "cache"
CACHE.mkdir()
ENV = {"development": True, "calls": 0}
READS = {"count": 0}


def is_development_server():
    ENV["calls"] += 1
    return ENV["development"]


def _repo_raw(rid):
    READS["count"] += 1  # one call per _cached_modules call that reached a cache file
    return {}


class ModuleRepositoryError(Exception):
    pass


LIC = {"id": "tec-tac-licensing", "name": "Licensed", "priority": 10, "trust": "official", "kind": "licensing", "enabled": True}
STAGED = []
ns = {
    "__name__": "tec_tac.module_repository", "json": json, "Path": Path, "CACHE_ROOT": CACHE, "_lcs": lcs,
    "_has_credentials": lambda raw: False, "_repo_raw": _repo_raw,
    "_cache_retired": lambda payload, credentialed: False, "_cache_credentials_rejected": lambda payload, credentialed: False,
    "CREDENTIALS_RELEASE_REASON": "c", "RETIRED_RELEASE_REASON": "r", "is_development_server": is_development_server,
    "list_repositories": lambda: [LIC], "installed_catalog_v2": list,
    "_candidate_compatibility": lambda candidate, installed: {"compatible": True},
    "_availability": lambda repos, offered, installed_only: {"state": "ready"},
    "all_repository_status": list, "version_satisfies": version_satisfies,
    "_repo": lambda rid: LIC, "ModuleRepositoryError": ModuleRepositoryError,
    "CREDENTIALS_REJECTED_MESSAGE": "cr", "RETIRED_MESSAGE": "rm",
    "_stage_licensing_release": lambda repo, rid, mid, candidate, request=None: STAGED.append(candidate) or {"staged": candidate["version"]},
}
exec(compile(ast.Module(body=picked, type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only

# the HAR's shape (debug/har/"module catalog.har", 3 November 2026): nine rows, category null, channel development, all entitled
HAR = [("wapm", "0.4.29"), ("wapm", "0.4.30"), ("wapm", "0.4.31"), ("wapm", "0.4.32"), ("licensing", "0.9.5"), ("licensing", "0.10.2"),
       ("backups", "0.8.1"), ("serverhealth", "0.2.0"), ("welcome", "1.2.11")]
rows = []
for module_id, version in HAR:
    item = {"id": module_id, "name": module_id.title(), "version": version, "channel": "development", "category": None,
            "entitled": True, "availability": "available"}
    rows.append(lcs.apply_availability(item))  # as a 1.17.108 sync wrote it: marked unclassified
must(all(item["download_unavailable_state"] == "unclassified" for item in rows), "the 1.17.108 cache shape")
(CACHE / "tec-tac-licensing.json").write_text(json.dumps({"modules": rows}), encoding="utf-8")

ENV.update(development=True, calls=0)
READS["count"] = 0
cat = ns["online_catalog"]()
offered = sorted((r["id"], r["version"]) for m in cat["modules"] for r in m["releases"] if not r.get("download_unavailable"))
must(len(offered) == 9 and offered == sorted(HAR), offered)
must(cat["unavailable"] == [], cat["unavailable"])
must({m["id"] for m in cat["modules"]} == {"wapm", "licensing", "backups", "serverhealth", "welcome"}, cat["modules"])
for m in cat["modules"]:
    must(m["category"] is None and m["category_warning"] == WARNING, m)
must({m["id"]: m["latest_version"] for m in cat["modules"]}["wapm"] == "0.4.32", "highest version selected")
must(READS["count"] == 1 and ENV["calls"] == 1, ("the cache and the development test are read once per request", READS, ENV))
print("       HAR shape on a development server: all nine rows offered with the warning; cache and dev test read once")

ENV.update(development=False, calls=0)
READS["count"] = 0
cat = ns["online_catalog"]()
must(cat["modules"] == [] and len(cat["unavailable"]) == 9, cat)
must(all(r["availability_state"] == "unclassified" and r["category"] is None and r["reason"] == lcs.ROW_TEXT["unclassified"]
         for r in cat["unavailable"]), cat["unavailable"])
must(READS["count"] == 1 and ENV["calls"] == 1, ("read once", READS, ENV))
print("       production server: all nine refused as unclassified")

# testing channel on a development server is refused; a categorised row is unchanged; unavailable[].category is normalised
mixed = [
    {"id": "tst", "version": "1.0.0", "channel": "testing", "category": None, "entitled": True, "availability": "available"},
    {"id": "cat", "version": "1.0.0", "channel": "production", "category": "server", "entitled": True, "availability": "available"},
    {"id": "old", "version": "1.0.0", "channel": "production", "category": "Premium", "entitled": False, "availability": "available"},
]
(CACHE / "tec-tac-licensing.json").write_text(json.dumps({"modules": mixed}), encoding="utf-8")
for dev in (True, False):
    ENV["development"] = dev
    cat = ns["online_catalog"]()
    must([m["id"] for m in cat["modules"]] == ["cat"] and cat["modules"][0]["category"] == "server", (dev, cat["modules"]))
    must(cat["modules"][0]["category_warning"] is None, cat["modules"][0])
    un = {r["id"]: r for r in cat["unavailable"]}
    must(un["tst"]["availability_state"] == "unclassified" and un["old"]["category"] == "premium", un)
print("       testing channel refused on a development server; a categorised row unchanged; unavailable[].category normalised")

# staging: no version names the newest release's reason; an unclassified development release stages on a development server only
stage_rows = [
    {"id": "wapm", "version": "0.4.30", "channel": "development", "category": "premium", "entitled": True, "availability": "missing"},
    {"id": "wapm", "version": "0.4.32", "channel": "testing", "category": None, "entitled": True, "availability": "available"},
    {"id": "wapm", "version": "0.4.31", "channel": "development", "category": "premium", "entitled": True, "availability": "channel_x"},
]
(CACHE / "tec-tac-licensing.json").write_text(json.dumps({"modules": stage_rows}), encoding="utf-8")
ENV["development"] = True
try:
    ns["stage_repository_package"]("tec-tac-licensing", "wapm")
    raise AssertionError("staged a release that is not offered")
except ModuleRepositoryError as exc:
    must(str(exc) == lcs.ROW_TEXT["unclassified"], str(exc))
(CACHE / "tec-tac-licensing.json").write_text(json.dumps({"modules": rows}), encoding="utf-8")
ENV["development"] = False
try:
    ns["stage_repository_package"]("tec-tac-licensing", "welcome")
    raise AssertionError("staged an unclassified release on a production server")
except ModuleRepositoryError as exc:
    must(str(exc) == lcs.ROW_TEXT["unclassified"], str(exc))
must(STAGED == [], STAGED)
ENV["development"] = True
must(ns["stage_repository_package"]("tec-tac-licensing", "wapm") == {"staged": "0.4.32"}, STAGED)
print("       staging: the newest release's reason with no version; unclassified stages on a development server only")

# ---------------------------------------------------------------------------------------------- 3. the install uses the signed manifest
stage_fn = next(n for n in REPO_TREE.body if isinstance(n, ast.FunctionDef) and n.name == "_stage_licensing_release")
must("category" not in ast.get_source_segment(SRC, stage_fn), "the licensed install never reads the Licensing Server's category")
must("from .module_category import is_development_server" in SRC, "Core's own development-server test is used")
CAT_SRC = (APP / "module_category.py").read_text(encoding="utf-8")
must("def is_development_server()" in CAT_SRC and "def refused(" in CAT_SRC, "the install-time test")
print("       install: the signed manifest's category (AD-21 at install); the dev test is module_category.is_development_server")


# ---------------------------------------------------------------------------------------------- 4. docs, contract, version, line endings
def read(path):
    return Path(path).read_text(encoding="utf-8")


DOC = read(ROOT / "docs" / "module-repositories.md")
TS = read(ROOT / "docs" / "troubleshooting-diagnostics.md")
for text, label in ((DOC, "module-repositories.md"), (TS, "troubleshooting")):
    must(lcs.ROW_TEXT["unclassified"] in text and WARNING in text and "1.17.109" in text, label)
CONTRACTS = read(APP / "contracts.py")
must("Added 1.17.109 (AD-21, additive)" in CONTRACTS and "category_warning" in CONTRACTS, "contract")
NOTES = read(ROOT / "RELEASE_NOTES_1.17.109.md")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "FAIL"):
    must(heading in NOTES, heading)
must(read(ROOT / "VERSION").strip() == "1.17.109" and json.loads(read(ROOT / "tec_tac_package.json"))["version"] == "1.17.109", "version")
for path in (REPO_PATH, APP / "contracts.py", ROOT / "docs" / "module-repositories.md", ROOT / "docs" / "troubleshooting-diagnostics.md"):
    data = path.read_bytes()
    must(b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b""), f"{path.name} lost its CRLF")
must(b"\r" not in (APP / "licensing_catalogue_source.py").read_bytes(), "licensing_catalogue_source.py must stay LF")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh has CR")
print("       docs, troubleshooting, contract, notes, version, line endings")
print("[TEST] PASS licensing unclassified as test 1.17.109")
