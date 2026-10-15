#!/usr/bin/env python3
"""1.17.39: module repository hardening, Core side only (the licensing server assessment of 14 October 2026).

Covered: each index entry is checked on its own; a bad entry is skipped and recorded as {index, id, version, reason}; a dotted id is
skipped with a reason that lists the allowed characters; a non-object entry is skipped with id null; duplicate id and version are both
skipped with reason 'duplicate'; the 100-record cap keeps a true skipped_count; an index where no entry is valid fails and keeps the old
cache; an empty modules array is ok; not schema 1, modules not an array and an address refused by the SSRF guard still fail the whole
index; the five informational release fields are passed through, a bad one becomes null and never drops the entry, and none of them
changes which release online_catalog selects; an old cache row without the fields reads as null; repository_status carries
skipped_count; the non-manager scrub replaces the reason and keeps id, version and index; and a source scan shows that no licensing,
entitlement, revocation or downgrade check was added to sync, listing or stage.

module_repository.py and module_repository_views.py import Django, the Tactical framework and Linux-only modules, so they cannot run
here. The real functions are read with ast and run with stubs for the network, the file system and the module manager (the method of
tests/module-repository-bundle-stage.sh). The views module is read the same way for the redaction function only.
"""
from __future__ import annotations

import ast
import json
import re
import tempfile
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_PATH = ROOT / "framwork/tec_tac/module_repository.py"
VIEWS_PATH = ROOT / "framwork/tec_tac/module_repository_views.py"
REPO_TEXT = REPO_PATH.read_text(encoding="utf-8")
VIEWS_TEXT = VIEWS_PATH.read_text(encoding="utf-8")
REPO_TREE = ast.parse(REPO_TEXT)
VIEWS_TREE = ast.parse(VIEWS_TEXT)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def extract(tree, names):
    picked = []
    for node in tree.body:
        is_def = isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
        is_assign = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
        if is_def or is_assign:
            picked.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in picked}
    missing = set(names) - found
    must(not missing, f"not found in source: {sorted(missing)}")
    return picked


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    # A stub with the same answers for the forms this test uses: plain versions, '*' and '>X.Y.Z'.
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise ModuleStateError(f"Invalid version {version!r}")
    if constraint in ("*", ""):
        return True
    if constraint.startswith(">="):
        return tuple(map(int, version.split("."))) >= tuple(map(int, constraint[2:].split(".")))
    if constraint.startswith(">"):
        return tuple(map(int, version.split("."))) > tuple(map(int, constraint[1:].split(".")))
    return True


# Stubs for the parts that touch the network, the disk and the module manager. Names the stubs define are never extracted.
REPO_CONFIG = {"id": "techflow", "name": "Tech Flow", "url": "https://repo.test/index.json", "trust": "official",
               "priority": 10, "enabled": True, "auth_token": "never-shown"}
BODY = [b""]
CACHE_DIR = Path(tempfile.mkdtemp(prefix="repo-skipped-")) / "cache"

ns: dict = {"json": json, "re": re, "urllib": urllib, "Path": Path, "CACHE_ROOT": CACHE_DIR, "version_satisfies": version_satisfies,
            "ModuleStateError": ModuleStateError, "Counter": Counter}
names = {
    "MAX_INDEX_BYTES", "MAX_SKIPPED_RECORDS", "MAX_SKIPPED_TEXT", "MAX_SKIPPED_REASON", "MAX_INFORMATIONAL_TEXT",
    "SKIPPED_REASON_FOR_OTHERS", "_CONTROL_CHARACTERS", "ModuleRepositoryError", "_RemoteAddressRefused", "_validate_release",
    "_informational_text", "_plain_text", "_skipped_record", "_accepted_releases", "_skipped_summary", "sync_repository",
    "repository_status", "_cached_modules", "_candidate_compatibility", "online_catalog", "all_repository_status", "public_repository",
    "_AVAILABILITY_MESSAGES", "_availability",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only


def _utcnow():
    return "2026-10-14T00:00:00+00:00"


def _repo(repository_id):
    must(repository_id == "techflow", repository_id)
    return dict(REPO_CONFIG)


def _fetch(url, maximum, timeout=12, *, trust="custom"):
    return BODY[0]


def _validate_remote_url(value, *, trust="custom"):
    host = urllib.parse.urlparse(value).hostname or ""
    if host == "blocked.test":
        raise ns["_RemoteAddressRefused"]("Repository URL resolves to a prohibited local, link-local, or reserved address.")
    if host == "nodns.test":
        raise ns["ModuleRepositoryError"]("Repository hostname could not be resolved.")
    return value


def _atomic_repo_json(path, payload):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload), encoding="utf-8")


def list_repositories():
    return [ns["public_repository"](dict(REPO_CONFIG))]


def installed_catalog_v2():
    return []


def _check_runtime_requirements(requires):
    return []


for key, value in {
    "_utcnow": _utcnow, "_repo": _repo, "_fetch": _fetch, "_validate_remote_url": _validate_remote_url,
    "_atomic_repo_json": _atomic_repo_json, "list_repositories": list_repositories, "installed_catalog_v2": installed_catalog_v2,
    "_check_runtime_requirements": _check_runtime_requirements,
}.items():
    ns[key] = value

# The views module needs Django and DRF, so only the redaction function and its key list are read.
views_ns: dict = {"SKIPPED_REASON_FOR_OTHERS": ns["SKIPPED_REASON_FOR_OTHERS"]}
views_code = compile(ast.Module(body=extract(VIEWS_TREE, {"_SENSITIVE_REPOSITORY_KEYS", "_redact_repository_status_for_non_manager"}),
                                 type_ignores=[]), str(VIEWS_PATH), "exec")
exec(views_code, views_ns)  # noqa: S102 - test only
scrub = views_ns["_redact_repository_status_for_non_manager"]

SHA = "ab" * 32
GOOD_REASON_OBJECT = "Repository modules entries must be objects."


def release(module_id="checks", version="0.4.0", **extra):
    entry = {"id": module_id, "version": version, "download": f"packages/{module_id}-{version}.zip", "sha256": SHA}
    entry.update(extra)
    return entry


def index_body(modules, schema=1):
    return json.dumps({"schema": schema, "modules": modules}).encode("utf-8")


def sync(modules=None, raw=None):
    BODY[0] = raw if raw is not None else index_body(modules)
    return ns["sync_repository"]("techflow")


def cache_payload():
    return json.loads((CACHE_DIR / "techflow.json").read_text(encoding="utf-8"))


def expect_error(fn, needle):
    try:
        fn()
    except ns["ModuleRepositoryError"] as exc:
        must(needle in str(exc), f"error {str(exc)!r} lacks {needle!r}")
        return exc
    raise AssertionError(f"expected ModuleRepositoryError containing {needle!r}")


# ---------------------------------------------------------------------------- a mixed index: one bad digest, one dotted id, one good
result = sync([release("checks", sha256="xyz"), release("bad.id"), release("alerts")])
sync_part = result["sync"]
must(sync_part["status"] == "ok" and sync_part["module_count"] == 1, sync_part)
must(sync_part["skipped_count"] == 2, sync_part)
first, second = sync_part["skipped"]
must(set(first) == {"index", "id", "version", "reason"}, first)
must(first["index"] == 0 and first["id"] == "checks" and first["version"] == "0.4.0", first)
must("SHA-256" in first["reason"], first)
must(second["index"] == 1 and second["id"] == "bad.id" and second["version"] == "0.4.0", second)
must("letters, digits, '-' and '_'" in second["reason"] and "dot is not allowed" in second["reason"], second)
cached = cache_payload()
must([m["id"] for m in cached["modules"]] == ["alerts"], cached["modules"])
must(cached["skipped_count"] == 2 and len(cached["skipped"]) == 2 and cached["status"] == "ok", cached)
status = ns["repository_status"]("techflow")["sync"]
must(status["skipped_count"] == 2 and len(status["skipped"]) == 2 and status["module_count"] == 1, status)
print("       mixed index: ok, module_count 1, skipped_count 2, records right")

# ---------------------------------------------------------------------------- a non-object entry
result = sync(["junk", release("checks")])
must(result["sync"]["module_count"] == 1, result["sync"])
must(result["sync"]["skipped"] == [{"index": 0, "id": None, "version": None, "reason": GOOD_REASON_OBJECT}], result["sync"]["skipped"])
print("       non-object entry: skipped with id null")

# ---------------------------------------------------------------------------- id and version are cut and cleaned
long_bad = "a" * 150 + "."
result = sync([release(long_bad, version="0.4.0"), release("bad\x07id.", version="1.0.0\x01"), release("checks")])
must(result["sync"]["module_count"] == 1, result["sync"])
records = result["sync"]["skipped"]
must(records[0]["id"] == "a" * 100 and len(records[0]["id"]) == 100, records[0])
must(records[1]["id"] == "badid." and records[1]["version"] == "1.0.0", records[1])
must(all("\x00" not in r["reason"] and "\x07" not in r["reason"] for r in records), records)
print("       id and version: cut to 100, control characters removed")

# ---------------------------------------------------------------------------- duplicates: both copies skipped
result = sync([release("checks"), release("checks"), release("alerts")])
must(result["sync"]["module_count"] == 1, result["sync"])
must([(r["index"], r["reason"]) for r in result["sync"]["skipped"]] == [(0, "duplicate"), (1, "duplicate")], result["sync"]["skipped"])
must([m["id"] for m in cache_payload()["modules"]] == ["alerts"], "a duplicate is never kept")
print("       duplicates: both copies skipped with reason duplicate")

# ---------------------------------------------------------------------------- the cap: 100 records, the real total
result = sync([release("bad", sha256="x") for _ in range(150)] + [release("checks")])
must(result["sync"]["module_count"] == 1, result["sync"])
must(result["sync"]["skipped_count"] == 150, result["sync"]["skipped_count"])
must(len(result["sync"]["skipped"]) == 100 and [r["index"] for r in result["sync"]["skipped"]] == list(range(100)), "cap")
cached = cache_payload()
must(cached["skipped_count"] == 150 and len(cached["skipped"]) == 100, "cache keeps the cap and the real total")
print("       cap: 100 records, skipped_count 150")

# ---------------------------------------------------------------------------- all invalid: fails, the old cache stays
sync([release("alerts")])
before = cache_payload()
expect_error(lambda: sync([release("bad", sha256="x"), "junk"]), "Every one of the 2 entries in the repository index was invalid")
after = cache_payload()
must(after["status"] == "error" and [m["id"] for m in after["modules"]] == ["alerts"], after)
must(after["modules"] == before["modules"], "the previous catalog is kept")
shown = ns["repository_status"]("techflow")["sync"]
must(shown["status"] == "error" and shown["module_count"] == 1, shown)
# duplicates only: every entry is skipped, so this is also all invalid
expect_error(lambda: sync([release("checks"), release("checks")]), "was invalid")
print("       all invalid: fails, keeps the old cache")

# ---------------------------------------------------------------------------- an empty array is ok
result = sync([])
must(result["sync"]["status"] == "ok" and result["sync"]["module_count"] == 0 and result["sync"]["skipped_count"] == 0, result["sync"])
print("       empty modules array: ok with module_count 0")

# ---------------------------------------------------------------------------- whole-index failures still fail
sync([release("alerts")])
expect_error(lambda: sync(raw=index_body([release("checks")], schema=2)), "schema 1")
cache_after_schema = cache_payload()
must(cache_after_schema["status"] == "error" and [m["id"] for m in cache_after_schema["modules"]] == ["alerts"], "schema failure keeps cache")
sync([release("alerts")])
expect_error(lambda: sync(raw=json.dumps({"schema": 1, "modules": {"id": "checks"}}).encode()), "must be an array")
expect_error(lambda: sync([release("checks"), release("ssrf", download="http://blocked.test/ssrf.zip")]), "prohibited local")
must(cache_payload()["status"] == "error", "an address refused by the guard fails the whole index")
print("       not schema 1, modules not an array, address guard: whole-index failures, cache kept")

# ---------------------------------------------------------------------------- a host that does not resolve is a skipped entry
result = sync([release("checks", download="http://nodns.test/checks.zip"), release("alerts")])
must(result["sync"]["module_count"] == 1 and result["sync"]["skipped"][0]["index"] == 0, result["sync"])
must("could not be resolved" in result["sync"]["skipped"][0]["reason"], result["sync"]["skipped"])
print("       unresolved download host: skipped entry, the rest kept")

# ---------------------------------------------------------------------------- informational fields: passed through, bad values null, entry kept
result = sync([
    release("checks", channel="  beta\x00\x07 ", lifecycle="x" * 100, downgrade_policy=5, signing_environment="", recommended="yes"),
    release("alerts", recommended=True, channel=None),
])
must(result["sync"]["status"] == "ok" and result["sync"]["module_count"] == 2 and result["sync"]["skipped_count"] == 0, result["sync"])
by_id = {m["id"]: m for m in cache_payload()["modules"]}
checks = by_id["checks"]
must(checks["channel"] == "beta", checks["channel"])
must(checks["lifecycle"] == "x" * 64, len(checks["lifecycle"]))
must(checks["downgrade_policy"] is None and checks["signing_environment"] is None and checks["recommended"] is None, checks)
must(by_id["alerts"]["recommended"] is True and by_id["alerts"]["channel"] is None, by_id["alerts"])
print("       informational fields: cleaned, capped, bad values null, entry kept")

# ---------------------------------------------------------------------------- selection is the same with and without the fields
with_fields = [release("checks", "0.4.0", recommended=True, channel="beta"), release("checks", "0.5.0", channel="stable", recommended=False)]
without_fields = [release("checks", "0.4.0"), release("checks", "0.5.0")]
sync(with_fields)
catalog_with = ns["online_catalog"]()["modules"]
sync(without_fields)
catalog_without = ns["online_catalog"]()["modules"]
pick_with = {k: catalog_with[0][k] for k in ("latest_version", "selected_repository_id", "update_available")}
pick_without = {k: catalog_without[0][k] for k in ("latest_version", "selected_repository_id", "update_available")}
must(pick_with == pick_without and pick_with["latest_version"] == "0.5.0", (pick_with, pick_without))
must(catalog_with[0]["channel"] == "stable" and catalog_with[0]["recommended"] is False, catalog_with[0])
must(catalog_without[0]["channel"] is None and catalog_without[0]["recommended"] is None, catalog_without[0])
print("       selection unchanged by the informational fields; the item shows the selected release's values")

# ---------------------------------------------------------------------------- an old cache row (written before 1.17.39) reads as null
CACHE_DIR.mkdir(parents=True, exist_ok=True)
(CACHE_DIR / "techflow.json").write_text(json.dumps({
    "schema": 1, "repository_id": "techflow", "status": "ok", "error": None, "synced_at": "2026-10-01T00:00:00+00:00",
    "modules": [{"id": "checks", "name": "Checks", "version": "0.4.0", "download_url": "https://repo.test/checks.zip", "sha256": SHA,
                 "dependencies": {}, "optional_dependencies": {}, "requires": {}}],
}), encoding="utf-8")
old = ns["online_catalog"]()["modules"][0]
must(old["channel"] is None and old["lifecycle"] is None and old["recommended"] is None and old["downgrade_policy"] is None
     and old["signing_environment"] is None, old)
old_status = ns["repository_status"]("techflow")["sync"]
must(old_status["skipped_count"] == 0 and old_status["skipped"] == [], old_status)
print("       old cache row without the fields: null, no skipped records")

# ---------------------------------------------------------------------------- the non-manager scrub
status_row = {
    "repositories": [{
        "id": "techflow", "url": "https://repo.test/index.json",
        "sync": {"status": "ok", "error": None, "module_count": 1, "skipped_count": 2, "skipped": [
            {"index": 0, "id": "bad", "version": "0.4.0", "reason": "The download https://10.0.0.5/x.zip is private."},
            {"index": 3, "id": None, "version": None, "reason": "Repository modules entries must be objects."},
        ]},
    }],
}
clean = scrub(status_row)
row = clean["repositories"][0]
must("url" not in row, row)
sync_clean = row["sync"]
must(sync_clean["skipped_count"] == 2, sync_clean)
must(sync_clean["skipped"][0] == {"index": 0, "id": "bad", "version": "0.4.0", "reason": ns["SKIPPED_REASON_FOR_OTHERS"]}, sync_clean)
must(sync_clean["skipped"][1] == {"index": 3, "id": None, "version": None, "reason": ns["SKIPPED_REASON_FOR_OTHERS"]}, sync_clean)
must("10.0.0.5" not in json.dumps(clean), "no host from a reason reaches a non-manager")
must(status_row["repositories"][0]["sync"]["skipped"][0]["reason"].startswith("The download"), "the original is not changed")
print("       non-manager scrub: reason generic, id, version and index kept")

# ---------------------------------------------------------------------------- source scan: no licensing, entitlement, revocation or downgrade check
text = REPO_TEXT + "\n" + VIEWS_TEXT
lowered = text.lower()
for banned in ("entitle", "revok", "get_capability", "licensing capability", "core.licensing", "tec_tac_licensing", "capabilities import"):
    must(banned not in lowered, f"module repository code must not contain {banned!r}")
licence_words = re.findall(r"licen[sc]\w*", text, flags=re.IGNORECASE)
must(set(licence_words) <= {"LicensingRequirementError"}, f"licence words other than the existing install-time error: {set(licence_words)}")
must(all(word == "downgrade_policy" for word in re.findall(r"downgrad\w*", text, flags=re.IGNORECASE)),
     "downgrade appears only as the informational field downgrade_policy")
print("       source scan: no licensing, entitlement, revocation or downgrade check")

print("[TEST] PASS module repository skipped entries and informational fields 1.17.39")
