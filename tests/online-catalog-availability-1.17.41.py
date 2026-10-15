#!/usr/bin/env python3
"""1.17.41: the Online catalog reads the repositories and says what is available (Johan, dev-server test, 15 October 2026).

Covered: no repository gives modules [] and state no_repository, with installed modules only in installed_only; an enabled repository
that never synced gives not_synced; a synced repository offering A and B with A installed gives modules [A, B] and installed_only holds
only installed modules no repository offers; update_available is true when a higher version is cached; a failed sync that kept a cache
still offers its modules; an all-error repository without a cache gives sync_failed; an empty index gives empty; a disabled repository
is ignored; count is len(modules); the non-manager scrub keeps the new keys, hides every URL and keeps the skipped reasons generic.

module_repository.py imports Django, so the real functions are read with ast and run with stubs (the method of
tests/module-repository-skipped-1.17.39.py).
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
REPO_TREE = ast.parse(REPO_TEXT)
VIEWS_TREE = ast.parse(VIEWS_PATH.read_text(encoding="utf-8"))


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
    must(not (set(names) - found), f"not found in source: {sorted(set(names) - found)}")
    return picked


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    if constraint in ("*", ""):
        return True
    if constraint.startswith(">"):
        return tuple(map(int, version.split("."))) > tuple(map(int, constraint[1:].split(".")))
    return True


CACHE_DIR = Path(tempfile.mkdtemp(prefix="catalog-availability-")) / "cache"
CACHE_DIR.mkdir(parents=True)
REPOS: list[dict] = []
INSTALLED: list[dict] = []

ns: dict = {"json": json, "re": re, "urllib": urllib, "Path": Path, "CACHE_ROOT": CACHE_DIR, "version_satisfies": version_satisfies,
            "ModuleStateError": ModuleStateError, "Counter": Counter}
names = {
    "MAX_INDEX_BYTES", "MAX_SKIPPED_RECORDS", "MAX_SKIPPED_TEXT", "MAX_SKIPPED_REASON", "MAX_INFORMATIONAL_TEXT",
    "SKIPPED_REASON_FOR_OTHERS", "_CONTROL_CHARACTERS", "ModuleRepositoryError", "_skipped_summary", "repository_status",
    "_cached_modules", "_candidate_compatibility", "online_catalog", "all_repository_status", "public_repository",
    "_AVAILABILITY_MESSAGES", "_availability",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only
ns["list_repositories"] = lambda: [ns["public_repository"](dict(r)) for r in REPOS]
ns["_repo"] = lambda rid: next(dict(r) for r in REPOS if r["id"] == rid)
ns["installed_catalog_v2"] = lambda: [dict(i) for i in INSTALLED]
ns["_check_runtime_requirements"] = lambda requires: []

views_ns: dict = {"SKIPPED_REASON_FOR_OTHERS": ns["SKIPPED_REASON_FOR_OTHERS"]}
views_body = extract(VIEWS_TREE, {"_SENSITIVE_REPOSITORY_KEYS", "_redact_repository_status_for_non_manager"})
exec(compile(ast.Module(body=views_body, type_ignores=[]), str(VIEWS_PATH), "exec"), views_ns)  # noqa: S102 - test only
scrub = views_ns["_redact_repository_status_for_non_manager"]

SHA = "ab" * 32


def repo(rid="techflow", enabled=True, priority=10):
    return {"id": rid, "name": rid.title(), "url": f"https://{rid}.test/index.json", "trust": "official", "priority": priority,
            "enabled": enabled}


def installed(module_id, version="0.1.0", source=None):
    return {"id": module_id, "name": module_id.title(), "extension_version": version, "source": source or {}}


def write_cache(rid, modules=None, status="ok", synced_at="2026-10-15T00:00:00+00:00", error=None, skipped=None):
    payload = {"schema": 1, "repository_id": rid, "status": status, "error": error, "modules": modules or [],
               "skipped": skipped or [], "skipped_count": len(skipped or [])}
    if synced_at:
        payload["synced_at"] = synced_at
    (CACHE_DIR / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")


def entry(module_id, version="0.4.0"):
    return {"id": module_id, "name": module_id.title(), "version": version, "download_url": f"https://x.test/{module_id}.zip",
            "sha256": SHA, "dependencies": {}, "optional_dependencies": {}, "requires": {}}


def reset(repos, installs):
    for item in CACHE_DIR.glob("*.json"):
        item.unlink()
    REPOS[:] = repos
    INSTALLED[:] = installs


# 1. no repository
reset([], [installed("agents"), installed("checks")])
cat = ns["online_catalog"]()
must(cat["modules"] == [] and cat["count"] == 0, cat["modules"])
must(cat["availability"]["state"] == "no_repository" and cat["availability"]["enabled_repositories"] == 0, cat["availability"])
must([i["id"] for i in cat["installed_only"]] == ["agents", "checks"] and cat["availability"]["installed_only_count"] == 2, cat["installed_only"])
must(cat["installed_only"][0] == {"id": "agents", "name": "Agents", "installed_version": "0.1.0", "installed_source": None}, cat["installed_only"][0])
must("Add one under Repositories" in cat["availability"]["message"], cat["availability"])
print("       no repository: modules [], no_repository, installed modules only in installed_only")

# 2. enabled, never synced
reset([repo()], [installed("agents")])
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "not_synced" and cat["availability"]["synced_repositories"] == 0 and cat["modules"] == [], cat["availability"])
print("       never synced: not_synced")

# 3. synced, A and B offered, A installed, gamma installed but offered nowhere
reset([repo()], [installed("alpha", "0.4.0"), installed("gamma")])
write_cache("techflow", [entry("alpha"), entry("beta")])
cat = ns["online_catalog"]()
by_id = {m["id"]: m for m in cat["modules"]}
must(list(by_id) == ["alpha", "beta"] and cat["count"] == 2, list(by_id))
must(by_id["alpha"]["installed"] is True and by_id["beta"]["installed"] is False, by_id)
must([i["id"] for i in cat["installed_only"]] == ["gamma"], cat["installed_only"])
must(cat["availability"]["state"] == "ready" and cat["availability"]["synced_repositories"] == 1 and cat["availability"]["message"] == "", cat["availability"])
must(by_id["alpha"]["update_available"] is False, by_id["alpha"])
print("       synced: modules [alpha, beta]; installed_only holds only gamma")

# 4. update available
reset([repo()], [installed("alpha", "0.3.0")])
write_cache("techflow", [entry("alpha", "0.4.0")])
cat = ns["online_catalog"]()
must(cat["modules"][0]["update_available"] is True and cat["modules"][0]["latest_version"] == "0.4.0", cat["modules"][0])
print("       higher cached version: update_available")

# 5. failed sync that kept the cache
reset([repo()], [])
write_cache("techflow", [entry("alpha")], status="error", error="boom")
cat = ns["online_catalog"]()
must([m["id"] for m in cat["modules"]] == ["alpha"] and cat["availability"]["state"] == "ready", cat["availability"])
print("       failed sync with a kept cache: modules still offered")

# 6. every repository failed, no cache of modules
reset([repo()], [installed("alpha")])
write_cache("techflow", status="error", synced_at=None, error="boom")
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "sync_failed" and cat["modules"] == [], cat["availability"])
must([i["id"] for i in cat["installed_only"]] == ["alpha"], cat["installed_only"])
print("       all error, no cache: sync_failed")

# 7. empty index
reset([repo()], [])
write_cache("techflow", [])
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "empty" and cat["availability"]["synced_repositories"] == 1, cat["availability"])
print("       empty synced index: empty")

# 8. disabled repository ignored
reset([repo("off", enabled=False)], [installed("alpha")])
write_cache("off", [entry("alpha")])
cat = ns["online_catalog"]()
must(cat["modules"] == [] and cat["availability"]["state"] == "no_repository", cat["availability"])
reset([repo("off", enabled=False), repo("on")], [])
write_cache("off", [entry("hidden")])
write_cache("on", [entry("shown")])
cat = ns["online_catalog"]()
must([m["id"] for m in cat["modules"]] == ["shown"] and cat["availability"]["enabled_repositories"] == 1, cat)
print("       disabled repository ignored")

# 9. pinned source rule: pinned to a repository that does not offer it
reset([repo("on")], [installed("alpha", source={"repository_id": "gone"}), installed("delta", source={"repository_id": "gone"})])
write_cache("on", [entry("alpha")])
cat = ns["online_catalog"]()
must(cat["modules"][0]["source_conflict"] is True, cat["modules"][0])
must([i["id"] for i in cat["installed_only"]] == ["delta"], cat["installed_only"])
print("       pinned source: source_conflict only when another repository offers it; otherwise installed_only")

# 10. non-manager redaction
reset([repo()], [installed("gamma", source={"repository_id": "techflow", "url": "https://techflow.test/x"})])
write_cache("techflow", [entry("alpha")],
            skipped=[{"index": 0, "id": "bad", "version": "1.0.0", "reason": "The download https://10.0.0.5/x.zip is private."}])
clean = scrub(ns["online_catalog"]())
text = json.dumps(clean)
must("10.0.0.5" not in text and "techflow.test" not in text and "download_url" not in text, text)
must(clean["availability"]["state"] == "ready" and clean["installed_only"][0]["id"] == "gamma" and clean["count"] == 1, clean["availability"])
must(clean["repositories"][0]["sync"]["skipped"][0]["reason"] == ns["SKIPPED_REASON_FOR_OTHERS"], clean["repositories"][0])
print("       non-manager: new keys kept, no URL, skipped reason generic")

# 11. GET never calls a repository
func = next(n for n in REPO_TREE.body if getattr(n, "name", "") == "online_catalog")
body = ast.get_source_segment(REPO_TEXT, func)
must("_fetch" not in body and "sync_repository" not in body, "online_catalog must not reach a repository")
print("       online_catalog makes no outbound call")

print("[TEST] PASS online catalog availability 1.17.41")
