#!/usr/bin/env python3
"""1.17.42 (CQ121): the official module repository is seeded once, disabled, and never rebuilt by code.

Covered: the first seed call writes exactly one record (id tec-tac-official, trust official, enabled false) and the marker
defaults_seeded; a second call changes nothing; delete_repository followed by a seed call leaves it gone; an administrator's edit
(enabled true, a new name) survives a later seed call; an existing repository with the same URL gets only the marker; an unwritable
or unreadable configuration logs a warning and does not raise; a default that fails URL validation is not written; the tick command
calls the step inside try/except; the seeded record passes the same URL validation as a manual add.

module_repository.py imports Django, so the real functions are read with ast and run with stubs (the method of
tests/online-catalog-availability-1.17.41.py). Nothing touches the network or the real configuration.
"""
from __future__ import annotations

import ast
import copy
import json
import logging
import re
import tempfile
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_PATH = ROOT / "framwork/tec_tac/module_repository.py"
TICK_PATH = ROOT / "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py"
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))


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


class TestLog:
    def __init__(self):
        self.records = []

    def warning(self, message, *args, **kwargs):
        self.records.append((message, args))


WORK = Path(tempfile.mkdtemp(prefix="default-repo-")) / "module-manager" / "repositories"
ns: dict = {
    "json": json, "re": re, "urllib": urllib, "uuid": uuid, "logging": logging, "datetime": datetime, "timezone": timezone,
    "Path": Path, "Counter": __import__("collections").Counter,
}
ns["REPOSITORY_ROOT"] = WORK
ns["CONFIG_FILE"] = WORK / "repositories.json"
ns["CACHE_ROOT"] = WORK / "cache"
ns["REPO_ID_RE"] = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
ns["TRUST_LEVELS"] = {"official", "internal", "custom"}


def atomic_json(path, payload, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")


ns["atomic_json"] = atomic_json
names = {
    "logger", "DEFAULT_REPOSITORIES", "DEFAULTS_SEEDED_KEY", "ModuleRepositoryError", "_utcnow", "_default_config",
    "_atomic_repo_json", "load_repositories", "_validated_port", "_clean_url", "_clean_repo_id", "public_repository",
    "list_repositories", "upsert_repository", "delete_repository", "seed_default_repositories",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names) + [
    n for n in REPO_TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TRUST_LEVELS" for t in n.targets)
], type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only

# the remote check: the real _clean_url runs, and a host that is local is refused the way the real guard refuses it
ns["_validate_remote_url"] = lambda value, trust="custom": _checked(value)


def _checked(value):
    url = ns["_clean_url"](value)
    if urllib.parse.urlparse(url).hostname in ("localhost", "127.0.0.1"):
        raise ns["ModuleRepositoryError"]("Repository URL resolves to a prohibited local address.")
    return url


log = TestLog()
ns["logger"] = log
seed = ns["seed_default_repositories"]
upsert = ns["upsert_repository"]
delete = ns["delete_repository"]
DEFAULT = ns["DEFAULT_REPOSITORIES"][0]
MARK = ns["DEFAULTS_SEEDED_KEY"]


def reset():
    if WORK.exists():
        for item in sorted(WORK.rglob("*"), reverse=True):
            item.unlink() if item.is_file() else item.rmdir()
    log.records.clear()


def stored():
    return json.loads(ns["CONFIG_FILE"].read_text(encoding="utf-8")) if ns["CONFIG_FILE"].is_file() else None


# (1) first call: exactly one record, official, disabled, marker written
reset()
seeded = seed()
must(seeded == ["tec-tac-official"], seeded)
config = stored()
must(len(config["repositories"]) == 1, config)
record = config["repositories"][0]
must(record["id"] == "tec-tac-official" and record["trust"] == "official" and record["enabled"] is False, record)
must(record["priority"] == 100 and record["name"] == "Tec-Tac official modules (Tech Flow Dynamics)", record)
must(record["url"] == "https://lic-service.tec-tac.techxflow.net.za/modules/index.json", record["url"])
must(config[MARK] == ["tec-tac-official"], config.get(MARK))
must(record["created_at"] and record["updated_at"], "timestamps are written as upsert writes them")
must(config["schema"] == 1, config)
print("       first call: one disabled official record, marker written")

# (2) second call: nothing changes, the file is byte-identical
before = ns["CONFIG_FILE"].read_bytes()
must(seed() == [], "the second call seeds nothing")
must(ns["CONFIG_FILE"].read_bytes() == before, "the file is untouched")
print("       second call: no change, file byte-identical")

# (3) an administrator removes it: a later seed call does not put it back
reset()
seed()
delete("tec-tac-official")
must(stored()["repositories"] == [], stored())
must(seed() == [], "a removed default is not seeded again")
must(stored()["repositories"] == [] and stored()[MARK] == ["tec-tac-official"], stored())
print("       removed by an administrator: stays removed, marker kept")

# (4) an administrator's edit survives a later seed call
reset()
seed()
edited = upsert({"name": "Our copy of the official feed", "enabled": True}, repository_id="tec-tac-official")
must(edited["enabled"] is True and edited["name"] == "Our copy of the official feed", edited)
must(seed() == [], "the edited entry is left alone")
after = stored()["repositories"]
must(len(after) == 1 and after[0]["enabled"] is True and after[0]["name"] == "Our copy of the official feed", after)
print("       administrator edit (enabled, new name): survives a later seed")

# (5) a disabled entry stays disabled and is not touched
reset()
seed()
upsert({"enabled": False}, repository_id="tec-tac-official")
must(seed() == [] and stored()["repositories"][0]["enabled"] is False, stored())
print("       disabled entry: not touched")

# (6) an existing repository with the same URL gets only the marker
reset()
ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
existing_url = DEFAULT["url"]
ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": [{
    "id": "our-feed", "name": "Our feed", "url": existing_url, "enabled": True, "priority": 50, "trust": "custom",
    "created_at": "2026-10-01T00:00:00+00:00", "updated_at": "2026-10-01T00:00:00+00:00",
}]}), encoding="utf-8")
must(seed() == [], "no second record for the same URL")
config = stored()
must([item["id"] for item in config["repositories"]] == ["our-feed"], config["repositories"])
must(config[MARK] == ["tec-tac-official"], config.get(MARK))
print("       same URL already present: only the marker is written")

# (7) an existing repository with the same id but another URL is left alone (no overwrite)
reset()
ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": [{
    "id": "tec-tac-official", "name": "Ours", "url": "https://feed.example.test/index.json", "enabled": True, "priority": 10,
    "trust": "custom", "created_at": "2026-10-01T00:00:00+00:00", "updated_at": "2026-10-01T00:00:00+00:00",
}]}), encoding="utf-8")
must(seed() == [], "an id that is already taken is not overwritten")
must(stored()["repositories"][0]["url"] == "https://feed.example.test/index.json", stored())
print("       same id already present: not overwritten")

# (8) an unwritable configuration logs a warning and does not raise
reset()
blocker = WORK.parent / "blocker"
blocker.parent.mkdir(parents=True, exist_ok=True)
blocker.write_text("a file, not a folder", encoding="utf-8")
ns["CONFIG_FILE"] = blocker / "repositories.json"
result = None
try:
    result = seed()
except Exception as exc:  # pragma: no cover - the failure this test guards against
    raise AssertionError(f"the seed raised: {exc!r}")
must(result == [], result)
must(log.records and "next tick" in log.records[0][0], log.records)
ns["CONFIG_FILE"] = WORK / "repositories.json"
print("       unwritable configuration: warning logged, nothing raised")

# (9) an unreadable configuration (broken JSON) logs and does not raise
reset()
ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
ns["CONFIG_FILE"].write_text("{not json", encoding="utf-8")
must(seed() == [] and log.records, "a broken file logs and seeds nothing")
must(ns["CONFIG_FILE"].read_text(encoding="utf-8") == "{not json", "a broken file is not overwritten")
print("       unreadable configuration: warning logged, file left as it was")

# (10) a default that fails the same URL validation as a manual add is not written, and no marker is set
reset()
saved_default = copy.deepcopy(DEFAULT)
ns["DEFAULT_REPOSITORIES"] = ({**saved_default, "url": "https://user:secret@lic-service.example.test/index.json"},)
must(seed() == [], "a credential URL is refused")
must(stored() is None or (stored()["repositories"] == [] and MARK not in stored()), stored())
must(log.records, "the refusal is logged")
ns["DEFAULT_REPOSITORIES"] = ({**saved_default, "url": "http://localhost/index.json"},)
must(seed() == [] and (stored() is None or MARK not in stored()), "a local address is refused and not marked")
ns["DEFAULT_REPOSITORIES"] = (saved_default,)
print("       default that fails URL validation: not written, no marker")

# (11) the seeded record passes the same validation as a manual add: the same stored URL
reset()
seed()
manual = upsert({"id": "manual-check", "name": "Manual check", "url": DEFAULT["url"], "trust": "official", "enabled": False})
must(manual["url"] == stored()["repositories"][0]["url"], (manual["url"], stored()["repositories"][0]["url"]))
print("       seeded URL matches what a manual add stores")

# (12) the tick command calls the step inside try/except
tick = ast.parse(TICK_PATH.read_text(encoding="utf-8"))
guarded = False
for node in ast.walk(tick):
    if isinstance(node, ast.Try):
        called = {n.func.id for stmt in node.body for n in ast.walk(stmt) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        if {"seed_default_repositories", "ensure_repository_sync_schedule"} <= called and node.handlers:
            guarded = True
must(guarded, "the tick calls the seed and the schedule inside try/except")
tick_text = TICK_PATH.read_text(encoding="utf-8")
must("repository_defaults_seeded={repo_seeded}" in tick_text, "the tick output appends the seed count")
print("       tick command: the step is guarded and its count is appended to the output")

print("[TEST] PASS default repository 1.17.42")
