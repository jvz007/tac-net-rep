#!/usr/bin/env python3
"""1.17.43 (CQ125, CQ126): the confirmed official index path, the one-time correction of a 1.17.42 seed address, and the docs.

Covered: a fresh seed writes the confirmed development-channel path, disabled; a 1.17.42 record that still holds the assumed path
/modules/index.json is corrected once (enabled true and false), and keeps its enabled flag, name and priority; an address an
administrator edited is never replaced, whatever the name or priority; another id that holds the old address is left alone; a removed
entry stays removed; a second call changes nothing; the docs and the contract note say the zone is Django's TIME_ZONE (UTC on stock
Tactical) and never 'server time'.

module_repository.py imports Django and the scheduler, so the real functions are read with ast and run with stubs (the method of
tests/default-repository-1.17.42.py). The configuration lock uses a no-op fcntl stub here; its behaviour is pinned by
tests/repository-seed-lock-1.17.43.py. Nothing touches the network or the real configuration.
"""
from __future__ import annotations

import ast
import contextlib
import ipaddress
import json
import logging
import re
import socket
import sys
import tempfile
import time
import types
import urllib.parse
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_PATH = ROOT / "framwork/tec_tac/module_repository.py"
CONTRACTS_PATH = ROOT / "framwork/tec_tac/contracts.py"
DOCS_REPO = ROOT / "docs/module-repositories.md"
DOCS_SCHED = ROOT / "docs/scheduler.md"
REPO_TEXT = REPO_PATH.read_text(encoding="utf-8")
REPO_TREE = ast.parse(REPO_TEXT)

NEW_URL = "https://lic-service.tec-tac.techxflow.net.za/api/v1/repository/channels/development/index.json"
OLD_URL = "https://lic-service.tec-tac.techxflow.net.za/modules/index.json"


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


# a no-op lock: the file operations are what this test checks
_fcntl = types.ModuleType("fcntl")
_fcntl.LOCK_EX, _fcntl.LOCK_NB, _fcntl.LOCK_UN = 2, 4, 8
_fcntl.flock = lambda fd, op: None
sys.modules["fcntl"] = _fcntl

WORK = Path(tempfile.mkdtemp(prefix="seed-1743-")) / "module-manager" / "repositories"


def atomic_json(path, payload, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")


ns: dict = {
    "json": json, "re": re, "urllib": urllib, "uuid": uuid, "logging": logging, "datetime": datetime, "timezone": timezone,
    "Path": Path, "Counter": Counter, "ipaddress": ipaddress, "contextlib": contextlib, "time": time, "socket": socket,
    "atomic_json": atomic_json,
    "REPOSITORY_ROOT": WORK, "CONFIG_FILE": WORK / "repositories.json", "CACHE_ROOT": WORK / "cache",
    "CONFIG_LOCK_WAIT_SECONDS": 0.2, "CONFIG_LOCK_POLL_SECONDS": 0.01,
    "REPO_ID_RE": re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$"), "TRUST_LEVELS": {"official", "internal", "custom"},
}
names = {
    "logger", "DEFAULT_REPOSITORIES", "DEFAULTS_SEEDED_KEY", "SUPERSEDED_DEFAULT_URLS", "CONFIG_LOCK", "_config_lock",
    "ModuleRepositoryError", "_RemoteAddressRefused", "_utcnow", "_default_config", "_atomic_repo_json", "load_repositories",
    "_validated_port", "_clean_url", "_normalize_address", "_always_blocked_address", "_private_address", "_CGNAT",
    "_resolve_remote_url", "_validate_remote_url", "_clean_repo_id", "public_repository", "list_repositories",
    "_find_repository", "_requested_name", "_requested_trust", "_requested_url", "upsert_repository", "delete_repository",
    "_seed_address_check", "_correct_superseded_url", "seed_default_repositories",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only

log = TestLog()
ns["logger"] = log
seed = ns["seed_default_repositories"]
upsert = ns["upsert_repository"]
delete = ns["delete_repository"]
MARK = ns["DEFAULTS_SEEDED_KEY"]
DEFAULT = ns["DEFAULT_REPOSITORIES"][0]
must(DEFAULT["url"] == NEW_URL, DEFAULT["url"])


def reset():
    if WORK.exists():
        for item in sorted(WORK.rglob("*"), reverse=True):
            item.unlink() if item.is_file() else item.rmdir()
    log.records.clear()


def stored():
    return json.loads(ns["CONFIG_FILE"].read_text(encoding="utf-8")) if ns["CONFIG_FILE"].is_file() else None


def write_config(payload):
    ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
    ns["CONFIG_FILE"].write_text(json.dumps(payload), encoding="utf-8")


def record(url, enabled, *, rid="tec-tac-official", name=None, priority=100, stamp="2026-10-15T00:00:00+00:00", updated=None):
    return {
        "id": rid, "name": name or DEFAULT["name"], "url": url, "enabled": enabled, "priority": priority, "trust": "official",
        "created_at": stamp, "updated_at": updated or stamp,
    }


# (1) a fresh seed writes the confirmed development-channel path, disabled, and the marker
reset()
must(seed() == ["tec-tac-official"], "a fresh seed writes the entry")
config = stored()
must(config["repositories"][0]["url"] == NEW_URL and config["repositories"][0]["enabled"] is False, config)
must(config[MARK] == ["tec-tac-official"], config.get(MARK))
print("       fresh seed: the confirmed development-channel path, disabled, marker written")

# (2) a 1.17.42 record that holds the assumed path is corrected once; enabled true stays true
reset()
write_config({"schema": 1, "repositories": [record(OLD_URL, True)], MARK: ["tec-tac-official"]})
must(seed() == [], "a corrected record is not counted as seeded")
item = stored()["repositories"][0]
must(item["url"] == NEW_URL and item["enabled"] is True, item)
must(item["updated_at"] != item["created_at"], "updated_at is written by the correction")
must(item["name"] == DEFAULT["name"] and item["priority"] == 100, item)
print("       1.17.42 address, enabled true: corrected, enabled, name and priority kept")

# (3) the same for a disabled record
reset()
write_config({"schema": 1, "repositories": [record(OLD_URL, False)], MARK: ["tec-tac-official"]})
seed()
item = stored()["repositories"][0]
must(item["url"] == NEW_URL and item["enabled"] is False, item)
print("       1.17.42 address, enabled false: corrected, still disabled")

# (4) a second call after the correction changes nothing
before = ns["CONFIG_FILE"].read_bytes()
must(seed() == [], "the second call seeds nothing")
must(ns["CONFIG_FILE"].read_bytes() == before, "the file is byte-identical after the correction has run")
print("       second call after correction: no change, file byte-identical")

# (5) an address an administrator edited is never replaced, whatever the name and priority
reset()
edited = "https://feed.example.test/index.json"
write_config({"schema": 1, "repositories": [record(edited, True, name="Ours", priority=10)], MARK: ["tec-tac-official"]})
seed()
item = stored()["repositories"][0]
must(item["url"] == edited and item["name"] == "Ours" and item["priority"] == 10 and item["updated_at"] == item["created_at"], item)
print("       administrator address edit: never replaced")

# (6) a changed name and priority with the 1.17.42 address: the address is corrected, the name and priority are kept
reset()
write_config({"schema": 1, "repositories": [record(OLD_URL, True, name="Our copy", priority=5)], MARK: ["tec-tac-official"]})
seed()
item = stored()["repositories"][0]
must(item["url"] == NEW_URL and item["name"] == "Our copy" and item["priority"] == 5 and item["enabled"] is True, item)
print("       1.17.42 address with an edited name and priority: address corrected, name and priority kept")

# (7) another id that holds the old address is left alone
reset()
write_config({"schema": 1, "repositories": [record(OLD_URL, True, rid="our-feed", name="Our feed")], MARK: ["tec-tac-official"]})
seed()
item = stored()["repositories"][0]
must(item["id"] == "our-feed" and item["url"] == OLD_URL, item)
print("       another id with the old address: left alone")

# (8) a removed entry stays removed; the correction does not bring it back
reset()
seed()
delete("tec-tac-official")
must(seed() == [] and stored()["repositories"] == [], stored())
print("       removed entry: stays removed")

# (9) the correction is the only automatic change: the address table names exactly the 1.17.42 seed address
must(ns["SUPERSEDED_DEFAULT_URLS"] == {"tec-tac-official": (OLD_URL,)}, ns["SUPERSEDED_DEFAULT_URLS"])
print("       superseded table: only the 1.17.42 assumed address")

# (10) docs and contract note: the zone is named, 'server time' is gone
for path in (DOCS_REPO, DOCS_SCHED, CONTRACTS_PATH):
    text = path.read_text(encoding="utf-8")
    must("server time" not in text, f"'server time' remains in {path.name}")
    must("UTC" in text, f"UTC is not named in {path.name}")
docs_repo = DOCS_REPO.read_text(encoding="utf-8")
must(NEW_URL in docs_repo and "development channel" in docs_repo, "the confirmed path and the development channel are documented")
must("CQ128" in docs_repo, "the production channel question is named")
must("Django" in docs_repo and "TIME_ZONE" in docs_repo, "the zone is named as Django's TIME_ZONE")
must("assumed path" in docs_repo, "the 1.17.43 correction is documented")
must("03:00 server time" not in REPO_TEXT, "the docstring no longer says server time")
docstring = ast.get_docstring(next(n for n in REPO_TREE.body if isinstance(n, ast.FunctionDef) and n.name == "ensure_repository_sync_schedule"))
must("UTC" in docstring and "TIME_ZONE" in docstring and "server time" not in docstring, docstring)
print("       docs, contract note and docstring: zone named (Django TIME_ZONE, UTC on stock Tactical), no 'server time'")

print("[TEST] PASS repository seed 1.17.43")
