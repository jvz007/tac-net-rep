#!/usr/bin/env python3
"""1.17.43 (held 1.17.42 review findings): no DNS on the seed, skipped_count after a failed sync, and the configuration lock.

Covered: the seed makes no DNS call, so an unresolvable official host is still seeded (and a localhost, credentialed or private IP
default is refused); the DNS answer of a manual add is taken before the lock, not under it; run_scheduled_sync counts skipped entries
only for a repository whose sync succeeded in this run; the configuration lock is an exclusive fcntl.flock around the seed, the
upsert and the delete, is released afterwards, and is bounded (a busy lock raises 'The repository configuration is busy. Try again.'
after the wait, and the seed logs one warning and never raises); a change written by another process while this one waits for the
lock is not lost, because the seed, the upsert and the delete read the configuration again inside the lock; the lock file is a sibling
of repositories.json and fcntl is imported inside the function.

A real two-process race cannot run on the Windows PC (no fcntl, no Django). fcntl is stubbed here; the dev server run is the real check.
Nothing touches the network or the real configuration.
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
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))

ZONE_OFFICIAL = "https://lic-service.tec-tac.techxflow.net.za/api/v1/repository/channels/development/index.json"
PUBLIC_IP = "93.184.216.34"


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


EVENTS: list[str] = []      # "dns" and "lock:<op>" in the order they happen
DNS_CALLS: list[str] = []
BUSY = {"on": False}
ON_LOCK: list = []          # callables run when the lock is taken, to model another process writing in between
LOCK_LOG: list[int] = []


class _Fcntl(types.ModuleType):
    pass


fake_fcntl = _Fcntl("fcntl")
fake_fcntl.LOCK_EX, fake_fcntl.LOCK_NB, fake_fcntl.LOCK_UN = 2, 4, 8


def _flock(fd, op):
    EVENTS.append(f"lock:{op}")
    LOCK_LOG.append(op)
    if op & fake_fcntl.LOCK_EX and not op & fake_fcntl.LOCK_UN:
        if BUSY["on"]:
            raise BlockingIOError(11, "busy")
        while ON_LOCK:
            ON_LOCK.pop(0)()


fake_fcntl.flock = _flock
sys.modules["fcntl"] = fake_fcntl

REAL_GETADDRINFO = socket.getaddrinfo


def _fake_getaddrinfo(host, port, *args, **kwargs):
    DNS_CALLS.append(str(host))
    EVENTS.append("dns")
    if host == "feed.example.test":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port or 443))]
    raise OSError("no such host (test stub)")


WORK = Path(tempfile.mkdtemp(prefix="seed-lock-1743-")) / "module-manager" / "repositories"


def atomic_json(path, payload, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")


class TestLog:
    def __init__(self):
        self.records = []

    def warning(self, message, *args, **kwargs):
        self.records.append((message, args))


# the sync step (run_scheduled_sync) needs the audit and scheduler modules; stubs stand in for them
AUDIT_ROWS: list[dict] = []


class SchedulerPermanentError(RuntimeError):
    pass


def record_audit(**kwargs):
    AUDIT_ROWS.append(kwargs)
    return {"recorded": True}


def service_audit_actor(**kwargs):
    return ("actor", kwargs["service"], kwargs["identity"])


sys.modules["tec_tac.audit"] = types.ModuleType("tec_tac.audit")
sys.modules["tec_tac.audit"].record = record_audit
sys.modules["tec_tac.audit"].service_audit_actor = service_audit_actor
sys.modules["tec_tac.scheduler"] = types.ModuleType("tec_tac.scheduler")
sys.modules["tec_tac.scheduler"].SchedulerPermanentError = SchedulerPermanentError

ns: dict = {
    "json": json, "re": re, "urllib": urllib, "uuid": uuid, "logging": logging, "datetime": datetime,
    "timezone": timezone, "Path": Path, "Counter": Counter, "ipaddress": ipaddress, "contextlib": contextlib, "time": time,
    "socket": socket, "atomic_json": atomic_json, "__package__": "tec_tac", "__name__": "tec_tac.module_repository",
    "REPOSITORY_ROOT": WORK, "CONFIG_FILE": WORK / "repositories.json", "CACHE_ROOT": WORK / "cache",
    "CONFIG_LOCK_WAIT_SECONDS": 0.2, "CONFIG_LOCK_POLL_SECONDS": 0.01,
    "REPO_ID_RE": re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$"), "TRUST_LEVELS": {"official", "internal", "custom"},
    "SYNC_ACTION_ID": "tec-tac.module-repository-sync", "SYNC_OWNER_KEY": "module-repository-sync",
    "MAX_SKIPPED_RECORDS": 100,
}
names = {
    "logger", "DEFAULT_REPOSITORIES", "DEFAULTS_SEEDED_KEY", "SUPERSEDED_DEFAULT_URLS", "CONFIG_LOCK", "_config_lock",
    "ModuleRepositoryError", "_RemoteAddressRefused", "_utcnow", "_default_config", "_atomic_repo_json", "load_repositories",
    "_validated_port", "_clean_url", "_normalize_address", "_always_blocked_address", "_private_address", "_CGNAT",
    "_resolve_remote_url", "_validate_remote_url", "_clean_repo_id", "public_repository", "list_repositories",
    "_find_repository", "_requested_name", "_requested_trust", "_requested_url", "upsert_repository", "delete_repository",
    "_seed_address_check", "_correct_superseded_url", "seed_default_repositories", "_repo", "_cached_modules",
    "repository_status", "_skipped_summary", "all_repository_status", "sync_all", "run_scheduled_sync",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only

log = TestLog()
ns["logger"] = log
ns["CONFIG_LOCK"] = WORK / "repositories.lock"
socket.getaddrinfo = _fake_getaddrinfo
seed = ns["seed_default_repositories"]
upsert = ns["upsert_repository"]
delete = ns["delete_repository"]
run_sync = ns["run_scheduled_sync"]
MARK = ns["DEFAULTS_SEEDED_KEY"]


def reset(repos=None):
    if WORK.exists():
        for item in sorted(WORK.rglob("*"), reverse=True):
            item.unlink() if item.is_file() else item.rmdir()
    log.records.clear()
    EVENTS.clear()
    DNS_CALLS.clear()
    LOCK_LOG.clear()
    BUSY["on"] = False
    ON_LOCK.clear()
    AUDIT_ROWS.clear()
    ns["CACHE_ROOT"].mkdir(parents=True, exist_ok=True)
    if repos is not None:
        ns["CONFIG_FILE"].parent.mkdir(parents=True, exist_ok=True)
        ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": repos}), encoding="utf-8")


def stored():
    return json.loads(ns["CONFIG_FILE"].read_text(encoding="utf-8")) if ns["CONFIG_FILE"].is_file() else None


def repo(rid, url=None, enabled=True):
    return {"id": rid, "name": rid.title(), "url": url or f"https://feed.example.test/{rid}.json", "trust": "custom", "priority": 100,
            "enabled": enabled, "created_at": "2026-10-01T00:00:00+00:00", "updated_at": "2026-10-01T00:00:00+00:00"}


# (1) the seed makes no DNS call: an official host that does not resolve is seeded, enabled false, marker written
reset()
result = seed()
must(result == ["tec-tac-official"], result)
must(DNS_CALLS == [], f"the seed made a DNS call: {DNS_CALLS}")
must(stored()["repositories"][0]["url"] == ZONE_OFFICIAL and stored()["repositories"][0]["enabled"] is False, stored())
must(log.records == [], "no warning for a host that does not resolve yet")
print("       seed: no DNS call; an unresolvable official host is seeded disabled, with no warning")

# (2) a default that is local, credentialed or a private literal is refused, with no DNS call and no marker
for bad_url, trust in (
    ("http://localhost/index.json", "official"),
    ("https://user:secret@lic-service.example.test/index.json", "official"),
    ("https://10.1.2.3/index.json", "official"),
    ("https://127.0.0.1/index.json", "official"),
):
    reset()
    ns["DEFAULT_REPOSITORIES"] = ({**ns["DEFAULT_REPOSITORIES"][0], "url": bad_url, "trust": trust},)
    must(seed() == [], f"refused: {bad_url}")
    must(stored() is None or MARK not in stored(), f"no marker for {bad_url}")
    must(log.records and "next tick" in log.records[0][0], log.records)
    must(DNS_CALLS == [], DNS_CALLS)
ns["DEFAULT_REPOSITORIES"] = ({**ns["DEFAULT_REPOSITORIES"][0], "url": "https://10.1.2.3/index.json", "trust": "internal"},)
reset()
must(seed() == ["tec-tac-official"], "a private literal is allowed for an internal trust")
ns["DEFAULT_REPOSITORIES"] = (
    {"id": "tec-tac-official", "name": "Tec-Tac official modules (Tech Flow Dynamics)", "url": ZONE_OFFICIAL, "trust": "official",
     "priority": 100, "enabled": False},
)
print("       seed: localhost, credentials and a private literal refused with no DNS call; a private literal ok for internal")

# (3) run_scheduled_sync: a failed repository's cached skipped count is not counted in this run
reset([repo("broken")])
ns["CACHE_ROOT"].mkdir(parents=True, exist_ok=True)
(ns["CACHE_ROOT"] / "broken.json").write_text(json.dumps({"schema": 1, "status": "ok", "synced_at": "2026-10-01T00:00:00+00:00",
                                                         "modules": [], "skipped": [], "skipped_count": 7}), encoding="utf-8")
SYNC_BEHAVIOUR = {"broken": "fail", "good": "ok"}


def fake_sync_repository(repository_id):
    if SYNC_BEHAVIOUR.get(repository_id) == "fail":
        raise ns["ModuleRepositoryError"]("Repository request failed due to a network or TLS error.")
    return {**ns["public_repository"](ns["_repo"](repository_id)), "sync": {"status": "ok", "synced_at": "2026-10-15T00:00:00+00:00",
                                                                      "error": None, "module_count": 1, "skipped_count": 2, "skipped": []}}


ns["sync_repository"] = fake_sync_repository
raised = False
try:
    run_sync({})
except SchedulerPermanentError:
    raised = True
must(raised, "every repository failed, so the run raises")
must(AUDIT_ROWS[-1]["after"]["entries_skipped"] == 0 and AUDIT_ROWS[-1]["after"]["failed"] == 1, AUDIT_ROWS[-1])
print("       sync, one failed repository with a cached count of 7: entries_skipped 0")

# (4) run_scheduled_sync: a succeeding repository's skipped entries count, a failed one's do not
reset([repo("good"), repo("broken")])
(ns["CACHE_ROOT"] / "broken.json").write_text(json.dumps({"schema": 1, "status": "ok", "modules": [], "skipped": [],
                                                          "skipped_count": 7}), encoding="utf-8")
counts = run_sync({})
must(counts == {"repositories": 2, "ok": 1, "failed": 1, "entries_skipped": 2}, counts)
print("       sync, one succeeding and one failed: entries_skipped counts only the succeeding one (2)")

# (5) the lock: an exclusive flock is taken and released around the seed, the upsert and the delete
reset()
seed()
must(LOCK_LOG[:1] == [6] and LOCK_LOG[-1] == 8, f"seed lock sequence {LOCK_LOG}")
reset([repo("ours")])
upsert({"name": "Ours, renamed"}, repository_id="ours")
must(LOCK_LOG[:1] == [6] and LOCK_LOG[-1] == 8, f"upsert lock sequence {LOCK_LOG}")
reset([repo("ours")])
delete("ours")
must(LOCK_LOG[:1] == [6] and LOCK_LOG[-1] == 8, f"delete lock sequence {LOCK_LOG}")
must(ns["CONFIG_LOCK"].parent == ns["CONFIG_FILE"].parent, "the lock file is a sibling of repositories.json")
print("       lock: exclusive flock taken and released by the seed, the upsert and the delete")

# (6) a busy lock is bounded: the upsert raises the busy message after the wait; the seed logs one warning and returns []
reset([repo("ours")])
BUSY["on"] = True
started = time.monotonic()
try:
    upsert({"name": "Blocked"}, repository_id="ours")
    raise AssertionError("a busy lock did not raise")
except ns["ModuleRepositoryError"] as exc:
    must(str(exc) == "The repository configuration is busy. Try again.", str(exc))
waited = time.monotonic() - started
must(0.15 <= waited < 3.0, f"the wait is bounded and about the configured 0.2 seconds, took {waited:.2f}s")
must(stored()["repositories"][0]["name"] == "Ours", "a busy upsert changes nothing")
reset()
BUSY["on"] = True
result = seed()
must(result == [] and len(log.records) == 1 and "next tick" in log.records[0][0], (result, log.records))
must(not ns["CONFIG_FILE"].exists(), "a busy seed writes nothing")
reset([repo("ours")])
BUSY["on"] = True
try:
    delete("ours")
    raise AssertionError("a busy delete did not raise")
except ns["ModuleRepositoryError"] as exc:
    must("busy" in str(exc), str(exc))
must(stored()["repositories"][0]["id"] == "ours", "a busy delete removes nothing")
BUSY["on"] = False
print("       busy lock: upsert and delete raise the busy message after the bounded wait; the seed logs once and never raises")

# (7) a change written by another process while this one waits for the lock is not lost (each step reads again inside the lock)
reset([repo("ours")])
ON_LOCK.append(lambda: ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": [repo("ours"), repo("theirs")]}),
                                                    encoding="utf-8"))
upsert({"id": "mine", "name": "Mine", "url": "https://93.184.216.34/mine.json"})
ids = [item["id"] for item in stored()["repositories"]]
must(sorted(ids) == ["mine", "ours", "theirs"], ids)
reset([repo("ours")])
ON_LOCK.append(lambda: ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": [repo("ours"), repo("theirs")]}),
                                                    encoding="utf-8"))
delete("ours")
must([item["id"] for item in stored()["repositories"]] == ["theirs"], stored())
reset()
ON_LOCK.append(lambda: ns["CONFIG_FILE"].write_text(json.dumps({"schema": 1, "repositories": [repo("theirs")]}), encoding="utf-8"))
must(seed() == ["tec-tac-official"], "the seed still adds its entry")
ids = [item["id"] for item in stored()["repositories"]]
must(sorted(ids) == ["tec-tac-official", "theirs"], ids)
print("       a change made while waiting for the lock: kept by the upsert, the delete and the seed")

# (8) the DNS answer of a manual add is taken before the lock, not under it
reset([repo("ours")])
upsert({"id": "dns-first", "name": "DNS first", "url": "https://feed.example.test/dns-first.json", "trust": "custom"})
must("dns" in EVENTS and EVENTS.index("dns") < EVENTS.index("lock:6"), EVENTS)
print("       manual add: the address check (DNS) runs before the lock is taken")

# (9) fcntl is imported inside the function, so the module still imports without it
module_level_imports = [alias.name for node in REPO_TREE.body if isinstance(node, ast.Import) for alias in node.names]
must("fcntl" not in module_level_imports, "fcntl is not imported at module level")
print("       fcntl: imported inside the lock only")

# (10) the lock file is a sibling of repositories.json in the real module
lock_assign = next(n for n in REPO_TREE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "CONFIG_LOCK" for t in n.targets))
src = ast.get_source_segment(REPO_PATH.read_text(encoding="utf-8"), lock_assign)
must(src == 'CONFIG_LOCK = REPOSITORY_ROOT / "repositories.lock"', src)

socket.getaddrinfo = REAL_GETADDRINFO
print("[TEST] PASS repository seed lock 1.17.43")
