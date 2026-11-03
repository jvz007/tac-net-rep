#!/usr/bin/env python3
"""1.17.103 (AD-56, AD-58 D6, C3): the licensed catalogue lists again.

Covered: a repository source of kind licensing is seeded beside the old retired entry (idempotent; a 1.17.102 configuration is upgraded
with no change to the old record; a removed source stays removed); a sync asks licensing.catalogue.module_catalogue(channel=...) with
keyword arguments only and stores the result in the existing cache shape (dependency lists become objects; release_id, publisher_id,
key_id and entitled are kept; no credential, no address); a provider that is missing, disabled, unhealthy or refuses Core is
licensing_unavailable and never an unrestricted list; not_registered, licence and channel_not_permitted states are plain states; a
temporary fault keeps the last good list and every other state empties it; the channel is a setting of each source, edited by a module
manager with a strict audit row first, and a changed channel drops the old list; the availability and the repository status carry the
state; the daily sync counts a licence state as attention, not a failure; a 1.17.102 cache and record still read; the docs, the
contract rows and the notes.

module_repository.py imports Django, so its real functions are read with ast and run with stubs (the method of
tests/repository-retired-1.17.99.py). licensing_catalogue_source.py imports no Django and is loaded as it is. The fake provider has the
real keyword-only signatures. Nothing touches the network.
"""
from __future__ import annotations

import ast
import importlib.util
import ipaddress
import json
import re
import sys
import tempfile
import types
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
REPO_PATH = APP / "module_repository.py"
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))
SENTINEL = "SENTINEL-BEARER-0123456789"


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


# ---------------------------------------------------------------------------------------------- a stand-in package so the real file loads
class ModuleStateError(RuntimeError):
    pass


_CONSTRAINT = re.compile(r"^(\*|(>=|<=|==|>|<)?\d+\.\d+\.\d+(,\s*(>=|<=|==|>|<)\d+\.\d+\.\d+)*)$")


def version_satisfies(version, constraint):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise ModuleStateError(f"bad version {version!r}")
    if not _CONSTRAINT.match(str(constraint or "*").strip() or "*"):
        raise ModuleStateError(f"bad constraint {constraint!r}")
    return True


class CapabilityOperationError(RuntimeError):
    def __init__(self, capability_id, message, status=None):
        super().__init__(message)
        self.status = status or {}


class CapabilityUnhealthy(RuntimeError):
    pass


PROVIDER = {"obj": None, "raise": None}
CALLS = []


def get_capability(capability_id, *, version=None, required=True, module_id=None):
    CALLS.append(("get_capability", capability_id, version))
    if PROVIDER["raise"] is not None:
        raise PROVIDER["raise"]
    return PROVIDER["obj"]


def make_package():
    pkg = types.ModuleType("tec_tac")
    pkg.__path__ = [str(APP)]
    sys.modules["tec_tac"] = pkg
    state = types.ModuleType("tec_tac.module_state")
    state.ModuleStateError = ModuleStateError
    state.version_satisfies = version_satisfies
    state.strip_repository_url = lambda url: url
    sys.modules["tec_tac.module_state"] = state
    caps = types.ModuleType("tec_tac.capabilities")
    caps.get_capability = get_capability
    sys.modules["tec_tac.capabilities"] = caps
    pkg.capabilities = caps
    audit = types.ModuleType("tec_tac.audit")
    audit.ROWS = []
    audit.FAIL = {"strict": False}

    def record(*, actor, module_id, action, object_type, object_id=None, message=None, before=None, after=None, metadata=None,
               operation_context=None, request=None, correlation_id=None, strict=False, verified_run=None):
        if audit.FAIL["strict"] and strict:
            raise RuntimeError("audit down")
        audit.ROWS.append({"actor": actor, "module_id": module_id, "action": action, "object_type": object_type, "object_id": object_id,
                           "message": message, "metadata": metadata, "strict": strict})
        return {"recorded": True}

    audit.record = record
    audit.service_audit_actor = lambda *, module_id, service, identity=None: f"service:{module_id}:{service}"
    sys.modules["tec_tac.audit"] = audit
    spec = importlib.util.spec_from_file_location("tec_tac.licensing_catalogue_source", APP / "licensing_catalogue_source.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tec_tac.licensing_catalogue_source"] = mod
    spec.loader.exec_module(mod)
    pkg.licensing_catalogue_source = mod
    return mod, audit


lcs, AUDIT = make_package()


# ---------------------------------------------------------------------------------------------- the fake provider (real signatures)
REL_A = "11111111-1111-4111-8111-111111111111"
REL_B = "22222222-2222-4222-8222-222222222222"
REL_C = "33333333-3333-4333-8333-333333333333"
SHA = "a" * 64


def module_entry(module_id="welcome", **over):
    entry = {
        "id": module_id, "name": module_id.title(), "category": "core", "entitled": True, "entitlement_source": "license", "availability": "available",
        "available_releases": [{
            "release_id": REL_A, "version": "1.2.11", "channel": "development", "environment": "development", "recommended": True,
            "requires": {"core": ">=1.17.99"}, "dependencies": ["agents>=1.0.0", "checks", {"id": "tasks", "constraint": ">=2.0.0,<3.0.0"}],
            "optional_dependencies": [], "sha256": SHA, "publisher_id": "tech_dev", "key_id": "key-1",
        }],
    }
    entry.update(over)
    return entry


class FakeProvider:
    """Keyword-only, exactly like licensing.catalogue 1.0.0. A positional call is a TypeError."""

    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.seen = answer, error, []

    def module_catalogue(self, *, channel=None):
        self.seen.append(("module_catalogue", channel))
        if self.error:
            raise self.error
        return self.answer(channel) if callable(self.answer) else self.answer

    def download_grant(self, *, release_id, channel=None):  # not used here
        raise AssertionError("the listing never asks for a grant")

    def registration_status(self):
        raise AssertionError("the listing never reads the registration")

    def health(self):
        return {"healthy": True}


def ok_answer(*modules, channel="development"):
    return {"ok": True, "state": "ok", "message": "Done.", "channel": channel, "generated_at": "2026-11-03T08:00:00Z",
            "max_endpoints": 100, "modules": list(modules) or [module_entry()]}


def state_answer(state):
    return {"ok": False, "state": state, "message": "text from the provider that Core must not copy"}


# ---------------------------------------------------------------------------------------------- 1. the source: mapping
rows, skipped = lcs.map_catalogue(ok_answer(module_entry()))
must(len(rows) == 1 and not skipped, (rows, skipped))
row = rows[0]
must(row["dependencies"] == {"agents": ">=1.0.0", "checks": "*", "tasks": ">=2.0.0,<3.0.0"}, row["dependencies"])
must(row["optional_dependencies"] == {} and row["requires"] == {"core": ">=1.17.99"}, row)
must(row["release_id"] == REL_A and row["publisher_id"] == "tech_dev" and row["key_id"] == "key-1" and row["entitled"] is True, row)
must(row["id"] == "welcome" and row["version"] == "1.2.11" and row["sha256"] == SHA and row["channel"] == "development", row)
must(row["download_url"] is None and row["signature_url"] is None and row["release_metadata_url"] is None, "no address in a licensed row")
must(row["signing_environment"] == "development" and row["recommended"] is True and row["lifecycle"] is None, row)
for key in ("name", "description", "download", "dependencies", "optional_dependencies", "requires", "channel", "lifecycle", "recommended",
            "downgrade_policy", "signing_environment", "version", "sha256", "id"):
    must(key in row, f"the cache row misses the existing key {key}")
must("token" not in json.dumps(row).lower() and "bearer" not in json.dumps(row).lower(), "a credential word in a row")
print("       mapping: dependency lists become objects; release_id, publisher_id, key_id and entitled kept; no address, no credential")

# a dependency object (mapping) is accepted as it is; an unreadable or invalid dependency skips that release, never drops the dependency
rows, skipped = lcs.map_catalogue(ok_answer(module_entry(available_releases=[
    {**module_entry()["available_releases"][0], "dependencies": {"agents": ">=1.0.0"}},
    {**module_entry()["available_releases"][0], "version": "1.2.12", "release_id": REL_B, "dependencies": [42]},
    {**module_entry()["available_releases"][0], "version": "1.2.13", "release_id": REL_C, "dependencies": ["agents ??bad"]},
    {**module_entry()["available_releases"][0], "version": "bad", "release_id": REL_C},
    {**module_entry()["available_releases"][0], "version": "1.2.14", "sha256": "nothex"},
    "not an object",
])))
must([r["version"] for r in rows] == ["1.2.11"] and rows[0]["dependencies"] == {"agents": ">=1.0.0"}, rows)
must(len(skipped) == 5 and all(set(s) == {"index", "id", "version", "reason"} for s in skipped), skipped)
print("       mapping: a bad dependency, version, SHA-256 or entry is skipped with a reason; nothing is dropped silently")

# duplicates skip both copies; a module that is not entitled is kept but flagged and never offered
dup = module_entry()
dup["available_releases"] = [dup["available_releases"][0], {**dup["available_releases"][0], "release_id": REL_B}]
rows, skipped = lcs.map_catalogue(ok_answer(dup))
must(rows == [] and len(skipped) == 2 and all(s["reason"] == "duplicate" for s in skipped), (rows, skipped))
rows, _ = lcs.map_catalogue(ok_answer(module_entry(entitled=False)))
must(rows[0]["entitled"] is False and rows[0]["download_unavailable"] is True and rows[0]["download_unavailable_state"] == "not_in_licence", rows)
print("       mapping: duplicates skipped; a module outside the licence is flagged download_unavailable")

# ---------------------------------------------------------------------------------------------- 2. the source: the provider call
PROVIDER["obj"] = FakeProvider(ok_answer())
PROVIDER["raise"] = None
CALLS.clear()
state, answer = lcs.fetch_catalogue("")
must(state == "ok" and answer["modules"], state)
must(PROVIDER["obj"].seen == [("module_catalogue", None)], PROVIDER["obj"].seen)   # empty channel -> the licence's own (None)
must(CALLS[0][1] == "licensing.catalogue" and CALLS[0][2] == ">=1.0.0,<2.0.0", CALLS)
PROVIDER["obj"] = FakeProvider(ok_answer(channel="testing"))
state, _ = lcs.fetch_catalogue("testing")
must(state == "ok" and PROVIDER["obj"].seen == [("module_catalogue", "testing")], PROVIDER["obj"].seen)
print("       provider call: keyword arguments only; the channel of the source is passed; an empty channel is None (the licence's own)")

# missing, disabled, unhealthy, refusing Core: licensing_unavailable, never a list
for label, exc in (("missing", RuntimeError("CapabilityUnavailable")), ("unhealthy", CapabilityUnhealthy("down"))):
    PROVIDER["raise"] = exc
    state, answer = lcs.fetch_catalogue(None)
    must(state == "licensing_unavailable" and answer is None, (label, state))
PROVIDER["raise"] = None
PROVIDER["obj"] = FakeProvider(error=CapabilityOperationError("licensing.catalogue", "refused", status={"state": "caller_not_allowed"}))
must(lcs.fetch_catalogue(None) == ("licensing_unavailable", None), "a provider that refuses Core must read as unavailable")
PROVIDER["obj"] = FakeProvider(error=ValueError("boom"))
must(lcs.fetch_catalogue(None) == ("licensing_unavailable", None), "a provider fault must read as unavailable")
for garbage in (None, [], "ok", {"ok": True}, {"state": "mystery"}, {"state": "ok", "ok": True, "modules": "x"}, {"state": "ok", "ok": False, "modules": []}):
    PROVIDER["obj"] = FakeProvider(garbage)
    state, answer = lcs.fetch_catalogue(None)
    must(state == "invalid_response" and answer is None, (garbage, state))
for state_name in ("not_registered", "licence_revoked", "licence_expired", "licence_grace_expired", "licence_refused", "channel_not_permitted",
                   "licensing_unavailable", "bad_request", "audit_unavailable"):
    PROVIDER["obj"] = FakeProvider(state_answer(state_name))
    must(lcs.fetch_catalogue(None) == (state_name, None), state_name)
must(set(lcs.TEXT) >= lcs.KNOWN_STATES and lcs.message_for("not_registered").startswith("This server is not registered"), "plain text per state")
must("text from the provider" not in lcs.message_for("not_registered"), "Core must use its own sentence")
print("       provider call: missing, unhealthy, disabled or refusing -> licensing_unavailable; garbage -> invalid_response; every state is a plain state with Core's sentence")

# the channel setting is validated
must(lcs.clean_channel(None) == "" and lcs.clean_channel("  ") == "" and lcs.clean_channel("Testing".lower()) == "testing", "clean_channel")
for bad in ("Production", "1abc", "a b", "x" * 33, "../x", 5, ["a"]):
    try:
        lcs.clean_channel(bad)
        raise AssertionError(f"accepted {bad!r}")
    except ValueError:
        pass
print("       channel: empty or a valid name; anything else is refused")


# ---------------------------------------------------------------------------------------------- 3. module_repository: sync, status, availability, upsert, seed
class TestLog:
    def __init__(self):
        self.records = []

    def warning(self, message, *args, **kwargs):
        self.records.append(("warning", message % args if args else message))

    def error(self, message, *args, **kwargs):
        self.records.append(("error", message % args if args else message))

    def info(self, *args, **kwargs):
        pass


class RepositoryHttpError(RuntimeError):
    pass


TMP = Path(tempfile.mkdtemp(prefix="tectac-licensing-repo-"))
CONFIG = TMP / "repositories.json"
CACHE = TMP / "cache"
ns = {
    "__name__": "tec_tac.module_repository", "__package__": "tec_tac",
    "ipaddress": ipaddress, "json": json, "re": re, "urllib": urllib, "Path": Path, "Counter": Counter, "datetime": datetime, "timezone": timezone,
    "logger": TestLog(), "CONFIG_FILE": CONFIG, "CACHE_ROOT": CACHE, "REPOSITORY_ROOT": TMP, "CONFIG_LOCK": TMP / "repositories.lock",
    "version_satisfies": version_satisfies, "ModuleStateError": ModuleStateError, "_lcs": lcs, "uuid": __import__("uuid"),
    "TRUST_LEVELS": {"official", "internal", "custom"}, "REPO_ID_RE": re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$"),
    "MAX_SKIPPED_RECORDS": 100, "MAX_SKIPPED_TEXT": 100, "MAX_SKIPPED_REASON": 300,
    "SKIPPED_REASON_FOR_OTHERS": "x", "RETIRED_MESSAGE": "retired", "CREDENTIALS_REJECTED_MESSAGE": "refused", "RETIRED_RELEASE_REASON": "r",
    "CREDENTIALS_RELEASE_REASON": "c",
}
names = {
    "ModuleRepositoryError", "_utcnow", "_default_config", "_atomic_repo_json", "load_repositories", "public_repository", "list_repositories",
    "_find_repository", "_requested_name", "_requested_priority", "_licensing_audit", "_upsert_licensing", "upsert_repository",
    "_sync_licensing", "sync_repository", "_repo", "_repo_raw", "repository_status", "_has_credentials", "_legacy_error_status",
    "_cache_credentials_rejected", "_cache_retired", "_skipped_summary", "all_repository_status", "sync_all", "_AVAILABILITY_MESSAGES",
    "_availability", "run_scheduled_sync", "RETIRED_STATUSES", "CREDENTIALS_STATUSES", "_LEGACY_RETIRED_ERROR", "DEFAULT_REPOSITORIES",
    "DEFAULTS_SEEDED_KEY", "SUPERSEDED_DEFAULT_URLS", "seed_default_repositories", "_seed_address_check", "_correct_superseded_url",
    "_clean_url", "_normalize_address", "_always_blocked_address", "_private_address", "_CGNAT", "_validated_port", "_cached_modules",
    "SYNC_OWNER_KEY",
}
update_node = next(n for n in REPO_TREE.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and "_AVAILABILITY_MESSAGES" in ast.dump(n.value))
body = extract(REPO_TREE, names) + [update_node]
# the file lock needs fcntl (Linux only): the real function is replaced by a plain context manager after loading
exec(compile(ast.Module(body=body, type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only
import contextlib


@contextlib.contextmanager
def _no_lock():
    yield


ns["_config_lock"] = _no_lock
ns["atomic_json"] = lambda path, payload, mode=0o660: Path(path).write_text(json.dumps(payload), encoding="utf-8")
ns["SYNC_OWNER_KEY"] = "module-repository-sync"
sync_repository, repository_status = ns["sync_repository"], ns["repository_status"]
ModuleRepositoryError = ns["ModuleRepositoryError"]
LOG = ns["logger"]


def write_config(repos, **extra):
    CONFIG.write_text(json.dumps({"schema": 1, "repositories": repos, **extra}), encoding="utf-8")


def stored():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def cache_file(rid="tec-tac-licensing"):
    path = CACHE / f"{rid}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def lic_record(**over):
    record = {"id": "tec-tac-licensing", "name": "Tec-Tac licensed modules (Licensing)", "url": "https://lic-service.tec-tac.techxflow.net.za",
              "enabled": True, "priority": 50, "trust": "official", "kind": "licensing", "channel": "", "created_at": "x", "updated_at": "x"}
    record.update(over)
    return record


# the real get_licensing_server_url is imported inside repository_status; give it the stand-in module
lsu = types.ModuleType("tec_tac.licensing_server_url")
lsu.get_licensing_server_url = lambda: {"url": "https://lic.example.test", "source": "config", "configured": True, "reason": None}
sys.modules["tec_tac.licensing_server_url"] = lsu

# --- seed: beside the old entry, idempotent, upgrade-safe
OLD = {"id": "tec-tac-official", "name": "Tec-Tac official modules (Tech Flow Dynamics)",
       "url": "https://lic-service.tec-tac.techxflow.net.za/api/v1/repository/channels/development/index.json", "enabled": False, "priority": 100,
       "trust": "official", "created_at": "2026-10-15T00:00:00+00:00", "updated_at": "2026-10-15T00:00:00+00:00"}
write_config([dict(OLD)], defaults_seeded=["tec-tac-official"])     # exactly what a 1.17.102 server holds
seed = ns["seed_default_repositories"]
must(seed() == ["tec-tac-licensing"], ("the licensing source is seeded on a 1.17.102 configuration", LOG.records))
config = stored()
must(config["repositories"][0] == OLD, "the old record is not touched")
seeded = config["repositories"][1]
must(seeded["id"] == "tec-tac-licensing" and seeded["kind"] == "licensing" and seeded["channel"] == "" and seeded["trust"] == "official"
     and seeded["enabled"] is True and seeded["priority"] < OLD["priority"], seeded)
must(config["defaults_seeded"] == ["tec-tac-official", "tec-tac-licensing"], config["defaults_seeded"])
must(seed() == [] and stored() == config, "a second call changes nothing")
delete_node = [r for r in config["repositories"] if r["id"] != "tec-tac-licensing"]
write_config(delete_node, defaults_seeded=config["defaults_seeded"])
must(seed() == [] and [r["id"] for r in stored()["repositories"]] == ["tec-tac-official"], "a removed source stays removed")
write_config([], )                                                   # a brand new server seeds both
must(seed() == ["tec-tac-official", "tec-tac-licensing"], "a fresh server seeds both, the licensing source after the old one")
write_config([dict(OLD), lic_record(enabled=False, channel="testing", name="Mine", priority=7)], defaults_seeded=["tec-tac-official"])
must(seed() == [] and stored()["repositories"][1]["channel"] == "testing" and stored()["repositories"][1]["enabled"] is False, "an edited source is never rebuilt")
print("       seed: beside the old entry, once, idempotent; a 1.17.102 configuration is upgraded; removed or edited stays as it is")

# --- sync
write_config([dict(OLD), lic_record()], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
PROVIDER["raise"] = None
PROVIDER["obj"] = FakeProvider(ok_answer(module_entry(), module_entry("agents", available_releases=[{**module_entry()["available_releases"][0], "release_id": REL_B, "dependencies": []}])))
result = sync_repository("tec-tac-licensing")
must(result["sync"]["status"] == "ok" and result["sync"]["module_count"] == 2 and result["sync"]["licensing_state"] == "ok", result["sync"])
cache = cache_file()
must(cache["status"] == "ok" and cache["licensing_state"] == "ok" and len(cache["modules"]) == 2 and cache["synced_at"], cache.keys())
must(PROVIDER["obj"].seen == [("module_catalogue", None)], "the source's own channel (empty) went to the provider")
cache_text = json.dumps(cache) + json.dumps(result)
must("http" not in json.dumps(cache), "no address in the cache")
must("auth_token" not in cache_text and SENTINEL not in cache_text and "artifact_access_token" not in cache_text, "no credential or address in the cache or the answer")
must(all(isinstance(m["dependencies"], dict) for m in cache["modules"]), "dependencies are objects in the cache")
print("       sync: the result is stored in the existing cache shape; no credential, no address")

# the channel is a setting of the source and is passed to the provider
write_config([dict(OLD), lic_record(channel="testing")], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
PROVIDER["obj"] = FakeProvider(ok_answer(channel="testing"))
sync_repository("tec-tac-licensing")
must(PROVIDER["obj"].seen == [("module_catalogue", "testing")] and cache_file()["repository"]["channel"] == "testing", PROVIDER["obj"].seen)
# channel_not_permitted is a plain state: the list is emptied, the channel is NOT switched
PROVIDER["obj"] = FakeProvider(state_answer("channel_not_permitted"))
try:
    sync_repository("tec-tac-licensing")
    raise AssertionError("channel_not_permitted must raise")
except ModuleRepositoryError as exc:
    must("does not allow the release channel" in str(exc) and "Core does not switch channels" in str(exc), str(exc))
must(PROVIDER["obj"].seen == [("module_catalogue", "testing")], "no second call on another channel: never a silent switch")
cache = cache_file()
must(cache["modules"] == [] and cache["synced_at"] is None and cache["licensing_state"] == "channel_not_permitted" and cache["status"] == "error", cache)
must(stored()["repositories"][1]["channel"] == "testing", "the stored channel is unchanged")
print("       channel: per source, passed to the provider; channel_not_permitted is shown as a state, the list is empty, nothing is switched")

# every definite state empties the list; a temporary fault keeps the last good one
write_config([dict(OLD), lic_record()], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
for definite in ("not_registered", "licence_revoked", "licence_expired", "licence_grace_expired", "licence_refused", "bad_request"):
    PROVIDER["obj"] = FakeProvider(ok_answer())
    sync_repository("tec-tac-licensing")
    must(cache_file()["modules"], "setup")
    PROVIDER["obj"] = FakeProvider(state_answer(definite))
    try:
        sync_repository("tec-tac-licensing")
        raise AssertionError(definite)
    except ModuleRepositoryError as exc:
        must(str(exc) == lcs.message_for(definite), (definite, str(exc)))
    after = cache_file()
    must(after["modules"] == [] and after["synced_at"] is None and after["licensing_state"] == definite, (definite, after))
for transient in ("licensing_unavailable", "invalid_response", "audit_unavailable"):
    PROVIDER["obj"] = FakeProvider(ok_answer())
    sync_repository("tec-tac-licensing")
    PROVIDER["obj"] = FakeProvider(state_answer(transient))
    try:
        sync_repository("tec-tac-licensing")
        raise AssertionError(transient)
    except ModuleRepositoryError:
        pass
    after = cache_file()
    must(len(after["modules"]) == 1 and after["synced_at"] and after["licensing_state"] == transient and after["status"] == "error", (transient, after))
print("       sync: not registered, revoked, expired, grace ended, refused, bad request empty the list; a temporary fault keeps the last good one")

# provider missing / unhealthy on the very first sync: nothing is offered, never an unrestricted list
write_config([dict(OLD), lic_record()], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
for path in CACHE.glob("*.json"):
    path.unlink()
PROVIDER["raise"] = RuntimeError("provider not installed")
try:
    sync_repository("tec-tac-licensing")
    raise AssertionError("must raise")
except ModuleRepositoryError as exc:
    must("Licensing module" in str(exc), str(exc))
first = cache_file()
must(first["modules"] == [] and first["licensing_state"] == "licensing_unavailable" and not first.get("synced_at"), first)
status = repository_status("tec-tac-licensing")
must(status["sync"]["licensing_state"] == "licensing_unavailable" and status["sync"]["module_count"] == 0, status["sync"])
must(status["url"] == "https://lic.example.test" and status["channel"] == "", "the status shows the pinned address and the channel")
PROVIDER["raise"] = None
print("       provider missing or unhealthy: licensing_unavailable, an empty list, never an unrestricted one")

# --- availability: the Licensing source says why nothing is offered
availability = ns["_availability"]
repos = [r for r in stored()["repositories"] if r.get("enabled", True)]
ns["repository_status"] = repository_status
state = availability(repos, 0, 0)
must(state["state"] == "licensing_unavailable" and state["message"] == lcs.message_for("licensing_unavailable") and state["licensing_state"] == "licensing_unavailable", state)
PROVIDER["obj"] = FakeProvider(state_answer("not_registered"))
try:
    sync_repository("tec-tac-licensing")
except ModuleRepositoryError:
    pass
state = availability(repos, 0, 0)
must(state["state"] == "not_registered" and "not registered" in state["message"], state)
PROVIDER["obj"] = FakeProvider(ok_answer())
sync_repository("tec-tac-licensing")
state = availability(repos, 1, 0)
must(state["state"] == "ready" and state["licensing_state"] is None, state)
for st in lcs.AVAILABILITY_STATES:
    must(ns["_AVAILABILITY_MESSAGES"][st] == lcs.message_for(st), st)
print("       availability: the licensing state and Core's sentence for every state; ready after a good sync")

# --- the daily run: a licence state is attention, not a failure; a provider that is down is a failure
sys.modules["tec_tac.scheduler"] = types.SimpleNamespace(SchedulerPermanentError=type("SchedulerPermanentError", (RuntimeError,), {}))
write_config([lic_record()], defaults_seeded=["tec-tac-licensing"])
run = ns["run_scheduled_sync"]
PROVIDER["obj"] = FakeProvider(state_answer("not_registered"))
counts = run({"parameters": {}})
must(counts == {"repositories": 1, "ok": 0, "failed": 0, "entries_skipped": 0, "licensing_attention": 1}, counts)
PROVIDER["obj"] = FakeProvider(state_answer("licensing_unavailable"))
try:
    run({"parameters": {}})
    raise AssertionError("a provider that is down is a failed run")
except RuntimeError as exc:
    must(exc.__class__.__name__ == "SchedulerPermanentError", exc)
PROVIDER["obj"] = FakeProvider(ok_answer())
counts = run({"parameters": {}})
must(counts["ok"] == 1 and counts["failed"] == 0 and "licensing_attention" not in counts, counts)
audit_rows = [r for r in AUDIT.ROWS if r["object_type"] == "module_repository" and r["action"] == "sync"]
must(len(audit_rows) == 3 and all(SENTINEL not in json.dumps(r) for r in audit_rows), "one count-only row per run")
print("       daily sync: a licence state is attention (not a failure), a provider that is down fails the run, counts only in the audit row")

# --- editing the source: the channel is a setting per source, edited by a module manager
upsert = ns["upsert_repository"]
write_config([dict(OLD), lic_record()], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
AUDIT.ROWS.clear()
PROVIDER["obj"] = FakeProvider(ok_answer())
sync_repository("tec-tac-licensing")
request = types.SimpleNamespace(user="a-person")
changed = upsert({"channel": "production", "name": "Licensed", "priority": 20, "enabled": True, "url": "https://evil.example.test/", "trust": "custom"},
                 repository_id="tec-tac-licensing", request=request)
rec = stored()["repositories"][1]
must(changed["channel"] == "production" and rec["channel"] == "production" and rec["name"] == "Licensed" and rec["priority"] == 20, rec)
must(rec["url"] == "https://lic-service.tec-tac.techxflow.net.za" and rec["trust"] == "official" and rec["kind"] == "licensing", "address, trust and kind are Core's")
must(cache_file() is None, "a changed channel drops the list of the old channel")
row = AUDIT.ROWS[-1]
must(row["actor"] == "a-person" and row["strict"] is True and row["action"] == "modify" and row["metadata"] == {"channel_before": "default", "channel_after": "production"}, row)
# no channel change -> no audit row, and an invalid channel changes nothing
AUDIT.ROWS.clear()
upsert({"priority": 21}, repository_id="tec-tac-licensing", request=request)
must(AUDIT.ROWS == [], "no row without a channel change")
for bad in ("Production", "1x", "a b", 5):
    try:
        upsert({"channel": bad}, repository_id="tec-tac-licensing", request=request)
        raise AssertionError(bad)
    except ModuleRepositoryError as exc:
        must("channel" in str(exc).lower(), str(exc))
must(stored()["repositories"][1]["channel"] == "production", "an invalid channel saved nothing")
# the audit row is written first: when it cannot be written nothing is saved
AUDIT.FAIL["strict"] = True
try:
    upsert({"channel": "testing"}, repository_id="tec-tac-licensing", request=request)
    raise AssertionError("must fail closed")
except ModuleRepositoryError as exc:
    must("audit record" in str(exc), str(exc))
AUDIT.FAIL["strict"] = False
must(stored()["repositories"][1]["channel"] == "production", "no audit row, no change")
try:
    upsert({"kind": "index"}, repository_id="tec-tac-licensing", request=request)
    raise AssertionError("kind is Core's")
except ModuleRepositoryError:
    pass
# other repositories: no channel field, no way to create a licensing source
for payload in ({"name": "x", "url": "https://x.example.test/i.json", "channel": "testing"}, {"name": "x", "url": "https://x.example.test/i.json", "kind": "licensing"}):
    try:
        upsert(payload)
        raise AssertionError(payload)
    except ModuleRepositoryError:
        pass
print("       edit: the channel is per source; the audit row is strict and first; an invalid channel, kind, address and trust are refused or ignored")

# --- upgrade: a 1.17.102 cache and record still read
write_config([dict(OLD)], defaults_seeded=["tec-tac-official"])
CACHE.mkdir(parents=True, exist_ok=True)
(CACHE / "tec-tac-official.json").write_text(json.dumps({"schema": 1, "repository_id": "tec-tac-official", "status": "error", "error": "Repository request returned HTTP 404.",
                                                         "modules": [], "last_attempt_at": "x"}), encoding="utf-8")
status = repository_status("tec-tac-official")
must(status["sync"]["retired"] is True and "licensing_state" not in status["sync"] and "channel" not in status, status)
state = availability([dict(OLD, enabled=True)], 0, 0)
must(state["state"] == "repository_retired" and state["licensing_state"] is None, state)
write_config([dict(OLD, enabled=True), lic_record()], defaults_seeded=["tec-tac-official", "tec-tac-licensing"])
(CACHE / "tec-tac-licensing.json").unlink(missing_ok=True)
state = availability([dict(OLD, enabled=True), lic_record()], 0, 0)    # beside a licensing source that never synced
must(state["state"] in ("not_synced", "sync_failed", "licensing_unavailable", "not_registered"), state)
print("       upgrade: a 1.17.102 record and cache read as before; the old repository stays retired beside the licensing source")

# ---------------------------------------------------------------------------------------------- 4. static: no module reaches the provider, docs, contracts, notes, version
SOURCE = (APP / "licensing_catalogue_source.py").read_text(encoding="utf-8")
for other in sorted(APP.glob("*.py")):
    if other.name in ("licensing_catalogue_source.py", "capabilities.py", "contracts.py"):
        continue
    text = other.read_text(encoding="utf-8")
    must("licensing.catalogue" not in text or other.name in ("module_repository.py",), f"{other.name} names licensing.catalogue: only licensing_catalogue_source.py may call it")
must(".module_catalogue(" not in (APP / "module_repository.py").read_text(encoding="utf-8") and "get_capability" not in (APP / "module_repository.py").read_text(encoding="utf-8"),
     "module_repository.py must not call the provider itself")
must("logger.exception" not in SOURCE and "exc_info" not in SOURCE, "the source never logs a traceback")
must(not re.search(r"(print|logger\.\w+)\([^)]*(token|bearer)", SOURCE, re.IGNORECASE), "the source never logs a token")
VIEWS = (APP / "module_repository_views.py").read_text(encoding="utf-8")
must("upsert_repository(request.data, repository_id=repository_id, request=request)" in VIEWS and "allow_source_change=allow_source_change, request=request" in VIEWS, "the views pass the request (audit)")
MODULES = ROOT.parents[1] / "modules"
if MODULES.is_dir():
    users = []
    for path in MODULES.rglob("*.py"):
        if "node_modules" in path.parts or "tests" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if re.search(r"module_repository|licensing_catalogue_source|catalog/online|modules/repositories", text) and path.parts[len(MODULES.parts)] != "licensing":
            users.append(str(path.relative_to(MODULES)))
    must(not users, f"modules use the repository code: {users}")
print("       static: only licensing_catalogue_source.py calls the provider; the views pass the request; no module uses the repository code")


def read(path):
    return Path(path).read_text(encoding="utf-8")


DOC = read(ROOT / "docs" / "module-repositories.md")
TS = read(ROOT / "docs" / "troubleshooting-diagnostics.md")
FOOT = "Tech Flow Dynamics · techxflow.co.za"
for text, label in ((DOC, "module-repositories.md"), (TS, "troubleshooting")):
    must(text.rstrip().endswith(FOOT) and text.count(FOOT) == 1, f"{label}: footer last")
    for state_name in sorted(lcs.KNOWN_STATES - {"ok"}):
        must(f"`{state_name}`" in text, f"{label} misses the state {state_name}")
    for extra in ("grant_expired", "download_refused", "download_failed", "verification_failed", "release_mismatch", "not_in_licence", "audit_not_saved"):
        must(extra in text, f"{label} misses {extra}")
must("channel" in DOC and "Licensing" in DOC and "1.17.103" in DOC and "tec-tac-licensing" in DOC, "the help text of the licensed source")
for sentence in lcs.TEXT.values():
    if sentence in ("Done.",):
        continue
    must(sentence[:40] in DOC or sentence[:40] in TS, f"a message is not in the help: {sentence[:50]}")
CONTRACTS = read(APP / "contracts.py")
must('"kind"' in CONTRACTS and "licensing_state" in CONTRACTS and "1.17.103" in CONTRACTS, "the contract rows")
NOTES = read(ROOT / "RELEASE_NOTES_1.17.103.md")
for heading in ("## What changed and why", "## Module-facing changes", "## Assumptions", "## Tests", "## Checks on the test server", "## Not done here", "FAIL"):
    must(heading in NOTES, heading)
must("not registered" in NOTES.lower() and "registered" in NOTES.lower(), "both paths in the dev02 checklist")
must(len(list(ROOT.glob("RELEASE_NOTES_*.md"))) == 1 and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.102.md").is_file(), "notes: one in the root, the old one moved")
must(read(ROOT / "VERSION").strip() == "1.17.103" and json.loads(read(ROOT / "tec_tac_package.json"))["version"] == "1.17.103", "version")
for path in (APP / "module_repository.py", APP / "contracts.py", ROOT / "docs" / "module-repositories.md", ROOT / "docs" / "troubleshooting-diagnostics.md"):
    must(b"\r\n" in path.read_bytes() and b"\n" not in path.read_bytes().replace(b"\r\n", b""), f"{path.name} lost its CRLF")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh has CR")
print("       docs, troubleshooting (every message, footer last), contract rows, notes, version, line endings")
print("[TEST] PASS licensing repository 1.17.103")
