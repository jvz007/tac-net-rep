#!/usr/bin/env python3
"""1.17.4 regression: the stable release is the secondary answer under a branch source.

online_status() with a branch source keeps latest_release null and adds stable_release (same GitHub fetch, 24-hour
cache and stale-on-error behaviour as a release source). cached_online_status(component, source) and system_status()
stop serving the stale release row as latest_release under a branch source. The contract entries match the code.
Django is not installed on the development PC, so the real system_update.py is loaded against stubs, as
tests/update-source-1.17.3.py does.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SHA_A = "a" * 40
SHA_B = "b" * 40
REPO = "jvz007/tac-net-rep"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ stubs
mods = {n: types.ModuleType(n) for n in ("tec_tac.safe_files", "tec_tac.trusted_publishers", "tec_tac.trust_policy")}
mods["tec_tac.safe_files"].atomic_json = lambda path, payload, **kw: Path(path).write_text(json.dumps(payload), encoding="utf-8")
mods["tec_tac.trusted_publishers"].PublisherTrustError = type("PublisherTrustError", (Exception,), {})
mods["tec_tac.trusted_publishers"].verify_release_manifest_signature = lambda *a, **k: None
mods["tec_tac.trusted_publishers"].verify_release_tree = lambda *a, **k: None
mods["tec_tac.trust_policy"].TrustPolicyError = type("TrustPolicyError", (Exception,), {})
mods["tec_tac.trust_policy"].acceptance = lambda *a, **k: {}
mods["tec_tac.trust_policy"].get_policy = lambda: {"minimum_level": "signed_development"}
mods["tec_tac.trust_policy"].require_accepted = lambda *a, **k: None
if "pwd" not in sys.modules:
    try:
        import pwd  # noqa: F401
    except ImportError:
        sys.modules["pwd"] = types.ModuleType("pwd")
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)
sys.modules["tec_tac"] = pkg
spec = importlib.util.spec_from_file_location("tec_tac.system_update", APP / "system_update.py")
su = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = su
spec.loader.exec_module(su)

tmp = Path(tempfile.mkdtemp(prefix="update-source-1174-"))
su.CACHE_ROOT = tmp / "cache"
su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"
su.HISTORY_ROOT = tmp / "history"
su.JOBS_ROOT = tmp / "jobs"
su.HISTORY_ROOT.mkdir()
su.JOBS_ROOT.mkdir()
su._read_config = dict
su._annotate_trust_acceptance = lambda trust: trust
su._release_signature_preview = lambda component, repo, commit: {"level": "signed_development"}
INSTALLED = {"v": "1.17.2"}
su._installed_version = lambda component: INSTALLED["v"]

GH = {"calls": [], "branch_fail": False, "head": SHA_A}
VER = {"result": b"1.17.3\n"}


def fake_github(url):
    GH["calls"].append(url)
    if url.endswith("/releases/latest"):
        return {"tag_name": "v1.17.1", "name": "1.17.1", "published_at": "2026-10-01T00:00:00Z", "html_url": "https://example/r"}
    if "/commits/" in url:
        return {"sha": SHA_B}
    if "/branches/" in url:
        if GH["branch_fail"]:
            raise su.SystemUpdateError("GitHub request failed (404): Branch not found")
        return {"name": "dev", "commit": {"sha": GH["head"], "commit": {"committer": {"date": "2026-10-08T09:30:00Z"}}}}
    raise AssertionError(url)


su._github_json = fake_github
su._github_content_bytes = lambda repo, path, ref: VER["result"]
BRANCH = {"type": "branch", "ref": "dev"}
RELEASE = {"type": "release", "ref": None}
OLD_KEYS = {"component", "repository", "installed_version", "latest_release", "checked_at", "release_error", "cache"}
BRANCH_KEYS = OLD_KEYS | {"source", "branch", "branch_error", "stable_release"}


def rcalls():
    return [u for u in GH["calls"] if u.endswith("/releases/latest")]


def reset():
    GH["calls"].clear()
    GH["branch_fail"] = False
    GH["head"] = SHA_A
    VER["result"] = b"1.17.3\n"
    INSTALLED["v"] = "1.17.2"
    if su.RELEASE_CACHE.is_file():
        su.RELEASE_CACHE.unlink()


# (1) branch primary, stable_release secondary, latest_release null
reset()
out = su.online_status("framework", force=True, source=BRANCH)
must(out["latest_release"] is None, out)
must(set(out) == BRANCH_KEYS, set(out))
sr = out["stable_release"]
must(sr["tag"] == "v1.17.1" and sr["commit"] == SHA_B and sr["operation"] == "downgrade", sr)
must(set(sr) == {"tag", "name", "published_at", "html_url", "commit", "release_trust", "operation"}, set(sr))
must(sr["release_trust"] == {"level": "signed_development"}, sr)
must(out["checked_at"] is not None and out["release_error"] is None and out["branch_error"] is None, out)
must(out["source"] == BRANCH and out["branch"]["head_commit"] == SHA_A, out)
must(len(rcalls()) == 1, GH["calls"])
plain = su.online_status("framework", force=True)
must(plain["latest_release"] == sr, (plain["latest_release"], sr))  # same shape as the release answer

# (2) the second call is served from cache; force bypasses it
reset()
su.online_status("framework", force=True, source=BRANCH)
GH["calls"].clear()
out = su.online_status("framework", source=BRANCH)
must(rcalls() == [] and not [u for u in GH["calls"] if "/commits/v" in u], f"a fresh cache must serve the release: {GH['calls']}")
must(out["stable_release"]["tag"] == "v1.17.1" and out["cache"]["hit"] is True and out["cache"]["stale"] is False, out)
su.online_status("framework", force=True, source=BRANCH)
must(len(rcalls()) == 1, "force bypasses the cache")
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
doc["components"]["framework"]["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")
GH["calls"].clear()
su.online_status("framework", source=BRANCH)
must(len(rcalls()) == 1, "a 25-hour-old cache refetches")

# (3) a GitHub release failure: release_error set, branch intact, branch_error null
reset()
good = su._github_json


def release_down(url):
    if url.endswith("/releases/latest"):
        raise su.SystemUpdateError("GitHub request failed (500)")
    return good(url)


su._github_json = release_down
out = su.online_status("framework", force=True, source=BRANCH)
must(out["release_error"] == "GitHub request failed (500)" and out["stable_release"] is None and out["latest_release"] is None, out)
must(out["branch_error"] is None and out["branch"]["head_commit"] == SHA_A and out["branch"]["state"] == "differs", out)
# stale-on-error: a cached release survives the failure as a stale stable_release
su._github_json = good
su.online_status("framework", force=True, source=BRANCH)
su._github_json = release_down
out = su.online_status("framework", force=True, source=BRANCH)
must(out["stable_release"]["tag"] == "v1.17.1" and out["cache"]["stale"] is True and out["release_error"], out)
must(out["branch_error"] is None, out)
su._github_json = good

# (4) a branch failure: branch_error set, stable_release intact, release_error null
reset()
GH["branch_fail"] = True
out = su.online_status("framework", force=True, source=BRANCH)
must("Branch not found" in out["branch_error"] and out["release_error"] is None, out)
must(out["stable_release"]["tag"] == "v1.17.1" and out["latest_release"] is None, out)
GH["branch_fail"] = False

# (5) a cache write failure becomes release_error, never an exception
reset()
real_write = su._write_release_cache


def failing_write(payload):
    raise OSError("disk full")


su._write_release_cache = failing_write
out = su.online_status("framework", force=True, source=BRANCH)
must(out["release_error"] and "OSError" in out["release_error"] and out["stable_release"] is None, out)
must(set(out) == BRANCH_KEYS and out["latest_release"] is None, out)
must(out["branch"]["head_commit"] == SHA_A, "the branch answer survives a release cache write failure")
su._write_release_cache = real_write

# (6) a release source or no source: the 1.17.3 answer, no stable_release key
reset()
for src in (None, RELEASE, {"type": "other"}):
    out = su.online_status("framework", force=True, source=src)
    must(set(out) == OLD_KEYS and "stable_release" not in out and out["latest_release"]["tag"] == "v1.17.1", (src, set(out)))

# (7) the held 1.17.3 Low: cached_online_status under a branch source
reset()
su.online_status("framework", force=True)  # seed the cache through a release check
GH["calls"].clear()
old = su.cached_online_status("framework")
must(set(old) == OLD_KEYS and old["latest_release"]["tag"] == "v1.17.1" and "stable_release" not in old, "no source: unchanged")
rel = su.cached_online_status("framework", RELEASE)
must(set(rel) == OLD_KEYS and rel["latest_release"]["tag"] == "v1.17.1", "release source: unchanged")
cb = su.cached_online_status("framework", BRANCH)
must(cb["latest_release"] is None and cb["stable_release"]["tag"] == "v1.17.1" and cb["source"] == BRANCH, cb)
must(set(cb) == OLD_KEYS | {"stable_release", "source"}, set(cb))
must(cb["cache"]["hit"] is True and cb["checked_at"] == old["checked_at"], cb)
must(GH["calls"] == [], "cached_online_status never calls GitHub")
su.RELEASE_CACHE.unlink()
empty = su.cached_online_status("framework", BRANCH)
must(empty["latest_release"] is None and empty["stable_release"] is None and empty["source"] == BRANCH and empty["cache"]["hit"] is False, empty)
must("stable_release" not in su.cached_online_status("framework"), "no source: no stable_release key")
must("stable_release" not in su._release_online_status("framework"), "_release_online_status is unchanged")

# (8) system_status passes each component's saved source
seen = {}
real_cached = su.cached_online_status
su.cached_online_status = lambda component, source=None: seen.setdefault(component, source) or {"component": component}
su._signed_release_min_version = lambda component: None
su._recent_history = lambda limit=12: []
saved = {"framework": BRANCH, "ui": RELEASE}
su._saved_update_sources = lambda: saved
status = su.system_status()
must(seen == saved and status["update_sources"] == saved, seen)
su.cached_online_status = real_cached
# end to end: a cached release row is the secondary line, not latest_release, under a saved branch source
reset()
su.online_status("framework", force=True)
su.online_status("ui", force=True)
status = su.system_status()
fw, ui = status["release_cache"]["framework"], status["release_cache"]["ui"]
must(fw["latest_release"] is None and fw["stable_release"]["tag"] == "v1.17.1" and fw["source"] == BRANCH, fw)
must(ui["latest_release"]["tag"] == "v1.17.1" and "stable_release" not in ui, ui)

# (9) contract entries and docs match the code keys
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
online = details["/api/tfd/system/updates/online/"]["GET"]["response"]
for key in BRANCH_KEYS - {"component", "repository", "installed_version"}:
    must(key in online, f"online contract lacks {key}")
must("not fetched" not in online["latest_release"] and "not fetched" not in online["release_error"], "the 1.17.3 note must be replaced")
must("non-null for a branch source" in online["release_error"] and "never sets branch_error" in online["release_error"], online["release_error"])
listing = details["/api/tfd/system/updates/"]["GET"]["response"]
must("release_cache" in listing and "stable_release" in listing["release_cache"] and "latest_release null" in listing["release_cache"], listing)
docs = (ROOT / "docs" / "update-source.md").read_text(encoding="utf-8")
must("stable_release" in docs and "does not call GitHub releases" not in docs and "Release data is not fetched" not in docs, "docs/update-source.md must describe 1.17.4")

print("update-source 1.17.4: ok")
