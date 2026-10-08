#!/usr/bin/env python3
"""1.17.3 regression: branch source online status.

A branch source no longer fetches GitHub's latest release (latest_release is null), and when no install
recorded a commit the branch state falls back to comparing VERSION files (CQ11). The stage contract entry
cannot drift from the view. Django is not installed on the development PC, so the real system_update.py is
loaded against stubs, as tests/update-source-1.17.2.py does. contracts.py and views.py are read by AST.
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

tmp = Path(tempfile.mkdtemp(prefix="update-source-1173-"))
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
VER = {"calls": [], "result": b"1.17.3\n"}


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


def fake_content(repo, path, ref):
    VER["calls"].append((repo, path, ref))
    result = VER["result"]
    if isinstance(result, Exception):
        raise result
    return result


su._github_json = fake_github
su._github_content_bytes = fake_content
BRANCH = {"type": "branch", "ref": "dev"}
RELEASE = {"type": "release", "ref": None}


def write_job(name, *, finished="2026-10-08T10:00:00Z", source=None):
    job = {"id": name, "component": "framework", "status": "succeeded", "finished_at": finished, "action": "install"}
    if source is not None:
        job["source"] = source
    (su.HISTORY_ROOT / f"{name}.json").write_text(json.dumps(job), encoding="utf-8")


def release_calls():
    return [u for u in GH["calls"] if u.endswith("/releases/latest") or "/commits/" in u]


# ------------------------------------------------------------------ item 1: no release call for a branch source
OLD_KEYS = {"component", "repository", "installed_version", "latest_release", "checked_at", "release_error", "cache"}
GH["calls"].clear()
out = su.online_status("framework", force=True, source=BRANCH)
must(release_calls() == [], f"a branch source must not call releases or commits: {GH['calls']}")
must(out["latest_release"] is None and out["release_error"] is None and out["checked_at"] is None, out)
must(OLD_KEYS | {"source", "branch", "branch_error"} == set(out), set(out))
must(out["component"] == "framework" and out["repository"] == REPO and out["installed_version"] == "1.17.2", out)
must(out["cache"] == {"hit": False, "stale": False, "ttl_hours": 24} and out["source"] == BRANCH and out["branch_error"] is None, out)
must(not su.RELEASE_CACHE.is_file() or "framework" not in json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))["components"],
     "a branch check must not write the release cache")
# A cached release is not read either: seed one, the branch answer still has no release.
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
doc["components"]["framework"] = {"repository": REPO, "checked_at": datetime.now(timezone.utc).isoformat(),
                                  "release": {"tag": "v9.9.9", "commit": SHA_B}}
su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")
out = su.online_status("framework", source=BRANCH)
must(out["latest_release"] is None, "the release cache must not be read for a branch source")
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
must("framework" in doc["components"] and "framework" in doc["branches"], "branches and components must coexist")
su.RELEASE_CACHE.unlink()

# A branch failure still sets branch_error only.
GH["branch_fail"] = True
out = su.online_status("framework", force=True, source={"type": "branch", "ref": "nope"})
must("Branch not found" in out["branch_error"] and out["release_error"] is None and out["latest_release"] is None, out)
must(out["branch"]["state"] == "unknown" and out["branch"]["differs"] is None and out["branch"]["basis"] is None, out["branch"])
GH["branch_fail"] = False

# Release and no source: same keys and values as before, and the release is fetched.
GH["calls"].clear()
plain = su.online_status("framework", force=True)
via_release = su.online_status("framework", force=True, source=RELEASE)
must(set(plain) == set(via_release) == OLD_KEYS, set(plain))
must(plain["latest_release"]["tag"] == "v1.17.1" and via_release["latest_release"]["tag"] == "v1.17.1", plain)
must(len([u for u in GH["calls"] if u.endswith("/releases/latest")]) == 2, GH["calls"])
must(su.online_status("framework", force=True, source={"type": "other"})["latest_release"]["tag"] == "v1.17.1", "a non-branch source is a release answer")
su.RELEASE_CACHE.unlink()


# ------------------------------------------------------------------ item 2: VERSION fallback
def branch(**kw):
    return su.online_status("framework", **kw, source=BRANCH)["branch"]


def fresh():
    GH["head"] = SHA_A
    VER["calls"].clear()
    VER["result"] = b"1.17.3\n"
    INSTALLED["v"] = "1.17.2"
    for f in su.HISTORY_ROOT.glob("*.json"):
        f.unlink()
    if su.RELEASE_CACHE.is_file():
        su.RELEASE_CACHE.unlink()


# (1) no job + equal VERSION
fresh()
VER["result"] = b"1.17.2\n"
b = branch(force=True)
must(b["state"] == "same" and b["differs"] is False and b["basis"] == "version", b)
must(b["head_version"] == "1.17.2" and b["installed_version"] == "1.17.2" and b["installed_commit"] is None, b)
# (2) different VERSION
fresh()
b = branch(force=True)
must(b["state"] == "differs" and b["differs"] is True and b["basis"] == "version" and b["head_version"] == "1.17.3", b)
# rebuild suffixes compare through _version_key (1.17.2-1 is newer than 1.17.2)
fresh()
VER["result"] = b"1.17.2-1"
must(branch(force=True)["state"] == "differs", "a rebuild suffix differs")
fresh()
VER["result"] = b"v1.17.2"
must(branch(force=True)["state"] == "same", "a leading v compares equal")
# (3) a recorded commit wins
fresh()
write_job("c1", source={"type": "branch", "repository": REPO, "ref": "dev", "commit": SHA_A})
VER["result"] = b"9.9.9"
b = branch(force=True)
must(b["state"] == "same" and b["differs"] is False and b["basis"] == "commit" and b["head_version"] is None and VER["calls"] == [], b)
GH["head"] = SHA_B
b = branch(force=True)
must(b["state"] == "differs" and b["basis"] == "commit" and VER["calls"] == [], "a commit that differs wins")
VER["result"] = b"1.17.2"
b = branch(force=True)
must(b["basis"] == "commit" and b["state"] == "differs" and VER["calls"] == [], "commit beats matching VERSIONs")
# (4) offline, other repository and pre-1.17.2 jobs fall back to version
for label, source in (("offline", {"type": "offline"}), ("other repo", {"type": "branch", "repository": "x/y", "ref": "dev", "commit": SHA_A}),
                      ("pre-1.17.2", None), ("no commit", {"type": "branch", "repository": REPO, "ref": "dev"})):
    fresh()
    write_job("j", source=source)
    VER["result"] = b"1.17.2"
    b = branch(force=True)
    must(b["state"] == "same" and b["basis"] == "version", (label, b))
# (5) unknown: 404, error, bad bytes, no installed VERSION, implausible strings; never branch_error
for label, result, installed in (("404", None, "1.17.2"), ("error", su.SystemUpdateError("GitHub request failed (500)"), "1.17.2"),
                                 ("os error", OSError("disk"), "1.17.2"), ("non-utf8", b"\xff\xfe\x00", "1.17.2"),
                                 ("no installed", b"1.17.3", None), ("html", b"<html>not found</html>", "1.17.2"),
                                 ("bad installed", b"1.17.3", "dev build"), ("empty", b"  \n", "1.17.2")):
    fresh()
    VER["result"] = result
    INSTALLED["v"] = installed
    out = su.online_status("framework", force=True, source=BRANCH)
    b = out["branch"]
    must(b["state"] == "unknown" and b["differs"] is None and b["basis"] is None and out["branch_error"] is None, (label, out))
    must(b["head_commit"] == SHA_A, (label, "head still resolved", b))
# (6) the read is against the head SHA, cached for the TTL, bypassed by force, refetched when the head moves
fresh()
branch(force=True)
must(VER["calls"] == [(REPO, "VERSION", SHA_A)], VER["calls"])
branch()
branch()
must(len(VER["calls"]) == 1, "a cached head_version is reused within 5 minutes")
row = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))["branches"]["framework"]
must(row["head_version"] == "1.17.3" and row["head_version_commit"] == SHA_A, row)
branch(force=True)
must(len(VER["calls"]) == 2, "force refetches")
GH["head"] = SHA_B
branch(force=True)
must(VER["calls"][-1] == (REPO, "VERSION", SHA_B), "the new head is read at its own SHA")
# a cached version recorded for another commit is not reused
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
doc["branches"]["framework"]["head_version_commit"] = SHA_A
su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")
n = len(VER["calls"])
branch()
must(len(VER["calls"]) == n + 1, "a cached version for another commit is not reused")
# an expired row refetches
doc = json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))
doc["branches"]["framework"]["checked_at"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")
n = len(VER["calls"])
branch()
must(len(VER["calls"]) == n + 1, "an expired cache refetches")
# a failed read is not cached
fresh()
VER["result"] = None
branch(force=True)
VER["result"] = b"1.17.3"
b = branch()
must(b["head_version"] == "1.17.3" and b["state"] == "differs", "a failed read must not be cached as unknown")

# ------------------------------------------------------------------ item 3: stage contract entry follows the view
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
entry = details["/api/tfd/system/updates/online/stage/"]["POST"]
views_src = (APP / "views.py").read_text(encoding="utf-8")
vtree = ast.parse(views_src)
cls = next(n for n in vtree.body if isinstance(n, ast.ClassDef) and n.name == "SystemUpdateOnlineStageView")
post = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "post")
read = set()
for node in ast.walk(post):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        base = node.func.value
        if isinstance(base, ast.Attribute) and base.attr == "data" and isinstance(node.args[0], ast.Constant):
            read.add(node.args[0].value)
must(read == {"component", "source_type", "ref"}, f"the stage view reads {read}")
must(set(entry["request"]) == read, "the contract must list the keys the view reads")
must("_require_module_manager" in ast.get_source_segment(views_src, post), "the view must require module manager rights")
online = details["/api/tfd/system/updates/online/"]["GET"]
for key in ("latest_release", "release_error", "source", "branch", "branch_error"):
    must(key in online["response"], f"online contract lacks {key}")
branch_text = online["response"]["branch"]
must("basis" in branch_text and "weaker" in branch_text and "VERSION" in branch_text, "the weaker version basis must be stated")
must("null" in online["response"]["latest_release"], "latest_release null for a branch source must be documented")
docs = (ROOT / "docs" / "update-source.md").read_text(encoding="utf-8")
must("weaker" in docs and "basis" in docs and "leaves the release data in place" not in docs, "docs/update-source.md must describe 1.17.3")

print("update-source 1.17.3: ok")
