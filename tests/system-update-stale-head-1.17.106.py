#!/usr/bin/env python3
"""1.17.106 regression: a stale branch head is never offered as current, and a branch stage never downgrades silently.

On dev02 (3 November 2026) GET /online/?refresh=none answered a branch head saved the day before (1.17.99) with
refresh.reason cache_fresh, while dev had moved to 1.17.105. The update-check lock could not be taken, so the saved
head came back as if fresh. The stage route accepted that commit because it matched the saved copy, and staged
1.17.99 as a downgrade. This test checks: a stale head is flagged (head_stale, reason not_refreshed, refresh.stale);
the lock failure sets branch_error; a stage re-resolves the head on the server and refuses an old commit with the
current head named; a head that cannot be confirmed is refused; the rate-limit block and the 20-second guard still
hold; a lower version is flagged as a downgrade; and a deliberate downgrade still installs with allow_downgrade.
Django, pwd and (on Windows) fcntl are not available on the development PC, so the real system_update.py is loaded
against stubs and a fake _github_open that counts every outbound request. Nothing here reaches the network.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import time
import types
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SHA_A, SHA_C = "a" * 40, "c" * 40
UTC = timezone.utc


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ stubs and loader
mods = {n: types.ModuleType(n) for n in ("tec_tac.safe_files", "tec_tac.trusted_publishers", "tec_tac.trust_policy", "tec_tac.module_job_logs")}
mods["tec_tac.safe_files"].atomic_json = lambda path, payload, **kw: Path(path).write_text(json.dumps(payload), encoding="utf-8")
mods["tec_tac.trusted_publishers"].PublisherTrustError = type("PublisherTrustError", (Exception,), {})
mods["tec_tac.trusted_publishers"].verify_release_manifest_signature = lambda *a, **k: {"verified": True}
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
pkg.module_job_logs = mods["tec_tac.module_job_logs"]
spec = importlib.util.spec_from_file_location("tec_tac.system_update", APP / "system_update.py")
su = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = su
spec.loader.exec_module(su)

su._read_config = dict
su._annotate_trust_acceptance = lambda trust: trust
INSTALLED = {"version": "1.17.104"}
su._installed_version = lambda component: INSTALLED["version"]
su._installed_source_commit = lambda component, repo: ("b" * 40, {"type": "branch", "ref": "dev"})
BRANCH = {"type": "branch", "ref": "dev"}
REPO_KEY = "jvz007/tac-net-rep:dev"

# ------------------------------------------------------------------ the fake GitHub
G = {"calls": [], "head": SHA_A}


class Resp:
    def __init__(self, body, headers):
        self._body = json.dumps(body).encode()
        self.headers = headers

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def headers():
    return {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "50", "X-RateLimit-Used": "10",
            "X-RateLimit-Reset": str(int(time.time()) + 3600), "X-RateLimit-Resource": "core"}


def fake_open(request, *, timeout):
    url = request.full_url
    G["calls"].append(url)
    if "/branches/" not in url:
        raise AssertionError(url)
    etag = f"b-{G['head'][:4]}"
    h = {**headers(), "ETag": etag}
    sent = {k.lower(): v for k, v in request.headers.items()}
    if sent.get("if-none-match") == etag:
        raise urllib.error.HTTPError(url, 304, "not modified", h, io.BytesIO(b""))
    return Resp({"name": "dev", "commit": {"sha": G["head"], "commit": {"committer": {"date": "2026-11-03T09:00:00Z"}}}}, h)


su._github_open = fake_open
su._github_headers = lambda: {"Accept": "x"}
downloads = []
su._download_to_stage = lambda url, *, filename, source, component: downloads.append(source) or {"source": source}


def reset():
    tmp = Path(tempfile.mkdtemp(prefix="gh-stale-11706-"))
    su.CACHE_ROOT = tmp / "cache"
    su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"
    su.HISTORY_ROOT, su.JOBS_ROOT, su.STAGED_ROOT = tmp / "history", tmp / "jobs", tmp / "staged"
    G.update(calls=[], head=SHA_A)
    downloads.clear()
    return tmp


def cache():
    return json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))


def put_cache(mutator):
    doc = cache()
    mutator(doc)
    su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")


def age(seconds):
    old = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()

    def mutate(doc):
        for row in doc.get("branch_sources", {}).values():
            row["checked_at"] = row["last_network_check"] = old
        for row in doc.get("github", {}).get("etags", {}).values():
            row["checked_at"] = old

    put_cache(mutate)


def block_rate_limit():
    def mutate(doc):
        doc.setdefault("github", {})["rate_limit"] = {
            "limited": True, "reset_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(), "limit": 60, "remaining": 0,
        }

    put_cache(mutate)


REAL_LOCK = su._refresh_lock


@contextlib.contextmanager
def lock_unavailable(*a, **k):
    yield False


# ------------------------------------------------------------------ (1) a fresh head is cache_fresh, and says what else is old
reset()
out = su.online_status("framework", source=BRANCH)
must(out["refresh"]["reason"] == "cache_stale" and out["branch"]["head_stale"] is False and out["branch"]["head_checked_at"], out)
out = su.online_status("framework", source=BRANCH)
must(out["refresh"]["reason"] == "cache_fresh" and out["branch"]["head_stale"] is False, out["refresh"])
must(out["refresh"]["stale"] == ["stable_release"] and out["cache"]["stale"] is True, out["refresh"])
print("       fresh head: cache_fresh, head_stale false; refresh.stale names the old stable release (the dev02 contradiction explained)")

# ------------------------------------------------------------------ (2) the dev02 case: stale head, lock not available, refresh=none
reset()
su.online_status("framework", source=BRANCH)
age(26 * 3600)
G["head"] = SHA_C
calls = len(G["calls"])
su._refresh_lock = lock_unavailable
out = su.online_status("framework", source=BRANCH, refresh="none")
su._refresh_lock = REAL_LOCK
must(len(G["calls"]) == calls, "no request when the lock is not held")
must(out["refresh"]["reason"] == "not_refreshed" and out["refresh"]["network_request"] is False, out["refresh"])
must(out["branch"]["head_commit"] == SHA_A and out["branch"]["head_stale"] is True, out["branch"])
must("branch_head" in out["refresh"]["stale"] and out["branch_error"] and "lock" in out["branch_error"], (out["refresh"], out["branch_error"]))
print("       stale head + lock not available: reason not_refreshed, head_stale true, branch_error set, no request")

# a stale head with GitHub reachable is refreshed by one conditional request
out = su.online_status("framework", source=BRANCH, refresh="none")
must(len(G["calls"]) == calls + 1 and out["branch"]["head_commit"] == SHA_C and out["branch"]["head_stale"] is False, out["branch"])
must(out["refresh"]["reason"] == "cache_stale" and "branch_head" not in out["refresh"]["stale"], out["refresh"])
print("       stale head + GitHub reachable: one request, the moved head, head_stale false")

# rate limit: the saved head is shown as stale, nothing is sent
age(26 * 3600)
block_rate_limit()
calls = len(G["calls"])
out = su.online_status("framework", source=BRANCH, refresh="none")
must(len(G["calls"]) == calls and out["refresh"]["reason"] == "rate_limited" and out["branch"]["head_stale"] is True, (out["refresh"], out["branch"]))
must("branch_head" in out["refresh"]["stale"], out["refresh"])
print("       rate limit exhausted: no request, head_stale true, reason rate_limited")

# a release source with a stale saved release that cannot be refreshed is not cache_fresh
reset()
put = {
    "schema": 2,
    "components": {"framework": {"repository": "jvz007/tac-net-rep", "checked_at": (datetime.now(UTC) - timedelta(hours=30)).isoformat(),
                                 "latest_release": {"tag": "1.15.189", "commit": SHA_A, "release_trust": {}}}},
}
su.CACHE_ROOT.mkdir(parents=True)
su.RELEASE_CACHE.write_text(json.dumps(put), encoding="utf-8")
su._refresh_lock = lock_unavailable
out = su.online_status("framework", source={"type": "release", "ref": None})
su._refresh_lock = REAL_LOCK
must(out["refresh"]["reason"] == "not_refreshed" and out["refresh"]["stale"] == ["latest_release"], out["refresh"])
print("       release source: a stale release that could not be refreshed reads not_refreshed")

# ------------------------------------------------------------------ (3) the stage re-resolves the head
reset()
su.online_status("framework", source=BRANCH)
age(30)  # past the 20-second guard
G["head"] = SHA_C
calls = len(G["calls"])
try:
    su.stage_online_package("framework", "branch", "dev", commit=SHA_A)
    raise AssertionError("an old commit must be refused")
except su.StaleCandidateError as exc:
    must(exc.code == "stale_candidate" and "dev has moved to ccccccc" in str(exc) and "aaaaaaa" in str(exc), str(exc))
    must("Refresh the check and try again" in str(exc), str(exc))
must(len(G["calls"]) == calls + 1 and not downloads, "one request, nothing downloaded")
must(cache()["branch_sources"][REPO_KEY]["head_commit"] == SHA_C, "the saved head is the current one")
print("       old commit: refused with 'dev has moved to ccccccc', one request, nothing downloaded")

# the current commit stages; inside 20 s of that check no further request is sent (the guard)
calls = len(G["calls"])
su.stage_online_package("framework", "branch", "dev", commit=SHA_C)
must(len(G["calls"]) == calls and downloads[-1]["commit"] == SHA_C, (G["calls"], downloads))
# after the guard, one conditional request (a 304) confirms it
age(30)
su.stage_online_package("framework", "branch", "dev", commit=SHA_C.upper())
must(len(G["calls"]) == calls + 1 and len(downloads) == 2, G["calls"])
print("       current commit: staged; inside 20 s no request, after it one conditional request")

# a head that cannot be confirmed (rate limit, saved head older than 5 minutes) is refused with no request
age(400)
block_rate_limit()
calls = len(G["calls"])
try:
    su.stage_online_package("framework", "branch", "dev", commit=SHA_C)
    raise AssertionError("an unconfirmed head must be refused")
except su.StaleCandidateError as exc:
    must("could not confirm the current head of dev" in str(exc), str(exc))
must(len(G["calls"]) == calls and len(downloads) == 2, "no request while the limit is exhausted")
# inside the 5-minute limit the saved head still stands, still with no request
age(60)
su.stage_online_package("framework", "branch", "dev", commit=SHA_C)
must(len(G["calls"]) == calls and len(downloads) == 3, "rate limit + head confirmed 60 s ago: staged, no request")
print("       rate limit: a head older than 5 minutes is refused, a 60-second-old one stands; no request either way")

# the lock not available + stale head: refused
reset()
su.online_status("framework", source=BRANCH)
age(400)
su._refresh_lock = lock_unavailable
try:
    su.stage_online_package("framework", "branch", "dev", commit=SHA_A)
    raise AssertionError("lock not available + stale head must be refused")
except su.StaleCandidateError:
    pass
finally:
    su._refresh_lock = REAL_LOCK
must(not downloads, "nothing downloaded")
print("       lock not available and stale head: refused")

# ------------------------------------------------------------------ (4) the downgrade flag, and the deliberate downgrade path
tmp = reset()


def framework_zip(version):
    path = tmp / f"framework-{version}.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("repo/VERSION", version + "\n")
        zf.writestr("repo/install.sh", "#!/bin/bash\n")
        zf.writestr("repo/framwork/tec_tac/__init__.py", "")
        zf.writestr("repo/tec_tac_package.json", json.dumps({"type": "tec-tac-framework", "version": version}))
    return path


su._unsigned_release_trust = lambda **k: {"signed": False, "state": "unsigned"}
su._accept_update_trust = lambda trust, subject: {"accepted": True}
INSTALLED["version"] = "1.17.104"
pre = su.inspect_archive(framework_zip("1.17.99"), source={"type": "branch", "ref": "dev", "commit": SHA_A})
must(pre["operation"] == "downgrade" and pre["downgrade"] is True and pre["confirmation_required"] == "downgrade", pre)
must("1.17.99" in pre["downgrade_warning"] and "1.17.104" in pre["downgrade_warning"] and "downgrade" in pre["downgrade_warning"], pre["downgrade_warning"])
pre = su.inspect_archive(framework_zip("1.17.105"))
must(pre["operation"] == "update" and pre["downgrade"] is False and pre["confirmation_required"] is None and pre["downgrade_warning"] is None, pre)
print("       a lower version: operation downgrade, downgrade true, confirmation_required downgrade, a warning naming both versions")

# install: a downgrade needs allow_downgrade; with it (the deliberate stable downgrade) it is queued
su._dispatch = lambda job_id: None
su.public_job = lambda job, **k: job  # the job view is not under test
su._load_stage = lambda upload_id: {"preview": {
    "component": "framework", "version": "1.15.189", "operation": "downgrade", "installable": True, "downgrade": True,
    "release_trust": {}, "source": {"type": "release", "ref": "1.15.189", "commit": SHA_A},
}}
try:
    su.queue_install("00000000-0000-0000-0000-000000000000")
    raise AssertionError("a downgrade without allow_downgrade must be refused")
except su.SystemUpdateError as exc:
    must("allow_downgrade" in str(exc), str(exc))
job = su.queue_install("00000000-0000-0000-0000-000000000000", allow_downgrade=True, requested_by="admin")
must(job["operation"] == "downgrade" and job["allow_downgrade"] is True, job)
print("       install: a downgrade without allow_downgrade is refused; the deliberate stable downgrade with it is queued")

# ------------------------------------------------------------------ (5) contract text
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(x.value) for x in contracts.body if isinstance(x, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in x.targets))
online = json.dumps(details["/api/tfd/system/updates/online/"]["GET"])
for needle in ("head_stale", "head_checked_at", "not_refreshed", "branch_head", "1.17.106"):
    must(needle in online, f"online contract lacks {needle}")
stage = json.dumps(details["/api/tfd/system/updates/online/stage/"]["POST"])
for needle in ("re-resolves the head", "confirmation_required", "downgrade_warning", "allow_downgrade", "has moved to"):
    must(needle in stage, f"stage contract lacks {needle}")
print("       contract text: online and stage routes updated additively")

print("[TEST] PASS system update stale head 1.17.106")
