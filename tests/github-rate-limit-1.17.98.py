#!/usr/bin/env python3
"""1.17.98 regression: GitHub rate-limit optimisation (one transport, ETags, single flight, suppression, pinned stage).

Core's online update check used to cost four to ten GitHub REST calls per component per click and one more call for every
page load that found a stale cache. 1.17.98 sends one conditional request for a branch refresh, keeps the stable release
independent, saves the VERSION and the signature preview by commit, shares one refresh between workers, records the
rate-limit headers, stops asking while the limit is exhausted, and lets the stage step install exactly the commit the check
showed. Django, pwd and (on Windows) fcntl are not available on the development PC, so the real system_update.py is loaded
against stubs and a fake _github_open that counts every outbound request. The two-process test needs fcntl and is skipped
with a plain message on Windows. Nothing here reaches the network.
"""
from __future__ import annotations

import ast
import base64
import importlib.util
import io
import json
import sys
import tempfile
import threading
import time
import types
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40
TOKEN = "ghp_SECRETTOKENVALUE0123456789"
UTC = timezone.utc


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ stubs and loader
mods = {n: types.ModuleType(n) for n in ("tec_tac.safe_files", "tec_tac.trusted_publishers", "tec_tac.trust_policy")}
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
spec = importlib.util.spec_from_file_location("tec_tac.system_update", APP / "system_update.py")
su = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = su
spec.loader.exec_module(su)

POLICY = {"minimum_level": "signed_development"}
su.get_trust_policy = lambda: dict(POLICY)
su._read_config = dict
su._annotate_trust_acceptance = lambda trust: trust
su._installed_version = lambda component: "1.17.97"
INSTALLED_COMMIT = {"sha": SHA_A}
su._installed_source_commit = lambda component, repo: (INSTALLED_COMMIT["sha"], {"type": "branch", "ref": "dev"})
BRANCH = {"type": "branch", "ref": "dev"}
RELEASE = {"type": "release", "ref": None}

# ------------------------------------------------------------------ the fake GitHub
G = {"calls": [], "headers": [], "head": SHA_A, "release_sha": SHA_B, "auth": False, "delay": 0.0, "fail": None, "limit_remaining": 4999}
LOCK = threading.Lock()


class Resp:
    def __init__(self, body, headers=None):
        self._body = json.dumps(body).encode()
        self.headers = headers or {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code, headers=None, body=b'{"message":"x"}'):
    return urllib.error.HTTPError("https://api.github.com/x", code, "msg", headers or {}, io.BytesIO(body))


def rl_headers(remaining=None, reset_in=3600):
    remaining = G["limit_remaining"] if remaining is None else remaining
    return {"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": str(remaining), "X-RateLimit-Used": str(5000 - remaining),
            "X-RateLimit-Reset": str(int(time.time()) + reset_in), "X-RateLimit-Resource": "core"}


def serve(url):
    if "/releases/latest" in url:
        return {"tag_name": "v1.18.0", "name": "1.18.0", "published_at": "2026-11-01T00:00:00Z", "html_url": "https://example/r"}, "r-etag"
    if "/commits/" in url:
        return {"sha": G["release_sha"], "files": [{"filename": "big"}] * 5}, f"c-{G['release_sha'][:4]}"
    if "/branches/" in url:
        return {"name": "dev", "commit": {"sha": G["head"], "commit": {"committer": {"date": "2026-11-01T09:00:00Z"}}}}, f"b-{G['head'][:4]}"
    if "/branches?" in url:
        return [{"name": "dev", "commit": {"sha": G["head"]}}], "l-etag"
    if "/contents/" in url:
        name = url.split("/contents/")[1].split("?")[0]
        data = b"1.18.0\n" if name == "VERSION" else b"{}"
        return {"type": "file", "encoding": "base64", "content": base64.b64encode(data).decode()}, None
    raise AssertionError(url)


def fake_open(request, *, timeout):
    url = request.full_url
    with LOCK:
        G["calls"].append(url)
        G["headers"].append(dict(request.headers))
    if G["delay"]:
        time.sleep(G["delay"])
    if G["fail"]:
        result = G["fail"](url)
        if result is not None:
            raise result
    body, etag = serve(url)
    sent = {k.lower(): v for k, v in request.headers.items()}
    headers = rl_headers()
    if etag:
        headers["ETag"] = etag
        if sent.get("if-none-match") == etag:
            raise http_error(304, headers, b"")
    return Resp(body, headers)


su._github_open = fake_open
su._github_headers = lambda: {"Accept": "x", **({"Authorization": f"Bearer {TOKEN}"} if G["auth"] else {})}
su.BRANCH_SUPPRESS_SECONDS = 20
su.RELEASE_SUPPRESS_SECONDS = 45
PREVIEW = {"calls": 0}


def fake_preview(component, repo, commit):
    PREVIEW["calls"] += 1
    return {"signed": True, "verified": True, "state": "verified"}


REAL_PREVIEW = su._release_signature_preview
su._release_signature_preview = fake_preview
real_content = su._github_content_bytes
workdir = [None]


def reset():
    tmp = Path(tempfile.mkdtemp(prefix="gh-rl-1198-"))
    workdir[0] = tmp
    su.CACHE_ROOT = tmp / "cache"
    su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"
    su.HISTORY_ROOT, su.JOBS_ROOT = tmp / "history", tmp / "jobs"
    G.update(calls=[], headers=[], head=SHA_A, release_sha=SHA_B, auth=False, delay=0.0, fail=None, limit_remaining=4999)
    PREVIEW["calls"] = 0
    INSTALLED_COMMIT["sha"] = SHA_A
    su._github_content_bytes = real_content


def n(kind=None):
    return len([u for u in G["calls"] if kind is None or kind in u])


def cache():
    return json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))


def put_cache(mutator):
    doc = cache()
    mutator(doc)
    su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")


def age(seconds):
    """Make every saved check look ``seconds`` old."""
    old = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()

    def mutate(doc):
        for row in doc.get("components", {}).values():
            row["checked_at"] = old
        for row in doc.get("branch_sources", {}).values():
            row["checked_at"] = row["last_network_check"] = old
        for row in doc.get("branches", {}).values():
            row["checked_at"] = old
        for row in doc["github"]["etags"].values():
            row["checked_at"] = old

    put_cache(mutate)


# ------------------------------------------------------------------ (1) fresh caches cost nothing; stale costs one
reset()
out = su.online_status("framework", source=BRANCH)
must(n() == 1 and n("/branches/dev") == 1, G["calls"])
must({k: out["refresh"][k] for k in ("network_request", "reason", "requested")} == {"network_request": True, "reason": "cache_stale", "requested": "none"}, out["refresh"])
must(out["branch"]["head_commit"] == SHA_A and out["branch"]["state"] == "same" and out["stable_release"] is None, out)
out = su.online_status("framework", source=BRANCH)
must(n() == 1 and out["refresh"]["network_request"] is False and out["refresh"]["reason"] == "cache_fresh", (G["calls"], out["refresh"]))
print("       branch: empty cache = 1 request, fresh cache = 0")

reset()
su.online_status("framework", source=RELEASE)
must(n("/releases/latest") == 1 and n("/commits/") == 1 and n("/contents/") == 0 and PREVIEW["calls"] == 1, G["calls"])
before = n()
out = su.online_status("framework", source=RELEASE)
must(n() == before and out["latest_release"]["tag"] == "v1.18.0" and out["refresh"]["network_request"] is False, G["calls"])
print("       release: fresh cache = 0 requests")

# stale branch = exactly one conditional request; a 304 refreshes checked_at and returns the saved body
reset()
su.online_status("framework", source=BRANCH)
age(400)
stamp = cache()["branch_sources"]["jvz007/tac-net-rep:dev"]["checked_at"]
G["headers"].clear()
before = n()
out = su.online_status("framework", source=BRANCH)
must(n() == before + 1, G["calls"])
sent = {k.lower(): v for k, v in G["headers"][-1].items()}
must(sent.get("if-none-match") == f"b-{SHA_A[:4]}", sent)
row = cache()["branch_sources"]["jvz007/tac-net-rep:dev"]
must(out["branch"]["head_commit"] == SHA_A and row["checked_at"] > stamp and row["head_commit"] == SHA_A and row["etag"], row)
must(cache()["github"]["etags"][f"https://api.github.com/repos/jvz007/tac-net-rep/branches/dev"]["body"]["commit"]["sha"] == SHA_A, "saved body")
print("       stale branch = 1 request with If-None-Match; 304 refreshes checked_at and keeps the body")

# a changed head returns 200 and replaces body and ETag
G["head"] = SHA_C
age(400)
out = su.online_status("framework", source=BRANCH)
must(out["branch"]["head_commit"] == SHA_C and out["branch"]["state"] == "differs", out["branch"])
print("       a moved head is read as a 200")

# ------------------------------------------------------------------ (2) the token never leaves the headers
reset()
G["auth"] = True
out = su.online_status("framework", source=BRANCH, refresh="all")
text = json.dumps(out) + su.RELEASE_CACHE.read_text(encoding="utf-8")
must(TOKEN not in text and "Bearer" not in text, "the token reached an answer or the cache")
must(all(h.get("Authorization") == f"Bearer {TOKEN}" for h in G["headers"]), "the token is sent to GitHub")
tel = out["github_rate_limit"]
must(tel["authenticated"] is True and tel["limit"] == 5000 and tel["remaining"] == 4999 and tel["resource"] == "core" and tel["reset_at"], tel)
must(set(tel) == {"limit", "remaining", "used", "reset", "reset_at", "resource", "authenticated", "observed_at", "limited"}, set(tel))
G["auth"] = False
age(400)
out = su.online_status("framework", source=BRANCH)
must(out["github_rate_limit"]["authenticated"] is False, "authenticated says whether an Authorization header was sent")
print("       rate-limit telemetry saved (also from 304s); token never stored, logged or returned")

# ------------------------------------------------------------------ (3) exhaustion
reset()
su.online_status("framework", source=BRANCH)
age(400)
reset_ts = int(time.time()) + 1800
G["fail"] = lambda url: http_error(403, {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "0", "X-RateLimit-Used": "60", "X-RateLimit-Reset": str(reset_ts)})
before = n()
out = su.online_status("framework", source=BRANCH)
err = out["github_rate_limit_error"]
must(n() == before + 1, G["calls"])
must(err["code"] == "github_rate_limit_exceeded" and err["detail"] == "GitHub API rate limit exhausted." and err["cached_data_available"] is True and err["reset_at"], err)
must(out["branch"]["head_commit"] == SHA_A, "the stale cache is kept and shown")
must(out["github_rate_limit"]["limited"] is True and out["refresh"]["reason"] == "rate_limited" or out["refresh"]["network_request"] is True, out["refresh"])
G["fail"] = None
before = n()
out = su.online_status("framework", source=BRANCH)
must(n() == before and out["github_rate_limit_error"]["cached_data_available"] is True and out["refresh"]["reason"] == "rate_limited", (G["calls"], out.get("refresh")))
out = su.online_status("framework", source=BRANCH, refresh="all")
must(n() == before and "github_rate_limit_error" in out, "no automatic retry before the reset time, forced or not")
print("       403 with remaining 0: structured error, stale cache shown, second call before reset = 0 requests")

# the reset time passes: asking resumes
put_cache(lambda d: d["github"]["rate_limit"].update(reset_at=(datetime.now(UTC) - timedelta(seconds=5)).isoformat()))
age(400)
out = su.online_status("framework", source=BRANCH)
must(n() == before + 1 and "github_rate_limit_error" not in out, G["calls"])
print("       after the reset time the check resumes")

# 429 with Retry-After, nothing saved: 429 error carries cached_data_available false
reset()
G["fail"] = lambda url: http_error(429, {"Retry-After": "120"})
try:
    su.online_status("framework", source=BRANCH)
    raise AssertionError("expected GithubRateLimitError")
except su.GithubRateLimitError as exc:
    must(exc.code == "github_rate_limit_exceeded" and exc.cached_data_available is False and exc.reset_at, exc)
    must(exc.as_dict()["detail"] == "GitHub API rate limit exhausted.", exc.as_dict())
G["fail"] = None
before = n()
try:
    su.online_status("framework", source=RELEASE)
    raise AssertionError("expected GithubRateLimitError for the release source too")
except su.GithubRateLimitError:
    pass
must(n() == before, "Retry-After blocks the next request too")
print("       429 + Retry-After: error with cached_data_available false when nothing is saved; blocked until it passes")

# 401 and 403 that are not a rate limit are never saved as a success
for code, hdrs in ((401, {}), (403, {"X-RateLimit-Remaining": "40"})):
    reset()
    G["fail"] = lambda url, code=code, hdrs=hdrs: http_error(code, hdrs)
    out = su.online_status("framework", source=BRANCH)
    must(out["branch_error"] and str(code) in out["branch_error"] and out["branch"]["head_commit"] is None, (code, out))
    must("github_rate_limit_error" not in out, "an authorization failure is not a rate limit")
    etags = cache()["github"]["etags"] if su.RELEASE_CACHE.is_file() else {}
    must(not any("/branches/" in k for k in etags) and not cache().get("branch_sources"), (code, etags))
    G["fail"] = None
    before = n()
    out = su.online_status("framework", source=BRANCH)
    must(n() == before + 1 and out["branch"]["head_commit"] == SHA_A, "no failure answer was cached")
print("       401 and 403 (not rate limit) are errors and never cached as a success")

# ------------------------------------------------------------------ (4) single flight
reset()
G["delay"] = 0.4
results = []


def worker(**kw):
    results.append(su.online_status("framework", **kw))


threads = [threading.Thread(target=worker, kwargs={"source": BRANCH, "refresh": "branch"}) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
must(n("/branches/dev") == 1 and len(results) == 8 and all(r["branch"]["head_commit"] == SHA_A for r in results), G["calls"])
print("       8 threads refreshing a branch at once = 1 outbound request")

reset()
G["delay"] = 0.4
results.clear()
threads = [threading.Thread(target=worker, kwargs={"source": RELEASE, "refresh": "release"}) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
must(n("/releases/latest") == 1 and n("/commits/") == 1 and len(results) == 8 and all(r["latest_release"]["tag"] == "v1.18.0" for r in results), G["calls"])
print("       8 threads refreshing the release at once = 1 release request, 1 commit request")

try:
    import fcntl  # noqa: F401
    HAVE_FCNTL = True
except ImportError:
    HAVE_FCNTL = False
if HAVE_FCNTL:
    import multiprocessing

    reset()
    counter = workdir[0] / "calls.txt"

    def child(cache_root):
        su.CACHE_ROOT = Path(cache_root)
        su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"

        def slow_open(request, *, timeout):
            with open(counter, "a", encoding="utf-8") as fh:
                fh.write(request.full_url + "\n")
            time.sleep(0.6)
            return fake_open(request, timeout=timeout)

        su._github_open = slow_open
        su.online_status("framework", source=BRANCH, refresh="branch")

    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=child, args=(str(su.CACHE_ROOT),)) for _ in range(2)]
    [p.start() for p in procs]
    [p.join() for p in procs]
    must(len([line for line in counter.read_text().splitlines() if "/branches/dev" in line]) == 1, counter.read_text())
    su._github_open = fake_open
    print("       a second process refreshing at once = 1 outbound request (fcntl.flock)")
else:
    print("       SKIPPED on this PC: the two-process single-flight test needs fcntl (runs on the dev server and Linux)")

# a lock that cannot be taken fails closed to the cache, never to a second request
reset()
su.online_status("framework", source=BRANCH)
age(400)
real_lock = su._file_lock
import contextlib  # noqa: E402


@contextlib.contextmanager
def no_lock(path, timeout):
    yield False


su._file_lock = no_lock
before = n()
out = su.online_status("framework", source=BRANCH)
must(n() == before and out["branch"]["head_commit"] == SHA_A, "lock failure: saved head shown, no request")
su._file_lock = real_lock
print("       a lock that cannot be taken fails closed to the cache")

# ------------------------------------------------------------------ (5) suppression
reset()
G["delay"] = 0.0
su.online_status("framework", source=BRANCH, refresh="branch")
outs = [su.online_status("framework", source=BRANCH, refresh="branch") for _ in range(9)]
must(n("/branches/dev") == 1, G["calls"])
must(all({k: o["refresh"][k] for k in ("network_request", "reason", "requested")} == {"network_request": False, "reason": "recently_refreshed", "requested": "branch"} for o in outs), outs[0]["refresh"])
age(30)  # older than 20 s: a forced branch refresh goes out again
su.online_status("framework", source=BRANCH, refresh="branch")
must(n("/branches/dev") == 2, G["calls"])
print("       10 rapid forced branch refreshes = 1 request, 'recently_refreshed' on the rest; after 20 s it asks again")

reset()
su.online_status("framework", source=RELEASE, refresh="release")
before = n()
out = su.online_status("framework", source=RELEASE, refresh="release")
must(n() == before and out["refresh"]["reason"] == "recently_refreshed", out["refresh"])
age(30)
su.online_status("framework", source=RELEASE, refresh="release")
must(n() == before, "inside the 45 s release window")
age(50)
su.online_status("framework", source=RELEASE, refresh="release")
must(n() > before, "after 45 s a forced release refresh asks again")
print("       forced release refresh: suppressed for 45 s")

# ------------------------------------------------------------------ (6) cache file schema 2
reset()
su.CACHE_ROOT.mkdir(parents=True)
su.RELEASE_CACHE.write_text(json.dumps({"schema": 1, "components": {}, "branches": {"framework": {
    "repository": "jvz007/tac-net-rep", "ref": "dev", "checked_at": datetime.now(UTC).isoformat(), "head_commit": SHA_A, "head_date": "d"}}}), encoding="utf-8")
doc = su._read_release_cache()
must(doc["schema"] == 2 and doc["branch_sources"] == {} and doc["commit_metadata"] == {} and doc["release_verification"] == {} and doc["github"]["etags"] == {}, doc)
out = su.online_status("framework", source=BRANCH)
must(n() == 0 and out["branch"]["head_commit"] == SHA_A, "a schema 1 branch row is still honoured")
su.online_status("framework", source=BRANCH, refresh="release")
doc = cache()
must(doc["schema"] == 2 and "components" in doc and "branches" in doc and "branch_sources" in doc, "schema 1 is upgraded in place by the next write")
for bad in ("not json {{", "[1, 2]", json.dumps({"schema": 2})):
    su.RELEASE_CACHE.write_text(bad, encoding="utf-8")
    must(su._read_release_cache() == su._empty_cache(), bad)
    out = su.online_status("framework", source=BRANCH)
    must(out["branch"]["head_commit"] == SHA_A and cache()["schema"] == 2, "a corrupt or wrong-shape file reads as empty and is rewritten")
print("       schema 1 is read and upgraded; a corrupt or wrong-shape file is rebuilt")

# ------------------------------------------------------------------ (7) refresh values and the force alias
reset()
for bad in ("everything", "BRANCHES", "1"):
    try:
        su.online_status("framework", source=BRANCH, refresh=bad)
        raise AssertionError(bad)
    except su.SystemUpdateError as exc:
        must("refresh must be" in str(exc), exc)
reset()
su.online_status("framework", source=BRANCH, refresh="branch")
must(n("/branches/dev") == 1 and n("/releases/") == 0, "refresh=branch never touches the release")
reset()
su.online_status("framework", source=BRANCH, refresh="release")
must(n("/branches/dev") == 1 and n("/releases/latest") == 1, "refresh=release refreshes the release (the branch is empty, so it loads once)")
reset()
su.online_status("framework", source=BRANCH)
age(100)  # the branch is 100 s old: still fresh (5 minutes), and older than the 20 s window
before_b, before_r = n("/branches/dev"), n("/releases/latest")
su.online_status("framework", source=BRANCH, refresh="release")
must(n("/branches/dev") == before_b and n("/releases/latest") == before_r + 1, "refresh=release does not force the branch")
reset()
su.online_status("framework", source=BRANCH, refresh="all")
must(n("/branches/dev") == 1 and n("/releases/latest") == 1, G["calls"])
# force=True alias: branch source -> branch only, release source -> release only, never all
reset()
su.online_status("framework", source=BRANCH, force=True)
must(n("/branches/dev") == 1 and n("/releases/latest") == 0, G["calls"])
out = su.online_status("framework", source=BRANCH, force=True)
must(out["refresh"]["requested"] == "branch", out["refresh"])
reset()
su.online_status("framework", source=RELEASE, force=True)
must(n("/releases/latest") == 1 and n("/branches/") == 0, G["calls"])
must(su._normalize_refresh(None, True, RELEASE) == "release" and su._normalize_refresh(None, True, BRANCH) == "branch" and su._normalize_refresh(None, False, BRANCH) == "none", "alias map")
must(su._normalize_refresh("none", True, BRANCH) == "none", "an explicit refresh wins over force")
print("       refresh=none|branch|release|all map to the right requests; force=true is an alias, never 'all'; invalid values are refused")

# a branch refresh never fetches the stable release; the release is shown from the saved copy marked stale
reset()
su.online_status("framework", source=RELEASE, refresh="release")
age(90000)
before = n("/releases/")
out = su.online_status("framework", source=BRANCH, refresh="branch")
must(n("/releases/") == before and out["stable_release"]["tag"] == "v1.18.0" and out["cache"]["stale"] is True, out["cache"])
print("       a branch refresh leaves the stable release alone (shown stale from the saved copy)")

# a Framework + UI branch refresh totals 2 requests
reset()
su.online_status("framework", source=BRANCH, refresh="branch")
su.online_status("ui", source=BRANCH, refresh="branch")
must(n() == 2, G["calls"])
print("       Framework + UI branch refresh = 2 requests in total")

# ------------------------------------------------------------------ (8) VERSION and signature preview saved by commit
reset()
VER = {"calls": 0}


def counting_content(repo, path, ref):
    VER["calls"] += 1
    return b"1.17.97\n"


su._github_content_bytes = counting_content
out = su.online_status("framework", source=BRANCH, refresh="branch")
must(VER["calls"] == 0 and out["branch"]["basis"] == "commit", "an installed commit is known: no VERSION request")
reset()
su._github_content_bytes = counting_content
INSTALLED_COMMIT["sha"] = None
VER["calls"] = 0
out = su.online_status("framework", source=BRANCH, refresh="branch")
must(VER["calls"] == 1 and out["branch"]["basis"] == "version" and out["branch"]["head_version"] == "1.17.97", (VER, out["branch"]))
age(9999)
su.online_status("framework", source=BRANCH, refresh="branch")
su.online_status("framework", source=BRANCH, refresh="branch")
must(VER["calls"] == 1 and cache()["commit_metadata"][f"jvz007/tac-net-rep:{SHA_A}"]["version"] == "1.17.97", "the VERSION saved by commit is reused with no expiry")
G["head"] = SHA_C
age(9999)
su.online_status("framework", source=BRANCH, refresh="branch")
must(VER["calls"] == 2, "a new commit is read once")
print("       VERSION: not read when the installed commit is known; saved by commit and never read twice")

reset()
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 1, PREVIEW)
age(99999)
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 1 and n("/releases/latest") == 2 and n("/commits/") == 2, "same commit: the preview is not fetched again")
G["release_sha"] = SHA_C
age(99999)
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 2, "a changed release commit re-checks the preview")
POLICY["minimum_level"] = "signed_production"
age(99999)
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 3, "a trust policy change re-checks the preview")
age(99999)
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 3, "and is then saved under the new fingerprint")
POLICY["minimum_level"] = "signed_development"
real_preview_fn = REAL_PREVIEW
fake_preview_fn = fake_preview


def failing_preview(component, repo, commit):
    PREVIEW["calls"] += 1
    raise su.SystemUpdateError("GitHub request failed: timed out")


su._release_signature_preview = failing_preview
G["release_sha"] = SHA_A
age(99999)
out = su.online_status("framework", source=RELEASE, refresh="release")
must(out["release_error"] and PREVIEW["calls"] == 4, out)
age(99999)
su.online_status("framework", source=RELEASE, refresh="release")
must(PREVIEW["calls"] == 5, "a network error is never saved as a preview")
su._release_signature_preview = fake_preview_fn
print("       signature preview saved by commit + trust fingerprint; policy change re-checks; errors are not saved")

# the preview is display only: its verification inputs are unchanged, and staging still verifies the downloaded bytes in full
src = (APP / "system_update.py").read_text(encoding="utf-8")
tree = ast.parse(src)
funcs = {f.name: f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)}


def calls_of(name):
    return {ast.unparse(c.func) for c in ast.walk(funcs[name]) if isinstance(c, ast.Call)}


must("_stage_bytes" in calls_of("_download_to_stage") and "inspect_archive" in calls_of("_stage_bytes"), "staging ends in inspect_archive")
must("verify_release_tree" in calls_of("inspect_archive") or "verify_release_tree" in ast.unparse(funcs["inspect_archive"]), "full signed-tree check")
must('required_permissions=(f"{component}.update",)' in ast.unparse(funcs["_release_signature_preview"]).replace("'", '"') or "required_permissions=(f'{component}.update',)" in ast.unparse(funcs["_release_signature_preview"]), "framework.update / ui.update permission kept")
seen = {}
mods["tec_tac.trusted_publishers"].verify_release_manifest_signature = lambda **kw: seen.update(kw) or {"verified": True}
su.verify_release_manifest_signature = mods["tec_tac.trusted_publishers"].verify_release_manifest_signature
su._github_content_bytes = lambda repo, path, ref: b"{}"
real_preview_fn("ui", "o/r", SHA_A)
must(seen["required_permissions"] == ("ui.update",) and seen["expected_component"] == "ui", seen)
su._github_content_bytes = lambda repo, path, ref: None
must(real_preview_fn("ui", "o/r", SHA_A)["state"] == "unsigned", "unsigned release")
su._github_content_bytes = lambda repo, path, ref: b"{}" if path.endswith("release.json") else None
must(real_preview_fn("ui", "o/r", SHA_A)["state"] == "invalid", "incomplete signing metadata")
print("       preview is display only: staging still runs inspect_archive; framework.update / ui.update permissions kept; unsigned still shown")

# ------------------------------------------------------------------ (9) stage pinned to the shown commit
reset()
su._github_content_bytes = real_content
downloads = []
su._download_to_stage = lambda url, *, filename, source, component: downloads.append((url, source)) or {"ok": True, "source": source}
su.online_status("framework", source=BRANCH, refresh="all")
before = n()
res = su.stage_online_package("framework", "branch", "dev", commit=SHA_A.upper())
must(n() == before and len(downloads) == 1 and downloads[0][1]["commit"] == SHA_A and SHA_A in downloads[0][0], (G["calls"], downloads))
res = su.stage_online_package("framework", "release", commit=SHA_B)
must(n() == before and len(downloads) == 2 and downloads[1][1]["commit"] == SHA_B and downloads[1][1]["ref"] == "v1.18.0", downloads)
for kind, ref, commit in (("branch", "dev", SHA_C), ("release", None, SHA_C)):
    try:
        su.stage_online_package("framework", kind, ref, commit=commit)
        raise AssertionError("a commit that does not match the saved one must be refused")
    except su.StaleCandidateError as exc:
        must(exc.code == "stale_candidate" and "Refresh the check and try again" in str(exc), exc)
must(len(downloads) == 2 and n() == before, "no download and no metadata call for a stale candidate")
reset()
downloads.clear()
for kind, ref in (("branch", "dev"), ("release", None)):
    try:
        su.stage_online_package("framework", kind, ref, commit=SHA_A)
        raise AssertionError("no saved check: refused")
    except su.StaleCandidateError:
        pass
must(not downloads and n() == 0, "no cache = stale_candidate, nothing downloaded")
try:
    su.stage_online_package("framework", "branch", "dev", commit="not-a-sha")
    raise AssertionError("invalid commit")
except su.SystemUpdateError as exc:
    must(not isinstance(exc, su.StaleCandidateError), exc)
# without commit: the old behaviour, one branch resolution (release: two) and the archive
reset()
downloads.clear()
su.stage_online_package("framework", "branch", "dev")
must(n("/branches/dev") == 1 and downloads[0][1]["commit"] == SHA_A, G["calls"])
su.stage_online_package("framework", "release")
must(n("/releases/latest") == 1 and n("/commits/") == 1 and downloads[1][1]["commit"] == SHA_B, G["calls"])
print("       stage: matching commit = 0 metadata calls + 1 archive; other commit or no check = stale_candidate; without commit unchanged")

# ------------------------------------------------------------------ (10) read-only routes never call GitHub
reset()
su._saved_update_sources = lambda: {}
su._recent_history = lambda limit=12: []
su._signed_release_min_version = lambda component: None
su.get_trust_policy = lambda: dict(POLICY)
status = su.system_status()
must(n() == 0 and "github_rate_limit" in status, G["calls"])
su.online_status("framework", source=BRANCH)
status = su.system_status()
must(status["github_rate_limit"]["limit"] == 5000 and n() == 1, "status reads the saved telemetry only")
transport_names = {"github_get_json", "_github_json", "_github_content_bytes", "_github_open", "_release_online_status", "_branch_head", "online_status", "list_branches", "stage_online_package"}
for name in ("get_job", "list_jobs", "public_job", "read_job_log", "system_status", "cached_online_status", "_recent_history"):
    must(not (calls_of(name) & transport_names), f"{name} must not call GitHub")
print("       job routes, system_status and cached_online_status make 0 GitHub calls; system_status shows the saved telemetry")

# ------------------------------------------------------------------ (11) the API layer
views = (APP / "views.py").read_text(encoding="utf-8")
vtree = ast.parse(views)
classes = {c.name: ast.unparse(c) for c in vtree.body if isinstance(c, ast.ClassDef)}
for name in ("SystemUpdateOnlineStatusView", "SystemUpdateOnlineStageView", "SystemUpdateBranchesView"):
    must("_require_module_manager(request.user)" in classes[name], f"{name} must keep _require_module_manager")
must("GithubRateLimitError" in classes["SystemUpdateOnlineStatusView"] and "_github_rate_limit_response" in classes["SystemUpdateOnlineStatusView"], "status maps the limit")
# 1.17.98: refresh is validated in one place, the service; the view maps its SystemUpdateError to 400
status_view = classes["SystemUpdateOnlineStatusView"]
must("refresh must be" not in status_view and "{'none', 'branch', 'release', 'all'}" not in status_view, "the view must not validate refresh a second time")
must("except SystemUpdateError" in status_view and "status=400" in status_view and "refresh=refresh" in status_view, "invalid refresh = 400 through SystemUpdateError")
must("StaleCandidateError" in classes["SystemUpdateOnlineStageView"] and "status=409" in classes["SystemUpdateOnlineStageView"] and "commit=commit" in classes["SystemUpdateOnlineStageView"], "stage: 409 stale_candidate and the optional commit")
must("GithubRateLimitError" in classes["SystemUpdateOnlineStageView"] and "GithubRateLimitError" in classes["SystemUpdateBranchesView"], "stage and branches map the limit")
helper_src = next(ast.unparse(f) for f in vtree.body if isinstance(f, ast.FunctionDef) and f.name == "_github_rate_limit_response")
must("status=429" in helper_src and "cached_data_available=False" in helper_src, "429 body")

contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
details = next(ast.literal_eval(x.value) for x in contracts.body if isinstance(x, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in x.targets))
online = json.dumps(details["/api/tfd/system/updates/online/"]["GET"])
for needle in ("refresh", "github_rate_limit_error", "github_rate_limit", "recently_refreshed", "429"):
    must(needle in online, f"online contract lacks {needle}")
stage = json.dumps(details["/api/tfd/system/updates/online/stage/"]["POST"])
for needle in ("commit", "stale_candidate", "409", "429"):
    must(needle in stage, f"stage contract lacks {needle}")
must("github_rate_limit" in json.dumps(details["/api/tfd/system/updates/"]["GET"]), "status contract lacks github_rate_limit")

# the branch list: ETag revalidation, and the saved list is shown with the warning when the limit is exhausted
reset()
must(su.list_branches("framework")["branches"][0]["name"] == "dev", "list")
su.online_status("framework", source=BRANCH)
age(400)
G["fail"] = lambda url: http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 600)})
su.online_status("framework", source=BRANCH)
G["fail"] = None
res = su.list_branches("framework")
must(res["github_rate_limit_error"]["cached_data_available"] is True and res["branches"][0]["name"] == "dev", res)
print("       API layer: refresh validation, 409/429 mapping, module-manager checks kept, contract text current")

# ------------------------------------------------------------------ (11b) review findings of the 1.17.98 rebuild reviews
# Medium: the stable_release row describes the 1.17.98 rule, not the 24-hour fetch and the force=1 bypass
online_get = details["/api/tfd/system/updates/online/"]["GET"]
stable_text = online_get["response"]["stable_release"]
must("force=1 bypasses the cache" not in stable_text and "24-hour release cache" not in stable_text, stable_text)
for needle in ("saved copy", "cache.stale", "refresh=release", "refresh=all", "force=1 under a branch source means refresh=branch"):
    must(needle in stable_text, f"stable_release row lacks {needle!r}")
must("bypasses the caches." not in online_get["query"]["force"] and "the stable release is not refreshed" in online_get["query"]["force"], online_get["query"]["force"])
must("an empty value is none" in online_get["query"]["refresh"], online_get["query"]["refresh"])

# Low: an empty refresh= is none, in the one place that validates it
for empty in ("", "  "):
    must(su._normalize_refresh(empty, False, BRANCH) == "none" and su._normalize_refresh(empty, True, BRANCH) == "branch", "empty refresh = none (or the force alias)")
reset()
out = su.online_status("framework", source=BRANCH, refresh="")
must(out["refresh"]["requested"] == "none", out["refresh"])

# Low: a transport failure is an error with the saved answer, never a fresh check
def unreachable(url):
    return urllib.error.URLError("network is unreachable")

reset()
su.online_status("framework", source=BRANCH, refresh="all")
age(400)
saved = cache()
branch_stamp = saved["branch_sources"]["jvz007/tac-net-rep:dev"]["checked_at"]
release_stamp = saved["components"]["framework"]["checked_at"]
G["fail"] = unreachable
try:
    su.github_get_json("https://api.github.com/repos/jvz007/tac-net-rep/branches/dev", ttl=timedelta(minutes=5))
    raise AssertionError("a transport failure with a saved answer must raise, not return it as fresh")
except su.GithubUnreachableError as exc:
    must(isinstance(exc, su.GithubRequestError) and exc.saved_body["commit"]["sha"] == SHA_A, exc.saved_body)
out = su.online_status("framework", source=BRANCH, refresh="all")
row = cache()["branch_sources"]["jvz007/tac-net-rep:dev"]
must(out["branch"]["head_commit"] == SHA_A and out["branch_error"] and "could not be reached" in out["branch_error"], out)
must(row["checked_at"] == branch_stamp and row["last_network_check"] == branch_stamp, "the saved head keeps its old check time")
must(out["stable_release"]["tag"] == "v1.18.0" and out["release_error"] and out["cache"]["stale"] is True, (out["release_error"], out["cache"]))
must(out["checked_at"] == release_stamp and cache()["components"]["framework"]["checked_at"] == release_stamp, "the saved release keeps its old checked_at")
out = su.online_status("framework", source=RELEASE, refresh="release")
must(out["latest_release"]["tag"] == "v1.18.0" and out["release_error"] and out["cache"]["stale"] is True and out["checked_at"] == release_stamp, out)
# an unpinned stage refuses the saved fallback; nothing is downloaded
downloads.clear()
for kind, ref in (("branch", "dev"), ("release", None)):
    try:
        su.stage_online_package("framework", kind, ref)
        raise AssertionError("an unpinned stage must not resolve a stale saved head")
    except su.GithubUnreachableError:
        pass
must(not downloads, downloads)
# the branch picker keeps the saved list, as before
G["fail"] = None
su.list_branches("framework")
put_cache(lambda doc: [r.update(checked_at="2000-01-01T00:00:00+00:00") for r in doc["github"]["etags"].values()])
G["fail"] = unreachable
must(su.list_branches("framework")["branches"][0]["name"] == "dev", "saved branch list shown")
# nothing saved: the plain error, as before
reset()
G["fail"] = unreachable
try:
    su.github_get_json("https://api.github.com/repos/jvz007/tac-net-rep/branches/dev")
    raise AssertionError("no saved answer: error")
except su.GithubRequestError as exc:
    must(not isinstance(exc, su.GithubUnreachableError), exc)
G["fail"] = None
print("       review fixes: stable_release text current; empty refresh = none; URLError keeps the old checked_at, sets the errors, refuses an unpinned stage")

# ------------------------------------------------------------------ (12) the GitHub token file rules (unchanged logic, stubs for pwd and stat)
class FakeStat:
    def __init__(self, uid=0, gid=1001, mode=0o100640):
        self.st_uid, self.st_gid, self.st_mode = uid, gid, mode


TOK = {"stat": FakeStat(), "symlink": False, "exists": True}
real_Path = su.Path


class FakePath(type(real_Path())):
    def exists(self):
        return TOK["exists"] if self.name == "github-token" else super().exists()

    def is_symlink(self):
        return TOK["symlink"] if self.name == "github-token" else super().is_symlink()

    def is_file(self):
        return True if self.name == "github-token" else super().is_file()

    def stat(self, *a, **k):
        return TOK["stat"] if self.name == "github-token" else super().stat(*a, **k)

    def read_text(self, *a, **k):
        return TOKEN + "\n" if self.name == "github-token" else super().read_text(*a, **k)


su.Path = FakePath
su.pwd = types.SimpleNamespace(getpwnam=lambda name: types.SimpleNamespace(pw_gid=1001))
real_headers = sys.modules["tec_tac.system_update"].__dict__.get("_real_github_headers")
src_headers = ast.parse((APP / "system_update.py").read_text(encoding="utf-8"))
fn = next(f for f in src_headers.body if isinstance(f, ast.FunctionDef) and f.name == "_github_headers")
ns = dict(su.__dict__)
exec(compile(ast.Module(body=[fn], type_ignores=[]), "headers", "exec"), ns)  # noqa: S102 - test-only extraction of the real function
headers_fn = ns["_github_headers"]
must(headers_fn()["Authorization"] == f"Bearer {TOKEN}", "root:tactical 0640 accepted")
for label, change in (
    ("symlink", {"symlink": True}), ("wrong owner", {"stat": FakeStat(uid=1000)}), ("wrong group", {"stat": FakeStat(gid=5)}),
    ("group-writable", {"stat": FakeStat(mode=0o100660)}), ("world-readable", {"stat": FakeStat(mode=0o100644)}),
):
    TOK.update(stat=FakeStat(), symlink=False)
    TOK.update(change)
    try:
        headers_fn()
        raise AssertionError(f"{label} must be refused")
    except su.SystemUpdateError as exc:
        must(TOKEN not in str(exc), "the token is never in an error")
TOK.update(stat=FakeStat(), symlink=False, exists=False)
must("Authorization" not in headers_fn(), "no token file: anonymous requests")
su.Path = real_Path
print("       token file rules intact: root:tactical 0640 accepted; symlink, wrong owner or group, group-writable, world-readable refused")

print("[TEST] PASS github rate limit 1.17.98")
