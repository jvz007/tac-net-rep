#!/usr/bin/env python3
"""1.18.43 regression: System update version picker (AD-77), list builds, stage one by version, three downgrade limits.

Covers: the branch list keeps only plain-version commits (a -N label and ordinary commits are skipped), newest first;
the release list skips drafts and prereleases; the saved ETag copy of both lists stays small; the list is served from
the cache inside 5 minutes with no request; a rate limit with a saved list answers with github_rate_limit_error; staging
by version (unknown version, wrong commit, a row that is not installable, a good row, a release row resolved at stage
time, an unsigned tree discarded even on a development server); and the limits (highest module minimum wins, a package
that lacks an applied migration, a Core below the installed UI's range, fail-closed reads, the row search's probe count).
Django, pwd and (on Windows) fcntl are not available on the development PC, so the real system_update.py is loaded
against stubs and a fake _github_open that counts every outbound request. Nothing here reaches the network.
"""
from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
import tempfile
import time
import types
import urllib.error
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
UTC = timezone.utc
REPO = "jvz007/tac-net-rep"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def sha(n: int) -> str:
    return f"{n:040x}"


# ------------------------------------------------------------------ stubs and loader
mods = {n: types.ModuleType(n) for n in ("tec_tac.safe_files", "tec_tac.trusted_publishers", "tec_tac.trust_policy", "tec_tac.module_job_logs")}
mods["tec_tac.safe_files"].atomic_json = lambda path, payload, **kw: Path(path).write_text(json.dumps(payload), encoding="utf-8")
mods["tec_tac.trusted_publishers"].PublisherTrustError = type("PublisherTrustError", (Exception,), {})
mods["tec_tac.trusted_publishers"].verify_release_manifest_signature = lambda *a, **k: {"verified": True}
mods["tec_tac.trusted_publishers"].verify_release_tree = lambda *a, **k: {"signed": True, "verified": True, "trusted": True, "state": "verified", "file_count": 3}
mods["tec_tac.trust_policy"].TrustPolicyError = type("TrustPolicyError", (Exception,), {})
mods["tec_tac.trust_policy"].acceptance = lambda *a, **k: {}
mods["tec_tac.trust_policy"].get_policy = lambda: {"minimum_level": "signed_development"}
mods["tec_tac.trust_policy"].require_accepted = lambda *a, **k: {"accepted": True}
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
su._github_headers = lambda: {"Accept": "x"}
INSTALLED = {"framework": "1.18.42", "ui": "0.13.1"}
su._installed_version = lambda component: INSTALLED[component]
APPLIED = {"set": {"0001_a", "0002_b", "0003_c", "0004_d"}}


def applied_hook():
    value = APPLIED["set"]
    if isinstance(value, Exception):
        raise value
    return set(value)


su._applied_core_migrations = applied_hook
BRANCH = {"type": "branch", "ref": "dev"}
RELEASE = {"type": "release", "ref": None}
TMP = Path(tempfile.mkdtemp(prefix="version-picker-11843-"))
EXT = TMP / "extensions"
UI_ROOT = TMP / "ui"
su._extensions_root = lambda: EXT
su._component_root = lambda component: UI_ROOT


def write_module(module_id, requires=None, raw=None):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    text = raw if raw is not None else json.dumps({"id": module_id, "requires": requires or {}})
    (folder / "tec_tac.json").write_text(text, encoding="utf-8")


def write_ui_requirement(spec):
    UI_ROOT.mkdir(parents=True, exist_ok=True)
    body = {"id": "tec-tac-ui", "version": "0.13.1", "requires": {"tec-tac-framework": spec} if spec else {}}
    (UI_ROOT / "tec_tac_package.json").write_text(json.dumps(body), encoding="utf-8")


# ------------------------------------------------------------------ the fake GitHub
G = {"calls": [], "commits": [], "releases": [], "migs": {}, "zips": {}, "tags": {}, "fail_contents": False}


class Resp:
    def __init__(self, body: bytes, headers):
        self._io = io.BytesIO(body)
        self.headers = headers

    def read(self, size=-1):
        return self._io.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def rl_headers():
    return {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "50", "X-RateLimit-Used": "10",
            "X-RateLimit-Reset": str(int(time.time()) + 3600), "X-RateLimit-Resource": "core"}


def fake_open(request, *, timeout):
    url = request.full_url
    G["calls"].append(url)
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    path = parts.path
    h = rl_headers()
    if path == f"/repos/{REPO}/commits" and "sha" in query:
        body = G["commits"]
    elif path == f"/repos/{REPO}/releases":
        body = G["releases"]
    elif path == f"/repos/{REPO}/contents/framwork/tec_tac/migrations":
        if G["fail_contents"]:
            raise urllib.error.HTTPError(url, 500, "boom", h, io.BytesIO(b"boom"))
        names = G["migs"].get(query["ref"][0])
        if names is None:
            raise urllib.error.HTTPError(url, 404, "not found", h, io.BytesIO(b"{}"))
        body = [{"name": "__init__.py", "type": "file"}] + [{"name": f"{n}.py", "type": "file"} for n in sorted(names)] + [{"name": "__pycache__", "type": "dir"}]
    elif path.startswith(f"/repos/{REPO}/commits/"):
        body = {"sha": G["tags"][urllib.parse.unquote(path.rsplit("/", 1)[1])]}
    elif path.startswith(f"/repos/{REPO}/zipball/"):
        return Resp(G["zips"][path.rsplit("/", 1)[1]], h)
    else:
        raise AssertionError(url)
    raw = json.dumps(body).encode()
    etag = f"e-{len(raw)}-{abs(hash(raw)) % 10**6}"
    h = {**h, "ETag": etag}
    sent = {k.lower(): v for k, v in request.headers.items()}
    if sent.get("if-none-match") == etag:
        raise urllib.error.HTTPError(url, 304, "not modified", h, io.BytesIO(b""))
    return Resp(raw, h)


su._github_open = fake_open


def calls_to(fragment):
    return [c for c in G["calls"] if fragment in c]


def commit_row(n, message, date="2026-11-20T10:00:00Z"):
    return {"sha": sha(n), "node_id": "x" * 40, "html_url": "https://example.invalid/" + str(n), "parents": [{"sha": sha(n - 1)}],
            "author": {"login": "someone"}, "commit": {"message": message + "\n\nbody text that must not be kept", "tree": {"sha": sha(n + 5000)},
                                                       "author": {"name": "A", "date": date}, "committer": {"name": "C", "date": date}}}


def migs(count):
    return {f"{i:04d}_{'abcdefgh'[i - 1]}" for i in range(1, count + 1)}


def make_zip(version, names, *, signed=True):
    path = TMP / f"pkg-{version}-{'s' if signed else 'u'}-{len(names)}.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("repo/VERSION", version + "\n")
        zf.writestr("repo/install.sh", "#!/bin/bash\n")
        zf.writestr("repo/framwork/tec_tac/__init__.py", "")
        zf.writestr("repo/framwork/tec_tac/migrations/__init__.py", "")
        for name in sorted(names):
            zf.writestr(f"repo/framwork/tec_tac/migrations/{name}.py", "")
        zf.writestr("repo/tec_tac_package.json", json.dumps({"type": "tec-tac-framework", "version": version}))
        if signed:
            zf.writestr("repo/tec-tac-release.json", "{}")
            zf.writestr("repo/tec-tac-release.json.sig", "sig")
    return path.read_bytes()


def reset():
    tmp = Path(tempfile.mkdtemp(prefix="vp-case-"))
    su.CACHE_ROOT = tmp / "cache"
    su.RELEASE_CACHE = su.CACHE_ROOT / "release-cache.json"
    su.HISTORY_ROOT, su.JOBS_ROOT, su.STAGED_ROOT = tmp / "history", tmp / "jobs", tmp / "staged"
    G.update(calls=[], fail_contents=False)
    INSTALLED.update(framework="1.18.42", ui="0.13.1")
    APPLIED["set"] = migs(4)
    for child in list(EXT.glob("*")) if EXT.exists() else []:
        for f in child.glob("*"):
            f.unlink()
        child.rmdir()
    EXT.mkdir(parents=True, exist_ok=True)
    if (UI_ROOT / "tec_tac_package.json").exists():
        (UI_ROOT / "tec_tac_package.json").unlink()
    return tmp


def cache():
    return json.loads(su.RELEASE_CACHE.read_text(encoding="utf-8"))


def put_cache(mutator):
    doc = cache()
    mutator(doc)
    su.RELEASE_CACHE.write_text(json.dumps(doc), encoding="utf-8")


def age_etags(seconds):
    old = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()

    def mutate(doc):
        for row in doc.get("github", {}).get("etags", {}).values():
            row["checked_at"] = old

    put_cache(mutate)


def block_rate_limit():
    def mutate(doc):
        doc.setdefault("github", {})["rate_limit"] = {
            "limited": True, "reset_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(), "limit": 60, "remaining": 0,
        }

    put_cache(mutate)


def raises(exc_type, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{exc_type.__name__} not raised")


# The main fixture: a dev branch, newest first, with commits that are not version builds mixed in.
FIXTURE = [(42, "1.18.42"), (41, "1.18.40-1"), (40, "Merge branch 'fix'"), (39, "1.18.41"), (38, "1.18.40"), (37, "1.18.39"),
           (36, "1.18.35"), (35, "1.18.30"), (34, "1.18.29")]


def fixture():
    G["commits"] = [commit_row(n, msg) for n, msg in FIXTURE]
    versions = {msg: n for n, msg in FIXTURE}
    G["migs"] = {sha(versions["1.18.42"]): migs(4), sha(versions["1.18.41"]): migs(4), sha(versions["1.18.40"]): migs(4),
                 sha(versions["1.18.39"]): migs(4), sha(versions["1.18.35"]): migs(3), sha(versions["1.18.30"]): migs(2), sha(versions["1.18.29"]): migs(2)}
    G["zips"] = {sha(versions["1.18.41"]): make_zip("1.18.41", migs(4)), sha(versions["1.18.40"]): make_zip("1.18.40", migs(4), signed=False),
                 sha(versions["1.18.39"]): make_zip("1.18.39", migs(4)), sha(versions["1.18.35"]): make_zip("1.18.35", migs(3)),
                 sha(versions["1.18.29"]): make_zip("1.18.29", migs(2))}
    G["releases"] = [
        {"tag_name": "v1.18.42", "name": "1.18.42", "published_at": "2026-11-22T08:00:00Z", "html_url": "u", "draft": False, "prerelease": False, "body": "x" * 500, "assets": [{"a": 1}]},
        {"tag_name": "v1.18.41", "name": "1.18.41", "published_at": "2026-11-21T08:00:00Z", "html_url": "u", "draft": True, "prerelease": False},
        {"tag_name": "v1.18.40", "name": "1.18.40", "published_at": "2026-11-20T08:00:00Z", "html_url": "u", "draft": False, "prerelease": True},
        {"tag_name": "v1.18.39", "name": "1.18.39", "published_at": "2026-11-19T08:00:00Z", "html_url": "u", "draft": False, "prerelease": False},
        {"tag_name": "v1.14.0", "name": "1.14.0", "published_at": "2026-01-19T08:00:00Z", "html_url": "u", "draft": False, "prerelease": False},
    ]
    G["tags"] = {"v1.18.39": sha(versions["1.18.39"]), "v1.18.42": sha(versions["1.18.42"])}


def by_version(out):
    return {row["version"]: row for row in out["versions"]}


# ------------------------------------------------------------------ (1) branch list, no limits in the way
reset()
fixture()
write_module("governance", {"framework": ">=1.18.35,<2.0.0"})
write_module("modulea", {"framework": ">=1.18.30", "ui": ">=0.13.0"})
write_module("plain")
out = su.list_versions("framework", BRANCH)
rows = by_version(out)
must([r["version"] for r in out["versions"]] == ["1.18.42", "1.18.41", "1.18.40", "1.18.39", "1.18.35", "1.18.30", "1.18.29"], [r["version"] for r in out["versions"]])
must("1.18.40-1" not in rows and len(rows) == 7, "a -N label and an ordinary commit are skipped")
must(rows["1.18.41"]["commit"] == sha(39) and rows["1.18.41"]["date"] == "2026-11-20T10:00:00Z", rows["1.18.41"])
must(rows["1.18.42"]["operation"] == "reinstall" and rows["1.18.42"]["installable"] and rows["1.18.42"]["reason"] is None, rows["1.18.42"])
must(out["component"] == "framework" and out["repository"] == REPO and out["source"] == {"type": "branch", "ref": "dev"} and out["installed_version"] == "1.18.42", out)
must(all("_ref" not in r for r in out["versions"]), "no private key leaks into the answer")
print("       branch list: plain-version commits only, newest first, commit and date present, no private keys")

# ------------------------------------------------------------------ (2) the limits on rows: highest minimum wins and names the module
must(rows["1.18.30"]["installable"] is False and rows["1.18.30"]["reason"] == "Module governance needs Tec-Tac Framework 1.18.35 or newer.", rows["1.18.30"])
must(rows["1.18.29"]["reason"] == "Module governance and 1 more needs Tec-Tac Framework 1.18.35 or newer.", rows["1.18.29"])
must(rows["1.18.39"]["installable"] is True and rows["1.18.41"]["operation"] == "downgrade", rows["1.18.39"])
print("       highest module minimum wins; the reason names the module and 'and 1 more'")

# ------------------------------------------------------------------ (3) the migration boundary, found by search
must(rows["1.18.35"]["installable"] is False and "lacks migration 0004_d" in rows["1.18.35"]["reason"] and "restore the server backup" in rows["1.18.35"]["reason"], rows["1.18.35"])
must(out["migration_check"] == "done" and out["lowest_installable"] == "1.18.39", (out["migration_check"], out["lowest_installable"]))
probes = calls_to("/contents/")
must(1 <= len(probes) <= 8, len(probes))
print(f"       migration boundary: 1.18.35 refused with the restore sentence, lowest_installable 1.18.39, {len(probes)} probes")

# ------------------------------------------------------------------ (4) cached: a second list makes no request at all
before = len(G["calls"])
again = su.list_versions("framework", BRANCH)
must(len(G["calls"]) == before and again["versions"] == out["versions"], "second list inside 5 minutes: no request (list and probes cached)")
print("       second list: served from the cache, 0 requests (the probes are saved by commit)")

# ------------------------------------------------------------------ (5) the saved list body is small
body = cache()["github"]["etags"][next(k for k in cache()["github"]["etags"] if "/commits?sha=" in k)]["body"]
must(isinstance(body, list) and len(body) == 9, body)
for item in body:
    must(set(item) == {"sha", "commit"} and set(item["commit"]) == {"message", "committer"} and set(item["commit"]["committer"]) == {"date"}, item)
    must("\n" not in item["commit"]["message"], item)
text = su.RELEASE_CACHE.read_text(encoding="utf-8")
must("body text that must not be kept" not in text and "node_id" not in text and "someone" not in text and "parents" not in text, "no full commit objects saved")
print("       saved commits list keeps only sha, first message line, committer date")

# ------------------------------------------------------------------ (6) release list: drafts and prereleases skipped, body reduced
reset()
fixture()
out = su.list_versions("framework", RELEASE)
rows = by_version(out)
must(sorted(rows) == ["1.14.0", "1.18.39", "1.18.42"], sorted(rows))
must(rows["1.18.39"]["commit"] is None and rows["1.18.39"]["date"] == "2026-11-19T08:00:00Z" and rows["1.18.39"]["operation"] == "downgrade", rows["1.18.39"])
must(rows["1.14.0"]["installable"] is False and "1.15.37" in rows["1.14.0"]["reason"], rows["1.14.0"])
rel_key = next(k for k in cache()["github"]["etags"] if "/releases" in k)
saved = cache()["github"]["etags"][rel_key]["body"]
must(all(set(r) == {"tag_name", "name", "published_at", "html_url", "draft", "prerelease"} for r in saved), saved)
must("assets" not in su.RELEASE_CACHE.read_text(encoding="utf-8"), "no full release objects saved")
print("       release list: drafts and prereleases skipped, commit null, an unsigned-era release not installable, saved body reduced")

# ------------------------------------------------------------------ (7) rate limit with a saved list: the saved list and github_rate_limit_error
reset()
fixture()
first = su.list_versions("framework", BRANCH)
age_etags(3600)
block_rate_limit()
before = len(G["calls"])
limited = su.list_versions("framework", BRANCH)
must(len(G["calls"]) == before, "nothing sent while the limit is exhausted")
must(limited["github_rate_limit_error"]["code"] == "github_rate_limit_exceeded" and limited["github_rate_limit_error"]["cached_data_available"] is True, limited.get("github_rate_limit_error"))
must([r["version"] for r in limited["versions"]] == [r["version"] for r in first["versions"]], "the saved list is shown")
reset()
fixture()
su._cache_update(lambda d: d.setdefault("github", {}).update(rate_limit={"limited": True, "reset_at": (datetime.now(UTC) + timedelta(minutes=30)).isoformat()}))
raises(su.GithubRateLimitError, su.list_versions, "framework", BRANCH)
print("       rate limit: a saved list is shown with github_rate_limit_error; with nothing saved the error is raised (429)")

# ------------------------------------------------------------------ (8) the UI limit, including an upper bound
reset()
fixture()
write_ui_requirement(">=1.18.40,<2.0.0")
out = su.list_versions("framework", BRANCH)
rows = by_version(out)
must(rows["1.18.39"]["installable"] is False and rows["1.18.39"]["reason"] == "The installed UI 0.13.1 needs Tec-Tac Framework >=1.18.40,<2.0.0. Downgrade the UI first.", rows["1.18.39"])
must(rows["1.18.40"]["installable"] is True and out["lowest_installable"] == "1.18.40", out["lowest_installable"])
INSTALLED["framework"] = "1.19.5"
write_ui_requirement(">=1.18.35,<1.19.0")
must("Downgrade the UI first" in su.downgrade_problem("framework", "1.19.2", package_migrations=migs(4)), "an upper bound counts")
must(su.downgrade_problem("framework", "1.18.40", package_migrations=migs(4)) is None, "inside the range")
write_ui_requirement(None)
must(su.downgrade_problem("framework", "1.19.2", package_migrations=migs(4)) is None, "no requirement, no limit")
(UI_ROOT / "tec_tac_package.json").write_text("{not json", encoding="utf-8")
must("installed UI could not be read" in su.downgrade_problem("framework", "1.19.2", package_migrations=migs(4)), "unreadable UI requirements fail closed")
print("       UI limit: below the range and above its upper bound say 'Downgrade the UI first'; unreadable fails closed")

# ------------------------------------------------------------------ (9) fail closed reads; an update or reinstall is never limited
reset()
write_module("broken", raw="{not json")
must(su.downgrade_problem("framework", "1.18.30") == "The requirements of module broken could not be read.", su.downgrade_problem("framework", "1.18.30"))
must(su.downgrade_problem("framework", "1.18.43") is None and su.downgrade_problem("framework", "1.18.42") is None, "update and reinstall are never limited")
reset()
APPLIED["set"] = su.SystemUpdateError("no database")
must("could not be read" in su.downgrade_problem("framework", "1.18.30", package_migrations=migs(1)), "an unreadable applied set refuses")
must(su.downgrade_problem("framework", "1.18.43", package_migrations=migs(1)) is None, "an update is not limited even then")
fixture()
out = su.list_versions("framework", BRANCH)
must(out["migration_check"] == "unavailable" and by_version(out)["1.18.41"]["installable"] is False and "could not be read" in by_version(out)["1.18.41"]["reason"], out["migration_check"])
must(by_version(out)["1.18.42"]["installable"] is True, "the installed version row is untouched")
print("       fail closed: an unreadable manifest or applied-migration set refuses a downgrade; updates are never limited")

# ------------------------------------------------------------------ (10) the row search: at most 8 probes on 100 rows, cached
reset()
INSTALLED["framework"] = "1.0.100"
APPLIED["set"] = migs(6)
G["commits"] = [commit_row(1000 + n, f"1.0.{n}") for n in range(100, 0, -1)]
G["migs"] = {sha(1000 + n): migs(min(8, n // 10)) for n in range(1, 101)}
out = su.list_versions("framework", BRANCH)
rows = by_version(out)
must(len(out["versions"]) == 100, len(out["versions"]))
probes = calls_to("/contents/")
must(len(probes) <= 8, len(probes))
must(rows["1.0.60"]["installable"] is True and rows["1.0.59"]["installable"] is False and out["lowest_installable"] == "1.0.60", (rows["1.0.60"], rows["1.0.59"]))
must(all(r["installable"] for n, r in ((int(v.split(".")[2]), r) for v, r in rows.items()) if n >= 60) and not any(r["installable"] for v, r in rows.items() if int(v.split(".")[2]) < 60), "boundary exact")
before = len(G["calls"])
su.list_versions("framework", BRANCH)
must(len(G["calls"]) == before, "second list makes no probe")
print(f"       100 rows: boundary found with {len(probes)} probes, saved so the second list makes none")

# ------------------------------------------------------------------ (11) a failed probe: unavailable, rows intact, stage still decides
reset()
fixture()
write_module("governance", {"framework": ">=1.18.35,<2.0.0"})
G["fail_contents"] = True
out = su.list_versions("framework", BRANCH)
must(out["migration_check"] == "unavailable", out["migration_check"])
rows = by_version(out)
must(rows["1.18.35"]["installable"] is True and rows["1.18.35"]["reason"] is None and rows["1.18.41"]["installable"] is True, "rows keep no migration verdict")
must(rows["1.18.30"]["installable"] is False, "a module floor still applies")
G["fail_contents"] = False
out = su.list_versions("framework", BRANCH)
must(out["migration_check"] == "done" and by_version(out)["1.18.35"]["installable"] is False, "once GitHub answers again the search completes (a failure was never saved)")
reset()
fixture()
write_module("governance", {"framework": ">=1.18.35,<2.0.0"})
staged = su.stage_online_package("framework", "version", version="1.18.35", commit=sha(36), source=BRANCH)
pre = staged["preview"]
must(pre["installable"] is False and "lacks migration 0004_d" in pre["install_block_reason"] and pre["operation"] == "downgrade", pre)
err = raises(su.SystemUpdateError, su.queue_install, staged["upload_id"], allow_downgrade=True, requested_by="admin")
must("lacks migration 0004_d" in str(err), err)
print("       failed probe: migration_check unavailable, rows intact; the stage check from the real archive still refuses, install refused")

# ------------------------------------------------------------------ (12) staging by version
reset()
fixture()
write_module("governance", {"framework": ">=1.18.35,<2.0.0"})
write_module("modulea", {"framework": ">=1.18.30"})
raises(su.StaleCandidateError, su.stage_online_package, "framework", "version", version="9.9.9", source=BRANCH)
raises(su.StaleCandidateError, su.stage_online_package, "framework", "version", version="1.18.41", commit=sha(777), source=BRANCH)
err = raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", version="1.18.29", source=BRANCH)
must(not isinstance(err, su.StaleCandidateError) and "governance" in str(err), err)
raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", source=BRANCH)
raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", version="1.18.41", commit="zz", source=BRANCH)
must(not calls_to("/zipball/"), "nothing downloaded for a refused version")
good = su.stage_online_package("framework", "version", version="1.18.41", commit=sha(39), source=BRANCH)
must(calls_to("/zipball/") == [f"https://api.github.com/repos/{REPO}/zipball/{sha(39)}"], calls_to("/zipball/"))
must(good["preview"]["source"] == {"type": "branch", "repository": REPO, "ref": "dev", "commit": sha(39)}, good["preview"]["source"])
must(good["preview"]["version"] == "1.18.41" and good["preview"]["operation"] == "downgrade" and good["preview"]["installable"] is True, good["preview"])
must(good["preview"]["release_trust"]["legacy"] is False and good["preview"]["release_trust"]["signed"] is True, good["preview"]["release_trust"])
job_source = good["preview"]["source"]
must(set(job_source) == {"type", "repository", "ref", "commit"}, "no new source keys, so the root helper copy still works")
without_commit = su.stage_online_package("framework", "version", version="1.18.39", source=BRANCH)
must(without_commit["preview"]["source"]["commit"] == sha(37), "the commit is optional")
print("       stage by version: unknown or wrong-commit versions are 409s, a refused row is 400 with its reason, a good row stages zipball/<sha> with the usual source dict")

# unsigned tree: discarded and refused, even on a development server that allows unsigned updates
su._development_unsigned_update_allowed = lambda: True
su._accept_update_trust = lambda trust, subject: {"accepted": True, "development_unsigned_override": True}
staged_before = sorted(p.name for p in su.STAGED_ROOT.glob("*"))
err = raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", version="1.18.40", commit=sha(38), source=BRANCH)
must(str(err) == "Core only installs signed builds by version; this one has no valid signed release file.", err)
must(sorted(p.name for p in su.STAGED_ROOT.glob("*")) == staged_before, "the unsigned stage was discarded")
print("       an unsigned tree is discarded and refused, even with the development unsigned override on")
su._development_unsigned_update_allowed = lambda: False

# a tree whose VERSION is not the one listed
G["zips"][sha(37)] = make_zip("1.18.38", migs(4))
err = raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", version="1.18.39", source=BRANCH)
must("not version 1.18.39" in str(err), err)
G["zips"][sha(37)] = make_zip("1.18.39", migs(4))

# release source: the tag is resolved at stage time, once
reset()
fixture()
before = len(calls_to("/commits/v1.18.39"))
rel = su.stage_online_package("framework", "version", version="1.18.39", source=RELEASE)
must(len(calls_to("/commits/v1.18.39")) == before + 1, "one tag lookup at stage time")
must(rel["preview"]["source"] == {"type": "release", "repository": REPO, "ref": "v1.18.39", "commit": sha(37)}, rel["preview"]["source"])
raises(su.StaleCandidateError, su.stage_online_package, "framework", "version", version="1.18.39", commit=sha(5), source=RELEASE)
err = raises(su.SystemUpdateError, su.stage_online_package, "framework", "version", version="1.14.0", source=RELEASE)
must("1.15.37" in str(err), err)
print("       release source: tag resolved to a commit at stage time; a different commit is stale; an unsigned-era release is refused")

# ------------------------------------------------------------------ (13) the limits apply to every package, an offline upload included
reset()
fixture()
write_module("governance", {"framework": ">=1.18.35,<2.0.0"})
path = TMP / "offline-1.18.29.zip"
path.write_bytes(make_zip("1.18.29", migs(4)))
pre = su.inspect_archive(path)
must(pre["installable"] is False and "governance" in pre["install_block_reason"], pre)
path.write_bytes(make_zip("1.18.39", migs(4)))
pre = su.inspect_archive(path)
must(pre["installable"] is True and pre["operation"] == "downgrade", pre)
path.write_bytes(make_zip("1.18.39", migs(5)))
must(su.inspect_archive(path)["installable"] is True, "a package with more migrations passes")
path.write_bytes(make_zip("1.18.39", migs(3)))
pre = su.inspect_archive(path)
must(pre["installable"] is False and "restore the server backup" in pre["install_block_reason"], pre)
path.write_bytes(make_zip("1.18.43", migs(3)))
must(su.inspect_archive(path)["installable"] is True, "an update never meets the limits")
print("       offline package: the same limits; missing migration refused, more migrations pass, an update is untouched")

# ------------------------------------------------------------------ (14) source-level checks (Django is not installed here)
views = ast.parse((APP / "views.py").read_text(encoding="utf-8"))
cls = next(n for n in views.body if isinstance(n, ast.ClassDef) and n.name == "SystemUpdateVersionsView")
must("SessionAuthenticated" in ast.unparse(cls) and "_require_module_manager" in ast.unparse(cls), "session auth and module-manager check")
src = ast.unparse(cls)
must("get_update_source(component)" in src and "request.query_params.get('component'" in src and "GithubRateLimitError" in src and "status=400" in src, "saved source, 429 and 400 mapping")
stage_cls = next(n for n in views.body if isinstance(n, ast.ClassDef) and n.name == "SystemUpdateOnlineStageView")
stage_src = ast.unparse(stage_cls)
must("version=version" in stage_src and "source=get_update_source(component)" in stage_src and "version must be a string" in stage_src, "stage view passes version and the saved source")
must("tec-tac-system-update-versions" in (APP / "urls.py").read_text(encoding="utf-8") and "system/updates/versions/" in (APP / "urls.py").read_text(encoding="utf-8"), "route registered")
must('"SystemUpdateVersionsView": "Tec-Tac · System Updates"' in (APP / "openapi.py").read_text(encoding="utf-8"), "openapi group")
contracts = (APP / "contracts.py").read_bytes()
must(b'"/api/tfd/system/updates/versions/"' in contracts and b"source_type version" in contracts and contracts.count(b"\n") == contracts.count(b"\r\n"), "contract entry, CRLF kept")
print("       view is session-authenticated and manager-only; urls, openapi and contracts name the new route; contracts.py keeps CRLF")

print("[TEST] PASS system version picker 1.18.43")
