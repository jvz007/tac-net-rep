#!/usr/bin/env python3
"""1.17.99 (AD-56, C1): the honest failure state for a repository that no longer offers public downloads, and the Licensing Server URL.

Covered: a sync that gets HTTP 401, 403, 404 or 410 marks the repository retired (cache flag, status row, availability state
repository_retired and its plain message); HTTP 429, 500, 502, 503, a timeout and a TLS error do not; a retired repository's cached
releases carry download_unavailable, are left out of modules[] and cannot be staged (no download is attempted); a transient failure
keeps the old cache offered; a later successful sync clears the retired state; a 1.17.98 cache (no flag, error text only) is read as
retired and a 1.17.98 cache with a 5xx text is not; a retired repository beside a healthy one leaves the healthy one offered;
validate/get_licensing_server_url (https only, no user info, no query or fragment, host required, bad value -> default with a reason,
the value is never logged); install.sh writes the key only when absent and carries an administrator's value over unchanged; the
contract row and notes; the help text and docs; no module under modules/ uses the repository code.

module_repository.py imports Django, so the real functions are read with ast and run with stubs (the method of
tests/online-catalog-availability-1.17.41.py). Fakes keep the real signatures; nothing touches the network.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_PATH = ROOT / "framwork/tec_tac/module_repository.py"
URL_PATH = ROOT / "framwork/tec_tac/licensing_server_url.py"
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


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    if constraint in ("*", ""):
        return True
    if constraint.startswith(">"):
        return tuple(map(int, version.split("."))) > tuple(map(int, constraint[1:].split(".")))
    return True


CACHE_DIR = Path(tempfile.mkdtemp(prefix="repository-retired-")) / "cache"
CACHE_DIR.mkdir(parents=True)
REPOS: list[dict] = []
INSTALLED: list[dict] = []
FETCHES: list[str] = []
FETCH_BEHAVIOUR: dict = {}
SHA = "ab" * 32


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


ns: dict = {
    "json": json, "re": re, "urllib": urllib, "Path": Path, "CACHE_ROOT": CACHE_DIR, "version_satisfies": version_satisfies,
    "ModuleStateError": ModuleStateError, "Counter": Counter, "_utcnow": _utcnow, "datetime": datetime, "timezone": timezone,
}
names = {
    "MAX_INDEX_BYTES", "MAX_SKIPPED_RECORDS", "MAX_SKIPPED_TEXT", "MAX_SKIPPED_REASON", "MAX_INFORMATIONAL_TEXT",
    "SKIPPED_REASON_FOR_OTHERS", "_CONTROL_CHARACTERS", "ModuleRepositoryError", "RepositoryHttpError", "RETIRED_STATUSES",
    "_LEGACY_RETIRED_ERROR", "RETIRED_MESSAGE", "RETIRED_RELEASE_REASON", "_skipped_summary", "repository_status",
    "CREDENTIALS_STATUSES", "CREDENTIALS_REJECTED_MESSAGE", "CREDENTIALS_RELEASE_REASON", "_has_credentials", "_legacy_error_status", "_cache_credentials_rejected", "_repo_raw",  # 1.17.100
    "_cache_retired", "_cached_modules", "_candidate_compatibility", "online_catalog", "all_repository_status", "public_repository",
    "_AVAILABILITY_MESSAGES", "_availability", "sync_repository", "stage_repository_package", "_PathUpload",
}
exec(compile(ast.Module(body=extract(REPO_TREE, names), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only
Err = ns["ModuleRepositoryError"]
HttpErr = ns["RepositoryHttpError"]


def fake_fetch(url, maximum, timeout=12, *, trust="custom"):
    FETCHES.append(url)
    behaviour = FETCH_BEHAVIOUR["next"]
    if isinstance(behaviour, BaseException):
        raise behaviour
    return behaviour


def fake_accepted(raw_modules, repo):
    return [dict(item) for item in raw_modules], []


def fake_atomic(path, payload):
    Path(path).write_text(json.dumps(payload), encoding="utf-8")


ns["_fetch"] = fake_fetch
ns["_accepted_releases"] = fake_accepted
ns["_atomic_repo_json"] = fake_atomic
ns["list_repositories"] = lambda: [ns["public_repository"](dict(r)) for r in REPOS]
ns["_repo"] = lambda rid: next(dict(r) for r in REPOS if r["id"] == rid)
ns["installed_catalog_v2"] = lambda: [dict(i) for i in INSTALLED]
ns["_check_runtime_requirements"] = lambda requires: []


def repo(rid="techflow", enabled=True, priority=10):
    return {"id": rid, "name": rid.title(), "url": f"https://{rid}.test/index.json", "trust": "official", "priority": priority,
            "enabled": enabled}


def entry(module_id, version="0.4.0"):
    return {"id": module_id, "name": module_id.title(), "version": version, "download_url": f"https://x.test/{module_id}.zip",
            "sha256": SHA, "dependencies": {}, "optional_dependencies": {}, "requires": {}}


def write_cache(rid, modules=None, **extra):
    payload = {"schema": 1, "repository_id": rid, "status": "ok", "error": None, "modules": modules or [],
               "skipped": [], "skipped_count": 0, "synced_at": "2026-10-30T00:00:00+00:00"}
    payload.update(extra)
    (CACHE_DIR / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")


def read_cache(rid):
    return json.loads((CACHE_DIR / f"{rid}.json").read_text(encoding="utf-8"))


def reset(repos, installs=()):
    for item in CACHE_DIR.glob("*.json"):
        item.unlink()
    REPOS[:] = repos
    INSTALLED[:] = list(installs)
    FETCHES.clear()


def sync_fails(exc):
    FETCH_BEHAVIOUR["next"] = exc
    try:
        ns["sync_repository"]("techflow")
    except Err:
        return
    raise AssertionError("the sync should have failed")


# 1. The 4xx mapping.
for code in (401, 403, 404, 410):
    reset([repo()])
    write_cache("techflow", [entry("alpha")])
    sync_fails(HttpErr(f"Repository request returned HTTP {code}.", code))
    cache = read_cache("techflow")
    must(cache["retired"] is True and cache["error_status"] == code and cache["status"] == "error", cache)
    status = ns["repository_status"]("techflow")["sync"]
    must(status["retired"] is True and status["status"] == "error", status)
    cat = ns["online_catalog"]()
    must(cat["availability"]["state"] == "repository_retired", cat["availability"])
    must(cat["availability"]["message"].startswith("This module repository no longer offers public downloads."), cat["availability"])
    must("Settings → Modules" in cat["availability"]["message"] and ".zip.sig" in cat["availability"]["message"], cat["availability"])
    must(cat["modules"] == [] and cat["count"] == 0, cat["modules"])
print("       HTTP 401, 403, 404 and 410 set retired, availability.state repository_retired and the plain message")

# 2. Not retired: other statuses, timeouts, TLS and network errors, a bad index.
for exc in (HttpErr("Repository request returned HTTP 500.", 500), HttpErr("Repository request returned HTTP 502.", 502),
            HttpErr("Repository request returned HTTP 503.", 503), HttpErr("Repository request returned HTTP 429.", 429),
            TimeoutError("timed out"), Err("Repository request failed due to a network or TLS error."), ValueError("bad json")):
    reset([repo()])
    write_cache("techflow", [entry("alpha")])
    sync_fails(exc)
    cache = read_cache("techflow")
    must("retired" not in cache and cache["status"] == "error", (exc, cache))
    cat = ns["online_catalog"]()
    must(cat["availability"]["state"] == "ready" and [m["id"] for m in cat["modules"]] == ["alpha"], (exc, cat["availability"]))
    must(cat["availability"]["retired_repositories"] == 0, cat["availability"])
print("       HTTP 429/500/502/503, timeouts, network and TLS errors and a bad index are not retired; the old cache stays offered")

# 3. Never synced and retired: no cache, the state is repository_retired, not sync_failed.
reset([repo()])
sync_fails(HttpErr("Repository request returned HTTP 404.", 404))
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "repository_retired", cat["availability"])
print("       first-ever sync that gets 404: repository_retired")

# 4. A stale cache is not offered for staging, and no download is attempted.
reset([repo()], [])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 410.", retired=True, error_status=410)
releases = ns["_cached_modules"](repo())
must(releases and all(r["download_unavailable"] is True and r["download_unavailable_reason"] for r in releases), releases)
for args in (("techflow", "alpha"), ("techflow", "alpha", "0.4.0")):
    try:
        ns["stage_repository_package"](*args)
    except Err as exc:
        must("no longer offers public downloads" in str(exc), str(exc))
    else:
        raise AssertionError("a retired release was staged")
must(FETCHES == [], FETCHES)
print("       a retired repository's releases carry download_unavailable; stage_repository_package refuses before any fetch")

# 5. A healthy repository beside a retired one stays offered; the state is not retired.
reset([repo("old", priority=5), repo("fresh", priority=20)])
write_cache("old", [entry("alpha")], status="error", error="Repository request returned HTTP 404.", retired=True)
write_cache("fresh", [entry("beta")])
cat = ns["online_catalog"]()
must([m["id"] for m in cat["modules"]] == ["beta"] and cat["availability"]["state"] == "ready", cat)
must(cat["availability"]["retired_repositories"] == 1, cat["availability"])
print("       a healthy repository beside a retired one: only its modules are offered, state ready, retired_repositories 1")

# 6. Recovery: a later successful sync clears the retired state.
reset([repo()])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 404.", retired=True, retired_at="x", error_status=404)
FETCH_BEHAVIOUR["next"] = json.dumps({"schema": 1, "modules": [entry("alpha", "0.5.0")]}).encode("utf-8")
ns["sync_repository"]("techflow")
cache = read_cache("techflow")
must("retired" not in cache and cache["status"] == "ok", cache)
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "ready" and cat["modules"][0]["latest_version"] == "0.5.0", cat["availability"])
print("       a successful sync rewrites the cache: not retired, modules offered again")

# 7. Upgrade from 1.17.98: no flag in the file, only the stored error text.
reset([repo()])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 404.", last_attempt_at="2026-11-01T03:00:00+00:00")
must(ns["repository_status"]("techflow")["sync"]["retired"] is True, "a 1.17.98 404 cache must read as retired")
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "repository_retired" and cat["modules"] == [], cat["availability"])
reset([repo()])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 503.", last_attempt_at="2026-11-01T03:00:00+00:00")
must(ns["repository_status"]("techflow")["sync"]["retired"] is False, "a 1.17.98 503 cache is not retired")
cat = ns["online_catalog"]()
must(cat["availability"]["state"] == "ready" and [m["id"] for m in cat["modules"]] == ["alpha"], cat["availability"])
reset([repo()])
write_cache("techflow", [entry("alpha")])  # a healthy 1.17.98 cache, untouched
must(ns["repository_status"]("techflow")["sync"]["retired"] is False and ns["online_catalog"]()["availability"]["state"] == "ready", "healthy cache")
reset([repo()])
write_cache("techflow", [entry("alpha")], status="error", error="Repository request returned HTTP 404 on the index.")
must(ns["repository_status"]("techflow")["sync"]["retired"] is False, "only the exact 1.17.98 text is read as retired")
reset([repo()])
(CACHE_DIR / "techflow.json").write_text("{not json", encoding="utf-8")
must(ns["repository_status"]("techflow")["sync"]["status"] == "error" and ns["_cached_modules"](repo()) == [], "corrupt cache")
print("       upgrade from 1.17.98: the stored 404 text reads as retired with no migration; 503, healthy, odd and corrupt caches do not")

# 8. A transient failure after a retired one keeps the retired state.
reset([repo()])
write_cache("techflow", [entry("alpha")])
sync_fails(HttpErr("Repository request returned HTTP 404.", 404))
sync_fails(HttpErr("Repository request returned HTTP 500.", 500))
must(read_cache("techflow").get("retired") is True, "a 500 after a retired sync keeps the retired flag")
print("       a 5xx after a retired sync keeps the retired state")

# 9. Licensing Server URL accessor.
spec = importlib.util.spec_from_file_location("licensing_server_url_under_test", URL_PATH)
lsu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lsu)
DEFAULT = "https://lic-service.tec-tac.techxflow.net.za"
must(lsu.DEFAULT_LICENSING_SERVER_URL == DEFAULT, lsu.DEFAULT_LICENSING_SERVER_URL)
conf_dir = Path(tempfile.mkdtemp(prefix="lic-url-"))
conf = conf_dir / "tec-tac.conf"
os.environ["TEC_TAC_CONFIG_FILE"] = str(conf)


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


capture = _Capture()
logging.getLogger("tec_tac.licensing_server_url").addHandler(capture)


def got(value=None, text=None):
    lsu._logged_reasons.clear()
    if text is not None:
        conf.write_text(text, encoding="utf-8")
    elif value is None:
        conf.write_text("TEC_TAC_ENVIRONMENT=production\n", encoding="utf-8")
    else:
        conf.write_text(f"TEC_TAC_ENVIRONMENT=production\nTEC_TAC_LICENSING_SERVER_URL={value}\n", encoding="utf-8")
    return lsu.get_licensing_server_url()


unset = got()
must(unset == {"url": DEFAULT, "source": "default", "configured": False, "reason": None}, unset)
conf.unlink()
must(lsu.get_licensing_server_url()["url"] == DEFAULT, "a missing file reads as unset")
must(got("")["source"] == "default" and got("")["reason"] is None, "an empty value is unset")
ok_cases = {
    "https://lic.example.com": "https://lic.example.com",
    "https://lic.example.com/": "https://lic.example.com",
    "  https://LIC.Example.com:8443/api/  ": "https://lic.example.com:8443/api",
    "https://lic.example.com:443": "https://lic.example.com",
    "https://10.1.2.3": "https://10.1.2.3",
    "https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443",
}
for raw, expected in ok_cases.items():
    result = got(raw)
    must(result["url"] == expected and result["source"] == "config" and result["configured"] is True and result["reason"] is None, (raw, result))
bad_cases = [
    "http://lic.example.com", "ftp://lic.example.com", "lic.example.com", "//lic.example.com", "https://",
    "https://user@lic.example.com", "https://user:secret@lic.example.com", "https://:secret@lic.example.com",
    "https://lic.example.com?x=1", "https://lic.example.com/?", "https://lic.example.com#frag", "https://lic.example.com/#",
    "https://lic.example.com:99999", "https://lic.example.com:abc", "https://lic example.com", "https://lic.example.com\\x",
    "https://lic.example.com/a/../b", "https://lic.example.com/a;x=1", "https://-bad-.example.com/x y", "https://exa_mple.com",
    "https://" + "a" * 600, "javascript:alert(1)",
]
for raw in bad_cases:
    result = got(raw)
    must(result["url"] == DEFAULT and result["source"] == "default" and result["configured"] is False and result["reason"], (raw, result))
    must("secret" not in json.dumps(result), result)
    pair = lsu.validate_licensing_server_url(raw)
    must(pair[0] is None and pair[1], (raw, pair))
must(any("is not used" in line for line in capture.lines), capture.lines)
must(not any("secret" in line or "example.com" in line for line in capture.lines), capture.lines)
for control in ("https://lic.example.com/a\x01b", "https://lic.example.com/a\x7fb", "https://lic.example.com/a\u0085b"):
    must(lsu.validate_licensing_server_url(control)[0] is None, control)
must(lsu.validate_licensing_server_url(None)[0] is None and lsu.validate_licensing_server_url(5)[0] is None, "non-text")
multi = got(text="# TEC_TAC_LICENSING_SERVER_URL=https://commented.example\nTEC_TAC_LICENSING_SERVER_URL=https://a.example\nTEC_TAC_LICENSING_SERVER_URL=https://b.example\n")
must(multi["url"] == "https://b.example", multi)
src = URL_PATH.read_text(encoding="utf-8")
must(not re.search(r"\b(write_text|write_bytes|urlopen|requests|http\.client|socket|subprocess|Authorization|Bearer)\b", src), "accessor must only read")
must("open(" not in src, "accessor opens no file for writing")
print("       URL accessor: https only, no user info, query, fragment, bad port or characters; invalid -> default with a reason; value never logged")

# 10. install.sh: the key is written only when absent; an administrator's value is carried over exactly.
install_text = (ROOT / "install.sh").read_text(encoding="utf-8")
read_start = install_text.index('EXISTING_LICENSING_SERVER_URL=""')
read_end = install_text.index('cat > "${MODULE_CONFIG}" <<EOF', read_start)
write_start = install_text.index('if [[ "${LICENSING_SERVER_URL_PRESENT}" == "1" ]]; then')
write_end = install_text.index('chown root:root "${MODULE_CONFIG}"', write_start)
read_block, write_block = install_text[read_start:read_end], install_text[write_start:write_end]
bash = shutil.which("bash")


def run_install(existing, env_value):
    path = conf_dir / "install-conf"
    if existing is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(existing.encode("utf-8"))
    script = (
        'set -u\nfail() { echo "FAIL: $*" >&2; exit 9; }\nMODULE_CONFIG="$1"\n' + read_block
        + 'printf "TEC_TAC_ENVIRONMENT=production\\n" > "${MODULE_CONFIG}"\n' + write_block
    )
    env = {**os.environ}
    env.pop("TEC_TAC_LICENSING_SERVER_URL", None)
    if env_value is not None:
        env["TEC_TAC_LICENSING_SERVER_URL"] = env_value
    done = subprocess.run([bash, "-c", script, "_", str(path)], capture_output=True, text=True, env=env, timeout=30, check=False)
    return done, (path.read_bytes().decode("utf-8") if path.is_file() else "")


must("fail" in write_block and "CR/LF" in write_block, "env value newline check")
if bash:
    done, text = run_install(None, None)
    must(done.returncode == 0 and "LICENSING" not in text, (done.stderr, text))
    done, text = run_install("TEC_TAC_ENVIRONMENT=production\n", "https://lic.example.com")
    must(done.returncode == 0 and text.count("TEC_TAC_LICENSING_SERVER_URL=https://lic.example.com") == 1, (done.stderr, text))
    done, text = run_install("TEC_TAC_LICENSING_SERVER_URL=https://admin.example.com/x\n", "https://env.example.com")
    must(done.returncode == 0 and text.count("TEC_TAC_LICENSING_SERVER_URL=") == 1 and "admin.example.com/x" in text and "env.example.com" not in text, text)
    done, text = run_install("TEC_TAC_LICENSING_SERVER_URL=http://bad value\r\n", None)
    must(done.returncode == 0 and "TEC_TAC_LICENSING_SERVER_URL=http://bad value\n" in text, repr(text))
    done, text = run_install("TEC_TAC_ENVIRONMENT=production\n", "https://x.example\nINJECTED=1")
    must(done.returncode == 9 and "INJECTED" not in text, (done.returncode, text))
    print("       install.sh: key written only when absent; an administrator's value (even invalid) is kept; newline injection refused")
else:
    print("       install.sh behaviour: SKIPPED here (no bash)")
must("TEC_TAC_LICENSING_SERVER_URL" not in (ROOT / "framwork/tec_tac/urls.py").read_text(encoding="utf-8"), "no web route for the key")
for path in (ROOT / "framwork/tec_tac").glob("*.py"):
    if path.name in {"licensing_server_url.py", "contracts.py"}:
        continue
    must("TEC_TAC_LICENSING_SERVER_URL" not in path.read_text(encoding="utf-8"), f"{path.name} must not read or write the key")

# 11. Contract, help text and docs.
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must('"name": "get_licensing_server_url"' in contracts and '"import_path": "tec_tac.licensing_server_url"' in contracts, "contract row")
must("repository_retired" in contracts and "download_unavailable" in contracts and "retired_repositories" in contracts, "contract notes")
FOOTER = "techxflow.co.za"
doc = (ROOT / "docs/module-repositories.md").read_text(encoding="utf-8")
for needle in ("repository_retired", "download_unavailable", "TEC_TAC_LICENSING_SERVER_URL", "Settings → Modules", "Troubleshooting"):
    must(needle in doc, f"docs/module-repositories.md lacks {needle!r}")
must(FOOTER in doc.rstrip().splitlines()[-1], "footer last in docs/module-repositories.md")
trouble = (ROOT / "docs/troubleshooting-diagnostics.md").read_text(encoding="utf-8")
must("repository_retired" in trouble and "TEC_TAC_LICENSING_SERVER_URL" in trouble, "troubleshooting entries")
must(FOOTER in trouble.rstrip().splitlines()[-1], "footer last in docs/troubleshooting-diagnostics.md")
print("       contract row and notes, docs and troubleshooting text (footer last)")

# 12. Module compatibility: no module uses the repository code or the online catalogue route.
modules_root = ROOT.parents[1] / "modules"
if modules_root.is_dir():
    hits = []
    for path in modules_root.rglob("*.py"):
        if "tests" in path.parts or "node_modules" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if re.search(r"catalog/online|module_repository|repository_status|online_catalog", text):
            hits.append(str(path.relative_to(modules_root)))
    must(not hits, f"a module uses the repository code: {hits}")
    print("       modules/: no module calls the online catalogue or the repository code")
else:
    print("       modules/ not found here: compatibility grep SKIPPED")

print("[TEST] PASS repository retired 1.17.99")
