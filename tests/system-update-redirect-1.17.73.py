#!/usr/bin/env python3
"""1.17.73 regression (external audit closure report, H1): redirects of the three GitHub call sites in system_update.py.

_github_json, _github_content_bytes and _download_to_stage go through _github_open. A redirect is followed over https only, at most 5 hops,
and the Authorization header goes only to api.github.com, github.com and codeload.github.com on the default port. codeload.github.com is
approved on purpose (Johan, 21 October 2026): the zipball redirect from api.github.com ends there and it keeps the token.
No network: sockets and urlopen are replaced by a refuse function for the whole run and a fake https handler answers.
Django is not installed on the development PC, so the real system_update.py is loaded against stubs, as tests/update-source-1.17.4.py does.
"""
from __future__ import annotations

import ast
import email.message
import importlib.util
import io
import json
import socket
import sys
import types
import urllib.error
import urllib.request
import urllib.response
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
TOKEN = "ghp_SECRETTOKEN123"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def refuse(*a, **k):
    raise AssertionError("network access attempted")


socket.socket = refuse
socket.create_connection = refuse
urllib.request.urlopen = refuse

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

HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "tec-tac-system-updater/1.3",
           "X-GitHub-Api-Version": "2022-11-28", "Authorization": f"Bearer {TOKEN}"}
su._github_headers = lambda: dict(HEADERS)


class Fake(urllib.request.BaseHandler):
    """Answers every https request from a table of url -> (code, location or body); records what it received."""

    handler_order = 100

    def __init__(self, table):
        self.table = table
        self.seen = []

    def https_open(self, req):
        self.seen.append((req.full_url, {k.lower(): v for k, v in list(req.header_items())}))
        code, payload = self.table.get(req.full_url, (200, b"{}"))
        redirect = code in (301, 302, 303, 307, 308)
        msg_headers = email.message.Message()
        if redirect:
            msg_headers["Location"] = payload
        response = urllib.response.addinfourl(io.BytesIO(b"" if redirect else payload), msg_headers, req.full_url, code)
        response.msg = "Found" if redirect else "OK"
        return response


ORIG_BUILD = su._build_github_opener


def install(table):
    fake = Fake(table)
    su._build_github_opener = lambda *extra: ORIG_BUILD(fake, *extra)
    return fake


START = "https://api.github.com/repos/o/r/zipball/" + "a" * 40
BODY = b"zipbytes"


def opened(first=START):
    return su._github_open(urllib.request.Request(first, headers=su._github_headers()), timeout=5)


def run(target):
    fake = install({START: (302, target), target: (200, BODY)})
    with opened() as response:
        must(response.read() == BODY, "body")
    last_url, last_headers = fake.seen[-1]
    must(last_url == target, (last_url, target))
    return fake, last_headers


# (1) and (2): approved hosts keep the token
for target in ("https://codeload.github.com/o/r/legacy.zip/refs/heads/x?token=signed", "https://github.com/o/r/zip/x",
               "https://api.github.com/repos/o/r/zipball/y"):
    _, seen = run(target)
    must(seen.get("authorization") == f"Bearer {TOKEN}", f"{target} lost the token")
print("       api.github.com, github.com and codeload.github.com keep the token (codeload receives it by design)")

# (3) other hosts are followed without the token, other headers intact
for target in ("https://evil.example/x", "https://codeload.github.com.evil.example/x", "https://evilgithub.com/x",
               "https://api.github.com@evil.example/x", "https://codeload.github.com:8443/x"):
    _, seen = run(target)
    must("authorization" not in seen, f"{target} kept the token: {seen}")
    must(seen.get("accept") == HEADERS["Accept"] and seen.get("user-agent") == HEADERS["User-Agent"]
         and seen.get("x-github-api-version") == HEADERS["X-GitHub-Api-Version"], f"{target}: other headers changed: {seen}")
print("       lookalike, user-info and non-default-port hosts are followed without Authorization; other headers stay")

# (4) non-https redirects are refused and never reached
for target in ("http://codeload.github.com/x?token=QUERYSECRET", "http://evil.example/x", "file:///etc/passwd", "ftp://x/y"):
    fake = install({START: (302, target)})
    try:
        opened()
        raise AssertionError(f"{target} was followed")
    except su.SystemUpdateError as exc:
        text = str(exc)
        must(TOKEN not in text and "QUERYSECRET" not in text and "token=" not in text and target not in text, text)
    must([u for u, _ in fake.seen] == [START], f"the target was reached: {fake.seen}")
print("       http, file and ftp redirects raise SystemUpdateError without the token or URL, and the target is never reached")


# (5) hop limit: chain(n) is n + 1 redirects from START
def chain(n):
    urls = [f"https://codeload.github.com/hop/{i}" for i in range(n + 1)]
    table = {START: (302, urls[0])}
    for i in range(n):
        table[urls[i]] = (302, urls[i + 1])
    table[urls[n]] = (200, BODY)
    return table


install(chain(4))
with opened() as response:
    must(response.read() == BODY, "five redirects complete")
install(chain(5))
try:
    opened()
    raise AssertionError("six redirects completed")
except su.SystemUpdateError as exc:
    must("too many" in str(exc), exc)
print("       a chain of exactly 5 redirects completes; a chain of 6 raises SystemUpdateError")

# (6) loop
install({START: (302, "https://codeload.github.com/a"), "https://codeload.github.com/a": (302, "https://codeload.github.com/b"),
         "https://codeload.github.com/b": (302, "https://codeload.github.com/a")})
try:
    opened()
    raise AssertionError("a loop completed")
except (su.SystemUpdateError, urllib.error.HTTPError):
    pass
print("       a redirect loop raises")

# (7) first URL must be https
fake = install({})
for first in ("http://api.github.com/x", "file:///etc/passwd", "ftp://x/y"):
    try:
        su._github_open(urllib.request.Request(first), timeout=5)
        raise AssertionError(f"{first} was opened")
    except su.SystemUpdateError:
        pass
must(not fake.seen, "a refused first URL reached the handler")
print("       a first URL that is not https is refused")

# (8) source check
source = (APP / "system_update.py").read_text(encoding="utf-8")
tree = ast.parse(source)
funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
for name in ("_github_json", "_github_content_bytes", "_download_to_stage"):
    calls = [ast.unparse(c.func) for c in ast.walk(funcs[name]) if isinstance(c, ast.Call)]
    must("urllib.request.urlopen" not in calls, f"{name} still calls urlopen")
    must("_github_open" in calls, f"{name} does not call _github_open")
must(not any(isinstance(c, ast.Call) and ast.unparse(c.func) == "urllib.request.urlopen" for c in ast.walk(tree)), "a urlopen call remains")
print("       the three call sites use _github_open and no urlopen call remains")

# (9) end to end
install({"https://api.github.com/repos/o/r/releases": (200, json.dumps({"ok": 1}).encode())})
must(su._github_json("https://api.github.com/repos/o/r/releases") == {"ok": 1}, "json")
content = {"type": "file", "encoding": "base64", "content": "aGVsbG8="}
install({"https://api.github.com/repos/o/r/contents/a/b.txt?ref=main": (200, json.dumps(content).encode())})
must(su._github_content_bytes("o/r", "a/b.txt", "main") == b"hello", "content")
staged = {}
su._stage_bytes = lambda reader, **kw: staged.update(data=reader(), **kw) or {"staged": True}
fake = install({START: (302, "https://codeload.github.com/o/r/legacy.zip/x"), "https://codeload.github.com/o/r/legacy.zip/x": (200, BODY)})
must(su._download_to_stage(START, filename="x.zip", source={"type": "branch"}, component="framework") == {"staged": True}, "stage")
must(staged["data"] == BODY and staged["expected_component"] == "framework", staged)
must(fake.seen[-1][1].get("authorization") == f"Bearer {TOKEN}", "the codeload zipball hop keeps the token")
print("       _github_json, _github_content_bytes and _download_to_stage work through the redirect handler")

# (10) _github_headers is untouched: the token line is still there (tests/review-1.15.52-rebuild.sh runs it for real)
must('headers["Authorization"] = f"Bearer {token}"' in source, "_github_headers token line")
print("system-update-redirect-1.17.73: PASS")
