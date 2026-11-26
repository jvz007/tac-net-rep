#!/usr/bin/env python3
"""Regression: Core 1.18.58. The Tec-Tac web address for the Engineer Console: ui_url in the enrol answer and GET console-sessions/sign-in-info/.

The source and logic checks run without Django; the real views run on SQLite when Django is importable (tests/console_sessions_harness.py). Covered: the
address comes from the runtime setting console_ui_url when set, otherwise from the single https origin in Tactical's CORS settings plus /tec-tac/; two
https origins, none, only http origins, a regular expression or allow-all entry on its own, or a fault while reading give None (null in the bundle,
503 ui_url_unavailable on the route); an http origin beside one https origin does not make it ambiguous; a stored setting that does not validate is
unavailable and does not fall back to CORS; the request's Origin, Referer, Host and query string change nothing; the route needs no sign-in, answers
Cache-Control no-store every time (200, 403, 429, 503), refuses forwarded http (403), counts every request (the 31st in a minute is 429 with
Retry-After 60, an IPv6 address by its /64), reads a cache fault as not limited, writes no audit row and answers exactly one key; the enrol answer keeps
every earlier key and adds ui_url (also null); the route is the only new unauthenticated pattern.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


# ---- source walk (always runs)
views = (APP / "console_session_views.py").read_text(encoding="utf-8")
certs = (APP / "console_certificates.py").read_text(encoding="utf-8")
urls = (APP / "urls.py").read_text(encoding="utf-8")
tree = ast.parse(views)
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ConsoleSessionSignInInfoView")
assigned = {t.id: ast.unparse(s.value) for s in cls.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
must(assigned["authentication_classes"] == "[]" and assigned["permission_classes"] == "[AllowAny]" and assigned["throttle_classes"] == "[]", assigned)
must(assigned["http_method_names"] == "['get', 'options']", "read-only")
must(any(ast.unparse(b) == "_NoStoreView" for b in cls.bases), "every answer, refusals included, is no-store")
body = ast.unparse(ast.Module(body=cls.body[1:], type_ignores=[]))  # without the docstring
for needle in ("forwarded_plaintext", "sign_in_info_limited", "console_ui_url", "ui_url_unavailable", "tls_required", "rate_limited"):
    must(needle in body, f"the view uses {needle}")
for forbidden in ("HTTP_ORIGIN", "HTTP_REFERER", "get_host", "query_params", "_tec_tac_ui_url", "audit", "record("):
    must(forbidden not in body, f"the view never uses {forbidden}")
must('path("console-sessions/sign-in-info/", ConsoleSessionSignInInfoView.as_view()' in urls, "the route is in urls.py")
helper_src = certs[certs.index("def console_ui_url()"):certs.index("def sign_in_info_limited")]
helper_fn = ast.parse(helper_src).body[0]
helper_code = ast.unparse(ast.Module(body=helper_fn.body[1:], type_ignores=[]))  # without the docstring
helper = helper_src
for forbidden in ("request", "META", "Origin", "Referer", "get_host", "HTTP_"):
    must(forbidden not in helper_code, f"console_ui_url never touches {forbidden}")
must("validate_console_ui_url(stored) or None" in helper_code and "configured_frontend_origins" in helper_code and "startswith('https://')" in helper_code and "len(secure) == 1" in helper_code, "the order and the https-only rule")
must(helper_code.index("if stored:") < helper_code.index("configured_frontend_origins"), "a stored value decides before CORS and never falls through")
must('"ui_url": console_ui_url()' in certs, "the enrol bundle carries ui_url")
must("SIGN_IN_INFO_PER_MINUTE = 30" in certs and "return count > SIGN_IN_INFO_PER_MINUTE" in certs, "30 a minute")
views_text_all = [p.name for p in sorted(APP.glob("*_views.py")) + [APP / "views.py"] if "sign-in-info" in p.read_text(encoding="utf-8") or "console_ui_url" in p.read_text(encoding="utf-8")]
must(views_text_all == ["console_session_views.py"], f"only the Console session views name it: {views_text_all}")

spec = importlib.util.spec_from_file_location("cs_harness", HERE / "console_sessions_harness.py")
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
h = H.boot()
if h is None:
    print("console ui url 1.18.58 regression: PASS (source walk only: Django is not installed)")
    sys.exit(0)

from django.test import override_settings  # noqa: E402

from tec_tac import console_certificate_views  # noqa: E402

cc, V, M = h.cc, h.views, h.models
URL = "/api/tfd/console-sessions/sign-in-info/"
CORS = {"CORS_ORIGIN_WHITELIST": ["https://rmm.example.com"]}


def setting(value):
    M.TecTacRuntimeConfig.objects.update_or_create(singleton=1, defaults={"console_ui_url": value})


def clear_setting():
    M.TecTacRuntimeConfig.objects.all()._raw_delete("default")


def ask(extra=None, path=URL):
    return h.call(V.ConsoleSessionSignInInfoView, "GET", path, extra=extra)


def is_ui_url(**settings_):
    with override_settings(**settings_):
        return cc.console_ui_url()


h.reset()
# ---- the source of the address
must(is_ui_url(**CORS) == "https://rmm.example.com/tec-tac/", "one https origin gives origin + /tec-tac/")
must(is_ui_url(CORS_ALLOWED_ORIGINS=["https://rmm.example.com:8443"]) == "https://rmm.example.com:8443/tec-tac/", "a port is kept (CORS_ALLOWED_ORIGINS)")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["https://rmm.example.com"], CORS_ALLOWED_ORIGINS=["https://RMM.example.com:443"]) == "https://rmm.example.com/tec-tac/", "the same origin in both lists is one")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["https://a.example.com", "https://b.example.com"]) is None, "two https origins: unavailable")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["https://a.example.com"], CORS_ALLOWED_ORIGINS=["https://b.example.com"]) is None, "two https origins in two lists: unavailable")
must(is_ui_url(CORS_ORIGIN_WHITELIST=[]) is None and is_ui_url() is None, "none: unavailable")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["http://rmm.example.com", "http://localhost:8080"]) is None, "only http origins: unavailable")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["https://rmm.example.com", "http://localhost:8080"]) == "https://rmm.example.com/tec-tac/", "an http origin beside one https origin does not make it ambiguous")
must(is_ui_url(CORS_ALLOWED_ORIGIN_REGEXES=[r"^https://.*\.example\.com$"]) is None, "a regular expression alone: unavailable")
must(is_ui_url(CORS_ALLOW_ALL_ORIGINS=True) is None and is_ui_url(CORS_ORIGIN_ALLOW_ALL=True) is None, "allow-all alone: unavailable")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["*", "null", "https://rmm.example.com/path", "https://u@rmm.example.com", 5, None]) is None, "entries that are not plain origins are ignored")
must(is_ui_url(CORS_ORIGIN_WHITELIST="https://rmm.example.com") is None, "a text instead of a list is ignored (the existing reader's rule)")

# the setting wins over CORS, and is read as stored
setting("https://other.example.org/tec-tac/")
must(is_ui_url(**CORS) == "https://other.example.org/tec-tac/", "the setting wins over CORS")
must(is_ui_url() == "https://other.example.org/tec-tac/", "and works with no CORS origin at all")
must(is_ui_url(CORS_ORIGIN_WHITELIST=["https://a.example.com", "https://b.example.com"]) == "https://other.example.org/tec-tac/", "and with an ambiguous CORS list")
# an invalid stored value is unavailable and never falls back
for tampered in ("http://rmm.example.com/tec-tac/", "https://rmm.example.com/other/", "garbage", "https://u@rmm.example.com/tec-tac/", "https://rmm.example.com/tec-tac/?x=1", "   "):
    setting(tampered)
    must(is_ui_url(**CORS) is None, f"a stored {tampered!r} is unavailable and does not fall back to CORS")
clear_setting()
must(is_ui_url(**CORS) == "https://rmm.example.com/tec-tac/", "no row: CORS again")
setting("")
must(is_ui_url(**CORS) == "https://rmm.example.com/tec-tac/", "an empty setting is unset")

# faults never raise and never fall back
import tec_tac.tactical_websocket as tw  # noqa: E402

real_origins = tw.configured_frontend_origins
tw.configured_frontend_origins = lambda: (_ for _ in ()).throw(RuntimeError("settings unreadable"))
try:
    must(cc.console_ui_url() is None, "a settings-read fault: None")
finally:
    tw.configured_frontend_origins = real_origins
real_current = M.TecTacRuntimeConfig.current
M.TecTacRuntimeConfig.current = classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("database down")))
try:
    with override_settings(**CORS):
        must(cc.console_ui_url() is None, "a database fault reading the setting: None, not the CORS origin")
finally:
    M.TecTacRuntimeConfig.current = real_current
clear_setting()

# ---- the request decides nothing
with override_settings(**CORS):
    plain = ask()
    must(plain.status_code == 200 and plain.data == {"ui_url": "https://rmm.example.com/tec-tac/"}, f"{plain.status_code} {plain.data}")
    hostile = ask(extra={"HTTP_ORIGIN": "https://evil.example.net", "HTTP_REFERER": "https://evil.example.net/x", "HTTP_HOST": "evil.example.net",
                         "HTTP_X_FORWARDED_HOST": "evil.example.net"}, path=URL + "?ui_url=https://evil.example.net/tec-tac/&host=evil.example.net")
    must(hostile.status_code == 200 and hostile.data == plain.data, f"another host, Origin, Referer and ?ui_url= change nothing: {hostile.data}")
    setting("https://admin.example.org/tec-tac/")
    hostile = ask(extra={"HTTP_ORIGIN": "https://evil.example.net", "HTTP_HOST": "evil.example.net"}, path=URL + "?ui_url=https://evil.example.net/")
    must(hostile.data == {"ui_url": "https://admin.example.org/tec-tac/"}, "nor does it beat the setting")
    clear_setting()

# ---- the route: no sign-in, no-store, https only
h.reset()
rows_before = len(h.rows)
with override_settings(**CORS):
    r = ask()
    must(r.status_code == 200 and set(r.data) == {"ui_url"} and r["Cache-Control"] == "no-store", "200: exactly one key, no-store")
    must(r.data["ui_url"].startswith("https://") and r.data["ui_url"].endswith("/tec-tac/"), r.data)
    for proto in ("http", "ws", "HTTP", "http, https"):
        r = ask(extra={"HTTP_X_FORWARDED_PROTO": proto})
        must(r.status_code == 403 and r.data["code"] == "tls_required" and r["Cache-Control"] == "no-store", f"forwarded {proto} is refused: {r.status_code}")
    must(ask(extra={"HTTP_X_FORWARDED_PROTO": "https"}).status_code == 200, "forwarded https is fine")
with override_settings(CORS_ORIGIN_WHITELIST=["https://a.example.com", "https://b.example.com"]):
    r = ask()
    must(r.status_code == 503 and r.data["code"] == "ui_url_unavailable" and r["Cache-Control"] == "no-store" and set(r.data) == {"detail", "code"}, f"{r.status_code} {r.data}")
    must("Ask your administrator" in r.data["detail"] and "CORS" not in r.data["detail"], "a plain message")
must(len(h.rows) == rows_before, "no audit row for any answer")
must(not [x for x in h.rows if x.get("action") in ("deny", "custom:console-signin-refused")], "and no deny row")

# the 31st request in a minute is 429 with Retry-After 60; another address is separate; IPv6 counts by its /64
h.reset()
with override_settings(**CORS):
    for n in range(30):
        must(ask(extra={"REMOTE_ADDR": "203.0.113.50"}).status_code == 200, f"request {n + 1} of 30 is served")
    r = ask(extra={"REMOTE_ADDR": "203.0.113.50"})
    must(r.status_code == 429 and r.data["code"] == "rate_limited" and r["Retry-After"] == "60" and r["Cache-Control"] == "no-store", f"the 31st: {r.status_code}")
    must(ask(extra={"REMOTE_ADDR": "203.0.113.51"}).status_code == 200, "another address is not limited")
    for n in range(30):
        must(ask(extra={"REMOTE_ADDR": f"2001:db8:1:2::{n + 1:x}"}).status_code == 200, "an IPv6 /64: served")
    must(ask(extra={"REMOTE_ADDR": "2001:db8:1:2:ffff::9"}).status_code == 429, "the 31st from the same /64 is 429")
    must(ask(extra={"REMOTE_ADDR": "2001:db8:1:3::1"}).status_code == 200, "another /64 is not limited")
must(len(h.rows) == 0, "the counter writes no row")
# it uses its own counter: the enrol failure counter is not touched and a sign-in failure does not spend it
h.reset()
for _ in range(15):
    cc.note_failure("203.0.113.60", cc.SIGNIN_FAILURE_PREFIX)
    cc.note_failure("203.0.113.60")
with override_settings(**CORS):
    must(ask(extra={"REMOTE_ADDR": "203.0.113.60"}).status_code == 200, "failure counters are not this route's counter")
must(cc.SIGN_IN_INFO_PREFIX not in (cc.FAILURE_PREFIX, cc.SIGNIN_FAILURE_PREFIX, cc.REFUSAL_ROW_PREFIX), "its own key prefix")

# a cache fault reads as not limited, and is logged, never raised
real_cache = cc._cache
cc._cache = lambda: (_ for _ in ()).throw(RuntimeError("cache down"))
h.logs.clear()
try:
    with override_settings(**CORS):
        must(cc.sign_in_info_limited("203.0.113.70") is False, "a cache fault is not limited")
        must(ask(extra={"REMOTE_ADDR": "203.0.113.70"}).status_code == 200, "and the route still answers")
    must(any("sign-in-info request counter" in line for line in h.logs), "the fault is logged")
finally:
    cc._cache = real_cache

# ---- the enrol answer: every earlier key, plus ui_url (also null)
KEYS = {"v", "host", "server_id", "ca_public_key", "ca_cert", "cert", "serial", "not_after", "engineer"}


def enrol_bundle(stored=None):
    h.reset()
    if stored:
        setting(stored)
    admin = h.new_user("admin", superuser=True)
    user = h.new_user()
    cc.authorise(admin, user.pk)
    code = cc.create_enrolment_code(user, H.HOST)["code"]
    pc = H.Pc("Work PC")
    body = pc.console.body(code, H.HOST, pc.label)
    response = h.call(console_certificate_views.ConsoleCertificateEnrolView, "POST", "/api/tfd/console-certificates/enrol/", raw=json.dumps(body).encode(),
                      extra={"HTTP_AUTHORIZATION": f"Enrol {code}"})
    must(response.status_code == 201, f"enrol: {response.status_code} {response.data}")
    return response


with override_settings(**CORS):
    r = enrol_bundle()
    must(set(r.data) == KEYS | {"ui_url"} and r.data["ui_url"] == "https://rmm.example.com/tec-tac/", sorted(r.data))
    must(r.data["v"] == 1 and r["Cache-Control"] == "no-store", "the bundle is otherwise as before")
with override_settings(CORS_ORIGIN_WHITELIST=["https://a.example.com", "https://b.example.com"]):
    r = enrol_bundle()
    must(r.status_code == 201 and set(r.data) == KEYS | {"ui_url"} and r.data["ui_url"] is None, "enrolment succeeds with ui_url null when no address can be named")
with override_settings(**CORS):
    r = enrol_bundle("https://admin.example.org")
    must(r.data["ui_url"] == "https://admin.example.org/tec-tac/", "the bundle uses the setting too")
    r = enrol_bundle("http://tampered.example.org/tec-tac/")
    must(r.status_code == 201 and r.data["ui_url"] is None, "a tampered setting: null, and enrolment still succeeds")
# the lookup never makes enrolment fail: even if the helper itself were to break, the answer helper never raises (it catches everything)
must("except Exception" in helper and "return None" in helper, "the helper catches everything")

# ---- the new route is the only new unauthenticated pattern (the Console token and every other class are unchanged)
open_views = sorted(n.name for n in tree.body if isinstance(n, ast.ClassDef) and any(isinstance(s, ast.Assign) and s.targets[0].id == "permission_classes" and ast.unparse(s.value) == "[AllowAny]" for s in n.body))
must(open_views == ["ConsoleSessionSignInInfoView", "ConsoleSessionTokenView"], open_views)
must("ConsoleSessionAuthentication" not in ast.unparse(cls) and "SessionAuthenticated" not in ast.unparse(cls), "no authentication class of any kind is listed")

print("console ui url 1.18.58 regression: PASS")
