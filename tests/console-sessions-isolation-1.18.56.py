#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). The Console token works on the Console routes and nowhere else.

Source walk (always): ConsoleSessionAuthentication is listed only on the three Console-only views of console_session_views.py (current, activity,
sign-out), no other Core file lists it as an authentication class, every console-sessions route in urls.py is one of the five views, and no extension
in this tree uses the class. Runtime (where Django is importable): the Console token is refused on a sample of Core routes (a session-guarded route
with Knox-style authentication, the browser's authorise route), a Knox token and a Tactical API key are refused on the Console routes, a request that
carries a Knox Authorization and X-Tectac-Console-Proof is refused (on a browser route and on a Console route), a TecTacConsole header next to
another authenticator keeps the conflict refusal, current/ never returns a secret.
"""
import ast
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"
spec = importlib.util.spec_from_file_location("cs_harness", HERE / "console_sessions_harness.py")
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must = H.must

# ---- source walk
CONSOLE_ONLY = {"ConsoleSessionCurrentView", "ConsoleSessionActivityView", "ConsoleSessionSignOutView"}
views_tree = ast.parse((APP / "console_session_views.py").read_text(encoding="utf-8"))
classes = {n.name: n for n in views_tree.body if isinstance(n, ast.ClassDef)}


def assigned(cls, name):
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign) and any(getattr(t, "id", "") == name for t in stmt.targets):
            return ast.unparse(stmt.value)
    return None


must(assigned(classes["_ConsoleOnlyView"], "authentication_classes") == "[ConsoleSessionAuthentication]", "the Console-only base lists the class alone")
must(assigned(classes["_ConsoleOnlyView"], "permission_classes") == "[ConsoleSessionAuthenticated]", "and its permission alone")
for name in CONSOLE_ONLY:
    must(any(ast.unparse(b) == "_ConsoleOnlyView" for b in classes[name].bases), f"{name} is Console-only")
    must(assigned(classes[name], "authentication_classes") is None, f"{name} does not change the base's classes")
for name in ("ConsoleSessionAuthoriseView", "ConsoleSessionTokenView"):
    must("ConsoleSessionAuthentication" not in ast.unparse(classes[name]) and "_ConsoleOnlyView" not in ast.unparse(classes[name]), f"{name} does not use the Console authentication")
must(assigned(classes["ConsoleSessionTokenView"], "authentication_classes") == "[]", "the token route has no authentication of its own (the code and the proof are the credential)")
must(assigned(classes["ConsoleSessionAuthoriseView"], "permission_classes") == "[SessionAuthenticated]", "authorise needs the browser's session guard")

holders = []
for path in sorted(APP.rglob("*.py")):
    text = path.read_text(encoding="utf-8")
    if "ConsoleSessionAuthentication" in text:
        holders.append(path.name)
must(sorted(holders) == ["console_session_views.py", "console_sessions.py", "contracts.py", "session_security.py"], f"only the Console files, the contract text and the session guard's one branch name the class: {holders}")
for path in sorted(APP.rglob("*_views.py")) + [APP / "views.py"]:
    if path.name == "console_session_views.py":
        continue
    must("ConsoleSessionAuthentication" not in path.read_text(encoding="utf-8"), f"{path.name} does not list the Console class")
for path in sorted((ROOT / "extensions").rglob("*.py")) if (ROOT / "extensions").exists() else []:
    must("ConsoleSessionAuthentication" not in path.read_text(encoding="utf-8"), f"{path} does not use the Console class")

urls_text = (APP / "urls.py").read_text(encoding="utf-8")
paths = re.findall(r'path\("(console-sessions/[^"]*)", (\w+)\.as_view\(\)', urls_text)
must(sorted(p for p, _ in paths) == ["console-sessions/activity/", "console-sessions/authorise/", "console-sessions/current/", "console-sessions/sign-out/", "console-sessions/token/"],
     f"the five routes: {paths}")
must({v for _, v in paths} == {"ConsoleSessionActivityView", "ConsoleSessionAuthoriseView", "ConsoleSessionCurrentView", "ConsoleSessionSignOutView", "ConsoleSessionTokenView"}, "each is one of the five views")
for route, view in paths:
    must(("Console-only" if view in CONSOLE_ONLY else "other") == ("Console-only" if route.split("/")[1] in ("current", "activity", "sign-out") else "other"), f"{route} maps to the right kind")
tactical_auth = (APP / "session_security.py").read_text(encoding="utf-8")
must('"TecTacConsole "' in tactical_auth, "the session guard's branch names the scheme")

modules_dir = ROOT.parent.parent / "modules"
if modules_dir.is_dir():
    users = [str(p.relative_to(modules_dir)) for p in modules_dir.rglob("*.py") if "TecTacConsole" in p.read_text(encoding="utf-8", errors="ignore") and "console_session" in p.read_text(encoding="utf-8", errors="ignore")]
    must(not users, f"no module uses the new capability yet (networkprobe's M1 will): {users}")

h = H.boot()
if h is None:
    print("console sessions isolation 1.18.56 regression: PASS (source walk only: Django is not installed)")
    sys.exit(0)

import types  # noqa: E402

from rest_framework.authentication import BaseAuthentication, get_authorization_header  # noqa: E402

M, cc, cs, V = h.models, h.cc, h.cs, h.views
CURRENT = "/api/tfd/console-sessions/current/"
h.reset()
user, pc, r = h.sign_in()
must(r.status_code == 201, "sign-in")


class KnoxLike(BaseAuthentication):
    """What Knox's TokenAuthentication does with a header of another scheme: nothing."""

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b"token":
            return None
        return None  # (a real token would be looked up here; this stand-in only needs to prove the other scheme is ignored)

    def authenticate_header(self, request):
        return "Token"


# the Console token on a session-guarded Core route and on the browser's authorise route
class Mine(V.ConsoleSessionAuthoriseView):
    authentication_classes = [KnoxLike]
    throttle_classes = []


for label, view, path in (("a session-guarded route", Mine, "/api/tfd/console-sessions/authorise/"),):
    raw = b"{}"
    request = h.factory.post(path, data=raw, content_type="application/json", HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}",
                             HTTP_X_TECTAC_CONSOLE_PROOF=pc.request_proof(H.HOST, pc.server_id, "POST", path, raw))
    resp = view.as_view()(request)
    must(resp.status_code in (401, 403), f"the Console token on {label} is refused: {resp.status_code}")
    must(not M.TecTacConsoleSignin.objects.filter(used_at__isnull=True).exists(), "and made no code")

from tec_tac import console_certificate_views  # noqa: E402


class MineRoute(console_certificate_views.ConsoleCertificateMineView):
    authentication_classes = [KnoxLike]


request = h.factory.get("/api/tfd/console-certificates/mine/", HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}",
                        HTTP_X_TECTAC_CONSOLE_PROOF=pc.request_proof(H.HOST, pc.server_id, "GET", "/api/tfd/console-certificates/mine/", b""))
resp = MineRoute.as_view()(request)
must(resp.status_code in (401, 403), f"the Console token on a Core route with Knox-style authentication is refused: {resp.status_code}")
# and on the real default authentication classes of DRF (session and basic) it is refused too
resp = console_certificate_views.ConsoleCertificateMineView.as_view()(h.factory.get("/api/tfd/console-certificates/mine/", HTTP_HOST=H.HOST, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}"))
must(resp.status_code in (401, 403), "and on DRF's default classes")

# a Knox token and a Tactical API key on the Console routes
browser = h.browser(user)
request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=browser.header)
must(V.ConsoleSessionCurrentView.as_view()(request).status_code == 401, "a Knox token is refused on a Console route")
request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=browser.header, HTTP_X_TECTAC_CONSOLE_PROOF=pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT))
must(V.ConsoleSessionCurrentView.as_view()(request).status_code == 401, "a Knox Authorization with a Console proof is refused on a Console route")
request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_X_API_KEY="an-api-key")
must(V.ConsoleSessionCurrentView.as_view()(request).status_code == 401, "an API key is refused on a Console route")
request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP)
must(V.ConsoleSessionCurrentView.as_view()(request).status_code == 401, "no credential is refused")

# a Knox Authorization and X-Tectac-Console-Proof together on a browser route are refused (the session guard)
resp = h.call(console_certificate_views.ConsoleCertificateMineView, "GET", "/api/tfd/console-certificates/mine/", session=browser,
              extra={"HTTP_X_TECTAC_CONSOLE_PROOF": pc.request_proof(H.HOST, pc.server_id, "GET", "/api/tfd/console-certificates/mine/")})
must(resp.status_code == 401 and resp.data["code"] == "session_invalid_state", f"a Knox Authorization with a Console proof is refused on a browser route: {resp.status_code} {getattr(resp, 'data', '')}")
resp = h.call(console_certificate_views.ConsoleCertificateMineView, "GET", "/api/tfd/console-certificates/mine/", session=browser)
must(resp.status_code == 200, f"the same browser route without the proof header works: {resp.status_code}")
# an API-key style request with a proof header is refused too
request = h.factory.get("/api/tfd/console-certificates/mine/", HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_X_API_KEY="k", HTTP_X_TECTAC_CONSOLE_PROOF="v1.1.a.b")
from rest_framework.test import force_authenticate  # noqa: E402

force_authenticate(request, user=user, token="k")
resp = console_certificate_views.ConsoleCertificateMineView.as_view()(request)
must(resp.status_code in (401, 403), f"an API key with a Console proof header is refused: {resp.status_code}")

# a TecTacConsole header next to another authenticator keeps the conflict refusal (the Knox branch compares the header to the digest)
other = types.SimpleNamespace(user=browser.user, instance=browser.instance, token=browser.token, header=f"TecTacConsole {pc.token}")
resp = h.call(console_certificate_views.ConsoleCertificateMineView, "GET", "/api/tfd/console-certificates/mine/", session=other)
must(resp.status_code == 401 and resp.data["code"] == "session_invalid_state", f"a TecTacConsole header with a Knox authenticator is refused: {resp.status_code} {getattr(resp, 'data', '')}")

# the Console authenticator's own identity is the Console session id, and only for the Console class
resp = V.ConsoleSessionCurrentView.as_view()(h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}",
                                                         HTTP_X_TECTAC_CONSOLE_PROOF=pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT)))
must(resp.status_code == 200, "the real Console request works")
text = repr(resp.data)
must(pc.token not in text and "digest" not in text and "knox" not in text.lower(), "current/ never returns a secret")
console_id = str(M.TecTacConsoleSession.objects.get(token_hash=cs.token_hash(pc.token)).pk)
must(M.TecTacSessionTrust.objects.filter(token_fingerprint=h.ss._fingerprint_for_identity(f"console:{console_id}")).count() == 1, "the trust row is the console:<id> one")

# console_info says nothing for anything that is not a Console request
for fake in (types.SimpleNamespace(), types.SimpleNamespace(successful_authenticator=KnoxLike(), auth=object()), None):
    must(cs.console_info(fake) is None, "console_info of a non-Console request is None")

print("console sessions isolation 1.18.56 regression: PASS")
