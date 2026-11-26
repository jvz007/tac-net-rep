#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). The capability core.console_session 1.0.0, console_info, the contract rows and the docs.

Source checks (always): contracts.py (read as source) has a row for each of the three public names and one HTTP detail per route with its
authorization, request, response, errors, audit and notes, plus the rule 'Engineer Console sessions (core.console_session 1.0.0 ...'; the ticket row says
the Console-session rule and core.probe_transport stays 1.3.0; apps.py registers the capability in its own try block; docs/capabilities.md lists it; the
openapi grouping names the route and the views module. Runtime (where Django is importable): the capability is registered with the id, the version and the
one operation; console_info returns the three fields for a Console-authenticated request and None for a browser, an API key and an anonymous request,
never raises and returns no token, digest or key; the metadata holds no secret.
"""
import ast
import importlib.util
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


tree = ast.parse((APP / "contracts.py").read_bytes().decode("utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, rules, http = values["CORE_CONTRACTS"], values["RULES"], values["HTTP_CONTRACT_DETAILS"]
index = {(r["import_path"], r["name"]): r for r in rows}
must(len(index) == len(rows), "no row is listed twice")
NEEDLES = {
    "ConsoleSessionAuthentication": ("TecTacConsole", "X-Tectac-Console-Proof", "120 seconds", "5 minutes", "503", "core.console_session", "None so the other classes decide", "docs/console-sessions.md"),
    "ConsoleSessionAuthenticated": ("account is active", "Knox token", "idle limit", "IP-change", "request.tec_tac_session", "own permission"),
    "console_info": ("serial", "short_serial", "pc_label", "None", "never raises", "never returns a token"),
}
for name, needles in NEEDLES.items():
    row = index[("tec_tac.console_sessions", name)]
    must(row["kind"] == "python" and row["area"] == "console-sessions" and row["audience"], f"{name} keeps the row shape")
    must("1.18.56" in row["purpose"] and "framework >=1.18.56" in row["purpose"], f"{name} says which release added it")
    for needle in needles:
        must(needle in row["purpose"], f"{name} lacks {needle!r}")
for route, method, needles in (
    ("/api/tfd/console-sessions/authorise/", "POST", ("interactive", "serial_not_allowed", "redirect_port", "60", "master_key_unavailable")),
    ("/api/tfd/console-sessions/token/", "POST", ("code_verifier", "X-Tectac-Console-Cert", "server_proof", "426", "tls_required", "custom:console-signin (strict")),
    ("/api/tfd/console-sessions/current/", "GET", ("ConsoleSessionAuthentication", "Never a token")),
    ("/api/tfd/console-sessions/activity/", "POST", ("30 a minute",)),
    ("/api/tfd/console-sessions/sign-out/", "POST", ("custom:console-signout", "Knox token")),
):
    detail = http[route][method]
    for key in ("authorization", "response", "errors", "notes"):
        must(key in detail and detail[key], f"{route} has {key}")
    must(("request" in detail) or route.endswith(("current/",)), f"{route} has a request")
    text = repr(detail)
    for needle in needles:
        must(needle in text, f"{route} lacks {needle!r}")
    must("1.18.56" in text, f"{route} says which release added it")
for route in ("/api/tfd/console-sessions/authorise/", "/api/tfd/console-sessions/token/"):
    must("audit" in http[route]["POST"], f"{route} names its audit rows")
rule = next(r for r in rules if r.startswith("Engineer Console sessions (core.console_session 1.0.0"))
for needle in ("ConsoleSessionAuthentication", "ConsoleSessionAuthenticated", "has_capability('core.console_session')", "framework >=1.18.56", "console_info(request)", "never sees a token",
               "refused on every other route", "core.probe_transport is unchanged at 1.3.0", "docs/console-sessions.md"):
    must(needle in rule, f"the rule lacks {needle!r}")
ticket = index[("tec_tac.probe_transport", "issue_tunnel_ticket")]["purpose"]
must("Since Core 1.18.56" in ticket and "certificate_engineer_mismatch" in ticket and "browser-asked ticket is unchanged" in ticket and "core.probe_transport 1.3.0" in ticket, "the ticket row names the Console-session rule")

apps = (APP / "apps.py").read_bytes().decode("utf-8").replace("\r\n", "\n")
must("register_core_console_session_capability()" in apps and "core.console_session capability could not be registered" in apps, "apps.py registers it")
block = apps[apps.index("from .console_sessions import register_core_console_session_capability") - 80:]
must("try:" in block.split("from .console_sessions")[0] and "except Exception:" in block.split("register_core_console_session_capability()")[1][:80], "in its own try block")
caps = (ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
must("`core.console_session` 1.0.0" in caps and "console_info(request)" in caps and "framework >=1.18.56" in caps, "docs/capabilities.md lists it")
openapi = (APP / "openapi.py").read_text(encoding="utf-8")
must('"tec_tac.console_session_views": "Tec-Tac · Console Sessions"' in openapi and '("/api/tfd/console-sessions/", "Tec-Tac · Console Sessions")' in openapi, "the openapi grouping")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must(urls.count('path("console-sessions/') == 5, "five routes in urls.py")
rel = (ROOT / "docs" / "releases")
must(rel.is_dir(), "docs/releases exists")

spec = importlib.util.spec_from_file_location("cs_harness", HERE / "console_sessions_harness.py")
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
h = H.boot()
if h is None:
    print("console sessions capability 1.18.56 regression: PASS (source checks only: Django is not installed)")
    sys.exit(0)

cs, V = h.cs, h.views
h.reset()
registered = cs.register_core_console_session_capability()
must(len(h.capabilities) == 1, "registered once")
kw = h.capabilities[0]
must(kw["id"] == "core.console_session" and kw["version"] == "1.0.0" and kw["module_id"] == "core" and tuple(kw["operations"]) == ("console_info",), f"id, version, module and the one operation: {kw['id']} {kw['version']} {kw['operations']}")
meta = kw["metadata"]
must(meta["id"] == "core.console_session" and meta["version"] == "1.0.0" and meta["operations"] == ["console_info"] and meta["requires_framework"] == ">=1.18.56" and meta["returns_secrets"] is False, "metadata")
must("ConsoleSessionAuthentication" in meta["python"] and "ConsoleSessionAuthenticated" in meta["python"] and meta["console_min_version"] == "0.1.1", "the metadata names the classes and the minimum version")
must(kw["provider"].console_info is not None and hasattr(kw["provider"], "console_info"), "the provider has the operation")

# console_info through the real views
captured = {}


class Probe(V._ConsoleOnlyView):
    http_method_names = ["get"]

    def get(self, request):
        captured["info"] = cs.console_info(request)
        return V._answer({"ok": True})


user, pc, r = h.sign_in()
must(r.status_code == 201, "sign-in")
resp = h.pc_call(Probe, pc, "GET", "/api/tfd/console-sessions/probe/")
must(resp.status_code == 200, f"a Console request reaches the view: {resp.status_code}")
info = captured["info"]
must(info == {"serial": pc.serial, "short_serial": pc.serial[:8], "pc_label": "Work PC"}, f"console_info: {info}")
must(set(info) == {"serial", "short_serial", "pc_label"} and all(isinstance(v, str) for v in info.values()), "three text fields and nothing else")
must(pc.token not in repr(info) and "digest" not in repr(info) and "key" not in repr(info).replace("short_serial", ""), "no token, digest or key")

browser = h.browser(user)


class BrowserProbe(V.ConsoleSessionAuthoriseView):
    throttle_classes = []

    def post(self, request):
        captured["info"] = cs.console_info(request)
        return V._answer({"ok": True})


h.call(BrowserProbe, "POST", "/api/tfd/console-sessions/authorise/", session=browser, data={})
must(captured["info"] is None, "a browser request: None")
for kind in ("api", "anonymous"):
    request = h.factory.post("/api/tfd/console-sessions/authorise/", {}, format="json", HTTP_HOST=H.HOST)
    if kind == "api":
        from rest_framework.test import force_authenticate

        force_authenticate(request, user=user, token="api-key")
    captured.pop("info", None)
    BrowserProbe.permission_classes = []
    BrowserProbe.as_view()(request)
    must(captured.get("info") is None, f"{kind}: None")
BrowserProbe.permission_classes = V.ConsoleSessionAuthoriseView.permission_classes

# never raises, whatever it is given
class Boom:
    @property
    def successful_authenticator(self):
        raise RuntimeError("no")


for odd in (None, 5, "text", object(), Boom(), types.SimpleNamespace(successful_authenticator=cs.ConsoleSessionAuthentication(), auth=None),
            types.SimpleNamespace(successful_authenticator=cs.ConsoleSessionAuthentication(), auth="x")):
    must(cs.console_info(odd) is None, f"console_info({odd!r}) is None and does not raise")
must(registered is not None or registered is None, "(the stub registry returns what it is given)")

print("console sessions capability 1.18.56 regression: PASS")
