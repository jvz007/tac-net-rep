#!/usr/bin/env python3
"""1.17.31 regression (C4 part 2; the server terminal route added in 1.17.34): the ticketed terminal socket route is appended once to Tactical's ws_urlpatterns, is skipped in DEMO,
and never stops start-up.

Reuses the fixtures of tests/tactical-websocket-ticket-1.17.31.py. Covered: the route ws/tfd/agent-terminal/<str:ticket>/ is appended to a
stub ws_urlpatterns once, a second install adds nothing, DEMO adds nothing, and a failure of the append raises only inside the guarded
call in apps.py (checked in the source). The lazy route closes 4503 when Tactical's consumer cannot be imported and hands the socket
to the consumer when it can. The capability and the route are registered inside apps.py's try blocks, so a fault there is logged and
Tactical still starts. The route is also checked as a server-only, ws-only mount: nothing is added to the HTTP urlpatterns.
"""
from __future__ import annotations

import ast
import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
TICKET_TEST = HERE / "tactical-websocket-ticket-1.17.31.py"
source = TICKET_TEST.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------------------------------------ 1. the mint"
G = {"__name__": "ws_route_fixtures", "__file__": str(TICKET_TEST)}
exec(compile(source.split(marker)[0], str(TICKET_TEST), "exec"), G)  # noqa: S102 - test-only reuse of the ticket fixtures
must, ws = G["must"], G["ws"]
APP = G["APP"]


def stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


# ------------------------------------------------------------------------------------------------ the Django and Tactical stubs
SETTINGS = SimpleNamespace(DEMO=False)
stub("django.conf", settings=SETTINGS)
stub("django.urls", path=lambda route, view: SimpleNamespace(pattern=route, callback=view))
TACTICAL_WS = [SimpleNamespace(pattern="ws/dashinfo/", callback=object())]
stub("tacticalrmm")
stub("tacticalrmm.urls", ws_urlpatterns=TACTICAL_WS, urlpatterns=[])
sys.modules["tacticalrmm"].urls = sys.modules["tacticalrmm.urls"]

# ------------------------------------------------------------------------------------------------ install: once, and not in DEMO
must(ws.ROUTE_PATTERN not in [str(p.pattern) for p in TACTICAL_WS], "the route is not there before the install")
must(ws.install_tactical_websocket_route() is True, "the first install appends the route")
mounted = [p for p in TACTICAL_WS if p.pattern == ws.ROUTE_PATTERN]
must(len(mounted) == 1, "the route is appended once")
must(isinstance(mounted[0].callback, ws._AgentTerminalRoute), "the route is the lazy terminal app")
must(TACTICAL_WS[0].pattern == "ws/dashinfo/", "Tactical's own routes are kept, in order")
must(ws.install_tactical_websocket_route() is False, "a second install adds nothing")
must(len([p for p in TACTICAL_WS if p.pattern == ws.ROUTE_PATTERN]) == 1, "still one route after a second install")

TACTICAL_WS.clear()
TACTICAL_WS.append(SimpleNamespace(pattern="ws/dashinfo/", callback=object()))
SETTINGS.DEMO = True
must(ws.install_tactical_websocket_route() is False and len(TACTICAL_WS) == 1, "DEMO adds no terminal route, as Tactical adds none")
SETTINGS.DEMO = False

# ------------------------------------------------------------------------------------------------ the lazy route: the consumer, or 4503
sent = []


async def send(message):
    sent.append(message)


async def receive():
    return {"type": "websocket.connect"}


calls = []


class FakeTerminalConsumer:
    @classmethod
    def as_asgi(cls):
        async def app(scope, receive_fn, send_fn):
            calls.append(("app", scope.get("url_route")))

        return app


agents = types.ModuleType("agents")
agents_consumers = types.ModuleType("agents.consumers")
agents_consumers.TerminalStreamConsumer = FakeTerminalConsumer
sys.modules.update({"agents": agents, "agents.consumers": agents_consumers})
channels_db = types.ModuleType("channels.db")
channels_db.database_sync_to_async = lambda fn: fn
sys.modules.update({"channels": types.ModuleType("channels"), "channels.db": channels_db})
# the lazy import loads tactical_websocket_consumers the first time; keep the fixture modules the consumer uses
G["G"]["load"]("tactical_websocket_consumers")

route = ws.agent_terminal_route()
scope = {"type": "websocket", "url_route": {"args": (), "kwargs": {"ticket": "t" * 43}}}
asyncio.run(route(scope, receive, send))
must(calls and calls[0][0] == "app" and calls[0][1]["kwargs"]["ticket"] == "t" * 43, "the socket goes to Tactical's consumer with the route")
must(not sent, "nothing is sent by the route when the consumer loads")

# Tactical's consumer moved or failed to import: the socket closes 4503 and nothing else happens
del sys.modules["tec_tac.tactical_websocket_consumers"]
sys.modules["agents.consumers"] = None  # an import of it now raises ImportError
sent.clear()
calls.clear()
asyncio.run(route(scope, receive, send))
must(sent == [{"type": "websocket.close", "code": 4503}], f"an import failure closes with 4503: {sent}")
must(not calls, "the consumer is not run")

# ------------------------------------------------------------------------------------------------ the server terminal route (1.17.34, AD-35)
# Tactical installs ws/trmmcli/ only when it is not DEMO, not HOSTED and not TRMM_DISABLE_WEB_TERMINAL. Core's server route follows that.
must(len([p for p in TACTICAL_WS if p.pattern == ws.SERVER_ROUTE_PATTERN]) == 0, "the server route was not added in the DEMO run above")
TACTICAL_WS.clear()
TACTICAL_WS.append(SimpleNamespace(pattern="ws/dashinfo/", callback=object()))
must(ws.install_tactical_websocket_route() is True, "a clean install adds routes")
patterns = [p.pattern for p in TACTICAL_WS]
must(ws.ROUTE_PATTERN in patterns and ws.SERVER_ROUTE_PATTERN in patterns, "both the agent and the server terminal routes are mounted")
must(isinstance([p for p in TACTICAL_WS if p.pattern == ws.SERVER_ROUTE_PATTERN][0].callback, ws._ServerTerminalRoute), "the server route is the lazy app")
must(ws.install_tactical_websocket_route() is False and len(TACTICAL_WS) == 3, "a second install adds nothing, for either route")
for name in ("HOSTED", "TRMM_DISABLE_WEB_TERMINAL"):
    TACTICAL_WS.clear()
    TACTICAL_WS.append(SimpleNamespace(pattern="ws/dashinfo/", callback=object()))
    setattr(SETTINGS, name, True)
    must(ws.install_tactical_websocket_route() is True, f"{name}: the agent route is still added")
    patterns = [p.pattern for p in TACTICAL_WS]
    must(ws.ROUTE_PATTERN in patterns and ws.SERVER_ROUTE_PATTERN not in patterns, f"{name}: no server terminal route, as Tactical adds no ws/trmmcli/")
    delattr(SETTINGS, name)
# core.consumers (Tactical's server terminal, Linux only) cannot be imported: the socket closes 4503 and nothing else happens
sys.modules["core.consumers"] = None
sent.clear()
asyncio.run(ws.server_terminal_route()(scope, receive, send))
must(sent == [{"type": "websocket.close", "code": 4503}], f"a missing server terminal consumer closes 4503: {sent}")

# ------------------------------------------------------------------------------------------------ the guarded calls in apps.py
apps_tree = ast.parse((APP / "apps.py").read_text(encoding="utf-8"))
ready = next(n for n in ast.walk(apps_tree) if isinstance(n, ast.FunctionDef) and n.name == "ready")


def guarded_call(name):
    """True when a call to ``name`` sits in a try block of ready(), so a fault there is logged and never raised."""
    for node in ast.walk(ready):
        if isinstance(node, ast.Try):
            for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(inner, ast.Call) and getattr(inner.func, "id", "") == name:
                    return True
    return False


must(guarded_call("install_tactical_websocket_route"), "the route install is inside a try in ready()")
must(guarded_call("register_core_tactical_websocket_capability"), "the capability registration is inside a try in ready()")
apps_source = (APP / "apps.py").read_text(encoding="utf-8")
must(apps_source.index("install_tactical_websocket_route") > apps_source.index('route_prefix = "api/tfd/"'),
     "the terminal route is installed after Core's own api/tfd route, in the same ready()")

# the HTTP urlpatterns of Tec-Tac are not touched by the terminal route
urls_source = (APP / "urls.py").read_text(encoding="utf-8")
must("ws/tfd" not in urls_source, "the terminal route is a websocket route, not an HTTP one")

print("tactical-websocket-route-1.17.31: ok")
