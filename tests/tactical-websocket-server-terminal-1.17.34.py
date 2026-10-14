#!/usr/bin/env python3
"""1.17.34 regression (AD-35 item 2): the server web terminal ticket and socket (kind server-terminal), run against a stub of Tactical's
core.consumers.TerminalConsumer (v1.5.2).

Reuses the fixtures of tests/tactical-websocket-consumer-1.17.31.py (and, through them, the ticket test and the operations harness). The
stub follows Tactical's TerminalConsumer: connect reads the user from the scope, refuses on the Global Settings switch and on
can_use_webterm (close 4401), accepts, then starts the shell; receive_json handles trmmcli.input, trmmcli.resize and trmmcli.disconnect;
disconnect kills the shell. The real class needs fcntl and pty and only runs on the dev server (tests/tactical-websocket-runtime-1.17.34.py).

Covered: a superuser asking as module globalsettings gets a ticket that holds no agent id and no raw ticket; a non-superuser is refused 403
superuser_required with one deny row; modules other than globalsettings (a core, a premium, a server and an unknown one) are refused
403 websocket_owner_required; Tactical's switch off, hosted mode and a missing can_use_webterm are refused 403 server_terminal_disabled;
the body must be exactly {} (view, 400), an agent id is refused; a ticket is single use (second use 4401); a foreign Origin closes 4003;
the sign-in re-check closes 4401; the audit row is written before the shell starts, a failed write closes 4502 with no shell, and there
is exactly one row per start; losing superuser standing mid-session closes 4003 and kills the shell; the switch going off or a lost
can_use_webterm does the same; idle and absolute limits close 4401 and kill the shell; input and resize keep the sign-in alive and output
does not; no row, log or sent message holds typed text, output, a ticket or a token; the agent-terminal kind and its close codes are
unchanged.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CONSUMER_TEST = HERE / "tactical-websocket-consumer-1.17.31.py"
text = CONSUMER_TEST.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------------------------------------ 1. a valid ticket connects"
C = {"__name__": "ws_server_terminal_fixtures", "__file__": str(CONSUMER_TEST)}
exec(compile(text.split(marker)[0], str(CONSUMER_TEST), "exec"), C)  # noqa: S102 - test-only reuse of the consumer fixtures
must, reset, make_user, ROWS = (C[k] for k in ("must", "reset", "make_user", "ROWS"))
ws, consumers, run, LOG_RECORDS, PARENT = (C[k] for k in ("ws", "consumers", "run", "LOG_RECORDS", "PARENT"))
T = C["G"]
NOW, TRUSTS, USERS, LIVE_TOKENS, POLICY, REVOKED_ROWS, CACHE = (
    T[k] for k in ("NOW", "TRUSTS", "USERS", "LIVE_TOKENS", "POLICY", "REVOKED_ROWS", "CACHE")
)
Roleish, TRUST_ID, FakeUser, FakeAuditLog, PLUGINS, ENABLED = (T[k] for k in ("Roleish", "TRUST_ID", "FakeUser", "FakeAuditLog", "PLUGINS", "ENABLED"))
Role, request_for, refusal, deny_rows, AGENT = T["Role"], T["request_for"], T["refusal"], T["deny_rows"], T["AGENT"]
session_security = sys.modules["tec_tac.session_security"]
TICK = 30

Role.FIELDS["can_use_webterm"] = "BooleanField"
PLUGINS["globalsettings"] = SimpleNamespace(
    plugin_id="globalsettings", plugin_type="extension", version="0.1.0",
    permission_groups=(("Use", ("globalsettings.use",)),), legacy=False, audit_events=(), category="core",
)
ENABLED["globalsettings"] = True

# ------------------------------------------------------------------------------------------------ the stub of Tactical's TerminalConsumer
SHELL = {"enabled": True, "killed": 0, "started": 0, "events": [], "closed": [], "order": []}
SWITCH = {"on": True}


class TerminalConsumer:
    """core/consumers.py TerminalConsumer (v1.5.2), reduced to the steps the relay depends on."""

    child_pid = None
    authorized = False
    connected = False

    def __init__(self, *args, **kwargs):
        self.scope = None
        self.user = None

    @classmethod
    def as_asgi(cls):
        raise AssertionError("the stub is driven directly by these tests")

    def connect(self):
        self.user = self.scope["user"]
        if not getattr(self.user, "is_authenticated", False):
            self.close(4401)
            return
        if not SWITCH["on"]:
            self.close(4401)
            return
        role = getattr(self.user, "role", None)
        allowed = self.user.is_superuser or bool(getattr(role, "is_superuser", False)) or bool(getattr(role, "can_use_webterm", False))
        if self.user.block_dashboard_login or not allowed:
            self.close(4401)
            return
        self.connected = True
        self.authorized = True
        self.accept()
        SHELL["started"] += 1
        SHELL["order"].append("shell")
        self.child_pid = 1234

    def accept(self):
        SHELL["events"].append(("accept", None))

    def close(self, code=None):
        SHELL["closed"].append(code)

    def send_json(self, payload):
        SHELL["events"].append(("json", payload))

    def kill_pty(self):
        if self.child_pid is not None:
            SHELL["killed"] += 1
            self.child_pid = None

    def disconnect(self, code):
        self.connected = False
        self.kill_pty()

    def receive_json(self, data):
        if not self.authorized:
            return None
        action = data.get("action")
        if action == "trmmcli.input":
            SHELL["events"].append(("input-handled", None))
        elif action == "trmmcli.disconnect":
            self.kill_pty()
            self.send_json({"action": "trmmcli.output", "data": {"output": "Terminal killed!"}})
        return None


core_pkg = types.ModuleType("core")
core_consumers = types.ModuleType("core.consumers")
core_consumers.TerminalConsumer = TerminalConsumer
sys.modules.update({"core": core_pkg, "core.consumers": core_consumers})
server = T["G"]["load"]("tactical_websocket_server_terminal")

# Tactical's switch: the Global Settings toggle, read through ws.server_terminal_enabled (its own test is below)
real_enabled = ws.server_terminal_enabled
ws.server_terminal_enabled = lambda: SWITCH["on"]
server.server_terminal_enabled = ws.server_terminal_enabled

# write_start_row writes the real (fake-table) audit row, and notes that the shell has not started yet
real_write = ws.write_start_row


def ordered_write(**kwargs):
    SHELL["order"].append("row")
    return real_write(**kwargs)


server.write_start_row = ordered_write
ws._monotonic = lambda: (NOW[0] - START["t"]).total_seconds()
START = {"t": None}


# ------------------------------------------------------------------------------------------------ helpers
def superuser(pk=5, name="admin", **kwargs):
    return FakeUser(pk, name, Roleish(), superuser=True, scope=(AGENT,), **kwargs)


def mint_server(user, *, module="globalsettings", data=None, **kwargs):
    req = request_for(user, data={} if data is None else data, **kwargs)
    return ws.issue_ticket(req, module_id=module, kind="server-terminal")


def fresh():
    reset()
    SWITCH["on"] = True
    ENABLED["globalsettings"] = True
    START["t"] = NOW[0]
    POLICY.update(idle_timeout_minutes=5, absolute_lifetime_minutes=480)
    del SHELL["events"][:], SHELL["closed"][:], SHELL["order"][:], LOG_RECORDS[:]
    SHELL.update(killed=0, started=0)


def scope_for(ticket, *, origin=None, host="techx.example"):
    headers = [(b"host", host.encode())]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return {"type": "websocket", "headers": headers, "user": SimpleNamespace(is_authenticated=False),
            "url_route": {"args": (), "kwargs": {"ticket": ticket}}}


def connect(ticket, **kwargs):
    consumer = server.TecTacServerTerminalConsumer()
    consumer.scope = scope_for(ticket, **kwargs)
    consumer.connect()
    if consumer._tec_stop is not None:
        consumer._tec_stop.set()  # the real 30 second thread ends at once, so the test drives _watch_tick
    return consumer


def tick(consumer, seconds=TICK):
    NOW[0] += timedelta(seconds=seconds)
    return consumer._watch_tick()


def server_rows():
    return [r for r in ROWS if r["action"] == "custom:server-terminal-start"]


# ------------------------------------------------------------------------------------------------ 1. the mint
fresh()
root = superuser()
result = mint_server(root)
must(set(result) == {"ticket", "path", "session_id", "expires_in", "kind"} and result["kind"] == "server-terminal", f"201 shape: {sorted(result)}")
must(result["path"] == f"/ws/tfd/server-terminal/{result['ticket']}/" and result["expires_in"] == 30, "the path and the 30 second life")
stored = next(iter(CACHE.data.values()))
must("agent_id" not in stored and stored["kind"] == "server-terminal" and stored["module_id"] == "globalsettings", "the ticket holds no agent id")
must(result["ticket"] not in json.dumps(list(CACHE.data)) + json.dumps(stored), "the raw ticket is not in the stored key or value")
must(not ROWS, "a mint writes no audit row")
must(ws.KINDS["agent-terminal"]["body_keys"] == ("agent_id",) and ws.KINDS["server-terminal"]["body_keys"] == (), "body keys per kind")
must(ws.CAPABILITY_VERSION == "1.1.0" and ws.tactical_websocket_contract_metadata()["version"] == "1.1.0", "capability 1.1.0")
must("server-terminal" in ws.tactical_websocket_contract_metadata()["kinds"] and "4502" in ws.tactical_websocket_contract_metadata()["close_codes"], "metadata lists the kind and 4502")

# a role superuser and the root user count as effective superusers
fresh()
role_super = FakeUser(7, "rolesuper", Roleish(superuser=True))
must(mint_server(role_super)["kind"] == "server-terminal", "a role superuser may ask")

# ------------------------------------------------------------------------------------------------ 2. refusals with a deny row
fresh()
tech = make_user(pk=5, flags=("can_use_webterm", "can_use_terminal"))  # holds the flag but is not a superuser
exc = refusal(lambda: mint_server(tech))
must(exc.status == 403 and exc.code == "superuser_required", f"a non-superuser is refused 403 superuser_required: {exc.status} {exc.code}")
rows = deny_rows()
must(len(rows) == 1 and rows[0]["action"] == "deny" and rows[0]["debug_info"]["module_id"] == "globalsettings", "one deny row against globalsettings")
must(rows[0]["debug_info"]["operation_context"].get("core_refusal") is True and rows[0]["object_type"] == "server", "the deny row is a Core refusal on the server object")
must(not CACHE.data, "no ticket was stored")

for label, module in (("a core module", "remote-background"), ("a premium module", "premium-x"), ("a server module", "server-x"),
                      ("an unknown module", "no-such-module"), ("Core itself", "core")):
    fresh()
    before = len(ROWS)
    exc = refusal(lambda module=module: mint_server(superuser(), module=module))
    must(exc.status == 403 and exc.code == "websocket_owner_required", f"{label} is refused 403 websocket_owner_required: {exc.code}")
    must(not CACHE.data, f"{label}: no ticket")
fresh()
ENABLED["globalsettings"] = False  # a disabled globalsettings is no owner
must(refusal(lambda: mint_server(superuser())).code == "websocket_owner_required", "a disabled globalsettings is refused")
fresh()
PLUGINS["globalsettings"].category = "premium"
must(refusal(lambda: mint_server(superuser())).code == "websocket_owner_required", "a globalsettings that is not a core module is refused")
PLUGINS["globalsettings"].category = "core"

fresh()
SWITCH["on"] = False
exc = refusal(lambda: mint_server(superuser()))
must(exc.status == 403 and exc.code == "server_terminal_disabled", f"Tactical's switch off is refused: {exc.code}")
must(len(deny_rows()) == 1 and not CACHE.data, "one deny row, no ticket")
fresh()
no_flag = FakeUser(9, "root", None)  # effective superuser by name, but no role and no flag: Tactical would refuse can_use_webterm
exc = refusal(lambda: mint_server(no_flag))
must(exc.status == 403 and exc.code == "server_terminal_disabled", f"a missing can_use_webterm is refused: {exc.code}")

fresh()
exc = refusal(lambda: ws.issue_ticket(request_for(superuser()), module_id="globalsettings", kind="server-terminal", agent_id=AGENT))
must(exc.status == 400 and exc.code == "invalid_ticket_request", "an agent id on the server kind is refused 400")
exc = refusal(lambda: mint_server(superuser(), session=False))
must(exc.status == 401 and exc.code == "authenticated_request_required", "no signed-in session is 401")
exc = refusal(lambda: mint_server(superuser(), digest=None))
must(exc.status == 401 and exc.code == "tactical_session_required", "no Tactical link is 401")

# ------------------------------------------------------------------------------------------------ the view: the body is exactly {}
views = T["G"]["load"]("tactical_websocket_views")
fresh()
view = views.TacticalWebSocketTicketView()
admin = superuser()
response = view.post(request_for(admin, data={}), "globalsettings", "server-terminal")
must(response.status_code == 201 and response.data["kind"] == "server-terminal", "the view answers 201 for {}")
for bad in ({"agent_id": AGENT}, {"x": 1}, [], "x", None):
    response = view.post(request_for(admin, data=bad), "globalsettings", "server-terminal")
    must(response.status_code == 400 and response.data["code"] == "invalid_ticket_request", f"a body other than {{}} is 400: {bad!r}")
response = view.post(request_for(admin, data={}), "remote-background", "server-terminal")
must(response.status_code == 403 and response.data["code"] == "websocket_owner_required", "the view refuses another module")
response = view.post(request_for(make_user(pk=6, name="tech2", flags=("can_use_webterm",)), data={}), "globalsettings", "server-terminal")
must(response.status_code == 403 and response.data["code"] == "superuser_required", "the view refuses a non-superuser")
response = view.post(request_for(admin, data={"agent_id": AGENT}), "remote-background", "agent-terminal")
must(response.status_code == 201, "the agent kind still takes {agent_id}")
response = view.post(request_for(admin, data={}), "remote-background", "agent-terminal")
must(response.status_code == 400 and response.data["code"] == "invalid_ticket_request", "the agent kind still refuses {}")

# ------------------------------------------------------------------------------------------------ 3. the socket: connect
fresh()
root = superuser()
result = mint_server(root)
ticket = result["ticket"]
consumer = connect(ticket)
must(SHELL["closed"] == [] and consumer.authorized and SHELL["started"] == 1, f"a valid ticket opens the socket and starts the shell: {SHELL['closed']}")
must(SHELL["order"] == ["row", "shell"], f"the audit row is written before the shell starts: {SHELL['order']}")
must(consumer.user is root, "the socket runs as the ticket's user")
must(not CACHE.data, "the ticket is consumed")
rows = server_rows()
must(len(rows) == 1, f"exactly one custom:server-terminal-start row, got {len(rows)}")
row = rows[0]
ctx = row["debug_info"]["operation_context"]
must(row["username"] == "admin" and row["object_type"] == "server" and row["debug_info"]["module_id"] == "globalsettings", "actor, object and owner")
must(row["after_value"] == {"session_id": result["session_id"]} and ctx["websocket"] == "server-terminal" and ctx["server_provenance"] == "tactical-websocket",
     "after value and provenance")
consumer.disconnect(1000)
must(SHELL["killed"] == 1 and len(server_rows()) == 1, "disconnect kills the shell and writes no second row")

# single use
fresh()
ticket = mint_server(superuser())["ticket"]
first = connect(ticket)
first.disconnect(1000)
del SHELL["closed"][:]
second = connect(ticket)
must(SHELL["closed"] == [4401] and SHELL["started"] == 1 and len(server_rows()) == 1, "a second use of the ticket closes 4401, no shell, no row")
for bad in ("q" * 43, "short", ""):
    del SHELL["closed"][:]
    connect(bad)
    must(SHELL["closed"] == [4401], f"an unknown or malformed ticket closes 4401: {bad!r}")
# an agent-terminal ticket never opens the server socket
fresh()
agent_ticket = ws.issue_ticket(request_for(make_user(pk=5)), module_id="remote-background", kind="agent-terminal", agent_id=AGENT)["ticket"]
connect(agent_ticket)
must(SHELL["closed"] == [4401] and SHELL["started"] == 0 and not server_rows(), "an agent-terminal ticket closes 4401 on the server socket")

# Origin
fresh()
ticket = mint_server(superuser())["ticket"]
connect(ticket, origin="https://evil.example")
must(SHELL["closed"] == [4003] and SHELL["started"] == 0 and not server_rows(), "a foreign Origin closes 4003: no row, no shell")
fresh()
ticket = mint_server(superuser())["ticket"]
good = connect(ticket, origin="https://techx.example")
must(SHELL["closed"] == [] and SHELL["started"] == 1, "the request host as Origin is accepted")
good.disconnect(1000)

# sign-in and standing re-checks at connect
for label, breaker, code in (
    ("a revoked session", lambda: setattr(TRUSTS[TRUST_ID], "revoked", True), 4401),
    ("a deleted Knox token", lambda: LIVE_TOKENS.discard("knox-1"), 4401),
    ("a disabled user", lambda: setattr(USERS[5], "is_active", False), 4401),
    ("lost superuser standing", lambda: (setattr(USERS[5], "is_superuser", False), setattr(USERS[5], "role", Roleish("can_use_webterm"))), 4003),
    ("the switch turned off", lambda: SWITCH.update(on=False), 4003),
    ("a lost can_use_webterm", lambda: (setattr(USERS[5], "is_superuser", False), setattr(USERS[5], "username", "root"), setattr(USERS[5], "role", None)), 4003),
):
    fresh()
    ticket = mint_server(superuser())["ticket"]
    breaker()
    connect(ticket)
    must(SHELL["closed"] == [code] and SHELL["started"] == 0 and not server_rows(), f"{label} closes {code} at connect: {SHELL['closed']}")

# ------------------------------------------------------------------------------------------------ 4. audit before the shell, fail closed
fresh()
ticket = mint_server(superuser())["ticket"]
FakeAuditLog.objects.fail = True
failed = connect(ticket)
must(SHELL["closed"] == [4502] and SHELL["started"] == 0 and not failed.authorized, f"a failed start row closes 4502 and starts no shell: {SHELL['closed']}")
must(not server_rows() and failed._tec_watch is None, "no row, no watcher")
FakeAuditLog.objects.fail = False
fresh()
ticket = mint_server(superuser())["ticket"]
live = connect(ticket)
live.receive_json({"action": "trmmcli.input", "data": {"input": "ls\n"}})
live.receive_json({"action": "trmmcli.resize", "data": {"rows": 30, "cols": 90}})
must(len(server_rows()) == 1, "input and resize write no further row")
live.disconnect(1000)

# ------------------------------------------------------------------------------------------------ 5. the watcher
fresh()
root = superuser()
live = connect(mint_server(root)["ticket"])
must(tick(live) is False and SHELL["closed"] == [], "a tick with everything in place closes nothing")
USERS[5].is_superuser = False  # the person loses superuser standing
USERS[5].role = Roleish("can_use_webterm")
must(tick(live) is True and SHELL["closed"] == [4003] and SHELL["killed"] == 1, f"losing superuser standing closes 4003 and kills the shell: {SHELL}")
live.disconnect(1000)
must(SHELL["killed"] == 1, "the shell is killed once")

fresh()
live = connect(mint_server(superuser())["ticket"])
SWITCH["on"] = False
must(tick(live) is True and SHELL["closed"] == [4003] and SHELL["killed"] == 1, "Tactical's switch going off closes 4003 and kills the shell")

for label, breaker in (("a revoked session", lambda: setattr(TRUSTS[TRUST_ID], "revoked", True)),
                       ("a deleted Knox token", lambda: LIVE_TOKENS.discard("knox-1")),
                       ("a disabled user", lambda: setattr(USERS[5], "is_active", False))):
    fresh()
    live = connect(mint_server(superuser())["ticket"])
    breaker()
    must(tick(live) is True and SHELL["closed"] == [4401] and SHELL["killed"] == 1, f"{label} closes 4401 and kills the shell")

# idle and absolute limits
fresh()
live = connect(mint_server(superuser())["ticket"])
ticks = 0
while not SHELL["closed"] and ticks < 20:
    tick(live)
    ticks += 1
must(SHELL["closed"] == [4401] and ticks == 10 and SHELL["killed"] == 1, f"an idle server terminal closes 4401 at the idle limit, got {SHELL['closed']} after {ticks}")
must(REVOKED_ROWS == [("idle-timeout", "session_idle_timeout")] and "knox-1" not in LIVE_TOKENS, "the sign-in ends like a REST idle timeout")

fresh()
live = connect(mint_server(superuser())["ticket"])
for n in range(1, 31):  # three times the idle limit, input every 3 minutes
    if n % 6 == 0:
        live.receive_json({"action": "trmmcli.input", "data": {"input": "x"}})
    tick(live)
must(SHELL["closed"] == [] and not TRUSTS[TRUST_ID].revoked, "input every 3 minutes keeps the server terminal open past 3x the idle limit")
live.receive_json({"action": "trmmcli.resize", "data": {"rows": 24, "cols": 80}})
must(live._tec_activity.take() is not None, "a resize counts")
ticks = 0
while not SHELL["closed"] and ticks < 30:
    tick(live)
    ticks += 1
must(SHELL["closed"] == [4401] and 9 <= ticks <= 11, "after the last input the idle limit applies again")

fresh()
live = connect(mint_server(superuser())["ticket"])
for n in range(1, 31):  # output alone, every tick
    live.send_json({"action": "trmmcli.output", "data": {"output": "tail -f"}})
    tick(live)
    if SHELL["closed"]:
        break
must(SHELL["closed"] == [4401], "output alone does not keep a server terminal alive")
for content in ({"action": "trmmcli.disconnect"}, {"action": "trmmcli.input", "data": {"input": ""}}, {"action": "input", "data": "x"},
                {"action": "trmmcli.output", "data": {"output": "x"}}, {"action": "trmmcli.resize", "data": {"rows": "1", "cols": 2}}):
    fresh()
    probe = TerminalConsumer  # keep the stub referenced
    live = connect(mint_server(superuser())["ticket"])
    live.receive_json(content)
    must(live._tec_activity.take() is None, f"does not count: {content['action']}")
    live.disconnect(1000)

fresh()
live = connect(mint_server(superuser())["ticket"])
for n in range(1, 200):
    tick(live, 240)
    live.receive_json({"action": "trmmcli.input", "data": {"input": "x"}})
    if SHELL["closed"]:
        break
must(SHELL["closed"] == [4401] and REVOKED_ROWS and REVOKED_ROWS[-1][0] == "absolute-timeout", "the absolute maximum closes 4401 despite constant input")

# the watcher survives a failure of its own check by closing the socket
fresh()
live = connect(mint_server(superuser())["ticket"])
live._watch_tick = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
live._tec_stop = types.SimpleNamespace(wait=lambda seconds: False, set=lambda: None)
live._watch()
must(SHELL["closed"] == [4401] and SHELL["killed"] == 1, "a failing watcher closes the socket and kills the shell")

# Tactical closing the socket itself: the watcher stops and no second close is sent
fresh()
live = connect(mint_server(superuser())["ticket"])
live._tec_stop = None
live._end(4003)
must(live.connected is False, "_end clears connected first, so Tactical's own 4030 close is not sent after it")

# ------------------------------------------------------------------------------------------------ 6. nothing typed in rows, logs or sends
fresh()
result = mint_server(superuser())
secret = "TYPED-SECRET-5521-rm-rf"
output = "OUTPUT-SECRET-9137"
live = connect(result["ticket"])
live.receive_json({"action": "trmmcli.input", "data": {"input": secret}})
live.receive_json({"action": "trmmcli.resize", "data": {"rows": 31337, "cols": 42424}})
live.send_json({"action": "trmmcli.output", "data": {"output": output}})
tick(live)
tick(live, 6 * 60)
live.disconnect(1000)
blob = json.dumps(ROWS, default=str) + "\n".join(LOG_RECORDS)
must(secret not in blob and output not in blob, "no typed text or output in a row or a log record")
must("31337" not in blob and "42424" not in blob, "no terminal size in a row or a log record")
must(result["ticket"] not in blob and "knox-1" not in blob.replace('"knox_digest"', ""), "no ticket or token in them either")
must([r["action"] for r in ROWS] == ["custom:server-terminal-start"], f"only the one start row exists: {[r['action'] for r in ROWS]}")

# ------------------------------------------------------------------------------------------------ 7. the agent terminal is unchanged
fresh()
user = make_user(pk=5)
agent_result = ws.issue_ticket(request_for(user), module_id="remote-background", kind="agent-terminal", agent_id=AGENT)
must(agent_result["path"] == f"/ws/tfd/agent-terminal/{agent_result['ticket']}/" and agent_result["kind"] == "agent-terminal", "the agent path and kind")
must(next(iter(CACHE.data.values()))["agent_id"] == AGENT, "the agent ticket still holds the agent id")
exc = refusal(lambda: ws.issue_ticket(request_for(user), module_id="remote-background", kind="agent-terminal", agent_id="bad id!"))
must(exc.status == 400 and exc.code == "invalid_agent_id", "a bad agent id is still 400 invalid_agent_id")
exc = refusal(lambda: ws.issue_ticket(request_for(user), module_id="globalsettings", kind="agent-terminal", agent_id=AGENT))
must(exc.status == 403 and exc.code == "websocket_owner_required", "globalsettings owns only the server kind")
exc = refusal(lambda: ws.issue_ticket(request_for(user), module_id="remote-background", kind="nope", agent_id=AGENT))
must(exc.status == 404 and exc.code == "websocket_kind_not_found", "an unknown kind is still 404")
must(ws.owner_module("agent-terminal")["id"] == "remote-background", "the agent kind's deny owner is unchanged")

# ------------------------------------------------------------------------------------------------ 8. Tactical's switch, read the way CoreSettings.web_terminal_enabled does
conf_settings = SimpleNamespace()
sys.modules["django.conf"] = types.SimpleNamespace(settings=conf_settings)


class FakeCore:
    web_terminal_enabled = True
    enable_server_webterminal = True


class FakeCoreModels:
    class CoreSettings:
        class objects:  # noqa: N801
            @staticmethod
            def first():
                return CORE["row"]


CORE = {"row": FakeCore()}
sys.modules["core.models"] = FakeCoreModels
must(real_enabled() is True, "on: not hosted, not disabled, the toggle on")
for name in ("HOSTED", "TRMM_DISABLE_WEB_TERMINAL", "DEMO"):
    setattr(conf_settings, name, True)
    must(real_enabled() is False, f"{name} turns it off")
    delattr(conf_settings, name)
CORE["row"] = SimpleNamespace(web_terminal_enabled=False)
must(real_enabled() is False, "the Global Settings toggle off turns it off")
CORE["row"] = None
must(real_enabled() is False, "no CoreSettings row is off")
sys.modules["core.models"] = None  # an import failure fails closed
must(real_enabled() is False, "an unreadable switch is off (fail closed)")

print("tactical-websocket-server-terminal-1.17.34: ok")
