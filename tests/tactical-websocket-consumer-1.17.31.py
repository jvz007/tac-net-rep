#!/usr/bin/env python3
"""1.17.31 regression (C4 part 2): the relayed Tactical terminal socket, run against a stub of Tactical's TerminalStreamConsumer.

Reuses the fixtures of tests/tactical-websocket-ticket-1.17.31.py (the operations harness, the Django boundary fakes, the real
tactical_websocket.py and the real audit.py). The stub stands for agents/consumers.py: its connect, start and disconnect follow the
v1.5.2 source (the user, the URL route kwargs, the terminal permission and scope, the started flag, the kill on disconnect). The real
Tactical class and the real Redis and channels run only on the dev server (tests/tactical-websocket-runtime-1.17.31.py).

Covered: a valid ticket is accepted and the socket takes its agent and session from the ticket, never from the URL; a replayed, expired,
unknown or malformed ticket closes 4401; a revoked session, a lost flag or an out-of-scope agent closes 4401 or 4003 as specified; a bad
Origin closes 4003 and no Origin is allowed; Tactical's own refusal leaves no watcher; one strict audit row per session start, a second
start writes none, and a row that cannot be written stops the start with audit_unavailable; the row and every log record carry no typed
input, output, ticket or token; the watcher closes the socket when the sign-in ends and is cancelled on disconnect; Tactical's kill is sent
on disconnect; the shell text is cleaned and capped.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
TICKET_TEST = HERE / "tactical-websocket-ticket-1.17.31.py"
source = TICKET_TEST.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------------------------------------ 1. the mint"
G = {"__name__": "ws_consumer_fixtures", "__file__": str(TICKET_TEST)}
exec(compile(source.split(marker)[0], str(TICKET_TEST), "exec"), G)  # noqa: S102 - test-only reuse of the ticket fixtures
must, reset, make_user, mint, ROWS, CACHE, TRUSTS, USERS, LIVE_TOKENS, FakeAuditLog, Roleish, AGENT, TRUST_ID = (
    G[k] for k in ("must", "reset", "make_user", "mint", "ROWS", "CACHE", "TRUSTS", "USERS", "LIVE_TOKENS", "FakeAuditLog", "Roleish",
                   "AGENT", "TRUST_ID")
)
ws = G["ws"]

SENT: list = []
CLOSED: list = []
PARENT = {"deny": False, "accepted": 0, "killed": 0, "started_calls": 0}


# ------------------------------------------------------------------------------------------------ the stub of Tactical's consumer
class TerminalStreamConsumer:
    """agents/consumers.py TerminalStreamConsumer (v1.5.2), reduced to the steps the relay depends on."""

    def __init__(self, *args, **kwargs):
        self.scope = None
        self.group_name = None
        self.started = False
        self.killed = False
        self._start_lock = asyncio.Lock()

    @classmethod
    def as_asgi(cls):
        async def app(scope, receive, send):
            raise AssertionError("the stub is driven directly by these tests")

        return app

    async def connect(self):
        self.user = self.scope["user"]
        if not getattr(self.user, "is_authenticated", False):
            await self.close(4401)
            return
        if self.user.block_dashboard_login:
            await self.close()
            return
        agent_id = self.scope["url_route"]["kwargs"]["agent_id"]
        session_id = self.scope["url_route"]["kwargs"]["session_id"]
        if PARENT["deny"] or not self.user.role or not getattr(self.user.role, "can_use_terminal", False):
            await self.close(code=4003)
            return
        self.group_name = f"terminal_{agent_id}_{session_id}"
        PARENT["accepted"] += 1
        await self.accept()

    async def disconnect(self, close_code):
        if not self.killed:
            PARENT["killed"] += 1
            SENT.append(("kill", None))

    async def receive_json(self, content):
        action = content.get("action")
        if action == "start":
            await self._start_terminal(content)
        elif action == "input":
            SENT.append(("trmmcli.input-handled", None))  # the real input never reaches a log of Core's

    async def _start_terminal(self, content):
        async with self._start_lock:
            if self.started:
                return
            self.started = True
            PARENT["started_calls"] += 1
            SENT.append(("started", content.get("shell")))

    async def accept(self):
        SENT.append(("accept", None))

    async def close(self, code=None):
        CLOSED.append(code)

    async def send_json(self, payload):
        SENT.append(("json", payload))

    async def _send_terminal_error(self, message, code="invalid_shell"):
        SENT.append(("terminal_error", code))


class _Channels:
    pass


def database_sync_to_async(fn):
    async def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


agents = types.ModuleType("agents")
agents_consumers = types.ModuleType("agents.consumers")
agents_consumers.TerminalStreamConsumer = TerminalStreamConsumer
sys.modules.update({"agents": agents, "agents.consumers": agents_consumers})
channels_db = types.ModuleType("channels.db")
channels_db.database_sync_to_async = database_sync_to_async
sys.modules.update({"channels": types.ModuleType("channels"), "channels.db": channels_db})

consumers = G["G"]["load"]("tactical_websocket_consumers")

# ------------------------------------------------------------------------------------------------ helpers
LOG_RECORDS: list[str] = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOG_RECORDS.append(record.getMessage() + " " + " ".join(str(a) for a in (record.args or ())))


_capture = _Capture(level=logging.DEBUG)
for name in ("tec_tac", "tec_tac.tactical_websocket", "tec_tac.tactical_websocket_consumers", "tec_tac.audit", "root"):
    logging.getLogger(name).addHandler(_capture)
    logging.getLogger(name).setLevel(logging.DEBUG)
logging.disable(logging.NOTSET)


def scope_for(ticket, *, origin=None, host="techx.example", url_agent="URL-AGENT", url_session="URL-SESSION"):
    headers = [(b"host", host.encode())]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return {
        "type": "websocket", "headers": headers, "user": SimpleNamespace(is_authenticated=False),
        "url_route": {"args": (), "kwargs": {"ticket": ticket, "agent_id": url_agent, "session_id": url_session}},
    }



# one loop for the whole file, so a watcher started by connect is still the same task when disconnect cancels it
LOOP = asyncio.new_event_loop()


def run(coro):
    return LOOP.run_until_complete(coro)


def connect(ticket, **kwargs):
    consumer = consumers.TecTacAgentTerminalConsumer()
    consumer.scope = scope_for(ticket, **kwargs)
    run(consumer.connect())
    return consumer


def fresh_socket():
    del SENT[:], CLOSED[:], LOG_RECORDS[:]
    PARENT.update(deny=False, accepted=0, killed=0, started_calls=0)


# ------------------------------------------------------------------------------------------------ 1. a valid ticket connects
reset()
user = make_user(pk=5)
fresh_socket()
ticket_result = mint(user)
ticket = ticket_result["ticket"]
consumer = connect(ticket, url_agent="URL-AGENT", url_session="URL-SESSION")
must(CLOSED == [] and ("accept", None) in SENT, "a valid ticket is accepted")
must(consumer.user is user, "the socket runs as the ticket's user")
must(consumer.scope["url_route"]["kwargs"] == {"agent_id": AGENT, "session_id": ticket_result["session_id"]},
     "agent and session come from the ticket, never from the URL")
must(consumer.group_name == f"terminal_{AGENT}_{ticket_result['session_id']}", "the group is the ticket's agent and session")
must(consumer._tec_watch is not None, "the watcher starts after Tactical accepts")
must(not CACHE.data, "the ticket is consumed")

async def cleanup(consumer):
    await consumer.disconnect(1000)
    await asyncio.sleep(0)
    if consumer._tec_watch is not None:
        consumer._tec_watch.cancel()
        await asyncio.sleep(0)

# ------------------------------------------------------------------------------------------------ 2. ticket refusals close 4401
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
first = connect(ticket)
run(cleanup(first))
fresh_socket()
replay = connect(ticket)
must(CLOSED == [4401] and replay.group_name is None, "a replayed ticket closes 4401 and opens nothing")

fresh_socket()
ticket = mint(user)["ticket"]
CACHE.data[ws.cache_key(ticket)]["expires_at"] = 0
must(connect(ticket).group_name is None and CLOSED == [4401], "an expired ticket closes 4401")

fresh_socket()
must(connect("q" * 43).group_name is None and CLOSED == [4401], "an unknown ticket closes 4401")

fresh_socket()
ticket = mint(user)["ticket"]
CACHE.mode = "down"
must(connect(ticket).group_name is None and CLOSED == [4401], "a store that cannot answer closes 4401")
CACHE.mode = "real"
reset()

# ------------------------------------------------------------------------------------------------ 3. sign-in and flag and scope re-checks
reset()
user = make_user(pk=5)
ticket = mint(user)["ticket"]
TRUSTS[TRUST_ID].revoked = True
fresh_socket()
must(connect(ticket).group_name is None and CLOSED == [4401], "a revoked session closes 4401 at connect")

reset()
user = make_user(pk=5)
ticket = mint(user)["ticket"]
LIVE_TOKENS.discard("knox-1")
fresh_socket()
must(connect(ticket).group_name is None and CLOSED == [4401], "a Knox token that is gone closes 4401")
LIVE_TOKENS.add("knox-1")

reset()
user = make_user(pk=5)
ticket = mint(user)["ticket"]
USERS[5].role = Roleish()  # the flag is removed after the ticket was issued
fresh_socket()
must(connect(ticket).group_name is None and CLOSED == [4003], "a lost can_use_terminal closes 4003")

reset()
user = make_user(pk=5)
ticket = mint(user)["ticket"]
USERS[5].scope_ids = set()
fresh_socket()
must(connect(ticket).group_name is None and CLOSED == [4003], "an agent that left the role's scope closes 4003")

reset()
user = make_user(pk=5)
ticket = mint(user)["ticket"]
fresh_socket()
PARENT["deny"] = True  # Tactical's own check refuses: Core accepts nothing and starts no watcher
consumer = connect(ticket)
must(consumer.group_name is None and consumer._tec_watch is None and CLOSED == [4003], "Tactical's own refusal opens no watcher")
reset()

# ------------------------------------------------------------------------------------------------ 4. Origin
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
bad = connect(ticket, origin="https://evil.example")
must(bad.group_name is None and CLOSED == [4003], "a foreign Origin closes 4003")
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
good = connect(ticket, origin="https://techx.example")
must(CLOSED == [] and good.group_name is not None, "an Origin with the request host is accepted")
run(cleanup(good))
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
none_sent = connect(ticket, origin=None)
must(CLOSED == [] and none_sent.group_name is not None, "no Origin is allowed")
run(cleanup(none_sent))
must(consumers.origin_allowed({"headers": [(b"host", b"a.example"), (b"origin", b"null")]}) is False, "an Origin of null is refused")
must(consumers.origin_allowed({"headers": [(b"origin", b"https://a.example")]}) is False, "an Origin with no Host is refused")
must(consumers.origin_allowed({"headers": [(b"host", b"A.example:8443"), (b"origin", b"https://a.example:8443")]}) is True,
     "the comparison ignores case")

# ------------------------------------------------------------------------------------------------ 5. one strict audit row per start
reset()
user = make_user(pk=5)
fresh_socket()
ticket_result = mint(user)
ticket = ticket_result["ticket"]
stored_correlation = next(iter(CACHE.data.values()))["correlation_id"]
live = connect(ticket)
must(live.group_name is not None, "connected")
secret_text = "rm -rf /typed-secret-7731"
output_text = "OUTPUT-SECRET-4410"


async def drive(consumer):
    await consumer.receive_json({"action": "start", "shell": "  bash\x07  ", "run_as_user": True})
    await consumer.receive_json({"action": "start", "shell": "zsh"})
    await consumer.receive_json({"action": "input", "data": secret_text})
    await consumer.disconnect(1000)


run(drive(live))
start_rows = [row for row in ROWS if row["action"] == "custom:terminal-start"]
must(len(start_rows) == 1, f"exactly one start row for two start messages, got {len(start_rows)}")
row = start_rows[0]
must(row["username"] == user.username and row["object_type"] == "agent" and row["debug_info"]["object_id"] == AGENT, "actor and object")
must(row["after_value"] == {"shell": "bash", "run_as_user": True, "session_id": ticket_result["session_id"]}, f"after value: {row['after_value']}")
ctx = row["debug_info"]["operation_context"]
must(ctx["server_provenance"] == "tactical-websocket" and ctx["websocket"] == "agent-terminal" and "core_refusal" not in ctx, "provenance")
must(row["debug_info"]["module_id"] == "remote-background", "the owner is the module on the row")
must(row["debug_info"]["correlation_id"] == stored_correlation, "the row carries the ticket's correlation id")
must(sum(1 for event in SENT if event[0] == "started") == 1, "Tactical started the shell once")
must(PARENT["started_calls"] == 1, "a second start while running never reaches Tactical's start")
blob = json.dumps(ROWS, default=str) + json.dumps(SENT, default=str) + "\n".join(LOG_RECORDS)
must(secret_text not in blob and output_text not in blob, "no typed input or output in rows, sends or logs")
must(ticket not in blob and "tec-tac:wsticket" not in "\n".join(LOG_RECORDS), "no ticket in rows or logs")
must(ticket_result["session_id"] in json.dumps(row["after_value"]), "the row names the session id")

# ------------------------------------------------------------------------------------------------ 6. an audit row that cannot be written stops the start
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
guarded = connect(ticket)
FakeAuditLog.objects.fail = True


async def start_once(consumer):
    await consumer.receive_json({"action": "start", "shell": "bash"})


run(start_once(guarded))
FakeAuditLog.objects.fail = False
must(("terminal_error", "audit_unavailable") in SENT, "the client is told audit_unavailable")
must(guarded.started is False and PARENT["started_calls"] == 0, "nothing starts without its row")
must(not [r for r in ROWS if r["action"] == "custom:terminal-start"], "no row either")
run(cleanup(guarded))

# ------------------------------------------------------------------------------------------------ 7. the watcher
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
watched = connect(ticket)
consumers.WATCH_SECONDS = 0.01
watched._tec_watch.cancel()  # replace the 30 second watcher with a quick one for this check


async def quick_watch(consumer):
    consumer._tec_watch = asyncio.ensure_future(consumer._watch())
    await asyncio.sleep(0.03)
    TRUSTS[TRUST_ID].revoked = True
    await asyncio.sleep(0.05)
    done = consumer._tec_watch.done()
    return done


must(run(quick_watch(watched)) is True, "the watcher ends after the trust row is revoked")
must(4401 in CLOSED, "the watcher closes the socket with 4401")
consumers.WATCH_SECONDS = 30

reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
long_watch = connect(ticket)
task = long_watch._tec_watch


async def cancel_on_disconnect(consumer, task):
    await consumer.disconnect(1000)
    await asyncio.sleep(0)
    return task.cancelled() or task.done()


must(run(cancel_on_disconnect(long_watch, task)) is True, "disconnect cancels the watcher")
must(long_watch._tec_watch is None and PARENT["killed"] >= 1 and ("kill", None) in SENT, "Tactical's disconnect still sends the kill")

# ------------------------------------------------------------------------------------------------ 8. shell text
must(consumers.clean_shell(None) == "default" and consumers.clean_shell("") == "default" and consumers.clean_shell("   ") == "default",
     "an empty shell is default")
cleaned = consumers.clean_shell("  a\x00b\x1bc" + "x" * 400)
must(len(cleaned) == 260 and "\x00" not in cleaned and "\x1b" not in cleaned and cleaned.startswith("abc"), "control characters go and the length is capped at 260")
must(consumers.clean_shell(12) == "12", "a non-text shell is text")

print("tactical-websocket-consumer-1.17.31: ok")
