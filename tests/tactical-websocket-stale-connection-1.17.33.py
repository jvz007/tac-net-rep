#!/usr/bin/env python3
"""1.17.33 regression: a stale database connection must not refuse a good ticket or close a running terminal.

Reuses the fixtures of tests/tactical-websocket-consumer-1.17.31.py (which reuses those of tests/tactical-websocket-ticket-1.17.31.py): a
stub of Django, of channels.db and of Tactical's TerminalStreamConsumer, with the real tactical_websocket.py, the real
tactical_websocket_consumers.py and the real audit.py. A fake django.db.OperationalError, InterfaceError and connections stand for the
real ones, which only exist on the dev server.

Covered: (a) the first read raises OperationalError and the retry passes, so session_refusal returns None and the connections were
closed once; (b) two failures fail closed (check_failed), with one 'Could not re-check' log line and one reconnect warning; (c) connect()
with a stale connection on the first recheck is accepted with a valid ticket; (d) a watcher tick with one stale connection leaves the
socket open, and a second failure in the same tick closes 4401; (e) a non-database error is not retried and closes nothing; (f) inside
a transaction nothing is closed or retried; (g) the strict audit write is never retried: a failed write sends audit_unavailable, starts
nothing and leaves no second row, and the connection is health-checked before the write; (h) InterfaceError is retried too; (i) no
ticket in the reconnect log line.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSUMER_TEST = HERE / "tactical-websocket-consumer-1.17.31.py"
text = CONSUMER_TEST.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------------------------------------ 1. a valid ticket connects"
C = {"__name__": "ws_stale_fixtures", "__file__": str(CONSUMER_TEST)}
exec(compile(text.split(marker)[0], str(CONSUMER_TEST), "exec"), C)  # noqa: S102 - test-only reuse of the consumer fixtures
must, reset, make_user, mint, ROWS, FakeAuditLog = (C[k] for k in ("must", "reset", "make_user", "mint", "ROWS", "FakeAuditLog"))
ws, consumers, connect, run, fresh_socket = (C[k] for k in ("ws", "consumers", "connect", "run", "fresh_socket"))
SENT, CLOSED, PARENT, LOG_RECORDS = C["SENT"], C["CLOSED"], C["PARENT"], C["LOG_RECORDS"]
FakeUser = C["G"]["FakeUser"]


# ------------------------------------------------------------------------------------------------ fake django.db
class OperationalError(Exception):
    pass


class InterfaceError(Exception):
    pass


class FakeConn:
    def __init__(self):
        self.in_atomic_block = False
        self.connection = object()  # opened
        self.usable = True
        self.closes = 0

    def is_usable(self):
        return self.usable

    def close(self):
        self.closes += 1
        self.connection = None


class FakeConnections:
    def __init__(self):
        self.conn = FakeConn()
        self.close_all_calls = 0

    def all(self):
        return [self.conn]

    def close_all(self):
        self.close_all_calls += 1
        self.conn.close()


CONNS = FakeConnections()
django_db = sys.modules["django.db"]
django_db.OperationalError, django_db.InterfaceError, django_db.connections = OperationalError, InterfaceError, CONNS

# user lookups are the first read of every check: make them fail on demand
INJECT = {"left": 0, "error": OperationalError, "calls": 0}
real_manager = FakeUser.objects


class FlakyUsers:
    @staticmethod
    def filter(**kwargs):
        INJECT["calls"] += 1
        if INJECT["left"] > 0:
            INJECT["left"] -= 1
            raise INJECT["error"]("the connection is closed")
        return real_manager.filter(**kwargs)


FakeUser.objects = FlakyUsers

# the shared capture handler sits on several parent loggers, so one record lands in LOG_RECORDS more than once: count on one logger
import logging  # noqa: E402

OWN_LOG: list[str] = []


class _OwnCapture(logging.Handler):
    def emit(self, record):
        OWN_LOG.append(record.getMessage())


logging.getLogger("tec_tac.tactical_websocket").addHandler(_OwnCapture(level=logging.DEBUG))


def arm(times, error=OperationalError):
    INJECT.update(left=times, error=error, calls=0)
    CONNS.close_all_calls = 0
    CONNS.conn = FakeConn()
    del LOG_RECORDS[:], OWN_LOG[:]


def ticket_value():
    """A fresh user and the value a consumed ticket holds. The mint reads no user, so the injected failures are not used up."""
    reset()
    user = make_user(pk=5)
    return user, ws.consume_ticket(mint(user)["ticket"])


# ------------------------------------------------------------------------------------------------ (a) one stale read, retry passes
user, value = ticket_value()
arm(1)
must(ws.session_refusal(value) is None, "(a) the first read fails with a stale connection and the retry passes")
must(CONNS.close_all_calls == 1, "(a) the connections were closed exactly once")
must(INJECT["calls"] == 2, "(a) the whole check ran again (the user read twice)")

# ------------------------------------------------------------------------------------------------ (b) two failures: fail closed
user, value = ticket_value()
arm(5)
must(ws.session_refusal(value) == "check_failed", "(b) two failures refuse the sign-in (fail closed)")
must(CONNS.close_all_calls == 1 and INJECT["calls"] == 2, "(b) exactly one retry")
must(sum("Could not re-check" in r for r in OWN_LOG) == 1, "(b) 'Could not re-check' is logged once, after the second failure")
must(sum("reconnecting once" in r for r in OWN_LOG) == 1, "(b) one reconnect warning line")

# ------------------------------------------------------------------------------------------------ (h) InterfaceError is retried
user, value = ticket_value()
arm(1, InterfaceError)
must(ws.session_refusal(value) is None and CONNS.close_all_calls == 1, "(h) InterfaceError is retried once, too")

# ------------------------------------------------------------------------------------------------ (e) a non-database error is not retried
user, value = ticket_value()
arm(1, RuntimeError)
must(ws.session_refusal(value) == "check_failed", "(e) a non-database error refuses")
must(CONNS.close_all_calls == 0 and INJECT["calls"] == 1, "(e) it is not retried and nothing is closed")
must(not any("reconnecting once" in r for r in OWN_LOG), "(e) no reconnect warning")

# ------------------------------------------------------------------------------------------------ (f) inside a transaction: no close, no retry
user, value = ticket_value()
arm(1)
CONNS.conn.in_atomic_block = True
must(ws.session_refusal(value) == "check_failed", "(f) inside a transaction the stale error refuses")
must(CONNS.close_all_calls == 0 and INJECT["calls"] == 1, "(f) the connection is not closed and the read is not retried inside a transaction")

# ------------------------------------------------------------------------------------------------ (c) connect with a stale first recheck
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
arm(1)
stale = connect(ticket)
must(CLOSED == [] and stale.group_name is not None, "(c) a stale connection at the first recheck still accepts a valid ticket (not 4401)")
must(CONNS.close_all_calls == 1, "(c) the connection was renewed once")
must(not any(ticket in r for r in LOG_RECORDS), "(i) the reconnect line holds no ticket")


async def end(consumer):
    await consumer.disconnect(1000)
    await asyncio.sleep(0)
    if consumer._tec_watch is not None:
        consumer._tec_watch.cancel()
        await asyncio.sleep(0)


run(end(stale))

# connect where both attempts fail closes 4401
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
arm(10**6)
dead = connect(ticket)
must(dead.group_name is None and CLOSED == [4401], "(c) two failures at connect close 4401")
arm(0)

# ------------------------------------------------------------------------------------------------ (d) the watcher tick
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
watched = connect(ticket)
watched._tec_watch.cancel()
consumers.WATCH_SECONDS = 0.01
arm(0)


async def watch_with_one_stale_read(consumer):
    consumer._tec_watch = asyncio.ensure_future(consumer._watch())
    await asyncio.sleep(0.005)
    INJECT["left"] = 1  # the next tick meets exactly one stale connection
    await asyncio.sleep(0.05)
    still_open = not consumer._tec_watch.done()
    INJECT["left"] = 10**6  # every read fails from now on: the retry in the same tick fails too
    await asyncio.sleep(0.05)
    return still_open, consumer._tec_watch.done()


still_open, ended = run(watch_with_one_stale_read(watched))
must(still_open, "(d) a tick that hits one stale connection does not close the socket")
must(CONNS.close_all_calls >= 1, "(d) that tick renewed the connection")
must(ended and CLOSED[-1:] == [4401], "(d) a second failure in the same tick closes 4401")
consumers.WATCH_SECONDS = 30
arm(0)

# ------------------------------------------------------------------------------------------------ (g) the audit write is never retried
reset()
user = make_user(pk=5)
fresh_socket()
ticket = mint(user)["ticket"]
guarded = connect(ticket)
manager = FakeAuditLog.objects
attempts = {"n": 0}
real_create = manager.create


def flaky_create(**kw):
    attempts["n"] += 1
    if attempts["n"] == 1:
        raise OperationalError("the connection is closed")
    return real_create(**kw)  # a second attempt WOULD succeed: it must never be made


manager.create = flaky_create
CONNS.conn.usable = False  # the pre-write health check finds a dead connection
before = CONNS.conn
run(guarded.receive_json({"action": "start", "shell": "bash"}))
manager.create = real_create
must(attempts["n"] == 1, "(g) the audit write was attempted once, not retried")
must(("terminal_error", "audit_unavailable") in SENT, "(g) the client is told audit_unavailable")
must(guarded.started is False and PARENT["started_calls"] == 0, "(g) nothing starts without its row")
must(not [r for r in ROWS if r["action"] == "custom:terminal-start"], "(g) no row, and no second row")
must(before.closes == 1, "(g) a dead connection was closed before the write")
run(end(guarded))

# the health check leaves a good connection and a transaction alone
CONNS.conn = FakeConn()
ws.ensure_usable_connections()
must(CONNS.conn.closes == 0, "(g) a usable connection is left alone")
CONNS.conn.usable = False
CONNS.conn.in_atomic_block = True
ws.ensure_usable_connections()
must(CONNS.conn.closes == 0, "(g) a connection inside a transaction is left alone")

# the helper itself: exactly one retry, the second error is raised unchanged
CONNS.conn = FakeConn()
calls = {"n": 0}


def always_stale():
    calls["n"] += 1
    raise OperationalError("still down")


try:
    ws.run_with_fresh_connection(always_stale)
except OperationalError:
    pass
else:
    raise AssertionError("the second failure must be raised")
must(calls["n"] == 2, "(b) run_with_fresh_connection runs the function twice at most")

print("tactical-websocket-stale-connection-1.17.33: ok")
