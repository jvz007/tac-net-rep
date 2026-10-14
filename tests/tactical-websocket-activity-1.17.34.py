#!/usr/bin/env python3
"""1.17.34 regression (AD-35 item 1): terminal input counts as session activity, and the watcher enforces the idle limit.

Reuses the fixtures of tests/tactical-websocket-consumer-1.17.31.py (a stub of Tactical's TerminalStreamConsumer, the real
tactical_websocket.py, the real tactical_websocket_consumers.py, the real audit.py) and, through them, those of
tests/tactical-websocket-ticket-1.17.31.py. session_security.record_terminal_activity is the REAL function, cut out of
session_security.py and run against fake trust rows with a fake clock (NOW) and a fake monotonic clock. The watcher is driven one tick
at a time (_watch_tick), so no test sleeps.

Covered: (1) an idle socket with no input closes 4401 at the first tick after the idle limit, the trust row is revoked (idle-timeout,
session_idle_timeout) and its Knox token ends; (2) input every few minutes keeps a socket open past three times the idle limit, and
last_activity_at and idle_expires_at move; (3) output alone does not refresh; (4) start, kill, unknown actions, empty input and a
resize that is not a pair of whole numbers do not count; (5) the absolute maximum closes 4401 even with constant input; (6) a disabled
user, a revoked session and a deleted Knox token close 4401; (7) a removed role, a lost can_use_terminal and an agent that left the
role's scope close 4003; (8) activity never moves last_activity_at backwards, never revives a revoked row, is clamped to now and is
refused when the idle limit had already passed before the input; (9) no database write per input frame, at most one save a tick; (10)
no log record and no audit row holds typed text, sizes, a ticket or a token; (11) a stale connection during the refresh is retried once
and a second failure closes 4401.
"""
from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSUMER_TEST = HERE / "tactical-websocket-consumer-1.17.31.py"
text = CONSUMER_TEST.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------------------------------------ 1. a valid ticket connects"
C = {"__name__": "ws_activity_fixtures", "__file__": str(CONSUMER_TEST)}
exec(compile(text.split(marker)[0], str(CONSUMER_TEST), "exec"), C)  # noqa: S102 - test-only reuse of the consumer fixtures
must, reset, make_user, mint, ROWS = (C[k] for k in ("must", "reset", "make_user", "mint", "ROWS"))
ws, consumers, connect, run, fresh_socket = (C[k] for k in ("ws", "consumers", "connect", "run", "fresh_socket"))
SENT, CLOSED, LOG_RECORDS = C["SENT"], C["CLOSED"], C["LOG_RECORDS"]
T = C["G"]  # the ticket fixtures
NOW, TRUSTS, USERS, LIVE_TOKENS, POLICY, REVOKED_ROWS = (T[k] for k in ("NOW", "TRUSTS", "USERS", "LIVE_TOKENS", "POLICY", "REVOKED_ROWS"))
Roleish, TRUST_ID, FakeUser, AGENT = T["Roleish"], T["TRUST_ID"], T["FakeUser"], T["AGENT"]
session_security = sys.modules["tec_tac.session_security"]
real_helper = session_security.record_terminal_activity
TICK = 30  # seconds between watcher ticks

START = {"t": None}


def clock():
    return (NOW[0] - START["t"]).total_seconds()


ws._monotonic = clock  # the fake monotonic clock follows the fake wall clock


def open_terminal(idle=5, absolute=480):
    """A connected socket whose real 30 second watcher is cancelled, so the test drives the ticks."""
    reset()
    START["t"] = NOW[0]
    POLICY.update(idle_timeout_minutes=idle, absolute_lifetime_minutes=absolute)
    session_security.record_terminal_activity = real_helper
    user = make_user(pk=5)
    fresh_socket()
    ticket_result = mint(user)
    consumer = connect(ticket_result["ticket"])
    must(CLOSED == [] and consumer._tec_watch is not None, "the socket opened")
    consumer._tec_watch.cancel()
    return consumer, user, ticket_result


def tick(consumer, seconds=TICK):
    NOW[0] += timedelta(seconds=seconds)
    return run(consumer._watch_tick())


def frame(consumer, content):
    run(consumer.receive_json(content))


def typed(consumer, text="ls -l\n"):
    frame(consumer, {"action": "input", "data": text})


# ------------------------------------------------------------------------------------------------ 1. idle with no input
consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
ticks = 0
while not CLOSED and ticks < 20:
    tick(consumer)
    ticks += 1
must(CLOSED == [4401], f"an idle socket closes 4401, got {CLOSED}")
must(ticks == 10, f"it closes at the first tick after the idle limit (5 minutes = 10 ticks), not at tick {ticks}")
must(trust.revoked and REVOKED_ROWS == [("idle-timeout", "session_idle_timeout")], f"the trust row is revoked as idle: {REVOKED_ROWS}")
must("knox-1" not in LIVE_TOKENS, "the Knox token ends with the row (the same as a REST request and the sweep)")

# ------------------------------------------------------------------------------------------------ 2. input every few minutes keeps it open
consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
first_idle_expiry = trust.idle_expires_at
last_seen = []
for n in range(1, 31):  # 15 minutes = three times the idle limit, one input every 3 minutes
    if n % 6 == 0:
        typed(consumer)
    tick(consumer)
    last_seen.append(trust.last_activity_at)
must(CLOSED == [] and not trust.revoked, f"a terminal with input every 3 minutes stays open past 3x the idle limit: {CLOSED}")
must(trust.last_activity_at > START["t"] + timedelta(minutes=10), "last_activity_at moved with the input")
must(trust.idle_expires_at > first_idle_expiry + timedelta(minutes=10), "idle_expires_at moved with it")
must(trust.last_seen_at >= trust.last_activity_at, "last_seen_at moved too")
must(REVOKED_ROWS == [], "nothing was revoked")
# then the person stops typing: the limit applies again
ticks = 0
while not CLOSED and ticks < 30:
    tick(consumer)
    ticks += 1
must(CLOSED == [4401] and 9 <= ticks <= 11, f"after the last input the idle limit closes it (5 minutes later), got {ticks} ticks")

# a resize counts too
consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
for n in range(1, 31):
    if n % 6 == 0:
        frame(consumer, {"action": "resize", "rows": 40, "cols": 120})
    tick(consumer)
must(CLOSED == [] and not trust.revoked, "a resize every 3 minutes keeps the socket open too")

# ------------------------------------------------------------------------------------------------ 3. output alone does not refresh
consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
before = trust.last_activity_at
ticks = 0
while not CLOSED and ticks < 20:
    run(consumer.send_json({"action": "trmmcli.output", "data": {"output": "tail -f says hello", "session_id": "s"}}))
    tick(consumer)
    ticks += 1
must(CLOSED == [4401] and ticks == 10, f"output alone closes it at the idle limit, got {CLOSED} after {ticks} ticks")
must(trust.last_activity_at == before and not trust.saves, "output never moved last_activity_at and never saved a row")
for output in ({"action": "trmmcli.output", "data": {"output": "x"}}, {"action": "terminal_info"}, {"action": "terminal_error"}):
    must(ws.counts_as_activity("agent-terminal", output) is False and ws.counts_as_activity("server-terminal", output) is False,
         f"an output frame does not count: {output['action']}")

# ------------------------------------------------------------------------------------------------ 4. what does not count
consumer, user, _ = open_terminal(idle=5)
not_counted = [
    {"action": "start", "shell": "bash"},
    {"action": "kill"},
    {"action": "trmmcli.input", "data": {"input": "x"}},          # a server frame on the agent socket
    {"action": "something-else", "data": "typed"},
    {"action": "input", "data": ""},
    {"action": "input"},
    {"action": "input", "data": 5},
    {"action": "input", "data": {"input": "x"}},
    {"action": "resize", "rows": "24", "cols": "80"},
    {"action": "resize", "rows": 24.5, "cols": 80},
    {"action": "resize", "rows": True, "cols": 80},
    {"action": "resize", "rows": 0, "cols": 80},
    {"action": "resize", "rows": -3, "cols": 80},
    {"action": "resize", "rows": 24},
    {"action": "resize"},
]
for content in not_counted:
    frame(consumer, content)
    must(consumer._tec_activity.take() is None, f"does not count: {json.dumps(content)}")
must(ws.counts_as_activity("agent-terminal", "input") is False and ws.counts_as_activity("agent-terminal", None) is False, "a frame that is not an object does not count")
frame(consumer, {"action": "input", "data": "a"})
must(consumer._tec_activity.take() is not None, "one typed character counts")
frame(consumer, {"action": "resize", "rows": 24, "cols": 80})
must(consumer._tec_activity.take() is not None, "a resize of whole numbers counts")
# none of the non-counting frames kept a socket alive
consumer, user, _ = open_terminal(idle=5)
ticks = 0
while not CLOSED and ticks < 30:
    for content in not_counted:
        frame(consumer, content)
    tick(consumer)
    ticks += 1
must(CLOSED == [4401] and ticks == 10, f"frames that do not count never keep a terminal open, got {CLOSED} after {ticks} ticks")
# the server frames (used by tests/tactical-websocket-server-terminal-1.17.34.py) follow the same rule
good_server = [{"action": "trmmcli.input", "data": {"input": "ls"}}, {"action": "trmmcli.resize", "data": {"rows": 24, "cols": 80}}]
bad_server = [{"action": "trmmcli.input", "data": {"input": ""}}, {"action": "trmmcli.input", "data": "ls"}, {"action": "trmmcli.input"},
              {"action": "trmmcli.resize", "data": {"rows": "24", "cols": 80}}, {"action": "trmmcli.resize", "data": {"rows": 24}},
              {"action": "trmmcli.disconnect"}, {"action": "input", "data": "ls"}, {"action": "trmmcli.output", "data": {"output": "x"}}]
must(all(ws.counts_as_activity("server-terminal", c) for c in good_server), "server input and resize count")
must(not any(ws.counts_as_activity("server-terminal", c) for c in bad_server), "server disconnect, output, empty and malformed frames do not count")

# ------------------------------------------------------------------------------------------------ 5. the absolute maximum, even with constant input
consumer, user, _ = open_terminal(idle=5, absolute=20)
trust = TRUSTS[TRUST_ID]
ticks = 0
while not CLOSED and ticks < 60:
    typed(consumer)
    tick(consumer)
    ticks += 1
must(CLOSED == [4401] and ticks == 40, f"the absolute maximum (20 minutes = 40 ticks) closes it despite constant input, got {ticks}")
must(REVOKED_ROWS == [("absolute-timeout", "session_absolute_timeout")] and "knox-1" not in LIVE_TOKENS, "revoked as absolute, Knox ended")

# ------------------------------------------------------------------------------------------------ 6. user, session and Knox
for label, breaker in (
    ("a disabled user", lambda: setattr(USERS[5], "is_active", False)),
    ("a user blocked from the dashboard", lambda: setattr(USERS[5], "block_dashboard_login", True)),
    ("a revoked session", lambda: setattr(TRUSTS[TRUST_ID], "revoked", True)),
    ("a deleted Knox token", lambda: LIVE_TOKENS.discard("knox-1")),
):
    consumer, user, _ = open_terminal(idle=5)
    must(tick(consumer) is False and CLOSED == [], f"{label}: still open before the change")
    breaker()
    typed(consumer)  # input does not save a closed sign-in
    must(tick(consumer) is True and CLOSED == [4401], f"{label} closes 4401 at the next tick, got {CLOSED}")

# ------------------------------------------------------------------------------------------------ 7. flag and scope (the watcher re-checks them)
consumer, user, _ = open_terminal(idle=5)
USERS[5].role = Roleish()  # the role loses can_use_terminal
must(tick(consumer) is True and CLOSED == [4003], f"a lost can_use_terminal closes 4003, got {CLOSED}")
consumer, user, _ = open_terminal(idle=5)
USERS[5].role = None  # the role is removed
must(tick(consumer) is True and CLOSED == [4003], f"a removed role closes 4003, got {CLOSED}")
consumer, user, _ = open_terminal(idle=5)
USERS[5].scope_ids = set()  # the agent moved out of scope
must(tick(consumer) is True and CLOSED == [4003], f"an agent moved out of scope closes 4003, got {CLOSED}")
consumer, user, _ = open_terminal(idle=5)
typed(consumer)
must(tick(consumer) is False and CLOSED == [], "with everything in place a tick closes nothing")

# ------------------------------------------------------------------------------------------------ 8. the helper itself
open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
t0 = NOW[0]
trust.last_activity_at = t0 + timedelta(minutes=1)  # a REST request refreshed the row after the input below
NOW[0] = t0 + timedelta(minutes=2)
must(real_helper(TRUST_ID, 5, "knox-1", t0 + timedelta(seconds=30)) is None, "an older input is accepted")
must(trust.last_activity_at == t0 + timedelta(minutes=1) and not trust.saves, "activity never moves last_activity_at backwards (and saves nothing)")
must(real_helper(TRUST_ID, 5, "knox-1", NOW[0] + timedelta(hours=3)) is None, "an input time in the future is clamped to now")
must(trust.last_activity_at == NOW[0], "clamped to the current time")
saves = len(trust.saves)
must(real_helper(TRUST_ID, 5, "knox-1", None) is None and len(trust.saves) == saves, "with no activity the helper only enforces: no save")
# the idle limit had already passed before the input
open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
before = trust.last_activity_at
NOW[0] += timedelta(minutes=6)
must(real_helper(TRUST_ID, 5, "knox-1", NOW[0]) == "session_idle_timeout", "an input after the idle limit passed is refused")
must(trust.revoked and trust.last_activity_at == before and REVOKED_ROWS == [("idle-timeout", "session_idle_timeout")],
     "the row is revoked and the late input moved nothing")
# a revoked row is never revived
saves = len(trust.saves)
must(real_helper(TRUST_ID, 5, "knox-1", NOW[0]) == "session_revoked" and trust.last_activity_at == before and len(trust.saves) == saves,
     "activity never revives a revoked row")
# another user's row, another digest, an unknown row
open_terminal(idle=5)
must(real_helper(TRUST_ID, 6, "knox-1", NOW[0]) == "session_revoked", "a different user is refused")
must(real_helper(TRUST_ID, 5, "other", NOW[0]) == "credential_unavailable", "a different Knox digest is refused")
must(real_helper(TRUST_ID, 5, "", NOW[0]) == "credential_unavailable", "an empty digest is refused")
must(real_helper("00000000-0000-4000-8000-000000000000", 5, "knox-1", NOW[0]) == "session_revoked", "an unknown row is refused")
must(not TRUSTS[TRUST_ID].revoked, "refusals for the wrong user or digest do not revoke the real row")
# a policy that was lengthened or shortened applies at once (recomputed from the row, as _expiry_verdict does)
open_terminal(idle=5)
NOW[0] += timedelta(minutes=4)
POLICY["idle_timeout_minutes"] = 3
must(real_helper(TRUST_ID, 5, "knox-1", None) == "session_idle_timeout", "a shorter idle policy applies at the next check")
open_terminal(idle=5)
NOW[0] += timedelta(minutes=4)
POLICY["idle_timeout_minutes"] = 60
must(real_helper(TRUST_ID, 5, "knox-1", None) is None, "a longer idle policy applies at the next check")

# ------------------------------------------------------------------------------------------------ 9. no database write per keystroke
consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
NOW[0] += timedelta(seconds=10)  # input in the same instant as the row's last activity would change nothing
for _ in range(200):
    typed(consumer, "x")
    frame(consumer, {"action": "resize", "rows": 30, "cols": 100})
must(not trust.saves, "200 input frames and 200 resizes wrote nothing")
tick(consumer)
must(len(trust.saves) == 1, f"the next tick saves once, got {len(trust.saves)}")
for _ in range(10):
    for _ in range(50):
        typed(consumer, "y")
    tick(consumer)
must(len(trust.saves) <= 11, f"at most one save a tick: {len(trust.saves)}")
tick(consumer)
tick(consumer)
must(len(trust.saves) <= 11, "a tick with no input saves nothing")

# ------------------------------------------------------------------------------------------------ 10. nothing typed in rows or logs
consumer, user, ticket_result = open_terminal(idle=5)
secret = "TYPED-SECRET-991-rm-rf"
run(consumer.receive_json({"action": "start", "shell": "bash"}))
typed(consumer, secret)
frame(consumer, {"action": "resize", "rows": 31337, "cols": 42424})
tick(consumer)
tick(consumer, 6 * 60)  # now idle: the revoke is logged and audited by session_security, which sees no frame
rows_and_logs = json.dumps(ROWS, default=str) + "\n".join(LOG_RECORDS)
must(secret not in rows_and_logs, "no typed text in an audit row or a log record")
must("31337" not in rows_and_logs and "42424" not in rows_and_logs, "no terminal size in an audit row or a log record")
must(ticket_result["ticket"] not in rows_and_logs and "knox-1" not in rows_and_logs.replace('"knox_digest"', ""), "no ticket or token in them either")
must(not [r for r in ROWS if r["action"] not in ("custom:terminal-start",)], "no audit row is written by a refresh or a close, only the start row")

# ------------------------------------------------------------------------------------------------ 11. a stale connection during the refresh
class OperationalError(Exception):
    pass


class InterfaceError(Exception):
    pass


class FakeConn:
    in_atomic_block = False
    connection = object()

    def is_usable(self):
        return True

    def close(self):
        pass


class FakeConnections:
    def __init__(self):
        self.close_all_calls = 0

    def all(self):
        return [FakeConn()]

    def close_all(self):
        self.close_all_calls += 1


CONNS = FakeConnections()
django_db = sys.modules["django.db"]
django_db.OperationalError, django_db.InterfaceError, django_db.connections = OperationalError, InterfaceError, CONNS

consumer, user, _ = open_terminal(idle=5)
trust = TRUSTS[TRUST_ID]
failures = {"left": 1}
calls = []


def flaky_helper(trust_id, user_id, digest, activity_at=None):
    calls.append(activity_at)
    if failures["left"] > 0:
        failures["left"] -= 1
        raise OperationalError("the connection is closed")
    return real_helper(trust_id, user_id, digest, activity_at)


session_security.record_terminal_activity = flaky_helper
typed(consumer)
must(tick(consumer) is False and CLOSED == [], "a stale connection on the refresh is retried once and the socket stays open")
must(CONNS.close_all_calls == 1 and len(calls) == 2, f"one reconnect and one retry: {CONNS.close_all_calls} closes, {len(calls)} calls")
must(calls[0] == calls[1] and calls[0] is not None, "the retry passes the same input time (the refresh is idempotent)")
must(trust.last_activity_at == calls[0], "the input time was recorded")
failures["left"] = 2
typed(consumer)
must(tick(consumer) is True and CLOSED == [4401], f"a second failure closes 4401, got {CLOSED}")
session_security.record_terminal_activity = real_helper

print("tactical-websocket-activity-1.17.34: ok")
