#!/usr/bin/env python3
"""1.17.93 regression: the token re-check no longer fails open forever (held Medium of Core 1.17.92).

Covered: transient results keep the socket open up to RECHECK + jitter + grace (960 s) after the last good check and close 1013 at the first
tick past it, with one identity_stale row and never 4401; a success inside the window resets the deadline; a real refusal still closes 4401;
a full auth pool (connect flood) does not affect the re-check, which runs on its own pool with the same close_old_connections hygiene.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, make_consumer, run = H.et, H.must, H.reset, H.add_agent, H.make_consumer, H.run
AUDITS, TOKENS, TOKEN, DB = H.AUDITS, H.TOKENS, H.TOKEN, H.DB
MODELS = sys.modules["rest_framework.authtoken.models"]
DEADLINE = et.RECHECK_SECONDS + et.RECHECK_JITTER_SECONDS + et.RECHECK_GRACE_SECONDS
must(et.RECHECK_GRACE_SECONDS == 300 and DEADLINE == 960 and et.POOL_SPECS["recheck"] == (2, 4096), "constants")


class _Raising:
    class objects:
        @staticmethod
        def select_related(*args):
            raise RuntimeError("db down")


def stale_rows():
    return [a for a in AUDITS if a["metadata"].get("reason") == "identity_stale"]


async def drive(conn, clock, seconds, step=30):
    """Tick every ``step`` seconds with the ping pushed out. True when the socket stayed open."""
    for _ in range(int(seconds // step)):
        clock.now += step
        conn._next_ping = clock.now + 10_000
        if not await conn._tick():
            return False
    return True


def due(conn, clock):
    conn._next_ping = clock.now + 10_000
    conn._next_recheck = clock.now


# ---------------------------------------------------------------- a fault that lasts: open up to 960 s, then 1013
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
conn = make_consumer(clock=clock)


async def case_stale():
    await conn.connect()
    conn._watch.cancel()
    start = clock.now
    must(conn._identity_ok_at == start, "recorded at connect")
    MODELS.Token = _Raising
    try:
        must(await drive(conn, clock, DEADLINE) and not conn.closed, "still up at the deadline")
        clock.now = start + DEADLINE + 1
        due(conn, clock)
        must(await conn._tick() is False and conn.closed == [1013], conn.closed)
        must(len(stale_rows()) == 1 and not stale_rows()[0]["refusal"] and 4401 not in conn.closed, AUDITS)
    finally:
        MODELS.Token = H.FakeToken


run(case_stale())

# ---------------------------------------------------------------- a success inside the window resets the deadline
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
conn = make_consumer(clock=clock)


async def case_reset():
    await conn.connect()
    conn._watch.cancel()
    start = clock.now
    MODELS.Token = _Raising
    try:
        must(await drive(conn, clock, 700) and not conn.closed, "700 s of fault: still up")
    finally:
        MODELS.Token = H.FakeToken
    clock.now += 30
    due(conn, clock)
    must(await conn._tick() is True and conn._identity_ok_at == clock.now, "a good re-check resets the clock")
    good_at = clock.now
    must(good_at - start > DEADLINE - 300, "the second window starts late in the first")
    MODELS.Token = _Raising
    try:
        clock.now = good_at + et.RECHECK_SECONDS
        due(conn, clock)
        must(await conn._tick() is True and not conn.closed, "a fault after the success is retried, not closed")
        must(await drive(conn, clock, DEADLINE - et.RECHECK_SECONDS - 30) and not conn.closed, "a fresh 960 s window after the success")
        clock.now = good_at + DEADLINE + 1
        due(conn, clock)
        must(await conn._tick() is False and conn.closed == [1013], conn.closed)
    finally:
        MODELS.Token = H.FakeToken


run(case_reset())

# ---------------------------------------------------------------- a real refusal still closes 4401 at once
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
conn = make_consumer(clock=clock)


async def case_refusal():
    await conn.connect()
    conn._watch.cancel()
    del TOKENS[TOKEN]
    clock.now += et.RECHECK_SECONDS + 1
    conn._next_ping = clock.now + 10_000
    must(await conn._tick() is False and conn.closed == [4401] and not stale_rows(), conn.closed)


run(case_refusal())

# ---------------------------------------------------------------- a full auth pool does not touch the re-check
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
conn = make_consumer(clock=clock)


async def case_pools():
    await conn.connect()
    conn._watch.cancel()
    await H.settle(conn)  # the connect audit row also calls close_old_connections
    saved = et._POOLS["auth"].backlog
    et._POOLS["auth"].backlog = 0
    try:
        must((await et.authenticate_async(TOKEN, "agentone")).reason == "busy", "the auth pool is full")
        clock.now += et.RECHECK_SECONDS + 1
        conn._next_ping = clock.now + 10_000
        DB.update(old=0, closed=0)
        must(await conn._tick() is True and not conn.closed and conn._identity_ok_at == clock.now, "the re-check still succeeds")
        must(DB["old"] == 2 and DB["closed"] == 1, "the recheck pool runs the auth job hygiene: " + str(DB))
        must(et.pool_inflight("recheck") == 0, "nothing left in flight")
    finally:
        et._POOLS["auth"].backlog = saved


run(case_pools())
print("PASS endpoint transport recheck 1.17.93")
