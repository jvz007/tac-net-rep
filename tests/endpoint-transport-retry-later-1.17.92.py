#!/usr/bin/env python3
"""1.17.92 regression: a server-side fault during authentication closes 1013 (retry later), never 4401, and never counts as an identity
failure (held Medium of the 29 October 2026 load test: 42 refusals of 4401 and 1129 of 4429 for valid tokens).

Covered: a database exception in the token lookup closes 1013, writes no 4401, leaves note_failure uncalled and the address counter at 0,
and the same token connects on the next attempt; an exhausted auth pool closes 1013; genuine unknown_token, agent_mismatch, no_agent and
inactive still close 4401 and count; a transient fault at the 10 minute re-check keeps the socket open and retries 30 s later, a real
refusal at the re-check closes 4401.
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
CACHE, AUDITS, TOKENS, TOKEN = H.CACHE, H.AUDITS, H.TOKENS, H.TOKEN
MODELS = sys.modules["rest_framework.authtoken.models"]


class _Raising:
    class objects:  # noqa: N801
        @staticmethod
        def select_related(*args):
            raise RuntimeError("db down")


def failure_keys():
    return [k for k in CACHE.data if k.startswith((et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX))]


must(et.CLOSE_RETRY_LATER == 1013 and "unavailable" in et.REFUSAL_MESSAGES and "busy" in et.REFUSAL_MESSAGES, "the code and the reasons")

# ---------------------------------------------------------------- a database fault: 1013, nothing counted, then the same token connects
reset()
add_agent("agentone", pk=1)
calls = []
real_note = et.note_failure
et.note_failure = lambda ip: calls.append(ip)


async def case_db_fault():
    MODELS.Token = _Raising
    c = make_consumer(channel="specific.t1")
    await c.connect()
    must(c.accepted and c.closed == [1013], c.closed)
    must(not calls and not failure_keys(), "nothing counted against the address or the agent")
    must(all(a["metadata"].get("reason") == "unavailable" and not a["refusal"] for a in AUDITS) and len(AUDITS) <= 1, AUDITS)
    must(4401 not in c.closed, "never 4401")
    # a burst of faults writes at most one row per throttle window
    for i in range(20):
        x = make_consumer(channel=f"specific.t{i + 2}")
        await x.connect()
        must(x.closed == [1013], x.closed)
    must(len(AUDITS) <= 1 and not calls and not failure_keys(), "throttled row, still nothing counted")
    MODELS.Token = H.FakeToken
    again = make_consumer(channel="specific.t-ok")
    await again.connect()
    must(again.accepted and not again.closed, "the same token connects on the next attempt")
    await again.disconnect(1000)


try:
    run(case_db_fault())
finally:
    MODELS.Token = H.FakeToken
    et.note_failure = real_note

# ---------------------------------------------------------------- an exhausted auth pool: 1013 busy, nothing counted
reset()
add_agent("agentone", pk=1)


async def case_pool_full():
    pool = et._POOLS["auth"]
    saved = pool.backlog
    pool.backlog = 0
    try:
        c = make_consumer(channel="specific.full")
        await c.connect()
        must(c.closed == [1013] and not failure_keys(), (c.closed, failure_keys()))
        must(AUDITS and AUDITS[-1]["metadata"]["reason"] == "busy", AUDITS)
    finally:
        pool.backlog = saved
    ok = make_consumer(channel="specific.nofull")
    await ok.connect()
    must(not ok.closed, "connects again once there is room")
    await ok.disconnect(1000)


run(case_pool_full())

# a timeout of the check is transient as well
reset()
add_agent("agentone", pk=1)
import threading  # noqa: E402

release = threading.Event()


class _Slow:
    class objects:  # noqa: N801
        @staticmethod
        def select_related(*args):
            release.wait(5)
            return H.FakeToken.objects.select_related()


async def case_timeout():
    MODELS.Token = _Slow
    saved = et.AUTH_TIMEOUT_SECONDS
    et.AUTH_TIMEOUT_SECONDS = 0.05
    try:
        c = make_consumer(channel="specific.slow")
        await c.connect()
        must(c.closed == [1013] and not failure_keys(), (c.closed, failure_keys()))
    finally:
        et.AUTH_TIMEOUT_SECONDS = saved
        MODELS.Token = H.FakeToken
        release.set()


run(case_timeout())

# ---------------------------------------------------------------- real identity answers still close 4401 and count
reset()
add_agent("agentone", pk=1)
TOKENS["d" * 40] = H.FakeTokenRow("d" * 40, H.FakeUser("dash"))
add_agent("agentoff", token="e" * 40, pk=2, active=False)


async def case_identity():
    for label, headers in (
        ("unknown_token", H.headers_for(token="c" * 40)),
        ("agent_mismatch", H.headers_for(agent_id="agenttwo")),
        ("no_agent", H.headers_for(token="d" * 40)),
        ("inactive", H.headers_for(token="e" * 40, agent_id="agentoff")),
    ):
        before = CACHE.data.get(et._failure_key("203.0.113.9"), 0)
        c = make_consumer(headers=headers, channel=f"specific.{label}")
        await c.connect()
        must(c.closed == [4401], (label, c.closed))
        must(AUDITS[-1]["metadata"]["reason"] == label and AUDITS[-1]["refusal"], (label, AUDITS[-1]))
        must(CACHE.data[et._failure_key("203.0.113.9")] == before + 1, (label, "counted"))


run(case_identity())

# ---------------------------------------------------------------- the 10 minute re-check
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
conn = make_consumer(clock=clock)


async def case_recheck():
    await conn.connect()
    conn._watch.cancel()
    start = clock.now
    must(conn._next_recheck == start + et.RECHECK_SECONDS, "no jitter with random 0")
    clock.now += et.RECHECK_SECONDS + 1
    conn._next_ping = clock.now + 1000
    MODELS.Token = _Raising
    try:
        must(await conn._tick() is True and not conn.closed, "a transient fault never closes the socket")
        must(conn._next_recheck == clock.now + et.RECHECK_RETRY_SECONDS, "retried 30 s later")
        clock.now += 5
        must(await conn._tick() is True and not conn.closed, "not retried before the retry time")
        clock.now += et.RECHECK_RETRY_SECONDS
        conn._next_ping = clock.now + 1000
        must(await conn._tick() is True and not conn.closed, "still up while the fault lasts")
    finally:
        MODELS.Token = H.FakeToken
    clock.now += et.RECHECK_RETRY_SECONDS + 1
    conn._next_ping = clock.now + 1000
    must(await conn._tick() is True and not conn.closed and conn._next_recheck == clock.now + et.RECHECK_SECONDS, "the retry succeeds and the normal period resumes")
    # a real refusal at the re-check closes 4401
    del TOKENS[TOKEN]
    clock.now += et.RECHECK_SECONDS + 1
    conn._next_ping = clock.now + 1000
    must(await conn._tick() is False and conn.closed == [4401], conn.closed)
    must(AUDITS[-1]["metadata"]["reason"] == "unknown_token" and AUDITS[-1]["refusal"], AUDITS[-1])


run(case_recheck())
print("PASS endpoint transport retry-later 1.17.92")
