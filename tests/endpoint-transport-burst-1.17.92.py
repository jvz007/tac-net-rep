#!/usr/bin/env python3
"""1.17.92 regression: burst handling with real threads (stub harness, real pools).

Covered: 500 concurrent connects complete with every authentication and cache call on Core's dedicated pools and none on the loop's default
executor; a ping is answered while 200 authentications are queued; a Celery send_task that blocks forever fills only the HANDOVER pool,
the next connect and ping still complete and the event gets no ack; the presence key deleted from the cache is re-created by the next
ping or pong with the original since and owner; a key now owned by another connection is not overwritten by a late refresh (touch only,
no set); a superseded connection never re-acquires; the auth job calls close_old_connections before and after each job and closes its
connection; the jitter stays in its bounds with an injected random.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, make_consumer, run = H.et, H.must, H.reset, H.add_agent, H.make_consumer, H.run
AUDITS_ = H.AUDITS
CACHE, CELERY, TOKENS, DB = H.CACHE, H.CELERY, H.TOKENS, H.DB
MODELS = sys.modules["rest_framework.authtoken.models"]
PING = json.dumps({"v": 1, "type": "ping", "id": "p1", "func": "", "payload": {}})
EVENT = {"v": 1, "type": "event", "id": "ev-1", "func": "reboot.choice", "payload": {}}

THREADS: dict = {"auth": [], "cache": []}
real_get = CACHE.get


def recording_get(key, default=None):
    THREADS["cache"].append(threading.current_thread().name)
    return real_get(key, default)


class _RecordingToken:
    class objects:  # noqa: N801
        @staticmethod
        def select_related(*args):
            THREADS["auth"].append(threading.current_thread().name)
            return H.FakeToken.objects.select_related()


class _Gate:
    """Blocks every token lookup until released."""

    def __init__(self):
        self.event = threading.Event()

    class objects:  # noqa: N801
        gate = None

        @staticmethod
        def select_related(*args):
            _Gate.objects.gate.wait(10)
            return H.FakeToken.objects.select_related()


def guard_default_executor(loop):
    original = loop.run_in_executor

    def guarded(executor, func, *args):
        if executor is None:
            raise AssertionError("the default executor was used: " + getattr(func, "__name__", repr(func)))
        return original(executor, func, *args)

    loop.run_in_executor = guarded


def agent(i):
    return f"agent{i}", f"{i:040x}"


# ---------------------------------------------------------------- 500 concurrent connects, only dedicated pools
reset()
for i in range(500):
    name, token = agent(i)
    add_agent(name, token=token, pk=i + 1)
MODELS.Token = _RecordingToken
CACHE.get = recording_get


async def case_500():
    guard_default_executor(asyncio.get_running_loop())
    consumers = []
    for i in range(500):
        name, token = agent(i)
        consumers.append(make_consumer(headers=H.headers_for(token=token, agent_id=name, real_ip=f"10.0.{i // 250}.{i % 250 + 1}"), channel=f"specific.b{i}"))
    await asyncio.gather(*(c.connect() for c in consumers))
    # every coroutine completes. The auth pool's backlog cap is 256: a connect over it (timing decides how many) closes 1013 at once and the agent retries.
    busy = [i for i, c in enumerate(consumers) if c.closed]
    must(all(consumers[i].closed == [et.CLOSE_RETRY_LATER] for i in busy), (len(busy), [consumers[i].closed for i in busy][:3]))
    for wave in range(5):
        if not busy:
            break
        for i in busy:
            name, token = agent(i)
            consumers[i] = make_consumer(headers=H.headers_for(token=token, agent_id=name, real_ip=f"10.0.{i // 250}.{i % 250 + 1}"), channel=f"specific.b{i}r{wave}")
        await asyncio.gather(*(consumers[i].connect() for i in busy))
        busy = [i for i in busy if consumers[i].closed]
    must(not busy and all(c.accepted and not c.closed for c in consumers), "every agent is connected after its retry")
    must(not [k for k in CACHE.data if k.startswith((et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX))], "1013 counted nothing")
    for c in consumers:
        c._watch.cancel()
        await H.settle(c)
    must(len(THREADS["auth"]) == 500 and all(n.startswith("tectac-ea-auth") for n in THREADS["auth"]), set(THREADS["auth"]))
    must(len(set(THREADS["auth"])) <= 6, "at most six auth threads")
    must(THREADS["cache"] and all(n.startswith("tectac-ea-cache") for n in THREADS["cache"]) and len(set(THREADS["cache"])) <= 8, set(THREADS["cache"]))
    must(DB["old"] == 1000 and DB["closed"] == 500, "close_old_connections before and after each job, and the connection closed: " + str(DB))
    for c in consumers:
        await c.disconnect(1000)
    must(et.pool_inflight("auth") == 0 and et.pool_inflight("cache") == 0 and et.pool_inflight("audit") == 0, "nothing left in flight")


try:
    run(case_500())
finally:
    MODELS.Token = H.FakeToken
    CACHE.get = real_get

# ---------------------------------------------------------------- a ping is answered while 200 authentications are queued
reset()
add_agent("agentone", pk=1)
for i in range(200):
    name, token = agent(i + 1000)
    add_agent(name, token=token, pk=i + 2000)


async def case_queue():
    live = make_consumer(channel="specific.live")
    await live.connect()
    live._watch.cancel()
    await H.settle(live)
    gate = threading.Event()
    _Gate.objects.gate = gate
    MODELS.Token = _Gate
    try:
        pending = []
        for i in range(200):
            name, token = agent(i + 1000)
            c = make_consumer(headers=H.headers_for(token=token, agent_id=name, real_ip="10.5.5.5"), channel=f"specific.q{i}")
            pending.append((c, asyncio.ensure_future(c.connect())))
        await asyncio.sleep(0.1)
        must(et.pool_inflight("auth") == 200, et.pool_inflight("auth"))
        started = time.monotonic()
        await live.receive(text_data=PING)
        must(time.monotonic() - started < 0.5 and json.loads(live.out[-1])["type"] == "pong", "the ping was answered while the auth pool was busy")
    finally:
        gate.set()
        MODELS.Token = H.FakeToken
    await asyncio.gather(*(t for _, t in pending))
    must(all(c.accepted and not c.closed for c, _ in pending), "all 200 connect once released")
    for c, _ in pending:
        c._watch.cancel()
        await H.settle(c)
        await c.disconnect(1000)
    await live.disconnect(1000)


run(case_queue())

# ---------------------------------------------------------------- a blocked broker fills only the HANDOVER pool
reset()
add_agent("agentone", pk=1)
add_agent("agenttwo", token=H.TOKEN2, pk=2)
et._OWNER = {"module_id": "nats-comms", "path": "nats_comms.tasks.handle", "task_name": "nats_comms.handle"}
block = threading.Event()
CELERY.on_send = lambda name, args: block.wait(10)
saved_timeout = et.ENQUEUE_TIMEOUT_SECONDS
et.ENQUEUE_TIMEOUT_SECONDS = 0.05


async def case_broker():
    guard_default_executor(asyncio.get_running_loop())
    a = make_consumer(channel="specific.A")
    await a.connect()
    a._watch.cancel()
    await H.settle(a)
    for n in range(4):
        await a.receive(text_data=json.dumps({**EVENT, "id": f"ev-{n}"}))
    await asyncio.gather(*list(a._events))
    must(et.pool_inflight("handover") == 4, et.pool_inflight("handover"))
    must(not [f for f in H.frames(a) if f["type"] == "ack"], "no ack while the broker blocks")
    b = make_consumer(headers=H.headers_for(token=H.TOKEN2, agent_id="agenttwo"), channel="specific.B")
    await asyncio.wait_for(b.connect(), 2)
    must(b.accepted and not b.closed, "a new connect still completes")
    b._watch.cancel()
    started = time.monotonic()
    await asyncio.wait_for(a.receive(text_data=PING), 2)
    must(time.monotonic() - started < 0.5 and H.frames(a)[-1]["type"] == "pong", "a ping is still answered")
    # a full pool is skipped at once: no thread is borrowed from anywhere else
    saved = et._POOLS["handover"].backlog
    et._POOLS["handover"].backlog = 4
    try:
        await a.receive(text_data=json.dumps({**EVENT, "id": "ev-full"}))
        await asyncio.gather(*list(a._events))
    finally:
        et._POOLS["handover"].backlog = saved
    must(not [f for f in H.frames(a) if f["type"] == "ack"], "no ack for a skipped hand-over")
    block.set()
    await a.disconnect(1000)
    await b.disconnect(1000)


try:
    run(case_broker())
finally:
    block.set()
    et.ENQUEUE_TIMEOUT_SECONDS = saved_timeout
    CELERY.on_send = None
time.sleep(0.2)

# ---------------------------------------------------------------- presence: re-acquire, never overwrite, never when superseded
reset()
add_agent("agentone", pk=1)
KEY = et.presence_key("agentone")


async def case_presence():
    c = make_consumer(channel="specific.p")
    await c.connect()
    c._watch.cancel()
    await H.settle(c)
    original = dict(CACHE.data[KEY])
    CACHE.data.pop(KEY)  # Redis restarted or evicted it
    await c.receive(text_data=PING)
    must(CACHE.data[KEY] == original and CACHE.timeouts[KEY] == 150, (CACHE.data.get(KEY), original))
    CACHE.data.pop(KEY)
    await c.receive(text_data=json.dumps({"v": 1, "type": "pong", "id": "core-1", "func": "", "payload": {}}))
    must(CACHE.data[KEY] == original, "a pong re-creates it too, with the original since and owner")
    # the owner is this connection: touch only, the value is never rewritten
    real_set = CACHE.set
    CACHE.set = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a refresh rewrote the value"))
    CACHE.touched = []
    CACHE.timeouts[KEY] = 5
    await c._refresh_presence()
    must(CACHE.touched == [KEY] and CACHE.timeouts[KEY] == 150, "touched")
    # another live connection owns it: a late refresh from the older connection leaves it alone
    CACHE.data[KEY] = {"connected": True, "since": "newer", "owner": "someone-else"}
    CACHE.touched = []
    await c._refresh_presence()
    must(CACHE.data[KEY] == {"connected": True, "since": "newer", "owner": "someone-else"} and not CACHE.touched, "the newer owner is untouched")
    CACHE.set = real_set
    # a superseded connection never re-acquires
    CACHE.data.pop(KEY)
    c._superseded = True
    await c._refresh_presence()
    await c.receive(text_data=PING)
    must(KEY not in CACHE.data, "a superseded connection never re-acquires")
    c._superseded = False
    await c.disconnect(1000)
    # the contract-level function, directly
    et.refresh_presence("agentone", "me", None)
    must(KEY not in CACHE.data, "no since, no re-acquire")


run(case_presence())

# ---------------------------------------------------------------- jitter
reset()
add_agent("agentone", pk=1)


async def case_jitter():
    for value, ping, recheck in ((0.0, 60.0, 600.0), (0.5, 65.0, 630.0), (0.999999, 60 + 9.99999, 600 + 59.99994)):
        clock = H.Clock()
        c = make_consumer(clock=clock, channel=f"specific.j{value}")
        c._random = lambda v=value: v
        await c.connect()
        c._watch.cancel()
        await H.settle(c)
        must(abs(c._next_ping - clock.now - ping) < 1e-3 and abs(c._next_recheck - clock.now - recheck) < 1e-3, (value, c._next_ping - clock.now, c._next_recheck - clock.now))
        must(et.PING_SECONDS <= c._next_ping - clock.now < et.PING_SECONDS + et.PING_JITTER_SECONDS, "ping jitter in bounds")
        must(et.RECHECK_SECONDS <= c._next_recheck - clock.now < et.RECHECK_SECONDS + et.RECHECK_JITTER_SECONDS, "re-check jitter in bounds")
        await c.disconnect(1000)


run(case_jitter())

# ---------------------------------------------------------------- the default executor is not used anywhere in the consumer
src = (H.APP / "endpoint_transport_consumer.py").read_text(encoding="utf-8")
must("run_in_executor" not in src and "database_sync_to_async" not in src, "no default executor, no thread-sensitive thread")
print("PASS endpoint transport burst 1.17.92")
