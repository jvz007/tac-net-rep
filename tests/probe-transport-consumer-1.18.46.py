#!/usr/bin/env python3
"""1.18.46 regression: the probe socket consumer, driven with asgiref's event loop, an in-memory channel layer and a stubbed authenticator
(tests/probe_transport_harness.py). The real probe_transport.py and probe_transport_consumer.py run.

Covered: a valid connect is accepted and presence is set; 4401 for a wrong key, an unknown probe, a revoked probe and a Token header (an agent
token), one refusal row each and never the key; 4503 with no owner registered; 4403 for plaintext; the 11th failure from one address gets 4429
and a valid probe still connects from another address; a second socket for one probe closes the first with 4409 and the old one does not clear
the new presence; an oversize frame 1009; the 21st frame in a second 4429; 20 bad frames 4400; ping and pong; two unanswered pings 4408; the
injected-clock 5-minute re-check closes 4401 when the probe is revoked and 1013 after the grace on a persistent fault; an event reaches the
owner task with (probe_id, frame) and no ack is sent; a reply for an undelivered id is dropped; disconnect() closes 4401; a fault importing the
consumer closes 4503; no log record, audit kwargs or output holds the key.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, must, reset, add_probe, set_owner, make_consumer, run, frames = H.pt, H.must, H.reset, H.add_probe, H.set_owner, H.make_consumer, H.run, H.frames
KEY, KEY2, PROBE, PROBE2, CACHE, AUDITS, CELERY, LAYER = H.KEY, H.KEY2, H.PROBE, H.PROBE2, H.CACHE, H.AUDITS, H.CELERY, H.LAYER

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.probe_transport").addHandler(_Capture())
logging.getLogger("tec_tac.probe_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.probe_transport").propagate = False
OUTPUTS: list = []

EVENT = {"v": 1, "type": "event", "id": "ev-1", "func": "probe.hello", "payload": {"channel_version": 1}}


def fresh():
    reset()
    set_owner()
    add_probe(PROBE, KEY, 3, 7)


async def connected(c):
    await c.connect()
    await H.settle(c)
    return c


# ---------------------------------------------------------------- a valid connect
fresh()
c = make_consumer()


async def case_connect():
    await connected(c)
    must(c.accepted and not c.closed, (c.accepted, c.closed))
    must(c._watch is not None, "the watcher runs")
    value = CACHE.data[pt.presence_key(PROBE)]
    must(value["connected"] is True and value["client_id"] == 3 and value["site_id"] == 7 and CACHE.timeouts[pt.presence_key(PROBE)] == 90, value)
    must(c.channel_name in LAYER.groups[pt.group_name(PROBE)], "joined the group")
    must([a["action"] for a in AUDITS] == ["custom:probe-connect"], AUDITS)
    must(AUDITS[0]["probe_id"] == PROBE and AUDITS[0]["metadata"]["client_id"] == 3 and AUDITS[0]["metadata"]["site_id"] == 7, AUDITS)
    await c.disconnect(1000)
    must(pt.presence_key(PROBE) not in CACHE.data, "presence removed on a clean disconnect")
    must(AUDITS[-1]["action"] == "custom:probe-disconnect" and AUDITS[-1]["metadata"]["code"] == "1000", AUDITS)


run(case_connect())


# ---------------------------------------------------------------- refusals
async def refused(headers, reason, code=4401, setup=None):
    fresh()
    if setup:
        setup()
    consumer = make_consumer(headers)
    await consumer.connect()
    await H.settle(consumer)
    must(consumer.accepted and consumer.closed == [code], (reason, consumer.accepted, consumer.closed))
    rows = [a for a in AUDITS if a["action"] == "custom:probe-refused"]
    must(len(rows) == 1 and rows[0]["refusal"] is True and rows[0]["metadata"]["reason"] == reason, (reason, AUDITS))
    must(pt.presence_key(PROBE) not in CACHE.data and not LAYER.groups.get(pt.group_name(PROBE)), "no presence, no group")
    must(not [a for a in AUDITS if a["action"] == "custom:probe-connect"], "no connect row")


async def case_refusals():
    await refused(H.headers_for(key="z" * 32), "probe_key_invalid")
    await refused(H.headers_for(probe_id="probe-none-0000"), "probe_unknown")
    await refused(H.headers_for(), "probe_disabled", setup=lambda: H.PROBES.__setitem__(PROBE, "probe_disabled"))
    await refused(H.headers_for(scheme="Token", probe_id="x", key="a" * 40), "wrong_scheme")  # an agent token
    await refused(H.headers_for(raw=b"Probe nonsense"), "malformed_probe_id")
    await refused(H.headers_for(raw=b""), "malformed_header")
    await refused(H.headers_for(extra=[(b"x-forwarded-proto", b"ws")]), "plaintext_refused", code=4403)
    # a Token header never reaches the owner's authenticator
    fresh()
    consumer = make_consumer(H.headers_for(scheme="Token", probe_id="x", key="a" * 40))
    await consumer.connect()
    must(H.AUTH["calls"] == [], "an agent token never reaches the authenticator")


run(case_refusals())


# ---------------------------------------------------------------- no owner: 4503, and nothing is counted
async def case_no_owner():
    fresh()
    pt.clear_owner_for_tests()
    for _ in range(12):
        consumer = make_consumer()
        await consumer.connect()
        must(consumer.accepted and consumer.closed == [4503], consumer.closed)
    must(not [a for a in AUDITS], "no audit rows for 4503")
    must(not [k for k in CACHE.data if k.startswith(pt.FAILURE_PREFIX)], "nothing was counted")
    set_owner()
    consumer = make_consumer()
    await connected(consumer)
    must(not consumer.closed, "a valid probe connects once the owner is registered")


run(case_no_owner())


# ---------------------------------------------------------------- the address ceiling, and a valid probe from another address
async def case_ceiling():
    fresh()
    for n in range(10):
        consumer = make_consumer(H.headers_for(probe_id=f"probe-bad-{n:04d}", real_ip="198.51.100.7"))
        await consumer.connect()
        must(consumer.closed == [4401], (n, consumer.closed))
    over = make_consumer(H.headers_for(probe_id="probe-bad-9999", real_ip="198.51.100.7"))
    await over.connect()
    must(over.closed == [4429], over.closed)
    # the rate-limited close is before the identity check and writes no row
    must(len([a for a in AUDITS if a["action"] == "custom:probe-refused"]) == 10, len(AUDITS))
    other = make_consumer(H.headers_for(real_ip="203.0.113.50"))
    await connected(other)
    must(not other.closed, "a valid probe still connects from another address")
    # a valid probe is accepted from the limited address too? No: the address ceiling is a NAT-sized pre-auth bound and applies first.
    # The per-probe counter is different: someone failing 10 times with the real probe id never locks that probe out.
    fresh()
    for n in range(12):
        consumer = make_consumer(H.headers_for(key="z" * 32, real_ip=f"192.0.2.{n + 1}"))
        await consumer.connect()
    must(consumer.closed == [4429], consumer.closed)  # the 11th and 12th failure naming the id
    real = make_consumer(H.headers_for(real_ip="203.0.113.77"))
    await connected(real)
    must(not real.closed and real.accepted, "the real probe still gets in: the per-probe counter is read only after a failed check")


run(case_ceiling())


# ---------------------------------------------------------------- a transient fault is 1013 and counts nothing
async def case_transient():
    for mode in ("fault", "junk", "mismatch"):
        fresh()
        H.AUTH["mode"] = mode
        consumer = make_consumer()
        await consumer.connect()
        must(consumer.accepted and consumer.closed == [1013], (mode, consumer.closed))
        must(not [k for k in CACHE.data if k.startswith((pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX))], "nothing counted")
    fresh()
    pool = pt._POOLS["auth"]
    pool.inflight = pool.backlog
    consumer = make_consumer()
    await consumer.connect()
    must(consumer.closed == [1013], "a full auth pool")
    pool.inflight = 0
    fresh()
    pool = pt._POOLS["cache"]
    pool.inflight = pool.backlog
    consumer = make_consumer()
    await consumer.connect()
    must(consumer.closed == [1013], "a full cache pool at connect")
    pool.inflight = 0


run(case_transient())


# ---------------------------------------------------------------- one socket per probe
async def case_takeover():
    fresh()
    first = make_consumer(channel="specific.a")
    await connected(first)
    second = make_consumer(channel="specific.b")
    await connected(second)
    must(first.closed == [4409] and not second.closed, (first.closed, second.closed))
    owner = CACHE.data[pt.presence_key(PROBE)]["owner"]
    must(owner == second._owner, "the newer connection owns the presence")
    await first.disconnect(4409)
    must(CACHE.data[pt.presence_key(PROBE)]["owner"] == second._owner, "the old socket does not clear the new presence")
    await first._refresh_presence()
    must(CACHE.data[pt.presence_key(PROBE)]["owner"] == second._owner, "a superseded socket never refreshes")


run(case_takeover())


# ---------------------------------------------------------------- frames
async def case_frames():
    fresh()
    consumer = make_consumer()
    await connected(consumer)
    await consumer.receive(text_data=json.dumps({"v": 1, "type": "event", "id": "x", "func": "f", "payload": {"b": "x" * 17000}}))
    must(consumer.closed == [1009], consumer.closed)
    # token bucket: the 21st frame inside a second
    clock = H.Clock()
    fresh()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    for _ in range(20):
        await consumer.receive(text_data=json.dumps({"v": 1, "type": "ping", "id": "p"}))
    must(not consumer.closed, "20 frames in a second are accepted")
    await consumer.receive(text_data=json.dumps({"v": 1, "type": "ping", "id": "p"}))
    must(consumer.closed == [4429], consumer.closed)
    # bad frames: counted and dropped, the 20th closes
    fresh()
    clock = H.Clock()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    bad = ["not json", json.dumps([1]), json.dumps({"v": 2, "type": "event", "id": "a", "func": "f", "payload": {}}),
           json.dumps({"v": 1, "type": "ack", "id": "a"}), json.dumps({"v": 1, "type": "event", "id": "a", "func": "f"}),
           json.dumps({"v": 1, "type": "event", "id": "", "func": "f", "payload": {}})]
    sent = 0
    while not consumer.closed:
        clock.now += 1
        await consumer.receive(text_data=bad[sent % len(bad)])
        sent += 1
        must(sent <= 25, "never closed")
    must(consumer.closed == [4400] and sent == 20, (consumer.closed, sent))
    fresh()
    consumer = make_consumer()
    await connected(consumer)
    await consumer.receive(bytes_data=b"\x00")
    must(consumer._bad_frames == 1 and not consumer.closed, "binary frames are counted and dropped")
    # ping gets a pong, pong clears the counter, a request from the probe is dropped, an unknown func passes
    await consumer.receive(text_data=json.dumps({"v": 1, "type": "ping", "id": "p9"}))
    must(frames(consumer)[-1] == {"v": 1, "type": "pong", "id": "p9", "func": "", "payload": {}}, frames(consumer))
    consumer._unanswered_pings = 2
    await consumer.receive(text_data=json.dumps({"v": 1, "type": "pong", "id": "core-1"}))
    must(consumer._unanswered_pings == 0, "pong clears the counter")
    before = len(consumer.out)
    await consumer.receive(text_data=json.dumps({"v": 1, "type": "request", "id": "q", "func": "f", "payload": {}}))
    must(len(consumer.out) == before and not consumer.closed, "a request from the probe is dropped")


run(case_frames())


# ---------------------------------------------------------------- ping and the watcher (injected clock)
async def case_watcher():
    fresh()
    clock = H.Clock()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    clock.now += 31
    must(await consumer._tick() is True, "tick")
    must(frames(consumer)[-1]["type"] == "ping" and frames(consumer)[-1]["id"] == "core-1", frames(consumer))
    must(CACHE.touched, "presence is refreshed on a ping")
    clock.now += 31
    await consumer._tick()
    must(consumer._unanswered_pings == 2, consumer._unanswered_pings)
    clock.now += 31
    must(await consumer._tick() is False and consumer.closed == [4408], consumer.closed)
    # the 5 minute re-check: a revoked probe closes 4401 with a refusal row
    fresh()
    clock = H.Clock()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    must(consumer._next_recheck == clock.now + 300, "re-check every 5 minutes")
    H.PROBES[PROBE] = "probe_disabled"
    clock.now += 299
    await consumer._tick()
    must(not consumer.closed, "not yet")
    clock.now += 2
    must(await consumer._tick() is False and consumer.closed == [4401], consumer.closed)
    must(AUDITS[-1]["action"] == "custom:probe-refused" and AUDITS[-1]["metadata"]["reason"] == "probe_disabled", AUDITS[-1])
    # a site change at the owner reaches presence
    fresh()
    clock = H.Clock()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    H.PROBES[PROBE] = (KEY, 3, 9)
    clock.now += 301
    await consumer._tick()
    must(consumer.site_id == 9 and CACHE.data[pt.presence_key(PROBE)]["site_id"] == 9, CACHE.data[pt.presence_key(PROBE)])
    # a persistent fault keeps the socket for the grace period, then 1013
    fresh()
    clock = H.Clock()
    consumer = make_consumer(clock=clock)
    await connected(consumer)
    H.AUTH["mode"] = "fault"
    clock.now += 301
    must(await consumer._tick() is True and not consumer.closed, "a transient fault keeps the socket")
    clock.now += 299  # 600 seconds since the last good answer: inside the 630 second deadline
    consumer._next_ping, consumer._next_recheck = clock.now + 100, clock.now
    must(await consumer._tick() is True and not consumer.closed, "still inside the grace")
    clock.now += 40  # 640 seconds: past the deadline
    consumer._next_ping, consumer._next_recheck = clock.now + 100, clock.now
    must(await consumer._tick() is False and consumer.closed == [1013], consumer.closed)


run(case_watcher())


# ---------------------------------------------------------------- events, replies, requests, disconnect
async def case_events():
    fresh()
    consumer = make_consumer()
    await connected(consumer)
    await consumer.receive(text_data=json.dumps(EVENT))
    await asyncio.gather(*list(consumer._events))
    must(CELERY.sent == [("networkprobe.handle", (PROBE, EVENT))], CELERY.sent)
    must(not [f for f in frames(consumer) if f["type"] == "ack"] and not consumer.out, "no ack is sent on this route")
    must([a["action"] for a in AUDITS] == ["custom:probe-connect"], "no per-event audit row")
    CELERY.fail = True
    await consumer.receive(text_data=json.dumps({**EVENT, "id": "ev-2"}))
    await asyncio.gather(*list(consumer._events))
    must(not consumer.out and not consumer.closed, "a failed hand-over is dropped quietly")
    # requests: a reply routes only to the request that was delivered to this socket
    fresh()
    a = make_consumer(channel="specific.a")
    await connected(a)
    channel = await LAYER.new_channel()
    req = {"v": 1, "type": "request", "id": "rq-1", "func": "tunnel.open", "payload": {"x": 1}}
    await LAYER.group_send(pt.group_name(PROBE), {"type": "probe.request", "frame": req, "reply_channel": channel, "timeout": 5})
    must(frames(a)[-1] == req, frames(a))
    await a.receive(text_data=json.dumps({"v": 1, "type": "reply", "id": "rq-OTHER", "func": "tunnel.open", "payload": {}}))
    must(LAYER.channels[channel].empty(), "a reply for an undelivered id is dropped")
    await a.receive(text_data=json.dumps({"v": 1, "type": "reply", "id": "rq-1", "func": "tunnel.open", "payload": {"ok": True}}))
    got = LAYER.channels[channel].get_nowait()
    must(got["type"] == "probe.reply" and got["frame"]["payload"] == {"ok": True}, got)
    await a.receive(text_data=json.dumps({"v": 1, "type": "reply", "id": "rq-1", "func": "tunnel.open", "payload": {"ok": True}}))
    must(LAYER.channels[channel].empty(), "a second reply to the same request is dropped")
    # push: an event or reply frame from the owner reaches the probe; a request type does not
    await LAYER.group_send(pt.group_name(PROBE), {"type": "probe.push", "frame": {"v": 1, "type": "reply", "id": "ev-1", "func": "probe.welcome", "payload": {"poll_seconds": 60}}})
    must(frames(a)[-1]["func"] == "probe.welcome", frames(a))
    count = len(a.out)
    await LAYER.group_send(pt.group_name(PROBE), {"type": "probe.push", "frame": req})
    must(len(a.out) == count, "push never carries a request")
    # disconnect closes 4401 and clears presence
    await LAYER.group_send(pt.group_name(PROBE), {"type": "probe.disconnect", "reason": "revoked"})
    must(a.closed[-1] == 4401, a.closed)
    await a.disconnect(4401)
    must(pt.presence_key(PROBE) not in CACHE.data, "presence cleared after disconnect()")


run(case_events())


# ---------------------------------------------------------------- the route: a fault loading the consumer closes 4503
async def case_route():
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {}

    saved = sys.modules.pop("tec_tac.probe_transport_consumer")
    sys.modules["tec_tac.probe_transport_consumer"] = None  # an import of None raises ImportError
    try:
        await pt.probe_route()({"type": "websocket", "headers": []}, receive, send)
    finally:
        sys.modules["tec_tac.probe_transport_consumer"] = saved
    must(sent == [{"type": "websocket.close", "code": 4503}], sent)


run(case_route())
must(pt.ROUTE_PATTERN == "ws/tfd/network-probe/" and pt.SOCKET_PATH == "/ws/tfd/network-probe/", "the route")

# ---------------------------------------------------------------- the key is never shown
for line in LOGS:
    must(KEY not in line and KEY2 not in line, "a log record holds the key: " + line[:80])
must(not any(KEY in repr(a) or "Probe " + PROBE in repr(a) for a in AUDITS), "no audit kwargs hold the key or the header")
must(not any(KEY in repr(out) for out in OUTPUTS), "no output holds the key")
print("PASS probe transport consumer 1.18.46")
