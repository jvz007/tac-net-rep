#!/usr/bin/env python3
"""1.17.90 regression: the endpoint agent socket consumer, driven with asgiref's event loop, an in-memory channel layer and a stubbed
identity (tests/endpoint_transport_harness.py). The real endpoint_transport.py and endpoint_transport_consumer.py run.

Covered: a valid connect is accepted and presence is set; 4401 for a wrong agent id, a dashboard user's token, an unknown token and an
inactive account (each with one refusal row, never the token); the 11th failure from one address gets 4429; a token deleted mid-connection
closes at the 10 minute re-check (injected clock); a second connection for the same agent closes the first (and the old one does not delete
the new presence); an oversize frame closes 1009; the 21st frame in a second closes 4429; bad shapes and unknown types are dropped, an
unknown func passes through untouched; ping is answered with pong and refreshes presence; two unanswered pings close the socket; an event
reaches the owner's task with (agent_id, frame), one audit row without payload, and the ack comes only after the enqueue (order asserted;
a failed enqueue or no owner sends no ack); agent A's reply for agent B's request id is dropped, the right agent's reply reaches the
waiting channel; a fault importing the consumer closes 4503; no output, row or log record holds the token.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, make_consumer, run, frames = H.et, H.must, H.reset, H.add_agent, H.make_consumer, H.run, H.frames
TOKEN, TOKEN2, CACHE, AUDITS, CELERY, LAYER, TOKENS = H.TOKEN, H.TOKEN2, H.CACHE, H.AUDITS, H.CELERY, H.LAYER, H.TOKENS

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.endpoint_transport").addHandler(_Capture())
logging.getLogger("tec_tac.endpoint_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.endpoint_transport").propagate = False

EVENT = {"v": 1, "type": "event", "id": "ev-1", "func": "reboot.choice", "payload": {"secret_choice": "later"}}


def register_owner():
    et._OWNER = {"module_id": "nats-comms", "path": "nats_comms.tasks.handle", "task_name": "nats_comms.handle"}


async def connect(consumer):
    await consumer.connect()
    return consumer


# ---------------------------------------------------------------- a valid connect
reset()
add_agent("agentone", pk=1)
c = make_consumer()


async def case_connect():
    await connect(c)
    must(c.accepted and not c.closed, (c.accepted, c.closed))
    must(c._watch is not None, "the watcher runs")
    value = CACHE.data[et.presence_key("agentone")]
    must(value["connected"] is True and value["since"] and CACHE.timeouts[et.presence_key("agentone")] == 150, value)
    must(c.channel_name in LAYER.groups[et.group_name("agentone")], "joined the group")
    must([a["action"] for a in AUDITS] == ["custom:endpoint-connect"], AUDITS)
    await c.disconnect(1000)
    must(et.presence_key("agentone") not in CACHE.data, "presence removed on a clean disconnect")
    must(AUDITS[-1]["action"] == "custom:endpoint-disconnect", AUDITS)


run(case_connect())


# ---------------------------------------------------------------- refusals
async def refused(headers, reason):
    reset()
    add_agent("agentone", pk=1)
    TOKENS["d" * 40] = H.FakeTokenRow("d" * 40, H.FakeUser("dash"))
    add_agent("agentoff", token="e" * 40, pk=2, active=False)
    cc = make_consumer(headers=headers)
    await cc.connect()
    must(cc.accepted and cc.closed == [4401], (reason, cc.closed))
    must(AUDITS[-1]["action"] == "custom:endpoint-refused" and AUDITS[-1]["metadata"]["reason"] == reason and AUDITS[-1]["refusal"], (reason, AUDITS))
    must(et.presence_key("agentone") not in CACHE.data and not LAYER.groups, "nothing joined")


run(refused(H.headers_for(agent_id="agenttwo"), "agent_mismatch"))
run(refused(H.headers_for(token="d" * 40), "no_agent"))
run(refused(H.headers_for(token="c" * 40), "unknown_token"))
run(refused(H.headers_for(token="e" * 40, agent_id="agentoff"), "inactive"))
run(refused(H.headers_for(token=None), "malformed_token"))
run(refused(H.headers_for(agent_id=None), "malformed_agent_id"))

# the 11th failure from one address gets 4429, other addresses and good agents are not counted
reset()
add_agent("agentone", pk=1)


async def case_rate():
    for _ in range(10):
        bad = make_consumer(headers=H.headers_for(token="c" * 40), channel=f"specific.b{_}")
        await bad.connect()
        must(bad.closed == [4401], bad.closed)
    eleventh = make_consumer(headers=H.headers_for(token="c" * 40), channel="specific.b11")
    await eleventh.connect()
    must(eleventh.closed == [4429], eleventh.closed)
    must(AUDITS[-1]["metadata"]["reason"] == "unknown_token" and len(AUDITS) == 10, "the limited refusal writes no row")
    other = make_consumer(headers=H.headers_for(real_ip="198.51.100.77"), channel="specific.other")
    await other.connect()
    must(not other.closed, "another address connects")
    await other.disconnect(1000)
    # a successful connect never counted
    must(CACHE.data[et._failure_key("203.0.113.9")] == 10, CACHE.data)


run(case_rate())

# plain text, no channel layer
reset()
add_agent("agentone", pk=1)
plain = make_consumer(headers=H.headers_for(extra=[(b"x-forwarded-proto", b"http")]))
run(plain.connect())
must(plain.closed == [4403], plain.closed)
reset()
add_agent("agentone", pk=1)
H.LAYER_ENABLED[0] = False
nolayer = make_consumer()
run(nolayer.connect())
must(nolayer.closed == [4503], nolayer.closed)
H.LAYER_ENABLED[0] = True

# ---------------------------------------------------------------- the 10 minute re-check (injected clock)
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
c = make_consumer(clock=clock)


async def case_recheck():
    await c.connect()
    c._watch.cancel()
    clock.now += 599
    c._unanswered_pings = 0
    must(await c._tick() is True and not c.closed, "before 10 minutes nothing is re-checked")
    del TOKENS[TOKEN]  # Tactical deleted the agent
    clock.now += 2
    must(await c._tick() is False and c.closed == [4401], c.closed)
    must(AUDITS[-1]["action"] == "custom:endpoint-refused" and AUDITS[-1]["metadata"]["reason"] == "unknown_token", AUDITS[-1])


run(case_recheck())

# ---------------------------------------------------------------- one connection per agent
reset()
add_agent("agentone", pk=1)
first, second = make_consumer(channel="specific.first"), make_consumer(channel="specific.second")


async def case_takeover():
    await first.connect()
    since_first = CACHE.data[et.presence_key("agentone")]["owner"]
    await second.connect()
    must(first.closed == [4409] and not second.closed, (first.closed, second.closed))
    since_second = CACHE.data[et.presence_key("agentone")]["owner"]
    must(since_second != since_first, "the newer connection owns the key")
    await first.disconnect(4409)
    must(CACHE.data.get(et.presence_key("agentone"), {}).get("owner") == since_second, "the old connection did not delete the new presence")
    await second.disconnect(1000)
    must(et.presence_key("agentone") not in CACHE.data, "the owner removes it")


run(case_takeover())

# ---------------------------------------------------------------- frames
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
c = make_consumer(clock=clock)


async def case_frames():
    await c.connect()
    c._watch.cancel()
    await c.receive(text_data="x" * (et.MAX_FRAME_BYTES + 1))
    must(c.closed == [1009], c.closed)
    c.closed.clear()
    await c.receive(text_data="not json")
    await c.receive(text_data=json.dumps([1, 2]))
    await c.receive(text_data=json.dumps({"v": 1, "type": "weird", "id": "x", "func": "f", "payload": {}}))
    await c.receive(bytes_data=b"\x00")
    must(not c.closed and c._bad_frames == 4 and not c.out, "bad frames are dropped, not answered")
    # a request from the agent and an ack for an unknown id are dropped
    await c.receive(text_data=json.dumps({"v": 1, "type": "request", "id": "r", "func": "f", "payload": {}}))
    await c.receive(text_data=json.dumps({"v": 1, "type": "ack", "id": "unknown"}))
    must(not c.out and not CELERY.sent, "nothing answered or queued")
    # ping answered with pong, presence refreshed
    CACHE.data.pop(et.presence_key("agentone"))
    CACHE.data[et.presence_key("agentone")] = {"connected": True, "since": c._since, "owner": c._owner}
    await c.receive(text_data=json.dumps({"v": 1, "type": "ping", "id": "p1", "func": "", "payload": {}}))
    must(frames(c) == [{"v": 1, "type": "pong", "id": "p1", "func": "", "payload": {}}], frames(c))
    must(CACHE.timeouts[et.presence_key("agentone")] == 150, "presence refreshed with its 150 s life")
    # 20 frames a second are fine, the 21st closes 4429
    c2 = make_consumer(clock=H.Clock(), channel="specific.rate")
    await c2.connect()
    c2._watch.cancel()
    ping = json.dumps({"v": 1, "type": "ping", "id": "p", "func": "", "payload": {}})
    for _ in range(20):
        await c2.receive(text_data=ping)
    must(not c2.closed, c2.closed)
    await c2.receive(text_data=ping)
    must(c2.closed == [4429], c2.closed)
    c2.closed.clear()
    c2._clock.now += 1.0
    await c2.receive(text_data=ping)
    must(not c2.closed, "the bucket refills")
    # too many bad frames close the socket
    c3 = make_consumer(clock=H.Clock(), channel="specific.bad")
    await c3.connect()
    c3._watch.cancel()
    for index in range(et.MAX_BAD_FRAMES):
        c3._clock.now += 1.0
        await c3.receive(text_data="nope")
    must(c3.closed == [4400], c3.closed)


run(case_frames())

# ---------------------------------------------------------------- pings from Core
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
c = make_consumer(clock=clock)


async def case_pings():
    await c.connect()
    c._watch.cancel()
    for expected in (1, 2):
        clock.now += 61
        c._next_recheck = clock.now + 1000
        must(await c._tick() is True, "ping sent")
        must(frames(c)[-1]["type"] == "ping" and frames(c)[-1]["id"] == f"core-{expected}", frames(c)[-1])
    await c.receive(text_data=json.dumps({"v": 1, "type": "pong", "id": "core-2", "func": "", "payload": {}}))
    must(c._unanswered_pings == 0, "a pong resets the count")
    for _ in range(2):
        clock.now += 61
        c._next_recheck = clock.now + 1000
        await c._tick()
    clock.now += 61
    c._next_recheck = clock.now + 1000
    must(await c._tick() is False and c.closed == [4408], c.closed)


run(case_pings())

# ---------------------------------------------------------------- events: owner task, one audit row, the ack only after the enqueue
reset()
add_agent("agentone", pk=1)
register_owner()
c = make_consumer()


async def case_event():
    await c.connect()
    c._watch.cancel()
    AUDITS.clear()
    H.ORDER.clear()
    CELERY.on_send = lambda name, args: H.ORDER.append("enqueue")
    original = c._send_frame

    async def tracked(frame):
        H.ORDER.append("ack" if frame["type"] == "ack" else "send")
        await original(frame)

    c._send_frame = tracked
    await c.receive(text_data=json.dumps(EVENT))
    await asyncio.gather(*list(c._events))
    must(CELERY.sent == [("nats_comms.handle", ("agentone", EVENT))], CELERY.sent)
    must(H.ORDER == ["enqueue", "audit", "ack"], H.ORDER)
    must(frames(c)[-1] == {"v": 1, "type": "ack", "id": "ev-1", "func": "reboot.choice", "payload": {}}, frames(c))
    row = AUDITS[0]
    must(row["action"] == "custom:endpoint-event" and row["agent_id"] == "agentone" and row["metadata"]["func"] == "reboot.choice" and row["metadata"]["frame_id"] == "ev-1", row)
    must("secret_choice" not in repr(AUDITS) and "later" not in repr(AUDITS), "no payload in the row")
    # the enqueue fails: no ack, no audit row, a throttled log line
    del c.out[:]
    AUDITS.clear()
    CELERY.fail = True
    await c.receive(text_data=json.dumps({**EVENT, "id": "ev-2"}))
    await asyncio.gather(*list(c._events))
    must(not c.out and not AUDITS, "no ack and no row when the hand-over failed")
    # no owner registered: no ack
    CELERY.fail = False
    et.clear_owner_for_tests()
    await c.receive(text_data=json.dumps({**EVENT, "id": "ev-3"}))
    await asyncio.gather(*list(c._events))
    must(not c.out and len(CELERY.sent) == 1, "no owner, no ack")
    # a slow broker is bounded by the timeout: no ack, the receive loop was not held
    register_owner()
    old_timeout = et.ENQUEUE_TIMEOUT_SECONDS
    et.ENQUEUE_TIMEOUT_SECONDS = 0.05
    import time

    CELERY.on_send = lambda name, args: time.sleep(0.3)
    started = asyncio.get_running_loop().time()
    await c.receive(text_data=json.dumps({**EVENT, "id": "ev-4"}))
    must(asyncio.get_running_loop().time() - started < 0.1, "receive returned at once")
    await asyncio.gather(*list(c._events))
    must(not c.out, "timed out: no ack")
    et.ENQUEUE_TIMEOUT_SECONDS = old_timeout
    await asyncio.sleep(0.35)


run(case_event())

# ---------------------------------------------------------------- requests and replies
reset()
add_agent("agentone", pk=1)
add_agent("agenttwo", token=TOKEN2, pk=2)
a = make_consumer(channel="specific.A")
b = make_consumer(headers=H.headers_for(token=TOKEN2, agent_id="agenttwo"), channel="specific.B")
REQ = {"v": 1, "type": "request", "id": "req-1", "func": "status.get", "payload": {}}


async def case_reply():
    await a.connect()
    await b.connect()
    a._watch.cancel()
    b._watch.cancel()
    reply_channel = await LAYER.new_channel()
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.request", "frame": REQ, "reply_channel": reply_channel, "timeout": 5})
    must(frames(b) == [REQ] and not a.out, "only agent B was asked")
    # agent A answers B's request id: dropped and counted, nothing reaches the channel
    await a.receive(text_data=json.dumps({"v": 1, "type": "reply", "id": "req-1", "func": "status.get", "payload": {"x": 1}}))
    must(LAYER.channels[reply_channel].empty() and a._dropped_replies == 1, "A cannot answer B's request")
    # B answers: routed to the waiting channel, once
    answer = {"v": 1, "type": "reply", "id": "req-1", "func": "status.get", "payload": {"ok": True}}
    await b.receive(text_data=json.dumps(answer))
    got = LAYER.channels[reply_channel].get_nowait()
    must(got == {"type": "endpoint.reply", "frame": answer}, got)
    await b.receive(text_data=json.dumps(answer))
    must(LAYER.channels[reply_channel].empty() and b._dropped_replies == 1, "a second reply is dropped")
    # a reply after the request's lifetime is dropped; a bad request message is not delivered
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.request", "frame": {**REQ, "id": "req-2"}, "reply_channel": reply_channel, "timeout": 1})
    import time

    b._clock = lambda: time.monotonic() + 100
    await b.receive(text_data=json.dumps({**answer, "id": "req-2"}))
    must(LAYER.channels[reply_channel].empty(), "expired entry")
    before = len(b.out)
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.request", "frame": {**REQ, "type": "event"}, "reply_channel": reply_channel})
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.request", "frame": {**REQ, "id": "req-3"}, "reply_channel": 5})
    must(len(b.out) == before, "invalid request messages are not delivered")
    # a push reaches the agent when it is an event
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.push", "frame": EVENT})
    must(frames(b)[-1] == EVENT, "push delivered")
    await LAYER.group_send(et.group_name("agenttwo"), {"type": "endpoint.push", "frame": REQ})
    must(len(frames(b)) == before + 1, "a request is not pushed")


run(case_reply())

# ---------------------------------------------------------------- an import fault closes 4503 and never raises
sent = []
original_import = sys.modules.pop("tec_tac.endpoint_transport_consumer")
sys.modules["tec_tac.endpoint_transport_consumer"] = None  # makes the import fail


async def collect(message):
    sent.append(message)


run(et._EndpointAgentRoute()({"type": "websocket"}, None, collect))
must(sent == [{"type": "websocket.close", "code": 4503}], sent)
sys.modules["tec_tac.endpoint_transport_consumer"] = original_import

# ---------------------------------------------------------------- the token appears nowhere
must(not any(m in "\n".join(LOGS) for m in H.SECRET_MARKERS), "no log record holds a token")
must(not any(m in repr(AUDITS) for m in H.SECRET_MARKERS), "no audit row holds a token")
consumer_source = (H.APP / "endpoint_transport_consumer.py").read_text(encoding="utf-8")
must("logger" in consumer_source and "self._token" in consumer_source and "log" not in consumer_source.split("self._token")[1].split("\n")[0].lower(), "the token is only kept")

# ---------------------------------------------------------------- 1.17.90-1: the audit table cannot be grown without limit
reset()
add_agent("agentone", pk=1)


async def case_flood():
    codes = []
    for i in range(50):
        p = make_consumer(headers=H.headers_for(extra=[(b"x-forwarded-proto", b"http")]), channel=f"specific.p{i}")
        await p.connect()
        codes.append(p.closed[0])
    for i in range(50):
        u = make_consumer(headers=H.headers_for(token="c" * 40), channel=f"specific.u{i}")
        await u.connect()
        codes.append(u.closed[0])
    must(codes[:10] == [4403] * 10 and codes[10:] == [4429] * 90, codes)
    rows = [a for a in AUDITS if a["action"] == "custom:endpoint-refused"]
    must(len(rows) <= 11 and len(AUDITS) <= 11, len(AUDITS))
    must(CACHE.data[et._failure_key("203.0.113.9")] == 10, "the plaintext refusal counts as a failure")


run(case_flood())

# ---------------------------------------------------------------- 1.17.90-1: group membership is renewed (channels_redis group_expiry 86400 s)
reset()
add_agent("agentone", pk=1)
clock = H.Clock()
old = make_consumer(clock=clock, channel="specific.old")
new = make_consumer(clock=clock, channel="specific.new")


async def case_group_expiry():
    await old.connect()
    old._watch.cancel()
    LAYER.groups[et.group_name("agentone")].clear()  # the layer dropped the member after group_expiry
    clock.now += et.PING_SECONDS + 1
    old._unanswered_pings = 0
    must(await old._tick() is True, "tick")
    must(old.channel_name in LAYER.groups[et.group_name("agentone")], "renewed on the ping")
    before = len(frames(old))
    await LAYER.group_send(et.group_name("agentone"), {"type": "endpoint.request", "frame": REQ, "reply_channel": "reply.1", "timeout": 5})
    must(len(frames(old)) == before + 1, "request reaches the connection after the expiry")
    await new.connect()
    must(old.closed == [4409], "takeover still closes the older connection")
    await new.disconnect(1000)


run(case_group_expiry())
print("PASS endpoint transport consumer 1.17.90")
