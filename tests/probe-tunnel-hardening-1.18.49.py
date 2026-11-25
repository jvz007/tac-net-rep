#!/usr/bin/env python3
"""1.18.49 regression: the tunnel relay review (M2, L2, L3, L4, L5, L8), on the in-memory harness (tests/probe_transport_harness.py).

M2: frames go to the peer's own channel with send() (which raises ChannelFull), never through group_send, which drops a message silently when a
member's channel is full. A full channel ends the session relay_overloaded on either side. Each direction numbers its frames inside the layer
message; a lost, repeated or reordered message ends the session relay_overloaded. Peer discovery is symmetric (a ready marker with the channel
name plus tunnel.paired, in both connect orders; a lost tunnel.paired is recovered by the watcher; a malformed channel name is refused). The
probe side holds frames, up to 1 MiB, until the Console's channel is known. A 10 MiB echo is still byte for byte.
L2: the 15 second pair wait does not end a drain that is still running. L3: the probe socket's own idle and hard-cap backstops. L4: more than
FRAMES_PER_SECOND_MAX messages in a second end the session protocol_error, counted without the cache. L8: no tunnel audit row holds the target.
L5: the docs name X-Forwarded-Proto, the nginx /ws/ block, the 60 second Redis note, the hosting-stack message limit and the new constants.
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, LAYER, CELERY, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.LAYER, H.CELERY, H.run
frame, Clock = H.frame, H.Clock
OPEN, DATA, ACK, CLOSE = 1, 2, 3, 4
PROBE_CH, CONSOLE_CH = "specific.tprobe", "specific.console"


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.add_probe(H.PROBE2, H.KEY2, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def ended_reason(sid):
    marker = CACHE.data.get(tun.end_key(sid))
    return marker["reason"] if marker else None


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


async def pair(idle_s=900, cap_s=14400, probe_first=False, clock=None, **spec_over):
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid, idle_s=idle_s, cap_s=cap_s, **spec_over))
    must(got["outcome"] == "ok", got)
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    first, second = (probe, console) if probe_first else (console, probe)
    for consumer in (first, second):
        await consumer.connect()
        await H.settle(consumer)
    must(not console.closed and not probe.closed, (console.closed, probe.closed))
    return console, probe, sid, clock


async def console_only(clock=None, **spec_over):
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid, **spec_over))["ticket"], clock=clock)
    await console.connect()
    await H.settle(console)
    return console, sid, clock


async def probe_only(clock=None):
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    return probe, sid, clock, got["ticket"]


# ---------------------------------------------------------------- (a) a full peer channel ends the session; nothing is lost silently
async def case_full_channel():
    # the Console sends, the probe's channel is full
    console, probe, sid, clock = await pair()
    LAYER.hold(PROBE_CH)
    held = [frame(DATA, 1, bytes([n]) * 10) for n in range(100)]
    for data in held:
        await console.receive(bytes_data=data)
    must(not console.closed and ended_reason(sid) is None, "100 frames fit in the channel")
    sent_before = len(LAYER.direct)
    await console.receive(bytes_data=frame(DATA, 1, b"101st"))
    await H.settle(console)
    must(ended_reason(sid) == "relay_overloaded" and console.closed[-1] == 1013 and console.close_reasons[-1] == "relay_overloaded", (console.closed, console.close_reasons))
    must(len(LAYER.direct) == sent_before + 1, "the 101st frame was offered once and refused")
    await console.receive(bytes_data=frame(DATA, 1, b"after the end"))
    must(len(LAYER.direct) == sent_before + 1, "nothing is sent after the end")
    # the tunnel.end for the full channel is dropped by the layer, as in channels_redis; the 100 held frames still arrive, in order
    must(probe.closed == [], "the probe has not seen the end message yet")
    delivered = await LAYER.release(PROBE_CH)
    must(delivered == 100 and probe.out_bytes == held, "the 100 held frames arrive in order")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await probe._tick() is False and probe.close_reasons[-1] == "relay_overloaded" and probe.closed[-1] == 1013, "the probe's watcher closes it with the same reason")
    await console.disconnect(1013)
    await H.settle(console)
    must(len(rows("custom:probe-tunnel-end")) == 1 and rows("custom:probe-tunnel-end")[0]["metadata"]["reason"] == "relay_overloaded", "one end row")
    # the probe sends, the Console's channel is full
    console, probe, sid, clock = await pair()
    LAYER.hold(CONSOLE_CH)
    out = [frame(DATA, 1, bytes([n]) * 10) for n in range(100)]
    for data in out:
        await probe.receive(bytes_data=data)
    must(not probe.closed, "100 frames fit")
    await probe.receive(bytes_data=frame(DATA, 1, b"101st"))
    await H.settle(probe)
    must(ended_reason(sid) == "relay_overloaded" and probe.closed[-1] == 1013 and probe.close_reasons[-1] == "relay_overloaded", (probe.closed, probe.close_reasons))
    delivered = await LAYER.release(CONSOLE_CH)
    must(delivered == 100 and console.out_bytes == out, "the Console receives the 100 held frames in order")
    clock.now += tun.FLUSH_SECONDS
    must(await console._tick() is False and console.close_reasons[-1] == "relay_overloaded", "the Console's watcher closes it")
    # a slow or failing layer ends it too, and the frame is not dropped silently
    for problem in (H.ChannelFull(), asyncio.TimeoutError(), RuntimeError("redis down")):
        console, probe, sid, _ = await pair()
        LAYER.fail_send = lambda channel, message, problem=problem: problem
        await probe.receive(bytes_data=frame(DATA, 1, b"x"))
        must(ended_reason(sid) == "relay_overloaded" and probe.close_reasons[-1] == "relay_overloaded", type(problem))


run(case_full_channel())


# ---------------------------------------------------------------- (b) a lost, repeated or reordered message ends the session
async def case_sequence():
    for lost_type in (DATA, ACK, CLOSE):
        console, probe, sid, _ = await pair()
        await console.receive(bytes_data=frame(OPEN, 1))
        state = {"dropped": False}

        def drop(channel, message, lost_type=lost_type, state=state):
            if channel == PROBE_CH and message["data"][0] == lost_type and not state["dropped"]:
                state["dropped"] = True
                return True
            return False

        LAYER.drop_send = drop
        lost = frame(lost_type, 1, b"\x00\x00\x00\x01" if lost_type == ACK else (b"\x00" if lost_type == CLOSE else b"gone"))
        await console.receive(bytes_data=lost)
        must(state["dropped"] and probe.closed == [], "the message was lost and nothing noticed yet")
        await console.receive(bytes_data=frame(DATA, 1, b"next"))
        await H.settle(probe)
        must(ended_reason(sid) == "relay_overloaded" and probe.closed[-1] == 1013 and probe.close_reasons[-1] == "relay_overloaded", ("gap", lost_type, probe.closed))
        must(frame(DATA, 1, b"next") not in probe.out_bytes, "the frame behind the gap is not delivered")
    # the Console's direction as well
    console, probe, sid, _ = await pair()
    LAYER.drop_send = lambda channel, message: channel == CONSOLE_CH and message["data"][0] == ACK
    await probe.receive(bytes_data=frame(ACK, 1, b"\x00\x00\x00\x01"))
    LAYER.drop_send = None
    await probe.receive(bytes_data=frame(DATA, 1, b"y"))
    must(ended_reason(sid) == "relay_overloaded" and console.close_reasons[-1] == "relay_overloaded", "a lost ACK towards the Console ends it")
    # a repeated message
    console, probe, sid, _ = await pair()
    await console.receive(bytes_data=frame(DATA, 1, b"one"))
    _channel, message = LAYER.direct[-1]
    await probe.tunnel_frame(dict(message))
    must(ended_reason(sid) == "relay_overloaded" and probe.close_reasons[-1] == "relay_overloaded", "a repeat ends it")
    # a reordered pair
    console, probe, sid, _ = await pair()
    LAYER.hold(PROBE_CH)
    await console.receive(bytes_data=frame(DATA, 1, b"first"))
    await console.receive(bytes_data=frame(DATA, 1, b"second"))
    LAYER.held[PROBE_CH].reverse()
    await LAYER.release(PROBE_CH)
    must(ended_reason(sid) == "relay_overloaded" and probe.out_bytes == [], "a reorder ends it before anything is delivered")
    # a message without a usable number (an old or forged one)
    for bad in ({}, {"seq": True}, {"seq": "0"}, {"seq": -1}, {"seq": 1.5}):
        console, probe, sid, _ = await pair()
        await probe.tunnel_frame({"type": "tunnel.frame", "side": "console", "data": frame(DATA, 1, b"z"), **bad})
        must(ended_reason(sid) == "relay_overloaded" and probe.out_bytes == [], ("unusable seq", bad))
    # the numbers run per direction and the wire frames are byte for byte what was sent
    console, probe, sid, _ = await pair()
    sent = [frame(OPEN, 1), frame(DATA, 1, b"a"), frame(ACK, 1, b"\x00\x00\x00\x01")]
    for data in sent:
        await console.receive(bytes_data=data)
    await probe.receive(bytes_data=frame(DATA, 2, b"b"))
    must([m["seq"] for c, m in LAYER.direct if c == PROBE_CH] == [0, 1, 2] and [m["seq"] for c, m in LAYER.direct if c == CONSOLE_CH] == [0], "per direction")
    must(probe.out_bytes == sent and console.out_bytes == [frame(DATA, 2, b"b")], "the wire frames carry no sequence number")


run(case_sequence())


# ---------------------------------------------------------------- (c) no frame goes through group_send
async def case_no_group_frames():
    console, probe, _sid, _clock = await pair()
    for data in (frame(OPEN, 1), frame(DATA, 1, b"d"), frame(ACK, 1, b"\x00\x00\x00\x01"), frame(CLOSE, 1, b"\x00")):
        await console.receive(bytes_data=data)
        await probe.receive(bytes_data=data)
    must(len(LAYER.direct) == 8, "eight frames went to the peers' own channels")
    await console.disconnect(1000)
    await H.settle(console)
    tunnel_sent = [(g, m) for g, m in LAYER.sent if g.startswith(tun.GROUP_PREFIX)]  # the probe's control group carries tunnel.close pushes, not frames
    kinds = {m["type"] for _, m in tunnel_sent}
    must(kinds <= {"tunnel.paired", "tunnel.end"} and "tunnel.paired" in kinds, kinds)
    for group, message in tunnel_sent:
        must(set(message) <= {"type", "side", "channel", "reason", "ended_by"} and "data" not in message, message)
    text = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "group_send":
            body = ast.unparse(node)
            must("tunnel.paired" in body or "end_message" in body, "group_send carries only tunnel.paired or tunnel.end: " + body)
    must(text.count('"tunnel.frame"') == 1, "one place builds a frame message")
    forward_node = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_forward")
    forward = ast.unparse(forward_node.body[1:])  # without the docstring
    must("'tunnel.frame'" in forward and "channel_layer.send(self._peer" in forward and "group_send" not in forward, "and it uses send to the peer's channel")


run(case_no_group_frames())


# ---------------------------------------------------------------- (d) peer discovery
async def case_discovery():
    for probe_first in (True, False):
        console, probe, sid, _ = await pair(probe_first=probe_first)
        must(console._paired and probe._paired and console._peer == PROBE_CH and probe._peer == CONSOLE_CH, (probe_first, console._peer, probe._peer))
        must(tun.ready_channel(sid, tun.SIDE_PROBE_READY) == PROBE_CH and tun.ready_channel(sid, tun.SIDE_CONSOLE_READY) == CONSOLE_CH, "both markers carry the channel")
        await console.receive(bytes_data=frame(OPEN, 1))
        await probe.receive(bytes_data=frame(DATA, 1, b"hello"))
        must(probe.out_bytes == [frame(OPEN, 1)] and console.out_bytes == [frame(DATA, 1, b"hello")], "both directions flow")
        state = tun.poll_session(sid)
        must(state["console_channel"] == CONSOLE_CH and state["ready"] is True, state)
    # a lost tunnel.paired towards the probe: its watcher finds the Console's marker
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    held = [frame(DATA, 1, b"early" * 3), frame(DATA, 1, b"early2")]
    for data in held:
        await probe.receive(bytes_data=data)

    async def lost(event):
        return None

    probe.tunnel_paired = lost
    console = H.make_console(got["ticket"], clock=clock)
    await console.connect()
    await H.settle(console)
    must(console._paired and not probe._paired and console.out_bytes == [], "the Console paired; the probe missed tunnel.paired")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await probe._tick() is True and probe._paired and probe._peer == CONSOLE_CH, "the probe's watcher pairs through the Console's marker")
    must(console.out_bytes == held, "and its held frames reach the Console in order")
    # a lost tunnel.paired towards the Console is still recovered by its watcher (1.18.48)
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    console = H.make_console(got["ticket"], clock=clock)
    await console.connect()
    await H.settle(console)
    console.tunnel_paired = lost
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    must(not console._paired and probe._paired, "the probe paired through the marker; the Console missed the message")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and console._paired and console._peer == PROBE_CH, "the Console's watcher pairs")
    # a malformed channel name is refused, from a marker, from a message, and from a marker without a name
    for bad in ("bad name", "x" * 201, "", "a/b", "chan\nnel", "ünï", None, 7, ["specific.x"]):
        must(tun.clean_channel(bad) is None, ("clean_channel", bad))
    must(tun.clean_channel("specific.abc!Def-1.x_") == "specific.abc!Def-1.x_" and tun.clean_channel("a" * 200) == "a" * 200, "a real channels name passes")
    for bad in ("bad name", "x" * 201, "a/b", None):
        console, sid, clock = await console_only()
        CACHE.set(tun.side_key(sid, tun.SIDE_PROBE_READY), {"at": 1, "channel": bad})
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is True and not console._paired and console._peer is None, ("marker", bad))
        await console.tunnel_paired({"type": "tunnel.paired", "side": "probe", "channel": bad})
        must(not console._paired and console._peer is None, ("message", bad))
    console, sid, clock = await console_only()
    CACHE.set(tun.side_key(sid, tun.SIDE_PROBE_READY), {"at": 1})
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and not console._paired, "a marker without a channel name (a 1.18.48 marker) does not pair")
    # an end that writes a marker with a bad name cannot make a frame go anywhere
    must(LAYER.direct == [], "nothing was sent to a malformed channel")
    # the side field: a tunnel.paired from the same side is ignored
    console, sid, clock = await console_only()
    await console.tunnel_paired({"type": "tunnel.paired", "side": "console", "channel": PROBE_CH})
    must(not console._paired, "a message from its own side does not pair")


run(case_discovery())


# ---------------------------------------------------------------- (e) the probe side holds frames until the Console's channel is known
async def case_probe_buffer():
    probe, sid, clock, ticket = await probe_only()
    must(not probe._paired, "no Console yet")
    out = [frame(DATA, 1, bytes([n]) * 50) for n in range(5)]
    for data in out:
        await probe.receive(bytes_data=data)
    must(probe._buffered == sum(len(d) for d in out) and LAYER.direct == [], "held, nothing sent")
    console = H.make_console(ticket, clock=clock)
    await console.connect()
    await H.settle(console)
    must(console.out_bytes == out and probe._paired and probe._buffered == 0, "drained in order when the Console's channel became known")
    await probe.receive(bytes_data=frame(DATA, 1, b"later"))
    must(console.out_bytes[-1] == frame(DATA, 1, b"later"), "direct forwarding afterwards")
    # over the 1 MiB cap on the probe side: console_not_connected
    probe, sid, clock, _ticket = await probe_only()
    chunk = frame(DATA, 1, b"x" * 32768)
    for _ in range(tun.BUFFER_CAP_BYTES // len(chunk)):
        await probe.receive(bytes_data=chunk)
    must(not probe.closed, "the cap is not reached")
    await probe.receive(bytes_data=chunk)
    must(probe.closed == [1000] and probe.close_reasons == ["console_not_connected"] and ended_reason(sid) == "console_not_connected", (probe.closed, probe.close_reasons))
    # the Console's side keeps probe_offline
    console, sid, clock = await console_only()
    for _ in range(tun.BUFFER_CAP_BYTES // len(chunk)):
        await console.receive(bytes_data=chunk)
    await console.receive(bytes_data=chunk)
    must(console.close_reasons == ["probe_offline"] and ended_reason(sid) == "probe_offline", console.close_reasons)
    # a drain on the probe side: a frame that arrives during it goes out after the earlier ones
    probe, sid, clock, ticket = await probe_only()
    first, second, late = frame(OPEN, 1), frame(DATA, 1, b"b"), frame(DATA, 1, b"late")
    for data in (first, second):
        await probe.receive(bytes_data=data)
    seen, started, release = [], asyncio.Event(), asyncio.Event()

    async def slow_forward(data):
        started.set()
        await release.wait()
        seen.append(bytes(data))
        return True

    probe._forward = slow_forward
    drain = asyncio.ensure_future(probe._complete_pairing(CONSOLE_CH))
    await started.wait()
    await probe.receive(bytes_data=late)
    release.set()
    await drain
    must(seen == [first, second, late] and probe._paired and probe._buffered == 0, seen)


run(case_probe_buffer())


# ---------------------------------------------------------------- (f) ten MiB echo, byte for byte, on the new path
async def case_echo():
    for probe_first in (False, True):
        console, probe, _sid, _ = await pair(probe_first=probe_first)
        sent = [frame(OPEN, 1)] + [frame(DATA, 1, bytes([n % 251]) * 32768) for n in range(320)]
        for data in sent:
            await console.receive(bytes_data=data)
            if console._clock() < 0:
                raise AssertionError
        must(probe.out_bytes == sent, "the probe received every frame, byte for byte, in order")
        for data in probe.out_bytes:
            await probe.receive(bytes_data=data)
        must(console.out_bytes == sent and console.bytes_up == 320 * 32768 == 10 * 1024 * 1024 and console.bytes_down == console.bytes_up, "echoed byte for byte")
        must(LAYER.direct and all(m["type"] == "tunnel.frame" for _, m in LAYER.direct), "all through send")
        # 640 frames inside one second is well under the rate limit
        must(not console.closed and not probe.closed, "no limit was hit")


# the echo pushes 641 messages per direction in zero injected time; the limit is 2000, so it passes
run(case_echo())


# ---------------------------------------------------------------- L2: the pair wait does not end a live drain
async def case_drain_across_pair_wait():
    console, sid, clock = await console_only()
    sent = [frame(OPEN, 1), frame(DATA, 1, b"a" * 10)]
    for data in sent:
        await console.receive(bytes_data=data)
    seen, started, release = [], asyncio.Event(), asyncio.Event()

    async def slow_forward(data):
        started.set()
        await release.wait()
        seen.append(bytes(data))
        return True

    console._forward = slow_forward
    drain = asyncio.ensure_future(console._complete_pairing(PROBE_CH))
    await started.wait()
    must(console._pairing and not console._paired, "the drain is running")
    clock.now += tun.PAIR_WAIT_SECONDS + 1  # past the 15 second mark
    must(await console._tick() is True and not console._ended_local and ended_reason(sid) is None, "the watcher leaves a running drain alone")
    release.set()
    await drain
    must(console._paired and seen == sent, "the drain finished and the session is paired")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and ended_reason(sid) is None, "and stays up")
    # a genuinely unpaired session still ends probe_offline at 15 seconds
    console, sid, clock = await console_only()
    clock.now += tun.PAIR_WAIT_SECONDS - 1
    must(await console._tick() is True, "14 seconds")
    clock.now += 1
    must(await console._tick() is False and console.close_reasons == ["probe_offline"] and ended_reason(sid) == "probe_offline", "15 seconds")
    # a drain that fails ends the session through relay_overloaded, not a hang
    console, sid, clock = await console_only()
    await console.receive(bytes_data=frame(OPEN, 1))
    LAYER.fail_send = lambda channel, message: H.ChannelFull()
    await console._complete_pairing(PROBE_CH)
    must(ended_reason(sid) == "relay_overloaded" and not console._paired, "a failing drain ends the session itself")
    # the same rule on the probe side: a Console that is attached but whose channel is unknown has 15 seconds from the first tick that saw it
    probe, sid, clock, _ticket = await probe_only()
    must(tun._attach(sid, "console"), "the Console's attach marker, without its ready marker")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await probe._tick() is True, "first sighting")
    clock.now += tun.PAIR_WAIT_SECONDS - 1
    must(await probe._tick() is True, "still waiting")
    clock.now += 1
    must(await probe._tick() is False and probe.close_reasons == ["console_not_connected"] and ended_reason(sid) == "console_not_connected", probe.close_reasons)
    probe, sid, clock, _ticket = await probe_only()
    tun._attach(sid, "console")
    await probe.receive(bytes_data=frame(OPEN, 1))
    clock.now += tun.WATCH_TICK_SECONDS
    must(await probe._tick() is True, "first sighting")
    seen, started, release = [], asyncio.Event(), asyncio.Event()

    async def slow_probe_forward(data):
        started.set()
        await release.wait()
        seen.append(bytes(data))
        return True

    probe._forward = slow_probe_forward
    drain = asyncio.ensure_future(probe._complete_pairing(CONSOLE_CH))
    await started.wait()
    clock.now += tun.PAIR_WAIT_SECONDS + 5
    must(await probe._tick() is True and ended_reason(sid) is None, "the probe's watcher leaves a running drain alone")
    release.set()
    await drain
    must(probe._paired, "paired after the drain")


run(case_drain_across_pair_wait())


# ---------------------------------------------------------------- L3: the probe socket's backstops
def closed_events():
    return [(task, args) for task, args in CELERY.sent if args[1]["func"] == "tunnel.closed"]


async def case_backstops():
    grace = tun.BACKSTOP_IDLE_GRACE_SECONDS
    # a dead Console worker (it never ticks): idle_timeout after idle_s plus the grace, with the last flushed counters
    console, probe, sid, clock = await pair(idle_s=60)
    tun.flush_stats(sid, WALL[0], 123, 45)  # the Console's last flush before it died
    clock.now += 60 + grace - 1
    must(await probe._tick() is True and ended_reason(sid) is None, "not yet")
    clock.now += 1
    must(await probe._tick() is False and probe.close_reasons[-1] == "idle_timeout" and ended_reason(sid) == "idle_timeout", probe.close_reasons)
    await H.settle(probe)
    end_rows = rows("custom:probe-tunnel-end")
    must(len(end_rows) == 1 and end_rows[0]["metadata"]["reason"] == "idle_timeout", end_rows)
    must(end_rows[0]["metadata"]["bytes_up"] == 123 and end_rows[0]["metadata"]["bytes_down"] == 45 and end_rows[0]["metadata"]["ended_by"] == "core", end_rows)
    events = closed_events()
    must(len(events) == 1 and events[0][1][1]["payload"]["bytes_up"] == 123 and events[0][1][1]["payload"]["bytes_down"] == 45 and events[0][1][1]["payload"]["reason"] == "idle_timeout", events)
    # the hard cap: created + cap_s + 60 seconds
    console, probe, sid, clock = await pair(cap_s=60)
    created = float(probe._record["created"])
    WALL[0] = created + 60 + tun.SLOT_GRACE_SECONDS - 1
    must(await probe._tick() is True and ended_reason(sid) is None, "inside the cap plus the grace")
    WALL[0] += 1
    must(await probe._tick() is False and probe.close_reasons[-1] == "hard_cap" and ended_reason(sid) == "hard_cap", probe.close_reasons)
    await H.settle(probe)
    must(len(rows("custom:probe-tunnel-end")) == 1 and len(closed_events()) == 1, "one row and one event")
    # DATA in either direction resets the idle clock; ACK, OPEN and CLOSE do not
    console, probe, sid, clock = await pair(idle_s=60)
    clock.now += 80
    await probe.receive(bytes_data=frame(DATA, 1, b"out"))  # probe to Console
    clock.now += 80
    must(await probe._tick() is True, "probe DATA reset the clock")
    await console.receive(bytes_data=frame(DATA, 1, b"in"))  # Console to probe, seen by tunnel_frame
    clock.now += 80
    must(await probe._tick() is True, "Console DATA reset the clock")
    clock.now += 10
    must(await probe._tick() is False and probe.close_reasons[-1] == "idle_timeout", "90 seconds after the last DATA")
    await H.settle(probe)
    console, probe, sid, clock = await pair(idle_s=60)
    clock.now += 80
    for data in (frame(OPEN, 2), frame(ACK, 1, b"\x00\x00\x00\x01"), frame(CLOSE, 1, b"\x00")):
        await probe.receive(bytes_data=data)
        await console.receive(bytes_data=data)
    clock.now += 10
    must(await probe._tick() is False and probe.close_reasons[-1] == "idle_timeout", "OPEN, ACK and CLOSE did not reset it")
    await H.settle(probe)
    # a live Console fires first: its own timers end the session, and exactly one end row and one tunnel.closed exist
    console, probe, sid, clock = await pair(idle_s=60)
    clock.now += 60
    must(await console._tick() is False and console.close_reasons[-1] == "idle_timeout", "the Console's clock fires at idle_s")
    must(probe.close_reasons[-1] == "idle_timeout" and ended_reason(sid) == "idle_timeout", "the probe was told")
    await console.disconnect(1000)
    await H.settle(console)
    await H.settle(probe)
    clock.now += grace + 5
    must(await probe._tick() is False, "the probe's watcher has nothing left to do")
    must(len(rows("custom:probe-tunnel-end")) == 1 and len(closed_events()) == 1, ("exactly one end row and one tunnel.closed", len(rows("custom:probe-tunnel-end")), len(closed_events()), [x["action"] for x in AUDITS]))
    must(rows("custom:probe-tunnel-end")[0]["metadata"]["ended_by"] == "core", "from the Console's own end")
    # an unpaired probe does not run the idle backstop (the Console has 60 seconds to come)
    probe, sid, clock, _ticket = await probe_only()
    clock.now += 600
    WALL[0] += 30
    must(await probe._tick() is True and ended_reason(sid) is None, "waiting for the Console is not idleness")


run(case_backstops())


# ---------------------------------------------------------------- L4: the frame rate
CACHE_CALLS = ("get", "set", "add", "touch", "incr", "delete", "get_many")
calls = {"n": 0}


def counting(fn):
    def wrapped(*a, **k):
        calls["n"] += 1
        return fn(*a, **k)

    return wrapped


async def case_rate():
    limit = tun.FRAMES_PER_SECOND_MAX
    must(limit == 2000, "the limit is 2000 a second")
    ack = frame(ACK, 1, b"\x00\x00\x00\x01")
    for sender in ("console", "probe"):
        console, probe, sid, clock = await pair()
        me, other = (console, probe) if sender == "console" else (probe, console)
        calls["n"] = 0
        originals = {n: getattr(CACHE, n) for n in CACHE_CALLS}
        for n in CACHE_CALLS:
            setattr(CACHE, n, counting(originals[n]))
        try:
            for _ in range(limit):
                await me.receive(bytes_data=ack)
        finally:
            for n in CACHE_CALLS:
                delattr(CACHE, n)
        must(not me.closed and ended_reason(sid) is None, f"exactly {limit} frames in a second pass on the {sender} side")
        must(calls["n"] == 0, "the rate check touched no cache call")
        must(len([1 for c, m in LAYER.direct if c == other.channel_name]) == limit, "and all of them were relayed")
        await me.receive(bytes_data=ack)
        await H.settle(me)
        must(me.closed[-1] == 1002 and me.close_reasons[-1] == "protocol_error" and ended_reason(sid) == "protocol_error", (me.closed, me.close_reasons))
        must(CACHE.data[tun.end_key(sid)]["ended_by"] == "core", "ended by core")
        must(other.close_reasons[-1] == "protocol_error", "the peer was closed with the reason")
        # the window resets when the clock moves on
        console, probe, sid, clock = await pair()
        me = console if sender == "console" else probe
        for _ in range(limit):
            await me.receive(bytes_data=ack)
        clock.now += 1.0
        for _ in range(limit):
            await me.receive(bytes_data=ack)
        must(not me.closed and ended_reason(sid) is None, "a new second, a new window")
    # a text frame, an oversize message and a short one still end protocol_error
    for sender in ("console", "probe"):
        for kwargs in ({"text_data": "hello"}, {"bytes_data": frame(DATA, 1, b"x" * (32768 + 1))}, {"bytes_data": b"\x02\x00"}, {"bytes_data": frame(9, 1)}):
            console, probe, sid, _ = await pair()
            me = console if sender == "console" else probe
            await me.receive(**kwargs)
            must(me.closed[-1] == 1002 and ended_reason(sid) == "protocol_error", (sender, list(kwargs)))
    # the check runs first: a flood of invalid messages is also counted
    console, probe, sid, clock = await pair()
    await console.receive(bytes_data=ack)
    text = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
    accept = text[text.index("async def _accept_frame"):text.index("unpaired_reason")]
    must(accept.index("_rate_exceeded()") < accept.index("check_frame"), "the rate is checked before the frame")
    must(text.count("await self._accept_frame(bytes_data)") == 2, "both consumers' receive() start with it")


run(case_rate())


# ---------------------------------------------------------------- L8: the target address is in no audit row
async def case_no_target():
    must("target" not in pt.TUNNEL_AUDIT_KEYS, "no tunnel row can hold a target")
    fresh()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid, target_label="10.1.2.3"))
    must(got["outcome"] == "ok", got)
    ticket_rows = rows("custom:probe-tunnel-ticket")
    must(len(ticket_rows) == 1 and "target" not in ticket_rows[0]["metadata"], ticket_rows)
    console, probe = H.make_console(got["ticket"], clock=Clock()), H.make_tunnel_probe(sid, clock=Clock())
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    await console.receive(bytes_data=frame(DATA, 1, b"x"))
    await console._end("ended_by_engineer", ended_by="engineer")
    await console.disconnect(1000)
    await H.settle(console)
    await H.settle(probe)
    must(len(AUDITS) >= 4, [a["action"] for a in AUDITS])
    must("10.1.2.3" not in repr(AUDITS), "the target address is in no audit row")
    # a spec that smuggles the key into a row's extra: the allow-list drops it
    must("target" not in pt._tunnel_extra({"target": "10.1.2.3", "session_id": "s"}), "the allow-list drops target")
    # the session record keeps the label for the owner's own use (it is audit text only and never leaves the cache)
    must(CACHE.data[tun.session_key(sid)]["target"] == "10.1.2.3", "the record still holds the label")


run(case_no_target())


# ---------------------------------------------------------------- L5 and the docs
def case_docs():
    doc = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
    tunnel = doc[doc.index("## The tunnel (contract 1.1.0)"):]
    for needle in ("X-Forwarded-Proto", "location ~ ^/ws/", "X-Forwarded-For", "60 seconds", "never stored", "16 MiB", "uvicorn", "--ws-max-size", "channel_layer.send",
                   "ChannelFull", "`seq`", "console_ready", "probe_ready", "tunnel.paired", "waits in Redis"):
        must(needle in tunnel, "the tunnel docs name " + needle)
    must(re.search(r"`FRAMES_PER_SECOND_MAX`[^.\n]*?2000", tunnel), "FRAMES_PER_SECOND_MAX is named with 2000")
    must(re.search(r"`BACKSTOP_IDLE_GRACE_SECONDS`[^.\n]*?30", tunnel), "BACKSTOP_IDLE_GRACE_SECONDS is named with 30")
    must(tun.FRAMES_PER_SECOND_MAX == 2000 and tun.BACKSTOP_IDLE_GRACE_SECONDS == 30, "the constants")
    must("Never a ticket, key, header, payload or target address" in tunnel, "the audit sentence holds again")
    for forbidden in ("kindly", "don't hesitate", "ethnocentric"):
        must(forbidden not in doc.lower(), forbidden)


case_docs()
print("PASS probe tunnel hardening 1.18.49")
