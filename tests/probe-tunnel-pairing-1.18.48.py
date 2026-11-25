#!/usr/bin/env python3
"""1.18.48 regression: the two held Mediums of 1.18.47, on the in-memory harness (tests/probe_transport_harness.py).

Pairing: the Console is paired only when the probe's socket is in the group (the "probe_ready" marker, written after accept and group_add),
not when the probe merely holds the attach marker. A frame sent while the probe is between its marker and its group_add is held and goes out
in order, byte for byte, none lost. A frame that arrives during the drain is sent after the earlier ones. A lost tunnel.paired is recovered
by the watcher. The 1 MiB buffer cap and the 15 second wait still end the session probe_offline. Both connect orders pair.

Activity: only the engineer's own DATA (Console to probe) reaches the sign-in as activity (rule 1.8, AD-35). Output from the target resets the
tunnel's own idle timer and counts bytes_down but never the sign-in; a session that only streams output ends at the sign-in idle limit.
"""
from __future__ import annotations

import asyncio
import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, WALL, LAYER, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.WALL, H.LAYER, H.run
frame, Clock = H.frame, H.Clock
OPEN, DATA, ACK, CLOSE = 1, 2, 3, 4


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


async def pair(idle_s=900, cap_s=14400, probe_first=False, clock=None):
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid, idle_s=idle_s, cap_s=cap_s))
    must(got["outcome"] == "ok", got)
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    first, second = (probe, console) if probe_first else (console, probe)
    for consumer in (first, second):
        await consumer.connect()
        await H.settle(consumer)
    must(not console.closed and not probe.closed, (console.closed, probe.closed))
    return console, probe, sid, clock


async def held_probe_session(clock=None):
    """A session whose probe has taken its attach marker but is held before accept and group_add. Returns (console, probe, sid, gate, task)."""
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    gate, original = asyncio.Event(), probe.accept

    async def held_accept():
        await gate.wait()
        await original()

    probe.accept = held_accept
    task = asyncio.ensure_future(probe.connect())
    for _ in range(2000):  # until the probe has taken its attach marker (it then waits at accept)
        if tun.side_attached(sid, "probe"):
            break
        await asyncio.sleep(0.001)
    must(tun.side_attached(sid, "probe") and not probe.accepted, "the probe holds the attach marker and is not in the group")
    must(not tun.side_attached(sid, tun.SIDE_PROBE_READY), "and has not written the ready marker")
    await console.connect()
    await H.settle(console)
    return console, probe, sid, gate, task


# ---------------------------------------------------------------- (a) the race: the attach marker is there, the probe is not in the group
async def case_race():
    console, probe, sid, gate, task = await held_probe_session()
    must(console.accepted and not console.closed and console._paired is False, "the Console is not paired: the probe is not in the group")
    sent = [frame(OPEN, 1), frame(DATA, 1, b"first" * 10)]
    for data in sent:
        await console.receive(bytes_data=data)
    must(probe.out_bytes == [] and console._buffered == sum(len(d) for d in sent), "the first frames are held")
    gate.set()
    await task
    await H.settle(probe)
    must(probe.out_bytes == sent, "the probe received the frames byte for byte, in order, none lost")
    must(console._paired and console._buffered == 0 and tun.side_attached(sid, tun.SIDE_PROBE_READY), "paired once the probe was in the group")
    more = [frame(DATA, 1, bytes([n]) * 100) for n in range(5)]
    for data in more:
        await console.receive(bytes_data=data)
    must(probe.out_bytes == sent + more, "later frames are not lost")


run(case_race())


# ---------------------------------------------------------------- (b) the same under load: 10 MiB of 32 KiB frames echoed
async def case_load():
    console, probe, _sid, gate, task = await held_probe_session()
    sent = [frame(OPEN, 1)] + [frame(DATA, 1, bytes([n % 251]) * 32768) for n in range(320)]
    held = sent[:5]  # DATA straight after OPEN, held (well under the 1 MiB buffer)
    for data in held:
        await console.receive(bytes_data=data)
    gate.set()
    await task
    await H.settle(probe)
    for data in sent[5:]:
        await console.receive(bytes_data=data)
    must(probe.out_bytes == sent, "every frame arrived byte for byte, in order, after a race at the start")
    for data in probe.out_bytes:
        await probe.receive(bytes_data=data)
    must(console.out_bytes == sent, "the echo came back byte for byte")
    must(console.bytes_up == 320 * 32768 == 10 * 1024 * 1024 and console.bytes_down == console.bytes_up, (console.bytes_up, console.bytes_down))


run(case_load())


# ---------------------------------------------------------------- (c) a frame that arrives during the drain goes after the earlier ones
async def case_drain_order():
    fresh()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=Clock())
    await console.connect()
    await H.settle(console)
    first, second, late, later = frame(OPEN, 1), frame(DATA, 1, b"b" * 10), frame(DATA, 1, b"late"), frame(DATA, 1, b"later")
    for data in (first, second):
        await console.receive(bytes_data=data)
    seen, started, release = [], asyncio.Event(), asyncio.Event()

    async def slow_forward(data):
        started.set()
        await release.wait()
        seen.append(bytes(data))
        return True

    console._forward = slow_forward
    drain = asyncio.ensure_future(console._complete_pairing())
    await started.wait()
    must(not console._paired and console._pairing, "the drain is running and the Console is not paired yet")
    await console.receive(bytes_data=late)  # arrives during the drain
    again = asyncio.ensure_future(console._complete_pairing())  # a second trigger (a connect-time look, a tick) does not start a second drain
    await asyncio.sleep(0)
    await again
    must(seen == [], "no second drain ran")
    release.set()
    await drain
    must(seen == [first, second, late], seen)
    must(console._paired and console._buffered == 0 and console._buffer == [], "paired only when the buffer was empty")
    await console.receive(bytes_data=later)
    must(seen[-1] == later and len(seen) == 4, "direct forwarding after the drain")


run(case_drain_order())


# ---------------------------------------------------------------- (d) the buffer cap and the 15 second wait still end the session
async def case_limits():
    # the attach marker alone does not pair: it is not the probe being in the group
    fresh()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=Clock())
    must(tun._attach(sid, "probe"), "attach marker taken")
    await console.connect()
    await H.settle(console)
    must(not console._paired, "an attach marker without the ready marker is not pairing")
    chunk = frame(DATA, 1, b"x" * 32768)
    for _ in range(tun.BUFFER_CAP_BYTES // len(chunk)):
        await console.receive(bytes_data=chunk)
    must(not console.closed, "the cap is not reached yet")
    await console.receive(bytes_data=chunk)
    must(console.closed == [1000] and console.close_reasons == ["probe_offline"] and ended_reason(sid) == "probe_offline", (console.closed, console.close_reasons))
    # no probe in the group within 15 seconds
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=clock)
    tun._attach(sid, "probe")
    await console.connect()
    await H.settle(console)
    clock.now += tun.PAIR_WAIT_SECONDS - 1
    must(await console._tick() is True, "still waiting at 14 seconds")
    clock.now += 1
    must(await console._tick() is False and console.close_reasons == ["probe_offline"] and ended_reason(sid) == "probe_offline", console.close_reasons)


run(case_limits())


# ---------------------------------------------------------------- (e) a lost tunnel.paired is recovered by the watcher through the ready marker
async def case_lost_paired():
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=clock)
    await console.connect()
    await H.settle(console)
    sent = [frame(OPEN, 1), frame(DATA, 1, b"abc")]
    for data in sent:
        await console.receive(bytes_data=data)

    async def lost(event):
        return None

    console.tunnel_paired = lost  # the message never reaches the Console
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    must(tun.side_attached(sid, tun.SIDE_PROBE_READY) and not console._paired and probe.out_bytes == [], "the ready marker is set but the Console missed tunnel.paired")
    clock.now += tun.WATCH_TICK_SECONDS
    must(await console._tick() is True and console._paired, "the next tick pairs through the ready marker")
    must(probe.out_bytes == sent, "the held frames were delivered in order")
    must(ended_reason(sid) is None, "and nothing ended")
    # a failed cache look at connect is recovered the same way
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=clock)
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    real = tun.side_attached
    calls = {"n": 0}

    def flaky(session_id, side):
        if side == tun.SIDE_PROBE_READY and calls["n"] == 0:
            calls["n"] += 1
            raise ConnectionError("cache blip")
        return real(session_id, side)

    tun.side_attached = flaky
    try:
        await console.connect()
        await H.settle(console)
        must(not console._paired, "the look at connect failed: not paired yet")
        clock.now += tun.WATCH_TICK_SECONDS
        must(await console._tick() is True and console._paired, "the watcher pairs on the next tick")
    finally:
        tun.side_attached = real


run(case_lost_paired())


# ---------------------------------------------------------------- (f) both connect orders pair at once
async def case_orders():
    for probe_first in (True, False):
        console, probe, sid, _ = await pair(probe_first=probe_first)
        must(console._paired, f"paired (probe_first={probe_first})")
        sent = [frame(OPEN, 1), frame(DATA, 1, b"z")]
        for data in sent:
            await console.receive(bytes_data=data)
        must(probe.out_bytes == sent, "frames reach the probe")
    state = tun.poll_session(sid)
    must(state["ready"] is True and state["probe"] is True and state["console"] is True and state["ended"] is None, state)


run(case_orders())


# ---------------------------------------------------------------- (g) the Console never decides pairing from the attach marker
def case_source():
    text = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
    console_part = text[text.index("class ProbeTunnelConsoleConsumer"):]
    for call in re.findall(r"side_attached\([^)]*\)", console_part):
        must('"probe"' not in call and "'probe'" not in call, "the Console must not read the probe attach marker: " + call)
    must(console_part.count("SIDE_PROBE_READY") == 2, "the Console reads the ready marker at connect and in its watcher")
    probe_part = text[text.index("class ProbeTunnelProbeConsumer"):text.index("class ProbeTunnelConsoleConsumer")]
    must(probe_part.index("group_add") < probe_part.index("mark_probe_ready") < probe_part.index('"type": "tunnel.paired"'),
         "the probe marks itself ready after group_add and before tunnel.paired")
    must("data[0]" in text and set(re.findall(r"data\[[^\]]*\]", text)) == {"data[0]"}, "Core still reads only byte 0")


case_source()


# ---------------------------------------------------------------- activity: only the engineer's own DATA reaches the sign-in
async def case_activity():
    # (1) six minutes in which only the probe sends DATA: no activity reaches the sign-in, the tunnel's own clock and bytes_down still move
    console, probe, _sid, clock = await pair()
    before = len(H.SIGNIN["calls"])
    for _ in range(6):
        clock.now += 60
        WALL[0] += 60
        await probe.receive(bytes_data=frame(DATA, 1, b"out" * 10))
        must(await console._tick() is True, "the session is alive")
    must(len(H.SIGNIN["calls"]) > before, "the 5-minute re-check ran")
    must(H.SIGNIN["calls"][-1][1] is None, "no activity was passed for output from the target")
    must(console.bytes_down == 6 * 30 and console.bytes_up == 0, (console.bytes_down, console.bytes_up))
    must(console._clock() - console._last_data < 1, "the tunnel's own idle timer was reset by the probe's DATA")
    # (2) one DATA frame from the engineer: the next re-check passes that frame's wall time, once
    stamp = WALL[0] + 7
    WALL[0] = stamp
    await console.receive(bytes_data=frame(DATA, 1, b"typed"))
    clock.now += 301
    WALL[0] += 301
    await probe.receive(bytes_data=frame(DATA, 1, b"echo"))  # later probe output must not move the passed time
    must(await console._tick() is True, "re-check passes")
    passed = H.SIGNIN["calls"][-1][1]
    must(passed is not None and passed.timestamp() == stamp, (passed, stamp))
    clock.now += 301
    WALL[0] += 301
    await probe.receive(bytes_data=frame(DATA, 1, b"more"))
    must(await console._tick() is True and H.SIGNIN["calls"][-1][1] is None, "and only once")
    # (3) ACK, OPEN and CLOSE from the Console pass no activity
    console, probe, _sid, clock = await pair()
    for data in (frame(OPEN, 1), frame(ACK, 1, b"\x00\x00\x00\x01"), frame(CLOSE, 1, b"\x00")):
        await console.receive(bytes_data=data)
    clock.now += 301
    must(await console._tick() is True and H.SIGNIN["calls"][-1][1] is None, "ACK-only Console traffic passes no activity")


run(case_activity())


async def case_idle_limit():
    """A model of the sign-in idle rule (AD-35) behind session_refusal: it refuses after 900 s without activity."""
    module = sys.modules["tec_tac.tactical_websocket"]
    original, state, idle = module.session_refusal, {}, 900

    def model(value, activity_at=None):
        H.SIGNIN["calls"].append((dict(value), activity_at))
        state.setdefault("last", WALL[0])
        if activity_at is not None:
            state["last"] = max(state["last"], activity_at.timestamp())
        return "session_idle" if WALL[0] - state["last"] > idle else None

    module.session_refusal = model
    try:
        # a streaming target and a silent engineer: the sign-in idles out although the tunnel is busy
        state.clear()
        console, probe, sid, clock = await pair()
        ended = None
        for step in range(1, 60):
            clock.now += 60
            WALL[0] += 60
            await probe.receive(bytes_data=frame(DATA, 1, b"stream"))
            if not await console._tick():
                ended = step * 60
                break
        must(ended is not None and ended <= 1300, ended)
        marker = CACHE.data[tun.end_key(sid)]
        must(marker["reason"] == "ended_by_core" and marker["detail"] == "session_idle", marker)
        must(console.close_reasons[-1] == "ended_by_core" and probe.close_reasons[-1] == "ended_by_core", "both sides closed")
        # the engineer's own input keeps the sign-in alive well past that point
        state.clear()
        console, probe, sid, clock = await pair()
        for _ in range(40):
            clock.now += 60
            WALL[0] += 60
            await console.receive(bytes_data=frame(DATA, 1, b"k"))
            must(await console._tick() is True, "the engineer is typing: the session stays")
    finally:
        module.session_refusal = original


run(case_idle_limit())
print("PASS probe tunnel pairing and activity 1.18.48")
