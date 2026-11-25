#!/usr/bin/env python3
"""1.18.50 regression: the two held 1.18.49 findings, on the in-memory harness (tests/probe_transport_harness.py).

MEDIUM: the probe socket's hard-cap backstop counted from the ticket, so a Console that connected late in the 60 second ticket window could be
ended by the probe before its own cap. The backstop now counts from the Console's real start (poll_session returns console_at, the console side
marker), or from the end of the ticket window while that is unknown, plus the cap plus SLOT_GRACE_SECONDS. The Console's own cap fires first;
a dead Console worker is still ended by the probe.
LOW: the 2000 messages a second cap counted DATA and ACK alike. Control frames (OPEN, ACK, CLOSE) keep FRAMES_PER_SECOND_MAX (2000), DATA frames
get DATA_FRAMES_PER_SECOND_MAX (10000), counted apart in the same one-second window, in memory only. Over either bound the session ends
protocol_error with detail rate_control or rate_data.
"""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, LAYER, CELERY, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.LAYER, H.CELERY, H.run
frame, Clock = H.frame, H.Clock
OPEN, DATA, ACK, CLOSE = 1, 2, 3, 4
logging.getLogger("tec_tac.probe_transport").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.probe_transport").propagate = False


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def ended(sid):
    return CACHE.data.get(tun.end_key(sid))


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


def closed_events():
    return [(task, args) for task, args in CELERY.sent if args[1]["func"] == "tunnel.closed"]


async def start(cap_s=14400, idle_s=900, console_delay=0, connect_probe=True, clock=None):
    """Issue a ticket at the current WALL, wait console_delay seconds, then connect the Console and the probe side. Returns
    (console, probe, session_id, clock, created)."""
    fresh()
    clock = clock or Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid, cap_s=cap_s, idle_s=idle_s))
    must(got["outcome"] == "ok", got)
    created = WALL[0]
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    WALL[0] += console_delay
    consumers = (console, probe) if connect_probe else (probe,)
    for consumer in consumers:
        await consumer.connect()
        await H.settle(consumer)
    return console, probe, sid, clock, created


# ---------------------------------------------------------------- MEDIUM: the backstop counts from the Console's start
async def case_backstop():
    must(tun.SLOT_GRACE_SECONDS >= tun.WATCH_TICK_SECONDS + tun.FLUSH_SECONDS + 15, "the grace covers a tick, a flush and 15 seconds of slack")
    # the Console connects at created + 59, cap 60: the old rule fired the probe at created + 120, the Console's own cap is at created + 119
    console, probe, sid, clock, created = await start(cap_s=60, console_delay=59)
    must(tun.poll_session(sid)["console_at"] == created + 59, tun.poll_session(sid))
    await console.receive(bytes_data=frame(DATA, 1, b"x" * 100))
    await probe.receive(bytes_data=frame(DATA, 1, b"y" * 40))
    clock.now += 60
    WALL[0] = created + 60 + tun.SLOT_GRACE_SECONDS  # the old backstop time
    must(await probe._tick() is True and ended(sid) is None and not probe.closed, "the probe does not end it at created + cap + 60")
    must(await console._tick() is False and console.close_reasons[-1] == "hard_cap" and ended(sid)["reason"] == "hard_cap", "the Console's cap ends it")
    await console.disconnect(1000)
    await H.settle(console)
    await H.settle(probe)
    end_rows = rows("custom:probe-tunnel-end")
    must(len(end_rows) == 1 and end_rows[0]["metadata"]["reason"] == "hard_cap" and end_rows[0]["metadata"]["bytes_up"] == 100 and end_rows[0]["metadata"]["bytes_down"] == 40, end_rows)
    events = closed_events()
    must(len(events) == 1 and events[0][1][1]["payload"]["bytes_up"] == 100 and events[0][1][1]["payload"]["bytes_down"] == 40, events)
    must(await probe._tick() is False and len(rows("custom:probe-tunnel-end")) == 1 and len(closed_events()) == 1, "the probe finds nothing left to do")

    # a dead Console worker (it never ticks): the probe ends it at the Console's start + cap + grace, with the last flushed counters
    console, probe, sid, clock, created = await start(cap_s=60, console_delay=59)
    tun.flush_stats(sid, WALL[0], 123, 45)
    WALL[0] = created + 59 + 60 + tun.SLOT_GRACE_SECONDS - 1
    must(await probe._tick() is True and ended(sid) is None, "not yet")
    WALL[0] += 1
    must(await probe._tick() is False and probe.close_reasons[-1] == "hard_cap" and ended(sid)["reason"] == "hard_cap", probe.close_reasons)
    await H.settle(probe)
    end_rows = rows("custom:probe-tunnel-end")
    must(len(end_rows) == 1 and end_rows[0]["metadata"]["bytes_up"] == 123 and end_rows[0]["metadata"]["bytes_down"] == 45, end_rows)
    must(len(closed_events()) == 1, "one tunnel.closed")

    # the existing 1.18.49 case: created equals console_at
    console, probe, sid, clock, created = await start(cap_s=60)
    WALL[0] = created + 60 + tun.SLOT_GRACE_SECONDS - 1
    must(await probe._tick() is True and ended(sid) is None, "inside the cap plus the grace")
    WALL[0] += 1
    must(await probe._tick() is False and ended(sid)["reason"] == "hard_cap", "created equals console_at: the old time")

    # the poll fails: the end of the ticket window is the latest start, so the backstop is later still
    console, probe, sid, clock, created = await start(cap_s=60)
    original = tun.poll_session
    tun.poll_session = lambda session_id: (_ for _ in ()).throw(RuntimeError("cache down"))
    try:
        WALL[0] = created + 60 + tun.SLOT_GRACE_SECONDS
        must(await probe._tick() is True and ended(sid) is None, "no attach time read: no early end")
        WALL[0] = created + tun.TICKET_TTL_SECONDS + 60 + tun.SLOT_GRACE_SECONDS
        must(await probe._tick() is False and ended(sid)["reason"] == "hard_cap", "the fallback start is the end of the ticket window")
    finally:
        tun.poll_session = original

    # a Console that never connected: the cap backstop is not what ends it; the 60 second rule is
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    must(H.issue(H.tunnel_spec(session_id=sid, cap_s=60))["outcome"] == "ok", "ticket")
    created = WALL[0]
    probe_side = H.make_tunnel_probe(sid, clock=clock)
    await probe_side.connect()
    await H.settle(probe_side)
    must(tun.poll_session(sid)["console_at"] is None and tun.poll_session(sid)["console"] is False, "no Console")
    WALL[0] = created + tun.TICKET_TTL_SECONDS - 1
    must(await probe_side._tick() is True and ended(sid) is None, "inside the ticket window")
    WALL[0] = created + tun.TICKET_TTL_SECONDS
    must(await probe_side._tick() is False and ended(sid)["reason"] == "console_not_connected", "the Console never came: console_not_connected, not hard_cap")


run(case_backstop())


# ---------------------------------------------------------------- LOW: control frames and DATA frames are counted apart
async def pair_ready(clock=None):
    console, probe, sid, clock, _ = await start(clock=clock)
    must(not console.closed and not probe.closed, "paired")
    return console, probe, sid, clock


CACHE_CALLS = ("get", "set", "add", "touch", "incr", "delete", "get_many")
calls = {"n": 0}


def counting(fn):
    def wrapped(*a, **k):
        calls["n"] += 1
        return fn(*a, **k)

    return wrapped


async def case_rates():
    control, data_limit = tun.FRAMES_PER_SECOND_MAX, tun.DATA_FRAMES_PER_SECOND_MAX
    must(control == 2000 and data_limit == 10000 and (tun.RATE_CONTROL, tun.RATE_DATA) == ("rate_control", "rate_data"), "the figures")
    ack = frame(ACK, 1, b"\x00\x00\x00\x01")
    dat = frame(DATA, 1, b"x")
    for sender in ("console", "probe"):
        # 2000 ACKs pass, the 2001st ends protocol_error with detail rate_control
        console, probe, sid, clock = await pair_ready()
        me, other = (console, probe) if sender == "console" else (probe, console)
        for _ in range(control):
            await me.receive(bytes_data=ack)
        must(not me.closed and ended(sid) is None, f"{control} ACKs pass on the {sender} side")
        await me.receive(bytes_data=ack)
        await H.settle(me)
        must(me.closed[-1] == 1002 and me.close_reasons[-1] == "protocol_error" and ended(sid)["reason"] == "protocol_error", (me.closed, me.close_reasons))
        must(ended(sid)["detail"] == "rate_control" and ended(sid)["ended_by"] == "core", ended(sid))
        must(other.close_reasons[-1] == "protocol_error", "the peer was closed with the reason")
        await console.disconnect(1006)
        await H.settle(console)
        must(rows("custom:probe-tunnel-end")[-1]["metadata"]["detail"] == "rate_control", "the end row says which bound")

        # 10000 DATA frames pass, no cache call is made by the check, the 10001st ends with detail rate_data
        console, probe, sid, clock = await pair_ready()
        me, other = (console, probe) if sender == "console" else (probe, console)
        calls["n"] = 0
        originals = {n: getattr(CACHE, n) for n in CACHE_CALLS}
        for n in CACHE_CALLS:
            setattr(CACHE, n, counting(originals[n]))
        try:
            for _ in range(data_limit):
                await me.receive(bytes_data=dat)
        finally:
            for n in CACHE_CALLS:
                delattr(CACHE, n)
        must(not me.closed and ended(sid) is None, f"{data_limit} DATA frames pass on the {sender} side")
        must(calls["n"] == 0, "the rate check touched no cache call")
        must(len([1 for c, m in LAYER.direct if c == other.channel_name and m.get("data") == dat]) == data_limit, "all of them were relayed")
        await me.receive(bytes_data=dat)
        await H.settle(me)
        must(me.closed[-1] == 1002 and ended(sid)["reason"] == "protocol_error" and ended(sid)["detail"] == "rate_data", ended(sid))
        await console.disconnect(1006)
        await H.settle(console)
        must(rows("custom:probe-tunnel-end")[-1]["metadata"]["detail"] == "rate_data", "the end row says rate_data")

        # the two are not one bucket: 5000 DATA and 1999 ACKs, and also 10000 DATA with 2000 ACKs, pass in one second
        for n_data, n_ack in ((5000, 1999), (data_limit, control)):
            console, probe, sid, clock = await pair_ready()
            me = console if sender == "console" else probe
            for _ in range(n_data):
                await me.receive(bytes_data=dat)
            for _ in range(n_ack):
                await me.receive(bytes_data=ack)
            must(not me.closed and ended(sid) is None, (sender, n_data, n_ack))
        # a full second later the window is clean again
        clock.now += 1.0
        for _ in range(data_limit):
            await me.receive(bytes_data=dat)
        for _ in range(control):
            await me.receive(bytes_data=ack)
        must(not me.closed and ended(sid) is None, "a new second, a new window")

        # a text frame, an empty or short message, an oversize one and an unknown type still end protocol_error, with no rate detail
        for kwargs in ({"text_data": "hello"}, {"bytes_data": b""}, {"bytes_data": b"\x02\x00"}, {"bytes_data": frame(DATA, 1, b"x" * (32768 + 1))}, {"bytes_data": frame(9, 1)}):
            console, probe, sid, _ = await pair_ready()
            me = console if sender == "console" else probe
            await me.receive(**kwargs)
            must(me.closed[-1] == 1002 and ended(sid)["reason"] == "protocol_error" and ended(sid)["detail"] == "", (sender, list(kwargs), ended(sid)))


run(case_rates())

# ---------------------------------------------------------------- the source and the docs
consumer = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
accept = consumer[consumer.index("async def _accept_frame"):consumer.index("unpaired_reason")]
must(accept.index("_rate_exceeded(") < accept.index("check_frame"), "the rate is checked before the frame")
must(consumer.count("await self._accept_frame(bytes_data)") == 2, "both consumers start receive() with it")
doc = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
tunnel = doc[doc.index("## The tunnel (contract 1.1.0)"):]
for needle in ("`FRAMES_PER_SECOND_MAX`", "`DATA_FRAMES_PER_SECOND_MAX`", "10000", "2000", "rate_control", "rate_data", "Console's attach time", "SLOT_GRACE_SECONDS"):
    must(needle in tunnel, "the docs name " + needle)
meta = pt.probe_transport_contract_metadata()["tunnel"]["limits"]
must(meta["control_frames_per_second"] == 2000 and meta["data_frames_per_second"] == 10000, meta)
print("PASS probe tunnel limits 1.18.50")
