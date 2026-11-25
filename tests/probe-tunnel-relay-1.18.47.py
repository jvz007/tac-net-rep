#!/usr/bin/env python3
"""1.18.47 regression (C2b): the two tunnel data routes and the relay, driven on an in-memory channel layer
(tests/probe_transport_harness.py). The real probe_tunnel.py and probe_tunnel_consumer.py run.

Covered: two scripted clients echo 10 MiB both ways in 32 KiB frames byte for byte; wrong schemes in both directions give 4401 and never reach
the authenticator; a reused or expired ticket 4401; a session of another probe, an unknown session, a missing session header 4404; an already
attached side 4409; plaintext 4403; a text frame, an unknown type byte, a short frame and a 32 KiB + 1 payload give 1002; only DATA resets
the idle timer and counts bytes; idle_timeout, hard_cap, console_disconnected, probe_offline, console_not_connected and relay_overloaded close
both sides with the reason as close text; the 1 MiB buffer before pairing; the account re-check at connect and every 5 minutes; a source scan
shows no logger or audit call touches frame bytes; pool-full and fault paths close 1013 or 4503 and count nothing; the routes install once.
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, LAYER, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.LAYER, H.run
frame, Clock = H.frame, H.Clock
OPEN, DATA, ACK, CLOSE = 1, 2, 3, 4

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.probe_transport").addHandler(_Capture())
logging.getLogger("tec_tac.probe_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.probe_transport").propagate = False
MARKER = b"PLANTED-MARKER-1f6c0e"


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.add_probe(H.PROBE2, H.KEY2, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


async def pair(idle_s=900, cap_s=14400, probe_first=False, clock=None):
    """A Console and a probe side attached to one session. Returns (console, probe, session_id, clock)."""
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
    must(not console.closed and not probe.closed and console.accepted and probe.accepted, (console.closed, probe.closed))
    return console, probe, sid, clock


async def refused(consumer, code, text=None):
    await consumer.connect()
    await H.settle(consumer)
    must(consumer.accepted and consumer.closed == [code], (consumer.closed, consumer.close_reasons))
    if text is not None:
        must(consumer.close_reasons == [text], consumer.close_reasons)


def ended_reason(sid):
    marker = CACHE.data.get(tun.end_key(sid))
    return marker["reason"] if marker else None


# ---------------------------------------------------------------- 10 MiB echo both ways, byte for byte
async def case_echo():
    console, probe, sid, _ = await pair()
    must(console._paired, "paired at connect (the probe attached after the Console)")
    sent = [frame(OPEN, 1)] + [frame(DATA, 1, bytes([n % 251]) * 32768) for n in range(320)]
    for data in sent:
        await console.receive(bytes_data=data)
    must(probe.out_bytes == sent, "the probe received every frame byte for byte, in order")
    for data in probe.out_bytes:  # the probe echoes
        await probe.receive(bytes_data=data)
    must(console.out_bytes == sent, "the Console received the echo byte for byte")
    must(sum(len(d) for d in sent if d[0] == DATA) - 320 * 5 == 320 * 32768 == 10 * 1024 * 1024, "ten MiB")
    must(console.bytes_up == 320 * 32768 and console.bytes_down == 320 * 32768, (console.bytes_up, console.bytes_down))
    must(console.out == [] and probe.out == [], "no text frame was ever sent")
    # the Console's counters reach the cache record at the next flush
    clock = console._clock
    clock.now += tun.FLUSH_SECONDS
    must(await console._tick() is True, "tick")
    stats = tun.read_stats(sid)
    must(stats["bytes_up"] == 320 * 32768 and stats["bytes_down"] == 320 * 32768 and stats["last_data"] is not None, stats)
    must(pt.tunnel_status("networkprobe", [sid])["sessions"][sid]["state"] == "open", "open once the Console is attached")


run(case_echo())


# ---------------------------------------------------------------- buffer before the probe attaches
async def case_buffer():
    fresh()
    sid = H.new_session_id()
    ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
    console = H.make_console(ticket, clock=Clock())
    await console.connect()
    await H.settle(console)
    must(not console._paired, "the probe is not attached yet")
    sent = [frame(OPEN, 1), frame(DATA, 1, b"a" * 100), frame(DATA, 1, b"b" * 200)]
    for data in sent:
        await console.receive(bytes_data=data)
    must(console._buffered == sum(len(d) for d in sent) and not any(m.get("type") == "tunnel.frame" for _, m in LAYER.direct), "held, not sent")
    probe = H.make_tunnel_probe(sid, clock=console._clock)
    await probe.connect()
    await H.settle(probe)
    must(probe.out_bytes == sent and console._paired and console._buffered == 0, "flushed in order on pairing")
    await console.receive(bytes_data=frame(DATA, 1, b"c"))
    must(probe.out_bytes[-1] == frame(DATA, 1, b"c"), "frames flow after pairing")
    # over the 1 MiB cap: the session ends probe_offline
    fresh()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=Clock())
    await console.connect()
    await H.settle(console)
    chunk = frame(DATA, 1, b"x" * 32768)
    for _ in range(tun.BUFFER_CAP_BYTES // len(chunk)):
        await console.receive(bytes_data=chunk)
    must(not console.closed, "the cap is not reached yet")
    await console.receive(bytes_data=chunk)
    must(console.closed == [1000] and console.close_reasons == ["probe_offline"] and ended_reason(sid) == "probe_offline", (console.closed, console.close_reasons))
    # no probe side within 15 seconds of the Console connecting
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    console = H.make_console(H.issue(H.tunnel_spec(session_id=sid))["ticket"], clock=clock)
    await console.connect()
    await H.settle(console)
    clock.now += tun.PAIR_WAIT_SECONDS - 1
    must(await console._tick() is True, "still waiting at 14 seconds")
    clock.now += 1
    must(await console._tick() is False and console.close_reasons == ["probe_offline"], console.close_reasons)


run(case_buffer())


# ---------------------------------------------------------------- credentials: wrong schemes, tickets, sessions
async def case_connect_refusals():
    fresh()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    ticket = got["ticket"]
    for scheme_header in (f"Probe {H.PROBE}.{H.KEY}", "Token " + "a" * 40):
        c = H.make_console(ticket, headers=[(b"authorization", scheme_header.encode())])
        await refused(c, 4401, "wrong_scheme")
    must(H.AUTH["calls"] == [], "no credential of another scheme reached the authenticator")
    for headers in ([], [(b"authorization", b"Ticket short")], [(b"authorization", b"Ticket " + b"a" * 43), (b"authorization", b"Ticket " + b"a" * 43)]):
        await refused(H.make_console(ticket, headers=headers), 4401, "malformed_header")
    must(CACHE.data.get(tun.ticket_key(ticket)) is not None, "refused headers did not burn the ticket")
    for scheme in ("Ticket", "Token"):
        p = H.make_tunnel_probe(sid, headers=H.headers_for(scheme=scheme, probe_id="x", key=ticket if scheme == "Ticket" else "a" * 40, extra=[(b"x-tunnel-session", sid.encode())]))
        await refused(p, 4401, "wrong_scheme")
    must(H.AUTH["calls"] == [], "a Ticket or Token header never reached the authenticator")
    must(CACHE.data.get(tun.ticket_key(ticket)) is not None, "a ticket sent to the probe route was not redeemed")
    # a plaintext connection
    plain = [(b"x-forwarded-proto", b"http")]
    await refused(H.make_console(ticket, headers=H.ticket_headers(ticket, extra=plain)), 4403, "plaintext_refused")
    await refused(H.make_tunnel_probe(sid, headers=H.headers_for(extra=plain + [(b"x-tunnel-session", sid.encode())])), 4403, "plaintext_refused")
    must(CACHE.data.get(tun.ticket_key(ticket)) is not None, "plaintext did not redeem the ticket")
    # no owner: 4503 for both, counting nothing
    pt.clear_owner_for_tests()
    await refused(H.make_console(ticket), 4503)
    await refused(H.make_tunnel_probe(sid), 4503)
    H.set_owner()
    # a good connect, then reuse
    console = H.make_console(ticket, clock=Clock())
    await console.connect()
    await H.settle(console)
    must(console.accepted and not console.closed, "the ticket works once")
    await refused(H.make_console(ticket, channel="specific.c2"), 4401, "ticket_invalid")
    # an expired ticket
    sid2 = H.new_session_id()
    ticket2 = H.issue(H.tunnel_spec(session_id=sid2))["ticket"]
    WALL[0] += 61
    await refused(H.make_console(ticket2), 4401, "ticket_invalid")
    # the audit rows carry no ticket or key
    blob = repr(AUDITS) + "\n".join(LOGS)
    for secret in (ticket, ticket2, H.KEY, "a" * 40):
        must(secret not in blob, "a secret leaked into a row or a log record")


run(case_connect_refusals())


async def case_probe_side_refusals():
    fresh()
    sid = H.new_session_id()
    H.issue(H.tunnel_spec(session_id=sid))
    # another probe's session
    await refused(H.make_tunnel_probe(sid, probe_id=H.PROBE2, key=H.KEY2), 4404, "session_not_pending")
    # an unknown session, a missing header, a malformed header
    await refused(H.make_tunnel_probe(H.new_session_id()), 4404, "session_not_pending")
    await refused(H.make_tunnel_probe(sid, headers=H.headers_for()), 4404, "session_header_invalid")
    await refused(H.make_tunnel_probe(sid, headers=H.headers_for(extra=[(b"x-tunnel-session", b"not-a-uuid")])), 4404, "session_header_invalid")
    must(not [k for k in CACHE.data if k.startswith((pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX))], "a 4404 is not an identity failure and counts nothing")
    # a bad key goes through the same counters as the control route
    for n in range(3):
        await refused(H.make_tunnel_probe(sid, key="z" * 32), 4401, "probe_key_invalid")
    must(CACHE.data[pt._failure_key("203.0.113.9")] == 3 and CACHE.data[pt._probe_failure_key(H.PROBE)] == 3, "counted against the shared address and probe-id counters")
    for n in range(7):
        await refused(H.make_tunnel_probe(sid, key="z" * 32), 4401)
    await refused(H.make_tunnel_probe(sid), 4429, "rate_limited")  # the 11th failure from one address
    CACHE.data.clear()
    pt.set_presence(H.PROBE, "x", "o", 3, 7)
    # the right probe: attached once; a second probe side closes 4409
    H.issue(H.tunnel_spec(session_id=(sid := H.new_session_id())))
    first = H.make_tunnel_probe(sid, channel="specific.p1")
    await first.connect()
    must(first.accepted and not first.closed, "the probe side attaches")
    await refused(H.make_tunnel_probe(sid, channel="specific.p2"), 4409, "probe_side_already_attached")
    must(not first.closed, "the first side is untouched by the refused second one")
    # a Console side already attached: the ticket is valid but the side is taken
    sid = H.new_session_id()
    ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
    must(tun._attach(sid, "console"), "attach")
    await refused(H.make_console(ticket), 4409, "console_already_attached")
    # an ended session is no longer pending, for either side
    sid = H.new_session_id()
    ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
    pt.end_tunnel("networkprobe", sid, "engineer")
    await refused(H.make_console(ticket), 4404, "session_not_pending")
    await refused(H.make_tunnel_probe(sid), 4404, "session_not_pending")


run(case_probe_side_refusals())


# ---------------------------------------------------------------- protocol errors
async def case_protocol():
    bad = {
        "unknown type 0": frame(0, 1, b"x"), "unknown type 5": frame(5, 1, b"x"), "unknown type 255": frame(255, 1),
        "short frame": b"\x02\x00\x00\x00", "empty": b"", "oversize": frame(DATA, 1, b"x" * (32768 + 1)),
    }
    for sender in ("console", "probe"):
        for label, data in bad.items():
            console, probe, sid, _ = await pair()
            who = console if sender == "console" else probe
            await who.receive(bytes_data=data)
            await H.settle(console)
            await H.settle(probe)
            must(console.closed[-1] == 1002 and probe.closed[-1] == 1002, (sender, label, console.closed, probe.closed))
            must(console.close_reasons[-1] == "protocol_error" and probe.close_reasons[-1] == "protocol_error", (sender, label))
            must(ended_reason(sid) == "protocol_error", (sender, label))
        console, probe, sid, _ = await pair()
        who = console if sender == "console" else probe
        await who.receive(text_data="hello")
        must(console.closed[-1] == 1002 and probe.closed[-1] == 1002 and ended_reason(sid) == "protocol_error", (sender, "text frame"))
    # the largest legal frames pass
    console, probe, sid, _ = await pair()
    for data in (frame(OPEN, 1), frame(DATA, 1, b"x" * 32768), frame(ACK, 1, b"\x00\x00\x80\x00"), frame(CLOSE, 1, b"\x00"), b"\x03\x00\x00\x00\x00"):
        await console.receive(bytes_data=data)
    must(not console.closed and not probe.closed and len(probe.out_bytes) == 5, "legal frames pass")


run(case_protocol())


# ---------------------------------------------------------------- idle and bytes: only DATA counts
async def case_idle():
    console, probe, sid, clock = await pair()
    for _ in range(5):  # 4000 seconds of OPEN, ACK and CLOSE only never reset the timer
        pass
    clock.now += 800
    for data in (frame(OPEN, 1), frame(ACK, 1, b"\x00\x00\x00\x01"), frame(CLOSE, 1, b"\x00")):
        await console.receive(bytes_data=data)
    await probe.receive(bytes_data=frame(ACK, 1, b"\x00\x00\x00\x01"))
    must(console.bytes_up == 0 and console.bytes_down == 0, "ACK, OPEN and CLOSE add no bytes")
    clock.now += 100
    must(await console._tick() is False and console.close_reasons[-1] == "idle_timeout", console.close_reasons)
    must(probe.close_reasons[-1] == "idle_timeout" and ended_reason(sid) == "idle_timeout", "both sides closed")
    # DATA in either direction resets the timer and counts payload bytes only (the 5 byte header is not counted)
    console, probe, sid, clock = await pair()
    clock.now += 800
    await console.receive(bytes_data=frame(DATA, 1, b"q" * 7))
    must(console.bytes_up == 7 and console.bytes_down == 0, (console.bytes_up, console.bytes_down))
    clock.now += 800
    must(await console._tick() is True, "DATA from the Console reset the timer")
    await probe.receive(bytes_data=frame(DATA, 1, b"r" * 11))
    must(console.bytes_down == 11, "bytes_down counts the probe to Console direction")
    clock.now += 899
    must(await console._tick() is True, "DATA from the probe reset it too")
    clock.now += 1
    must(await console._tick() is False and ended_reason(sid) == "idle_timeout", "idle after idle_s with no DATA")
    # idle_s from the ticket
    console, probe, sid, clock = await pair(idle_s=60)
    clock.now += 60
    must(await console._tick() is False and console.close_reasons[-1] == "idle_timeout", "a 60 second idle limit")


run(case_idle())


async def case_ends():
    # hard cap, even with traffic
    console, probe, sid, clock = await pair(cap_s=120)
    for _ in range(3):
        clock.now += 40
        await console.receive(bytes_data=frame(DATA, 1, b"x"))
        ok = await console._tick()
    must(ok is False and console.close_reasons[-1] == "hard_cap" and probe.close_reasons[-1] == "hard_cap" and ended_reason(sid) == "hard_cap", console.close_reasons)
    # the Console drops: no resume
    console, probe, sid, _ = await pair()
    await console.disconnect(1006)
    await H.settle(console)
    must(ended_reason(sid) == "console_disconnected" and probe.close_reasons[-1] == "console_disconnected", (ended_reason(sid), probe.close_reasons))
    # the probe's data socket drops
    console, probe, sid, _ = await pair()
    await probe.disconnect(1006)
    must(ended_reason(sid) == "probe_offline" and console.close_reasons[-1] == "probe_offline", (ended_reason(sid), console.close_reasons))
    # the server shuts down
    console, probe, sid, _ = await pair()
    await console.disconnect(1012)
    must(ended_reason(sid) == "server_restart" and probe.closed[-1] == 1001 and probe.close_reasons[-1] == "server_restart", "server_restart")
    # the Console never came: the probe side waits the 60 second ticket window
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    H.issue(H.tunnel_spec(session_id=sid))
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    clock.now += 5
    WALL[0] += 59
    must(await probe._tick() is True, "still inside the ticket window")
    WALL[0] += 1
    must(await probe._tick() is False and probe.close_reasons[-1] == "console_not_connected" and ended_reason(sid) == "console_not_connected", probe.close_reasons)
    # a relay that cannot keep up: ChannelFull from send (1.18.49: frames go to the peer's channel), and a slow layer
    for problem in (H.ChannelFull(), asyncio.TimeoutError()):
        console, probe, sid, _ = await pair()
        LAYER.fail_send = lambda channel, message, problem=problem: problem if message.get("type") == "tunnel.frame" else None
        await console.receive(bytes_data=frame(DATA, 1, b"x"))
        LAYER.fail_send = None
        await H.settle(console)
        must(ended_reason(sid) == "relay_overloaded" and console.closed[-1] == 1013 and console.close_reasons[-1] == "relay_overloaded", (type(problem), console.closed))
        must(probe.close_reasons[-1] == "relay_overloaded", "both sides closed")
    # the first end wins: a later end changes nothing
    console, probe, sid, _ = await pair()
    await console._end("hard_cap")
    await probe._end("probe_offline")
    must(ended_reason(sid) == "hard_cap", "the first reason stands")


run(case_ends())


# ---------------------------------------------------------------- the account is checked at connect and every 5 minutes
async def case_account():
    for label, setup in (
        ("sign-in revoked", lambda: H.SIGNIN.update(refusal="session_revoked")),
        ("user disabled", lambda: H.SIGNIN.update(refusal="user_unavailable")),
        ("permission removed", lambda: H.PERMS.update(granted=False)),
        ("module disabled", lambda: H.REGISTRY.update(enabled=False)),
    ):
        fresh()
        sid = H.new_session_id()
        ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
        setup()
        c = H.make_console(ticket)
        await c.connect()
        await H.settle(c)
        must(c.accepted and c.closed == [4401], (label, c.closed))
        must(not tun.side_attached(sid, "console"), label + ": the side was not taken")
    # the re-check at 5 minutes ends the session ended_by_core
    for label, setup, detail in (
        ("sign-in revoked", lambda: H.SIGNIN.update(refusal="session_revoked"), "session_revoked"),
        ("user disabled", lambda: H.SIGNIN.update(refusal="user_unavailable"), "user_unavailable"),
        ("permission removed", lambda: H.PERMS.update(granted=False), "permission_missing"),
        ("module disabled", lambda: H.REGISTRY.update(enabled=False), "module_disabled"),
    ):
        console, probe, sid, clock = await pair()
        clock.now += 299
        must(await console._tick() is True, "not yet 5 minutes")
        clock.now += 2
        setup()
        must(await console._tick() is False, label)
        marker = CACHE.data[tun.end_key(sid)]
        must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == detail, (label, marker))
        must(console.close_reasons[-1] == "ended_by_core" and probe.close_reasons[-1] == "ended_by_core", label)
    # a passing re-check keeps the session; DATA since the last check is handed to the sign-in as activity, silence is not
    console, probe, sid, clock = await pair()
    clock.now += 301
    must(await console._tick() is True, "re-check passes")
    must(H.SIGNIN["calls"][-1][1] is None, "no DATA since connect: no activity time")
    await console.receive(bytes_data=frame(DATA, 1, b"x"))
    clock.now += 301
    must(await console._tick() is True and H.SIGNIN["calls"][-1][1] is not None, "DATA counts as activity for the sign-in rules")
    clock.now += 301
    must(await console._tick() is True and H.SIGNIN["calls"][-1][1] is None, "and only once")
    # the probe is gone: no presence and no data socket at the re-check
    console, probe, sid, clock = await pair()
    CACHE.data.pop(tun.side_key(sid, "probe"))
    CACHE.data.pop(pt.presence_key(H.PROBE))
    clock.now += 301
    must(await console._tick() is False and ended_reason(sid) == "probe_offline", "probe_offline at the re-check")
    # a persistent fault at the re-check fails closed after the grace
    console, probe, sid, clock = await pair()
    original = tun.console_recheck
    tun.console_recheck = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down"))
    clock.now += 301
    must(await console._tick() is True, "a transient fault keeps the socket")
    clock.now += tun.RECHECK_SECONDS + tun.RECHECK_JITTER_SECONDS + tun.RECHECK_GRACE_SECONDS
    await console.receive(bytes_data=frame(DATA, 1, b"x"))  # traffic keeps the idle timer from ending the session first
    must(await console._tick() is False and ended_reason(sid) == "ended_by_core" and CACHE.data[tun.end_key(sid)]["detail"] == "recheck_stale", "closed after the grace")
    tun.console_recheck = original
    # the probe side's identity is checked again at 5 minutes: a revoked probe ends the session
    console, probe, sid, clock = await pair()
    clock.now += 301
    H.PROBES[H.PROBE] = "probe_disabled"
    must(await probe._tick() is False and probe.closed[-1] == 4401 and ended_reason(sid) == "ended_by_core", (probe.closed, ended_reason(sid)))
    must(console.close_reasons[-1] == "ended_by_core", "the Console was told")


run(case_account())


# ---------------------------------------------------------------- pools, faults and the route
async def _collect(sent, message):
    sent.append(message)


async def case_faults():
    fresh()
    sid = H.new_session_id()
    ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
    for pool in ("auth", "cache"):
        reset_pool = pt._POOLS[pool]
        reset_pool.inflight = reset_pool.backlog
        for consumer in (H.make_console(ticket), H.make_tunnel_probe(sid)):
            await consumer.connect()
            must(consumer.closed == [1013], (pool, consumer.side, consumer.closed))
        reset_pool.inflight = 0
    must(not [k for k in CACHE.data if k.startswith((pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX))], "a busy pool counts nothing")
    must(CACHE.data.get(tun.ticket_key(ticket)) is not None, "a busy pool did not redeem the ticket")
    H.AUTH["mode"] = "fault"
    probe = H.make_tunnel_probe(sid)
    await probe.connect()
    must(probe.closed == [1013] and not [k for k in CACHE.data if k.startswith(pt.FAILURE_PREFIX)], "an owner fault closes 1013 and counts nothing")
    H.AUTH["mode"] = "normal"
    # no channel layer
    H.LAYER_ENABLED[0] = False
    c = H.make_console(ticket)
    await c.connect()
    must(c.closed == [4503] and CACHE.data.get(tun.ticket_key(ticket)) is not None, "no channel layer: 4503 and the ticket is kept")
    H.LAYER_ENABLED[0] = True
    # the consumer cannot be loaded: 4503 and Tactical goes on
    package = sys.modules["tec_tac"]
    saved = sys.modules.pop("tec_tac.probe_tunnel_consumer")
    saved_attr = package.__dict__.pop("probe_tunnel_consumer")
    sys.modules["tec_tac.probe_tunnel_consumer"] = None
    try:
        for side in ("probe", "console"):
            sent = []
            await tun._TunnelRoute(side)({"type": "websocket"}, None, lambda message, sent=sent: _collect(sent, message))
            must(sent == [{"type": "websocket.close", "code": 4503}], (side, sent))
    finally:
        sys.modules["tec_tac.probe_tunnel_consumer"] = saved
        package.probe_tunnel_consumer = saved_attr


run(case_faults())


def case_install():
    appended: list = []
    urls = SimpleNamespace(ws_urlpatterns=[])
    paths = SimpleNamespace(path=lambda pattern, view: SimpleNamespace(pattern=pattern, view=view))
    sys.modules["tacticalrmm"] = SimpleNamespace(urls=urls)
    sys.modules["tacticalrmm.urls"] = urls
    sys.modules["django.urls"] = paths
    must(tun.install_tunnel_probe_route() is True and tun.install_tunnel_probe_route() is False, "the probe route installs once")
    must(tun.install_tunnel_console_route() is True and tun.install_tunnel_console_route() is False, "the Console route installs once")
    patterns = [p.pattern for p in urls.ws_urlpatterns]
    must(patterns == ["ws/tfd/network-probe/tunnel/", "ws/tfd/probe-tunnel/"], patterns)
    must("ws/tfd/network-probe/" not in patterns, "the control route is not touched")
    appended.extend(patterns)
    must(tun.PROBE_SIDE_SOCKET_PATH == "/ws/tfd/network-probe/tunnel/" and tun.CONSOLE_SOCKET_PATH == "/ws/tfd/probe-tunnel/", "socket paths")


case_install()


# ---------------------------------------------------------------- no logger or audit call touches frame bytes
def scan_calls(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    forbidden = {"data", "bytes_data", "text_data", "event", "frame", "payload", "ticket", "key", "value", "headers", "scope"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = ast.unparse(func)
        if not (name.startswith("logger.") or name in ("self._throttled_log", "self._audit", "pt.record_probe_event", "_audit")):
            continue
        for arg in list(node.args) + [k.value for k in node.keywords]:
            names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(arg) if isinstance(n, ast.Attribute)}
            if isinstance(arg, ast.Constant):
                continue
            must(not (names & forbidden) or name == "pt.record_probe_event" and not (names & {"data", "bytes_data", "text_data", "payload", "ticket", "key"}),
                 f"{path}:{node.lineno} {name} touches {names & forbidden}")


for source in ("probe_tunnel_consumer.py", "probe_tunnel.py"):
    scan_calls(H.APP / source)
text = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
must("json" not in text and "decode(" not in text and "struct" not in text, "the relay parses nothing")
import re

indexes = re.findall(r"data\[[^\]]*\]", text)
must(indexes and set(indexes) == {"data[0]"} and len(indexes) == 4, ("only byte 0 is ever read", indexes))


# ---------------------------------------------------------------- planted marker bytes never appear anywhere
async def case_marker():
    console, probe, _sid, _clock = await pair()
    await console.receive(bytes_data=frame(DATA, 1, MARKER * 10))
    await probe.receive(bytes_data=frame(DATA, 1, MARKER * 10))
    await console.disconnect(1000)
    await H.settle(console)
    blob = (repr(AUDITS) + "\n".join(LOGS) + repr(CACHE.data) + repr(H.CELERY.sent)).encode()
    must(MARKER not in blob and MARKER.decode() not in repr(AUDITS), "traffic never reaches a row, a log, the cache or the owner")


run(case_marker())
print("PASS probe tunnel relay 1.18.47")
