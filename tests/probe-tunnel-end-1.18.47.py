#!/usr/bin/env python3
"""1.18.47 regression (C2c): end_tunnel, end_tunnels_for_probe, tunnel_status, the tunnel.closed event and the audit rows.

Covered: End by engineer, admin and core closes both data sockets and the probe gets tunnel.close on its control channel; ending twice writes
one end row and delivers one tunnel.closed; an unknown session is invalid; end_tunnels_for_probe ends all and only that probe's sessions and
keeps a disconnect reason in the audit row; tunnel_status shows pending, open, ended and unknown with counters; tunnel.closed carries the Console
consumer's counters (zero when the Console never attached) and reaches the owner's task as (probe_id, frame) with source core; the 1.0.0
disconnect does not end tunnels; Core ends a refused probe's tunnels itself; audit rows carry the fields and no row, log record or exception text
holds a ticket, key, Authorization value or payload byte.
"""
from __future__ import annotations

import asyncio
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
DATA = 2

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.probe_transport").addHandler(_Capture())
logging.getLogger("tec_tac.probe_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.probe_transport").propagate = False
MARKER = b"PLANTED-MARKER-77aa"
SECRETS: list = []


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.add_probe(H.PROBE2, H.KEY2, 3, 7)
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


async def control(probe_id=H.PROBE, key=H.KEY, channel=None):
    c = H.make_consumer(H.headers_for(probe_id, key), channel=channel or f"specific.ctl-{probe_id}")
    await c.connect()
    await H.settle(c)
    must(c.accepted and not c.closed, "control channel up")
    return c


async def session(probe_id=H.PROBE, user=H.ENGINEER, console=True, probe_side=True, ctl=None):
    if pt.presence_key(probe_id) not in CACHE.data:
        H.probe_online(probe_id)
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid, probe_id=probe_id), H.engineer_request(user_id=user))
    must(got["outcome"] == "ok", got)
    SECRETS.append(got["ticket"])
    clock = Clock()
    c = p = None
    if console:
        c = H.make_console(got["ticket"], clock=clock, channel=f"specific.c-{sid[:8]}")
        await c.connect()
        await H.settle(c)
        must(c.accepted and not c.closed, "console up")
    if probe_side:
        p = H.make_tunnel_probe(sid, probe_id=probe_id, key=H.KEY if probe_id == H.PROBE else H.KEY2, clock=clock, channel=f"specific.p-{sid[:8]}")
        await p.connect()
        await H.settle(p)
        must(p.accepted and not p.closed, "probe side up")
    return sid, c, p, clock


def rows(action):
    return [a for a in AUDITS if a["action"] == action]


def closed_events():
    return [(task, args) for task, args in CELERY.sent if args[1]["func"] == "tunnel.closed"]


def tunnel_close_frames(ctl):
    import json

    return [f for f in (json.loads(x) for x in ctl.out) if f.get("func") == "tunnel.close"]


async def in_thread(func, *args):
    return await asyncio.to_thread(func, *args)


# ---------------------------------------------------------------- End by engineer, admin and core
async def case_end_each():
    for ended_by, reason in (("engineer", "ended_by_engineer"), ("admin", "ended_by_admin"), ("core", "ended_by_core")):
        fresh()
        ctl = await control()
        sid, console, probe, _ = await session()
        await console.receive(bytes_data=frame(DATA, 1, MARKER * 3))
        await probe.receive(bytes_data=frame(DATA, 1, MARKER * 3))
        result = await in_thread(pt.end_tunnel, "networkprobe", sid, ended_by)
        must(result == {"outcome": "ok", "session_id": sid, "already_ended": False, "reason": reason, "ended_by": ended_by}, result)
        must(console.closed[-1] == 1000 and console.close_reasons[-1] == reason and probe.close_reasons[-1] == reason, "both sockets closed at once with the reason")
        frames = tunnel_close_frames(ctl)
        must(len(frames) == 1 and frames[0]["type"] == "event" and frames[0]["payload"] == {"session_id": sid, "reason": reason, "ended_by": ended_by}, frames)
        must(pt.validate_frame(frames[0], allowed_types=("event",)) is None, "a frame the probe accepts")
        marker = CACHE.data[tun.end_key(sid)]
        must(marker["reason"] == reason and marker["ended_by"] == ended_by, marker)
        must(sid not in tun.read_index(), "the slot is free")
        # the Console consumer reports its final counters when its socket goes
        await console.disconnect(1000)
        await H.settle(console)
        events = closed_events()
        must(len(events) == 1, events)
        task, (probe_id, event) = events[0]
        must(task == "networkprobe.handle" and probe_id == H.PROBE, (task, probe_id))
        must(event["func"] == "tunnel.closed" and event["type"] == "event" and pt.validate_frame(event, allowed_types=("event",)) is None, event)
        must(event["payload"] == {"session_id": sid, "reason": reason, "ended_by": ended_by, "bytes_up": len(MARKER) * 3, "bytes_down": len(MARKER) * 3, "source": "core"}, event["payload"])
        end_rows = rows("custom:probe-tunnel-end")
        must(len(end_rows) == 1, end_rows)
        row = end_rows[0]
        must(row["probe_id"] == H.PROBE and row["metadata"]["reason"] == reason and row["metadata"]["ended_by"] == ended_by and row["metadata"]["session_id"] == sid
             and row["metadata"]["engineer"] == H.ENGINEER and "duration" in row["metadata"] and row["refusal"] is False, row)
        stats = tun.read_stats(sid)
        must(stats["bytes_up"] == len(MARKER) * 3 and row["metadata"]["bytes_up"] == stats["bytes_up"] and row["metadata"]["bytes_down"] == stats["bytes_down"], "counters in the row")
        must(len(rows("custom:probe-tunnel-connect")) == 2 and {r["metadata"]["side"] for r in rows("custom:probe-tunnel-connect")} == {"console", "probe"}, "connect rows")


run(case_end_each())


# ---------------------------------------------------------------- twice, unknown, invalid
async def case_twice_and_invalid():
    fresh()
    ctl = await control()
    sid, console, _probe, _ = await session()
    first = await in_thread(pt.end_tunnel, "networkprobe", sid, "engineer")
    second = await in_thread(pt.end_tunnel, "networkprobe", sid, "admin")
    must(first["already_ended"] is False and second["already_ended"] is True and second["reason"] == "ended_by_engineer" and second["ended_by"] == "engineer", (first, second))
    await console.disconnect(1000)
    await H.settle(console)
    await in_thread(pt.end_tunnel, "networkprobe", sid, "core")
    must(len(rows("custom:probe-tunnel-end")) == 1 and len(closed_events()) == 1 and len(tunnel_close_frames(ctl)) == 1, "one end row, one tunnel.closed, one tunnel.close")
    for args, label in (((H.new_session_id(), "engineer"), "unknown session"), (("not-a-uuid", "engineer"), "bad id"), ((sid, "nobody"), "bad ended_by"), ((None, "engineer"), "none")):
        must(pt.end_tunnel("networkprobe", *args) == {"outcome": "invalid"}, label)
    must(pt.end_tunnel("alerts", sid, "engineer") == {"outcome": "invalid"}, "module_id must be the verified caller")
    H.CALLER["module_id"] = "alerts"
    must(pt.end_tunnel("alerts", sid, "engineer") == {"outcome": "denied"}, "another module")
    must(pt.end_tunnels_for_probe("alerts", H.PROBE, "ended_by_core") == {"outcome": "denied", "ended": []}, "another module")
    must(pt.tunnel_status("alerts", [sid]) == {"outcome": "denied", "sessions": {}}, "another module")
    H.CALLER["module_id"] = None
    must(pt.end_tunnel("networkprobe", sid, "engineer") == {"outcome": "denied"}, "unverifiable")
    H.CALLER["module_id"] = "networkprobe"
    through = pt._PROVIDER.end_tunnel(module_id="networkprobe", session_id=sid, ended_by="engineer")
    must(through["already_ended"] is True, "through the provider")


run(case_twice_and_invalid())


# ---------------------------------------------------------------- all and only one probe's sessions
async def case_for_probe():
    fresh()
    ctl = await control()
    ctl2 = await control(H.PROBE2, H.KEY2)
    mine = [await session(user=H.ENGINEER) for _ in range(2)]
    other = await session(probe_id=H.PROBE2, user=H.ENGINEER)
    result = await in_thread(pt.end_tunnels_for_probe, "networkprobe", H.PROBE, "ended_by_core")
    must(result["outcome"] == "ok" and sorted(result["ended"]) == sorted(m[0] for m in mine), result)
    for sid, console, probe, _ in mine:
        must(console.close_reasons[-1] == "ended_by_core" and probe.close_reasons[-1] == "ended_by_core" and tun.get_end(sid)["reason"] == "ended_by_core", sid)
    must(not other[1].closed and not other[2].closed and tun.get_end(other[0]) is None, "the other probe's session is untouched")
    must(len(tunnel_close_frames(ctl)) == 2 and tunnel_close_frames(ctl2) == [], "only that probe is told")
    # a 1.0.0 disconnect reason ends ended_by_core and keeps the reason in the audit row
    sid2 = other[0]
    got = await in_thread(pt.end_tunnels_for_probe, "networkprobe", H.PROBE2, "revoked")
    must(got == {"outcome": "ok", "ended": [sid2]}, got)
    marker = tun.get_end(sid2)
    must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "revoked", marker)
    await other[1].disconnect(1000)  # an attached Console writes the end row at its close, with its final counters
    await H.settle(other[1])
    must(next(r for r in rows("custom:probe-tunnel-end") if r["metadata"].get("session_id") == sid2)["metadata"]["detail"] == "revoked", "reason kept in the audit row")
    for reason in ("probe_offline", "server_restart"):
        s, c, _, _ = await session()
        got = await in_thread(pt.end_tunnels_for_probe, "networkprobe", H.PROBE, reason)
        must(got["ended"] == [s] and tun.get_end(s)["reason"] == reason and c.close_reasons[-1] == reason, (reason, got))
    must(await in_thread(pt.end_tunnels_for_probe, "networkprobe", H.PROBE, "ended_by_core") == {"outcome": "ok", "ended": []}, "no live session")
    for args in ((H.PROBE, "idle_timeout"), ("bad id", "ended_by_core"), (H.PROBE, None), (None, "ended_by_core")):
        must(pt.end_tunnels_for_probe("networkprobe", *args) == {"outcome": "invalid", "ended": []}, args)
    # the 1.0.0 disconnect does not end tunnels by itself
    s, c, _p, _ = await session()
    must(pt.disconnect("networkprobe", H.PROBE, "disabled")["outcome"] in ("ok", "offline"), "disconnect")
    must(tun.get_end(s) is None and s in tun.read_index(), "disconnect() ends no tunnel; the owner calls end_tunnels_for_probe")


run(case_for_probe())


# ---------------------------------------------------------------- tunnel_status
async def case_status():
    fresh()
    await control()
    sid_pending = H.new_session_id()
    SECRETS.append(H.issue(H.tunnel_spec(session_id=sid_pending))["ticket"])
    sid_open, console, probe, clock = await session()
    await console.receive(bytes_data=frame(DATA, 1, b"abcd"))
    await probe.receive(bytes_data=frame(DATA, 1, b"xy"))
    clock.now += tun.FLUSH_SECONDS
    await console._tick()
    sid_end, _c2, _p2, _ = await session(user=H.ENGINEER)
    await in_thread(pt.end_tunnel, "networkprobe", sid_end, "admin")
    unknown = H.new_session_id()
    got = pt.tunnel_status("networkprobe", [sid_pending, sid_open, sid_end, unknown])
    must(got["outcome"] == "ok", got)
    rows_ = got["sessions"]
    must(rows_[sid_pending]["state"] == "pending" and rows_[sid_pending]["console_connected"] is False and rows_[sid_pending]["probe_id"] == H.PROBE, rows_[sid_pending])
    must(rows_[sid_open]["state"] == "open" and rows_[sid_open]["console_connected"] and rows_[sid_open]["probe_connected"] and rows_[sid_open]["bytes_up"] == 4
         and rows_[sid_open]["bytes_down"] == 2 and rows_[sid_open]["started"] and rows_[sid_open]["last_data"], rows_[sid_open])
    must(rows_[sid_end]["state"] == "ended" and rows_[sid_end]["reason"] == "ended_by_admin" and rows_[sid_end]["ended_by"] == "admin", rows_[sid_end])
    must(rows_[unknown]["state"] == "unknown" and rows_[unknown]["probe_id"] is None, rows_[unknown])
    for row in rows_.values():
        must(set(row) == {"state", "probe_id", "started", "last_data", "console_connected", "probe_connected", "bytes_up", "bytes_down", "reason", "ended_by"}, row)
    by_probe = pt.tunnel_status("networkprobe", probe_id=H.PROBE)
    must(by_probe["outcome"] == "ok" and set(by_probe["sessions"]) == {sid_pending, sid_open}, "live sessions of the probe")
    must(pt.tunnel_status("networkprobe", [])["sessions"] == {}, "an empty list")
    ids = [H.new_session_id() for _ in range(200)]
    must(pt.tunnel_status("networkprobe", ids)["outcome"] == "ok", "200 ids")
    must(pt.tunnel_status("networkprobe", ids + [H.new_session_id()]) == {"outcome": "invalid", "sessions": {}}, "201 ids")
    must(pt.tunnel_status("networkprobe") == {"outcome": "invalid", "sessions": {}} and pt.tunnel_status("networkprobe", ["x"]) == {"outcome": "invalid", "sessions": {}}, "bad arguments")
    must(pt.tunnel_status("networkprobe", ids[:1], H.PROBE)["outcome"] == "invalid" and pt.tunnel_status("networkprobe", probe_id="bad id")["outcome"] == "invalid", "both or a bad probe id")
    CACHE.down = True
    must(pt.tunnel_status("networkprobe", [sid_open])["outcome"] == "unavailable", "a cache fault")
    CACHE.down = False


run(case_status())


# ---------------------------------------------------------------- tunnel.closed when the Console never attached
async def case_never_attached():
    fresh()
    ctl = await control()
    sid, console, probe, _ = await session(console=False, probe_side=False)
    got = await in_thread(pt.end_tunnel, "networkprobe", sid, "engineer")
    must(got["outcome"] == "ok", got)
    events = closed_events()
    must(len(events) == 1 and events[0][1][1]["payload"]["bytes_up"] == 0 and events[0][1][1]["payload"]["bytes_down"] == 0 and events[0][1][1]["payload"]["source"] == "core", events)
    must(len(tunnel_close_frames(ctl)) == 1, "the probe is told")
    # a probe side that ends it (the Console never came) delivers it with zero counters
    fresh()
    ctl = await control()
    clock = Clock()
    sid = H.new_session_id()
    SECRETS.append(H.issue(H.tunnel_spec(session_id=sid))["ticket"])
    probe = H.make_tunnel_probe(sid, clock=clock)
    await probe.connect()
    await H.settle(probe)
    WALL[0] += 61
    clock.now += 5
    must(await probe._tick() is False, "console_not_connected")
    await H.settle(probe)
    events = closed_events()
    must(len(events) == 1 and events[0][1][1]["payload"]["reason"] == "console_not_connected" and events[0][1][1]["payload"]["ended_by"] == "core"
         and events[0][1][1]["payload"]["bytes_up"] == 0, events)
    must(len(rows("custom:probe-tunnel-end")) == 1 and len(tunnel_close_frames(ctl)) == 1, "one row, one tunnel.close")
    # an offline probe still has its data side closed and the session ends
    fresh()
    sid, console, probe, _ = await session()
    CACHE.data.pop(pt.presence_key(H.PROBE), None)
    got = await in_thread(pt.end_tunnel, "networkprobe", sid, "engineer")
    must(got["outcome"] == "ok" and console.close_reasons[-1] == "ended_by_engineer" and probe.close_reasons[-1] == "ended_by_engineer", "data side closed with no control channel")
    # a full handover pool or an owner fault: logged, and the session still ends
    fresh()
    sid, console, probe, _ = await session()
    CELERY.fail = True
    got = await in_thread(pt.end_tunnel, "networkprobe", sid, "engineer")
    await console.disconnect(1000)
    await H.settle(console)
    must(got["outcome"] == "ok" and tun.get_end(sid) is not None and console.closed[-1] == 1000, "the session ends although the owner could not be reached")
    CELERY.fail = False
    fresh()
    sid, console, probe, _ = await session()
    pool = pt._POOLS["handover"]
    pool.inflight = pool.backlog
    await console._end("hard_cap")
    await console.disconnect(1000)
    await H.settle(console)
    pool.inflight = 0
    must(tun.get_end(sid)["reason"] == "hard_cap" and probe.close_reasons[-1] == "hard_cap", "a full handover pool does not stop the end")


run(case_never_attached())


# ---------------------------------------------------------------- Core ends a refused probe's tunnels itself
async def case_refused_probe():
    fresh()
    clock = Clock()
    c = H.make_consumer(H.headers_for(), clock=clock, channel="specific.ctl-refuse")
    await c.connect()
    await H.settle(c)
    sid, console, probe, _ = await session()
    clock.now += 301
    H.PROBES[H.PROBE] = "probe_disabled"
    must(await c._tick() is False and c.closed[-1] == 4401, "the control channel refuses the probe at its re-check")
    marker = tun.get_end(sid)
    must(marker is not None and marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "probe_disabled", marker)
    must(console.close_reasons[-1] == "ended_by_core" and probe.close_reasons[-1] == "ended_by_core", "both data sockets closed")
    must(H.KEY not in repr(AUDITS), "the key is out of everything")


run(case_refused_probe())

# ---------------------------------------------------------------- the audit helper keeps only its own fields
captured: list = []
sys_audit = H.sys.modules["tec_tac.audit"]
sys_audit._record_probe_transport = lambda **kw: captured.append(kw)
pt.record_probe_event("custom:probe-tunnel-end", H.PROBE, reason="idle_timeout",
                      extra={"engineer": 5, "session_id": "s", "bytes_up": 10, "bytes_down": 0, "duration": 3, "ended_by": "core", "side": "console", "ticket": "SECRET", "key": "SECRET",
                             "payload": b"SECRET", "flag": True, "none": None, "target": "x" * 300})
meta = captured[-1]["metadata"]
must(set(meta) == {"reason", "engineer", "session_id", "bytes_up", "bytes_down", "duration", "ended_by", "side"}, meta)  # 1.18.49: no target key can reach a tunnel row
must("SECRET" not in repr(captured), "only the named fields reach a row")
pt.record_probe_event("custom:probe-connect", H.PROBE, ip="203.0.113.9")
must(captured[-1]["metadata"] == {"ip": "203.0.113.9"}, "no extra, no change")
sys_audit._record_probe_transport = lambda **kw: AUDITS.append(kw)

# ---------------------------------------------------------------- nothing secret anywhere
blob = repr(AUDITS) + " ".join(LOGS) + repr(CELERY.sent) + repr(CACHE.data)
for secret in SECRETS + [H.KEY, H.KEY2, f"Probe {H.PROBE}.{H.KEY}", MARKER.decode()]:
    must(secret not in blob, "a secret leaked: " + secret[:6])
must(not any(secret in repr(CACHE.data) for secret in SECRETS), "no raw ticket in the cache")
print("PASS probe tunnel end 1.18.47")
