#!/usr/bin/env python3
"""1.18.56 regression: the two held Lows of the 1.18.55 review.

On the in-memory harness (tests/probe_transport_harness.py). (1) A late ca_replaced task ends only the sessions of the replaced CA: with one old-CA
session and one new-CA session live, run_end('ca_replaced', old) ends only the old one; a marker written before this release (no server_id) is judged
by the certificate row of its serial (old CA ends, new CA does not, an unreadable row or no serial ends: fail closed); a session with no Console
attached is left alone; a new-CA session started after the replacement is never touched. (2) A celery SoftTimeLimitExceeded raised while ending a
session propagates out of _end_sessions and run_end and ends no further session; an ordinary exception is still logged and the loop continues.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, WALL, CERTS, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.WALL, H.CERTS, H.run
logging.getLogger("tec_tac.probe_transport").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.probe_transport").propagate = False  # the fault cases log a warning on purpose

OLD, NEW = "0" * 31 + "1", "0" * 31 + "2"
S_OLD, S_NEW, S_GONE, S_BROKEN = "e1" * 16, "e2" * 16, "e3" * 16, "e4" * 16
ISSUER = {S_OLD: OLD, S_NEW: NEW, S_GONE: None}


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def issuer_of(serial):
    if serial == S_BROKEN:
        raise RuntimeError("database down")
    return ISSUER[serial]


certs_stub = sys.modules["tec_tac.console_certificates"]
certs_stub.ca_server_id_for_serial = issuer_of


tun.MAX_SESSIONS_PER_ENGINEER = 10  # the limits are not what this test is about: six live sessions of one person on one probe
tun.MAX_SESSIONS_PER_PROBE = 10


async def live(serial, server_id, channel, engineer=0):
    """One connected Console session under the CA ``server_id`` with certificate ``serial``."""
    got = H.issue(H.tunnel_spec())
    must(got["outcome"] == "ok", got)
    CERTS["serial"], CERTS["server_id"], CERTS["not_after"] = serial, server_id, WALL[0] + 86400
    console = H.make_console(got["ticket"], channel=channel)
    await console.connect()
    await H.settle(console)
    must(console.accepted and not console.closed, (console.closed, console.close_reasons))
    return console, got["session_id"]


def ended(sid):
    return CACHE.data.get(tun.end_key(sid)) is not None


async def off(func, *args):
    import asyncio

    return await asyncio.to_thread(func, *args)


async def main():
    # ---- (1) only the replaced CA's sessions end
    fresh()
    _a, sid_old = await live(S_OLD, OLD, "specific.c1")
    _b, sid_new = await live(S_NEW, NEW, "specific.c2")
    out = await off(tun.run_end, "ca_replaced", OLD)
    must(out == [sid_old] and ended(sid_old) and not ended(sid_new), f"only the old CA's session ends: {out}")
    must(CACHE.data[tun.end_key(sid_old)]["detail"] == "ca_replaced" and CACHE.data[tun.end_key(sid_old)]["reason"] == "ended_by_core", "with the usual end row detail")
    must(await off(tun.run_end, "ca_replaced", OLD) == [], "a second run ends nothing")
    must(await off(tun.run_end, "ca_replaced", "9" * 32) == [] and not ended(sid_new), "another CA id ends nothing")
    # a session of the new CA that starts after the replacement is never touched, even by a task that runs late
    _c, sid_later = await live(S_NEW, NEW, "specific.c3")
    await off(tun.run_end, "ca_replaced", OLD)
    must(not ended(sid_later) and not ended(sid_new), "new-CA sessions are never touched by the old CA's task")
    must(tun.end_for_ca(OLD) == [], "end_for_ca is the same function")
    # end_all_sessions is still there for a caller that means every session
    must(sorted(await off(tun.end_all_sessions, "ca_replaced")) == sorted([sid_new, sid_later]), "end_all_sessions still ends every live session")

    # ---- a marker from before this release has no server_id: the certificate row of its serial decides
    fresh()
    sessions = {}
    for number, (name, serial) in enumerate((("old", S_OLD), ("new", S_NEW), ("gone", S_GONE), ("broken", S_BROKEN))):
        console, sid = await live(S_OLD, NEW, f"specific.{name}", engineer=number)
        marker = CACHE.data[tun.side_key(sid, "console")]
        CACHE.data[tun.side_key(sid, "console")] = {"at": marker["at"], "cert_serial": serial}  # the 1.18.55 marker shape
        sessions[name] = sid
    console, sid_noserial = await live(S_OLD, NEW, "specific.noserial", engineer=4)
    CACHE.data[tun.side_key(sid_noserial, "console")] = {"at": 1.0}
    out = await off(tun.run_end, "ca_replaced", OLD)
    must(ended(sessions["old"]), "an old marker whose certificate row is of the replaced CA ends")
    must(not ended(sessions["new"]), "an old marker whose certificate row is of the new CA does not")
    must(ended(sessions["gone"]), "an old marker whose certificate row is gone ends (unreadable: fail closed)")
    must(ended(sessions["broken"]), "an old marker whose certificate row cannot be read ends (fail closed)")
    must(ended(sid_noserial), "a marker with no serial and no server id ends (fail closed)")
    must(sorted(out) == sorted([sessions["old"], sessions["gone"], sessions["broken"], sid_noserial]), f"exactly those ended: {out}")
    # a session whose Console never connected has no CA-bound credential yet and is left alone
    fresh()
    got = H.issue(H.tunnel_spec())
    must(got["outcome"] == "ok", got)
    must(await off(tun.run_end, "ca_replaced", OLD) == [] and not ended(got["session_id"]), "a session whose Console never connected is left alone")
    # a marker with a server id is trusted over the certificate row
    fresh()
    console, sid = await live(S_OLD, NEW, "specific.m1")
    must(not tun._session_on_ca(sid, OLD) and tun._session_on_ca(sid, NEW), "a recorded server_id decides without reading the certificate row")

    # ---- (2) the soft time limit stops the run cleanly
    class SoftTimeLimitExceeded(Exception):
        pass

    fake_celery = types.ModuleType("celery")
    fake_exceptions = types.ModuleType("celery.exceptions")
    fake_exceptions.SoftTimeLimitExceeded = SoftTimeLimitExceeded
    saved = {k: sys.modules.get(k) for k in ("celery", "celery.exceptions")}
    sys.modules["celery"], sys.modules["celery.exceptions"] = fake_celery, fake_exceptions
    real_end = tun.end_session
    try:
        fresh()
        first, sid1 = await live(S_OLD, OLD, "specific.t1")
        second, sid2 = await live(S_OLD, OLD, "specific.t2")
        third, sid3 = await live(S_OLD, OLD, "specific.t3")
        calls = []

        def limited(session_id, *args, **kwargs):
            calls.append(session_id)
            raise SoftTimeLimitExceeded()

        tun.end_session = limited
        raised = []
        for call in (lambda: tun._end_sessions(lambda sid: True, "ca_replaced"), lambda: tun.run_end("ca_replaced", OLD), lambda: tun.run_end("certificate_revoked", S_OLD)):
            calls.clear()
            try:
                await off(call)
            except SoftTimeLimitExceeded:
                raised.append(len(calls))
        must(raised == [1, 1, 1], f"the soft limit propagates out of _end_sessions and run_end and no further session is tried: {raised}")
        must(not (ended(sid1) or ended(sid2) or ended(sid3)), "and no session was ended by those calls")
        # an ordinary exception is logged and the loop goes on
        seen = []

        def flaky(session_id, *args, **kwargs):
            seen.append(session_id)
            if len(seen) == 1:
                raise RuntimeError("one session fails")
            return real_end(session_id, *args, **kwargs)

        tun.end_session = flaky
        out = await off(tun.run_end, "ca_replaced", OLD)
        must(len(seen) == 3 and len(out) == 2, f"one fault is logged and the other two sessions still end: {seen} {out}")
    finally:
        tun.end_session = real_end
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    # without celery in the process the placeholder is never raised and the loop works
    fresh()
    _x, sid_x = await live(S_OLD, OLD, "specific.nc")
    must(await off(tun.run_end, "ca_replaced", OLD) == [sid_x], "without celery importable the end still works")

    source = Path(tun.__file__).read_text(encoding="utf-8")
    must("except SoftTimeLimitExceeded:" in source and source.index("except SoftTimeLimitExceeded:") < source.index("A tunnel session could not be ended for a Console certificate change"), "the re-raise comes before the generic handler")
    must("end_all_sessions(\"ca_replaced\")" not in source.split("def run_end")[1].split("def certificate_revoked")[0], "run_end no longer ends every session for ca_replaced")


run(main())
print("probe tunnel end lows 1.18.56 regression: PASS")
