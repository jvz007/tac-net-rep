#!/usr/bin/env python3
"""1.18.47 regression (held Low 1 and Low 2 of 1.18.46 on the probe route).

Low 1: a text frame of 15000 '[' is under the 16 KiB limit and makes json.loads raise RecursionError. It counts as one bad frame, the socket
stays open and ProbeConsumer.disconnect cleanup still runs; 20 of them close 4400.
Low 2: the pools are sized with headroom like the endpoint route (auth 6 threads and 256 backlog, recheck 2 and 4096, cache and audit raised in
proportion, handover kept), and a bounded ceiling of 64 connects in flight before the identity check answers 1013 and counts nothing, on the
control route and on both tunnel routes, and releases when the connect decision is made. The docs name the fleet size.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, must, reset, CACHE, run = H.pt, H.must, H.reset, H.CACHE, H.run

# ---------------------------------------------------------------- Low 1
try:
    json.loads("[" * 15000)
    raise AssertionError("json.loads accepted 15000 nested arrays")
except RecursionError:
    pass
frame_text = "[" * 15000
must(len(frame_text.encode()) < pt.MAX_FRAME_BYTES, "under the 16 KiB limit")


async def case_nested():
    reset()
    H.set_owner()
    H.add_probe()
    c = H.make_consumer(clock=H.Clock())
    await c.connect()
    await H.settle(c)
    must(c.accepted and not c.closed, "connected")
    await c.receive(text_data=frame_text)
    must(c._bad_frames == 1 and not c.closed, "one bad frame, the socket stays open")
    for _ in range(18):
        await c.receive(text_data=frame_text)
    must(c._bad_frames == 19 and not c.closed, "19 bad frames")
    await c.receive(text_data=frame_text)
    must(c.closed == [4400], c.closed)
    await c.disconnect(4400)
    must(pt.presence_key(H.PROBE) not in CACHE.data, "the disconnect cleanup ran and cleared presence")
    must(c._connected is False, "disconnected")


run(case_nested())

# ---------------------------------------------------------------- Low 2: pool sizes
must(pt.POOL_SPECS["auth"] == (6, 256) and pt.POOL_SPECS["recheck"] == (2, 4096), pt.POOL_SPECS)
must(pt.POOL_SPECS["cache"] == (6, 2000) and pt.POOL_SPECS["audit"] == (3, 800) and pt.POOL_SPECS["handover"] == (2, 64), pt.POOL_SPECS)
source = (H.APP / "probe_transport.py").read_text(encoding="utf-8")
must('"auth": (6, 256)' in source and '"recheck": (2, 4096)' in source, "the numbers are in the source")
must(pt.UNAUTHENTICATED_IN_FLIGHT == 64 and pt._UNAUTH.limit == 64, "the ceiling is 64")

# ---------------------------------------------------------------- Low 2: the ceiling
async def case_ceiling():
    reset()
    H.set_owner()
    H.add_probe()
    H.probe_online()
    H.REGISTRY["plugins"] = [H.SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    sid = H.new_session_id()
    ticket = H.issue(H.tunnel_spec(session_id=sid))["ticket"]
    # over the ceiling: 1013 before any identity check, counted nowhere
    pt._UNAUTH.count = pt.UNAUTHENTICATED_IN_FLIGHT
    for consumer in (H.make_consumer(), H.make_console(ticket), H.make_tunnel_probe(sid)):
        await consumer.connect()
        must(consumer.accepted and consumer.closed == [1013], (consumer.closed,))
    must(H.AUTH["calls"] == [] and CACHE.data.get(H.tun.ticket_key(ticket)) is not None, "no identity check and no ticket redeemed")
    must(not [k for k in CACHE.data if k.startswith((pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX))], "counted nowhere")
    must(pt.unauth_in_flight() == 64, "a refused connect releases nothing it did not take")
    pt._UNAUTH.count = 0
    # a normal connect, a refused one and a faulting one all release
    c = H.make_consumer()
    await c.connect()
    must(not c.closed and pt.unauth_in_flight() == 0, "released after a good connect")
    bad = H.make_consumer(H.headers_for(key="z" * 32), channel="specific.c9")
    await bad.connect()
    must(bad.closed == [4401] and pt.unauth_in_flight() == 0, "released after a refusal")
    original = pt.authenticate_async

    async def boom(*a, **k):
        raise RuntimeError("fault")

    pt.authenticate_async = boom
    try:
        faulty = H.make_consumer(channel="specific.c10")
        try:
            await faulty.connect()
        except RuntimeError:
            pass
    finally:
        pt.authenticate_async = original
    must(pt.unauth_in_flight() == 0, "released after a fault")
    # 64 slow identity checks hold 64 slots; the 65th is answered 1013 at once and the others finish and release
    gate = threading.Event()
    real = H.PROBES.copy()

    def slow(probe_id, key):
        gate.wait(5)
        return {"probe_id": probe_id, "client_id": 3, "site_id": 7}

    H.sys.modules["nprobe_stub.auth"].authenticate = slow
    for i in range(64):
        H.add_probe(f"probe-slow-{i:04d}", H.KEY)
    held = []
    for i in range(64):
        consumer = H.make_consumer(H.headers_for(f"probe-slow-{i:04d}", H.KEY, real_ip=f"198.51.100.{i + 1}"), channel=f"specific.s{i}")
        held.append((consumer, asyncio.ensure_future(consumer.connect())))
    for _ in range(50):
        await asyncio.sleep(0.01)
        if pt.unauth_in_flight() == 64:
            break
    must(pt.unauth_in_flight() == 64, pt.unauth_in_flight())
    extra = H.make_consumer(H.headers_for(real_ip="198.51.100.200"), channel="specific.extra")
    await extra.connect()
    must(extra.closed == [1013], "the 65th connect is answered 1013")
    gate.set()
    await asyncio.gather(*(task for _, task in held))
    must(pt.unauth_in_flight() == 0 and all(not c.closed for c, _ in held), "all finished and released")
    H.sys.modules["nprobe_stub.auth"].authenticate = H._authenticate
    H.PROBES.update(real)


run(case_ceiling())

# ---------------------------------------------------------------- the docs name the fleet size
doc = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
for needle in ("up to 500 connected probes", "50 concurrent tunnel sessions", "`UNAUTHENTICATED_IN_FLIGHT` is 64", "`(6, 256)`", "`(2, 4096)`"):
    must(needle in doc, "the docs name " + needle)
print("PASS probe transport hardening 1.18.47")
