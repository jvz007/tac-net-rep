#!/usr/bin/env python3
"""1.18.51 regression: held 1.18.50 Low finding. A DATA frame with a payload under DATA_SMALL_PAYLOAD_BYTES (512) counts against the control
bound (FRAMES_PER_SECOND_MAX, 2000 a second, detail rate_control), not the DATA bound (DATA_FRAMES_PER_SECOND_MAX, 10000, detail rate_data), so a
flood of 1-byte frames cannot hide in the 10000. Bulk frames (512 bytes up to 32 KiB) keep the DATA bound. Still in memory only, no cache
call, checked before check_frame. Runs on the in-memory harness (tests/probe_transport_harness.py)."""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.run
frame, Clock = H.frame, H.Clock
OPEN, DATA, ACK, CLOSE = 1, 2, 3, 4
logging.getLogger("tec_tac.probe_transport").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.probe_transport").propagate = False
CACHE_CALLS = ("get", "set", "add", "delete", "get_many", "set_many", "incr")


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0


def ended(sid):
    return CACHE.data.get(tun.end_key(sid))


async def start():
    fresh()
    clock = Clock()
    sid = H.new_session_id()
    got = H.issue(H.tunnel_spec(session_id=sid))
    must(got["outcome"] == "ok", got)
    console, probe = H.make_console(got["ticket"], clock=clock), H.make_tunnel_probe(sid, clock=clock)
    for consumer in (console, probe):
        await consumer.connect()
        await H.settle(consumer)
    return console, probe, sid, clock


SMALL_1, SMALL_511, BIG_512, BIG_1500, BIG_32K = (frame(DATA, 1, b"x" * n) for n in (1, 511, 512, 1500, 32768))
ACK_FRAME = frame(ACK, 1, b"\x00\x00\x00\x01")


def count(me, frames):
    """Run frames through _rate_exceeded (the check receive() makes first) and return the first bound that was passed, or None."""
    for item in frames:
        over = me._rate_exceeded(item)
        if over:
            return over
    return None


async def case_counting():
    must(tun.DATA_SMALL_PAYLOAD_BYTES == 512 and tun.DATA_FRAMES_PER_SECOND_MAX == 10000 and tun.FRAMES_PER_SECOND_MAX == 2000, "the figures")
    must(len(SMALL_511) - tun.HEADER_LEN == 511 and len(BIG_512) - tun.HEADER_LEN == 512, "the frames hold the payload sizes they claim")
    for sender in ("console", "probe"):
        console, probe, _sid, clock = await start()
        me = console if sender == "console" else probe

        def window(me=me):
            me._rate_start, me._rate_count, me._rate_data = None, 0, 0  # a fresh one-second window

        # 2000 one-byte DATA frames pass; the 2001st is over the control bound
        window()
        must(count(me, [SMALL_1] * 2000) is None, f"2000 small frames pass ({sender})")
        must(me._rate_exceeded(SMALL_1) == tun.RATE_CONTROL == "rate_control", f"the 2001st small frame is rate_control ({sender})")
        # 511 bytes is small, 512 is big
        window()
        must(count(me, [SMALL_511] * 2000) is None and me._rate_exceeded(SMALL_511) == "rate_control", "511-byte payloads count as small")
        window()
        must(count(me, [BIG_512] * 2001) is None and me._rate_data == 2001 and me._rate_count == 0, "512-byte payloads count against DATA only")
        # 10000 frames of 512 bytes pass, the 10001st is rate_data
        window()
        must(count(me, [BIG_512] * 10000) is None, "10000 big frames pass")
        must(me._rate_exceeded(BIG_512) == "rate_data", "the 10001st big frame is rate_data")
        # a 32 KB frame still counts as big
        window()
        must(count(me, [BIG_32K]) is None and me._rate_data == 1 and me._rate_count == 0, "a 32 KiB frame counts as DATA")
        must(count(me, [BIG_1500] * 9999) is None and me._rate_exceeded(BIG_1500) == "rate_data", "1.5 KB frames keep the 10000 bound")
        # mixed: 5000 big DATA plus 1999 ACKs pass
        window()
        must(count(me, [BIG_512] * 5000 + [ACK_FRAME] * 1999) is None, "5000 big DATA and 1999 ACKs pass")
        # 1500 small plus 500 ACKs pass; 1500 small plus 501 ACKs are over
        window()
        must(count(me, [SMALL_1] * 1500 + [ACK_FRAME] * 500) is None, "1500 small DATA and 500 ACKs pass")
        window()
        must(count(me, [SMALL_1] * 1500 + [ACK_FRAME] * 501) == "rate_control", "1500 small DATA and 501 ACKs end rate_control")
        # a new second resets both windows
        window()
        count(me, [SMALL_1] * 2000 + [BIG_512] * 10000)
        clock.now += 1.0
        must(me._rate_exceeded(SMALL_1) is None and me._rate_count == 1 and me._rate_data == 0, "a new second resets both windows")
        await console.disconnect(1006)
        await H.settle(console)


async def case_session_ends():
    # a 1-byte flood ends the session protocol_error with detail rate_control, on either side, with no cache call from the check
    for sender in ("console", "probe"):
        console, probe, sid, _clock = await start()
        me = console if sender == "console" else probe
        calls = {"n": 0}
        originals = {n: getattr(CACHE, n) for n in CACHE_CALLS if hasattr(CACHE, n)}

        def counting(func, calls=calls):
            def wrapped(*a, **k):
                calls["n"] += 1
                return func(*a, **k)
            return wrapped

        for n, func in originals.items():
            setattr(CACHE, n, counting(func))
        try:
            for _ in range(2000):
                await me.receive(bytes_data=SMALL_1)
        finally:
            for n in originals:
                delattr(CACHE, n)
        must(not me.closed and ended(sid) is None, f"2000 one-byte frames pass on the {sender} side")
        must(calls["n"] == 0, "the rate check made no cache call")
        await me.receive(bytes_data=SMALL_1)
        await H.settle(me)
        must(me.closed[-1] == 1002 and ended(sid)["reason"] == "protocol_error" and ended(sid)["detail"] == "rate_control", ended(sid))
        await console.disconnect(1006)
        await H.settle(console)


run(case_counting())
run(case_session_ends())

consumer = (H.APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
accept = consumer[consumer.index("async def _accept_frame"):consumer.index("unpaired_reason")]
must(accept.index("_rate_exceeded(") < accept.index("check_frame"), "the rate is checked before the frame")
must("DATA_SMALL_PAYLOAD_BYTES" in consumer and "DATA_SMALL_PAYLOAD_BYTES" in (H.APP / "probe_tunnel.py").read_text(encoding="utf-8"), "both files name the threshold")
doc = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
for needle in ("`DATA_SMALL_PAYLOAD_BYTES`", "512", "1.18.51", "rate_control"):
    must(needle in doc, "the docs name " + needle)
meta = pt.probe_transport_contract_metadata()["tunnel"]["limits"]
must(meta["small_data_payload_bytes"] == 512 and meta["data_frames_per_second"] == 10000 and meta["control_frames_per_second"] == 2000, meta)
must("under 512 bytes of payload" in str(pt.probe_transport_contract_metadata()["tunnel"]["close_codes"]["1002"]), "the 1002 text says it")
print("PASS probe tunnel limits 1.18.51")
