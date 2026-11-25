#!/usr/bin/env python3
"""1.18.46 regression: Core's probe transport, the parts without a socket (tests/probe_transport_harness.py; the real probe_transport.py runs).

Covered: header parsing (Probe accepted; Token, duplicated, empty, over-long and non-ASCII headers refused with reason codes); authenticate_probe
accepts the dict and refuses each refusal code, and a mismatch, a non-dict, a fault, a timeout and a full pool are transient; the failure
counters (address ceiling, the per-probe counter read only after a failed check, IPv6 by /64); register_owner (wrong module, unverified caller,
folder check for both paths, idempotent, different path refused, second owner refused); denied from all five operations for lookalikes, Core
itself and an unverifiable frame; request offline, timeout and ok with the reply channel freed; send, presence and disconnect shapes and the
2000-id cap; the key never appears in any return, log record or audit kwargs.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import time as real_time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, must, reset, run, add_probe, set_owner = H.pt, H.must, H.reset, H.run, H.add_probe, H.set_owner
KEY, PROBE, PROBE2, CACHE, LAYER, AUDITS = H.KEY, H.PROBE, H.PROBE2, H.CACHE, H.LAYER, H.AUDITS

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage() + " " + (record.exc_text or ""))


logging.getLogger("tec_tac.probe_transport").addHandler(_Capture())
logging.getLogger("tec_tac.probe_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.probe_transport").propagate = False


def scope(*headers):
    return {"headers": list(headers)}


# ---------------------------------------------------------------- header parsing
good = scope((b"authorization", f"Probe {PROBE}.{KEY}".encode()))
must(pt.parse_probe_headers(good) == (PROBE, KEY, None), pt.parse_probe_headers(good))
must(pt.parse_probe_headers(scope((b"Authorization", f"probe {PROBE}.{KEY}".encode())))[2] is None, "scheme and name are case-insensitive")
must(pt.parse_probe_headers(scope((b"authorization", b"Token " + b"a" * 40))) == (None, None, "wrong_scheme"), "an agent token header")
must(pt.parse_probe_headers(scope()) == (None, None, "malformed_header"), "no header")
two = scope((b"authorization", f"Probe {PROBE}.{KEY}".encode()), (b"authorization", f"Probe {PROBE}.{KEY}".encode()))
must(pt.parse_probe_headers(two) == (None, None, "malformed_header"), "a duplicated header")
must(pt.parse_probe_headers(scope((b"authorization", b"")))[2] == "malformed_header", "empty")
must(pt.parse_probe_headers(scope((b"authorization", b"Probe")))[2] == "malformed_header", "no space")
must(pt.parse_probe_headers(scope((b"authorization", b"Probe " + b"a" * 500)))[2] == "malformed_header", "over-long")
must(pt.parse_probe_headers(scope((b"authorization", f"Probe {PROBE}.{KEY}\xe9".encode("latin-1"))))[2] == "malformed_header", "non-ASCII")
must(pt.parse_probe_headers(scope((b"authorization", f"Probe short.{KEY}".encode())))[2] == "malformed_probe_id", "short id")
must(pt.parse_probe_headers(scope((b"authorization", f"Probe {PROBE}{KEY}".encode())))[2] == "malformed_probe_id", "no dot")
must(pt.parse_probe_headers(scope((b"authorization", f"Probe {PROBE}.short".encode()))) == (PROBE, None, "malformed_key"), "short key keeps the id")
must(pt.parse_probe_headers(scope((b"authorization", f"Probe {PROBE}.{KEY}!".encode())))[2] == "malformed_key", "bad key character")
must(pt.client_ip({"headers": [(b"x-real-ip", b"198.51.100.4")], "client": ("10.0.0.1", 1)}) == "198.51.100.4", "x-real-ip")
must(pt.client_ip({"headers": [(b"x-forwarded-for", b"1.2.3.4")], "client": ("10.0.0.1", 1)}) == "10.0.0.1", "x-forwarded-for never used")
must(pt.forwarded_plaintext(scope((b"x-forwarded-proto", b"ws"))) and not pt.forwarded_plaintext(scope((b"x-forwarded-proto", b"wss"))), "plaintext")

# ---------------------------------------------------------------- authenticate_probe
reset()
set_owner()
add_probe(PROBE, KEY, 3, 7)
H.PROBES[PROBE2] = "probe_disabled"
r = pt.authenticate_probe(PROBE, KEY)
must(r.ok and r.probe_id == PROBE and r.client_id == 3 and r.site_id == 7 and not r.transient, r)
for result, code in ((pt.authenticate_probe(PROBE, "z" * 20), "probe_key_invalid"), (pt.authenticate_probe("probe-none-0000", KEY), "probe_unknown"),
                     (pt.authenticate_probe(PROBE2, KEY), "probe_disabled")):
    must(not result.ok and not result.transient and result.reason == code, (code, result))
must(pt.authenticate_probe("bad id", KEY).reason == "malformed_probe_id" and pt.authenticate_probe(PROBE, "x").reason == "malformed_key", "malformed")
for mode in ("fault", "junk", "mismatch"):
    H.AUTH["mode"] = mode
    t = pt.authenticate_probe(PROBE, KEY)
    must(not t.ok and t.transient and t.reason == "unavailable", (mode, t))
H.AUTH["mode"] = "normal"
pt.clear_owner_for_tests()
must(pt.authenticate_probe(PROBE, KEY).transient, "no owner is transient")
set_owner()


async def case_async():
    ok = await pt.authenticate_async(PROBE, KEY)
    must(ok.ok, ok)
    pt.AUTH_TIMEOUT_SECONDS = 0.05
    original = H._authenticate

    def slow(probe_id, key):
        real_time.sleep(0.3)
        return original(probe_id, key)

    sys.modules["nprobe_stub.auth"].authenticate = slow
    slow_result = await pt.authenticate_async(PROBE, KEY)
    must(slow_result.transient and slow_result.reason == "unavailable", slow_result)
    sys.modules["nprobe_stub.auth"].authenticate = original
    pt.AUTH_TIMEOUT_SECONDS = 10.0
    pool = pt._POOLS["auth"]
    pool.inflight = pool.backlog
    busy = await pt.authenticate_async(PROBE, KEY)
    must(busy.transient and busy.reason == "busy", busy)
    pool.inflight = 0


run(case_async())

# ---------------------------------------------------------------- failure counters
reset()
set_owner()
add_probe(PROBE, KEY)
ip = "203.0.113.9"
for n in range(1, 11):
    must(pt.note_failed_check(ip, "probe-aaaa-1111") is False, f"failure {n} is not over the limit")
must(pt.rate_limited(ip), "10 failures from one address reach the ceiling")
must(pt.note_failed_check("203.0.113.10", "probe-aaaa-1111") is True, "the 11th failure naming the id is over its limit")
must(pt.probe_limited("probe-aaaa-1111") and not pt.probe_limited(PROBE), "the limit is per probe id")
for _ in range(15):
    pt.note_failed_check("198.51.100.1", PROBE)
must(pt.authenticate_probe(PROBE, KEY).ok, "a valid probe is accepted whatever its counter says (it is read only after a failed check)")
must(pt.probe_limited("not valid!") is False, "an invalid id is never limited")
v6a, v6b = "2001:db8:1:2::1", "2001:db8:1:2:ffff::9"
for _ in range(10):
    pt.note_failure(v6a)
must(pt.rate_limited(v6b) and not pt.rate_limited("2001:db8:1:3::1"), "IPv6 counts by its /64")
CACHE.down = True
must(pt.rate_limited(ip) is False and pt.probe_limited(PROBE) is False, "a cache fault reads as not limited")
pt.note_failure(ip)
CACHE.down = False

# ---------------------------------------------------------------- register_owner
reset()
folder, auth_path, task_path = H.make_owner_folder()
res = pt.register_owner("networkprobe", auth_path, task_path)
must(res == {"outcome": "ok", "registered": True, "idempotent": False}, res)
must(pt.get_owner()["task_name"] == "networkprobe.handle", pt.get_owner())
must(pt.register_owner("networkprobe", auth_path, task_path)["idempotent"] is True, "identical re-registration")
must(pt.register_owner("networkprobe", auth_path, "networkprobe.tasks.other")["outcome"] == "invalid", "different task path refused")
must(pt.register_owner("networkprobe", "networkprobe.auth.other", task_path)["outcome"] == "invalid", "different authenticator refused")
must(pt.register_owner("networkprobe-2", auth_path, task_path)["outcome"] == "denied", "module_id must be the verified caller")
H.CALLER["module_id"] = "networkprobe-2"
must(pt.register_owner("networkprobe-2", auth_path, task_path) == {"outcome": "denied"}, "a second owner id is not the owner")
H.CALLER["module_id"] = None
must(pt.register_owner("networkprobe", auth_path, task_path) == {"outcome": "denied"}, "an unverified caller")
H.CALLER["module_id"] = "networkprobe"
must(pt._register_owner("other-module", auth_path, task_path)["outcome"] == "denied", "the internal check also refuses another id")
for kwargs, label in (({"task_inside": False}, "task outside"), ({"auth_inside": False}, "authenticator outside"),
                      ({"task_is_celery": False}, "task not a celery task"), ({"auth_is_function": False}, "authenticator not a plain function")):
    reset()
    _, a, t = H.make_owner_folder(**kwargs)
    out = pt.register_owner("networkprobe", a, t)
    must(out["outcome"] == "invalid" and pt.get_owner() is None, (label, out))
reset()
_, a, t = H.make_owner_folder()
must(pt.register_owner("networkprobe", "bad path!", t)["outcome"] == "invalid", "not a dotted path")
H.REGISTRY["enabled"] = False
must(pt.register_owner("networkprobe", a, t)["outcome"] == "denied", "a disabled module cannot register")
H.REGISTRY["enabled"] = True
H.REGISTRY["plugins"] = []
must(pt.register_owner("networkprobe", a, t)["outcome"] == "denied", "a module that is not installed cannot register")

# ---------------------------------------------------------------- denied for every other caller
REQ = {"v": 1, "type": "request", "id": "r1", "func": "x.y", "payload": {}}
EVT = {"v": 1, "type": "event", "id": "e1", "func": "x.y", "payload": {}}
reset()
set_owner()
for who in ("networkprobe-lookalike", "endpoint-comms", "core", "networkprobe2", None):
    H.CALLER["module_id"] = who
    outs = [pt.register_owner("networkprobe", "a.b", "a.c"), pt.request("networkprobe", PROBE, REQ), pt.send("networkprobe", PROBE, EVT),
            pt.presence("networkprobe", [PROBE]), pt.disconnect("networkprobe", PROBE, "revoked")]
    for out in outs:
        must(out["outcome"] == "denied", (who, out))
H.CALLER["module_id"] = "networkprobe"

# ---------------------------------------------------------------- request, send, presence, disconnect
must(pt.request("networkprobe", PROBE, REQ)["outcome"] == "offline", "offline from presence, at once")
must(pt.request("other", PROBE, REQ)["outcome"] == "invalid", "module_id must equal the verified caller")
must(pt.request("networkprobe", "bad id", REQ)["outcome"] == "invalid" and pt.request("networkprobe", PROBE, EVT)["outcome"] == "invalid", "invalid")
must(pt.request("networkprobe", PROBE, REQ, timeout="x")["outcome"] == "invalid", "invalid timeout")
big = {**REQ, "payload": {"blob": "x" * (pt.MAX_FRAME_BYTES + 10)}}
must(pt.request("networkprobe", PROBE, big)["outcome"] == "invalid", "over 16 KiB")
must(pt.send("networkprobe", PROBE, EVT)["outcome"] == "offline", "send offline")
must(pt.send("networkprobe", PROBE, REQ)["outcome"] == "invalid", "send takes event or reply only")
must(pt.send("networkprobe", PROBE, {**EVT, "type": "reply"})["outcome"] == "offline", "a reply is accepted")
must(pt.disconnect("networkprobe", PROBE, "revoked")["outcome"] == "offline", "disconnect offline")
must(pt.disconnect("networkprobe", PROBE, "because")["outcome"] == "invalid", "reason from the fixed list")
pt.set_presence(PROBE, "2026-11-25T10:00:00+00:00", "own", 3, 7)
pres = pt.presence("networkprobe", [PROBE, PROBE2, PROBE])
must(pres["outcome"] == "ok" and pres["presence"][PROBE] == {"connected": True, "since": "2026-11-25T10:00:00+00:00", "client_id": 3, "site_id": 7}, pres)
must(pres["presence"][PROBE2] == {"connected": False, "since": None, "client_id": None, "site_id": None} and len(pres["presence"]) == 2, pres)
must(pt.presence("networkprobe", [f"probe-{i:08d}" for i in range(2000)])["outcome"] == "ok", "2000 ids")
must(pt.presence("networkprobe", [f"probe-{i:08d}" for i in range(2001)])["outcome"] == "invalid", "2001 ids")
must(pt.presence("networkprobe", "probe")["outcome"] == "invalid" and pt.presence("networkprobe", ["bad id"])["outcome"] == "invalid", "invalid ids")
CACHE.down = True
must(pt.presence("networkprobe", [PROBE])["outcome"] == "offline", "cache down")
CACHE.down = False

# delivery through an in-memory layer (a sink in place of a consumer)
MESSAGES: list = []


class Sink:
    async def probe_request(self, event):
        MESSAGES.append(event)
        await LAYER.send(event["reply_channel"], {"type": "probe.reply", "frame": {"v": 1, "type": "reply", "id": event["frame"]["id"], "func": "x", "payload": {"a": 1}}})

    async def probe_push(self, event):
        MESSAGES.append(event)

    async def probe_disconnect(self, event):
        MESSAGES.append(event)


LAYER.consumers["specific.sink"] = Sink()
LAYER.groups[pt.group_name(PROBE)] = {"specific.sink"}
answer = pt.request("networkprobe", PROBE, REQ, timeout=5)
must(answer["outcome"] == "ok" and answer["reply"]["payload"] == {"a": 1}, answer)
must(not [c for c in LAYER.channels if c != "specific.sink"], "the reply channel is freed")
must(pt.send("networkprobe", PROBE, EVT)["outcome"] == "ok" and MESSAGES[-1]["type"] == "probe.push", "send reaches the group")
must(pt.disconnect("networkprobe", PROBE, "key_rotated")["outcome"] == "ok" and MESSAGES[-1]["type"] == "probe.disconnect", "disconnect reaches the group")
LAYER.consumers.clear()  # nobody answers: the request times out within timeout + 1
started = real_time.monotonic()
quiet = pt.request("networkprobe", PROBE, REQ, timeout=1)
must(quiet["outcome"] == "timeout" and real_time.monotonic() - started < 2.5, quiet)
must(not [c for c in LAYER.channels if c != "specific.sink"], "the reply channel is freed after a timeout")

# ---------------------------------------------------------------- the key is never shown
for out in (pres, answer, quiet, pt.authenticate_probe(PROBE, KEY)):
    must(KEY not in repr(out), "the key is in a return value")
must(not any(KEY in line for line in LOGS), "no log record holds the key")
must(not any(KEY in repr(a) for a in AUDITS), "no audit kwargs hold the key")
print("PASS probe transport identity 1.18.46")
