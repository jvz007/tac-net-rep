#!/usr/bin/env python3
"""1.18.55 regression: the live end of tunnel sessions after a Console certificate revoke or CA replacement runs in a background task, not in
the web request. Same in-memory harness as tests/probe-tunnel-certificates-1.18.53.py (tests/probe_transport_harness.py); the Celery task module is
a stub that records what the hook queued, the real probe_tunnel.py runs.

The hooks write the backstop marker (the one cache set left in the request), queue one task with one bounded broker attempt (2 s timeouts, no
retry, expires 120, ignore_result) and return []. A broker or cache fault never raises. The task body (probe_tunnel.run_end) ends the right
sessions inside END_BUDGET_SECONDS. The marker alone still ends a session at its 5-second tick.
"""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import logging
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset, CACHE, AUDITS, WALL, run = H.pt, H.tun, H.must, H.reset, H.CACHE, H.AUDITS, H.WALL, H.run
Clock, CERTS = H.Clock, H.CERTS
logging.getLogger("tec_tac.probe_transport").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.probe_transport").propagate = False

SERIAL_X, SERIAL_Y = "1" * 32, "2" * 32


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append((record.levelno, record.getMessage()))


CAP = Capture()
tun.logger.addHandler(CAP)
tun.logger.setLevel(logging.DEBUG)
tun.logger.propagate = False


class FakeBroker:
    def __init__(self, owner, transport_options, connect_timeout):
        self.owner, self.options, self.timeout = owner, transport_options, connect_timeout

    def __enter__(self):
        self.owner.connections.append({"transport_options": self.options, "connect_timeout": self.timeout})
        if self.owner.fail == "connect":
            raise ConnectionError("broker down")
        return self

    def __exit__(self, *exc):
        return False


class FakeTask:
    """Stands in for the Celery task object of tec_tac.tasks (the real module needs Tactical's Celery app)."""

    def __init__(self):
        self.connections, self.sent, self.fail = [], [], None
        self.app = SimpleNamespace(connection_for_write=lambda transport_options=None, connect_timeout=None: FakeBroker(self, transport_options, connect_timeout))

    def apply_async(self, args=None, **kwargs):
        if self.fail == "send":
            raise TimeoutError("broker timed out")
        self.sent.append({"args": args, **kwargs})


TASK = FakeTask()
tasks_stub = types.ModuleType("tec_tac.tasks")
tasks_stub.end_console_certificate_sessions = TASK
sys.modules["tec_tac.tasks"] = tasks_stub


def fresh():
    reset()
    H.set_owner()
    H.add_probe(H.PROBE, H.KEY, 3, 7)
    H.probe_online()
    H.REGISTRY["plugins"] = [SimpleNamespace(plugin_id="networkprobe", plugin_type="extension", legacy=False, root=HERE)]
    WALL[0] = 1_000_000.0
    TASK.connections.clear()
    TASK.sent.clear()
    TASK.fail = None
    CAP.lines.clear()


def issued():
    got = H.issue(H.tunnel_spec())
    must(got["outcome"] == "ok", got)
    return got


async def connect(ticket, clock=None, channel="specific.console"):
    console = H.make_console(ticket, clock=clock, channel=channel)
    await console.connect()
    await H.settle(console)
    return console


async def off(func, *args):
    return await asyncio.to_thread(func, *args)


async def tick(console, clock, seconds=5):
    clock.now += seconds
    WALL[0] += seconds
    return await console._tick()


def count_end_calls():
    calls = []
    real = tun.end_session

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    tun.end_session = counting
    return calls, real


async def cases():
    # ---- the hooks: marker in the request, one queued task, nothing ended in the calling thread
    fresh()
    got = issued()
    CERTS["serial"] = SERIAL_X
    live = await connect(got["ticket"])
    calls, real = count_end_calls()
    try:
        out = await off(tun.certificate_revoked, SERIAL_X)
    finally:
        tun.end_session = real
    must(out == [], f"the hook returns the empty list: {out}")
    must(calls == [] and not live.closed, "end_session was never called in the calling thread")
    must(CACHE.data[tun.cert_revoked_key(SERIAL_X)] == 1 and CACHE.timeouts[tun.cert_revoked_key(SERIAL_X)] == tun._keep_seconds(), "the marker")
    must(len(TASK.sent) == 1, f"exactly one task queued: {TASK.sent}")
    sent = TASK.sent[0]
    must(sent["args"] == ["certificate_revoked", SERIAL_X] and sent["retry"] is False and sent["expires"] == 120 and sent["ignore_result"] is True, sent)
    must(TASK.connections == [{"transport_options": {"socket_timeout": 2, "socket_connect_timeout": 2}, "connect_timeout": 2}], TASK.connections)
    must(sent["connection"] is not None, "the bounded connection is the one used")

    # the CA replacement: the same
    TASK.sent.clear()
    TASK.connections.clear()
    out = await off(tun.ca_replaced, CERTS["server_id"])
    must(out == [] and not live.closed, "ca_replaced ends nothing inline")
    must(CACHE.data[tun.ca_replaced_key(CERTS["server_id"])] == 1, "the CA marker")
    must(len(TASK.sent) == 1 and TASK.sent[0]["args"] == ["ca_replaced", CERTS["server_id"]] and TASK.sent[0]["retry"] is False, TASK.sent)
    must(TASK.connections == [{"transport_options": {"socket_timeout": 2, "socket_connect_timeout": 2}, "connect_timeout": 2}], TASK.connections)

    # ---- a broker that raises (on connect, or on send) leaves the marker, logs once, and does not raise
    for mode in ("connect", "send"):
        fresh()
        TASK.fail = mode
        CERTS["serial"] = SERIAL_X
        out = await off(tun.certificate_revoked, SERIAL_X)
        must(out == [], mode)
        must(CACHE.data[tun.cert_revoked_key(SERIAL_X)] == 1, f"{mode}: the marker stays")
        warnings = [text for level, text in CAP.lines if level >= logging.WARNING]
        must(len(warnings) == 1 and "not queued" in warnings[0], f"{mode}: one warning: {warnings}")
        CAP.lines.clear()
        out = await off(tun.ca_replaced, CERTS["server_id"])
        must(out == [] and CACHE.data[tun.ca_replaced_key(CERTS["server_id"])] == 1, f"{mode}: the CA marker stays")
        must(len([1 for level, _ in CAP.lines if level >= logging.WARNING]) == 1, f"{mode}: one warning for the CA hook")
    must(tun.queue_end("certificate_revoked", SERIAL_X) is False, "queue_end says False when the broker did not take it")
    TASK.fail = None
    must(tun.queue_end("certificate_revoked", SERIAL_X) is True, "and True when it did")

    # a missing task module (a worker image without it) is the same as a broker fault: never raises
    fresh()
    saved = sys.modules.pop("tec_tac.tasks")
    sys.modules["tec_tac.tasks"] = None  # an import of it now raises ImportError
    try:
        must(await off(tun.certificate_revoked, SERIAL_X) == [], "no task module: no raise")
        must(CACHE.data[tun.cert_revoked_key(SERIAL_X)] == 1, "no task module: the marker stays")
    finally:
        sys.modules["tec_tac.tasks"] = saved

    # ---- a cache that raises on the marker still queues the task
    fresh()
    real_set = CACHE.set
    CACHE.set = lambda key, value, timeout=None: (_ for _ in ()).throw(ConnectionError("down")) if key.startswith((tun.CERT_REVOKED_PREFIX, tun.CA_REPLACED_PREFIX)) else real_set(key, value, timeout)
    try:
        must(await off(tun.certificate_revoked, SERIAL_X) == [] and len(TASK.sent) == 1, "a marker fault still queues the end")
        must(await off(tun.ca_replaced, CERTS["server_id"]) == [] and len(TASK.sent) == 2, "and for the CA")
    finally:
        CACHE.set = real_set

    # ---- the task body ends the right sessions, with the right detail, and a second run ends nothing
    fresh()
    consoles = []
    for number, serial in enumerate((SERIAL_X, SERIAL_X, SERIAL_Y)):
        got = issued()
        CERTS["serial"] = serial
        consoles.append((await connect(got["ticket"], channel=f"specific.console{number}"), got["session_id"]))
    (_a, sid_a), (_b, sid_b), (_c, sid_c) = consoles
    c = _c
    ended = await off(tun.run_end, "certificate_revoked", SERIAL_X)
    must(sorted(ended) == sorted([sid_a, sid_b]), ended)
    for sid in (sid_a, sid_b):
        marker = CACHE.data.get(tun.end_key(sid))
        must(marker["reason"] == "ended_by_core" and marker["ended_by"] == "core" and marker["detail"] == "certificate_revoked", marker)
    must(CACHE.data.get(tun.end_key(sid_c)) is None and not c.closed, "the other certificate's session is untouched")
    must(await off(tun.run_end, "certificate_revoked", SERIAL_X) == [], "a second run ends nothing more")
    ended = await off(tun.run_end, "ca_replaced", CERTS["server_id"])
    must(ended == [sid_c], ended)
    must(CACHE.data[tun.end_key(sid_c)]["detail"] == "ca_replaced", "the CA detail")
    must(await off(tun.run_end, "ca_replaced", CERTS["server_id"]) == [], "nothing is left")
    must(await off(tun.run_end, "something_else", "x") == [], "an unknown kind ends nothing")

    # ---- the time budget, with a fake clock: what is not ended in time is left to the marker and the tick
    fresh()
    sessions = []
    for number in range(3):
        got = issued()
        CERTS["serial"] = SERIAL_X
        console = await connect(got["ticket"], clock=Clock(), channel=f"specific.console{number}")
        sessions.append((console, got["session_id"]))
    await off(tun.certificate_revoked, SERIAL_X)
    real_end = tun.end_session

    def slow_end(*args, **kwargs):
        WALL[0] += 6
        return real_end(*args, **kwargs)

    tun.end_session = slow_end
    try:
        ended = await off(tun.run_end, "certificate_revoked", SERIAL_X)
    finally:
        tun.end_session = real_end
    must(len(ended) == 2, f"two ended inside the {tun.END_BUDGET_SECONDS} second budget: {ended}")
    left = [(console, sid) for console, sid in sessions if sid not in ended]
    must(len(left) == 1 and CACHE.data.get(tun.end_key(left[0][1])) is None, "one is left")
    clock = Clock()
    left[0][0]._clock = clock
    must(await tick(left[0][0], clock) is False, "its next tick ends it from the marker")

    # ---- the marker alone ends a session at its 5-second tick although the task never ran
    fresh()
    clock = Clock()
    got = issued()
    CERTS["serial"] = SERIAL_X
    console = await connect(got["ticket"], clock=clock)
    TASK.fail = "connect"
    await off(tun.certificate_revoked, SERIAL_X)
    must(not console.closed, "nothing ended in the request")
    must(await tick(console, clock) is False, "the tick ends it from the marker alone")
    must(CACHE.data[tun.end_key(got["session_id"])]["detail"] == "certificate_revoked", "with the revoke detail")


run(cases())

# ---- static checks
source = (ROOT / "framwork" / "tec_tac" / "tasks.py").read_text(encoding="utf-8")
tree = ast.parse(source)
found = None
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == "end_console_certificate_sessions":
        for deco in node.decorator_list:
            if isinstance(deco, ast.Call):
                found = {kw.arg: ast.literal_eval(kw.value) for kw in deco.keywords}
                found["_name"] = ast.literal_eval(deco.keywords[0].value) if deco.keywords[0].arg == "name" else None
must(found is not None, "the task exists")
must(found["name"] == "tec_tac.end_console_certificate_sessions" and found["ignore_result"] is True and found["soft_time_limit"] == 30 and found["time_limit"] == 45, found)

cert_source = (ROOT / "framwork" / "tec_tac" / "console_certificates.py").read_text(encoding="utf-8")
must(sorted(set(re.findall(r"_tunnel\(\)\.(\w+)", cert_source))) == ["ca_replaced", "certificate_revoked"], "console_certificates calls only the two hook names")
tunnel_source = (ROOT / "framwork" / "tec_tac" / "probe_tunnel.py").read_text(encoding="utf-8")
hook_bodies = re.findall(r"def (?:certificate_revoked|ca_replaced)\(.*?(?=\ndef )", tunnel_source, re.DOTALL)
must(len(hook_bodies) == 2 and all("end_for_certificate(" not in body and "end_all_sessions(" not in body for body in hook_bodies), "no inline end in either hook")
docs = (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
must("the end runs in a background task; the marker ends a session within 5 seconds even if the task never runs" in docs, "documented")

print("probe tunnel end queue 1.18.55 regression: PASS")
