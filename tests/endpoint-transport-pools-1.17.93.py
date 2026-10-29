#!/usr/bin/env python3
"""1.17.93 regression: audit-pool hygiene and a busy cache pool (held Mediums of Core 1.17.92).

Covered: one audit row raises close_old_connections twice and closes nothing; a close_old_connections that raises is logged and the row is
still written; a failing audit write never raises and still cleans up; a full cache pool closes 1013 busy at the pre-check (valid token) and
instead of 4401 when a failure cannot be counted, counting nothing; a real cache error (cache down) behaves as before; the 11th failed
check naming one agent id from 11 addresses closes 4429 with a rate_limited_agent row, the per-address 11th attempt closes 4429 with no
row, and a valid token for that id still connects.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, make_consumer, run = H.et, H.must, H.reset, H.add_agent, H.make_consumer, H.run
CACHE, AUDITS, DB = H.CACHE, H.AUDITS, H.DB
audit_stub = sys.modules["tec_tac.audit"]
django_db = sys.modules["django.db"]


def failure_keys():
    return [k for k in CACHE.data if k.startswith((et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX))]


def rows():
    return [a for a in AUDITS if a["action"] == "custom:endpoint-refused"]


# ---------------------------------------------------------------- audit pool hygiene
reset()


async def case_audit():
    await et.run_in_pool("audit", et.record_endpoint_event, "custom:endpoint-connect", "agentone", ip="1.2.3.4")
    must(len(AUDITS) == 1 and DB["old"] == 2 and DB["closed"] == 0, "before and after the write, final=False: " + str(DB))
    # a close_old_connections that raises is logged and the row is still written
    real = django_db.close_old_connections

    def boom():
        DB["old"] += 1
        raise RuntimeError("db gone")

    django_db.close_old_connections = boom
    try:
        before = len(AUDITS)
        await et.run_in_pool("audit", et.record_endpoint_event, "custom:endpoint-connect", "agentone")
        must(len(AUDITS) == before + 1, "the row is written although the cleanup failed")
    finally:
        django_db.close_old_connections = real
    # a failing write never raises and still cleans up
    real_write = audit_stub._record_endpoint_transport

    def failing(**kw):
        raise RuntimeError("write failed")

    audit_stub._record_endpoint_transport = failing
    try:
        DB["old"] = 0
        await et.run_in_pool("audit", et.record_endpoint_event, "custom:endpoint-connect", "agentone")
        must(DB["old"] == 2, "cleanup before and after a failed write: " + str(DB))
    finally:
        audit_stub._record_endpoint_transport = real_write


run(case_audit())

# ---------------------------------------------------------------- a full cache pool at the pre-check
reset()
add_agent("agentone", pk=1)


async def case_busy_precheck():
    pool = et._POOLS["cache"]
    saved = pool.backlog
    pool.backlog = 0  # every cache call finds the pool full
    try:
        good = make_consumer(channel="specific.bc1")
        await good.connect()
        must(good.accepted and good.closed == [1013], good.closed)
        must(rows() and rows()[-1]["metadata"]["reason"] == "busy", AUDITS)
        must(not failure_keys(), "nothing counted")
        bad = make_consumer(headers=H.headers_for(token="c" * 40), channel="specific.bc2")
        await bad.connect()
        must(bad.closed == [1013] and 4401 not in bad.closed and not failure_keys(), (bad.closed, failure_keys()))
    finally:
        pool.backlog = saved


run(case_busy_precheck())

# ---------------------------------------------------------------- the pool is full only when the failure is counted
reset()
add_agent("agentone", pk=1)


async def case_busy_after_check():
    real_run = et.run_in_pool

    async def run_in_pool(name, func, /, *args, **kwargs):
        if name == "cache" and getattr(func, "__name__", "") == "note_failed_check":
            raise et.PoolFull("cache")
        return await real_run(name, func, *args, **kwargs)

    et.run_in_pool = run_in_pool
    try:
        bad = make_consumer(headers=H.headers_for(token="c" * 40), channel="specific.bc3")
        await bad.connect()
        must(bad.closed == [1013] and not failure_keys(), (bad.closed, failure_keys()))
        must(rows()[-1]["metadata"]["reason"] == "busy", rows())
        good = make_consumer(channel="specific.bc4")
        await good.connect()
        must(good.accepted and not good.closed, "a valid token is not affected: nothing needed counting")
        await good.disconnect(1000)
    finally:
        et.run_in_pool = real_run


run(case_busy_after_check())

# ---------------------------------------------------------------- a real cache error: reads as not limited, as before
reset()
add_agent("agentone", pk=1)


async def case_cache_down():
    CACHE.down = True
    try:
        good = make_consumer(channel="specific.cd1")
        await good.connect()
        must(good.accepted and not good.closed, "a valid token connects while the cache is down")
        bad = make_consumer(headers=H.headers_for(token="c" * 40), channel="specific.cd2")
        await bad.connect()
        must(bad.closed == [4401], bad.closed)
        await good.disconnect(1000)
    finally:
        CACHE.down = False


run(case_cache_down())

# ---------------------------------------------------------------- per-agent 4429 writes a row, per-address 4429 does not
reset()
add_agent("agentone", pk=1)


async def case_limits():
    codes = []
    for i in range(11):
        c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id="agentone", real_ip=f"198.51.100.{i + 1}"), channel=f"specific.l{i}")
        await c.connect()
        codes.append(c.closed[0])
    must(codes == [4401] * 10 + [4429], codes)
    must(len(rows()) == 11 and rows()[-1]["metadata"]["reason"] == "rate_limited_agent" and rows()[-1]["refusal"], rows()[-1])
    good = make_consumer(headers=H.headers_for(real_ip="192.0.2.77"), channel="specific.lgood")
    await good.connect()
    must(good.accepted and not good.closed, "a valid token for that id still connects")
    await good.disconnect(1000)
    del AUDITS[:]
    for i in range(10):
        c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id=f"ghost{i}", real_ip="203.0.113.50"), channel=f"specific.p{i}")
        await c.connect()
        must(c.closed == [4401], c.closed)
    written = len(AUDITS)
    eleventh = make_consumer(headers=H.headers_for(token="c" * 40, agent_id="ghost99", real_ip="203.0.113.50"), channel="specific.p11")
    await eleventh.connect()
    must(eleventh.closed == [4429] and len(AUDITS) == written, "the per-address 4429 writes no row")


run(case_limits())
must("rate_limited_agent" in et.REFUSAL_MESSAGES and "identity_stale" in et.REFUSAL_MESSAGES, "reasons")
print("PASS endpoint transport pools 1.17.93")
