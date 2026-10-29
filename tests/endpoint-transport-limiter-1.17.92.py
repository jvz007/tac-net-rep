#!/usr/bin/env python3
"""1.17.92 regression: the failure limiter never refuses a valid token (closes held Medium 2 of 1.17.90-1).

Stub harness (tests/endpoint_transport_harness.py), the real endpoint_transport.py and consumer. Covered (rebuild 1.17.92-1: the signed AD-54 limit of 10 failed attempts a minute per address is the default, the 600 ceiling and the global row budget are off): 10 failing attempts from one IPv4 address close 4401 and the 11th closes 4429 with no audit row under default settings, another address still connects; an IPv6 address in the same /64 shares one counter, another /64 does not, IPv4 stays exact; 11
failed attempts naming one agent id: the 11th gets 4429 but a valid token for that agent id still connects (the limit is read only after a
failed check); the 601st refusal audit row in a minute is not written and one summary line is logged, a new minute is free; a cache fault
reads as not limited.
"""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must, reset, add_agent, make_consumer, run = H.et, H.must, H.reset, H.add_agent, H.make_consumer, H.run
CACHE, AUDITS = H.CACHE, H.AUDITS

LOGS: list = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage())


logging.getLogger("tec_tac.endpoint_transport").addHandler(_Capture())
logging.getLogger("tec_tac.endpoint_transport").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.endpoint_transport").propagate = False

must(et.FAILURES_PER_ADDRESS_PER_MINUTE == 10 and et.FAILURES_PER_AGENT_PER_MINUTE == 10 and et.REFUSAL_ROWS_PER_MINUTE == 0, "the signed defaults")


async def failing(index, ip="203.0.113.9", agent_id=None, channel_prefix="f"):
    c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id=agent_id or f"ghost{index}", real_ip=ip), channel=f"specific.{channel_prefix}{index}")
    await c.connect()
    return c


# ---------------------------------------------------------------- 100 failing clients behind one address, then a valid token
reset()
add_agent("agentone", pk=1)


async def case_nat():
    codes = [(await failing(i)).closed[0] for i in range(10)]
    must(codes == [4401] * 10, codes)
    eleventh = await failing(10)
    must(eleventh.closed == [4429], eleventh.closed)  # the signed limit: the 11th failed attempt from one IPv4 address in a minute
    must(len([a for a in AUDITS if a["action"] == "custom:endpoint-refused"]) == 10, "the limited attempt writes no row")
    good = make_consumer(headers=H.headers_for(real_ip="198.51.100.50"), channel="specific.good")
    await good.connect()
    must(good.accepted and not good.closed, good.closed)
    await good.disconnect(1000)


run(case_nat())

# ---------------------------------------------------------------- 600 failures from one address, the 601st connect is 4429 with no row
reset()
add_agent("agentone", pk=1)


async def case_ceiling():
    for _ in range(et.FAILURES_PER_ADDRESS_PER_MINUTE):
        et.note_failure("203.0.113.9")
    c = await failing(1)
    must(c.closed == [4429] and not AUDITS, (c.closed, AUDITS))
    # the ceiling is pre-auth: even a valid token from this address waits for the next minute (the plan's NAT-sized bound)
    other = make_consumer(headers=H.headers_for(real_ip="198.51.100.2"), channel="specific.other")
    await other.connect()
    must(not other.closed, "another address connects")
    await other.disconnect(1000)
    H.WALL[0] += 61
    again = make_consumer(channel="specific.again")
    await again.connect()
    must(not again.closed, "a new minute is free")
    await again.disconnect(1000)


run(case_ceiling())

# ---------------------------------------------------------------- IPv6 by /64, IPv4 exact
reset()
for _ in range(et.FAILURES_PER_ADDRESS_PER_MINUTE):
    et.note_failure("2001:db8:1:2::1")
must(et.rate_limited("2001:db8:1:2:ffff:ffff:ffff:ffff"), "same /64 shares one counter")
must(not et.rate_limited("2001:db8:1:3::1"), "another /64 does not")
must(et._address_key("2001:db8:1:2::1") == "2001:db8:1:2::/64", et._address_key("2001:db8:1:2::1"))
must(et._address_key("203.0.113.9") == "203.0.113.9" and et._address_key("unknown") == "unknown", "IPv4 exact, others as given")
for _ in range(et.FAILURES_PER_ADDRESS_PER_MINUTE):
    et.note_failure("203.0.113.9")
must(et.rate_limited("203.0.113.9") and not et.rate_limited("203.0.113.10"), "IPv4 stays exact")

# ---------------------------------------------------------------- 11 failures naming one agent id: the 11th is 4429, a valid token still connects
reset()
add_agent("agentone", pk=1)


async def case_agent():
    codes = []
    for i in range(11):
        c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id="agentone", real_ip=f"198.51.100.{i + 1}"), channel=f"specific.a{i}")
        await c.connect()
        codes.append(c.closed[0])
    must(codes == [4401] * 10 + [4429], codes)
    # 1.17.93: the per-agent 4429 writes a row (reason rate_limited_agent); only the per-address 4429 stays rowless
    must(len(AUDITS) == 11 and AUDITS[-1]["metadata"]["reason"] == "rate_limited_agent", "the per-agent limited refusal writes its row")
    good = make_consumer(headers=H.headers_for(real_ip="192.0.2.77"), channel="specific.agentgood")
    await good.connect()
    must(good.accepted and not good.closed, "a valid token for that agent id still connects (read only after a failed check)")
    await good.disconnect(1000)
    # reading the limit never happens before the check
    must(not et.agent_limited("not a valid id!") and et.agent_limited("agentone"), "only a pattern-valid id is counted")
    must("agent_limited" in (H.APP / "endpoint_transport_consumer.py").read_text(encoding="utf-8") or "note_failed_check" in (H.APP / "endpoint_transport_consumer.py").read_text(encoding="utf-8"), "the consumer reads it")


run(case_agent())

# ---------------------------------------------------------------- the global budget of refusal rows
reset()
del LOGS[:]


async def case_budget():
    # default (0): every refusal is written, no summary line
    for i in range(30):
        c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id=f"ghostoff{i}", real_ip=f"10.2.0.{i + 1}"), channel=f"specific.o{i}")
        await c.connect()
    must(len([a for a in AUDITS if a["action"] == "custom:endpoint-refused"]) == 30 and not [m for m in LOGS if "refusals in a minute" in m], "no budget by default")
    reset()
    del LOGS[:]
    et.REFUSAL_ROWS_PER_MINUTE = 600  # the opt-in proposal, only to test the mechanism
    for i in range(601):
        c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id=f"ghost{i}", real_ip=f"10.1.{i // 250}.{i % 250 + 1}"), channel=f"specific.r{i}")
        await c.connect()
        must(c.closed == [4401], (i, c.closed))
    rows = [a for a in AUDITS if a["action"] == "custom:endpoint-refused"]
    must(len(rows) == 600, len(rows))
    summaries = [m for m in LOGS if "refusals in a minute" in m]
    must(len(summaries) == 1, LOGS)
    c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id="ghostmore", real_ip="10.9.9.9"), channel="specific.more")
    await c.connect()
    must(len([a for a in AUDITS if a["action"] == "custom:endpoint-refused"]) == 600 and len([m for m in LOGS if "refusals in a minute" in m]) == 1, "still one summary line")
    H.WALL[0] += 61
    c = make_consumer(headers=H.headers_for(token="c" * 40, agent_id="ghostnext", real_ip="10.9.9.10"), channel="specific.next")
    await c.connect()
    must(len([a for a in AUDITS if a["action"] == "custom:endpoint-refused"]) == 601, "a new minute is free")


try:
    run(case_budget())
finally:
    et.REFUSAL_ROWS_PER_MINUTE = 0

# ---------------------------------------------------------------- a cache fault reads as not limited
reset()
add_agent("agentone", pk=1)
CACHE.down = True
must(not et.rate_limited("203.0.113.9") and not et.agent_limited("agentone") and et.refusal_row_allowed(), "a cache fault reads as not limited")
et.note_failure("203.0.113.9")
et.note_agent_failure("agentone")


async def case_fault():
    c = make_consumer(channel="specific.fault")
    await c.connect()
    must(c.accepted and not c.closed, "a valid token connects with the cache down")
    await c.disconnect(1000)


run(case_fault())
CACHE.down = False
print("PASS endpoint transport limiter 1.17.92")
