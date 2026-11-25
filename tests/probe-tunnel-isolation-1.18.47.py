#!/usr/bin/env python3
"""1.18.47 regression (AD-54): the tunnel routes and the agent route share nothing, and the tunnel keeps its own names apart from the control route.

Covered: probe_tunnel.py and probe_tunnel_consumer.py import nothing from endpoint_transport or its consumer (ast, and no indirect import); no
cache prefix, group prefix, audit action, credential or owner is shared with the agent route; the tunnel's cache prefixes and group prefix are
distinct from the control route's group and presence keys and from each other's prefixes (no prefix starts another); the ticket prefix is not
the terminal ticket's; the tunnel uses the probe route's own pools (never a pool of the agent route); every audit action of the new files is
custom:probe-tunnel-* and none is an agent action; an agent token and an agent id never reach the probe authenticator on a tunnel route.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, tun, must, reset = H.pt, H.tun, H.must, H.reset
APP = H.APP
NEW_FILES = ("probe_tunnel.py", "probe_tunnel_consumer.py")

# ---------------------------------------------------------------- no import of the agent route, in either direction
for name in NEW_FILES:
    text = (APP / name).read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            must("endpoint_transport" not in (node.module or "") and not any("endpoint_transport" in a.name for a in node.names), (name, ast.dump(node)))
        elif isinstance(node, ast.Import):
            must(not any("endpoint_transport" in a.name for a in node.names), (name, ast.dump(node)))
    must("from .endpoint" not in text and "import endpoint" not in text and "tec_tac.endpoint" not in text, name + " names no agent route module")
    must("import_module(" not in text and "__import__" not in text, name + " has no indirect import")
agent_text = (APP / "endpoint_transport.py").read_bytes().decode("utf-8") + (APP / "endpoint_transport_consumer.py").read_bytes().decode("utf-8")
must("probe_tunnel" not in agent_text, "the agent route does not import the tunnel either")

# ---------------------------------------------------------------- separate strings
et = importlib.import_module("tec_tac.endpoint_transport")
sys.modules["tec_tac.audit"]._record_endpoint_transport = lambda **kw: None
tunnel_prefixes = {
    "TICKET_PREFIX": tun.TICKET_PREFIX, "SESSION_PREFIX": tun.SESSION_PREFIX, "SIDE_PREFIX": tun.SIDE_PREFIX, "END_PREFIX": tun.END_PREFIX, "STATS_PREFIX": tun.STATS_PREFIX,
    "CLOSED_PREFIX": tun.CLOSED_PREFIX, "AUDITED_PREFIX": tun.AUDITED_PREFIX, "TICKET_RATE_PREFIX": tun.TICKET_RATE_PREFIX, "GROUP_PREFIX": tun.GROUP_PREFIX,
    "INDEX_KEY": tun.INDEX_KEY, "LOCK_KEY": tun.LOCK_KEY,
}
control_prefixes = [pt.GROUP_PREFIX, pt.PRESENCE_PREFIX, pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX]
agent_prefixes = [et.GROUP_PREFIX, et.PRESENCE_PREFIX, et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX, et.REFUSAL_ROWS_PREFIX]
terminal_prefix = "tec-tac:wsticket:v1:"
for name, value in tunnel_prefixes.items():
    for other in control_prefixes + agent_prefixes + [terminal_prefix]:
        must(not value.startswith(other) and not other.startswith(value), ("a tunnel name starts or is started by another route's", name, value, other))
names = list(tunnel_prefixes.items())
for i, (a_name, a) in enumerate(names):
    for b_name, b in names[i + 1:]:
        must(a != b and not a.startswith(b) and not b.startswith(a), ("two tunnel names overlap", a_name, b_name, a, b))
must(tun.GROUP_PREFIX == "tectac-pnt-" and not tun.GROUP_PREFIX.startswith(pt.GROUP_PREFIX) and not tun.GROUP_PREFIX.startswith(et.GROUP_PREFIX), "the group prefix is its own")
must(tun.TICKET_PREFIX == "tec-tac:pt:ticket:" and tun.TICKET_PREFIX != terminal_prefix, "the ticket store is its own, not the terminal ticket's")
for route in (tun.PROBE_SIDE_ROUTE_PATTERN, tun.CONSOLE_ROUTE_PATTERN):
    must(route not in (pt.ROUTE_PATTERN, et.ROUTE_PATTERN), "a route of its own")

# ---------------------------------------------------------------- the pools are the probe route's own, never the agent route's
consumer_text = (APP / "probe_tunnel_consumer.py").read_text(encoding="utf-8")
must("run_in_pool(" in consumer_text and "pt.run_in_pool" in consumer_text and "run_in_executor" not in consumer_text and "sync_to_async" not in consumer_text and "to_thread" not in consumer_text,
     "blocking calls go through the probe route's own pools only")
for pool in set(re.findall(r'run_in_pool\(\s*"([a-z]+)"', consumer_text)):
    must(pool in pt.POOL_SPECS and pt._POOLS[pool] is not et._POOLS[pool], "pool " + pool)

# ---------------------------------------------------------------- audit actions
actions = set()
for name in NEW_FILES:
    actions |= set(re.findall(r'"(custom:[a-z-]+)"', (APP / name).read_text(encoding="utf-8")))
must(actions == {"custom:probe-tunnel-ticket", "custom:probe-tunnel-connect", "custom:probe-tunnel-end", "custom:probe-tunnel-refused"}, actions)
agent_actions = set(re.findall(r'"(custom:[a-z-]+)"', agent_text))
control_actions = set(re.findall(r'"(custom:[a-z-]+)"', (APP / "probe_transport_consumer.py").read_text(encoding="utf-8")))
must(not actions & (agent_actions | control_actions), "no audit action is shared with another route")
must("_record_probe_transport" in (APP / "probe_transport.py").read_text(encoding="utf-8") and "_record_endpoint_transport" not in "".join((APP / n).read_text(encoding="utf-8") for n in NEW_FILES), "own audit writer")


# ---------------------------------------------------------------- credentials never cross on the tunnel routes
async def case_credentials():
    reset()
    H.set_owner()
    H.add_probe()
    H.probe_online()
    sid = H.new_session_id()
    H.issue(H.tunnel_spec(session_id=sid))
    agent_token = "a" * 40
    for headers in ([(b"authorization", b"Token " + agent_token.encode()), (b"x-agent-id", b"agentone")], [(b"authorization", b"Token " + agent_token.encode())]):
        probe = H.make_tunnel_probe(sid, headers=headers + [(b"x-tunnel-session", sid.encode())])
        await probe.connect()
        must(probe.closed == [4401], probe.closed)
        console = H.make_console("x", headers=headers)
        await console.connect()
        must(console.closed == [4401], console.closed)
    must(H.AUTH["calls"] == [], "an agent token never reached the probe authenticator")
    # an agent id is not a session id, and a probe key is not a ticket
    must(tun.parse_session_header({"headers": [(b"x-tunnel-session", b"agentone")]}) is None, "an agent id is not a session id")
    must(tun.parse_ticket_headers({"headers": [(b"authorization", f"Probe {H.PROBE}.{H.KEY}".encode())]}) == (None, "wrong_scheme"), "a probe credential is not a ticket")
    must(pt.parse_probe_headers({"headers": [(b"authorization", b"Ticket " + b"a" * 43)]})[2] == "wrong_scheme", "a ticket is not a probe credential")
    must(et.parse_endpoint_headers({"headers": [(b"authorization", b"Ticket " + b"a" * 43), (b"x-agent-id", b"agentone")]})[2] == "malformed_token", "the agent parser refuses a ticket")


H.run(case_credentials())

# ---------------------------------------------------------------- only networkprobe owns the tunnel, and the agent owner never touches it
reset()
H.set_owner()
H.CALLER["module_id"] = "endpoint-comms"
must(pt.issue_tunnel_ticket(H.engineer_request(), "endpoint-comms", H.tunnel_spec()) == {"outcome": "denied"}, "endpoint-comms cannot issue a tunnel ticket")
must(pt.end_tunnels_for_probe("endpoint-comms", H.PROBE, "ended_by_core") == {"outcome": "denied", "ended": []}, "nor end tunnels")
H.CALLER["module_id"] = "networkprobe"
must(et._verified_owner_id() is None, "networkprobe is no endpoint owner")
print("PASS probe tunnel isolation 1.18.47")
