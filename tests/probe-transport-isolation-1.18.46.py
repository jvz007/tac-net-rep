#!/usr/bin/env python3
"""1.18.46 regression (AD-54): the probe route and the agent route share nothing.

Covered: probe_transport.py and probe_transport_consumer.py do not import endpoint_transport (ast); no cache prefix, group name, pool name,
thread prefix or audit action of the two routes is shared; the real endpoint_transport.parse_endpoint_headers refuses a Probe header and the
real probe parser refuses a Token header; an agent id or agent token never reaches the probe authenticator; register_owner of networkprobe
never changes the endpoint owner, and the reverse.
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
pt, must, reset = H.pt, H.must, H.reset
APP = H.APP

# ---------------------------------------------------------------- no import of the other route
for name in ("probe_transport.py", "probe_transport_consumer.py"):
    tree = ast.parse((APP / name).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            must("endpoint_transport" not in (node.module or "") and not any("endpoint_transport" in a.name for a in node.names), (name, ast.dump(node)))
        elif isinstance(node, ast.Import):
            must(not any("endpoint_transport" in a.name for a in node.names), (name, ast.dump(node)))
    text = (APP / name).read_text(encoding="utf-8")
    must("import_module(\"tec_tac.endpoint" not in text and "__import__" not in text, name + " has no indirect import")
agent_text = (APP / "endpoint_transport.py").read_bytes().decode("utf-8")
agent_tree = ast.parse(agent_text)
for node in ast.walk(agent_tree):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        must("probe_transport" not in ast.dump(node), "the agent route does not import the probe route either")

# ---------------------------------------------------------------- separate strings
et = importlib.import_module("tec_tac.endpoint_transport")  # the real agent route, under the same stubs
stub_audit = sys.modules["tec_tac.audit"]
stub_audit._record_endpoint_transport = lambda **kw: None
for pair in (("GROUP_PREFIX",), ("PRESENCE_PREFIX",), ("FAILURE_PREFIX",), ("ROUTE_PATTERN",), ("SOCKET_PATH",)):
    must(getattr(pt, pair[0]) != getattr(et, pair[0]), pair)
must(pt.PROBE_FAILURE_PREFIX != et.AGENT_FAILURE_PREFIX, "failure prefix per id")
prefixes = [pt.GROUP_PREFIX, pt.PRESENCE_PREFIX, pt.FAILURE_PREFIX, pt.PROBE_FAILURE_PREFIX]
agent_prefixes = [et.GROUP_PREFIX, et.PRESENCE_PREFIX, et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX, et.REFUSAL_ROWS_PREFIX]
for a in prefixes:
    for b in agent_prefixes:
        must(not a.startswith(b) and not b.startswith(a), ("a prefix of one route starts the other", a, b))
must(set(pt.POOL_SPECS) == set(et.POOL_SPECS) and pt._POOLS is not et._POOLS, "separate pool objects")
for name in pt.POOL_SPECS:
    must(pt._POOLS[name] is not et._POOLS[name], "pool " + name)
pt._POOLS["auth"].submit(lambda: None).result()
import threading

must(any(t.name.startswith("tectac-pn-auth") for t in threading.enumerate()) and not any(t.name.startswith("tectac-ea-") for t in threading.enumerate()), "own thread prefix")
pt.reset_pools_for_tests()
actions = set(re.findall(r'"(custom:[a-z-]+)"', (APP / "probe_transport_consumer.py").read_text(encoding="utf-8")))
agent_actions = set(re.findall(r'"(custom:[a-z-]+)"', agent_text + (APP / "endpoint_transport_consumer.py").read_bytes().decode("utf-8")))
must(actions == {"custom:probe-connect", "custom:probe-disconnect", "custom:probe-refused"}, actions)
must(not actions & agent_actions, "no audit action is shared")
audit_source = (APP / "audit.py").read_bytes().decode("utf-8")
must('"probe-transport"' in audit_source and 'SERVER_PROVENANCE_PROBE_TRANSPORT = "probe-transport"' in audit_source, "own provenance")
must(pt.CAPABILITY_ID != et.CAPABILITY_ID, "own capability id")
for name in ("MAX_FRAME_BYTES", "PING_SECONDS", "RECHECK_SECONDS", "PRESENCE_SECONDS"):
    must(getattr(pt, name) != getattr(et, name), name + " is the probe's own number")

# ---------------------------------------------------------------- each parser refuses the other credential
agent_scope = {"headers": [(b"authorization", b"Token " + b"a" * 40), (b"x-agent-id", b"agentone")]}
probe_scope = {"headers": [(b"authorization", f"Probe {H.PROBE}.{H.KEY}".encode()), (b"x-agent-id", b"agentone")]}
must(et.parse_endpoint_headers(probe_scope)[2] == "malformed_token", "the agent parser refuses a Probe header")
must(pt.parse_probe_headers(agent_scope)[2] == "wrong_scheme", "the probe parser refuses a Token header")
must(et.parse_endpoint_headers(agent_scope)[2] is None, "the agent parser still accepts its own")
must(pt.parse_probe_headers(probe_scope)[2] is None, "the probe parser still accepts its own")
# an agent id is not a probe id, and the reverse (the agent id alphabet has no 8 character floor)
must(not pt.PROBE_ID_PATTERN.fullmatch("agent.one") and et.AGENT_ID_PATTERN.fullmatch(H.PROBE) is not None, "alphabets")


# ---------------------------------------------------------------- an agent credential never reaches the authenticator
async def case_consumer():
    reset()
    H.set_owner()
    H.add_probe()
    for headers in (H.headers_for(scheme="Token", probe_id="x", key="a" * 40), [(b"authorization", b"Token " + b"a" * 40), (b"x-agent-id", b"agentone")]):
        consumer = H.make_consumer(headers)
        await consumer.connect()
        must(consumer.closed == [4401], consumer.closed)
    must(H.AUTH["calls"] == [], "an agent token never reached the authenticator")


H.run(case_consumer())

# ---------------------------------------------------------------- the two owner registries are separate
reset()
folder, auth_path, task_path = H.make_owner_folder()
must(pt.register_owner("networkprobe", auth_path, task_path)["outcome"] == "ok", "probe owner")
must(et.get_owner() is None, "the probe owner did not touch the endpoint owner")
et._OWNER = {"module_id": "endpoint-comms", "path": "endpoint_comms.tasks.handle", "task_name": "endpoint_comms.handle"}
must(pt.get_owner()["module_id"] == "networkprobe", "the endpoint owner did not touch the probe owner")
et.clear_owner_for_tests()
must(pt.get_owner() is not None, "clearing one registry leaves the other")
# endpoint-comms is not a probe owner and networkprobe is not an endpoint owner
H.CALLER["module_id"] = "endpoint-comms"
must(pt.register_owner("endpoint-comms", auth_path, task_path) == {"outcome": "denied"}, "endpoint-comms cannot own the probe route")
must(pt.request("endpoint-comms", H.PROBE, {"v": 1, "type": "request", "id": "a", "func": "f", "payload": {}})["outcome"] == "denied", "nor call it")
H.CALLER["module_id"] = "networkprobe"
must(et._verified_owner_id() is None and et.register_owner("networkprobe", "x.y") == {"outcome": "denied"}, "networkprobe cannot own the agent route")
must(et.get_owner() is None, "still no endpoint owner")
print("PASS probe transport isolation 1.18.46")
