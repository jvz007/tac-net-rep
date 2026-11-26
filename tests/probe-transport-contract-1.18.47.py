#!/usr/bin/env python3
"""1.18.47 regression: the contract core.probe_transport 1.4.0 (1.18.58: the ticket spec takes a list of permissions, additive; 1.18.53: the Console certificate, additive; 1.18.50: set_tunnel_site added; first written for 1.1.0: the five 1.0.0 operations unchanged, and issue_tunnel_ticket, end_tunnel,
end_tunnels_for_probe, tunnel_status added; the 1.18.46 contract test, updated).

Covered (the real probe_transport.py under the stubs of tests/probe_transport_harness.py; contracts.py and audit.py need Django, so their
source is read with ast): the ten CORE_CONTRACTS rows exist, point at functions of tec_tac.probe_transport and agree with
probe_transport_contract_metadata() (operations, version 1.0.0, owner networkprobe); the capability registers once with the five operations
and its metadata; apps.py wires the registration and the route in their own guarded blocks; _record_probe_transport writes provenance
probe-transport, object type probe, never strict, core_refusal only for a refusal, and never a key.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import logging
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
pt, must = H.pt, H.must
logging.getLogger("tec_tac.probe_transport").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.probe_transport").propagate = False  # the last case logs a warning on purpose
APP = H.APP

OPERATIONS_1_0_0 = ["register_owner", "request", "send", "presence", "disconnect"]
TUNNEL_OPERATIONS = ["issue_tunnel_ticket", "end_tunnel", "end_tunnels_for_probe", "tunnel_status"]
TUNNEL_OPERATIONS_1_2_0 = ["set_tunnel_site"]
OPERATIONS = OPERATIONS_1_0_0 + TUNNEL_OPERATIONS + TUNNEL_OPERATIONS_1_2_0
tun = H.tun
meta = pt.probe_transport_contract_metadata()
must(meta["id"] == "core.probe_transport" and meta["version"] == "1.4.0" and pt.CAPABILITY_VERSION == "1.4.0", "id and version")
must(len(OPERATIONS) == 10 and list(pt.OPERATIONS) == OPERATIONS, "ten operations")
must("1.1.0 (Core 1.18.47, framework >=1.18.47)" in meta["added_in"] and "1.0.0 (Core 1.18.46)" in meta["added_in"] and "Additive" in meta["added_in"], meta["added_in"])
must("1.2.0 (Core 1.18.50, framework >=1.18.50)" in meta["added_in"], meta["added_in"])
must("1.3.0 (Core 1.18.53, framework >=1.18.53)" in meta["added_in"] and "console_certificate_required" in meta["added_in"], meta["added_in"])
must("1.4.0 (Core 1.18.58, framework >=1.18.58)" in meta["added_in"] and "permissions" in meta["added_in"], meta["added_in"])
must("console_certificate_required" in meta["operations_detail"]["issue_tunnel_ticket"], "the new denied code is in the operation text")
must("X-Tectac-Console-Cert" in meta["tunnel"]["routes"]["console"] and "certificate_engineer_mismatch" in meta["tunnel"]["close_codes"]["4401"], "the Console headers and the seven reasons")
must("cert_serial" in meta["tunnel"]["audit"] and "custom:console-cert-refused" in meta["tunnel"]["audit"], "the audit text")
tunnel = meta["tunnel"]
must(tunnel["close_reasons"] == list(tun.ALL_REASONS) and len(tun.END_REASONS) == 14, "the fixed reason list")
must(tunnel["limits"]["sessions"] == 50 and tunnel["limits"]["sessions_per_probe"] == 5 and tunnel["limits"]["sessions_per_engineer"] == 3
     and tunnel["limits"]["tickets_per_engineer_per_minute"] == 10 and tunnel["limits"]["idle_seconds"] == 900 and tunnel["limits"]["hard_cap_seconds"] == 14400, tunnel["limits"])
must("/ws/tfd/probe-tunnel/" in tunnel["routes"]["console"] and "/ws/tfd/network-probe/tunnel/" in tunnel["routes"]["probe"], "the two routes")
for needle in ("4401", "4403", "4404", "4409", "1002", "1013", "1001", "4503"):
    must(needle in tunnel["close_codes"], "tunnel close code " + needle)
must(meta["operations"] == OPERATIONS, meta["operations"])
must("networkprobe" in meta["owner"] and pt.OWNER_MODULES == ("networkprobe",), "the one owner")
for needle in ("4401", "4403", "4400", "4409", "4408", "4429", "4503", "1009", "1013"):
    must(needle in meta["close_codes"], "close code " + needle)
must(meta["frame"]["limits"]["bytes_per_frame"] == 16 * 1024 and meta["frame"]["limits"]["frames_per_second"] == 20, meta["frame"])
for name in OPERATIONS:
    must(name in meta["operations_detail"], "detail for " + name)


# ---------------------------------------------------------------- the CORE_CONTRACTS rows
def literal_assignment(path, target):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == target for t in node.targets):
            return ast.literal_eval(node.value)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == target:
            return ast.literal_eval(node.value)
    raise AssertionError(target + " not found")


rows = [r for r in literal_assignment(APP / "contracts.py", "CORE_CONTRACTS") if r.get("area") == "probe-transport"]
must(sorted(r["name"] for r in rows) == sorted(OPERATIONS), [r["name"] for r in rows])
must(len(rows) == 10, "ten rows")
all_rows = literal_assignment(APP / "contracts.py", "CORE_CONTRACTS")
must(len({(r["import_path"], r["name"]) for r in all_rows}) == len(all_rows), "no duplicate contract rows")
for row in rows:
    must(row["import_path"] == "tec_tac.probe_transport" and row["kind"] == "python" and row["audience"] == "backend/premium-owner", row)
    if row["name"] in OPERATIONS_1_0_0:  # the 1.0.0 rows are untouched
        must("added 1.18.46" in row["purpose"] and "core.probe_transport 1.0.0" in row["purpose"] and "framework >=1.18.46" in row["purpose"], row["name"])
        must("networkprobe" in row["purpose"] or row["name"] == "register_owner", row["name"])
    elif row["name"] in TUNNEL_OPERATIONS_1_2_0:
        must("added 1.18.50" in row["purpose"] and "core.probe_transport 1.2.0" in row["purpose"] and "framework >=1.18.50" in row["purpose"], row["name"])
        must("networkprobe" in row["purpose"] and "Additive" in row["purpose"], row["name"])
    else:
        must("added 1.18.47" in row["purpose"] and "core.probe_transport 1.1.0" in row["purpose"] and "framework >=1.18.47" in row["purpose"], row["name"])
        must("networkprobe" in row["purpose"] and "Additive" in row["purpose"], row["name"])
    function = getattr(pt, row["name"])
    must(inspect.isfunction(function) and row["name"] in row["purpose"].split("(")[0], row["name"])
    first = list(inspect.signature(function).parameters)
    must(first[0] == "module_id" or (row["name"] == "issue_tunnel_ticket" and first[:2] == ["request", "module_id"]), row["name"] + " takes the verified module_id")
# the older rows are untouched: the endpoint transport rows are all still there
must({r["name"] for r in all_rows if r.get("area") == "endpoint-transport"} == {"register_owner", "request", "send_many", "presence"}, "endpoint rows unchanged")

# ---------------------------------------------------------------- the capability
registered: list = []
stub_caps = types.ModuleType("tec_tac.capabilities")
stub_caps.register_capability = lambda **kw: registered.append(kw) or kw
sys.modules["tec_tac.capabilities"] = stub_caps
pt.register_core_probe_transport_capability()
must(len(registered) == 1, registered)
cap = registered[0]
must(cap["id"] == "core.probe_transport" and cap["module_id"] == "core" and cap["version"] == "1.4.0", cap["id"])
must(list(cap["operations"]) == OPERATIONS and cap["metadata"] == meta, "operations and metadata")
for name in OPERATIONS:
    must(callable(getattr(cap["provider"], name)), "the provider has " + name)

# ---------------------------------------------------------------- apps.py wiring
apps = (APP / "apps.py").read_bytes().decode("utf-8")
must("register_core_probe_transport_capability()" in apps and "install_probe_route()" in apps, "apps.py wires both")
tree = ast.parse(apps)
must("install_tunnel_probe_route()" in apps and "install_tunnel_console_route()" in apps, "apps.py wires both tunnel routes")
guarded = 0
names = ("install_probe_route", "register_core_probe_transport_capability", "install_tunnel_probe_route", "install_tunnel_console_route")
for node in ast.walk(tree):
    if isinstance(node, ast.Try):
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        hits = [n for n in names if f"id='{n}'" in body]
        if hits:
            guarded += 1
            must(node.handlers and len(hits) == 1 and "install_endpoint_agent_route" not in body, ("its own guarded block, apart from the others", hits))
must(guarded == 4, guarded)
must("\r\n" in apps and apps.count("\n") == apps.count("\r\n"), "apps.py keeps CRLF")

# ---------------------------------------------------------------- _record_probe_transport (the function source, run against stubs)
source = (APP / "audit.py").read_bytes().decode("utf-8")
tree = ast.parse(source)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_record_probe_transport")
const = next(n for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "SERVER_PROVENANCE_PROBE_TRANSPORT")
must(ast.literal_eval(const.value) == "probe-transport", "the provenance constant")
CALLS: list = []
ACTORS: list = []
namespace = {
    "Any": object,
    "SERVER_PROVENANCE_PROBE_TRANSPORT": "probe-transport",
    "_TACTICAL_OPERATION_AUTHORITY": object(),
    "service_audit_actor": lambda **kw: ACTORS.append(kw) or ("actor", kw["service"]),
    "_record_row": lambda **kw: CALLS.append(kw) or kw,
}
exec(compile(ast.Module(body=[node], type_ignores=[]), "audit.py", "exec"), namespace)  # noqa: S102 - the repo's own function, stubs only
write = namespace["_record_probe_transport"]
write(action="custom:probe-connect", probe_id=H.PROBE, message="m", metadata={"client_id": 3, "site_id": 7, "ip": "203.0.113.9"})
row = CALLS[-1]
must(row["module_id"] == "core" and row["object_type"] == "probe" and row["object_id"] == H.PROBE and row["strict"] is False, row)
must(row["operation_context"] == {"server_provenance": "probe-transport"} and ACTORS[-1] == {"module_id": "core", "service": "probe-transport"}, row)
write(action="custom:probe-refused", probe_id=None, message="m", metadata={"reason": "wrong_scheme"}, refusal=True)
must(CALLS[-1]["operation_context"] == {"server_provenance": "probe-transport", "core_refusal": True} and CALLS[-1]["object_id"] is None, CALLS[-1])
must(H.KEY not in repr(CALLS), "no key in a row")
# the real writer path: only the fields named in the docs reach the row
captured: list = []
audit_stub = sys.modules["tec_tac.audit"]
audit_stub._record_probe_transport = lambda **kw: captured.append(kw)
pt.record_probe_event("custom:probe-refused", H.PROBE, reason="probe_key_invalid", ip="203.0.113.9", client_id=3, site_id=True, code=4401, refusal=True)
must(captured[-1]["metadata"] == {"reason": "probe_key_invalid", "ip": "203.0.113.9", "client_id": 3, "code": "4401"}, captured[-1])
pt.record_probe_event("custom:probe-refused", "bad id!", reason="malformed_probe_id")
must(captured[-1]["probe_id"] is None, "an invalid probe id is written without one")
audit_stub._record_probe_transport = lambda **kw: (_ for _ in ()).throw(RuntimeError("db down"))
pt.record_probe_event("custom:probe-connect", H.PROBE)  # never raises

# ---------------------------------------------------------------- the 1.0.0 operations behave as they did
H.reset()
H.set_owner()
must(pt.presence("networkprobe", [H.PROBE]) == {"outcome": "ok", "presence": {H.PROBE: {"connected": False, "since": None, "client_id": None, "site_id": None}}}, "presence unchanged")
must(pt.disconnect("networkprobe", H.PROBE, "nonsense") == {"outcome": "invalid"} and pt.disconnect("networkprobe", H.PROBE, "disabled") == {"outcome": "offline"}, "disconnect unchanged")
must(pt.send("networkprobe", H.PROBE, {"v": 1, "type": "event", "id": "a", "func": "f", "payload": {}}) == {"outcome": "offline"}, "send unchanged")
must(pt.request("networkprobe", H.PROBE, {"v": 1, "type": "request", "id": "a", "func": "f", "payload": {}}) == {"outcome": "offline", "reply": None}, "request unchanged")
must(pt.request("networkprobe", H.PROBE, {"v": 1, "type": "event", "id": "a", "func": "f", "payload": {}}) == {"outcome": "invalid", "reply": None}, "request still wants a request frame")
H.CALLER["module_id"] = "alerts"
for result in (pt.presence("alerts", [H.PROBE]), pt.issue_tunnel_ticket(H.engineer_request(), "alerts", H.tunnel_spec()), pt.end_tunnel("alerts", H.new_session_id(), "core"),
               pt.end_tunnels_for_probe("alerts", H.PROBE, "ended_by_core"), pt.tunnel_status("alerts", [])):
    must(result["outcome"] == "denied", result)
H.CALLER["module_id"] = "networkprobe"
must(pt.POOL_SPECS["handover"] == (2, 64) and pt.MAX_FRAME_BYTES == 16 * 1024 and pt.ROUTE_PATTERN == "ws/tfd/network-probe/" and pt.OWNER_MODULES == ("networkprobe",), "1.0.0 numbers unchanged")
print("PASS probe transport contract 1.18.47")
