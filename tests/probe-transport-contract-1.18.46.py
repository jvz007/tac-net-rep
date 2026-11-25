#!/usr/bin/env python3
"""1.18.46 regression: the contract core.probe_transport 1.0.0 (register_owner, request, send, presence, disconnect).

Covered (the real probe_transport.py under the stubs of tests/probe_transport_harness.py; contracts.py and audit.py need Django, so their
source is read with ast): the five CORE_CONTRACTS rows exist, point at functions of tec_tac.probe_transport and agree with
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

OPERATIONS = ["register_owner", "request", "send", "presence", "disconnect"]
meta = pt.probe_transport_contract_metadata()
must(meta["id"] == "core.probe_transport" and meta["version"] == "1.0.0" and pt.CAPABILITY_VERSION == "1.0.0", "id and version")
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
all_rows = literal_assignment(APP / "contracts.py", "CORE_CONTRACTS")
must(len({(r["import_path"], r["name"]) for r in all_rows}) == len(all_rows), "no duplicate contract rows")
for row in rows:
    must(row["import_path"] == "tec_tac.probe_transport" and row["kind"] == "python" and row["audience"] == "backend/premium-owner", row)
    must("added 1.18.46" in row["purpose"] and "core.probe_transport 1.0.0" in row["purpose"] and "framework >=1.18.46" in row["purpose"], row["name"])
    must("networkprobe" in row["purpose"] or row["name"] == "register_owner", row["name"])
    function = getattr(pt, row["name"])
    must(inspect.isfunction(function) and row["name"] in row["purpose"].split("(")[0], row["name"])
    first = inspect.signature(function).parameters
    must(next(iter(first)) == "module_id", row["name"] + " takes module_id first")
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
must(cap["id"] == "core.probe_transport" and cap["module_id"] == "core" and cap["version"] == "1.0.0", cap["id"])
must(list(cap["operations"]) == OPERATIONS and cap["metadata"] == meta, "operations and metadata")
for name in OPERATIONS:
    must(callable(getattr(cap["provider"], name)), "the provider has " + name)

# ---------------------------------------------------------------- apps.py wiring
apps = (APP / "apps.py").read_bytes().decode("utf-8")
must("register_core_probe_transport_capability()" in apps and "install_probe_route()" in apps, "apps.py wires both")
tree = ast.parse(apps)
guarded = 0
for node in ast.walk(tree):
    if isinstance(node, ast.Try):
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        if "install_probe_route" in body or "register_core_probe_transport_capability" in body:
            guarded += 1
            must(node.handlers and "install_endpoint_agent_route" not in body, "its own guarded block, apart from the agent route")
must(guarded == 2, guarded)

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
print("PASS probe transport contract 1.18.46")
