#!/usr/bin/env python3
"""1.17.8 regression: the Tactical operation audit writer is private to Core (held Low from the 1.17.7 review).

Reuses the stub harness of tests/audit-declared-browser-events-1.17.0.py, like tests/audit-server-provenance-1.17.7.py.
Django is not installed on the development PC.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, tech, PKG = H["audit"], H["ROWS"], H["reset"], H["tech"], H["PKG"]


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


# 1. the public name is gone, and nothing public writes server provenance
must(not hasattr(audit, "record_tactical_operation"), "audit.record_tactical_operation must not exist")
must(hasattr(audit, "_record_tactical_operation"), "the private writer exists")
public = [name for name in dir(audit) if not name.startswith("_")]
provenance_writers = []
tree = ast.parse((PKG / "audit.py").read_text(encoding="utf-8"))
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and not node.name.startswith("_") and "SERVER_PROVENANCE_TACTICAL_OPERATION" in ast.dump(node):
        provenance_writers.append(node.name)
must(provenance_writers == [], f"public functions that write server provenance: {provenance_writers}")
must(all(not name.startswith("record_tactical") for name in public), public)
must(not hasattr(audit.AuditProvider, "record_tactical_operation"), "the provider has no such method")

# 2. the private writer still writes the row, with no module-permission check
reset()
real_check = audit._actor_can_use_module
audit._actor_can_use_module = lambda actor, module: False
try:
    res = audit._record_tactical_operation(
        actor=tech, module_id="declaring-demo", action="run", object_type="agent", object_id="a-1", message="Core ran it",
        operation="reboot", tactical_status=200,
    )
    must(res["recorded"] is True, res)
    ctx = ROWS[-1]["debug_info"]["operation_context"]
    must(ctx == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": 200}, ctx)
    audit._record_tactical_operation(actor=tech, module_id="declaring-demo", action="deny", object_type="agent", operation="reboot",
                                    tactical_status=403, refusal=True)
    ctx = ROWS[-1]["debug_info"]["operation_context"]
    must(ctx.get("core_refusal") is True and ctx["server_provenance"] == "tactical-operation" and ctx["tactical_status"] == 403, ctx)
finally:
    audit._actor_can_use_module = real_check

# 3. record() and metadata still cannot carry it
reset()
try:
    audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", operation_context={"server_provenance": "tactical-operation"})
    raise AssertionError("record() accepted server_provenance")
except audit.AuditContractError:
    pass
audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", metadata={"server_provenance": "tactical-operation"})
must("server_provenance" not in ROWS[-1]["debug_info"]["operation_context"], ROWS[-1])

# 4. only tactical_operations.py calls the private writer, under any spelling
callers = {}
for path in sorted(PKG.glob("*.py")):
    text = path.read_text(encoding="utf-8")
    if "_record_tactical_operation" not in text:
        continue
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in ("_record_tactical_operation", "record_tactical_operation"):
                callers.setdefault(path.name, 0)
                callers[path.name] += 1
must(set(callers) == {"tactical_operations.py"}, callers)

# 5. the executor's _write_row path still records the row
spec = importlib.util.spec_from_file_location("tec_tac.tactical_operations", PKG / "tactical_operations.py")
ops = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ops
spec.loader.exec_module(ops)
operation = ops.TacticalOperation(
    id="reboot", module_id="declaring-demo", method="POST", route="agents/{agent_id}/reboot/", segments=(), trailing_slash=True,
    permissions=(), scope=(), body_fields=(), audit_action="run", audit_object_type="agent", audit_fields=(),
)
reset()
request = types.SimpleNamespace(user=tech, META={}, tec_tac_request_id="req-1")
result = ops._write_row(request, operation, action="run", object_id="a-1", message="Core ran it", tactical_status=200)
must(result.get("recorded") is True, result)
must(ROWS[-1]["debug_info"]["operation_context"]["server_provenance"] == "tactical-operation", ROWS[-1])
print("[TEST] PASS audit private operation writer 1.17.8")
