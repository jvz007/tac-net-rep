#!/usr/bin/env python3
"""1.17.7 regression: Core-owned server provenance and record() refusing forged Core keys.

Closes the held 1.17.0 Low 'browser_provenance is still forgeable through backend record()'. Reuses the stub harness of
tests/audit-declared-browser-events-1.17.0.py (everything before its first scenario), so the real audit.py and
audit_views.py run with only the Tactical ORM boundary faked. Django is not installed on the development PC.
"""
from __future__ import annotations

import ast
import inspect
import json
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
audit, audit_views, ROWS, reset, post, tech = H["audit"], H["audit_views"], H["ROWS"], H["reset"], H["post"], H["tech"]
ROOT, PKG = H["ROOT"], H["PKG"]
GRANTED = H["GRANTED"]


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def refuses(fn, key):
    try:
        fn()
    except audit.AuditContractError as exc:
        must(key in str(exc) and "Core-owned" in str(exc), str(exc))
        return
    raise AssertionError(f"{key} was accepted")


# ------------------------------------------------------------------ 1. record() refuses every Core-owned key
for key, value in (("browser_provenance", "module-declared-event"), ("server_provenance", "tactical-operation"), ("core_refusal", True), ("core_refusal", False)):
    reset()
    refuses(lambda: audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", operation_context={key: value}), key)
    refuses(lambda: audit.get_audit_provider().record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", operation_context={key: value}), key)
    must(not ROWS, "a refused call writes nothing")
must(audit.CORE_CONTEXT_KEYS == ("browser_provenance", "core_refusal", "server_provenance"), audit.CORE_CONTEXT_KEYS)
# A normal context, and build_operation_context-shaped keys, still pass.
reset()
res = audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent",
                   operation_context={"source_module": "x", "source_action": "y", "source_run_id": None, "requested_by": None})
must(res["recorded"] is True and ROWS[0]["debug_info"]["operation_context"]["source_module"] == "x", res)
# Metadata cannot carry them into operation_context.
reset()
audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", metadata={"server_provenance": "tactical-operation"})
must("server_provenance" not in ROWS[0]["debug_info"]["operation_context"], ROWS[0])

# ------------------------------------------------------------------ 2. the executor's internal call
# A person with no module grant: the public record() refuses, Core's own call does not.
reset()
GRANTED.clear()
real_check = audit._actor_can_use_module
audit._actor_can_use_module = lambda actor, module: False
try:
    audit.record(actor=tech, module_id="declaring-demo", action="run", object_type="agent", object_id="a-1")
    raise AssertionError("record() let a person without a module grant write")
except audit.AuditContractError as exc:
    must("not permitted" in str(exc), exc)
res = audit.record_tactical_operation(
    actor=tech, module_id="declaring-demo", action="run", object_type="agent", object_id="a-1", message="Core ran it",
    after={"mode": "now"}, metadata={"operation": "reboot"}, operation="reboot", tactical_status=200,
)
must(res["recorded"] is True and res["username"] == "tech" and res["module_id"] == "declaring-demo", res)
row = ROWS[-1]
must(row["username"] == "tech" and row["action"] == "run" and row["after_value"] == {"mode": "now"}, row)
ctx = row["debug_info"]["operation_context"]
must(ctx == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": 200}, ctx)
must(row["debug_info"]["actor_kind"] == "human" and row["debug_info"]["actor_identity"] == "tech", row["debug_info"])
must(row["debug_info"]["module_id"] == "declaring-demo" and row["debug_info"]["module_version"] == "2.0.0", row["debug_info"])
# a refusal row also carries core_refusal
audit.record_tactical_operation(actor=tech, module_id="declaring-demo", action="deny", object_type="agent", object_id="a-1", message="m",
                                operation="reboot", tactical_status=None, refusal=True)
ctx = ROWS[-1]["debug_info"]["operation_context"]
must(ctx == {"server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": None, "core_refusal": True}, ctx)
# the internal call still needs an authenticated actor and a known module
for bad_actor in (types.SimpleNamespace(is_authenticated=False, username="x"), types.SimpleNamespace(is_authenticated=True, username="")):
    try:
        audit.record_tactical_operation(actor=bad_actor, module_id="declaring-demo", action="run", object_type="agent", operation="r")
        raise AssertionError("bad actor accepted")
    except audit.AuditContractError:
        pass
try:
    audit.record_tactical_operation(actor=tech, module_id="missing-demo", action="run", object_type="agent", operation="r")
    raise AssertionError("unknown module accepted")
except audit.AuditContractError:
    pass
audit._actor_can_use_module = real_check
# the authority value is not reachable through the public surface
must("authority" not in inspect.signature(audit.record).parameters, "record() must not accept authority")
must("authority" not in inspect.signature(audit.AuditProvider.record).parameters, "provider.record() must not accept authority")

# ------------------------------------------------------------------ 3. oversized operation_context keeps the Core keys
audit_limit = types.ModuleType("django.conf")


class _Settings:
    AUDIT_MAX_VALUE_BYTES = 512 * 2**10


audit_limit.settings = _Settings
saved_conf = sys.modules.get("django.conf")
sys.modules["django.conf"] = audit_limit
try:
    reset()
    audit._record_row(
        actor=tech, module_id="declaring-demo", action="run", object_type="agent", object_id="a-1", authority=audit._TACTICAL_OPERATION_AUTHORITY,
        operation_context={"blob": "o" * (600 * 1024), "server_provenance": "tactical-operation", "operation": "reboot", "tactical_status": 502,
                           "core_refusal": True, "browser_provenance": "module-declared-event"},
    )
    ctx = ROWS[0]["debug_info"]["operation_context"]
    must("error" in ctx and ctx["server_provenance"] == "tactical-operation" and ctx["operation"] == "reboot" and ctx["tactical_status"] == 502, ctx)
    must(ctx["core_refusal"] is True and ctx["browser_provenance"] == "module-declared-event", ctx)
    must(len(json.dumps(ROWS[0]["debug_info"]).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES, "row fits")
    marker = {}
    audit._keep_browser_provenance(marker, {"server_provenance": "x" * 101, "operation": "r"})
    must(marker == {}, marker)
    marker = {}
    audit._keep_browser_provenance(marker, {"server_provenance": "tactical-operation", "tactical_status": True})
    must(marker == {"server_provenance": "tactical-operation"}, marker)
finally:
    if saved_conf is None:
        sys.modules.pop("django.conf", None)
    else:
        sys.modules["django.conf"] = saved_conf

# ------------------------------------------------------------------ 6. contract and docs text
tree = ast.parse((PKG / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


details = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/audit/record/"]["POST"]
must("server_provenance" in json.dumps(details) and "Core-owned" in json.dumps(details), details)
record_row = next(r for r in literal("CORE_CONTRACTS") if r["name"] == "record" and r["area"] == "audit")
must("server_provenance" in record_row["purpose"] and "core.tactical_operations" in record_row["purpose"], record_row)
docs = (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8")
must("`server_provenance`" in docs and "AD-19" in docs and "AD-8" in docs, "the doc names the third key, AD-8 and AD-19")
print("[TEST] PASS audit server provenance 1.17.7")
