#!/usr/bin/env python3
"""1.17.6 regression: record() refuses forged Core keys.

Amended in 1.17.7: AD-19 brought the executor back, so the absence checks are gone. The executor, the third key
(server_provenance) and the deprecation are covered by tests/tactical-operations-1.17.7.py and
tests/audit-server-provenance-1.17.7.py.

Closes the held 1.17.0 Low 'browser_provenance is still forgeable through backend record()'. Reuses the stub harness of
tests/audit-declared-browser-events-1.17.0.py (everything before its first scenario), so the real audit.py and
audit_views.py run with only the Tactical ORM boundary faked. Django is not installed on the development PC.
"""
from __future__ import annotations

import ast
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
for key, value in (("browser_provenance", "module-declared-event"), ("core_refusal", True), ("core_refusal", False)):
    reset()
    refuses(lambda key=key, value=value: audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", operation_context={key: value}), key)
    refuses(lambda key=key, value=value: audit.get_audit_provider().record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", operation_context={key: value}), key)
    must(not ROWS, "a refused call writes nothing")
must(audit.CORE_CONTEXT_KEYS == ("browser_provenance", "core_refusal", "server_provenance"), audit.CORE_CONTEXT_KEYS)
# A normal context, and build_operation_context-shaped keys, still pass.
reset()
res = audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent",
                   operation_context={"source_module": "x", "source_action": "y", "source_run_id": None, "requested_by": None})
must(res["recorded"] is True and ROWS[0]["debug_info"]["operation_context"]["source_module"] == "x", res)
# Metadata cannot carry them into operation_context.
reset()
audit.record(actor=tech, module_id="declaring-demo", action="view", object_type="agent", metadata={"browser_provenance": "x"})
must("browser_provenance" not in ROWS[0]["debug_info"]["operation_context"], ROWS[0])

# ------------------------------------------------------------------ 2. oversized operation_context keeps the Core keys
audit_limit = types.ModuleType("django.conf")


class _Settings:
    AUDIT_MAX_VALUE_BYTES = 512 * 2**10


audit_limit.settings = _Settings
saved_conf = sys.modules.get("django.conf")
sys.modules["django.conf"] = audit_limit
try:
    reset()
    audit._record_row(
        actor=tech, module_id="declaring-demo", action="view", object_type="agent", object_id="a-1",
        operation_context={"blob": "o" * (600 * 1024), "core_refusal": True, "browser_provenance": "module-declared-event"},
    )
    ctx = ROWS[0]["debug_info"]["operation_context"]
    must("error" in ctx and ctx["core_refusal"] is True and ctx["browser_provenance"] == "module-declared-event", ctx)
    must(len(json.dumps(ROWS[0]["debug_info"]).encode()) <= _Settings.AUDIT_MAX_VALUE_BYTES, "row fits")
finally:
    if saved_conf is None:
        sys.modules.pop("django.conf", None)
    else:
        sys.modules["django.conf"] = saved_conf

# ------------------------------------------------------------------ 3. the declared browser path: unchanged answers, no deprecation, no server path
reset()
ok = post(tech)
must(ok.status_code == 201, ok.status_code)
must(ROWS[0]["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event"}, ROWS[0])
reset()
gone = post(tech, object_id="a-2")
must(gone.status_code == 404 and gone.data["recorded"] is False, (gone.status_code, gone.data))
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
must(ROWS[0]["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event", "core_refusal": True}, ROWS)
reset()
GRANTED.add("both-demo.use")
perm = post(tech, module_id="both-demo", action="view", object_type="agent", object_id="a-1")
must(perm.status_code == 201 and ROWS[0]["debug_info"]["operation_context"] == {}, "the permissioned path sets no marker")
GRANTED.clear()
# ------------------------------------------------------------------ 4. contract and docs text
tree = ast.parse((PKG / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


details = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/audit/record/"]["POST"]
must("browser_provenance since 1.17.6" in json.dumps(details), details)
record_row = next(r for r in literal("CORE_CONTRACTS") if r["name"] == "record" and r["area"] == "audit")
must("Since 1.17.6 operation_context may not carry browser_provenance or core_refusal" in record_row["purpose"], record_row)
docs = (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8")
must("`browser_provenance`" in docs and "AD-8" in docs, "docs")
print("[TEST] PASS audit provenance hardening 1.17.6")
