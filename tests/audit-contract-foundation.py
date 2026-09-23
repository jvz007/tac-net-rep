#!/usr/bin/env python3
import importlib.util
import inspect
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "framwork" / "tec_tac" / "audit.py"
spec = importlib.util.spec_from_file_location("audit_contract_subject", path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class Actor:
    is_authenticated = True
    is_superuser = True
    username = "alice"

class Row:
    pk = 42

class Manager:
    def __init__(self): self.rows=[]; self.fail=False
    def create(self, **kwargs):
        if self.fail: raise RuntimeError("db down")
        self.rows.append(kwargs); return Row()

class FakeAuditLog:
    objects = Manager()

def resolve(mid):
    if mid == "missing": raise audit.AuditContractError("Unknown Tec-Tac module_id: missing")
    return {"id": mid, "version":"9.9.9", "permissions":(), "legacy":False}

audit._resolve_module = resolve
audit._actor_can_use_module = lambda actor, module: getattr(actor, "is_authenticated", False)
audit._auditlog_model = lambda: FakeAuditLog

# Standard create/modify/delete/action vocabulary.
for action in ("add", "modify", "delete", "run", "approve", "deny", "enable", "disable", "install", "uninstall"):
    result = audit.record(actor=Actor(), module_id="demo", action=action, object_type="thing", object_id="7", message="event")
    assert result["recorded"] is True and result["action"] == action
assert len(FakeAuditLog.objects.rows) == 10

# Tactical field compatibility + before/after JSON and provenance.
before={"name":"old"}; after={"name":"new"}
audit.record(actor=Actor(), module_id="demo", action="modify", object_type="patch_profile", object_id=123, before=before, after=after, metadata={"ticket":1})
row=FakeAuditLog.objects.rows[-1]
assert row["username"] == "alice"
assert row["before_value"] == before and row["after_value"] == after
assert row["debug_info"]["source"] == "tec-tac"
assert row["debug_info"]["module_id"] == "demo"
assert row["debug_info"]["module_version"] == "9.9.9"
assert row["debug_info"]["object_id"] == "123"
assert row["debug_info"]["metadata"] == {"ticket":1}
assert set(row) == {"username","action","object_type","before_value","after_value","message","debug_info"}

# Actor spoof prevention: public backend signature has actor but no username.
sig = inspect.signature(audit.record)
assert "actor" in sig.parameters and "username" not in sig.parameters
try:
    audit.record(actor=Actor(), username="mallory", module_id="demo", action="view", object_type="thing")
    raise AssertionError("username spoof unexpectedly accepted")
except TypeError:
    pass

# Missing/invalid module IDs and restricted authenticated users.
try:
    audit.record(actor=Actor(), module_id="missing", action="view", object_type="thing")
    raise AssertionError("missing module accepted")
except audit.AuditContractError:
    pass
try:
    audit._normalize_object_type("Bad Object Type")
    raise AssertionError("invalid object type accepted")
except audit.AuditContractError:
    pass
class Restricted:
    is_authenticated = True
    is_superuser = False
    username = "restricted"
    allowed = False
audit._actor_can_use_module = lambda actor, module: getattr(actor, "allowed", True)
try:
    audit.record(actor=Restricted(), module_id="demo", action="view", object_type="thing")
    raise AssertionError("restricted actor accepted")
except audit.AuditContractError:
    pass
audit._actor_can_use_module = lambda actor, module: getattr(actor, "is_authenticated", False)

# Invalid actions/object IDs and controlled fallback.
try:
    audit.record(actor=Actor(), module_id="demo", action="made up action", object_type="thing")
    raise AssertionError("invalid action accepted")
except audit.AuditContractError:
    pass
assert audit.record(actor=Actor(), module_id="demo", action="custom:recalculate", object_type="thing")["recorded"]

# Oversized metadata becomes a safe marker while provenance remains present.
huge={"blob":"x"*(600*1024)}
audit.record(actor=Actor(), module_id="demo", action="view", object_type="thing", metadata=huge)
meta=FakeAuditLog.objects.rows[-1]["debug_info"]
assert meta["source"] == "tec-tac" and meta["module_id"] == "demo"
assert "error" in meta["metadata"]

# Audit persistence failure is non-fatal by default and strict when requested.
FakeAuditLog.objects.fail=True
result=audit.record(actor=Actor(), module_id="demo", action="view", object_type="thing")
assert result["recorded"] is False and result["error"] == "audit_write_failed"
try:
    audit.record(actor=Actor(), module_id="demo", action="view", object_type="thing", strict=True)
    raise AssertionError("strict failure did not raise")
except audit.AuditWriteError:
    pass

print("[TEST] PASS Tec-Tac audit write contract behavior")
