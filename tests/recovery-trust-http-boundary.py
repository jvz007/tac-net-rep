#!/usr/bin/env python3
"""D3 regression: recovery trust HTTP boundary is superuser-only, audited and async."""
from __future__ import annotations
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Minimal package/DRF stubs so this is a behavioural unit test with no Django runtime.
pkg = types.ModuleType("tec_tac"); pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg

rf = types.ModuleType("rest_framework")
rf.status = types.SimpleNamespace(HTTP_202_ACCEPTED=202)
sys.modules["rest_framework"] = rf
exc = types.ModuleType("rest_framework.exceptions")
class PermissionDenied(Exception): pass
class ValidationError(Exception): pass
exc.PermissionDenied = PermissionDenied; exc.ValidationError = ValidationError
sys.modules["rest_framework.exceptions"] = exc
resp = types.ModuleType("rest_framework.response")
class Response:
    def __init__(self, data, status=200): self.data=data; self.status_code=status
resp.Response=Response; sys.modules["rest_framework.response"] = resp
views = types.ModuleType("rest_framework.views")
class APIView: pass
views.APIView=APIView; sys.modules["rest_framework.views"] = views

calls = {"audit": [], "trust": [], "identity": 0, "status": []}

audit = types.ModuleType("tec_tac.audit")
class AuditContractError(Exception): pass
class AuditWriteError(Exception): pass
def record(**kwargs): calls["audit"].append(kwargs); return {"recorded": True}
audit.AuditContractError=AuditContractError; audit.AuditWriteError=AuditWriteError; audit.record=record
sys.modules["tec_tac.audit"] = audit

caps=types.ModuleType("tec_tac.capabilities")
def build_operation_context(**kwargs): return kwargs
caps.build_operation_context=build_operation_context; sys.modules["tec_tac.capabilities"] = caps

sb=types.ModuleType("tec_tac.server_backup")
class ServerBackupError(Exception): pass
def recovery_identity_core(**kwargs): calls["identity"] += 1; return {"installation_id":"target","server_name":"target-rmm"}
def recovery_trust_job_status_core(*, job_id): calls["status"].append(job_id); return {"job_id":job_id,"status":"running"}
def trust_recovery_signer_core(**kwargs): calls["trust"].append(kwargs); return {"job_id":"11111111-1111-4111-8111-111111111111","status":"queued","action":"trust_recovery_signer"}
sb.ServerBackupError=ServerBackupError; sb.recovery_identity_core=recovery_identity_core; sb.recovery_trust_job_status_core=recovery_trust_job_status_core; sb.trust_recovery_signer_core=trust_recovery_signer_core
sys.modules["tec_tac.server_backup"] = sb

ss=types.ModuleType("tec_tac.session_security")
class SessionAuthenticated: pass
ss.SessionAuthenticated=SessionAuthenticated; sys.modules["tec_tac.session_security"] = ss

spec=importlib.util.spec_from_file_location("tec_tac.server_backup_views", ROOT/"framwork"/"tec_tac"/"server_backup_views.py")
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

class User:
    is_authenticated=True
    def __init__(self, username, superuser=False): self.username=username; self.is_superuser=superuser; self.role=None
    def get_and_set_role_cache(self): return self.role
class Request:
    def __init__(self,user,data=None,query=None): self.user=user; self.data=data or {}; self.query_params=query or {}

view=mod.RecoveryTrustView()
normal=Request(User("normal"))
try:
    view.get(normal)
except PermissionDenied: pass
else: raise AssertionError("non-superuser recovery identity GET was allowed")
assert calls["identity"] == 0, "unauthorized GET dispatched a root identity job"

admin=User("admin", True)
identity=view.get(Request(admin))
assert identity.status_code == 200 and calls["identity"] == 1

# Raw browser destination objects are no longer accepted; the hardened fields are required.
try:
    view.post(Request(admin,{"backup_ref":"destination:remote-a:file.tgz","destination":{"id":"remote-a","host":"evil.example"}}))
except ValidationError: pass
else: raise AssertionError("legacy raw destination trust payload was accepted")
assert not calls["trust"] and not calls["audit"]

payload={
    "backup_ref":"destination:remote-a:file.tgz",
    "destination_id":"remote-a",
    "expected_key_id":"source-a",
    "expected_fingerprint":"AA"*32,
    "expected_server_name":"source-rmm",
    "expected_installation_id":"install-a",
}
out=view.post(Request(admin,payload))
assert out.status_code == 202 and out.data["status"] == "queued"
assert len(calls["audit"]) == 1
ar=calls["audit"][0]
assert ar["strict"] is True and ar["actor"].username == "admin"
assert ar["after"]["key_id"] == "source-a"
assert ar["after"]["public_key_sha256"] == ("aa"*32)
assert ar["after"]["server_name"] == "source-rmm" and ar["after"]["backup_ref"] == payload["backup_ref"]
assert len(calls["trust"]) == 1
tr=calls["trust"][0]
assert tr["destination_id"] == "remote-a" and "destination" not in tr
assert tr["expected_fingerprint"] == ("aa"*32)

poll=view.get(Request(admin,query={"job_id":"11111111-1111-4111-8111-111111111111"}))
assert poll.data["job"]["status"] == "running" and calls["status"]
print("[TEST] PASS D3 recovery trust HTTP authorization, strict audit and async boundary")
