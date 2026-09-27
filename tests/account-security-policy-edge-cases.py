#!/usr/bin/env python3
"""Behavioural coverage for D1 policy mutation edge cases L81/L82/L84."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


# Minimal package/runtime stubs let this exercise the real view without needing
# the Tactical Django/DRF environment in the build container.
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG)]
sys.modules["tec_tac"] = pkg

rf_response = types.ModuleType("rest_framework.response")
class Response:
    def __init__(self, data=None, status=200):
        self.data = data
        self.status_code = status
rf_response.Response = Response
sys.modules["rest_framework"] = types.ModuleType("rest_framework")
sys.modules["rest_framework.response"] = rf_response
rf_views = types.ModuleType("rest_framework.views")
class APIView:
    pass
rf_views.APIView = APIView
sys.modules["rest_framework.views"] = rf_views

# Load the real policy module first.
policy_spec = importlib.util.spec_from_file_location("tec_tac.account_security_policy", PKG / "account_security_policy.py")
policy = importlib.util.module_from_spec(policy_spec)
sys.modules[policy_spec.name] = policy
policy_spec.loader.exec_module(policy)

# L82: subprocess argv is not shell-parsed, so legitimate Tactical usernames
# containing '+' or Unicode must be accepted and passed intact.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    helper = td / "tec-tac-system-update"
    helper.write_text("#!/bin/sh\n")
    policy.SYSTEM_UPDATE_HELPER = helper
    policy.POLICY_FILE = td / "account-security-policy.json"
    policy.POLICY_FILE.write_text(json.dumps({
        "schema": 1,
        "protect_superuser_accounts": True,
        "updated_at": None,
        "updated_by": "existing",
    }))
    seen = {}
    class Result:
        stdout = json.dumps({"ok": True})
        stderr = ""
    def fake_run(command, **kwargs):
        seen["command"] = command
        return Result()
    original_run = policy.subprocess.run
    policy.subprocess.run = fake_run
    try:
        policy.set_policy(True, updated_by="Jöhn+Admin")
    finally:
        policy.subprocess.run = original_run
    require(seen["command"][-1] == "Jöhn+Admin", "Unicode/+ username was not preserved")

# Stub the remaining relative imports used by the view.
audit = types.ModuleType("tec_tac.audit")
class AuditContractError(ValueError):
    pass
class AuditWriteError(RuntimeError):
    pass
audit.AuditContractError = AuditContractError
audit.AuditWriteError = AuditWriteError
audit.record = lambda **kwargs: None
sys.modules["tec_tac.audit"] = audit

rbac = types.ModuleType("tec_tac.rbac")
rbac.is_effective_superuser = lambda user: bool(getattr(user, "effective_superuser", False))
sys.modules["tec_tac.rbac"] = rbac

session = types.ModuleType("tec_tac.session_security")
class SessionAuthenticated:
    pass
session.SessionAuthenticated = SessionAuthenticated
session.can_manage_account_security = lambda user: True
sys.modules["tec_tac.session_security"] = session

view_spec = importlib.util.spec_from_file_location("tec_tac.account_security_views", PKG / "account_security_views.py")
views = importlib.util.module_from_spec(view_spec)
sys.modules[view_spec.name] = views
view_spec.loader.exec_module(views)

class User:
    effective_superuser = True
    username = "root-admin"

class Request:
    user = User()
    def __init__(self, requested):
        self.data = {"protect_superuser_accounts": requested}

# L81: any strict audit failure, including AuditContractError, rolls back the
# requested change instead of returning with an unaudited policy state.
calls = []
views.get_policy = lambda: {"protect_superuser_accounts": False}
def set_valid(value, *, updated_by=""):
    calls.append(bool(value))
    return {"protect_superuser_accounts": bool(value)}
views.set_policy = set_valid
def fail_contract(**kwargs):
    raise AuditContractError("audit contract unavailable")
views.record = fail_contract
response = views.AccountSecurityPolicyView().put(Request(True))
require(response.status_code == 500, "audit failure did not reject policy change")
require(calls == [True, False], f"policy was not rolled back after AuditContractError: {calls}")

# L84: a corrupt existing policy remains repairable by an effective superuser.
# The audit explicitly records that the previous state was unreadable.
def corrupt_policy():
    raise policy.AccountSecurityPolicyError("corrupt")
views.get_policy = corrupt_policy
calls.clear()
recorded = {}
def record_ok(**kwargs):
    recorded.update(kwargs)
views.record = record_ok
response = views.AccountSecurityPolicyView().put(Request(False))
require(response.status_code == 200, "corrupt policy could not be repaired")
require(calls == [False], "repair did not write requested policy")
require(recorded.get("before") == {"policy_state": "unreadable"}, "repair audit did not mark unreadable prior state")
require(recorded.get("metadata", {}).get("repaired_corrupt_policy") is True, "repair audit metadata missing")

# If that repair cannot be audited, fail closed to protection=ON rather than
# retaining the requested unaudited value.
calls.clear()
views.record = fail_contract
response = views.AccountSecurityPolicyView().put(Request(False))
require(response.status_code == 500, "unaudited corrupt-policy repair was retained")
require(calls == [False, True], f"corrupt-policy audit failure did not fail closed: {calls}")

print("account-security-policy-edge-cases: PASS")
