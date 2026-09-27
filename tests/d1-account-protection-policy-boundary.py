#!/usr/bin/env python3
"""D1 closure guard: superuser-account protection remains a Core policy setting."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


# Exercise the real policy parser without Django/Tactical dependencies.
spec = importlib.util.spec_from_file_location("d1_account_security_policy", PKG / "account_security_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

with tempfile.TemporaryDirectory() as td:
    policy.POLICY_FILE = Path(td) / "account-security-policy.json"

    # D1 is a policy decision, not an unconditional account lockout.
    require(policy.get_policy()["protect_superuser_accounts"] is False, "D1 default must remain policy-off")
    require(policy.protection_enabled() is False, "missing D1 policy must preserve the documented default-off state")

    policy.POLICY_FILE.write_text(json.dumps({
        "schema": 1,
        "protect_superuser_accounts": True,
        "updated_at": None,
        "updated_by": "test",
    }), encoding="utf-8")
    require(policy.protection_enabled() is True, "D1 enabled policy was not enforced")

    policy.POLICY_FILE.write_text(json.dumps({
        "schema": 1,
        "protect_superuser_accounts": False,
        "updated_at": None,
        "updated_by": "test",
    }), encoding="utf-8")
    require(policy.protection_enabled() is False, "D1 disabled policy did not restore native account behavior")

    # Corrupt explicit policy remains fail-closed; this is recovery behavior,
    # not a change to the documented default for an absent policy file.
    policy.POLICY_FILE.write_text("{broken", encoding="utf-8")
    require(policy.protection_enabled() is True, "corrupt D1 policy did not fail closed")


guard_source = (PKG / "tactical_account_guard.py").read_text(encoding="utf-8")
views_source = (PKG / "account_security_views.py").read_text(encoding="utf-8")
docs_source = (ROOT / "docs" / "account-security-policy.md").read_text(encoding="utf-8")

# Existing-superuser account protection must consult the policy at the native
# Tactical mutation boundary. The separate privilege-grant boundary remains
# unconditional by design and is not governed by D1.
protected_fn = guard_source.split("def _protected_account_violation", 1)[1].split("\ndef ", 1)[0]
require("if not protection_enabled():" in protected_fn, "native superuser-account guard no longer consults D1 policy")
require("return None" in protected_fn, "D1 policy-off path no longer preserves Tactical behavior")

role_flag_fn = guard_source.split("def _role_flag_violation", 1)[1].split("\ndef ", 1)[0]
require("protection_enabled" not in role_flag_fn, "superuser grant/revoke boundary was incorrectly made optional")

# Reading is available to account-security admins, while changing the global
# policy requires effective-superuser authority.
require("can_manage_account_security(request.user)" in views_source, "D1 policy read authorization drifted")
require("if not is_effective_superuser(request.user):" in views_source, "D1 policy mutation is no longer superuser-only")
require('"protect_superuser_accounts" not in request.data' in views_source, "D1 policy PUT no longer requires the explicit setting")

# Documentation is part of the decision contract.
require("`protect_superuser_accounts` defaults to `false`" in docs_source, "D1 default-off policy is no longer documented")
require("Only an effective superuser can change it" in docs_source, "D1 mutation authority is no longer documented")

print("d1-account-protection-policy-boundary: PASS")
