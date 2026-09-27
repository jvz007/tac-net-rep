#!/usr/bin/env python3
"""L83 regression: malformed account-security schema fails closed, never as ValueError."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "account_security_policy.py"
spec = importlib.util.spec_from_file_location("account_security_policy_l83", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    policy = Path(td) / "account-security-policy.json"
    mod.POLICY_FILE = policy

    policy.write_text(json.dumps({"schema": "not-a-number", "protect_superuser_accounts": False}), encoding="utf-8")
    try:
        mod.get_policy()
    except mod.AccountSecurityPolicyError:
        pass
    except ValueError as exc:
        raise AssertionError("malformed schema escaped as ValueError") from exc
    else:
        raise AssertionError("malformed schema was accepted")

    if mod.protection_enabled() is not True:
        raise AssertionError("malformed policy did not fail closed")

    if mod.protection_enabled(fail_closed=False) is not False:
        raise AssertionError("explicit non-guard diagnostic read did not honor fail_closed=False")

print("account-security corrupt-schema fail-closed: PASS")
