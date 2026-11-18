#!/usr/bin/env python3
"""Regression: the dummy backup-code hash is built on first use, not at import (Core 1.18.1)."""
import ast
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"

calls = {"make": [], "check": []}


def fake_make_password(value, *args, **kwargs):
    calls["make"].append(value)
    return f"hash-{len(calls['make'])}"


def fake_check_password(value, encoded, *args, **kwargs):
    calls["check"].append((value, encoded))
    return False


def stub(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    sys.modules[name] = mod
    return mod


stub("pyotp")
stub("django")
stub("django.conf", settings=types.SimpleNamespace())
stub("django.contrib")
stub("django.contrib.auth")
stub("django.contrib.auth.hashers", make_password=fake_make_password, check_password=fake_check_password)
stub("django.db", transaction=types.SimpleNamespace())
stub("django.utils", timezone=types.SimpleNamespace())
package = types.ModuleType("tec_tac")
package.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package
stub("tec_tac.models", TecTacMfaBackupCode=object)
stub("tec_tac.session_security", SessionSecurityError=Exception, _audit=lambda *a, **k: None)

mfa = importlib.import_module("tec_tac.mfa_backup")

# (1) nothing hashed at import
assert calls["make"] == [], calls
assert not hasattr(mfa, "_DUMMY_CODE_HASH")

# (2) first call: one hash, ten checks, all against that hash
mfa.burn_backup_code_hash_cost()
assert len(calls["make"]) == 1, calls["make"]
assert len(calls["check"]) == mfa.BACKUP_CODE_COUNT == 10
assert {encoded for _, encoded in calls["check"]} == {"hash-1"}
assert all(value == "TEC-TAC-INVALID-CODE" for value, _ in calls["check"])

# (3) second call: cached hash, same check budget
mfa.burn_backup_code_hash_cost()
assert len(calls["make"]) == 1
assert len(calls["check"]) == 20

# (4) explicit budgets
before = len(calls["check"])
mfa.burn_backup_code_hash_cost(checks=3)
assert len(calls["check"]) - before == 3
mfa.burn_backup_code_hash_cost(checks=0)
mfa.burn_backup_code_hash_cost(checks=-2)
assert len(calls["check"]) - before == 3
assert len(calls["make"]) == 1

# (5) no module-level statement calls make_password
tree = ast.parse((PKG_DIR / "mfa_backup.py").read_text(encoding="utf-8"))
for node in tree.body:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        continue
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            name = getattr(func, "id", getattr(func, "attr", ""))
            assert name != "make_password", f"module-level make_password at line {node.lineno}"

print("mfa backup lazy dummy hash 1.18.1 regression: PASS")
