#!/usr/bin/env python3
"""1.17.115 regression: ``tec_tac.rbac.is_effective_superuser`` is public and fails closed.

The real function is cut out of rbac.py by AST (the module needs Tactical's Role model, and Django is not installed here). Covered: a Django
superuser and a role superuser are True; neither, anonymous, an inactive superuser, a truthy non-bool flag (1, 'yes') and a role cache that
raises are False; a user object without the cache method falls back to ``user.role``; a broken object never raises; the contract row is
present with the right import path and framework floor; the existing consumers keep their test (1.17.29 and 1.17.30 are re-run by the release).
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


tree = ast.parse((APP / "rbac.py").read_text(encoding="utf-8"))
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "is_effective_superuser")
ns: dict = {}
exec(compile(ast.Module(body=[fn], type_ignores=[]), "rbac.py", "exec"), ns)  # noqa: S102 - the real function, not user input
check = ns["is_effective_superuser"]


class Role:
    def __init__(self, flag):
        self.is_superuser = flag


class User:
    def __init__(self, *, auth=True, active=None, superuser=False, role=None, cache="ok"):
        self.is_authenticated = auth
        if active is not None:
            self.is_active = active
        self.is_superuser = superuser
        self.role = role
        self._cache = cache

    def get_and_set_role_cache(self):
        if self._cache == "raise":
            raise RuntimeError("cache failed")
        return self.role


class NoCache:
    """A user object with no get_and_set_role_cache."""

    def __init__(self, role=None, superuser=False):
        self.is_authenticated = True
        self.is_superuser = superuser
        self.role = role


must(check(User(superuser=True)) is True, "Django superuser")
must(check(User(role=Role(True))) is True, "role superuser")
must(check(User(superuser=True, role=Role(True), active=True)) is True, "both, explicitly active")
must(check(User(role=Role(False))) is False, "role without the flag")
must(check(User()) is False, "no role")
must(check(User(auth=False, superuser=True)) is False, "anonymous")
must(check(User(auth=1, superuser=True)) is False, "authenticated must be exactly True")
must(check(User(superuser=True, active=False)) is False, "inactive Django superuser")
must(check(User(role=Role(True), active=False)) is False, "inactive role superuser")
for odd in (1, "yes", object()):
    must(check(User(superuser=odd)) is False, f"truthy non-bool superuser {odd!r}")
    must(check(User(role=Role(odd))) is False, f"truthy non-bool role flag {odd!r}")
must(check(User(role=Role(True), cache="raise")) is False, "a failing role read fails closed")
must(check(User(superuser=True, cache="raise")) is True, "the Django flag needs no role read")
must(check(NoCache(role=Role(True))) is True, "no cache method falls back to user.role")
must(check(NoCache(role=Role(False))) is False and check(NoCache()) is False, "fallback without the flag")
must(check(None) is False and check(object()) is False and check("x") is False, "odd objects")


class Exploding:
    @property
    def is_authenticated(self):
        raise RuntimeError("boom")


class ExplodingFlag:
    is_authenticated = True

    @property
    def is_superuser(self):
        raise RuntimeError("boom")


must(check(Exploding()) is False and check(ExplodingFlag()) is False, "a broken object never raises")
must(isinstance(check(User(superuser=True)), bool), "always a bool")

# ---- the contract row
contracts_tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
text = (APP / "contracts.py").read_text(encoding="utf-8")
must('"name": "is_effective_superuser"' in text and "requires framework >=1.17.115" in text, "contract row")
start = text.index('"name": "is_effective_superuser"')
row = text[text.rfind("{", 0, start):text.index("},", start)]
must('"area": "rbac"' in row and '"import_path": "tec_tac.rbac"' in row and '"audience": "backend"' in row, row)
must("Fails closed" in row and "never raises" in row, row)
must(ast.dump(contracts_tree) is not None, "contracts.py parses")
print("rbac-effective-superuser-public-1.17.115: ok")
