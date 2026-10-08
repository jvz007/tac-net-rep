#!/usr/bin/env python3
"""1.17.2 CQ10 regression: core.runtime_settings.manage lets a role change runtime settings.

Loads the real rbac.py and runtime_settings.py against stubs (Django is not installed here).
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
NEW = "core.runtime_settings.manage"
PRIV = "core.privileged_operations"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class Role:
    pass


GRANTS: dict[int, set[str]] = {}
LOOKUP_FAILS = {"on": False}


class _Qs:
    def __init__(self, hit):
        self.hit = hit

    def exists(self):
        if LOOKUP_FAILS["on"]:
            raise RuntimeError("db down")
        return self.hit


class Permission:
    class objects:
        @staticmethod
        def filter(role_id, codename, granted):
            return _Qs(codename in GRANTS.get(role_id, set()))


def passthrough(*a, **k):
    return lambda fn: fn


names = ("django", "django.db", "drf_spectacular", "drf_spectacular.utils", "rest_framework",
         "rest_framework.exceptions", "rest_framework.response", "rest_framework.views", "accounts",
         "accounts.models", "tec_tac.registry", "tec_tac.models", "tec_tac.session_security",
         "tec_tac.throttles", "tec_tac.audit")
mods = {n: types.ModuleType(n) for n in names}
mods["accounts.models"].Role = Role
mods["tec_tac.registry"].get_plugins = lambda: ()


class Atomic:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


mods["django.db"].transaction = types.SimpleNamespace(atomic=lambda: Atomic())
mods["drf_spectacular.utils"].extend_schema = passthrough
mods["drf_spectacular.utils"].extend_schema_view = passthrough
mods["rest_framework.exceptions"].PermissionDenied = PermissionDenied
mods["rest_framework.response"].Response = Response
mods["rest_framework.views"].APIView = type("APIView", (), {})
mods["tec_tac.session_security"].SessionAuthenticated = type("SessionAuthenticated", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteMinThrottle = type("Min", (), {})
mods["tec_tac.throttles"].RuntimeSettingsWriteDayThrottle = type("Day", (), {})
mods["tec_tac.audit"].record = lambda **kw: None


class Config:
    pk = 1
    module_register_timeout_seconds = 30
    updated_at = None
    updated_by = None

    def save(self, update_fields=None):
        pass


CONFIG = Config()


class TecTacRuntimeConfig:
    @classmethod
    def current(cls):
        return CONFIG

    class objects:
        @staticmethod
        def select_for_update():
            return types.SimpleNamespace(get=lambda pk: CONFIG)


mods["tec_tac.models"].TecTacRuntimeConfig = TecTacRuntimeConfig
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)
sys.modules["tec_tac"] = pkg


def load(name):
    spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


rbac = load("rbac")
rbac._permission_model = lambda: Permission
rs = load("runtime_settings")


class User:
    def __init__(self, *, role_id=None, superuser=False, role_superuser=False, anonymous=False):
        self.is_authenticated = not anonymous
        self.is_superuser = superuser
        self.username = "u"
        self._role = types.SimpleNamespace(id=role_id, is_superuser=role_superuser) if role_id is not None else None

    def get_and_set_role_cache(self):
        return self._role


GRANTS[1] = {NEW}
GRANTS[2] = {PRIV}
GRANTS[3] = {"core.resources.clients.manage"}
users = {
    "superuser": User(superuser=True),
    "role superuser": User(role_id=9, role_superuser=True),
    "new codename": User(role_id=1),
    "privileged": User(role_id=2),
    "neither": User(role_id=3),
}
for who, ok in (("superuser", True), ("role superuser", True), ("new codename", True), ("privileged", True), ("neither", False)):
    must(rbac.can_manage_runtime_settings(users[who]) is ok, f"{who}: expected {ok}")
must(rbac.can_manage_runtime_settings(User(anonymous=True)) is False, "anonymous must be refused")
must(rbac.can_manage_runtime_settings(User()) is False, "a user with no role must be refused")

# Holding the new codename does not make a user a privileged-operations holder.
must(rbac.can_manage_privileged_operations(users["new codename"]) is False, "new codename must not grant privileged operations")

LOOKUP_FAILS["on"] = True
must(rbac.can_manage_runtime_settings(users["new codename"]) is False, "a failing lookup must read as False")
LOOKUP_FAILS["on"] = False

# Catalog: group exists and the codename is registered.
must(rbac.CORE_PERMISSION_GROUPS["Runtime settings"] == (NEW,), "group missing")
must(NEW in rbac.registered_permissions(()), "codename not registered")
core = rbac.permission_catalog(())[0]
must(NEW in core["permissions"] and any(g["name"] == "Runtime settings" for g in core["groups"]), "catalog missing the codename")
must(PRIV in rbac.CORE_PERMISSION_GROUPS["Privileged operations"], "privileged group must stay")

# View behaviour.
view = rs.RuntimeSettingsView()
body = {"module_register_timeout_seconds": 60}
for who in ("superuser", "new codename", "privileged"):
    CONFIG.module_register_timeout_seconds = 30
    resp = view.patch(types.SimpleNamespace(user=users[who], data=dict(body)))
    must(resp.status_code == 200 and CONFIG.module_register_timeout_seconds == 60, f"{who} must be able to PATCH")
CONFIG.module_register_timeout_seconds = 30
try:
    view.patch(types.SimpleNamespace(user=users["neither"], data=dict(body)))
except PermissionDenied as exc:
    must(NEW in str(exc) and PRIV in str(exc), "403 message must name both rights")
else:
    raise AssertionError("a user with neither right must get 403")
must(CONFIG.module_register_timeout_seconds == 30, "a refused PATCH must change nothing")
must(view.get(types.SimpleNamespace(user=users["neither"])).status_code == 200, "any signed-in user may GET")

# Role-editor PUT: the new codename is not superuser-gated; privileged operations still is.
src = (APP / "views.py").read_text(encoding="utf-8")
cls = next(n for n in ast.parse(src).body if isinstance(n, ast.ClassDef) and n.name == "RoleExtensionPermissionsView")
put = ast.get_source_segment(src, next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "put"))
must("CORE_PRIVILEGED_PERMISSION" in put and "is_effective_superuser" in put, "privileged gate must remain in the role editor")
must("runtime_settings" not in put.lower() and NEW not in put, "the role editor must not gate the new codename")

# Update-source PATCH uses the same rule.
us = (APP / "runtime_settings.py").read_text(encoding="utf-8")
must(us.count("can_manage_runtime_settings(request.user)") >= 1, "views must use can_manage_runtime_settings")
print("[TEST] PASS 1.17.2 runtime settings permission core.runtime_settings.manage")
