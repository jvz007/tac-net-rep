#!/usr/bin/env python3
"""1.17.6 regression: rbac.has_tactical_permission and tactical_permission_flags mirror Tactical's _has_perm.

Loads the real rbac.py against stubs (Django is not installed here), as tests/runtime-settings-permission-1.17.2.py does.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


class Field:
    def __init__(self, kind):
        self.kind = kind

    def get_internal_type(self):
        return self.kind


class FieldDoesNotExist(Exception):
    pass


class Role:
    FIELDS = {"can_reboot_agents": "BooleanField", "can_send_wol": "BooleanField", "can_code_sign": "BooleanField",
              "can_view_clients": "ManyToManyField", "name": "CharField", "is_superuser": "BooleanField"}

    class _meta:
        @staticmethod
        def get_field(name):
            if name not in Role.FIELDS:
                raise FieldDoesNotExist(name)
            return Field(Role.FIELDS[name])


mods = {n: types.ModuleType(n) for n in ("accounts", "accounts.models", "tec_tac.registry")}
mods["accounts.models"].Role = Role
mods["tec_tac.registry"].get_plugins = lambda: ()
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(APP)]
sys.modules.update(mods)
sys.modules["tec_tac"] = pkg
spec = importlib.util.spec_from_file_location("tec_tac.rbac", APP / "rbac.py")
rbac = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rbac
spec.loader.exec_module(rbac)


class Granted:
    def __init__(self, **flags):
        self.is_superuser = flags.pop("is_superuser", False)
        self.__dict__.update(flags)


class User:
    def __init__(self, role=None, *, superuser=False, anonymous=False, installer=False, boom=False):
        self.is_authenticated = not anonymous
        self.is_superuser = superuser
        self.is_installer_user = installer
        self._role, self._boom = role, boom

    def get_and_set_role_cache(self):
        if self._boom:
            raise RuntimeError("db down")
        return self._role


has = rbac.has_tactical_permission
F = "can_reboot_agents"

must(has(User(superuser=True), F) is True, "django superuser passes with no role")
must(has(User(Granted(is_superuser=True)), F) is True, "role superuser passes")
must(has(User(Granted(can_reboot_agents=True)), F) is True, "granted flag")
must(has(User(Granted(can_reboot_agents=False)), F) is False, "flag false")
must(has(User(Granted()), F) is False, "missing flag attribute is denied")
must(has(User(None), F) is False, "no role is denied")
must(has(User(Granted(can_reboot_agents=True), installer=True), F) is False, "installer user is denied")
must(has(User(Granted(is_superuser=True), installer=True), F) is False, "installer user is denied even with a superuser role")
must(has(User(Granted(can_reboot_agents=True), anonymous=True), F) is False, "unauthenticated is denied")
must(has(None, F) is False, "no user is denied")
must(has(User(boom=True), F) is False, "a lookup error fails closed")

for bad in ("can_nothing", "name", "is_superuser", "can_view_clients", "", None, 5, "reboot"):
    try:
        has(User(superuser=True), bad)
    except ValueError:
        continue
    raise AssertionError(f"{bad!r} must raise ValueError")

# several flags at once: validated together, evaluated once
flags = rbac.tactical_permission_flags(User(Granted(can_reboot_agents=True, can_send_wol=False)), ["can_reboot_agents", "can_send_wol", "can_code_sign"])
must(flags == {"can_reboot_agents": True, "can_send_wol": False, "can_code_sign": False}, flags)
must(rbac.tactical_permission_flags(User(superuser=True), []) == {}, "empty list")
try:
    rbac.tactical_permission_flags(User(superuser=True), ["can_reboot_agents", "can_nothing"])
    raise AssertionError("one bad flag must raise")
except ValueError:
    pass
must(rbac.tactical_permission_flags(User(boom=True), ["can_send_wol"]) == {"can_send_wol": False}, "closed on error")

# has_extension_permission is unchanged: it still rejects a Tactical flag as an unknown codename
try:
    rbac.has_extension_permission(User(superuser=True), "can_reboot_agents")
    raise AssertionError("has_extension_permission must still refuse an unregistered codename")
except ValueError:
    pass

# contract row
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
names = {(r["import_path"], r["name"]): r for r in rows}
for name in ("has_tactical_permission", "tactical_permission_flags"):
    row = names[("tec_tac.rbac", name)]
    must(row["area"] == "rbac" and row["kind"] == "python", row)
print("tactical permission helper 1.17.6: ok")
