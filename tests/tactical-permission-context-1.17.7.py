#!/usr/bin/env python3
"""1.17.7 regression: GET /api/tfd/ui/context/ carries tactical_permissions, from rbac.tactical_permission_catalog.

Loads the real rbac.py against stubs (Django is not installed here), as tests/tactical-permission-helper-1.17.6.py does.
"""
from __future__ import annotations

import ast
import importlib.util
import json
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
    def __init__(self, name, kind):
        self.name, self.kind = name, kind

    def get_internal_type(self):
        return self.kind


class FieldDoesNotExist(Exception):
    pass


class Role:
    # Order matters: the catalog keeps the order of the Role model's fields. A reverse relation has no internal type.
    FIELDS = [
        ("name", "CharField"), ("can_reboot_agents", "BooleanField"), ("can_view_clients", "ManyToManyField"),
        ("is_superuser", "BooleanField"), ("can_send_wol", "BooleanField"), ("can_code_sign", "BooleanField"),
        ("can_not_a_flag", "CharField"),
    ]

    class _meta:
        @staticmethod
        def get_field(name):
            for field_name, kind in Role.FIELDS:
                if field_name == name:
                    return Field(field_name, kind)
            raise FieldDoesNotExist(name)

        @staticmethod
        def get_fields():
            return [Field(n, k) for n, k in Role.FIELDS] + [SimpleReverse()]


class SimpleReverse:
    name = "can_reverse"

    def get_internal_type(self):
        raise AttributeError("a reverse relation has no internal type")


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
        self._role, self._boom, self.lookups = role, boom, 0

    def get_and_set_role_cache(self):
        self.lookups += 1
        if self._boom:
            raise RuntimeError("db down")
        return self._role


catalog = rbac.tactical_permission_catalog
FLAGS = ["can_reboot_agents", "can_send_wol", "can_code_sign"]

# every boolean can_* field is present, in model order; non-boolean fields, is_superuser and reverse relations are not
must(list(catalog(User(None))) == FLAGS, list(catalog(User(None))))
must(all(isinstance(value, bool) for value in catalog(User(None)).values()), "plain booleans")
# a django superuser and a role superuser have every flag
must(catalog(User(superuser=True)) == dict.fromkeys(FLAGS, True), "django superuser")
must(catalog(User(Granted(is_superuser=True))) == dict.fromkeys(FLAGS, True), "role superuser")
# a role's own flags are honoured; a missing attribute is false
must(catalog(User(Granted(can_reboot_agents=True, can_send_wol=False))) == {"can_reboot_agents": True, "can_send_wol": False, "can_code_sign": False}, "role flags")
# installer, no role, anonymous, no user and a lookup failure are all false
for label, user in (
    ("installer", User(Granted(can_reboot_agents=True), installer=True)),
    ("installer superuser role", User(Granted(is_superuser=True), installer=True)),
    ("no role", User(None)),
    ("anonymous", User(Granted(can_reboot_agents=True), anonymous=True)),
    ("no user", None),
    ("lookup failure", User(boom=True)),
):
    must(catalog(user) == dict.fromkeys(FLAGS, False), label)
# one role lookup for the whole catalog
counted = User(Granted(can_reboot_agents=True))
catalog(counted)
must(counted.lookups == 1, counted.lookups)
# the model cannot be listed: fail closed with an empty object, never raise
saved = Role._meta.get_fields
Role._meta.get_fields = staticmethod(lambda: (_ for _ in ()).throw(RuntimeError("model gone")))
must(catalog(User(superuser=True)) == {}, "unlistable model")
Role._meta.get_fields = saved
json.dumps(catalog(User(superuser=True)))
# the existing per-flag helper is unchanged
must(rbac.has_tactical_permission(User(Granted(can_send_wol=True)), "can_send_wol") is True, "has_tactical_permission")

# the view publishes it and keeps every earlier key in place
views = (APP / "views.py").read_text(encoding="utf-8")
must("    tactical_permission_catalog,\n" in views, "imported")
body = views.split("class UiContextView", 1)[1].split("class ExtensionPermissionCatalogView", 1)[0]
for earlier in ("user", "permissions", "extensions", "capabilities", "module_status", "notice_unread_count", "preferences",
                "module_register_timeout_seconds", "tactical_ui", "tactical_web_ui", "preferences_initialized", "preferences_updated_at"):
    must(f'"{earlier}"' in body, earlier)
must('"tactical_permissions": tactical_permission_catalog(request.user),' in body, "published")
must(body.index('"tactical_ui"') < body.index('"tactical_permissions"') < body.index('"tactical_web_ui"'), "stable position after tactical_ui")

# contract rows
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


row = {(r["import_path"], r["name"]): r for r in literal("CORE_CONTRACTS")}[("tec_tac.rbac", "tactical_permission_catalog")]
must(row["area"] == "rbac" and row["kind"] == "python" and "1.17.7" in row["purpose"] and "tactical_permissions" in row["purpose"], row)
context = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/ui/context/"]["GET"]
must("tactical_permissions" in context["response"] and "1.17.7" in context["response"]["tactical_permissions"], context)
must("module_register_timeout_seconds" in context["response"], "the 1.17.1 field stays")
browser = next(r for r in literal("BROWSER_CONTRACTS") if r.get("id") == "ui.authenticated.runtime-context")
must("tactical_permissions.<flag>" in browser["operations"] and "module_register_timeout_seconds" in browser["operations"], browser["operations"])
must("Tactical permission flags in the runtime context" in (ROOT / "docs" / "tactical-operations.md").read_text(encoding="utf-8"), "docs")
print("[TEST] PASS tactical permission context 1.17.7")
