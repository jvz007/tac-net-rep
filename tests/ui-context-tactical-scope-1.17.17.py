#!/usr/bin/env python3
"""1.17.17 regression: GET /api/tfd/ui/context/ carries tactical_scope (mode and counts only), from resources_adapter.role_scope_descriptor.

Loads the real adapter against stubs (Django is not installed here), as tests/tactical-permission-context-1.17.7.py does for the
permission flags, and compiles the view helper out of views.py. The ids stay in the Python contract: the browser payload never
carries an id list, so the startup response stays small (CQ55, assumed answer a).
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


for name, attrs in (
    ("django", {}),
    ("django.core", {}),
    ("django.core.exceptions", {"ValidationError": type("ValidationError", (Exception,), {})}),
    ("django.db", {"IntegrityError": type("IntegrityError", (Exception,), {}), "transaction": types.SimpleNamespace(atomic=contextlib.nullcontext)}),
    ("django.db.models", {"Q": object}),
):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
spec = importlib.util.spec_from_file_location("adapter_real", APP / "resources_adapter.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class Relation:
    def __init__(self, ids=(), boom=False):
        self.ids, self.boom = list(ids), boom

    def exists(self):
        if self.boom:
            raise RuntimeError("down")
        return bool(self.ids)

    def values_list(self, *fields, flat=False):
        if self.boom:
            raise RuntimeError("down")
        return list(self.ids)


class Role:
    def __init__(self, clients=(), sites=(), superuser=False, boom=False):
        self.can_view_clients, self.can_view_sites, self.is_superuser = Relation(clients, boom), Relation(sites, boom), superuser


class User:
    def __init__(self, role=None, *, superuser=False, installer=False, anonymous=False, boom=False):
        self.is_authenticated, self.is_superuser, self.is_installer_user = not anonymous, superuser, installer
        self._role, self._boom = role, boom
        self.role = None

    def get_and_set_role_cache(self):
        if self._boom:
            raise RuntimeError("db down")
        return self._role


# the helper, compiled from the real views.py with the real adapter behind it
tree = ast.parse((APP / "views.py").read_text(encoding="utf-8"))
helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_tactical_scope_context")
namespace = {"resources_adapter": adapter}
exec(compile(ast.Module(body=[helper], type_ignores=[]), "views.py", "exec"), namespace)
scope = namespace["_tactical_scope_context"]
KEYS = ["mode", "unrestricted", "whole_client_count", "site_count"]
NONE = {"mode": "none", "unrestricted": False, "whole_client_count": 0, "site_count": 0}

cases = (
    ("superuser", User(superuser=True), {"mode": "unrestricted", "unrestricted": True, "whole_client_count": 0, "site_count": 0}),
    ("role superuser", User(Role(superuser=True)), {"mode": "unrestricted", "unrestricted": True, "whole_client_count": 0, "site_count": 0}),
    ("empty relations", User(Role()), {"mode": "unrestricted", "unrestricted": True, "whole_client_count": 0, "site_count": 0}),
    ("clients", User(Role(clients=[3, 1, 2])), {"mode": "clients", "unrestricted": False, "whole_client_count": 3, "site_count": 0}),
    ("sites", User(Role(sites=[10, 11])), {"mode": "sites", "unrestricted": False, "whole_client_count": 0, "site_count": 2}),
    ("mixed", User(Role(clients=[1], sites=[10, 11, 12])), {"mode": "mixed", "unrestricted": False, "whole_client_count": 1, "site_count": 3}),
    ("no role", User(None), NONE),
    ("installer", User(Role(clients=[1]), installer=True), NONE),
    ("installer superuser role", User(Role(superuser=True), installer=True), NONE),
    ("anonymous", User(Role(clients=[1]), anonymous=True), NONE),
    ("no user", None, NONE),
    ("role lookup failure", User(boom=True), NONE),
    ("relation failure", User(Role(clients=[1], boom=True)), NONE),
)
for label, user, expected in cases:
    got = scope(user)
    must(got == expected and list(got) == KEYS, (label, got))
    must(json.loads(json.dumps(got)) == expected, label)
    # counts and mode only: never an id list
    must(not any(isinstance(value, (list, tuple, set, dict)) for value in got.values()), (label, "no id list"))
# a large MSP role costs the same few bytes
big = scope(User(Role(clients=range(1, 400), sites=range(1000, 3000))))
must(big["whole_client_count"] == 399 and big["site_count"] == 2000 and len(json.dumps(big)) < 140, big)
# a descriptor that fails never breaks the startup payload
saved = adapter.role_scope_descriptor
adapter.role_scope_descriptor = lambda user: (_ for _ in ()).throw(RuntimeError("adapter down"))
must(scope(User(Role(clients=[1]))) == NONE, "failure gives none")
adapter.role_scope_descriptor = saved

# the view publishes it, keeps every earlier key and its place
views = (APP / "views.py").read_text(encoding="utf-8")
must("from . import resources_adapter\n" in views, "imported")
body = views.split("class UiContextView", 1)[1].split("class ExtensionPermissionCatalogView", 1)[0]
for earlier in ("user", "permissions", "extensions", "capabilities", "module_status", "notice_unread_count", "preferences", "module_register_timeout_seconds",
                "tactical_ui", "tactical_permissions", "tactical_web_ui", "preferences_initialized", "preferences_updated_at"):
    must(f'"{earlier}"' in body, earlier)
must('"tactical_scope": _tactical_scope_context(request.user),' in body, "published")
must(body.index('"tactical_permissions"') < body.index('"tactical_scope"') < body.index('"tactical_web_ui"'), "next to tactical_permissions")

# contract rows and docs
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HTTP_CONTRACT_DETAILS" for t in n.targets))
context = ast.literal_eval(node.value)["/api/tfd/ui/context/"]["GET"]
text = context["response"]["tactical_scope"]
must("1.17.17" in text and "counts only" in text and "never id lists" in text and "mode none" in text and "tactical_permissions" in context["response"], text)
must("tactical_scope" in (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8"), "docs")
print("[TEST] PASS ui context tactical scope 1.17.17")
