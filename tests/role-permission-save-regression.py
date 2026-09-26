#!/usr/bin/env python3
"""Regression: full-map role saves only protect actual privileged transitions."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "framwork" / "tec_tac" / "views.py"
CORE = "core.privileged_operations"
OTHER = "sample.read"

# Execute the actual RoleExtensionPermissionsView.put body without importing the
# complete Tactical/Django application. This keeps the regression portable while
# testing the shipped endpoint implementation rather than a duplicate helper.
tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
method = None
for node in tree.body:
    if isinstance(node, ast.ClassDef) and node.name == "RoleExtensionPermissionsView":
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == "put":
                method = child
                break
assert method is not None, "RoleExtensionPermissionsView.put not found"
method.decorator_list = []
method.name = "role_permissions_put"
module = ast.Module(body=[method], type_ignores=[])
ast.fix_missing_locations(module)

class PermissionDenied(Exception):
    pass

class Response:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status

class Role:
    def __init__(self, role_id=7, name="Helpdesk"):
        self.id = role_id
        self.name = name
        self.is_superuser = False

class Actor:
    def __init__(self, effective=False):
        self.effective = effective

class Request:
    def __init__(self, actor, permissions):
        self.user = actor
        self.data = {"permissions": permissions}

role = Role()
current = {CORE: False, OTHER: False}
sets = []
audits = []

def get_object_or_404(model, pk):
    assert pk == role.id
    return role

def registered_permissions():
    return frozenset({CORE, OTHER})

def get_all_role_permissions(obj):
    assert obj is role
    return dict(current)

def is_effective_superuser(actor):
    return actor.effective

def set_extension_permission(obj, codename, granted):
    assert obj is role
    sets.append((codename, granted))
    current[codename] = granted

def _audit_privileged(actor, action, object_type, **kwargs):
    audits.append((actor, action, object_type, kwargs))

ns = {
    "get_object_or_404": get_object_or_404,
    "Role": Role,
    "Response": Response,
    "registered_permissions": registered_permissions,
    "get_all_role_permissions": get_all_role_permissions,
    "is_effective_superuser": is_effective_superuser,
    "set_extension_permission": set_extension_permission,
    "_audit_privileged": _audit_privileged,
    "PermissionDenied": PermissionDenied,
    "CORE_PRIVILEGED_PERMISSION": CORE,
}
exec(compile(module, str(SOURCE), "exec"), ns)
put = ns["role_permissions_put"]
view = object()
normal = Actor(False)
superuser = Actor(True)

# Full permission map with unchanged privileged=False must remain saveable.
resp = put(view, Request(normal, {CORE: False, OTHER: True}), role.id)
assert resp.status_code == 200
assert (OTHER, True) in sets
assert not audits

# Full permission map with unchanged privileged=True must also remain saveable.
current.update({CORE: True, OTHER: True})
sets.clear()
resp = put(view, Request(normal, {CORE: True, OTHER: False}), role.id)
assert resp.status_code == 200
assert (OTHER, False) in sets
assert not audits

# Actual grant/revoke transitions stay protected for ordinary role managers.
for before, after in ((False, True), (True, False)):
    current[CORE] = before
    sets.clear()
    try:
        put(view, Request(normal, {CORE: after, OTHER: current[OTHER]}), role.id)
    except PermissionDenied:
        pass
    else:
        raise AssertionError(f"ordinary role manager changed privileged permission {before}->{after}")
    assert not sets, "permission writes occurred before privileged transition denial"

# Effective superusers may make the transition and it is audited exactly then.
current[CORE] = False
sets.clear()
audits.clear()
resp = put(view, Request(superuser, {CORE: True, OTHER: current[OTHER]}), role.id)
assert resp.status_code == 200
assert (CORE, True) in sets
assert len(audits) == 1
meta = audits[0][3]["metadata"]
assert meta["previous_granted"] is False and meta["granted"] is True

# Type validation happens before privilege-transition handling.
current[CORE] = False
sets.clear()
audits.clear()
resp = put(view, Request(normal, {CORE: "false", OTHER: True}), role.id)
assert resp.status_code == 400
assert not sets and not audits

print("[TEST] PASS role full-map save privilege transition guard")
