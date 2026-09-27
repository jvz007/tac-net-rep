#!/usr/bin/env python3
"""R5 regression: native Tactical role/user editors cannot mint superuser authority."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "tactical_account_guard.py"

# Minimal dependency stubs keep this regression runnable outside a Tactical VM.
class ObjectDoesNotExist(Exception):
    pass

class PermissionDenied(Exception):
    pass

class ValidationError(Exception):
    pass

class BooleanField:
    TRUE = {True, 1, "1", "true", "True", "yes", "on"}
    FALSE = {False, 0, "0", "false", "False", "no", "off"}
    def run_validation(self, value):
        if value in self.TRUE:
            return True
        if value in self.FALSE:
            return False
        raise ValidationError("invalid boolean")

class DoesNotExist(ObjectDoesNotExist):
    pass

class Query:
    def __init__(self, manager): self.manager = manager; self.pk = None
    def only(self, *args): return self
    def select_for_update(self, *args, **kwargs): return self
    def select_related(self, *args): return self
    def filter(self, pk): self.pk = int(pk); return self
    def get(self, pk):
        if int(pk) not in self.manager.rows: raise DoesNotExist()
        return self.manager.rows[int(pk)]
    def filter(self, pk): self.pk = int(pk); return self
    def first(self): return self.manager.rows.get(self.pk)

class Manager:
    def __init__(self): self.rows = {}
    def only(self, *args): return Query(self)
    def filter(self, pk): return Query(self).filter(pk)
    def select_for_update(self, *args, **kwargs): return Query(self)
    def select_related(self, *args): return Query(self)

class Role:
    DoesNotExist = DoesNotExist
    objects = Manager()
    def __init__(self, pk, is_superuser=False):
        self.pk = self.id = int(pk)
        self.is_superuser = bool(is_superuser)

class User:
    objects = Manager()
    def __init__(self, pk, role_id=None, is_superuser=False):
        self.pk = self.id = int(pk)
        self.role_id = role_id
        self.is_superuser = bool(is_superuser)
        self.role = Role.objects.rows.get(role_id) if role_id is not None else None

class APIKey:
    objects = Manager()
    def __init__(self, pk, user, key="SECRET"):
        self.pk = self.id = int(pk)
        self.user = user
        self.key = key

# Stub modules imported by the guard.
django = types.ModuleType("django")
django_core = types.ModuleType("django.core")
django_exc = types.ModuleType("django.core.exceptions")
django_exc.ObjectDoesNotExist = ObjectDoesNotExist
django_db = types.ModuleType("django.db")
class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
class Transaction:
    @staticmethod
    def atomic(): return Atomic()
django_db.transaction = Transaction
sys.modules.update({"django": django, "django.core": django_core, "django.core.exceptions": django_exc, "django.db": django_db})

rf = types.ModuleType("rest_framework")
rf_exc = types.ModuleType("rest_framework.exceptions")
rf_exc.PermissionDenied = PermissionDenied
rf_exc.ValidationError = ValidationError
rf_fields = types.ModuleType("rest_framework.fields")
rf_fields.BooleanField = BooleanField
sys.modules.update({"rest_framework": rf, "rest_framework.exceptions": rf_exc, "rest_framework.fields": rf_fields})

accounts = types.ModuleType("accounts")
accounts_models = types.ModuleType("accounts.models")
accounts_models.Role = Role
accounts_models.User = User
accounts_models.APIKey = APIKey
sys.modules.update({"accounts": accounts, "accounts.models": accounts_models})

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
rbac = types.ModuleType("tec_tac.rbac")
rbac.is_effective_superuser = lambda actor: bool(getattr(actor, "effective_superuser", False))
sys.modules["tec_tac.rbac"] = rbac
policy_state = {"enabled": False}
account_policy = types.ModuleType("tec_tac.account_security_policy")
account_policy.protection_enabled = lambda **kwargs: policy_state["enabled"]
sys.modules["tec_tac.account_security_policy"] = account_policy

audits = []
audit_mod = types.ModuleType("tec_tac.audit")
def record(**kwargs):
    audits.append(kwargs)
    return {"recorded": True}
audit_mod.record = record
sys.modules["tec_tac.audit"] = audit_mod

spec = importlib.util.spec_from_file_location("tec_tac.tactical_account_guard", MODULE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class Actor:
    def __init__(self, effective=False, username="operator"):
        self.effective_superuser = effective
        self.is_authenticated = True
        self.username = username

normal = Actor(False)
superuser = Actor(True, "root-admin")

# Role create: ordinary role saves work; superuser role creation is protected.
mod._guard_role_create(normal, {"name": "Helpdesk", "is_superuser": False})
try:
    mod._guard_role_create(normal, {"name": "Escalated", "is_superuser": True})
except PermissionDenied:
    pass
else:
    raise AssertionError("non-superuser created a superuser role")
assert audits[-1]["object_type"] == "role_superuser_change"
mod._guard_role_create(superuser, {"name": "Admins", "is_superuser": True})

# Role update: unchanged full-form payloads remain valid; actual transitions block.
ordinary = Role(10, False)
admin_role = Role(11, True)
mod._guard_role_update(normal, ordinary, {"name": "Helpdesk", "is_superuser": False})
mod._guard_role_update(normal, admin_role, {"name": "Admins", "is_superuser": True})
for role, requested in ((ordinary, True), (admin_role, False)):
    try:
        mod._guard_role_update(normal, role, {"is_superuser": requested})
    except PermissionDenied:
        pass
    else:
        raise AssertionError("non-superuser changed Role.is_superuser")
mod._guard_role_update(superuser, ordinary, {"is_superuser": True})

# User assignment: assigning a superuser role is protected, ordinary roles are not.
Role.objects.rows = {10: ordinary, 11: admin_role, 12: Role(12, True)}
mod._guard_user_create(normal, {"username": "tech", "role": 10})

# Python bool is an int. Tactical user-create treats role=True as pk=1, so
# Core must resolve the same value instead of discarding it.
Role.objects.rows[1] = Role(1, True)
try:
    mod._guard_user_create(normal, {"username": "t", "role": True})
except PermissionDenied:
    pass
else:
    raise AssertionError("role=True bypassed superuser-role assignment guard")
try:
    mod._guard_user_create(normal, {"username": "tech", "role": 11})
except PermissionDenied:
    pass
else:
    raise AssertionError("non-superuser assigned superuser role on user create")
assert audits[-1]["object_type"] == "superuser_role_assignment"
mod._guard_user_create(superuser, {"username": "admin2", "role": 11})

existing = User(50, role_id=11)
# Full user form resending the already assigned superuser role is not a new grant.
mod._guard_user_update(normal, existing, {"email": "x@example.invalid", "role": 11})
try:
    mod._guard_user_update(normal, User(51, role_id=10), {"role": 12})
except PermissionDenied:
    pass
else:
    raise AssertionError("non-superuser assigned superuser role on user update")
mod._guard_user_update(superuser, User(51, role_id=10), {"role": 12})

# D1 policy: default Off preserves Tactical behaviour for existing superuser accounts.
policy_state["enabled"] = False
existing_admin = User(70, role_id=11)
existing_admin.role = admin_role
normal_user = User(71, role_id=10)
normal_user.role = ordinary
mod._guard_user_update(normal, existing_admin, {"email": "allowed@example.invalid", "role": 11})

# When enabled, only an effective superuser may act on an existing superuser account.
policy_state["enabled"] = True
try:
    mod._guard_user_update(normal, existing_admin, {"email": "blocked@example.invalid", "role": 11})
except PermissionDenied:
    pass
else:
    raise AssertionError("D1 policy did not protect an existing superuser account")
assert audits[-1]["object_type"] == "superuser_account_protection"
mod._guard_user_update(superuser, existing_admin, {"email": "allowed@example.invalid", "role": 11})
policy_state["enabled"] = False

# Install wrappers around Tactical's native methods and prove idempotence/pass-through.
class GetAddRoles:
    def post(self, request, *args, **kwargs): return "role-create-ok"
class GetUpdateDeleteRole:
    def put(self, request, pk, *args, **kwargs): return f"role-update-{pk}"
class GetAddUsers:
    def post(self, request, *args, **kwargs): return "user-create-ok"
class GetUpdateDeleteUser:
    def put(self, request, pk, *args, **kwargs): return f"user-update-{pk}"
    def delete(self, request, pk, *args, **kwargs): return f"user-delete-{pk}"
class UserActions:
    def post(self, request, *args, **kwargs): return "password-reset-ok"
    def put(self, request, *args, **kwargs): return "totp-reset-ok"
class FakeResponse:
    def __init__(self, data): self.data = data

class GetAddAPIKeys:
    def get(self, request, *args, **kwargs):
        rows = []
        for key in APIKey.objects.rows.values():
            rows.append({"id": key.pk, "user": key.user.pk, "key": key.key})
        return FakeResponse(rows)
    def post(self, request, *args, **kwargs): return "api-key-create-ok"
class GetUpdateDeleteAPIKey:
    def put(self, request, pk, *args, **kwargs): return f"api-key-update-{pk}"
    def delete(self, request, pk, *args, **kwargs): return f"api-key-delete-{pk}"
class TOTPSetup:
    def post(self, request, *args, **kwargs): return "totp-setup-ok"
class ResetPass:
    def put(self, request, *args, **kwargs): return "self-password-reset-ok"
class Reset2FA:
    def put(self, request, *args, **kwargs): return "self-totp-reset-ok"

views = types.ModuleType("accounts.views")
views.GetAddRoles = GetAddRoles
views.GetUpdateDeleteRole = GetUpdateDeleteRole
views.GetAddUsers = GetAddUsers
views.GetUpdateDeleteUser = GetUpdateDeleteUser
views.UserActions = UserActions
views.GetAddAPIKeys = GetAddAPIKeys
views.GetUpdateDeleteAPIKey = GetUpdateDeleteAPIKey
views.TOTPSetup = TOTPSetup
views.ResetPass = ResetPass
views.Reset2FA = Reset2FA
accounts.views = views
sys.modules["accounts.views"] = views

User.objects.rows = {70: existing_admin, 71: normal_user}
APIKey.objects.rows = {5: APIKey(5, existing_admin), 6: APIKey(6, normal_user)}
mod.install_tactical_account_guard()
first = (
    views.GetAddRoles.post,
    views.GetUpdateDeleteRole.put,
    views.GetAddUsers.post,
    views.GetUpdateDeleteUser.put,
    views.GetUpdateDeleteUser.delete,
    views.UserActions.post,
    views.UserActions.put,
    views.GetAddAPIKeys.get,
    views.GetAddAPIKeys.post,
    views.GetUpdateDeleteAPIKey.put,
    views.GetUpdateDeleteAPIKey.delete,
)
mod.install_tactical_account_guard()
second = (
    views.GetAddRoles.post,
    views.GetUpdateDeleteRole.put,
    views.GetAddUsers.post,
    views.GetUpdateDeleteUser.put,
    views.GetUpdateDeleteUser.delete,
    views.UserActions.post,
    views.UserActions.put,
    views.GetAddAPIKeys.get,
    views.GetAddAPIKeys.post,
    views.GetUpdateDeleteAPIKey.put,
    views.GetUpdateDeleteAPIKey.delete,
)
assert first == second, "guard installation is not idempotent"

class Request:
    def __init__(self, actor, data): self.user = actor; self.data = data

assert GetAddRoles().post(Request(normal, {"name": "Ops", "is_superuser": False})) == "role-create-ok"
try:
    GetAddUsers().post(Request(normal, {"username": "bool-role", "role": True}))
except PermissionDenied:
    pass
else:
    raise AssertionError("wrapped Tactical user-create endpoint allowed role=True escalation")
try:
    GetAddRoles().post(Request(normal, {"name": "Bad", "is_superuser": True}))
except PermissionDenied:
    pass
else:
    raise AssertionError("wrapped Tactical role endpoint allowed escalation")

User.objects.rows = {50: existing}
assert GetUpdateDeleteUser().put(Request(normal, {"email": "x@example.invalid", "role": 11}), 50) == "user-update-50"

assert len(audits) >= 4
print("[TEST] PASS Tactical native superuser role/account guard")

# D1 wrapper coverage for destructive account/API-key actions.
User.objects.rows = {70: existing_admin, 71: normal_user}
policy_state["enabled"] = True
for call in (
    lambda: GetUpdateDeleteUser().delete(Request(normal, {}), 70),
    lambda: UserActions().post(Request(normal, {"id": 70, "password": "x"})),
    lambda: UserActions().put(Request(normal, {"id": 70})),
    lambda: GetAddAPIKeys().post(Request(normal, {"user": 70, "name": "x"})),
    lambda: GetUpdateDeleteAPIKey().put(Request(normal, {"name": "x"}), 5),
    lambda: GetUpdateDeleteAPIKey().delete(Request(normal, {}), 5),
):
    try:
        call()
    except PermissionDenied:
        pass
    else:
        raise AssertionError("D1 wrapper allowed a non-superuser action against a protected account")

# D1 API-key ownership must follow Tactical's writable `user` field, never the
# read-only API-key `id` field.  These are the review's exact bypass cases.
for call in (
    lambda: GetAddAPIKeys().post(Request(normal, {"id": 71, "user": 70, "name": "x"})),
    lambda: GetAddAPIKeys().post(Request(normal, {"id": "x", "user": 70, "name": "x"})),
    lambda: GetUpdateDeleteAPIKey().put(Request(normal, {"id": 71, "user": 70}), 6),
):
    try:
        call()
    except PermissionDenied:
        pass
    else:
        raise AssertionError("D1 API-key guard trusted id instead of the persisted user owner")

# D1 read protection: non-superusers may list API keys but must never receive
# secrets belonging to protected superuser accounts. Effective superusers retain
# Tactical's native response.
APIKey.objects.rows = {5: APIKey(5, existing_admin, "SUPERUSER-SECRET"), 6: APIKey(6, normal_user, "NORMAL-SECRET")}
normal_response = GetAddAPIKeys().get(Request(normal, {}))
assert "SUPERUSER-SECRET" not in repr(normal_response.data), "protected API-key secret leaked to non-superuser"
assert any(row.get("id") == 5 and row.get("key") == "[REDACTED]" for row in normal_response.data)
assert any(row.get("id") == 6 and row.get("key") == "NORMAL-SECRET" for row in normal_response.data)
super_response = GetAddAPIKeys().get(Request(superuser, {}))
assert any(row.get("id") == 5 and row.get("key") == "SUPERUSER-SECRET" for row in super_response.data), "superuser lost native API-key visibility"

assert GetUpdateDeleteUser().delete(Request(superuser, {}), 70) == "user-delete-70"
policy_state["enabled"] = False
print("tactical superuser/account-protection guard regression OK")
