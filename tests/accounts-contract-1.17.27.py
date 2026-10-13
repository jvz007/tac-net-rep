#!/usr/bin/env python3
"""1.17.27 regression: core.accounts create_user and list_grantable_roles (binding entry, accounts contracts for User Invite).

Django, Tactical and the database are not installed on the development PC. So the real tec_tac/accounts.py runs against stubs: an in-memory
user and role table, a transaction that rolls back the users, the audit rows and the on-commit queue on an exception, Django's password
validators reduced to the four rules Tactical configures, the username and email validators, and the Core audit and caller helpers as
small fakes. Covered: a happy path (id returned, role, names, a usable password hash, no TOTP key, one strict audit row, Mesh sync once and
only after the commit); username and email clashes, ignoring case, and the same clash found on insert; weak passwords (short, common,
numeric-only, close to the username) with no password anywhere in the message or the audit row; a missing role and a superuser role
(refused); an inviter who is missing, inactive, an installer user, without can_manage_accounts, or demoted since the invite (nothing created);
bool and non-positive ids; a failing audit write rolls the user back; a caller that is not verified or not on the allow-list writes nothing;
list_grantable_roles rules and row keys; the contract rows, the docs and the registration.
The dev-server check (real tables) is tests/accounts-runtime-1.17.27.py, not run here.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import difflib
import hashlib
import importlib
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
PASSWORD = "Vine-Harbour-Lantern-72"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


# ---- Django and Tactical stand-ins -------------------------------------------------------------------------------------------------------
class ValidationError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.messages = [message] if isinstance(message, str) else list(message)


class IntegrityError(Exception):
    pass


stub("django")
stub("django.core")
stub("django.core.exceptions", ValidationError=ValidationError)


class FakeCache:
    """django.core.cache stand-in (1.17.30): add, incr and set with expiry on a clock the test moves, and a switch that makes it fail."""

    def __init__(self):
        self.data = {}
        self.now = 0.0
        self.down = False

    def _live(self, key):
        item = self.data.get(key)
        if item is not None and item[1] <= self.now:
            del self.data[key]
            item = None
        return item

    def add(self, key, value, timeout=None):
        if self.down:
            raise RuntimeError("cache down")
        if self._live(key) is None:
            self.data[key] = (value, self.now + timeout)
            return True
        return False

    def incr(self, key):
        if self.down:
            raise RuntimeError("cache down")
        item = self._live(key)
        if item is None:
            raise ValueError(key)
        self.data[key] = (item[0] + 1, item[1])
        return item[0] + 1

    def set(self, key, value, timeout=None):
        if self.down:
            raise RuntimeError("cache down")
        self.data[key] = (value, self.now + timeout)


CACHE = FakeCache()
stub("django.core.cache", cache=CACHE)
COMMON = {"password", "12345678", "qwertyui", "letmein1", "iloveyou"}


def validate_password(password, user=None):
    errors = []
    if len(password) < 8:
        errors.append("This password is too short. It must contain at least 8 characters.")
    if password.lower() in COMMON:
        errors.append("This password is too common.")
    if password.isdigit():
        errors.append("This password is entirely numeric.")
    if user is not None:
        for label, value in (("username", user.username), ("email address", user.email), ("first name", user.first_name), ("last name", user.last_name)):
            if value and difflib.SequenceMatcher(None, password.lower(), str(value).lower()).ratio() >= 0.7:
                errors.append(f"The password is too similar to the {label}.")
    if errors:
        raise ValidationError(errors)


stub("django.contrib")
stub("django.contrib.auth")
stub("django.contrib.auth.password_validation", validate_password=validate_password)


class UnicodeUsernameValidator:
    def __call__(self, value):
        if not re.fullmatch(r"[\w.@+-]+", value):
            raise ValidationError("Enter a valid username.")


stub("django.contrib.auth.validators", UnicodeUsernameValidator=UnicodeUsernameValidator)


def validate_email(value):
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ValidationError("Enter a valid email address.")


stub("django.core.validators", validate_email=validate_email)

USERS: dict = {}
ROLES: dict = {}
AUDITS: list = []
PENDING: list = []
DEPTH = [0]
RACE = {"on": False}
FAIL = {"on": False}
MESH_CALLS: list = []
ARGS: list = []
CALLER = {"value": None}
NEXT = {"user": 100}


class _Query:
    def __init__(self, rows):
        self.rows = list(rows)

    def filter(self, **kw):
        out = []
        for row in self.rows:
            ok = True
            for key, want in kw.items():
                if key == "pk":
                    ok = ok and row.pk == int(want)
                elif key == "username__iexact":
                    ok = ok and not RACE["on"] and row.username.lower() == str(want).lower()
                elif key == "email__iexact":
                    ok = ok and not RACE["on"] and row.email.lower() == str(want).lower()
                else:
                    ok = ok and getattr(row, key) == want
            if ok:
                out.append(row)
        return _Query(out)

    def order_by(self, *fields):
        return _Query(sorted(self.rows, key=lambda r: tuple(getattr(r, f) for f in fields)))

    def select_for_update(self, **kw):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def exists(self):
        return bool(self.rows)

    def values(self, *fields):
        return [{f: getattr(r, f) for f in fields} for r in self.rows]


class RoleRow:
    def __init__(self, pk, name, is_superuser=False, can_manage_accounts=False):
        self.pk = self.id = pk
        self.name, self.is_superuser, self.can_manage_accounts = name, is_superuser, can_manage_accounts


class UserRow:
    def __init__(self, pk=None, username="", email="", first_name="", last_name="", role_id=None, is_active=True, is_installer_user=False,
                 is_superuser=False, password_hash=None, totp_key=None):
        self.pk = self.id = pk
        self.username, self.email, self.first_name, self.last_name = username, email, first_name, last_name
        self.role_id, self.is_active, self.is_installer_user, self.is_superuser = role_id, is_active, is_installer_user, is_superuser
        self.password_hash, self.totp_key = password_hash, totp_key
        self.is_authenticated = True

    @property
    def role(self):
        return ROLES.get(self.role_id)

    @role.setter
    def role(self, value):
        self.role_id = None if value is None else value.pk

    def save(self):
        clash = [u for u in USERS.values() if u.username == self.username and u.pk != self.pk]
        if clash:
            raise IntegrityError("UNIQUE constraint failed: username")
        if self.pk is None:
            NEXT["user"] += 1
            self.pk = self.id = NEXT["user"]
        USERS[self.pk] = self


class _UserManager:
    @staticmethod
    def create_user(username, email, password):
        row = UserRow(username=username, email=email, password_hash=_hash(password))
        row.save()
        return row


class User:
    objects = None  # set below, after the query class exists

    def __init__(self, **kw):
        base = {"pk": None, "username": "", "email": "", "first_name": "", "last_name": ""}
        base.update(kw)
        self.__dict__.update(UserRow(**base).__dict__)


User.objects = SimpleNamespace(
    filter=lambda **kw: _Query(USERS.values()).filter(**kw),
    create_user=_UserManager.create_user,
)


class Role:
    objects = SimpleNamespace(
        select_for_update=lambda **kw: _Query(ROLES.values()),
        filter=lambda **kw: _Query(ROLES.values()).filter(**kw),
        order_by=lambda *f: _Query(ROLES.values()).order_by(*f),
    )


stub("accounts")
stub("accounts.models", Role=Role, User=User)


def _hash(password):
    return "hash$" + hashlib.sha256(("salt-" + password).encode()).hexdigest()


def check_password(user, password):
    return user.password_hash == _hash(password)


@contextlib.contextmanager
def atomic():
    snapshot = {pk: copy.copy(u) for pk, u in USERS.items()}
    audit_len = len(AUDITS)
    outer = DEPTH[0] == 0
    DEPTH[0] += 1
    try:
        yield
    except BaseException:
        DEPTH[0] -= 1
        if outer:
            PENDING.clear()
        USERS.clear()
        USERS.update(snapshot)
        del AUDITS[audit_len:]
        RACE["on"] = False  # after the rollback the database sees the row that was written in between
        raise
    else:
        DEPTH[0] -= 1
        if outer:
            callbacks = list(PENDING)
            PENDING.clear()
            for callback in callbacks:
                callback()


def on_commit(callback):
    if DEPTH[0] > 0:
        PENDING.append(callback)
    else:
        callback()


stub("django.db", IntegrityError=IntegrityError, transaction=SimpleNamespace(atomic=atomic, on_commit=on_commit))


class _Task:
    def delay(self):
        MESH_CALLS.append({"depth": DEPTH[0], "users": len(USERS)})


stub("core")
stub("core.tasks", sync_mesh_perms_task=_Task())


# ---- Core's own helpers (stubbed here; tests/caller-identity-core-provider-1.17.27.py runs the real caller helper) ----------------------
def record(**kw):
    if FAIL["on"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


def service_audit_actor(*, module_id, service, identity=None):
    return SimpleNamespace(kind="service", module_id=module_id, service=service, identity=identity or f"{module_id}.{service}")


def calling_module_for_core_provider(*, provider_file):
    ARGS.append(provider_file)
    return CALLER["value"]


pkg = stub("tec_tac")
pkg.__path__ = [str(APP)]
stub("tec_tac.audit", record=record, service_audit_actor=service_audit_actor)
stub("tec_tac.caller_identity", calling_module_for_core_provider=calling_module_for_core_provider)


def is_effective_superuser(user):
    if not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    role = getattr(user, "role", None)
    return bool(getattr(role, "is_superuser", False)) if role else False


def tactical_permission_flags(user, flags):
    denied = {name: False for name in flags}
    if not getattr(user, "is_authenticated", False) or getattr(user, "is_installer_user", False):
        return denied
    if getattr(user, "is_superuser", False):
        return {name: True for name in flags}
    role = getattr(user, "role", None)
    if not role:
        return denied
    if role.is_superuser:
        return {name: True for name in flags}
    return {name: bool(getattr(role, name, False)) for name in flags}


stub("tec_tac.rbac", is_effective_superuser=is_effective_superuser, tactical_permission_flags=tactical_permission_flags)
accounts = importlib.import_module("tec_tac.accounts")
CALLER_ID = SimpleNamespace(module_id="userinvite", kind="module", module_version="0.9.0")


# ---- fixtures -----------------------------------------------------------------------------------------------------------------------------
def reset():
    USERS.clear()
    ROLES.clear()
    AUDITS.clear()
    PENDING.clear()
    MESH_CALLS.clear()
    ARGS.clear()
    DEPTH[0] = 0
    RACE["on"] = False
    FAIL["on"] = False
    CALLER["value"] = CALLER_ID
    NEXT["user"] = 100
    CACHE.data.clear()
    CACHE.now = 0.0
    CACHE.down = False
    ROLES[1] = RoleRow(1, "Technician")
    ROLES[2] = RoleRow(2, "Super Admin", is_superuser=True)
    ROLES[3] = RoleRow(3, "Account Manager", can_manage_accounts=True)
    ROLES[4] = RoleRow(4, "Auditor")
    USERS[3] = UserRow(3, "boss", "boss@techxflow.co.za", "Boss", "One", role_id=3, password_hash=_hash("unused-1"))
    USERS[10] = UserRow(10, "tech", "tech@techxflow.co.za", "Tech", "Two", role_id=1)
    USERS[11] = UserRow(11, "rootadmin", "root@techxflow.co.za", "Root", "Admin", role_id=2, is_superuser=False)
    USERS[12] = UserRow(12, "inactive.boss", "inactive@techxflow.co.za", "Old", "Boss", role_id=3, is_active=False)
    USERS[13] = UserRow(13, "installer", "installer@techxflow.co.za", "Install", "Er", role_id=3, is_installer_user=True)
    USERS[14] = UserRow(14, "viewer", "viewer@techxflow.co.za", "View", "Er", role_id=4)
    USERS[15] = UserRow(15, "superuser", "su@techxflow.co.za", "Super", "User", role_id=None, is_superuser=True)
    USERS[16] = UserRow(16, "norole", "norole@techxflow.co.za", "No", "Role", role_id=None)
    NEXT["user"] = 100


def invite_args(**overrides):
    args = {"username": "jane.doe", "email": "jane@example.co.za", "first_name": "Jane", "last_name": "Doe", "role_id": 1, "password": PASSWORD,
            "invited_by_id": 3}
    args.update(overrides)
    return args


def user_count():
    return len(USERS)


def must_refuse(code, **overrides):
    before_users, before_audit, before_mesh = user_count(), len(AUDITS), len(MESH_CALLS)
    try:
        accounts.create_user(**invite_args(**overrides))
    except accounts.AccountsError as exc:
        must(exc.code == code, f"expected {code}, got {exc.code}: {exc.message}")
        must(PASSWORD not in exc.message and PASSWORD not in str(exc), "the refusal names no password")
        must(user_count() == before_users and len(AUDITS) == before_audit and len(MESH_CALLS) == before_mesh, f"{code} creates nothing")
        return exc
    raise AssertionError(f"expected {code}, the call succeeded")


# ---- create_user: happy path ---------------------------------------------------------------------------------------------------------------
reset()
created = accounts.create_user(**invite_args())
must(type(created).__name__ == "CreatedUser" and set(created.__dataclass_fields__) == {"user_id", "username", "role_id"}, "returns only ids and name")
row = USERS[created.user_id]
must(created.username == "jane.doe" and created.role_id == 1, created)
must(row.role_id == 1 and row.first_name == "Jane" and row.last_name == "Doe" and row.email == "jane@example.co.za", "role and names set")
must(check_password(row, PASSWORD) and row.password_hash != PASSWORD, "usable hashed password, never stored plain")
must(row.totp_key is None, "Core never sets a TOTP key")
must(len(AUDITS) == 1, f"one audit row, got {len(AUDITS)}")
audit = AUDITS[0]
must(audit["module_id"] == "core" and audit["action"] == "add" and audit["object_type"] == "user", audit)
must(audit["object_id"] == str(created.user_id) and audit["strict"] is True, audit)
must(audit["actor"].kind == "service" and audit["actor"].module_id == "core" and audit["actor"].identity == "userinvite.accept-invite", audit["actor"].__dict__)
must(audit["metadata"] == {"role_id": 1, "invited_by_id": 3, "caller_module": "userinvite", "purpose": "accept-invite", "totp_set": False}, audit["metadata"])
blob = json.dumps(AUDITS, default=lambda o: o.__dict__)
must(PASSWORD not in blob and row.password_hash not in blob and "jane@example.co.za" not in blob and "jane.doe" not in blob, "audit row holds no password, hash, email or username")
must(len(MESH_CALLS) == 1 and MESH_CALLS[0] == {"depth": 0, "users": user_count()}, f"Mesh sync once, after the commit: {MESH_CALLS}")
must(len(ARGS) >= 1 and Path(ARGS[0]).resolve() == (APP / "accounts.py").resolve(), "the provider's own file is what Core verifies from")

# ---- clashes, ignoring case --------------------------------------------------------------------------------------------------------------
reset()
must_refuse("username_taken", username="TECH")
reset()
must_refuse("email_taken", email="TECH@TECHXFLOW.co.za")
reset()
must_refuse("username_taken", username="Tech")
# a clash that the check does not see (a row written in between) is found on insert, with the same code
reset()
RACE["on"] = True
must_refuse("username_taken", username="tech")

# ---- weak passwords -----------------------------------------------------------------------------------------------------------------------
for weak in ("short1!", "password", "20261014", "jane.doe2026"):
    reset()
    exc = must_refuse("weak_password", password=weak)
    must(exc.message.startswith("The password is too weak.") and not (len(weak) > 8 and weak in exc.message), exc.message)
    must(not any(weak in json.dumps(a, default=str) for a in AUDITS), "no password in the audit")

# ---- roles --------------------------------------------------------------------------------------------------------------------------------
reset()
must_refuse("role_not_found", role_id=99)
reset()
must_refuse("role_not_grantable", role_id=2)  # a superuser role is refused while CQ86 is open
reset()
must_refuse("role_not_grantable", role_id=2, invited_by_id=15)  # even a superuser inviter

# ---- the inviter, checked again at acceptance -------------------------------------------------------------------------------------------
reset()
must_refuse("inviter_not_allowed", invited_by_id=999)
reset()
must_refuse("inviter_not_allowed", invited_by_id=12)  # inactive
reset()
must_refuse("inviter_not_allowed", invited_by_id=13)  # installer user
reset()
must_refuse("inviter_not_allowed", invited_by_id=14)  # no can_manage_accounts
reset()
must_refuse("inviter_not_allowed", invited_by_id=16)  # no role
reset()
ROLES[3].can_manage_accounts = False  # demoted since the invite was sent
must_refuse("inviter_not_allowed", invited_by_id=3)
reset()
created = accounts.create_user(**invite_args(invited_by_id=15))  # a superuser inviter may still use a non-superuser role
must(USERS[created.user_id].role_id == 1, "superuser inviter, non-superuser role")

# ---- ids and types -----------------------------------------------------------------------------------------------------------------------
for overrides in ({"role_id": True}, {"invited_by_id": True}, {"role_id": "1"}, {"role_id": 0}, {"invited_by_id": -3}, {"role_id": None},
                  {"username": ""}, {"username": "bad name!"}, {"email": "not-an-email"}, {"password": None}, {"first_name": "x" * 151},
                  {"last_name": "bad\x07name"}):
    reset()
    must_refuse("invalid_input", **overrides)

# ---- audit failure rolls the user back ----------------------------------------------------------------------------------------------------
reset()
FAIL["on"] = True
must_refuse("audit_failed")
FAIL["on"] = False

# ---- caller -------------------------------------------------------------------------------------------------------------------------------
reset()
CALLER["value"] = None  # not verified
must_refuse("caller_not_allowed")
reset()
CALLER["value"] = SimpleNamespace(module_id="alerts", kind="module", module_version="1.0.0")
must_refuse("caller_not_allowed")
reset()
CALLER["value"] = SimpleNamespace(module_id="core", kind="module", module_version="1.0.0")
must_refuse("caller_not_allowed")

# ---- list_grantable_roles -----------------------------------------------------------------------------------------------------------------
reset()
everything = [(r["name"], r["id"]) for r in accounts.list_grantable_roles(USERS[15])]
must(everything == [("Account Manager", 3), ("Auditor", 4), ("Super Admin", 2), ("Technician", 1)], everything)
must(all(set(r) == {"id", "name", "is_superuser"} for r in accounts.list_grantable_roles(USERS[15])), "row keys are exactly id, name, is_superuser")
rootrole = accounts.list_grantable_roles(USERS[11])
must([r["id"] for r in rootrole] == [3, 4, 2, 1], "a role superuser sees every role")
plain = accounts.list_grantable_roles(USERS[3])
must([r["name"] for r in plain] == ["Account Manager", "Auditor", "Technician"], plain)
must(not any(r["is_superuser"] for r in plain), "a plain manager sees no superuser role")
must(all(r["is_superuser"] is False for r in plain), "is_superuser is a plain boolean")
for who in (USERS[14], USERS[13], USERS[16], SimpleNamespace(is_authenticated=False)):
    try:
        accounts.list_grantable_roles(who)
    except accounts.AccountsError as exc:
        must(exc.code == "accounts_permission_required", exc.code)
    else:
        raise AssertionError("a user without can_manage_accounts is denied")
CALLER["value"] = None
try:
    accounts.list_grantable_roles(USERS[15])
except accounts.AccountsError as exc:
    must(exc.code == "caller_not_allowed", exc.code)
else:
    raise AssertionError("an unverified caller gets no roles")
CALLER["value"] = CALLER_ID

# ---- error codes and metadata -------------------------------------------------------------------------------------------------------------
subclasses = {cls.code for cls in vars(accounts).values() if isinstance(cls, type) and issubclass(cls, accounts.AccountsError) and cls is not accounts.AccountsError}
must(subclasses == set(accounts.ERROR_CODES), (subclasses, accounts.ERROR_CODES))
meta = accounts.accounts_contract_metadata()
must(meta["id"] == "core.accounts" and meta["version"] == "1.2.0" and meta["callers"] == ["userinvite"], meta)
must(meta["operations"] == ["create_user", "list_grantable_roles", "check_available"] and meta["creates_totp_key"] is False and meta["errors"] == list(accounts.ERROR_CODES), meta)

registered = {}
stub("tec_tac.capabilities", register_capability=lambda **kw: registered.update(kw) or SimpleNamespace(**kw))
accounts.register_core_accounts_capability()
must(registered["id"] == "core.accounts" and registered["module_id"] == "core" and registered["version"] == "1.2.0", registered)
must(registered["operations"] == ("create_user", "list_grantable_roles", "check_available") and registered["metadata"] == meta, registered)
must(registered["provider"].create_user is accounts.create_user and registered["provider"].list_grantable_roles is accounts.list_grantable_roles, "provider")

apps_src = (APP / "apps.py").read_text(encoding="utf-8")
must("register_core_accounts_capability()" in apps_src and "core.accounts capability registration failed" in apps_src, "ready() registers it, guarded")

# ---- the contract rows and docs ---------------------------------------------------------------------------------------------------------
contracts_tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
core_rows = next(ast.literal_eval(n.value) for n in contracts_tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
acc_rows = {r["name"]: r for r in core_rows if r["area"] == "accounts"}
must(set(acc_rows) == {"create_user", "list_grantable_roles", "check_available"}, acc_rows.keys())  # check_available: 1.17.29
for name, row in acc_rows.items():
    must(row["import_path"] == "tec_tac.accounts" and row["kind"] == "python" and row["purpose"] and row["audience"], row)
    must(re.search(rf"^def {name}\b", (APP / "accounts.py").read_text(encoding="utf-8"), re.MULTILINE), f"{name} is defined")
    must(("1.17.29" if name == "check_available" else "1.17.27") in row["purpose"] and "core.accounts" in row["purpose"], f"{name} names its release and capability")
must("caller_not_allowed" in acc_rows["create_user"]["purpose"] and "accounts_permission_required" in acc_rows["list_grantable_roles"]["purpose"], "errors named")

docs = (ROOT / "docs" / "accounts-contract.md").read_text(encoding="utf-8")
for needle in ("core.accounts", "1.2.0", "userinvite", "accept-invite", "CQ86", "CQ87", "AccountsError", "weak_password", "role_not_grantable",
               "inviter_not_allowed", "caller_not_allowed", "audit_failed", "accounts_permission_required", "totp_set", "can_manage_accounts"):
    must(needle in docs, f"docs/accounts-contract.md names {needle}")
for code in accounts.ERROR_CODES:
    must(f"`{code}`" in docs, f"docs name the error {code}")

print("[TEST] PASS accounts contract 1.17.27")
