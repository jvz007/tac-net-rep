#!/usr/bin/env python3
"""1.17.28 regression: Tactical's SSO provider and settings admin, superuser only, with the lock-out guard (CQ84 a, Johan 14 October 2026).

Django, allauth and Tactical are not installed on the development PC, so the real tactical_account_guard.py runs against stubs: in-memory
SocialApp, SocialAccount and CoreSettings tables, a transaction that rolls back on an exception, and Tactical's ee/sso/views.py handlers as
small fakes that behave like the real ones (the failsafe that clears the block when SSO is off, the licence answer 423 for enabling SSO,
the 404 for an unknown provider or account). Covered: a caller who is not an effective superuser (a holder of can_manage_accounts
included) is refused on all five writes with one deny row and no change, before the body is read; a superuser's add, edit, delete,
settings save and disconnect each write exactly one strict row of the right shape; no client id, secret or external uid appears in any
row; blocking local sign-in with no provider, and deleting the last provider while blocked, are refused with 409 sso_lockout_guard and
change nothing; the failsafe and a non-boolean body are checked on the state Tactical stores, and that state is rolled back when it would
lock everyone out; Tactical's 423, 400 and 404 write no success row; a failed audit write rolls the change back; a create that cannot be
matched still writes a row (matched 0); the list redacts the secret for a non-superuser only; the wrappers install once and install
cleanly without ee.sso; the contract rule and docs/sso-admin.md name the routes; docs/api-keys.md no longer says SSO is left out.
The dev-server check (real tables) is tests/sso-admin-runtime-1.17.28.py, not run here.
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "tactical_account_guard.py"
CLIENT = "CLIENTID-SENTINEL-4d2a"
SECRET = "SECRET-SENTINEL-9c7e"
UID = "UID-SENTINEL-77ab"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class ObjectDoesNotExist(Exception):
    pass


class PermissionDenied(Exception):
    pass


class ValidationError(Exception):
    pass


class Http404(Exception):
    pass


class BodyRead(BaseException):
    """Raised when a wrapper reads the body. A BaseException, so the guard's own ``except Exception`` cannot hide it."""


class BooleanField:
    def run_validation(self, value):
        return bool(value)


class Response:
    """DRF's Response takes ``status=``; the fake takes that and the older name."""

    def __init__(self, data=None, status_code=200, status=None):
        self.data = data
        self.status_code = status if status is not None else status_code


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


# ------------------------------------------------------------------------------------------------ tables
class Q:
    """A small queryset: the methods the guard calls, over a list of rows."""

    def __init__(self, rows):
        self.rows = list(rows)

    def all(self):
        return Q(self.rows)

    def select_for_update(self, **kw):
        return self

    def select_related(self, *a):
        return self

    def order_by(self, *a):
        return self

    def exclude(self, **kw):
        return Q([r for r in self.rows if not all(getattr(r, k) == v for k, v in kw.items())])

    def filter(self, **kw):
        out = []
        for row in self.rows:
            ok = True
            for key, value in kw.items():
                if key == "pk__in":
                    ok = ok and row.pk in set(value)
                elif key == "pk":
                    ok = ok and row.pk == int(value)
                else:
                    ok = ok and getattr(row, key) == value
            if ok:
                out.append(row)
        return Q(out)

    def first(self):
        return self.rows[0] if self.rows else None

    def count(self):
        return len(self.rows)

    def values_list(self, field, flat=False):
        return [getattr(row, field) for row in self.rows]


class Manager:
    def __init__(self, table):
        self.table = table

    def _q(self):
        return Q(self.table.values())

    def __getattr__(self, name):
        return getattr(self._q(), name)


class SettingsManager:
    def select_for_update(self, **kw):
        return self

    def order_by(self, *a):
        return self

    def first(self):
        return SETTINGS


class SocialAppRow:
    def __init__(self, pk, name, provider_id, client_id, secret, server_url, role):
        self.pk = self.id = pk
        self.name, self.provider, self.provider_id = name, "openid_connect", provider_id
        self.client_id, self.secret = client_id, secret
        self.settings = {"server_url": server_url, "role": role}


class SocialAccountRow:
    def __init__(self, pk, uid, provider, user_id):
        self.pk, self.uid, self.provider, self.user_id = pk, uid, provider, user_id

    @property
    def user(self):
        return USERS[self.user_id]


class UserRow:
    def __init__(self, pk, username):
        self.pk, self.username = pk, username


class CoreSettingsRow:
    sso_enabled = False
    block_local_user_logon = False


APPS: dict = {}
ACCOUNTS: dict = {}
USERS = {10: UserRow(10, "tech.one")}
SETTINGS = CoreSettingsRow()
STATE = {"licensed": True, "fail_audit": False, "hide_created": False, "next": 2}
CALLS: list = []
AUDITS: list = []


def reset():
    APPS.clear()
    APPS[1] = SocialAppRow(1, "Ci Sso", "Ci-Sso", CLIENT + "-1", SECRET + "-1", "https://login.example.test", "user")
    APPS[2] = SocialAppRow(2, "Lab", "Lab", CLIENT + "-2", SECRET + "-2", "https://lab.example.test", None)
    ACCOUNTS.clear()
    ACCOUNTS[1] = SocialAccountRow(1, UID, "openid_connect", 10)
    SETTINGS.sso_enabled = False
    SETTINGS.block_local_user_logon = False
    AUDITS.clear()
    CALLS.clear()
    STATE.update(licensed=True, fail_audit=False, hide_created=False, next=2)


@contextlib.contextmanager
def atomic():
    saved = (copy.deepcopy(APPS), copy.deepcopy(ACCOUNTS), dict(SETTINGS.__dict__))
    try:
        yield
    except BaseException:
        APPS.clear()
        APPS.update(saved[0])
        ACCOUNTS.clear()
        ACCOUNTS.update(saved[1])
        SETTINGS.__dict__.update(saved[2])
        raise


class _Transaction:
    atomic = staticmethod(atomic)

    @staticmethod
    def get_connection():
        return types.SimpleNamespace(in_atomic_block=False)

    @staticmethod
    def on_commit(cb):
        cb()


def record(**kw):
    if STATE["fail_audit"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kw)
    return {"recorded": True}


# ------------------------------------------------------------------------------------------------ stubs for the imports the guard makes
stub("django")
stub("django.core")
stub("django.core.exceptions", ObjectDoesNotExist=ObjectDoesNotExist)
stub("django.db", transaction=_Transaction)
stub("rest_framework")
stub("rest_framework.exceptions", PermissionDenied=PermissionDenied, ValidationError=ValidationError)
stub("rest_framework.fields", BooleanField=BooleanField)
stub("rest_framework.response", Response=Response)
stub("accounts")
stub("accounts.models", Role=type("Role", (), {}), User=type("User", (), {}), APIKey=type("APIKey", (), {}))
stub("allauth")
stub("allauth.socialaccount")
stub("allauth.socialaccount.models", SocialApp=types.SimpleNamespace(objects=Manager(APPS)), SocialAccount=types.SimpleNamespace(objects=Manager(ACCOUNTS)))
stub("core")
stub("core.models", CoreSettings=types.SimpleNamespace(objects=SettingsManager()))
pkg = stub("tec_tac")
pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
stub("tec_tac.rbac", is_effective_superuser=lambda actor: bool(getattr(actor, "effective_superuser", False)))
stub("tec_tac.account_security_policy", protection_enabled=lambda **kw: False)
stub("tec_tac.audit", record=record)


def make_view(*methods):
    """A Tactical view class with the given methods, each answering 200 'ok' until the test replaces it."""
    attrs = {}
    for name in methods:
        attrs[name] = (lambda self, request, *a, **k: Response("ok", 200))
    return type("View", (), attrs)


# Tactical's accounts views (the account guard's own wrappers are tested in tests/api-key-audit-1.17.26.py)
accounts_views = stub(
    "accounts.views",
    GetAddRoles=make_view("post"), GetUpdateDeleteRole=make_view("put", "delete"), GetAddUsers=make_view("post"),
    GetUpdateDeleteUser=make_view("put", "delete"), UserActions=make_view("post", "put"), GetAddAPIKeys=make_view("get", "post"),
    GetUpdateDeleteAPIKey=make_view("put", "delete"), TOTPSetup=make_view("post"), ResetPass=make_view("put"), Reset2FA=make_view("put"),
)


def _db_bool(value) -> bool:
    """Django's BooleanField reads these as true; anything else is false in this stub."""
    return value in (True, 1, "1", "t", "true", "True")


def _provider_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9\s]", "", name).replace(" ", "-")


class GetAddSSOProvider:
    """Tactical's ee/sso/views.py GetAddSSOProvider, as the guard sees it."""

    def get(self, request):
        CALLS.append("get")
        return Response([
            {"id": a.pk, "name": a.name, "provider": a.provider, "provider_id": a.provider_id, "client_id": a.client_id,
             "secret": a.secret, "server_url": a.settings["server_url"], "role": a.settings["role"]} for a in APPS.values()
        ])

    def post(self, request):
        CALLS.append("post")
        data = request.data
        if not data.get("name"):
            return Response({"name": ["This field is required."]}, 400)
        data["settings"] = {"server_url": data["server_url"], "role": data["role"] or None}
        data["provider_id"] = _provider_id(data["name"])
        if not STATE["hide_created"]:
            pk = STATE["next"] = STATE["next"] + 1
            APPS[pk] = SocialAppRow(pk, data["name"], data["provider_id"], data.get("client_id"), data.get("secret"),
                                    data["server_url"], data["role"] or None)
        return Response("ok", 200)


class GetUpdateDeleteSSOProvider:
    """Tactical's ee/sso/views.py GetUpdateDeleteSSOProvider, as the guard sees it."""

    def put(self, request, pk):
        CALLS.append("put")
        app = APPS.get(int(pk))
        if app is None:
            raise Http404("No SocialApp matches the given query.")
        data = request.data
        for field in ("client_id", "secret"):
            if field in data:
                setattr(app, field, data[field])
        app.settings = {"server_url": data["server_url"], "role": data["role"] or None}
        return Response("ok", 200)

    def delete(self, request, pk):
        CALLS.append("delete")
        if int(pk) not in APPS:
            raise Http404("No SocialApp matches the given query.")
        del APPS[int(pk)]
        return Response("ok", 200)


class GetUpdateSSOSettings:
    """Tactical's ee/sso/views.py GetUpdateSSOSettings and CoreSettings.save (the failsafe and the licence answer)."""

    def get(self, request):
        return Response({"block_local_user_logon": SETTINGS.block_local_user_logon, "sso_enabled": SETTINGS.sso_enabled})

    def post(self, request):
        CALLS.append("settings")
        data = request.data
        raw_sso, raw_block = data["sso_enabled"], data["block_local_user_logon"]
        if not raw_sso and raw_block:  # CoreSettings.save: the failsafe clears the block when SSO is off (the raw value is judged)
            raw_block = False
        if not SETTINGS.sso_enabled and _db_bool(raw_sso) and not STATE["licensed"]:  # the token check raises ValidationError: 423
            return Response("This feature requires a Tier 1 or higher sponsorship", 423)
        SETTINGS.sso_enabled = _db_bool(raw_sso)
        SETTINGS.block_local_user_logon = _db_bool(raw_block)
        return Response("ok", 200)


class DisconnectSSOAccount:
    """Tactical's ee/sso/views.py DisconnectSSOAccount."""

    def delete(self, request):
        CALLS.append("disconnect")
        data = request.data
        for pk, account in list(ACCOUNTS.items()):
            if account.uid == data["account"] and account.provider == data["provider"]:
                del ACCOUNTS[pk]
                return Response("ok", 200)
        raise Http404("No SocialAccount matches the given query.")


class GetAccessToken:
    """Sign-in, not admin: the guard must leave it alone."""

    def post(self, request, format=None):
        return Response("sign-in", 200)


ee = stub("ee")
ee_sso = stub("ee.sso")
ee.sso = ee_sso
ee_sso.views = stub("ee.sso.views", GetAddSSOProvider=GetAddSSOProvider, GetUpdateDeleteSSOProvider=GetUpdateDeleteSSOProvider,
                    GetUpdateSSOSettings=GetUpdateSSOSettings, DisconnectSSOAccount=DisconnectSSOAccount, GetAccessToken=GetAccessToken)

spec = importlib.util.spec_from_file_location("tec_tac.tactical_account_guard", MODULE)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)

# ------------------------------------------------------------------------------------------------ install: once, and without ee.sso
# the six writes and the list read Core wraps; the settings GET stays Tactical's (GET unchanged)
WRAPPED = (
    (GetAddSSOProvider, "get"), (GetAddSSOProvider, "post"), (GetUpdateDeleteSSOProvider, "put"), (GetUpdateDeleteSSOProvider, "delete"),
    (GetUpdateSSOSettings, "post"), (DisconnectSSOAccount, "delete"),
)
SSO_ORIGINALS = {(cls, m): getattr(cls, m) for cls, m in WRAPPED}
settings_get_before = GetUpdateSSOSettings.get
sign_in_before = GetAccessToken.post

# ee.sso missing: the accounts wrappers still install, the SSO ones are skipped with one log line
saved_views = ee_sso.views
del ee_sso.views
sys.modules["ee.sso.views"] = None
guard.install_tactical_account_guard()
must(getattr(accounts_views.GetAddRoles, "post") is not None and guard._already_guarded(accounts_views.GetAddAPIKeys.post), "accounts wrappers installed")
for (cls, method), original in SSO_ORIGINALS.items():
    must(getattr(cls, method) is original, ("without ee.sso the SSO methods are untouched", cls.__name__, method))
sys.modules["ee.sso.views"] = saved_views  # restored for the install with ee.sso present
ee_sso.views = saved_views

# ee.sso present: wrapped once, marked, and a second install changes nothing
guard.install_tactical_account_guard()
for (cls, method), original in SSO_ORIGINALS.items():
    wrapped = getattr(cls, method)
    must(wrapped is not original and guard._already_guarded(wrapped), ("SSO method wrapped", cls.__name__, method))
after_first = {key: getattr(key[0], key[1]) for key in SSO_ORIGINALS}
guard.install_tactical_account_guard()
for key, wrapped in after_first.items():
    must(getattr(key[0], key[1]) is wrapped, ("idempotent install", key))
must(GetAccessToken.post is sign_in_before, "the sign-in view is not wrapped")
must(GetUpdateSSOSettings.get is settings_get_before, "the settings GET stays Tactical's")
must("GetAccessToken" not in MODULE.read_text(encoding="utf-8").split("def _install_sso_wrappers", 1)[1].split("def install_tactical_account_guard", 1)[0],
     "the sign-in view is not in the install list")


# ------------------------------------------------------------------------------------------------ helpers
class Actor:
    effective_superuser = False
    username = "tech.admin"


class Boss(Actor):
    effective_superuser = True
    username = "root"


class Request:
    def __init__(self, data, user):
        self.data, self.user = data, user


class Poison:
    """Request data the wrapper must never read for a caller who is not a superuser."""

    def __contains__(self, key):
        raise BodyRead("the body was read before the superuser check")

    def get(self, *a, **k):
        raise BodyRead("the body was read before the superuser check")

    def __getitem__(self, key):
        raise BodyRead("the body was read before the superuser check")


def deny_rows():
    return [r for r in AUDITS if r.get("action") == "deny"]


def success_rows():
    return [r for r in AUDITS if r.get("action") != "deny" and str(r.get("object_type", "")).startswith("sso_")]


def dumped():
    return json.dumps(AUDITS, default=str)


def expect_status(fn, status, code=None):
    try:
        resp = fn()
    except Exception as exc:  # noqa: BLE001 - the answer is inspected below
        raise AssertionError(f"expected a {status} answer, got {exc!r}") from exc
    must(resp.status_code == status, (status, resp.status_code, resp.data))
    if code is not None:
        must(resp.data.get("code") == code, (code, resp.data))
    return resp


def add_call(user, body):
    return GetAddSSOProvider.post(None, Request(body, user))


def edit_call(user, pk, body):
    return GetUpdateDeleteSSOProvider.put(None, Request(body, user), pk)


def delete_call(user, pk, body=None):
    return GetUpdateDeleteSSOProvider.delete(None, Request(body or {}, user), pk)


def settings_call(user, body):
    return GetUpdateSSOSettings.post(None, Request(body, user))


def disconnect_call(user, body):
    return DisconnectSSOAccount.delete(None, Request(body, user))


NEW_PROVIDER = {"name": "Okta Prod", "client_id": CLIENT + "-new", "secret": SECRET + "-new", "server_url": "https://okta.example.test",
                "role": "user"}

# ------------------------------------------------------------------------------------------------ (1) superuser only, before the body
reset()
refusals = [
    ("add_provider", lambda: add_call(Actor(), Poison())),
    ("edit_provider", lambda: edit_call(Actor(), 1, Poison())),
    ("delete_provider", lambda: delete_call(Actor(), 1, Poison())),
    ("save_settings", lambda: settings_call(Actor(), Poison())),
    ("disconnect_account", lambda: disconnect_call(Actor(), Poison())),
]
for operation, call in refusals:
    before_apps = {pk: (a.name, a.client_id, a.secret, dict(a.settings)) for pk, a in APPS.items()}
    before_settings = dict(SETTINGS.__dict__)
    before_accounts = sorted(ACCOUNTS)
    try:
        call()
    except PermissionDenied as exc:
        must(str(exc) == guard.SSO_SUPERUSER_DETAIL, (operation, str(exc)))
    else:
        raise AssertionError(f"{operation} must be refused for a non-superuser")
    must(not CALLS, (operation, "Tactical is never reached"))
    must({pk: (a.name, a.client_id, a.secret, dict(a.settings)) for pk, a in APPS.items()} == before_apps, (operation, "providers unchanged"))
    must(dict(SETTINGS.__dict__) == before_settings and sorted(ACCOUNTS) == before_accounts, (operation, "settings and accounts unchanged"))
deny = deny_rows()
must(len(deny) == 5, deny)
must({r["object_type"] for r in deny} == {guard.SSO_SUPERUSER_OBJECT}, deny)
must([r["metadata"]["operation"] for r in deny] == ["add_provider", "edit_provider", "delete_provider", "save_settings", "disconnect_account"], deny)
must(not success_rows(), "a refusal writes no success row")
must(not any(SECRET in str(r) or CLIENT in str(r) for r in deny), "a deny row carries no value")

# the list is open to a caller who can list accounts; a non-superuser sees the secret redacted, a superuser sees it
reset()
listed = GetAddSSOProvider.get(None, Request({}, Actor()))
must(all(item["secret"] == guard.SSO_REDACTED for item in listed.data) and len(listed.data) == 2, listed.data)
must(not deny_rows(), "a read writes no row")
listed = GetAddSSOProvider.get(None, Request({}, Boss()))
must(listed.data[0]["secret"] == SECRET + "-1" and listed.data[0]["client_id"] == CLIENT + "-1", "a superuser sees the secret, as Tactical lists it")
must(not AUDITS, "a superuser's read writes no row")

# ------------------------------------------------------------------------------------------------ (2) the superuser's writes: one row each, no value in any row
reset()
resp = add_call(Boss(), dict(NEW_PROVIDER))
must(resp.status_code == 200 and "Okta-Prod" in {a.provider_id for a in APPS.values()}, resp.data)
rows = success_rows()
must(len(rows) == 1, rows)
row = rows[0]
must(row["action"] == "add" and row["module_id"] == "core" and row["object_type"] == "sso_provider" and row["object_id"] == "3", row)
must(row["metadata"] == {"name": "Okta Prod", "provider_id": "Okta-Prod", "server_url": "https://okta.example.test", "role": "user"}, row["metadata"])
must(row["after"] == row["metadata"] and row["before"] is None and row["strict"] is True, row)
must(CLIENT not in dumped() and SECRET not in dumped(), "the add row holds no client id or secret")

reset()
resp = edit_call(Boss(), 1, {"client_id": CLIENT + "-2", "secret": SECRET + "-2", "server_url": "https://new.example.test", "role": "admin"})
must(resp.status_code == 200, resp.data)
row = success_rows()[0]
must(row["action"] == "modify" and row["object_id"] == "1" and row["object_type"] == "sso_provider", row)
must(row["metadata"]["changed"] == ["client_id", "secret", "server_url", "role"], row["metadata"])
must(row["before"] == {"name": "Ci Sso", "provider_id": "Ci-Sso", "server_url": "https://login.example.test", "role": "user"}, row["before"])
must(row["after"] == {"name": "Ci Sso", "provider_id": "Ci-Sso", "server_url": "https://new.example.test", "role": "admin"}, row["after"])
must(CLIENT not in dumped() and SECRET not in dumped(), "an edit row holds no client id or secret")

reset()
resp = edit_call(Boss(), 1, {"client_id": CLIENT + "-1", "secret": SECRET + "-1", "server_url": "https://login.example.test", "role": "user"})
must(resp.status_code == 200 and success_rows()[0]["metadata"]["changed"] == [], success_rows())

reset()
resp = delete_call(Boss(), 2)
must(resp.status_code == 200 and 2 not in APPS, resp.data)
row = success_rows()[0]
must(row["action"] == "delete" and row["object_id"] == "2" and row["before"] == {"name": "Lab", "provider_id": "Lab", "server_url": "https://lab.example.test",
                                                                               "role": None} and row["after"] is None, row)
must(CLIENT not in dumped() and SECRET not in dumped(), "a delete row holds no client id or secret")

reset()
resp = settings_call(Boss(), {"sso_enabled": True, "block_local_user_logon": False})
must(resp.status_code == 200 and SETTINGS.sso_enabled is True, resp.data)
row = success_rows()[0]
must(row["action"] == "modify" and row["object_type"] == "sso_settings" and row["object_id"] == "sso_settings", row)
must(row["before"] == {"sso_enabled": False, "block_local_user_logon": False} and row["after"] == {"sso_enabled": True, "block_local_user_logon": False},
     row)

reset()
resp = disconnect_call(Boss(), {"account": UID, "provider": "openid_connect"})
must(resp.status_code == 200 and 1 not in ACCOUNTS, resp.data)
row = success_rows()[0]
must(row["action"] == "delete" and row["object_type"] == "sso_account" and row["object_id"] == "10", row)
must(row["metadata"] == {"provider": "openid_connect", "username": "tech.one"}, row["metadata"])
must(UID not in dumped(), "the external uid is never recorded")

# ------------------------------------------------------------------------------------------------ (3) the lock-out guard
reset()
APPS.clear()  # no provider row at all
resp = expect_status(lambda: settings_call(Boss(), {"sso_enabled": True, "block_local_user_logon": True}), 409, "sso_lockout_guard")
must(resp.data["detail"] == guard.SSO_LOCKOUT_TEXT, resp.data)
must(SETTINGS.block_local_user_logon is False and SETTINGS.sso_enabled is False, "nothing changed")
must(len(deny_rows()) == 1 and deny_rows()[-1]["object_type"] == guard.SSO_LOCKOUT_OBJECT, deny_rows())
must(not success_rows(), "a refusal writes no success row")

reset()
APPS.clear()
CALLS.clear()
expect_status(lambda: settings_call(Boss(), {"sso_enabled": True, "block_local_user_logon": True}), 409, "sso_lockout_guard")
must(CALLS == [], "the strict body is refused before Tactical is called")

# deleting the last provider while local sign-in is blocked
reset()
SETTINGS.sso_enabled, SETTINGS.block_local_user_logon = True, True
del APPS[2]
expect_status(lambda: delete_call(Boss(), 1), 409, "sso_lockout_guard")
must(1 in APPS and not success_rows() and CALLS == [], "the last provider stays, and Tactical is not called")
must(deny_rows()[-1]["metadata"]["operation"] == "delete_provider", deny_rows())

# deleting one of two while blocked: allowed
reset()
SETTINGS.sso_enabled, SETTINGS.block_local_user_logon = True, True
resp = delete_call(Boss(), 2)
must(resp.status_code == 200 and 2 not in APPS and 1 in APPS, resp.data)

# deleting the last provider when local sign-in is not blocked: allowed
reset()
del APPS[2]
resp = delete_call(Boss(), 1)
must(resp.status_code == 200 and not APPS, resp.data)

# SSO off plus block: the failsafe is Tactical's; the lock-out check does not refuse it, and the row shows the block as stored (false)
reset()
APPS.clear()
resp = settings_call(Boss(), {"sso_enabled": False, "block_local_user_logon": True})
must(resp.status_code == 200 and SETTINGS.block_local_user_logon is False, resp.data)
row = success_rows()[0]
must(row["after"] == {"sso_enabled": False, "block_local_user_logon": False}, row)

# a body that is not two real booleans is checked on the state Tactical stored, and rolled back when that locks everyone out
reset()
APPS.clear()
before_state = dict(SETTINGS.__dict__)
CALLS.clear()
expect_status(lambda: settings_call(Boss(), {"sso_enabled": "true", "block_local_user_logon": "true"}), 409, "sso_lockout_guard")
must(CALLS == ["settings"], "the non-boolean body reaches Tactical, which stores it")
must(dict(SETTINGS.__dict__) == before_state, ("rolled back", dict(SETTINGS.__dict__)))
must(not success_rows(), "no success row for the rolled-back save")

# with a provider, a stored block is allowed
reset()
resp = settings_call(Boss(), {"sso_enabled": "true", "block_local_user_logon": "true"})
must(resp.status_code == 200 and SETTINGS.block_local_user_logon is True, resp.data)


# ------------------------------------------------------------------------------------------------ (4) Tactical's own refusals write no success row
reset()
STATE["licensed"] = False
resp = settings_call(Boss(), {"sso_enabled": True, "block_local_user_logon": False})
must(resp.status_code == 423 and SETTINGS.sso_enabled is False and not success_rows(), (resp.status_code, success_rows()))
STATE["licensed"] = True

reset()
resp = add_call(Boss(), {"server_url": "https://x.example.test", "role": "user"})  # no name: Tactical's 400
must(resp.status_code == 400 and len(APPS) == 2 and not success_rows(), (resp.status_code, success_rows()))

reset()
try:
    edit_call(Boss(), 99, {"client_id": "x", "secret": "y", "server_url": "z", "role": None})
except Http404:
    pass
else:
    raise AssertionError("an unknown provider is Tactical's 404")
must(not success_rows(), "a 404 writes no row")

reset()
try:
    delete_call(Boss(), 99)
except Http404:
    pass
else:
    raise AssertionError("an unknown provider is Tactical's 404 on delete")
must(not success_rows(), "a 404 on delete writes no row")

reset()
try:
    disconnect_call(Boss(), {"account": "no-such-uid", "provider": "openid_connect"})
except Http404:
    pass
else:
    raise AssertionError("an unknown account is Tactical's 404")
must(not success_rows() and 1 in ACCOUNTS, "a 404 on disconnect writes no row")

# ------------------------------------------------------------------------------------------------ (5) a failed audit write rolls the change back
reset()
STATE["fail_audit"] = True
try:
    add_call(Boss(), dict(NEW_PROVIDER))
except RuntimeError:
    pass
else:
    raise AssertionError("a failed strict audit write must raise")
finally:
    STATE["fail_audit"] = False
must(sorted(APPS) == [1, 2], "the provider create was rolled back")
reset()
STATE["fail_audit"] = True
try:
    settings_call(Boss(), {"sso_enabled": True, "block_local_user_logon": False})
except RuntimeError:
    pass
finally:
    STATE["fail_audit"] = False
must(SETTINGS.sso_enabled is False, "the settings save was rolled back")

# ------------------------------------------------------------------------------------------------ (6) a create that cannot be matched still writes a row
reset()
STATE["hide_created"] = True
resp = add_call(Boss(), dict(NEW_PROVIDER))
must(resp.status_code == 200, resp.data)
row = success_rows()[0]
must(row["action"] == "add" and row["object_id"] is None and row["metadata"]["matched"] == 0, row)
must(row["metadata"]["name"] == "Okta Prod" and CLIENT not in dumped(), row)
STATE["hide_created"] = False

# ------------------------------------------------------------------------------------------------ (7) the contract and the docs name the routes and rules
contract = (ROOT / "framwork" / "tec_tac" / "contracts.py").read_text(encoding="utf-8")
for needle in ("SSO admin", "/accounts/ssoproviders/", "can_manage_accounts", "sso_lockout_guard", "sso_admin_superuser_required", "Requires framework >=1.17.28"):
    must(needle in contract, ("contracts.py", needle))
doc = (ROOT / "docs" / "sso-admin.md").read_text(encoding="utf-8")
for needle in ("/accounts/ssoproviders/", "/accounts/ssoproviders/settings/", "/accounts/ssoproviders/account/", "sso_lockout_guard", "[REDACTED]",
               "never stored", "can_manage_accounts", "CQ84"):
    must(needle in doc, ("docs/sso-admin.md", needle))
api_doc = (ROOT / "docs" / "api-keys.md").read_text(encoding="utf-8")
must("Not in this release" not in api_doc and "SSO provider and settings admin" not in api_doc, "docs/api-keys.md no longer leaves SSO out")

print("[TEST] PASS sso admin guard 1.17.28")
