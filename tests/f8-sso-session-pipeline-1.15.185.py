#!/usr/bin/env python3
"""F8 behavioural acceptance: SSO enters the normal Core session-security pipeline.

This is deliberately portable: it imports the real SessionAuthenticated and
ensure_request_session code with small model/runtime doubles. It proves the
policy branch and the audit write rather than grepping source text.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"

# ----- minimal Django/DRF/Knox environment needed by the real module -----
settings = types.SimpleNamespace(SECRET_KEY="f8-secret", ROOT_USER="root")
django = types.ModuleType("django")
django_conf = types.ModuleType("django.conf"); django_conf.settings = settings
django_auth = types.ModuleType("django.contrib.auth"); django_auth.get_user_model = lambda: object

class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
class Transaction:
    @staticmethod
    def atomic(): return Atomic()
django_db = types.ModuleType("django.db"); django_db.transaction = Transaction
class Q:
    def __init__(self, *args, **kwargs): pass
    def __or__(self, other): return self
    def __and__(self, other): return self
    def __invert__(self): return self
django_models = types.ModuleType("django.db.models"); django_models.Q = Q
fixed_now = datetime(2026, 9, 29, 18, 0, tzinfo=dt_timezone.utc)
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone"); django_timezone.now = lambda: fixed_now
django_utils.timezone = django_timezone
sys.modules.update({
    "django": django, "django.conf": django_conf, "django.contrib.auth": django_auth,
    "django.db": django_db, "django.db.models": django_models,
    "django.utils": django_utils, "django.utils.timezone": django_timezone,
})

knox = types.ModuleType("knox")
knox_models = types.ModuleType("knox.models")
class AuthToken: pass
AuthToken.objects = types.SimpleNamespace(filter=lambda **kwargs: types.SimpleNamespace(delete=lambda: (0, {})))
knox_models.AuthToken = AuthToken
sys.modules.update({"knox": knox, "knox.models": knox_models})

allauth = types.ModuleType("allauth")
allauth_social = types.ModuleType("allauth.socialaccount")
allauth_social_models = types.ModuleType("allauth.socialaccount.models")
class _SocialAccountQuery:
    def filter(self, **kwargs): return self
    def only(self, *args): return self
    def order_by(self, *args): return self
    def first(self): return types.SimpleNamespace(provider="openid_connect")
class SocialAccount: objects = _SocialAccountQuery()
allauth_social_models.SocialAccount = SocialAccount
sys.modules.update({
    "allauth": allauth,
    "allauth.socialaccount": allauth_social,
    "allauth.socialaccount.models": allauth_social_models,
})

rf = types.ModuleType("rest_framework")
rf_exc = types.ModuleType("rest_framework.exceptions")
class APIException(Exception):
    def __init__(self, detail=None):
        self.detail = detail
        super().__init__(str(detail))
rf_exc.APIException = APIException
rf_perm = types.ModuleType("rest_framework.permissions")
class IsAuthenticated:
    def has_permission(self, request, view):
        return bool(getattr(getattr(request, "user", None), "is_authenticated", False))
rf_perm.IsAuthenticated = IsAuthenticated
sys.modules.update({"rest_framework": rf, "rest_framework.exceptions": rf_exc, "rest_framework.permissions": rf_perm})

pkg = types.ModuleType("tec_tac"); pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability = lambda **kwargs: kwargs
sys.modules["tec_tac.capabilities"] = caps

# ----- fake ORM with the operations used by ensure_request_session -----
class TrustDoesNotExist(Exception): pass

class SessionRow:
    def __init__(self, *, pk, token_fingerprint, defaults):
        self.pk = self.id = pk
        self.token_fingerprint = token_fingerprint
        self.user = defaults["user"]
        self.user_id = self.user.pk
        self.username = defaults["username"]
        self.last_activity_at = defaults["last_activity_at"]
        self.last_seen_at = defaults["last_seen_at"]
        self.initial_ip = defaults["initial_ip"]
        self.last_ip = defaults["last_ip"]
        self.user_agent_hash = defaults["user_agent_hash"]
        self.knox_digest = defaults["knox_digest"]
        self.absolute_expires_at = defaults["absolute_expires_at"]
        self.idle_expires_at = defaults["idle_expires_at"]
        self.created_at = fixed_now
        self.updated_at = fixed_now
        self.revoked = False
        self.revoked_at = None
        self.revoked_by = ""
        self.revocation_reason = ""
    def save(self, update_fields=None):
        self.saved_fields = tuple(update_fields or ())

class TrustQuery:
    def __init__(self, manager, rows): self.manager = manager; self.rows = list(rows)
    def select_for_update(self): return self
    def filter(self, **kwargs):
        rows = self.rows
        for key, value in kwargs.items():
            if key == "knox_digest": rows = [r for r in rows if r.knox_digest == value]
            elif key == "token_fingerprint": rows = [r for r in rows if r.token_fingerprint == value]
            elif key == "pk": rows = [r for r in rows if r.pk == value]
            else: raise AssertionError(f"unsupported trust filter {key}")
        return TrustQuery(self.manager, rows)
    def order_by(self, *args): return self
    def get(self, **kwargs):
        rows = self.filter(**kwargs).rows
        if not rows: raise TrustDoesNotExist()
        assert len(rows) == 1, rows
        return rows[0]
    def __iter__(self): return iter(self.rows)

class TrustManager:
    def __init__(self): self.rows = []
    def select_for_update(self): return TrustQuery(self, self.rows)
    def get(self, **kwargs): return TrustQuery(self, self.rows).get(**kwargs)
    def get_or_create(self, *, token_fingerprint, defaults):
        for row in self.rows:
            if row.token_fingerprint == token_fingerprint:
                return row, False
        row = SessionRow(pk=len(self.rows) + 1, token_fingerprint=token_fingerprint, defaults=defaults)
        self.rows.append(row)
        return row, True

TRUST = TrustManager()
class TecTacSessionTrust:
    DoesNotExist = TrustDoesNotExist
    objects = TRUST

class AuditManager:
    def __init__(self): self.rows = []
    def create(self, **kwargs):
        row = types.SimpleNamespace(**kwargs)
        self.rows.append(row)
        return row
AUDITS = AuditManager()
class TecTacSessionAudit: objects = AUDITS

class Config:
    last_history_cleanup_at = None
    @classmethod
    def current(cls): return cls()
class TecTacSessionSecurityConfig(Config): pass

models_mod = types.ModuleType("tec_tac.models")
models_mod.TecTacSessionTrust = TecTacSessionTrust
models_mod.TecTacSessionAudit = TecTacSessionAudit
models_mod.TecTacSessionSecurityConfig = TecTacSessionSecurityConfig
sys.modules["tec_tac.models"] = models_mod

spec = importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)

# Keep this test on the real permission class + real ensure_request_session + real _audit.
policy = {
    "absolute_lifetime_minutes": 480,
    "idle_timeout_minutes": 30,
    "ip_change_policy": "reauthenticate",
    "session_audit_enabled": True,
}
mod.get_effective_policy = lambda user, request: dict(policy)
mod.token_fingerprint = lambda request: "fingerprint-sso"
mod.request_knox_digest = lambda request: "digest-sso"
mod.effective_client_ip = lambda request, policy=None: "192.0.2.44"
mod.user_agent_hash = lambda request: "ua-hash"
mod._legacy_knox_fingerprint = lambda request: None

class User:
    def __init__(self, *, sso, totp_key=None):
        self.pk = self.id = 7
        self.username = "alice"
        self.is_authenticated = True
        self.is_superuser = False
        self.is_sso_user = sso
        self.totp_key = totp_key

class Request:
    def __init__(self, user): self.user = user

permission = mod.SessionAuthenticated()

# MFA policy gate: a normal Tactical Knox credential without local TOTP remains
# enrollment-only and must not create a Tec-Tac operational trust/audit row.
normal = Request(User(sso=False, totp_key=None))
try:
    permission.has_permission(normal, object())
    raise AssertionError("non-SSO user without TOTP unexpectedly passed the MFA gate")
except mod.SessionSecurityDenied as exc:
    assert exc.session_code == "mfa_enrollment_required", exc.session_code
assert TRUST.rows == []
assert AUDITS.rows == []

# SSO follows Tactical's external-provider MFA model, but it still must enter
# Core's normal session-security boundary and create the same session audit row.
sso_request = Request(User(sso=True, totp_key=None))
assert permission.has_permission(sso_request, object()) is True
assert len(TRUST.rows) == 1
row = TRUST.rows[0]
assert row.username == "alice"
assert row.knox_digest == "digest-sso"
assert getattr(sso_request, "tec_tac_session") is row
assert len(AUDITS.rows) == 1
assert AUDITS.rows[0].event_type == "session_created"
assert AUDITS.rows[0].metadata["auth_method"] == "sso"
assert AUDITS.rows[0].metadata["provider"] == "openid_connect"
assert AUDITS.rows[0].session is row
assert AUDITS.rows[0].username == "alice"
assert AUDITS.rows[0].new_ip == "192.0.2.44"

print("[TEST] PASS F8 SSO uses normal Core session-security, MFA policy and audit pipeline")
