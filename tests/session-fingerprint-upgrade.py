#!/usr/bin/env python3
"""Regression: old session fingerprints cannot resurrect revoked Knox credentials."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"

# Minimal framework stubs for the focused compatibility helpers.
settings = types.SimpleNamespace(SECRET_KEY="unit-test-secret", ROOT_USER="root")
django = types.ModuleType("django")
django_conf = types.ModuleType("django.conf"); django_conf.settings = settings
django_auth = types.ModuleType("django.contrib.auth"); django_auth.get_user_model = lambda: object
django_db = types.ModuleType("django.db")
class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
class Transaction:
    @staticmethod
    def atomic(): return Atomic()
django_db.transaction = Transaction
django_models = types.ModuleType("django.db.models")
class Q:
    def __init__(self, *args, **kwargs): pass
    def __or__(self, other): return self
    def __and__(self, other): return self
    def __invert__(self): return self
django_models.Q = Q
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone")
django_timezone.now = lambda: None
django_utils.timezone = django_timezone
sys.modules.update({
    "django": django, "django.conf": django_conf, "django.contrib.auth": django_auth,
    "django.db": django_db, "django.db.models": django_models,
    "django.utils": django_utils, "django.utils.timezone": django_timezone,
})

knox = types.ModuleType("knox")
knox_models = types.ModuleType("knox.models")
class AuthToken: pass
AuthToken.objects = types.SimpleNamespace()
knox_models.AuthToken = AuthToken
knox_crypto = types.ModuleType("knox.crypto")
def hash_token(raw): return hashlib.sha512(raw.encode("utf-8")).hexdigest()
knox_crypto.hash_token = hash_token
sys.modules.update({"knox": knox, "knox.models": knox_models, "knox.crypto": knox_crypto})

rf = types.ModuleType("rest_framework")
rf_exc = types.ModuleType("rest_framework.exceptions")
class APIException(Exception):
    def __init__(self, detail=None): self.detail = detail; super().__init__(str(detail))
rf_exc.APIException = APIException
rf_perm = types.ModuleType("rest_framework.permissions")
class IsAuthenticated: pass
rf_perm.IsAuthenticated = IsAuthenticated
sys.modules.update({"rest_framework": rf, "rest_framework.exceptions": rf_exc, "rest_framework.permissions": rf_perm})

pkg = types.ModuleType("tec_tac"); pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability = lambda *a, **k: None
sys.modules["tec_tac.capabilities"] = caps

class DoesNotExist(Exception): pass
class Session:
    def __init__(self, fingerprint, digest="", revoked=False, marker=""):
        self.token_fingerprint = fingerprint
        self.knox_digest = digest
        self.revoked = revoked
        self.last_seen_at = marker
        self.created_at = marker
        self.saved = []
    def save(self, update_fields=None): self.saved.append(tuple(update_fields or []))

class Query:
    def __init__(self, manager, rows=None): self.manager = manager; self.rows = list(manager.rows if rows is None else rows)
    def select_for_update(self): return self
    def filter(self, **kwargs):
        rows = self.rows
        for key, value in kwargs.items(): rows = [row for row in rows if getattr(row, key) == value]
        return Query(self.manager, rows)
    def order_by(self, *fields):
        # The production helper explicitly selects a revoked row if any, so exact
        # timestamp ordering is irrelevant to this regression.
        return self
    def get(self, **kwargs):
        rows = self.filter(**kwargs).rows
        if len(rows) != 1: raise DoesNotExist()
        return rows[0]
    def __iter__(self): return iter(self.rows)

class Manager:
    def __init__(self): self.rows = []
    def select_for_update(self): return Query(self)

class TecTacSessionTrust:
    DoesNotExist = DoesNotExist
    objects = Manager()
class TecTacSessionAudit: pass
class TecTacSessionSecurityConfig:
    @classmethod
    def current(cls): return types.SimpleNamespace()
models_mod = types.ModuleType("tec_tac.models")
models_mod.TecTacSessionTrust = TecTacSessionTrust
models_mod.TecTacSessionAudit = TecTacSessionAudit
models_mod.TecTacSessionSecurityConfig = TecTacSessionSecurityConfig
sys.modules["tec_tac.models"] = models_mod

spec = importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)

class KnoxAuth: __module__ = "knox.auth"
class Request:
    def __init__(self, raw):
        digest = hash_token(raw)
        self.successful_authenticator = KnoxAuth()
        self.auth = types.SimpleNamespace(digest=digest)
        self.META = {"HTTP_AUTHORIZATION": f"Token {raw}", "HTTP_X_API_KEY": ""}
        self.user = types.SimpleNamespace(pk=7, username="tech", is_authenticated=True)
        self.session = None

request = Request("secret-bearer")
current = mod.token_fingerprint(request)
legacy = mod._legacy_knox_fingerprint(request)
assert current != legacy, "test requires old/new fingerprints to differ"
digest = mod.request_knox_digest(request)

# A revoked row carrying the stable Knox digest must dominate any active duplicate.
active = Session("active-old", digest=digest, revoked=False, marker="new")
revoked = Session("revoked-old", digest=digest, revoked=True, marker="old")
TecTacSessionTrust.objects.rows = [active, revoked]
found = mod._existing_session_for_credential(request, current_fingerprint=current)
assert found is revoked, "revoked credential state did not dominate duplicate active state"

# Even an active row under the *new/current* fingerprint may not override an
# older revoked tombstone for the same underlying Knox credential.
current_active = Session(current, digest=digest, revoked=False, marker="current")
TecTacSessionTrust.objects.rows = [current_active, revoked]
found = mod._existing_session_for_credential(request, current_fingerprint=current)
assert found is revoked, "current-fingerprint active row resurrected a revoked Knox credential"

# Rows predating knox_digest population are recovered through the old bearer HMAC.
legacy_row = Session(legacy, digest="", revoked=True, marker="legacy")
TecTacSessionTrust.objects.rows = [legacy_row]
found = mod._existing_session_for_credential(request, current_fingerprint=current)
assert found is legacy_row, "legacy fingerprint row was not recovered"
assert legacy_row.knox_digest == digest, "legacy row was not bound to stable Knox digest"
assert legacy_row.saved and "knox_digest" in legacy_row.saved[-1]

# A different/unrelated Authorization bearer cannot be used as the legacy bridge.
bad = Request("different-bearer")
bad.auth.digest = digest  # authenticator says original credential, header says another
try:
    mod._legacy_knox_fingerprint(bad)
except mod.SessionSecurityDenied:
    pass
else:
    raise AssertionError("legacy compatibility accepted a bearer that did not match request.auth.digest")

print("[TEST] PASS session fingerprint upgrade preserves revoked credential state")
