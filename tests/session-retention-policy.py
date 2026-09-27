#!/usr/bin/env python3
"""D4 regression: Core-owned retention policy and credential-aware tombstones."""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"

settings = types.SimpleNamespace(SECRET_KEY="retention-test-secret", ROOT_USER="root")
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
    def __init__(self, *args, **kwargs): self.args=args; self.kwargs=kwargs
    def __or__(self, other): return self
    def __and__(self, other): return self
    def __invert__(self): return self
django_models.Q = Q
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone"); django_timezone.now = lambda: datetime.now(dt_timezone.utc)
django_utils.timezone = django_timezone
sys.modules.update({
    "django": django, "django.conf": django_conf, "django.contrib.auth": django_auth,
    "django.db": django_db, "django.db.models": django_models,
    "django.utils": django_utils, "django.utils.timezone": django_timezone,
})

class TokenQuery:
    def __init__(self, live): self.live=live
    def filter(self, *args, **kwargs): return self
    def exists(self): return self.live
class TokenManager:
    live = False
    def filter(self, **kwargs): return TokenQuery(self.live)
knox = types.ModuleType("knox")
knox_models = types.ModuleType("knox.models")
class AuthToken: pass
AuthToken.objects = TokenManager()
knox_models.AuthToken = AuthToken
sys.modules.update({"knox": knox, "knox.models": knox_models})

rf = types.ModuleType("rest_framework")
rf_exc = types.ModuleType("rest_framework.exceptions")
class APIException(Exception):
    def __init__(self, detail=None): self.detail=detail; super().__init__(str(detail))
rf_exc.APIException = APIException
rf_perm = types.ModuleType("rest_framework.permissions")
class IsAuthenticated: pass
rf_perm.IsAuthenticated = IsAuthenticated
sys.modules.update({"rest_framework": rf, "rest_framework.exceptions": rf_exc, "rest_framework.permissions": rf_perm})

pkg = types.ModuleType("tec_tac"); pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
captured = {}
def register_capability(**kwargs): captured.update(kwargs); return kwargs
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability = register_capability
sys.modules["tec_tac.capabilities"] = caps

class Config:
    idle_timeout_minutes=30
    absolute_lifetime_minutes=480
    ip_change_policy="reauthenticate"
    session_audit_enabled=True
    activity_heartbeat_seconds=60
    history_retention_days=30
    last_history_cleanup_at=None
    trusted_proxies=[]
    updated_by_label=""
    def save(self, update_fields=None): self.saved=tuple(update_fields or [])
CONFIG=Config()
class TecTacSessionSecurityConfig:
    @classmethod
    def current(cls): return CONFIG
class DummyManager:
    def filter(self, *a, **k): return self
    def count(self): return 0
class TecTacSessionTrust: objects=DummyManager()
class TecTacSessionAudit: objects=DummyManager()
models_mod=types.ModuleType("tec_tac.models")
models_mod.TecTacSessionSecurityConfig=TecTacSessionSecurityConfig
models_mod.TecTacSessionTrust=TecTacSessionTrust
models_mod.TecTacSessionAudit=TecTacSessionAudit
sys.modules["tec_tac.models"] = models_mod

spec=importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

# D4 setting is part of Core policy and remains audited.
audits=[]
mod._audit=lambda *a, **k: audits.append((a,k))
updated=mod._update_global_policy({"history_retention_days": 45}, requested_by="root")
assert updated["history_retention_days"] == 45
assert CONFIG.history_retention_days == 45
assert audits and audits[-1][1].get("force") is True
assert "history_retention_days" in audits[-1][1]["metadata"]["fields"]
try:
    mod._update_global_policy({"history_retention_days": 0}, requested_by="root")
except mod.SessionSecurityError:
    pass
else:
    raise AssertionError("retention lower bound was not enforced")

# Policy mutation must not be module-callable through the capability provider.
mod.register_core_session_security_capability()
assert mod.CAPABILITY_VERSION == "2.0.0"
assert "update_policy" not in captured["operations"]
assert not hasattr(mod.SessionSecurityProvider(), "update_policy")
assert mod.SessionSecurityProvider.cleanup.__code__.co_varnames[:2] == ("self", "context")

# Legacy stored proxy values are revalidated on every read; unsafe entries do not
# become trusted merely because an older Core accepted them.
CONFIG.trusted_proxies = ["10.0.0.0/8", "8.8.8.8/32", "0.0.0.0/0", "not-a-network"]
policy = mod.get_effective_policy()
assert policy["trusted_proxies"] == ["10.0.0.0/8"], policy

# Revoked Knox tombstone survives only while Tactical's token remains live.
row=types.SimpleNamespace(knox_digest="digest-1", token_fingerprint="fp")
AuthToken.objects.live=True
assert mod._revoked_tombstone_is_live(row, now=django_timezone.now(), active_non_knox=set()) is True
AuthToken.objects.live=False
assert mod._revoked_tombstone_is_live(row, now=django_timezone.now(), active_non_knox=set()) is False

# API-key/Django-session tombstones are matched by the stable credential HMAC.
fp=mod._fingerprint_for_identity("api-key:17")
row=types.SimpleNamespace(knox_digest="", token_fingerprint=fp)
assert mod._revoked_tombstone_is_live(row, now=django_timezone.now(), active_non_knox={fp}) is True
assert mod._revoked_tombstone_is_live(row, now=django_timezone.now(), active_non_knox=set()) is False
# If credential inventory cannot be read, retention fails closed and preserves.
assert mod._revoked_tombstone_is_live(row, now=django_timezone.now(), active_non_knox=None) is True

print("[TEST] PASS D4 session retention policy and tombstone lifecycle")
