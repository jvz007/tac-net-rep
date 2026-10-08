#!/usr/bin/env python3
"""D4 behavioural regression: scheduled retention performs real in-memory deletions."""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"
NOW = datetime(2026, 9, 27, 8, 0, tzinfo=dt_timezone.utc)

settings = types.SimpleNamespace(SECRET_KEY="retention-delete-secret", ROOT_USER="root")
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

def _lookup(row, key, expected):
    if "__" in key:
        field, op = key.split("__", 1)
    else:
        field, op = key, "eq"
    actual = getattr(row, field)
    if op == "eq": return actual == expected
    if op == "lt": return actual is not None and actual < expected
    if op == "lte": return actual is not None and actual <= expected
    if op == "gt": return actual is not None and actual > expected
    if op == "gte": return actual is not None and actual >= expected
    if op == "isnull": return (actual is None) is bool(expected)
    raise AssertionError(f"unsupported lookup {key}")

class Q:
    def __init__(self, *args, **kwargs):
        self.children = list(args)
        self.kwargs = dict(kwargs)
        self.connector = "AND"
        self.negated = False
    def _combine(self, other, connector):
        q = Q(self, other); q.connector = connector; return q
    def __or__(self, other): return self._combine(other, "OR")
    def __and__(self, other): return self._combine(other, "AND")
    def __invert__(self):
        q = Q(self); q.negated = True; return q
    def matches(self, row):
        parts = [child.matches(row) for child in self.children]
        parts += [_lookup(row, k, v) for k, v in self.kwargs.items()]
        result = (any(parts) if self.connector == "OR" else all(parts)) if parts else True
        return not result if self.negated else result

django_models = types.ModuleType("django.db.models"); django_models.Q = Q
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone"); django_timezone.now = lambda: NOW
django_utils.timezone = django_timezone
sys.modules.update({
    "django": django, "django.conf": django_conf, "django.contrib.auth": django_auth,
    "django.db": django_db, "django.db.models": django_models,
    "django.utils": django_utils, "django.utils.timezone": django_timezone,
})

class TokenQuery:
    def __init__(self, digests, live): self.digests=set(digests); self.live=live
    def filter(self, *args, **kwargs): return self
    def exists(self): return bool(self.digests & self.live)
class TokenManager:
    def __init__(self): self.live=set(); self.user_tokens={}
    def filter(self, **kwargs):
        if "digest" in kwargs: return TokenQuery({kwargs.get("digest")}, self.live)
        if "user__username" in kwargs: return TokenQuery(self.user_tokens.get(str(kwargs["user__username"]), set()), self.live)
        return TokenQuery(set(), self.live)
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
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability = lambda **kwargs: kwargs
sys.modules["tec_tac.capabilities"] = caps

class Row:
    def __init__(self, manager, **values):
        self._manager = manager
        self.__dict__.update(values)
    def delete(self):
        self._manager.rows.remove(self)

class QuerySet:
    def __init__(self, manager, rows): self.manager=manager; self.rows=list(rows)
    def filter(self, *args, **kwargs):
        rows=self.rows
        for q in args: rows=[row for row in rows if q.matches(row)]
        for key, value in kwargs.items(): rows=[row for row in rows if _lookup(row, key, value)]
        return QuerySet(self.manager, rows)
    def count(self): return len(self.rows)
    def values_list(self, field, flat=False): return [getattr(row, field) for row in self.rows]
    def delete(self):
        for row in list(self.rows):
            if row in self.manager.rows: self.manager.rows.remove(row)
        return (len(self.rows), {})
    def iterator(self): return iter(list(self.rows))

class Manager:
    def __init__(self): self.rows=[]
    def add(self, **values):
        row=Row(self, **values); self.rows.append(row); return row
    def filter(self, *args, **kwargs): return QuerySet(self, self.rows).filter(*args, **kwargs)

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
    def save(self, update_fields=None): self.saved_fields=tuple(update_fields or ())
CONFIG=Config()
class TecTacSessionSecurityConfig:
    @classmethod
    def current(cls): return CONFIG
class TecTacSessionTrust: objects=Manager()
class TecTacSessionAudit: objects=Manager()
models_mod=types.ModuleType("tec_tac.models")
models_mod.TecTacSessionSecurityConfig=TecTacSessionSecurityConfig
models_mod.TecTacSessionTrust=TecTacSessionTrust
models_mod.TecTacSessionAudit=TecTacSessionAudit
sys.modules["tec_tac.models"] = models_mod

spec=importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
mod._active_non_knox_credential_fingerprints=lambda *, now: set()

old = NOW - timedelta(days=45)
recent = NOW - timedelta(days=2)
# Expired unrevoked row: must be deleted by queryset.delete().
TecTacSessionTrust.objects.add(
    revoked=False, absolute_expires_at=old, idle_expires_at=old,
    revoked_at=None, updated_at=old, knox_digest="", token_fingerprint="expired", username="expired-user",
)
# Old revoked row with no live credential: must be individually deleted.
TecTacSessionTrust.objects.add(
    revoked=True, absolute_expires_at=old, idle_expires_at=old,
    revoked_at=old, updated_at=old, knox_digest="dead-token", token_fingerprint="dead", username="dead-user",
)
# Old revoked row with a live Knox credential: must remain as a tombstone.
TecTacSessionTrust.objects.add(
    revoked=True, absolute_expires_at=old, idle_expires_at=old,
    revoked_at=old, updated_at=old, knox_digest="live-token", token_fingerprint="live", username="live-user",
)
AuthToken.objects.live.add("live-token")
# Old revoked legacy row with no digest but a still-live Knox token for the same
# username: must remain even after retention because Tactical can still accept it.
TecTacSessionTrust.objects.add(
    revoked=True, absolute_expires_at=old, idle_expires_at=old,
    revoked_at=old, updated_at=old, knox_digest="", token_fingerprint="legacy-live", username="legacy-user",
)
AuthToken.objects.live.add("legacy-user-token")
AuthToken.objects.user_tokens["legacy-user"] = {"legacy-user-token"}
# Recent revoked row: inside retention and must remain.
TecTacSessionTrust.objects.add(
    revoked=True, absolute_expires_at=recent, idle_expires_at=recent,
    revoked_at=recent, updated_at=recent, knox_digest="", token_fingerprint="recent", username="recent-user",
)
TecTacSessionAudit.objects.add(created_at=old)
TecTacSessionAudit.objects.add(created_at=recent)

result = mod.cleanup_session_history_if_due(now=NOW)
assert result["ran"] is True
assert result["expired_sessions_deleted"] == 1, result
assert result["revoked_tombstones_deleted"] == 1, result
assert result["audit_events_deleted"] == 1, result
assert CONFIG.last_history_cleanup_at == NOW
assert CONFIG.saved_fields == ("last_history_cleanup_at",)
assert sorted(row.token_fingerprint for row in TecTacSessionTrust.objects.rows) == ["legacy-live", "live", "recent"]
assert len(TecTacSessionAudit.objects.rows) == 1 and TecTacSessionAudit.objects.rows[0].created_at == recent

# A second scheduler tick inside 24h must not rerun retention or alter rows.
second = mod.cleanup_session_history_if_due(now=NOW + timedelta(hours=1))
assert second["ran"] is False and second["reason"] == "not_due", second
assert sorted(row.token_fingerprint for row in TecTacSessionTrust.objects.rows) == ["legacy-live", "live", "recent"]

print("[TEST] PASS D4 scheduled cleanup deletes expired rows and preserves live tombstones")
