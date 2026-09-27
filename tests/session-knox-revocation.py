#!/usr/bin/env python3
"""M2 behavioural regression: Tec-Tac revocation invalidates Tactical Knox credentials."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"

settings = types.SimpleNamespace(SECRET_KEY="m2-secret", ROOT_USER="root")
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
class Q:
    def __init__(self, *args, **kwargs): pass
    def __or__(self, other): return self
    def __and__(self, other): return self
    def __invert__(self): return self
django_models = types.ModuleType("django.db.models"); django_models.Q = Q
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone"); django_timezone.now = lambda: None
django_utils.timezone = django_timezone
sys.modules.update({
    "django": django, "django.conf": django_conf, "django.contrib.auth": django_auth,
    "django.db": django_db, "django.db.models": django_models,
    "django.utils": django_utils, "django.utils.timezone": django_timezone,
})

class TokenQuery:
    def __init__(self, manager, digests): self.manager=manager; self.digests=set(digests)
    def exclude(self, **kwargs):
        digests=set(self.digests)
        if "digest__in" in kwargs: digests -= {str(v) for v in kwargs["digest__in"]}
        else: raise AssertionError(f"unsupported token exclude {kwargs}")
        return TokenQuery(self.manager, digests)
    def delete(self):
        self.manager.deleted.append(set(self.digests))
        self.manager.live -= self.digests
        return (len(self.digests), {})
class TokenManager:
    def __init__(self): self.live=set(); self.deleted=[]; self.user_tokens={}
    def filter(self, **kwargs):
        if "digest" in kwargs: return TokenQuery(self, {str(kwargs["digest"])})
        if "digest__in" in kwargs: return TokenQuery(self, {str(v) for v in kwargs["digest__in"]})
        if "user__username" in kwargs: return TokenQuery(self, set(self.user_tokens.get(str(kwargs["user__username"]), set())))
        return TokenQuery(self, set())
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

pkg = types.ModuleType("tec_tac"); pkg.__path__=[str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability=lambda **kwargs: kwargs
sys.modules["tec_tac.capabilities"] = caps

class Row:
    def __init__(self, id, username, digest, revoked=False):
        self.id=id; self.pk=id; self.username=username; self.knox_digest=digest; self.revoked=revoked
        self.revoked_at=None; self.revoked_by=""; self.revocation_reason=""
    def save(self, update_fields=None): self.saved_fields=tuple(update_fields or ())

class QuerySet:
    def __init__(self, manager, rows): self.manager=manager; self.rows=list(rows)
    def select_for_update(self): return self
    def filter(self, **kwargs):
        rows=self.rows
        for key, value in kwargs.items():
            if key == "pk": rows=[r for r in rows if r.pk == value]
            elif key == "username": rows=[r for r in rows if r.username == value]
            elif key == "revoked": rows=[r for r in rows if r.revoked is value]
            elif key == "knox_digest__in": rows=[r for r in rows if r.knox_digest in set(value)]
            else: raise AssertionError(f"unsupported filter {key}")
        return QuerySet(self.manager, rows)
    def exclude(self, **kwargs):
        rows=self.rows
        for key, value in kwargs.items():
            if key == "pk": rows=[r for r in rows if r.pk != value]
            else: raise AssertionError(f"unsupported exclude {key}")
        return QuerySet(self.manager, rows)
    def get(self, **kwargs):
        found=self.filter(**kwargs).rows
        assert len(found)==1, found
        return found[0]
    def values_list(self, field, flat=False):
        assert flat is True
        return [getattr(r, field) for r in self.rows]
    def first(self): return self.rows[0] if self.rows else None
    def __iter__(self): return iter(list(self.rows))

class TrustManager:
    def __init__(self): self.rows=[]
    def select_for_update(self): return QuerySet(self, self.rows)
    def filter(self, **kwargs): return QuerySet(self, self.rows).filter(**kwargs)

TRUST=TrustManager()
class TecTacSessionTrust: objects=TRUST
class Config:
    @classmethod
    def current(cls): return types.SimpleNamespace()
class TecTacSessionSecurityConfig(Config): pass
class TecTacSessionAudit: pass
models_mod=types.ModuleType("tec_tac.models")
models_mod.TecTacSessionSecurityConfig=TecTacSessionSecurityConfig
models_mod.TecTacSessionTrust=TecTacSessionTrust
models_mod.TecTacSessionAudit=TecTacSessionAudit
sys.modules["tec_tac.models"] = models_mod

spec=importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

# Exercise the real revocation helper, including Tactical Knox invalidation.
mod._serialize_session = lambda row, **kwargs: {"id": str(row.id), "revoked": row.revoked}
audits=[]
mod._audit = lambda *args, **kwargs: audits.append((args, kwargs))

# Single Tec-Tac session revoke must remove the linked Tactical Knox token.
one=Row("s1", "alice", "digest-one")
TRUST.rows[:] = [one]
AuthToken.objects.live={"digest-one"}; AuthToken.objects.deleted=[]
result=mod.revoke_session("s1", reason="admin", requested_by="root")
assert result["revoked"] is True
assert one.revoked is True
assert "digest-one" not in AuthToken.objects.live
assert {"digest-one"} in AuthToken.objects.deleted

# Revoke-other-sessions must remove each revoked session's Knox token while
# preserving the explicitly excluded/current session credential.
current=Row("current", "alice", "keep-digest")
other1=Row("s2", "alice", "drop-a")
other2=Row("s3", "alice", "drop-b")
TRUST.rows[:] = [current, other1, other2]
AuthToken.objects.live={"keep-digest", "drop-a", "drop-b", "unobserved-knox"}; AuthToken.objects.deleted=[]
AuthToken.objects.user_tokens={"alice": set(AuthToken.objects.live)}
result=mod.revoke_user_sessions("alice", except_session_id="current", reason="others", requested_by="alice")
assert result["revoked"] == 2, result
assert current.revoked is False and other1.revoked is True and other2.revoked is True
assert AuthToken.objects.live == {"keep-digest"}, AuthToken.objects.live
assert {"drop-a", "drop-b", "unobserved-knox"} in AuthToken.objects.deleted

# A legacy trust row without a Knox digest cannot safely identify one Tactical
# token. Fail closed by invalidating that user's Knox credentials instead of
# leaving a native Tactical session alive.
legacy=Row("legacy", "alice", "")
TRUST.rows[:] = [legacy]
AuthToken.objects.live={"legacy-live", "unrelated"}; AuthToken.objects.deleted=[]
AuthToken.objects.user_tokens={"alice": {"legacy-live"}, "bob": {"unrelated"}}
mod.revoke_session("legacy", requested_by="root")
assert legacy.revoked is True
assert AuthToken.objects.live == {"unrelated"}
assert {"legacy-live"} in AuthToken.objects.deleted

# Automatic revocation paths use the same helper, so an idle/IP/absolute revoke
# also invalidates the linked Tactical credential rather than only the Tec-Tac row.
auto=Row("auto", "alice", "auto-digest")
AuthToken.objects.live={"auto-digest"}; AuthToken.objects.deleted=[]
mod._revoke_locked(auto, reason="idle-timeout", requested_by="core")
assert auto.revoked is True
assert AuthToken.objects.live == set()
assert {"auto-digest"} in AuthToken.objects.deleted

print("[TEST] PASS M2 Tec-Tac revocation invalidates linked Knox credentials")
