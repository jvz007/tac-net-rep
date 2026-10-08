#!/usr/bin/env python3
"""1.17.1 CQ4 regression: the scheduler sweep enforces session expiry without a request."""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"
TICK = ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tec_tac_scheduler_tick.py"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=dt_timezone.utc)


# --- Minimal query layer: Q objects are real predicates over plain row objects. ---
def _match(row, key, value):
    field, _, op = key.partition("__")
    actual = getattr(row, field)
    if op == "":
        return actual == value
    if op == "lt":
        return actual is not None and actual < value
    if op == "lte":
        return actual is not None and actual <= value
    if op == "isnull":
        return (actual is None) is bool(value)
    if op == "in":
        return actual in set(value)
    raise AssertionError(f"unsupported lookup {key}")


class Q:
    def __init__(self, *args, **kwargs):
        self.args, self.kwargs, self.mode = args, kwargs, "and"

    def __or__(self, other):
        q = Q(self, other)
        q.mode = "or"
        return q

    def __and__(self, other):
        return Q(self, other)

    def test(self, row):
        parts = [a.test(row) for a in self.args] + [_match(row, k, v) for k, v in self.kwargs.items()]
        return any(parts) if self.mode == "or" else all(parts)


class Rows(list):
    """A list that also behaves like the few QuerySet methods the code uses."""

    def _wrap(self, rows):
        out = Rows(rows)
        out.manager = self.manager
        return out

    def filter(self, *qs, **kwargs):
        rows = [r for r in self if all(q.test(r) for q in qs) and all(_match(r, k, v) for k, v in kwargs.items())]
        return self._wrap(rows)

    def exclude(self, **kwargs):
        return self._wrap([r for r in self if not all(_match(r, k, v) for k, v in kwargs.items())])

    def order_by(self, *fields):
        return self._wrap(sorted(self, key=lambda r: getattr(r, fields[0])))

    def values_list(self, field, flat=False):
        assert flat is True
        return [getattr(r, field) for r in self]

    def select_for_update(self, skip_locked=False):
        assert skip_locked is True, "sweep must lock with skip_locked=True"
        return self._wrap([r for r in self if r.pk not in self.manager.locked])

    def first(self):
        return self[0] if self else None

    def count(self):
        return len(self)

    def delete(self):
        n = len(self)
        for r in list(self):
            self.manager.rows.remove(r)
        return (n, {})

    def iterator(self):
        return iter(list(self))


class Manager:
    def __init__(self):
        self.rows = []
        self.locked = set()

    def _all(self):
        out = Rows(self.rows)
        out.manager = self
        return out

    def filter(self, *qs, **kw):
        return self._all().filter(*qs, **kw)

    def select_for_update(self, skip_locked=False):
        return self._all().select_for_update(skip_locked=skip_locked)


class AtomicCtx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def install_stubs():
    for name in ("django", "django.conf", "django.contrib", "django.contrib.auth", "django.db", "django.db.models",
                 "django.utils", "django.utils.timezone", "knox", "knox.models", "rest_framework",
                 "rest_framework.exceptions", "rest_framework.permissions"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["django.conf"].settings = types.SimpleNamespace(SECRET_KEY="sweep-secret")
    sys.modules["django.contrib.auth"].get_user_model = lambda: object
    sys.modules["django.db"].transaction = types.SimpleNamespace(atomic=lambda: AtomicCtx())
    sys.modules["django.db.models"].Q = Q
    sys.modules["django.utils"].timezone = sys.modules["django.utils.timezone"]
    sys.modules["django.utils.timezone"].now = lambda: NOW

    class APIException(Exception):
        def __init__(self, detail=None):
            super().__init__(str(detail))

    sys.modules["rest_framework.exceptions"].APIException = APIException
    sys.modules["rest_framework.permissions"].IsAuthenticated = type("IsAuthenticated", (), {})
    pkg = types.ModuleType("tec_tac")
    pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
    sys.modules["tec_tac"] = pkg
    caps = types.ModuleType("tec_tac.capabilities")
    caps.register_capability = lambda **kw: kw
    sys.modules["tec_tac.capabilities"] = caps


install_stubs()


class Token:
    def __init__(self, digest, username):
        self.digest = digest
        self.username = username


class TokenManager(Manager):
    def filter(self, *qs, **kwargs):
        if "user__username" in kwargs:
            name = kwargs.pop("user__username")
            out = Rows([t for t in self.rows if t.username == name])
            out.manager = self
            return out.filter(*qs, **kwargs)
        return self._all().filter(*qs, **kwargs)


class AuthToken:
    objects = TokenManager()


sys.modules["knox.models"].AuthToken = AuthToken


class Row:
    def __init__(self, pk, username, digest, *, created, activity, revoked=False):
        self.pk = self.id = pk
        self.username = username
        self.knox_digest = digest
        self.created_at = created
        self.last_activity_at = activity
        self.absolute_expires_at = created + timedelta(hours=8)
        self.idle_expires_at = activity + timedelta(minutes=30)
        self.revoked = revoked
        self.revoked_at = None
        self.revoked_by = ""
        self.revocation_reason = ""

    def save(self, update_fields=None):
        pass


TRUST = Manager()


class TecTacSessionTrust:
    objects = TRUST


POLICY = types.SimpleNamespace(history_retention_days=30)


class TecTacSessionSecurityConfig:
    @classmethod
    def current(cls):
        return POLICY


class TecTacSessionAudit:
    objects = Manager()


models_mod = types.ModuleType("tec_tac.models")
models_mod.TecTacSessionSecurityConfig = TecTacSessionSecurityConfig
models_mod.TecTacSessionTrust = TecTacSessionTrust
models_mod.TecTacSessionAudit = TecTacSessionAudit
sys.modules["tec_tac.models"] = models_mod

spec = importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

audits = []
mod._audit = lambda event, **kw: audits.append((event, kw))
policy = {"idle_timeout_minutes": 30, "absolute_lifetime_minutes": 480, "session_audit_enabled": True}
mod._policy_dict = lambda config=None: dict(policy)
mod._active_non_knox_credential_fingerprints = lambda **kw: None


def reset(rows, tokens):
    TRUST.rows[:] = rows
    TRUST.locked = set()
    AuthToken.objects.rows[:] = [Token(d, u) for d, u in tokens]
    audits.clear()


def digests():
    return {t.digest for t in AuthToken.objects.rows}


def row(pk, user, digest, *, age_min, idle_min, revoked=False):
    return Row(pk, user, digest, created=NOW - timedelta(minutes=age_min), activity=NOW - timedelta(minutes=idle_min), revoked=revoked)


# (a) idle-expired and absolute-expired rows are revoked, exact token deleted, one audit event each.
idle = row("idle", "alice", "d-idle", age_min=100, idle_min=45)
absolute = row("abs", "alice", "d-abs", age_min=500, idle_min=1)
reset([idle, absolute], [("d-idle", "alice"), ("d-abs", "alice"), ("d-other", "alice")])
res = mod.sweep_expired_sessions(now=NOW)
assert idle.revoked and absolute.revoked, res
assert idle.revocation_reason == "idle-timeout" and absolute.revocation_reason == "absolute-timeout"
assert idle.revoked_by == absolute.revoked_by == "tec-tac-scheduler"
assert digests() == {"d-other"}, digests()
assert sorted(e for e, _ in audits) == ["session_absolute_timeout", "session_idle_timeout"], audits
assert all(kw["requested_by"] == "tec-tac-scheduler" for _, kw in audits)
assert res["revoked"] == 2 and res["idle_timeout"] == 1 and res["absolute_timeout"] == 1, res

# (b) an active row and its token are untouched.
active = row("act", "bob", "d-act", age_min=100, idle_min=5)
reset([active], [("d-act", "bob")])
res = mod.sweep_expired_sessions(now=NOW)
assert not active.revoked and digests() == {"d-act"} and not audits and res["revoked"] == 0, res

# (c) a row without a digest is skipped and counted; the user's other tokens survive.
legacy = row("leg", "carol", "", age_min=600, idle_min=600)
reset([legacy], [("d-carol-live", "carol")])
res = mod.sweep_expired_sessions(now=NOW)
assert not legacy.revoked and digests() == {"d-carol-live"} and res["skipped_no_digest"] == 1 and not audits, res

# (d) a revoked row whose token is still live has that exact token deleted.
gone = row("gone", "dave", "d-gone", age_min=10, idle_min=1, revoked=True)
reset([gone], [("d-gone", "dave"), ("d-dave-other", "dave")])
res = mod.sweep_expired_sessions(now=NOW)
assert digests() == {"d-dave-other"} and res["orphan_tokens_deleted"] == 1, (digests(), res)

# (e) a policy shortened since the row was written expires it (stored expiry still in the future).
short = row("short", "erin", "d-short", age_min=100, idle_min=20)
reset([short], [("d-short", "erin")])
assert mod.sweep_expired_sessions(now=NOW)["revoked"] == 0
policy["idle_timeout_minutes"] = 10
res = mod.sweep_expired_sessions(now=NOW)
assert short.revoked and short.revocation_reason == "idle-timeout" and res["revoked"] == 1, res
policy["idle_timeout_minutes"] = 30

# A policy lengthened since the row was written does not expire it early (matches ensure_request_session).
long_row = row("long", "frank", "d-long", age_min=100, idle_min=40)
long_row.idle_expires_at = NOW - timedelta(minutes=10)  # stored under the old, shorter policy
reset([long_row], [("d-long", "frank")])
policy["idle_timeout_minutes"] = 60
assert mod.sweep_expired_sessions(now=NOW)["revoked"] == 0 and not long_row.revoked
policy["idle_timeout_minutes"] = 30

# (f) limit is honoured.
many = [row(f"m{i}", "gina", f"d-m{i}", age_min=100, idle_min=90 + i) for i in range(5)]
reset(many, [(f"d-m{i}", "gina") for i in range(5)])
res = mod.sweep_expired_sessions(now=NOW, limit=2)
assert res["checked"] == 2 and res["revoked"] == 2 and sum(r.revoked for r in many) == 2, res
res = mod.sweep_expired_sessions(now=NOW, limit=500)
assert all(r.revoked for r in many) and digests() == set()

# A row locked by a live request is skipped, not blocked on, and not revoked.
locked = row("lock", "hank", "d-lock", age_min=100, idle_min=90)
reset([locked], [("d-lock", "hank")])
TRUST.locked = {"lock"}
res = mod.sweep_expired_sessions(now=NOW)
assert not locked.revoked and res["skipped_locked"] == 1 and digests() == {"d-lock"}, res

# One failing row does not stop the others.
bad = row("bad", "ivy", "d-bad", age_min=100, idle_min=90)
ok = row("ok", "ivy", "d-ok", age_min=99, idle_min=90)


def _fail_save(update_fields=None):
    raise RuntimeError("db")


bad.save = _fail_save
reset([bad, ok], [("d-bad", "ivy"), ("d-ok", "ivy")])
res = mod.sweep_expired_sessions(now=NOW)
assert res["errors"] == 1 and ok.revoked, res

# (g) cleanup_session_history deletes the token of a stale unrevoked row before the row.
# A stale row without a digest never deletes another of that user's tokens.
stale = Row("stale", "jo", "d-stale", created=NOW - timedelta(days=40), activity=NOW - timedelta(days=40))
stale.absolute_expires_at = stale.idle_expires_at = NOW - timedelta(days=39)
stale_legacy = Row("stale-legacy", "jo", "", created=NOW - timedelta(days=40), activity=NOW - timedelta(days=40))
stale_legacy.absolute_expires_at = stale_legacy.idle_expires_at = NOW - timedelta(days=39)
reset([stale, stale_legacy], [("d-stale", "jo"), ("d-jo-live", "jo")])
res = mod.cleanup_session_history()
assert digests() == {"d-jo-live"}, digests()
assert res["expired_sessions_deleted"] == 2 and not TRUST.rows, res

# (h) the scheduler tick prints session_expiry_sweep=error and continues when the sweep raises.
base = types.ModuleType("django.core.management.base")


class Out:
    def __init__(self):
        self.lines = []

    def write(self, value):
        self.lines.append(str(value))


class BaseCommand:
    def __init__(self):
        self.stdout = Out()
        self.stderr = Out()


base.BaseCommand = BaseCommand
for n in ("django.core", "django.core.management"):
    sys.modules[n] = types.ModuleType(n)
sys.modules["django.core.management.base"] = base
sched = types.ModuleType("tec_tac.scheduler")
sched.dispatch_due_schedules = lambda: {"checked": 1, "queued": [], "skipped": [], "cleaned": 0, "now": "t"}
sys.modules["tec_tac.scheduler"] = sched
fake = types.ModuleType("tec_tac.session_security")
order = []
fake.cleanup_session_history_if_due = lambda: order.append("cleanup") or {"ran": True}


def boom():
    order.append("sweep")
    raise RuntimeError("db unavailable")


fake.sweep_expired_sessions = boom
sys.modules["tec_tac.session_security"] = fake
spec = importlib.util.spec_from_file_location("tick_under_test", TICK)
tick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tick)
cmd = tick.Command()
cmd.handle()
assert order == ["cleanup", "sweep"], order
assert any("session_expiry_sweep=error" in l for l in cmd.stdout.lines), cmd.stdout.lines
assert any("retrying next tick" in l for l in cmd.stderr.lines), cmd.stderr.lines
fake.sweep_expired_sessions = lambda: {"revoked": 3, "skipped_no_digest": 1, "orphan_tokens_deleted": 0}
tick.sweep_expired_sessions = fake.sweep_expired_sessions
cmd = tick.Command()
cmd.handle()
assert any("session_expiry_sweep=ran" in l and "sweep_revoked=3" in l for l in cmd.stdout.lines), cmd.stdout.lines

# The sweep is internal: the capability contract version does not move.
assert mod.CAPABILITY_VERSION == "2.0.0"

print("[TEST] PASS 1.17.1 session expiry sweep revokes expired sessions and their Knox tokens")
