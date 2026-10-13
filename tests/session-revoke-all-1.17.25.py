#!/usr/bin/env python3
"""1.17.25 regression (CQ76): end every login session, the caller's own included by default, and report current_kept from what was spared.

Builds on tests/session-revoke-all-1.17.24.py (same stubs). Covered here: the default ends the caller's own token and trust row
and reports current_kept false; include_current false spares the caller's token and trust row by digest, and a legacy row with
no bound digest by primary key (the held Low); a missing digest or a missing row spares nothing, and current_kept is false;
current_kept needs both the token and the row (never true when only one survived); the view defaults include_current to true,
passes the caller's trust row through, refuses a non-boolean (null included) with 400, and refuses a non-superuser with 403 and
one deny row; the audit metadata carries include_current and current_kept and never a digest. Django is not installed on the
development PC; the real Knox delete and the transaction rollback run in tests/session-revoke-all-runtime-1.17.24.py on the dev server.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


settings = types.SimpleNamespace(SECRET_KEY="s", ROOT_USER="root")
ERRORS = {"n": 0}


class Atomic:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            ERRORS["n"] += 1
        return False


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


class Q:
    def __init__(self, *a, **k):
        pass

    def __or__(self, o):
        return self

    __and__ = __invert__ = __or__


mod("django")
mod("django.conf", settings=settings)
mod("django.contrib")
mod("django.contrib.auth", get_user_model=lambda: object)
mod("django.db", transaction=types.SimpleNamespace(atomic=lambda: Atomic()))
mod("django.db.models", Q=Q)
mod("django.utils", timezone=types.SimpleNamespace(now=lambda: "now"))
sys.modules["django.utils.timezone"] = sys.modules["django.utils"].timezone
mod("django.shortcuts", get_object_or_404=lambda *a, **k: None)


class Token:
    def __init__(self, digest, user_id):
        self.digest, self.user_id = digest, user_id


class TokenQS:
    def __init__(self, tokens):
        self.tokens = list(tokens)

    def exclude(self, **kw):
        out = self.tokens
        if "digest" in kw:
            out = [t for t in out if t.digest != kw["digest"]]
        return TokenQS(out)

    def delete(self):
        gone = {t.digest for t in self.tokens}
        TOKENS[:] = [t for t in TOKENS if t.digest not in gone]

    def exists(self):
        return bool(self.tokens)

    def __iter__(self):
        return iter(list(self.tokens))


TOKENS: list = []


class AuthToken:
    objects = types.SimpleNamespace(all=lambda: TokenQS(TOKENS), filter=lambda **kw: TokenQS([t for t in TOKENS if t.digest == kw["digest"]]))


mod("knox")
mod("knox.models", AuthToken=AuthToken)


class APIException(Exception):
    def __init__(self, detail=None):
        super().__init__(str(detail))


class IsAuthenticated:
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


mod("rest_framework")
mod("rest_framework.exceptions", APIException=APIException)
mod("rest_framework.permissions", IsAuthenticated=IsAuthenticated)
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.capabilities", register_capability=lambda **k: k)


class Trust:
    def __init__(self, id, username, digest):
        self.id = self.pk = id
        self.username, self.knox_digest, self.revoked = username, digest, False
        self.revoked_by = self.revocation_reason = ""

    def save(self, update_fields=None):
        pass


class TrustQS:
    def __init__(self, rows):
        self.rows = list(rows)

    def select_for_update(self):
        return self

    def filter(self, **kw):
        rows = self.rows
        if "revoked" in kw:
            rows = [r for r in rows if r.revoked is kw["revoked"]]
        return TrustQS(rows)

    def exclude(self, **kw):
        rows = self.rows
        if "knox_digest" in kw:
            rows = [r for r in rows if r.knox_digest != kw["knox_digest"]]
        return TrustQS(rows)

    def __iter__(self):
        return iter(list(self.rows))


TRUSTS: list = []


class TecTacSessionTrust:
    objects = types.SimpleNamespace(select_for_update=lambda: TrustQS(TRUSTS), filter=lambda **kw: TrustQS(TRUSTS).filter(**kw))


mod("tec_tac.models", TecTacSessionTrust=TecTacSessionTrust, TecTacSessionSecurityConfig=type("C", (), {}), TecTacSessionAudit=type("A", (), {}))
ROWS: list = []
FAIL = {"on": False}


def record(**kw):
    if FAIL["on"]:
        raise RuntimeError("audit store down")
    ROWS.append(kw)


mod("tec_tac.audit", record=record)


def load(name):
    spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


ss = load("session_security")
EVENTS: list = []
ss._audit = lambda event_type, **kw: EVENTS.append((event_type, kw))


def user(name, **kw):
    return types.SimpleNamespace(**{"username": name, "is_authenticated": True, "is_superuser": False, "role": None, "pk": name, **kw})


root = user("root")
sup = user("boss", is_superuser=True)
role_super = user("rolesup", role=types.SimpleNamespace(is_superuser=True))
acct_admin = user("acct", role=types.SimpleNamespace(is_superuser=False, can_manage_accounts=True))
plain = user("plain")


def reset():
    TOKENS[:] = [Token("d-boss", 1), Token("d-boss2", 1), Token("d-root", 2), Token("d-a", 3), Token("d-b", 4)]
    TRUSTS[:] = [Trust(1, "boss", "d-boss"), Trust(2, "root", "d-root"), Trust(3, "a", "d-a"), Trust(4, "b", "d-b")]
    ROWS.clear()
    EVENTS.clear()
    FAIL["on"] = False


def call(who, **kw):
    return ss.revoke_all_login_sessions(requested_by=who.username, requester=who, **kw)


# (A) the default ends the caller's own token and trust row too; current_kept is false
reset()
out = call(sup, reason="clean-up", current_digest="d-boss")
must(out == {"revoked_tokens": 5, "revoked_sessions": 4, "users": 4, "current_kept": False}, out)
must(not TOKENS and all(r.revoked for r in TRUSTS), "the default ends everything, the caller's own included")
event = next(e for e in EVENTS if e[0] == "all_login_sessions_revoked")[1]
must(event["metadata"] == {"tokens": 5, "users": 4, "tec_tac_sessions": 4, "include_current": True, "current_kept": False}, event)
must(ROWS[0]["metadata"] == event["metadata"] and ROWS[0]["strict"] is True, ROWS)

# (B) include_current false spares the caller's token and row by digest; the answer and the audit say so
reset()
out = call(sup, include_current=False, current_digest="d-boss", current_session=TRUSTS[0])
must(out == {"revoked_tokens": 4, "revoked_sessions": 3, "users": 4, "current_kept": True}, out)
must([t.digest for t in TOKENS] == ["d-boss"] and [r.id for r in TRUSTS if not r.revoked] == [1], "the caller is spared")
must(ROWS[0]["metadata"] == {"tokens": 4, "users": 4, "tec_tac_sessions": 3, "include_current": False, "current_kept": True}, ROWS)

# (C) the held Low: a legacy trust row with no bound digest is spared by its primary key while its token survives
reset()
TRUSTS[0].knox_digest = ""
out = call(sup, include_current=False, current_digest="d-boss", current_session=TRUSTS[0])
must(out == {"revoked_tokens": 4, "revoked_sessions": 3, "users": 4, "current_kept": True}, out)
must([t.digest for t in TOKENS] == ["d-boss"], "the caller's token survives")
must([r.id for r in TRUSTS if not r.revoked] == [1], "the legacy row is not revoked while its token survives")

# (D) include_current false with no digest and no row: nothing is spared, and the answer says so (not true)
reset()
out = call(sup, include_current=False, current_digest=None, current_session=TRUSTS[0])
must(out == {"revoked_tokens": 5, "revoked_sessions": 4, "users": 4, "current_kept": False}, out)
must(not TOKENS and all(r.revoked for r in TRUSTS), "no digest means nothing is spared")
reset()
out = call(sup, include_current=False, current_digest="", current_session=None)
must(out["current_kept"] is False and not TOKENS, out)

# (E) a row spared with its token gone is not a kept session: current_kept needs both
reset()
TOKENS[:] = [t for t in TOKENS if t.digest != "d-boss"]
out = call(sup, include_current=False, current_digest="d-boss", current_session=TRUSTS[0])
must(out["current_kept"] is False and [r.id for r in TRUSTS if not r.revoked] == [1], out)

# (F) the token spared with its row gone is not a kept session either
reset()
TRUSTS[:] = [r for r in TRUSTS if r.id != 1]
out = call(sup, include_current=False, current_digest="d-boss", current_session=None)
must(out["current_kept"] is False and [t.digest for t in TOKENS] == ["d-boss"], out)

# (G) the view: the default is true, the trust row is passed through, a non-boolean (null included) is 400
views = load("session_security_views")
must(views.revoke_all_login_sessions is ss.revoke_all_login_sessions, "the view calls the real function")
views.request_knox_digest = lambda request: "d-boss"


class Req:
    def __init__(self, who, data, session=None):
        self.user, self.data = who, data
        if session is not None:
            self.tec_tac_session = session


v = views.AdminAllLoginSessionsRevokeView()
reset()
resp = v.post(Req(sup, {}, TRUSTS[0]))
must(resp.status_code == 200 and resp.data["current_kept"] is False and not TOKENS, resp.data)
reset()
resp = v.post(Req(sup, {"include_current": False}, TRUSTS[0]))
must(resp.status_code == 200 and resp.data["current_kept"] is True and [t.digest for t in TOKENS] == ["d-boss"], resp.data)
for bad in ({"include_current": None}, {"include_current": "false"}, {"include_current": 0}):
    reset()
    resp = v.post(Req(sup, bad, TRUSTS[0]))
    must(resp.status_code == 400 and len(TOKENS) == 5 and not any(r.revoked for r in TRUSTS), (bad, resp.status_code))

# (H) a non-superuser is refused with 403, one deny row, and nothing changes
reset()
resp = v.post(Req(acct_admin, {"include_current": False}, TRUSTS[0]))
must(resp.status_code == 403 and len(TOKENS) == 5 and not any(r.revoked for r in TRUSTS), resp.status_code)
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["strict"] is False and not EVENTS, ROWS)
reset()
resp = v.post(Req(plain, {}, TRUSTS[0]))
must(resp.status_code == 403 and len(TOKENS) == 5, resp.status_code)

# (I) the audit metadata never carries a digest, whatever the case
reset()
call(sup, include_current=False, current_digest="d-boss", current_session=TRUSTS[0])
text = repr(ROWS) + repr(EVENTS)
must("d-boss" not in text and "d-a" not in text and "current_kept" in text and "include_current" in text, "counts and flags only")

# (J) the signature default and the contract row
must(ss.revoke_all_login_sessions.__kwdefaults__["include_current"] is True, "the default ends the caller's session (CQ76)")
must("current_session" in ss.revoke_all_login_sessions.__kwdefaults__, "the caller's trust row is an optional keyword")
contracts_src = (APP / "contracts.py").read_text(encoding="utf-8")
must("default true (1.17.25, CQ76)" in contracts_src and "current_kept\": \"boolean: true only when" in contracts_src, "contract text")
doc = (ROOT / "docs" / "session-security.md").read_text(encoding="utf-8")
must("default true" in doc and "current_kept" in doc and "include_current: false" in doc, "doc")

print("session revoke all 1.17.25: ok")
