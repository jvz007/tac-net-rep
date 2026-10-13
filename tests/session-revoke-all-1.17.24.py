#!/usr/bin/env python3
"""1.17.24 regression: end every login session for every user (CO17, Johan's test of 12 October 2026).

Django is not installed on the development PC, so the real session_security.py and session_security_views.py are loaded
against stubs (the style of tests/session-knox-revocation.py). Covered: a superuser ends every session and token but keeps
their own; include_current ends that too; protected accounts are included; an account administrator, a plain user and an
anonymous caller are refused with nothing changed; a deny row for the refused call; one session audit event and one strict
Core row with counts only; a failed Core audit write raises (the transaction block sees the error); no tokens gives zeros and
still one event; reason cut to 255; the route and the contract row exist. Real AuthToken deletes run on the dev server.
"""
from __future__ import annotations

import ast
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

    def __iter__(self):
        return iter(list(self.tokens))


TOKENS: list = []


class AuthToken:
    objects = types.SimpleNamespace(all=lambda: TokenQS(TOKENS))


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


# (1) a superuser keeps their own current session by default; protected accounts (root) are included
for who in (sup, root, role_super):
    reset()
    out = call(who, reason="clean-up", current_digest="d-boss")
    must(out == {"revoked_tokens": 4, "revoked_sessions": 3, "users": 4, "current_kept": True}, out)
    must([t.digest for t in TOKENS] == ["d-boss"], TOKENS)
    must([r.id for r in TRUSTS if not r.revoked] == [1], "own trust row kept")
    must(all(r.revoked for r in TRUSTS if r.id != 1), "others revoked")
    # one session audit event, one strict Core row, counts only
    kinds = [e[0] for e in EVENTS if e[0] == "all_login_sessions_revoked"]
    must(len(kinds) == 1, EVENTS)
    event = next(e for e in EVENTS if e[0] == "all_login_sessions_revoked")[1]
    must(event["metadata"] == {"tokens": 4, "users": 4, "tec_tac_sessions": 3, "include_current": False} and event.get("force") is True, event)
    must(len(ROWS) == 1, ROWS)
    row = ROWS[0]
    must(row["module_id"] == "core" and row["action"] == "custom:revoke-all-sessions" and row["object_type"] == "login_sessions" and row["strict"] is True, row)
    must(row["metadata"] == event["metadata"], row)
    text = repr(row) + repr(event)
    must("d-a" not in text and "d-boss" not in text and "d-root" not in text, "no digest in any audit row")
    must(out["users"] == 4, out)

# (2) include_current ends the caller's session too
reset()
out = call(sup, current_digest="d-boss", include_current=True)
must(out == {"revoked_tokens": 5, "revoked_sessions": 4, "users": 4, "current_kept": False}, out)
must(not TOKENS and all(r.revoked for r in TRUSTS), "everything ended")
must(ROWS[0]["metadata"]["include_current"] is True, ROWS)

# (3) no current digest known: nothing is kept, and the answer says so
reset()
out = call(sup, current_digest=None)
must(out["current_kept"] is False and not TOKENS, out)

# (4) refused callers: nothing changes, one deny row each
for who in (acct_admin, plain, user("anon", is_authenticated=False)):
    reset()
    try:
        call(who, current_digest="x")
    except PermissionError:
        pass
    else:
        raise AssertionError(f"{who.username} must be refused")
    must(len(TOKENS) == 5 and not any(r.revoked for r in TRUSTS) and not EVENTS, "nothing changed")
    must(len(ROWS) == 1 and ROWS[0]["action"] == "deny" and ROWS[0]["strict"] is False and ROWS[0]["object_type"] == "login_sessions", ROWS)
must(ss.revoke_all_login_sessions.__kwdefaults__["include_current"] is False, "default keeps the current session")

# (5) a failed deny write never turns the refusal into another error
reset()
FAIL["on"] = True
try:
    call(plain)
except PermissionError:
    pass
else:
    raise AssertionError("must be refused")

# (6) a failed strict Core audit write raises, so the transaction block rolls back
reset()
FAIL["on"] = True
before = ERRORS["n"]
try:
    call(sup, current_digest="d-boss")
except RuntimeError:
    pass
else:
    raise AssertionError("a failed audit write must raise")
must(ERRORS["n"] == before + 1, "the transaction saw the error")

# (7) no active tokens: zeros, still one session event and one Core row
reset()
TOKENS.clear()
TRUSTS.clear()
out = call(sup, current_digest="d-boss")
must(out == {"revoked_tokens": 0, "revoked_sessions": 0, "users": 0, "current_kept": True}, out)
must(len([e for e in EVENTS if e[0] == "all_login_sessions_revoked"]) == 1 and len(ROWS) == 1, (EVENTS, ROWS))

# (8) the view: reason cut to 255, bad types refused, 403 mapped, digest passed through
views = load("session_security_views")
seen = {}


def fake(**kw):
    seen.update(kw)
    if not ss._is_effective_superuser(kw["requester"]):
        raise PermissionError("Ending every login session requires superuser authority.")
    return {"revoked_tokens": 0, "revoked_sessions": 0, "users": 0, "current_kept": True}


views.revoke_all_login_sessions = fake
views.request_knox_digest = lambda request: "d-cur"


class Req:
    def __init__(self, who, data):
        self.user, self.data = who, data


v = views.AdminAllLoginSessionsRevokeView()
resp = v.post(Req(sup, {"reason": "x" * 400}))
must(resp.status_code == 200 and len(seen["reason"]) == 255 and seen["include_current"] is False and seen["current_digest"] == "d-cur", seen)
resp = v.post(Req(sup, {}))
must(resp.status_code == 200 and seen["reason"] == "administrator-request", seen)
resp = v.post(Req(sup, {"include_current": True}))
must(resp.status_code == 200 and seen["include_current"] is True, seen)
for bad in ({"include_current": "yes"}, {"include_current": 1}, {"reason": 5}):
    must(v.post(Req(sup, bad)).status_code == 400, bad)
must(v.post(Req(acct_admin, {})).status_code == 403, "account administrator")

# (9) the route and the contract row
urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("access/sessions/revoke-all/", AdminAllLoginSessionsRevokeView.as_view()' in urls and "AdminAllLoginSessionsRevokeView," in urls, "route")
contracts = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
table = next(ast.literal_eval(n.value) for n in contracts.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
must("include_current" in table["/api/tfd/access/sessions/revoke-all/"]["POST"]["request"], "contract row")
must("revoke-all" in (ROOT / "docs" / "session-security.md").read_text(encoding="utf-8"), "doc")

print("session revoke all 1.17.24: ok")
