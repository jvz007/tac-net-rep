"""Runtime check for Core 1.17.24, updated for Core 1.17.25 (CQ76): end every login session for every user. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Knox and the Tactical database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/session-revoke-all-runtime-1.17.24.py

It runs the real route POST /api/tfd/access/sessions/revoke-all/ as a throwaway superuser, with real Knox tokens, inside one
database transaction that is ROLLED BACK at the end, so the tokens that exist on the server come back. It checks: the caller's own
token is kept by default, every other token is deleted (a protected account's too), include_current ends the caller's as well, an
account administrator without superuser authority gets 403 and nothing changes, and the audit rows carry counts only. From 1.17.25 the
default (no include_current in the body) ends the caller's own session too, so the probe that keeps it sends include_current false.
Prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import Role, User
from django.db import transaction
from knox.models import AuthToken
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac import session_security_views
from tec_tac.models import TecTacSessionAudit

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]


class Rollback(Exception):
    pass


class FakeAuth:
    """What request.auth carries: only the digest is read."""

    def __init__(self, digest):
        self.digest = digest


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def make_user(suffix, *, superuser=False, role=None):
    user = User(username=f"{MARK}-{suffix}", is_superuser=superuser, role=role)
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def call(user, digest, body=None):
    request = APIRequestFactory().post("/api/tfd/access/sessions/revoke-all/", body or {}, format="json")
    force_authenticate(request, user=user, token=FakeAuth(digest))
    # The session guard needs a Knox token that Core has seen; the view and the revoke logic are what run here.
    return session_security_views.AdminAllLoginSessionsRevokeView.as_view(permission_classes=[])(request)


try:
    with transaction.atomic():
        boss = make_user("boss", superuser=True)
        admin_role = Role.objects.create(name=f"{MARK}-accounts", can_manage_accounts=True)
        account_admin = make_user("acct", role=admin_role)
        victim = make_user("victim")
        protected = make_user("protected", superuser=True)
        tokens = {name: AuthToken.objects.create(user)[0] for name, user in (("boss", boss), ("acct", account_admin), ("victim", victim), ("protected", protected))}
        digests = {name: token.digest for name, token in tokens.items()}

        def an_account_administrator_is_refused():
            before = AuthToken.objects.count()
            response = call(account_admin, digests["acct"])
            check(response.status_code == 403, response.status_code)
            check(AuthToken.objects.count() == before, "nothing was deleted")
            check(AuditLog.objects.filter(object_type="login_sessions", action="deny").exists(), "a deny row was written")

        def a_superuser_keeps_their_own_session():
            response = call(boss, digests["boss"], {"reason": "probe", "include_current": False})
            check(response.status_code == 200 and response.data["current_kept"] is True, getattr(response, "data", None))
            check(AuthToken.objects.filter(digest=digests["boss"]).exists(), "the caller's token is kept")
            check(AuthToken.objects.count() == 1, f"every other token is gone, protected accounts included: {AuthToken.objects.count()}")
            check(response.data["revoked_tokens"] >= 3 and response.data["users"] >= 3, response.data)

        def audit_rows_carry_counts_only():
            event = TecTacSessionAudit.objects.filter(event_type="all_login_sessions_revoked").order_by("-created_at").first()
            check(event is not None and set(event.metadata) == {"tokens", "users", "tec_tac_sessions", "include_current", "current_kept"}, event and event.metadata)
            check(all(d not in repr(event.metadata) for d in digests.values()), "no digest in the event")
            row = AuditLog.objects.filter(object_type="login_sessions", action="custom:revoke-all-sessions").order_by("-pk").first()
            check(row is not None and all(d not in repr(row.__dict__) for d in digests.values()), "a Core audit row, no digest")

        def the_default_ends_the_callers_session_too():
            response = call(boss, digests["boss"], {})
            check(response.status_code == 200 and response.data["current_kept"] is False, getattr(response, "data", None))
            check(not AuthToken.objects.filter(digest=digests["boss"]).exists(), "the caller's own token is gone by default")

        def include_current_ends_the_callers_session_too():
            fresh = AuthToken.objects.create(victim)[0]
            response = call(boss, digests["boss"], {"include_current": True})
            check(response.status_code == 200 and response.data["current_kept"] is False, getattr(response, "data", None))
            check(AuthToken.objects.count() == 0 and not AuthToken.objects.filter(digest=fresh.digest).exists(), "every token is gone")

        for name, fn in (
            ("an account administrator without superuser authority is refused with a deny row", an_account_administrator_is_refused),
            ("a superuser ends every other session and keeps their own", a_superuser_keeps_their_own_session),
            ("the audit rows carry counts only", audit_rows_carry_counts_only),
            ("the default ends the caller's session too (1.17.25)", the_default_ends_the_callers_session_too),
            ("include_current ends the caller's session too", include_current_ends_the_callers_session_too),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed (the transaction was rolled back)")
if not all(RESULTS):
    sys.exit(1)
