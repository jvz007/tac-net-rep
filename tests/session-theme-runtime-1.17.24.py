"""Runtime check for Core 1.17.24: the session theme, the real migration 0028 and the three calls. DEV SERVER ONLY.
It did NOT run on the development PC (Django and the Tactical database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac && ../env/bin/python manage.py shell < /path/to/tests/session-theme-runtime-1.17.24.py

It checks that migration 0028 added the column, then runs the real SessionThemeView GET, PUT and DELETE against throwaway session
rows inside one transaction that is rolled back: the three themes, refused values, another session and another user untouched, the
saved preference untouched and a revoked row not written. Prints PASS or FAIL for each step and exits with status 1 when any fails.
"""
import sys
import uuid
from datetime import timedelta

from accounts.models import User
from django.db import transaction
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac import preferences, session_security_views
from tec_tac.models import TecTacSessionTrust

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]


class Rollback(Exception):
    pass


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


def make_session(user, suffix):
    now = timezone.now()
    return TecTacSessionTrust.objects.create(
        token_fingerprint=f"{MARK}-{suffix}", user=user, username=user.username, last_activity_at=now, last_seen_at=now,
        absolute_expires_at=now + timedelta(hours=8), idle_expires_at=now + timedelta(minutes=30),
    )


def call(method, session, body=None):
    factory = APIRequestFactory()
    url = "/api/tfd/session/theme/"
    request = getattr(factory, method)(url, body, format="json") if body is not None else getattr(factory, method)(url)
    force_authenticate(request, user=session.user)
    # The session guard sets request.tec_tac_session from a Knox token. Here the row is attached directly, and the view logic runs.
    request.tec_tac_session = session
    return session_security_views.SessionThemeView.as_view(permission_classes=[])(request)


try:
    with transaction.atomic():
        check("session_theme" in {f.name for f in TecTacSessionTrust._meta.get_fields()}, "migration 0028 added the column")
        alice = User(username=f"{MARK}-alice")
        alice.set_password(uuid.uuid4().hex)
        alice.save()
        bob = User(username=f"{MARK}-bob")
        bob.set_password(uuid.uuid4().hex)
        bob.save()
        mine, other_session, bobs = make_session(alice, "a1"), make_session(alice, "a2"), make_session(bob, "b1")
        before_prefs = preferences.get_user_preferences(alice)[0]

        def default_and_the_three_themes():
            check(call("get", mine).data == {"theme": None}, "default")
            for theme in ("dark", "light", "high-contrast"):
                response = call("put", mine, {"theme": theme})
                check(response.status_code == 200 and response.data == {"theme": theme}, response.data)
                mine.refresh_from_db()
                check(mine.session_theme == theme, "stored on the row")

        def a_refused_value_changes_nothing():
            for body in ({"theme": "blue"}, {"theme": None}, {"theme": True}, {}, {"theme": "dark", "x": 1}):
                response = call("put", mine, body)
                check(response.status_code == 400, (body, response.status_code))
            mine.refresh_from_db()
            check(mine.session_theme == "high-contrast", "unchanged")

        def other_rows_are_untouched():
            other_session.refresh_from_db()
            bobs.refresh_from_db()
            check(other_session.session_theme == "" and bobs.session_theme == "", "another session of the same user and another user")

        def clear():
            check(call("delete", mine).data == {"theme": None}, "delete")
            mine.refresh_from_db()
            check(mine.session_theme == "", "cleared")

        def the_saved_preference_is_untouched():
            check(preferences.get_user_preferences(alice)[0] == before_prefs, "the saved preference document did not change")

        def a_revoked_row_is_not_written():
            mine.revoked = True
            mine.save(update_fields=["revoked"])
            call("put", mine, {"theme": "light"})
            mine.refresh_from_db()
            check(mine.session_theme == "", "a revoked row keeps no choice")

        for name, fn in (
            ("migration 0028 and the three themes through PUT and GET", default_and_the_three_themes),
            ("a refused value changes nothing", a_refused_value_changes_nothing),
            ("another session and another user are untouched", other_rows_are_untouched),
            ("DELETE clears the choice", clear),
            ("the saved preference is untouched", the_saved_preference_is_untouched),
            ("a revoked row is not written", a_revoked_row_is_not_written),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed (the transaction was rolled back)")
if not all(RESULTS):
    sys.exit(1)
