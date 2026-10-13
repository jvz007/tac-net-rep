"""Runtime check for Core 1.17.26: one Core audit row per API key create, edit and delete. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Knox, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/api-key-audit-runtime-1.17.26.py

It drives Tactical's real GetAddAPIKeys and GetUpdateDeleteAPIKey views, with Core's guard installed, through DRF's APIRequestFactory as a
probe superuser. Everything is written inside one transaction that is ROLLED BACK at the end. Prints PASS or FAIL for each step.

Checks: the guard is installed on the three write handlers; create, edit and delete each add audit rows that name the key; no new audit
row carries the key value; the key is gone after the delete. The exact row shape (object_type api_key, action add, modify, delete) is
pinned by tests/api-key-audit-1.17.26.py. Here the rows are read from Tactical's own AuditLog, so this step proves they reach it.
"""
import sys
import uuid

from accounts.models import APIKey, User
from django.db import transaction
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
KEY_NAME = MARK[-20:]


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


def new_rows(since):
    return list(AuditLog.objects.filter(pk__gt=since).order_by("pk"))


def last_id():
    row = AuditLog.objects.order_by("-pk").first()
    return row.pk if row else 0


def text(rows):
    return " ".join(repr(row.__dict__) for row in rows)


try:
    with transaction.atomic():
        from accounts import views as tactical_views
        from tec_tac.tactical_account_guard import _already_guarded

        admin = User(username=f"{MARK}-admin", is_superuser=True, email=f"{MARK}@probe.invalid")
        admin.set_password(uuid.uuid4().hex)
        admin.save()
        factory = APIRequestFactory()

        def guard_installed():
            check(_already_guarded(tactical_views.GetAddAPIKeys.post), "create")
            check(_already_guarded(tactical_views.GetUpdateDeleteAPIKey.put), "edit")
            check(_already_guarded(tactical_views.GetUpdateDeleteAPIKey.delete), "delete")

        def create_edit_delete():
            since = last_id()
            request = factory.post("/accounts/apikeys/", {"name": KEY_NAME, "user": admin.pk}, format="json")
            force_authenticate(request, user=admin)
            check(tactical_views.GetAddAPIKeys.as_view()(request).status_code == 200, "create answered 200")
            key = APIKey.objects.get(name=KEY_NAME)
            rows = new_rows(since)
            check(rows, "a create wrote audit rows")
            check(KEY_NAME in text(rows) and str(admin.username) in text(rows), "a create row names the key and its owner")
            check(key.key not in text(rows), "the key value is in no create row")

            since = last_id()
            request = factory.put(f"/accounts/apikeys/{key.pk}/", {"name": KEY_NAME[:-1] + "z"}, format="json")
            force_authenticate(request, user=admin)
            check(tactical_views.GetUpdateDeleteAPIKey.as_view()(request, pk=key.pk).status_code == 200, "edit answered 200")
            rows = new_rows(since)
            check(rows, "an edit wrote audit rows")
            check(key.key not in text(rows), "the key value is in no edit row")

            since = last_id()
            request = factory.delete(f"/accounts/apikeys/{key.pk}/")
            force_authenticate(request, user=admin)
            check(tactical_views.GetUpdateDeleteAPIKey.as_view()(request, pk=key.pk).status_code == 200, "delete answered 200")
            rows = new_rows(since)
            check(rows, "a delete wrote audit rows")
            check(key.key not in text(rows), "the key value is in no delete row")
            check(not APIKey.objects.filter(pk=key.pk).exists(), "the key is gone")

        step("the guard is installed on the three write handlers", guard_installed)
        step("create, edit and delete each write rows and never the key value", create_edit_delete)
        raise Rollback()
except Rollback:
    pass

print("RESULT:", "PASS" if all(RESULTS) else "FAIL", f"({sum(RESULTS)}/{len(RESULTS)})")
sys.exit(0 if all(RESULTS) else 1)
