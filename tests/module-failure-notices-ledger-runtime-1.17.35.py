"""Runtime check for Core 1.17.35: the ledger copy of an old email marker keeps the marker's own time. It did NOT run on the development PC
(Django is not installed there), so auto_now_add and the real .update(created_at=) cannot be proved there.

Run it on the dev server through Tactical's manage.py shell, so Django, the real database and the real Core code are loaded (after
Core 1.17.34's migration 0030_notice_ledger has run):

    cp /opt/tec-tac-src/tests/module-failure-notices-ledger-runtime-1.17.35.py /tmp/ && chmod 644 /tmp/module-failure-notices-ledger-runtime-1.17.35.py
    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/module-failure-notices-ledger-runtime-1.17.35.py'

It proves what the stub test (tests/module-failure-notices-1.17.35.py) cannot: that the real ``notices.ledger_add`` with created_at writes the
time the ORM would not otherwise keep (auto_now_add only sets now on the first save, so the time goes in with an update), that a row the
call does not create keeps its time, that ``ledger_count_since`` counts a copied row only inside the last hour, and that
``module_failure_notices._default_email_have`` copies a real TecTacUserNotice marker with that marker's created_at.

Everything runs inside one database transaction that is rolled back at the end, so no user, marker, ledger row or notice is left behind. It
prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import uuid
from datetime import datetime, timedelta, timezone

from accounts.models import User
from django.db import transaction
from tec_tac import module_failure_notices as mfn, notices
from tec_tac.models import TecTacNoticeLedger, TecTacUserNotice

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
NOW = datetime.now(timezone.utc).replace(microsecond=0)
KEY = str(uuid.uuid4())


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


def close(a, b, seconds=2):
    return abs((a - b).total_seconds()) <= seconds


def run():
    user = User(username=f"{MARK}-user", email="probe-ledger@example.invalid")
    user.set_password(uuid.uuid4().hex)
    user.save()
    old = NOW - timedelta(hours=3)

    def copies_with_the_old_time():
        created = notices.ledger_add("email", KEY, [user.pk], created_at={user.pk: old})
        assert created == 1, f"one row created, got {created}"
        row = TecTacNoticeLedger.objects.get(user_id=user.pk, kind="email", key=KEY)
        assert close(row.created_at, old), f"created_at is the marker's time ({old.isoformat()}), got {row.created_at.isoformat()}"

    def the_hourly_count_ignores_it():
        assert notices.ledger_count_since("email", NOW - timedelta(hours=1)) == 0, "a row from three hours ago is outside the last hour"
        assert notices.ledger_count_since("email", NOW - timedelta(hours=4)) >= 1, "and inside the last four hours"

    def existing_rows_keep_their_time():
        again = notices.ledger_add("email", KEY, [user.pk], created_at={user.pk: NOW})
        assert again == 0, f"no second row, got {again}"
        row = TecTacNoticeLedger.objects.get(user_id=user.pk, kind="email", key=KEY)
        assert close(row.created_at, old), "the existing row keeps its time"

    def no_time_means_now():
        other = str(uuid.uuid4())
        notices.ledger_add("email", other, [user.pk])
        row = TecTacNoticeLedger.objects.get(user_id=user.pk, kind="email", key=other)
        assert close(row.created_at, datetime.now(timezone.utc), 120), f"no created_at gives now, got {row.created_at.isoformat()}"

    def real_marker_is_copied_with_its_time():
        marker_key = str(uuid.uuid4())
        client_id = f"{mfn.EMAIL_CLIENT_ID_PREFIX}{marker_key}"
        marker = TecTacUserNotice.objects.create(user=user, client_id=client_id, message="probe marker")
        TecTacUserNotice.objects.filter(pk=marker.pk).update(created_at=NOW - timedelta(minutes=20))
        pairs = mfn._default_email_have([client_id])
        assert (client_id, user.pk) in pairs, "the marker is read as already tried"
        row = TecTacNoticeLedger.objects.get(user_id=user.pk, kind="email", key=marker_key)
        assert close(row.created_at, NOW - timedelta(minutes=20)), f"the copy keeps the marker's time, got {row.created_at.isoformat()}"
        assert notices.ledger_count_since("email", NOW - timedelta(hours=1)) >= 1, "a marker from 20 minutes ago counts toward the last hour"
        again = mfn._default_email_have([client_id])
        assert again == pairs and TecTacNoticeLedger.objects.filter(user_id=user.pk, kind="email", key=marker_key).count() == 1, \
            "a second read copies nothing"

    step("ledger_add writes the given created_at on the real table", copies_with_the_old_time)
    step("the hourly count sees a copied row only inside its own hour", the_hourly_count_ignores_it)
    step("an existing ledger row keeps its time", existing_rows_keep_their_time)
    step("ledger_add without a time still uses now", no_time_means_now)
    step("a real TecTacUserNotice marker is copied with its own time, once", real_marker_is_copied_with_its_time)

    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass

left = User.objects.filter(username__startswith=MARK).count()
print("no probe rows left" if left == 0 else f"FAIL {left} probe user(s) left behind")
RESULTS.append(left == 0)
if all(RESULTS):
    print("module-failure-notices-ledger-runtime-1.17.35: ok")
else:
    print("module-failure-notices-ledger-runtime-1.17.35: FAILED")
    raise SystemExit(1)
