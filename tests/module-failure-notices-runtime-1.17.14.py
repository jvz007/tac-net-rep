"""Runtime check for Core 1.17.14 module failure notices (CQ36, CQ41). It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, the real database and the real Core code are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/module-failure-notices-runtime-1.17.14.py

It proves what the stub test (tests/module-failure-notices-1.17.14.py) cannot: that ``publish_system_notice`` and
``sweep_failed_jobs`` write real ``TecTacUserNotice`` rows, one per recipient (an active superuser and the active user named in the job's
``requested_by``), that an inactive user, an installer user and a plain user who did not start the job get none, that a second sweep
adds nothing, and that a notice the person has already read stays read.

Everything happens inside one database transaction that is rolled back at the end, so no user, notice or job is left behind. The jobs live
in a temporary folder. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import json
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from accounts.models import User
from django.db import transaction
from django.utils import timezone as dj_timezone
from tec_tac import module_failure_notices as mfn, module_manager_v2 as v2, notices
from tec_tac.models import TecTacUserNotice

RESULTS = []
TMP = Path(tempfile.mkdtemp(prefix="tectac-runtime-failnotice-"))
SAVED_JOBS_ROOT = v2.JOBS_ROOT
v2.JOBS_ROOT = TMP
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
NOW = datetime.now(timezone.utc)


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


def make_user(suffix, **fields):
    user = User(username=f"{MARK}-{suffix}", **fields)
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def job_file(job_id, **fields):
    body = {"id": job_id, "status": "failed", "action": "enable", "plugin_id": "tectac-probe", "requested_by": f"{MARK}-requester",
            "finished_at": (NOW - timedelta(minutes=1)).isoformat(), "error": "the lifecycle step failed at /var/lib/tec-tac/x", **fields}
    (TMP / f"{job_id}.json").write_text(json.dumps(body), encoding="utf-8")


def run():
    sup = make_user("super", is_superuser=True)
    requester = make_user("requester")
    bystander = make_user("bystander")
    inactive_sup = make_user("inactive", is_superuser=True, is_active=False)
    installer = make_user("installer", is_superuser=True, is_installer_user=True)
    job_id = str(uuid.uuid4())
    key = f"module-job-failed:{job_id}"

    def recipients_are_the_right_people():
        found = {user.pk for user in notices.system_notice_recipients([requester.username])}
        assert sup.pk in found and requester.pk in found, found
        assert bystander.pk not in found and inactive_sup.pk not in found and installer.pk not in found, found
        assert requester.pk not in {user.pk for user in notices.system_notice_recipients([])}, "a plain user who did not start the job"
        assert len([u for u in notices.system_notice_recipients([sup.username]) if u.pk == sup.pk]) == 1, "one entry per person"

    def sweep_stores_one_notice_per_recipient():
        job_file(job_id)
        stored = mfn.sweep_failed_jobs(now=NOW)
        assert stored >= 2, stored
        rows = TecTacUserNotice.objects.filter(client_id=key)
        owners = {row.user_id for row in rows}
        assert sup.pk in owners and requester.pk in owners, owners
        assert bystander.pk not in owners and inactive_sup.pk not in owners and installer.pk not in owners, owners
        row = rows.get(user=requester)
        assert row.level == "error" and row.source == "core" and row.read_at is None, row
        assert row.action_route == "/modules" and row.title == "Module job failed", row
        assert "could not be enabled" in row.message and "/var/lib" not in row.message and row.message.isascii(), row.message

    def second_sweep_adds_nothing():
        before = TecTacUserNotice.objects.filter(client_id=key).count()
        assert mfn.sweep_failed_jobs(now=NOW) == 0
        assert TecTacUserNotice.objects.filter(client_id=key).count() == before

    def a_read_notice_stays_read():
        row = TecTacUserNotice.objects.get(client_id=key, user=requester)
        row.read_at = dj_timezone.now()
        row.save(update_fields=["read_at"])
        mfn.sweep_failed_jobs(now=NOW)
        assert TecTacUserNotice.objects.get(pk=row.pk).read_at is not None, "the sweep reset a read notice"
        created = notices.publish_system_notice([requester], client_id=key, message="again")
        assert created == 0 and TecTacUserNotice.objects.get(pk=row.pk).read_at is not None and TecTacUserNotice.objects.get(pk=row.pk).message != "again"

    def a_succeeded_job_and_an_old_job_owe_nothing():
        ok, old = str(uuid.uuid4()), str(uuid.uuid4())
        job_file(ok, status="succeeded")
        job_file(old, finished_at=(NOW - timedelta(days=9)).isoformat())
        mfn.sweep_failed_jobs(now=NOW)
        assert not TecTacUserNotice.objects.filter(client_id__in=[f"module-job-failed:{ok}", f"module-job-failed:{old}"]).exists()

    def publish_needs_a_client_id_and_a_clean_route():
        for bad in ({"client_id": ""}, {"client_id": "bad id!"}, {"client_id": "x", "action_route": "https://evil.example"}):
            try:
                notices.publish_system_notice([sup], message="m", **bad)
            except notices.NoticeError:
                continue
            raise AssertionError(f"accepted {bad}")

    step("recipients are the active superusers and the requester only", recipients_are_the_right_people)
    step("a failed job stores one notice per recipient, level error, source core, route /modules", sweep_stores_one_notice_per_recipient)
    step("a second sweep adds nothing", second_sweep_adds_nothing)
    step("a notice that was read stays read", a_read_notice_stays_read)
    step("a succeeded job and a job older than seven days owe nothing", a_succeeded_job_and_an_old_job_owe_nothing)
    step("publish_system_notice refuses a missing client_id and an external route", publish_needs_a_client_id_and_a_clean_route)


try:
    with transaction.atomic():
        run()
        raise Rollback()
except Rollback:
    pass
finally:
    v2.JOBS_ROOT = SAVED_JOBS_ROOT

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)
