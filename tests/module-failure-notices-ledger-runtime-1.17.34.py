"""Runtime check for Core 1.17.34: old "Module job failed" notices do not come back after "Clear read". It did NOT run on the development PC
(Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, the real database and the real Core code are loaded (after
migration 0030_notice_ledger has run):

    cp /opt/tec-tac-src/tests/module-failure-notices-ledger-runtime-1.17.34.py /tmp/ && chmod 644 /tmp/module-failure-notices-ledger-runtime-1.17.34.py
    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/module-failure-notices-ledger-runtime-1.17.34.py'

It proves what the stub test (tests/module-failure-notices-1.17.34.py) cannot: that the real TecTacNoticeLedger table, the real
``notices.clear_read`` and the real ``sweep_failed_jobs`` behave together. A throwaway superuser and requester get a notice for a failed job;
every read notice is then cleared with ``notices.clear_read`` (the UI's "Clear read"); a second sweep stores nothing and the ledger is
intact. The same for the Priority 1 email, with a fake sender (nothing is ever mailed and the real administrators are never recipients).
A job finished 7 hours or 3 days ago owes nothing. ``notices._prune_user`` leaves the ledger alone, ``notices.ledger_prune`` removes only
rows older than 7 days, and deleting the throwaway user removes its ledger rows.

Everything happens inside one database transaction that is rolled back at the end, so no user, notice, ledger row or job is left behind. The
jobs live in a temporary folder. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import json
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from accounts.models import User
from django.db import transaction
from tec_tac import module_failure_notices as mfn, module_manager_v2 as v2, notices
from tec_tac.models import TecTacNoticeLedger, TecTacUserNotice

RESULTS = []
TMP = Path(tempfile.mkdtemp(prefix="tectac-runtime-ledger-"))
SAVED_JOBS_ROOT = v2.JOBS_ROOT
v2.JOBS_ROOT = TMP
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
NOW = datetime.now(timezone.utc)
SENT = []


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


def job_file(job_id, finished_ago, **fields):
    body = {"id": job_id, "status": "failed", "action": "enable", "plugin_id": "tectac-probe", "requested_by": f"{MARK}-requester",
            "finished_at": (NOW - finished_ago).isoformat(), "error": "the lifecycle step failed", **fields}
    (TMP / f"{job_id}.json").write_text(json.dumps(body), encoding="utf-8")


def run():
    sup = make_user("super", is_superuser=True, email="probe-super@example.invalid")
    requester = make_user("requester")

    def recipients_for(requested_by):
        # only the throwaway people: a real administrator never gets a probe notice or a probe email
        return [sup] + ([requester] if requested_by == requester.username else [])

    def sweep(*, email=False, **extra):
        seams = dict(now=NOW, recipients_for=recipients_for, configured=lambda: bool(email), host=lambda: "93.184.216.34",
                     send=lambda address, subject, body: SENT.append(address) or True)
        seams.update(extra)
        return mfn.sweep_failed_jobs(**seams)

    def clear_everything_read():
        for user in (sup, requester):
            notices.mark_all_read(user)
            notices.clear_read(user)

    def ledger(kind, job_id):
        return TecTacNoticeLedger.objects.filter(kind=kind, key=job_id)

    job_a = str(uuid.uuid4())
    key_a = f"module-job-failed:{job_a}"
    job_file(job_a, timedelta(minutes=2))

    def notice_is_raised_and_ledgered():
        assert sweep() == 2, "the superuser and the requester each get one notice"
        assert TecTacUserNotice.objects.filter(client_id=key_a).count() == 2
        assert ledger("notice", job_a).count() == 2, "both are in the ledger"

    def clear_read_does_not_bring_it_back():
        clear_everything_read()
        assert not TecTacUserNotice.objects.filter(client_id=key_a).exists(), "Clear read removed the notice rows"
        assert ledger("notice", job_a).count() == 2, "Clear read left the ledger alone"
        report = {}
        assert sweep(report=report) == 0, "the next sweep stores nothing"
        assert not TecTacUserNotice.objects.filter(client_id=key_a).exists(), "no row came back"
        assert report["skipped_notified"] == 1, report
        for _ in range(3):
            sweep()
        assert not TecTacUserNotice.objects.filter(client_id=key_a).exists() and ledger("notice", job_a).count() == 2

    def pruning_the_notice_rows_leaves_the_ledger():
        job_b = str(uuid.uuid4())
        job_file(job_b, timedelta(minutes=3))
        sweep()
        before = TecTacNoticeLedger.objects.filter(user=sup).count()
        notices._prune_user(sup.pk)
        assert TecTacNoticeLedger.objects.filter(user=sup).count() == before, "_prune_user does not touch the ledger"

    def old_jobs_owe_nothing():
        seven_hours, three_days = str(uuid.uuid4()), str(uuid.uuid4())
        job_file(seven_hours, timedelta(hours=7))
        job_file(three_days, timedelta(days=3))
        report = {}
        assert sweep(email=True, report=report) == 0, "an old job stores nothing"
        for job_id in (seven_hours, three_days):
            assert not TecTacUserNotice.objects.filter(client_id=f"module-job-failed:{job_id}").exists(), "no notice row"
            assert not TecTacNoticeLedger.objects.filter(key=job_id).exists(), "no ledger row"
        assert report["skipped_old"] >= 2 and report["emailed"] == 0, report

    def email_is_sent_once_and_survives_clear_read():
        job_c = str(uuid.uuid4())
        job_file(job_c, timedelta(minutes=1), requested_by="system")
        del SENT[:]
        assert sweep(email=True) == 1, "the superuser gets the notice"
        assert SENT == ["probe-super@example.invalid"], f"one email, to the throwaway superuser only: {SENT}"
        assert ledger("email", job_c).count() == 1, "the email is in the ledger"
        assert not TecTacUserNotice.objects.filter(client_id__startswith=mfn.EMAIL_CLIENT_ID_PREFIX, user=sup).exists(), "no marker row is written any more"
        clear_everything_read()
        del SENT[:]
        sweep(email=True)
        sweep(email=True)
        assert SENT == [], f"no second email after Clear read: {SENT}"

    def ledger_counts_for_the_cap():
        from django.utils import timezone as dj_timezone

        count = notices.ledger_count_since("email", dj_timezone.now() - timedelta(hours=1))
        assert count >= 1, count
        assert mfn._default_recent(dj_timezone.now() - timedelta(hours=1)) == count, "the sweep's cap count reads the ledger"

    def ledger_prune_keeps_recent_rows():
        from django.utils import timezone as dj_timezone

        old = TecTacNoticeLedger.objects.create(user=sup, kind="notice", key="probe-old")
        new = TecTacNoticeLedger.objects.create(user=sup, kind="notice", key="probe-new")
        TecTacNoticeLedger.objects.filter(pk=old.pk).update(created_at=dj_timezone.now() - timedelta(days=8))
        notices.ledger_prune()
        assert not TecTacNoticeLedger.objects.filter(pk=old.pk).exists(), "an 8 day old row is pruned"
        assert TecTacNoticeLedger.objects.filter(pk=new.pk).exists(), "a fresh row stays"
        assert ledger("notice", job_a).count() == 2, "the rows inside 7 days stay"

    def the_unique_key_holds():
        before = TecTacNoticeLedger.objects.count()
        assert notices.ledger_add("notice", "probe-dup", [sup]) == 1
        assert notices.ledger_add("notice", "probe-dup", [sup, requester]) == 1, "only the new person is added"
        assert TecTacNoticeLedger.objects.count() == before + 2

    def deleting_a_user_removes_the_ledger_rows():
        pk = requester.pk
        requester.delete()
        assert not TecTacNoticeLedger.objects.filter(user_id=pk).exists(), "the ledger rows go with the user (on delete cascade)"

    for name, fn in (
        ("a failed job is raised and ledgered for each recipient", notice_is_raised_and_ledgered),
        ("Clear read does not bring the notice back, and the ledger stays", clear_read_does_not_bring_it_back),
        ("pruning the notice rows leaves the ledger alone", pruning_the_notice_rows_leaves_the_ledger),
        ("jobs finished 7 hours and 3 days ago owe no notice and no email", old_jobs_owe_nothing),
        ("the Priority 1 email is sent once and survives Clear read", email_is_sent_once_and_survives_clear_read),
        ("the email cap counts ledger rows", ledger_counts_for_the_cap),
        ("the ledger prune removes only rows older than 7 days", ledger_prune_keeps_recent_rows),
        ("the unique key holds", the_unique_key_holds),
        ("deleting a user removes its ledger rows", deleting_a_user_removes_the_ledger_rows),
    ):
        step(name, fn)


try:
    with transaction.atomic():
        run()
        raise Rollback()
except Rollback:
    pass
finally:
    v2.JOBS_ROOT = SAVED_JOBS_ROOT
    for path in TMP.glob("*.json"):
        path.unlink()
    TMP.rmdir()

left = TecTacNoticeLedger.objects.filter(key__startswith="probe-").count() + User.objects.filter(username__startswith=MARK).count()
print(f"PASS rolled back: {left} probe rows left" if left == 0 else f"FAIL rolled back: {left} probe rows left")
RESULTS.append(left == 0)
if not all(RESULTS):
    print(f"{RESULTS.count(False)} step(s) FAILED")
    sys.exit(1)
print("module-failure-notices-ledger-runtime-1.17.34: ok")
