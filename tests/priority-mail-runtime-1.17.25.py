"""Runtime check for Core 1.17.25: Core's Priority 1 email through Tactical's own sender. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/priority-mail-runtime-1.17.25.py

It exercises the real Tactical CoreSettings (the email_is_configured property, the real smtp_host field), the real TecTacUserNotice
marker rows that make the hourly cap, and the real audit write. Tactical's send_mail is replaced for the whole run by a stub that
records what it is asked and never connects to a mail server, so nothing is sent. Everything is written inside one transaction that is
ROLLED BACK at the end. Prints PASS or FAIL for each step and exits with status 1 when any step fails.

Checks: email_is_configured answers a plain yes or no (Core never reads the password); the marker count reads the real rows of the last
hour; a sweep over a probe failed job sends through the stub only to administrators, one message each, with test=True, and writes one
count-only audit row; the stub is the only sender that was called; an address that is refused never reaches the stub.
"""
import sys
import uuid
from datetime import datetime, timedelta, timezone

from accounts.models import User
from django.db import transaction
from logs.models import AuditLog
from tacticalrmm.utils import get_core_settings
from tec_tac import module_failure_notices as mfn
from tec_tac import priority_mail
from tec_tac.models import TecTacUserNotice

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
JOB_ID = str(uuid.uuid4())
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


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def stub_send_mail(self, subject, body, attachment=None, attachment_filename=None, attachment_type=None, attachment_extension=None,
                   alert_template=None, override_recipients=(), test=False):
    """Replaces Tactical's send_mail for this run. It records the call and never connects to a server."""
    SENT.append({"override_recipients": list(override_recipients), "test": test})
    return "stub", True


def make_admin(suffix, superuser=True):
    user = User(username=f"{MARK}-{suffix}", is_superuser=superuser, email=f"{MARK}-{suffix}@probe.invalid")
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


try:
    with transaction.atomic():
        core = get_core_settings()
        real_send = type(core).send_mail
        type(core).send_mail = stub_send_mail
        try:
            admin_one = make_admin("one")
            admin_two = make_admin("two")
            make_admin("plain", superuser=False)

            def configured_flag_is_a_plain_answer():
                answer = priority_mail.is_configured()
                check(isinstance(answer, bool), f"a yes or no, got {type(answer).__name__}")

            def marker_rows_are_counted():
                now = datetime.now(timezone.utc)
                before = mfn._default_recent(now - timedelta(hours=1))
                for n in range(3):
                    row = TecTacUserNotice.objects.create(user=admin_one, client_id=f"{mfn.EMAIL_CLIENT_ID_PREFIX}{MARK}-{n}",
                                                          source="core", level="info", title="probe", message="probe")
                    TecTacUserNotice.objects.filter(pk=row.pk).update(created_at=now - timedelta(minutes=5))
                check(mfn._default_recent(now - timedelta(hours=1)) == before + 3, "three marker rows in the last hour")
                TecTacUserNotice.objects.filter(client_id__startswith=f"{mfn.EMAIL_CLIENT_ID_PREFIX}{MARK}").update(
                    created_at=now - timedelta(hours=2))
                check(mfn._default_recent(now - timedelta(hours=1)) == before, "rows older than an hour do not count")

            def a_sweep_sends_only_to_administrators_and_audits_counts():
                SENT.clear()
                job = {"id": JOB_ID, "status": "failed", "action": "enable", "plugin_id": f"probe-{MARK}",
                       "finished_at": datetime.now(timezone.utc).isoformat(), "error": "probe", "requested_by": f"{MARK}-plain"}
                mfn.sweep_failed_jobs(jobs=[job])
                sent_to = [item["override_recipients"][0] for item in SENT if item["override_recipients"]]
                check(all(len(item["override_recipients"]) == 1 and item["test"] is True for item in SENT), SENT)
                check(f"{MARK}-plain@probe.invalid" not in sent_to, "a non-administrator requester gets no email")
                check(not any(address.endswith("@probe.invalid") and address not in (
                    f"{MARK}-one@probe.invalid", f"{MARK}-two@probe.invalid") for address in sent_to), sent_to)
                row = AuditLog.objects.filter(object_type="module_job_email", object_id=JOB_ID, action="custom:priority-mail").order_by("-pk").first()
                check(row is not None, "one count-only audit row for the job")
                check(set((row.metadata or {}).keys()) >= {"recipients", "sent", "refused", "outcome", "code", "requested_by"}, row.metadata)
                check(all(isinstance(value, (int, str)) for value in row.metadata.values()), "counts and codes only")
                check(MARK not in repr(row.metadata) and "probe.invalid" not in repr(row.metadata), "no address in the audit row")

            def an_address_with_a_comma_never_reaches_the_stub():
                check(priority_mail.clean_address(f"{MARK},x@probe.invalid") is None, "a comma is refused")

            for name, fn in (
                ("email_is_configured answers a plain yes or no", configured_flag_is_a_plain_answer),
                ("the marker rows are counted for the last hour", marker_rows_are_counted),
                ("a sweep sends to administrators only, and writes one count-only audit row", a_sweep_sends_only_to_administrators_and_audits_counts),
                ("a comma in an address is refused", an_address_with_a_comma_never_reaches_the_stub),
            ):
                step(name, fn)
        finally:
            type(core).send_mail = real_send
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed (the transaction was rolled back; nothing was sent)")
if not all(RESULTS):
    sys.exit(1)
