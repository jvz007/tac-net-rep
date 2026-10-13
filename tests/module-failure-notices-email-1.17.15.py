#!/usr/bin/env python3
"""1.17.15 regression, updated for 1.17.25: the Priority 1 email for a failed module job (Johan CQ41, 10 October 2026; AD-28 amendment).

Django-free part. Runs the real ``module_failure_notices.py``, ``priority_mail.py`` and ``module_replacement.py`` with Django, the
Linux-only modules and Tactical's ``tacticalrmm`` stubbed. The 1.17.15 SMTP sender and its settings dict are gone: the email goes
through Tactical's own sender (tests/priority-mail-1.17.25.py pins that path, the refusals and the cap). This file keeps what the
1.17.15 email promised and still holds: the subject names the module and the server, the body carries the notice text and no path,
one try per recipient and job (a second sweep never sends again, even after a failed send), a recipient with no address is skipped,
a failing send never raises, the sweep sends after the toast, the email is off when Tactical's email is not configured, and the
module reads no Tactical model. The database part is a dev-server script.
"""
from __future__ import annotations

import logging
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import module_failure_notices as mfn  # noqa: E402
from tec_tac import priority_mail  # noqa: E402

# The mail server's name points at a public address (the public-address check passes). No network is used.
priority_mail.resolve_addresses = lambda name: ["93.184.216.34"]

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
JOB_ID = "00000000-0000-4000-8000-000000000001"
SERVER = "shtf-dev.example.test"
HOST = "smtp.example.test"


def stamp(minutes=0):
    return (NOW - timedelta(minutes=minutes)).isoformat()


def job(n=1, **extra):
    base = {"id": f"00000000-0000-4000-8000-{n:012d}", "status": "failed", "action": "enable", "plugin_id": "patching",
            "finished_at": stamp(minutes=n), "error": "the lifecycle step failed", "requested_by": "alice"}
    base.update(extra)
    return base


ROOT_USER = SimpleNamespace(pk=1, email="root@example.test")
ALICE = SimpleNamespace(pk=2, email="alice@example.test")
NO_ADDRESS = SimpleNamespace(pk=3, email="")


class FakeSender:
    """Records each (address, subject, body) it is asked to send. ``fail`` makes every send answer False, as a refused relay would."""

    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def __call__(self, address, subject, body):
        if self.fail:
            return False
        self.sent.append((address, subject, body))
        return True


class Markers:
    """Stands in for the TecTacUserNotice rows that mark an email as tried: (client id, user pk)."""

    def __init__(self):
        self.rows = set()

    def have(self, client_ids):
        return {pair for pair in self.rows if pair[0] in client_ids}

    def mark(self, user, client_id):
        self.rows.add((client_id, user.pk))


# ------------------------------------------------------------------------------------------ labels and keys
must(mfn.notice_for_job(job(1))["module"] == "patching", "a plugin id is the module label")
must(mfn.notice_for_job(job(2, action="batch_install", plugin_id="batch"))["module"] == "batch install", "batch label")
must(mfn.notice_for_job(job(3, action="bundle_install", plugin_id="pack"))["module"] == "bundle pack", "bundle label")
must(mfn.notice_for_job(job(4, plugin_id="x/../y"))["module"] == "[path]", "a path-like id is not echoed")
notice = mfn.notice_for_job(job(1))
must(mfn.email_client_id_for(notice) == f"module-job-failed-email:{JOB_ID}", mfn.email_client_id_for(notice))
must(len(mfn.email_client_id_for(notice)) <= 64, "the email client id fits the 64 character column")
must(mfn.email_client_id_for({"client_id": "something-else:1"}) is None, "only a job notice has an email id")
must(mfn.email_client_id_for({"client_id": "module-job-failed:../etc"}) is None, "a bad job id has no email id")

# ------------------------------------------------------------------------------------------ off when Tactical's email is not configured
sender, markers = FakeSender(), Markers()
tried = mfn.send_p1_email(notice, [ROOT_USER, ALICE], configured=lambda: False, host=lambda: HOST, send=sender, have=markers.have,
                          mark=markers.mark, server=SERVER, now=NOW)
must(tried == 0 and sender.sent == [] and markers.rows == set(), "not configured: nothing is sent and nothing is marked")

# ------------------------------------------------------------------------------------------ the content
sender, markers = FakeSender(), Markers()
sent = mfn.send_p1_email(notice, [ROOT_USER, ALICE, NO_ADDRESS], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0,
                         send=sender, have=markers.have, mark=markers.mark, server=SERVER, now=NOW)
must(sent == 2 and len(sender.sent) == 2, (sent, len(sender.sent)))
must({address for address, _, _ in sender.sent} == {"root@example.test", "alice@example.test"}, "the audience, no address skipped")
for _address, subject, body in sender.sent:
    must("patching" in subject and SERVER in subject and subject.isascii(), subject)
    must("\r" not in subject and "\n" not in subject, repr(subject))
    must("could not be enabled" in body and "Error: the lifecycle step failed" in body, body)
    must(f"Server: {SERVER}" in body and "Module: patching" in body, body)
    must("techxflow.co.za" in body and "\n\n\n" not in body, body)
    must("/var/lib" not in body and "C:\\" not in body, body)
must(sorted(pair[0] for pair in markers.rows) == [f"module-job-failed-email:{JOB_ID}"] * 2, markers.rows)
must((f"module-job-failed-email:{JOB_ID}", NO_ADDRESS.pk) not in markers.rows, "a person with no address is not marked")

# ------------------------------------------------------------------------------------------ one try per job and person
sender2 = FakeSender()
tried2 = mfn.send_p1_email(notice, [ROOT_USER, ALICE], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0, send=sender2,
                           have=markers.have, mark=markers.mark, server=SERVER, now=NOW)
must(tried2 == 0 and sender2.sent == [], "a second tick never sends the same email again")

# a failed send is tried once, is marked, and nothing raises
failing, marks = FakeSender(fail=True), Markers()
tried3 = mfn.send_p1_email(notice, [ROOT_USER], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0, send=failing,
                           have=marks.have, mark=marks.mark, server=SERVER, now=NOW)
must(tried3 == 0 and failing.sent == [] and len(marks.rows) == 1, "a failed send is tried once and never raises")
retry = FakeSender()
must(mfn.send_p1_email(notice, [ROOT_USER], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0, send=retry,
                       have=marks.have, mark=marks.mark, server=SERVER, now=NOW) == 0, "a failed send is not retried every minute")

# a sender that raises is a failed send, never an error
def boom(address, subject, body):
    raise OSError("sender is down")


raising, marks2 = boom, Markers()
must(mfn.send_p1_email(notice, [ROOT_USER], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0, send=raising,
                       have=marks2.have, mark=marks2.mark, server=SERVER, now=NOW) == 0, "a raising sender never raises out")

# a second job is a second email
other = mfn.notice_for_job(job(9, plugin_id="other"))
fresh = FakeSender()
must(mfn.send_p1_email(other, [ROOT_USER], configured=lambda: True, host=lambda: HOST, recent=lambda since: 0, send=fresh,
                       have=markers.have, mark=markers.mark, server=SERVER, now=NOW) == 1, "a different job gets its own email")
must(mfn.send_p1_email({"client_id": "bad"}, [ROOT_USER], configured=lambda: True, host=lambda: HOST, send=FakeSender(), server=SERVER,
                       now=NOW) == 0, "a notice without a job id sends nothing")

# ------------------------------------------------------------------------------------------ the server name
name = mfn._server_name()
must(isinstance(name, str) and name and name.isascii() and len(name) <= mfn.EMAIL_SERVER_MAX, name)

# ------------------------------------------------------------------------------------------ the sweep sends after the toast
PEOPLE = {"root": ROOT_USER, "alice": ALICE, "bob": NO_ADDRESS}
TOASTS: set = set()


def recipients_for(requested_by):
    """The toast audience: the administrators plus the requester. ``""`` (the email audience) gives the administrators only."""
    people = [ROOT_USER]
    if requested_by in PEOPLE and PEOPLE[requested_by] not in people:
        people.append(PEOPLE[requested_by])
    return people


def publish(recipients, notice_row):
    created = 0
    for user in recipients:
        if (notice_row["client_id"], user.pk) not in TOASTS:
            TOASTS.add((notice_row["client_id"], user.pk))
            created += 1
    return created


def toast_existing(ids):
    return {pair for pair in TOASTS if pair[0] in ids}


sweep_markers, sweep_sender = Markers(), FakeSender()
stored = mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                               configured=lambda: True, host=lambda: HOST, send=sweep_sender, recent=lambda since: 0,
                               audit=lambda job_id, metadata: None, email_have=sweep_markers.have, mark_sent=sweep_markers.mark)
must(stored == 2, stored)
must(len(sweep_sender.sent) == 1 and sweep_sender.sent[0][0] == "root@example.test",
     "the email goes to the administrators only: the requester gets the toast, not the email")
again = FakeSender()
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                           configured=lambda: True, host=lambda: HOST, send=again, recent=lambda since: 0,
                           audit=lambda job_id, metadata: None, email_have=sweep_markers.have, mark_sent=sweep_markers.mark) == 0
      and again.sent == [], "the next tick stores and sends nothing")
off = FakeSender()
mfn.sweep_failed_jobs(now=NOW, jobs=[job(5)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                      configured=lambda: False, host=lambda: HOST, send=off, recent=lambda since: 0, audit=lambda job_id, metadata: None,
                      email_have=sweep_markers.have, mark_sent=sweep_markers.mark)
must(off.sent == [], "not configured, no email; the toast still goes out on its own")
must(any(pair[0] == f"module-job-failed:{job(5)['id']}" for pair in TOASTS), "the toast was stored")
broken = mfn.sweep_failed_jobs(now=NOW, jobs=[job(6)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                               configured=lambda: 1 / 0, host=lambda: HOST, send=off, recent=lambda since: 0,
                               audit=lambda job_id, metadata: None, email_have=sweep_markers.have, mark_sent=sweep_markers.mark)
must(broken >= 0 and off.sent == [], "a configured-flag failure never stops the sweep and sends nothing")

# the module reads no Tactical model, and no Core SMTP client: the layer rule and AD-28 condition 3
source = (ROOT / "framwork" / "tec_tac" / "module_failure_notices.py").read_text(encoding="utf-8")
must("CoreSettings.objects" not in source and "core.models" not in source and "import CoreSettings" not in source,
     "Core must not read Tactical's CoreSettings")
must("smtplib" not in source and "_smtp_send" not in source and "_mail_settings" not in source, "no Core SMTP client")

print("[TEST] PASS module failure notices email 1.17.15 (updated 1.17.25)")
