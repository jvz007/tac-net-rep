#!/usr/bin/env python3
"""1.17.15 regression: the Priority 1 email for a failed module job (Johan CQ41, 10 October 2026). Django-free part.

Runs the real ``module_failure_notices.py`` and ``module_replacement.py`` with Django and the Linux-only modules stubbed. It
covers: the email is skipped when the sender or the host is missing (and when there is no settings contract, which is the
production state today), the subject names the module and the server, the body carries the notice text, one try per
recipient and job (a second sweep never sends again, even after a failed send), that a recipient with no address is skipped,
the SMTP sender follows Tactical's way (implicit TLS on 465, STARTTLS with a login) against a fake server, a failing send
never raises, and the sweep sends after the toast notice. The database part is a dev-server script.
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

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
JOB_ID = "00000000-0000-4000-8000-000000000001"
SERVER = "shtf-dev.example.test"
SETTINGS = {
    "smtp_host": "smtp.example.test", "smtp_port": 587, "smtp_from_email": "tec-tac@example.test",
    "smtp_requires_auth": False, "smtp_host_user": "", "smtp_host_password": "",
}


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
    """Records each message it is asked to send. ``fail`` makes every send raise, as a dead SMTP host would."""

    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def __call__(self, settings, message):
        if self.fail:
            raise OSError("smtp host unreachable")
        self.sent.append((dict(settings), message))


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

# ------------------------------------------------------------------------------------------ the production state
must(mfn._mail_settings() is None, "no outbound email contract yet: the default settings are None")
sender = FakeSender()
must(mfn.send_p1_email(notice, [ROOT_USER], settings=None, server=SERVER, send=sender) == 0 and sender.sent == [],
     "with no contract the email is off, and it reads nothing from Tactical")

# ------------------------------------------------------------------------------------------ skipped when not configured
for label, cfg in (("empty sender", {**SETTINGS, "smtp_from_email": ""}), ("blank sender", {**SETTINGS, "smtp_from_email": "  "}),
                   ("no host", {**SETTINGS, "smtp_host": ""}), ("empty mapping", {})):
    sender, markers = FakeSender(), Markers()
    tried = mfn.send_p1_email(notice, [ROOT_USER, ALICE], settings=cfg, server=SERVER, have=markers.have, send=sender,
                              mark=markers.mark)
    must(tried == 0 and sender.sent == [] and markers.rows == set(), (label, tried, sender.sent))

# ------------------------------------------------------------------------------------------ the content
sender, markers = FakeSender(), Markers()
tried = mfn.send_p1_email(notice, [ROOT_USER, ALICE, NO_ADDRESS], settings=SETTINGS, server=SERVER, have=markers.have,
                          send=sender, mark=markers.mark)
must(tried == 2 and len(sender.sent) == 2, (tried, len(sender.sent)))
must({msg["To"] for _, msg in sender.sent} == {"root@example.test", "alice@example.test"}, "the audience, no address skipped")
for _, msg in sender.sent:
    subject = msg["Subject"]
    must("patching" in subject and SERVER in subject and subject.isascii(), subject)
    must(msg["From"] == "tec-tac@example.test", msg["From"])
    body = msg.get_body(preferencelist=("plain",)).get_content()
    must("could not be enabled" in body and "Error: the lifecycle step failed" in body, body)
    must(f"Server: {SERVER}" in body and "Module: patching" in body, body)
    must("techxflow.co.za" in body and "\n\n\n" not in body, body)
    must("/var/lib" not in body and "C:\\" not in body, body)
must(sorted(pair[0] for pair in markers.rows) == [f"module-job-failed-email:{JOB_ID}"] * 2, markers.rows)

# ------------------------------------------------------------------------------------------ one try per job and person
sender2 = FakeSender()
tried2 = mfn.send_p1_email(notice, [ROOT_USER, ALICE], settings=SETTINGS, server=SERVER, have=markers.have, send=sender2,
                           mark=markers.mark)
must(tried2 == 0 and sender2.sent == [], "a second tick never sends the same email again")

# a failed send is logged, the try is still marked, and nothing raises
failing, marks = FakeSender(fail=True), Markers()
tried3 = mfn.send_p1_email(notice, [ROOT_USER], settings=SETTINGS, server=SERVER, have=marks.have, send=failing, mark=marks.mark)
must(tried3 == 1 and failing.sent == [] and len(marks.rows) == 1, "a failed send is tried once and never raises")
retry = FakeSender()
must(mfn.send_p1_email(notice, [ROOT_USER], settings=SETTINGS, server=SERVER, have=marks.have, send=retry, mark=marks.mark) == 0,
     "a failed send is not retried every minute")

# a second job is a second email
other = mfn.notice_for_job(job(9, plugin_id="other"))
fresh = FakeSender()
must(mfn.send_p1_email(other, [ROOT_USER], settings=SETTINGS, server=SERVER, have=markers.have, send=fresh, mark=markers.mark) == 1,
     "a different job gets its own email")
must(mfn.send_p1_email({"client_id": "bad"}, [ROOT_USER], settings=SETTINGS, server=SERVER, send=FakeSender()) == 0,
     "a notice without a job id sends nothing")

# ------------------------------------------------------------------------------------------ the default SMTP sender
class FakeSMTP:
    """A stand-in for smtplib.SMTP and SMTP_SSL: records the conversation instead of talking to a server."""
    instances = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, message):
        self.calls.append(("send", message["To"]))


import smtplib  # noqa: E402

real_smtp, real_ssl = smtplib.SMTP, smtplib.SMTP_SSL
smtplib.SMTP = FakeSMTP
smtplib.SMTP_SSL = type("FakeSSL", (FakeSMTP,), {})
try:
    message = mfn._p1_message(notice, SERVER, SETTINGS, "alice@example.test")
    FakeSMTP.instances.clear()
    mfn._smtp_send({**SETTINGS, "smtp_requires_auth": True, "smtp_host_user": "tec", "smtp_host_password": "pw"}, message)
    plain = FakeSMTP.instances[-1]
    must(plain.host == "smtp.example.test" and plain.port == 587 and plain.timeout == mfn.SMTP_TIMEOUT_SECONDS, vars(plain))
    must(plain.calls == ["ehlo", "starttls", ("login", "tec", "pw"), ("send", "alice@example.test"), "quit"], plain.calls)
    FakeSMTP.instances.clear()
    mfn._smtp_send({**SETTINGS, "smtp_port": 465, "smtp_requires_auth": True, "smtp_host_user": "tec"}, message)
    implicit = FakeSMTP.instances[-1]
    must(type(implicit).__name__ == "FakeSSL" and implicit.context is not None, "port 465 uses implicit TLS")
    must("starttls" not in implicit.calls and ("login", "tec", "") in implicit.calls, implicit.calls)
    FakeSMTP.instances.clear()
    mfn._smtp_send({**SETTINGS, "smtp_requires_auth": False}, message)
    open_relay = FakeSMTP.instances[-1]
    must(open_relay.calls == [("send", "alice@example.test"), "quit"], open_relay.calls)
finally:
    smtplib.SMTP, smtplib.SMTP_SSL = real_smtp, real_ssl

# ------------------------------------------------------------------------------------------ the server name
name = mfn._server_name()
must(isinstance(name, str) and name and name.isascii() and len(name) <= mfn.EMAIL_SERVER_MAX, name)

# ------------------------------------------------------------------------------------------ the sweep sends after the toast
PEOPLE = {"root": ROOT_USER, "alice": ALICE, "bob": NO_ADDRESS}
TOASTS: set = set()


def recipients_for(requested_by):
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
                               mail_settings=lambda: SETTINGS, email_have=sweep_markers.have, send_mail=sweep_sender,
                               mark_sent=sweep_markers.mark)
must(stored == 2 and len(sweep_sender.sent) == 2, (stored, len(sweep_sender.sent)))
must({msg["To"] for _, msg in sweep_sender.sent} == {"root@example.test", "alice@example.test"}, "the toast audience gets the email")
again = FakeSender()
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                           mail_settings=lambda: SETTINGS, email_have=sweep_markers.have, send_mail=again,
                           mark_sent=sweep_markers.mark) == 0 and again.sent == [], "the next tick stores and sends nothing")
off = FakeSender()
mfn.sweep_failed_jobs(now=NOW, jobs=[job(5)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                      mail_settings=lambda: None, email_have=sweep_markers.have, send_mail=off, mark_sent=sweep_markers.mark)
must(off.sent == [], "no settings, no email; the toast still goes out on its own")
broken = mfn.sweep_failed_jobs(now=NOW, jobs=[job(6)], recipients_for=recipients_for, publish=publish, existing=toast_existing,
                               mail_settings=lambda: 1 / 0, email_have=sweep_markers.have, send_mail=off, mark_sent=sweep_markers.mark)
must(broken >= 0 and off.sent == [], "a settings failure never stops the sweep and sends nothing")

# the email module reads no Tactical model: that is the layer rule (Core reads accounts and sign-in only)
source = (ROOT / "framwork" / "tec_tac" / "module_failure_notices.py").read_text(encoding="utf-8")
must("CoreSettings.objects" not in source and "core.models" not in source and "import CoreSettings" not in source,
     "Core must not read Tactical's CoreSettings")

print("[TEST] PASS module failure notices email 1.17.15")
