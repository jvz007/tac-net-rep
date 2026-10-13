#!/usr/bin/env python3
"""1.17.25 regression: Core's own Priority 1 email through Tactical's own sender (AD-28 amendment, Johan chose (c), 13 October 2026).

Django-free. Runs the real ``priority_mail.py`` and ``module_failure_notices.py`` with Tactical's ``CoreSettings`` replaced by a strict
fake: it answers only ``smtp_host``, ``email_is_configured`` and ``send_mail``, and any other attribute (the SMTP password included)
is an AssertionError. The public-address check resolves names through a fake resolver, so nothing touches the network. Covered: the
email is off and writes nothing when Tactical's email is not configured, and a later configuration sends the recent failures; every
refusal of the mail server's name (empty, unresolvable, loopback, link-local, metadata, private, carrier-grade, IPv4-mapped, NAT64,
6to4, multicast, unspecified, one bad address among good ones) gives one count-only row and marks the recipients, while a public name
passes; the resolver runs only when there is something to send; an address with a comma, space, newline, quote, two at-signs, an empty
value or 255 characters never reaches the sender; duplicates collapse; at most 20 recipients per job; the hourly cap (20, read once per
sweep and spent across jobs) sends nothing over the cap, leaves the recipients unmarked, logs a count, and a later hour sends; a
non-administrator requester gets no email; one send per recipient with exactly one address and test=True; the first failed send stops
the job and marks the rest; Tactical's returned text (a host name and the password) never appears in an audit row, a log, a return
value, a notice or a marker; the audit row's shape; the source reads no CoreSettings field but the three allowed, and no SMTP client
or password name exists anywhere in Core's tec_tac package; a second sweep never sends again; the entry points never raise.
The dev-server part (the real email_is_configured flag, the marker-row count and the audit row) is tests/priority-mail-runtime-1.17.25.py.
"""
from __future__ import annotations

import logging
import re
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
sys.path.insert(0, str(ROOT / "framwork"))


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

SECRET = "SMTP-PASSWORD-SENTINEL-7d3f"
TACTICAL_TEXT = "connection to mail.example.test failed for tec-admin with " + SECRET


class StrictCoreSettings:
    """Tactical's CoreSettings as Core may touch it. Only smtp_host, email_is_configured and send_mail; anything else fails the test."""

    def __init__(self):
        self.smtp_host = "mail.example.test"
        self.email_is_configured = True
        self._secret = SECRET  # the SMTP password: Core must never reach it
        self.sent: list = []
        self.reply = ("ok", True)
        self.error = None

    def __getattr__(self, name):
        raise AssertionError(f"Core read a Tactical mail field it may not read: {name}")

    def send_mail(self, subject, body, attachment=None, attachment_filename=None, attachment_type=None, attachment_extension=None,
                  alert_template=None, override_recipients=(), test=False):
        if self.error is not None:
            raise self.error
        self.sent.append({"subject": subject, "body": body, "override_recipients": list(override_recipients), "test": test})
        return self.reply


CORE = StrictCoreSettings()
_stub("tacticalrmm")
sys.modules["tacticalrmm.utils"] = types.ModuleType("tacticalrmm.utils")
sys.modules["tacticalrmm.utils"].get_core_settings = lambda: CORE

AUDIT_CALLS: list = []
_audit_stub = types.ModuleType("tec_tac.audit")
_audit_stub.service_audit_actor = lambda *, module_id, service, identity=None: SimpleNamespace(kind="service", module_id=module_id, service=service)
_audit_stub.record = lambda **kw: AUDIT_CALLS.append(kw)
sys.modules["tec_tac.audit"] = _audit_stub

from tec_tac import module_failure_notices as mfn  # noqa: E402
from tec_tac import priority_mail  # noqa: E402

RESOLVE: dict = {}
RESOLVE_CALLS: list = []


def fake_resolve(name):
    RESOLVE_CALLS.append(name)
    if name not in RESOLVE:
        raise OSError("name does not resolve")
    return list(RESOLVE[name])


priority_mail.resolve_addresses = fake_resolve
RESOLVE["mail.example.test"] = ["93.184.216.34"]  # a public address: the default case

LOGS: list = []


class Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(f"{record.levelname} " + record.getMessage() + " " + (repr(record.exc_info[1]) if record.exc_info else ""))


logging.getLogger().addHandler(Capture(level=logging.DEBUG))
logging.getLogger().setLevel(logging.DEBUG)

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
CLOCK = {"now": NOW}


def job(n, requested_by="alice", **extra):
    base = {"id": f"00000000-0000-4000-8000-{n:012d}", "status": "failed", "action": "enable", "plugin_id": "patching",
            "finished_at": (NOW - timedelta(minutes=n)).isoformat(), "error": "the lifecycle step failed", "requested_by": requested_by}
    base.update(extra)
    return base


def user(pk, email, superuser=True):
    return SimpleNamespace(pk=pk, email=email, is_superuser=superuser)


ROOT_USER = user(1, "root@example.test")
BOSS = user(2, "boss@example.test")
ALICE = user(3, "alice@example.test", superuser=False)
PEOPLE = {"alice": ALICE}
ADMINS = [ROOT_USER, BOSS]


class Store:
    """The TecTacUserNotice rows the sweep reads and writes: toasts, and marker rows with the time they were written."""

    def __init__(self):
        self.markers: list = []  # (client_id, user pk, created_at)
        self.toasts: set = set()
        self.toast_rows: list = []

    def have(self, client_ids):
        return {(c, pk) for c, pk, _ in self.markers if c in client_ids}

    def mark(self, user_row, client_id):
        self.markers.append((client_id, getattr(user_row, "pk", user_row), CLOCK["now"]))

    def recent(self, since):
        return sum(1 for c, _, at in self.markers if c.startswith(mfn.EMAIL_CLIENT_ID_PREFIX) and at >= since)

    def toast_existing(self, ids):
        return {pair for pair in self.toasts if pair[0] in ids}

    def publish(self, recipients, notice_row):
        created = 0
        for person in recipients:
            if (notice_row["client_id"], person.pk) not in self.toasts:
                self.toasts.add((notice_row["client_id"], person.pk))
                self.toast_rows.append(dict(notice_row))
                created += 1
        return created


STORE = Store()


def recipients_for(requested_by):
    """The toast audience: the administrators plus a requester who is in PEOPLE. ``""`` (the email audience) is the administrators."""
    people = list(ADMINS)
    if requested_by in PEOPLE and PEOPLE[requested_by] not in people:
        people.append(PEOPLE[requested_by])
    return people


def sweep(jobs, **overrides):
    seams = dict(now=CLOCK["now"], jobs=jobs, recipients_for=recipients_for, publish=STORE.publish, existing=STORE.toast_existing,
                 recent=STORE.recent, audit=lambda job_id, md: AUDIT_ROWS.append((job_id, dict(md))), email_have=STORE.have,
                 mark_sent=STORE.mark)
    seams.update(overrides)
    return mfn.sweep_failed_jobs(**seams)


AUDIT_ROWS: list = []
ADMIN_ADDRESSES = {"root@example.test", "boss@example.test"}


def fresh(admins=None):
    global ADMINS
    CORE.smtp_host, CORE.email_is_configured, CORE.sent, CORE.reply, CORE.error = "mail.example.test", True, [], ("ok", True), None
    CORE.__dict__["_secret"] = SECRET
    STORE.markers.clear()
    STORE.toasts.clear()
    STORE.toast_rows.clear()
    AUDIT_ROWS.clear()
    AUDIT_CALLS.clear()
    LOGS.clear()
    RESOLVE_CALLS.clear()
    CLOCK["now"] = NOW
    ADMINS = list(admins) if admins is not None else [ROOT_USER, BOSS]


def sent_to():
    return [item["override_recipients"][0] for item in CORE.sent]


# ------------------------------------------------------------------------------------------------ the address rule
for good in ("root@example.test", "a.b+c@sub.example.test", "X@x.test"):
    must(priority_mail.clean_address(good) == good, good)
for bad in ("a,b@x.test", "a;b@x.test", "a<b@x.test", "a>b@x.test", 'a"b@x.test', "a'b@x.test", "a b@x.test", "a\nb@x.test",
            "a\rb@x.test", "a\tb@x.test", "a@@x.test", "@x.test", "a@", "a", "", None, "q" * 250 + "@x.test", "üml@x.test",
            "a\x00b@x.test"):
    must(priority_mail.clean_address(bad) is None, repr(bad))
must(priority_mail.clean_address("x" * 64 + "@" + "y" * 200 + ".test") is None, "longer than 254 characters")

# ------------------------------------------------------------------------------------------------ the host rule (pure)
REFUSED_ADDRESSES = ["127.0.0.1", "::1", "169.254.10.10", "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
                     "10.0.0.5", "192.168.1.20", "172.16.0.9", "100.64.0.9", "::ffff:10.0.0.5", "64:ff9b::a00:5", "2002:a00:5::1",
                     "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1", "fc00::5", "192.0.2.1", "240.0.0.1"]
for address in REFUSED_ADDRESSES:
    must(priority_mail.refused_reason(address) is not None, address)
for address in ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:93.184.216.34", "64:ff9b::5db8:d822"):
    must(priority_mail.refused_reason(address) is None, address)
must(priority_mail.public_refusal("") == priority_mail.REFUSED and "" not in RESOLVE_CALLS, "an empty name is refused before any lookup")
must(priority_mail.public_refusal(None) == priority_mail.REFUSED, "no name is refused")
RESOLVE["nope.example"] = []
must(priority_mail.public_refusal("nope.example") == priority_mail.REFUSED, "a name with no addresses is refused")
RESOLVE["mixed.example"] = ["93.184.216.34", "10.1.1.1"]
must(priority_mail.public_refusal("mixed.example") == priority_mail.REFUSED, "one private address among public ones refuses the name")
RESOLVE["scoped.example"] = ["fe80::1%eth0"]
must(priority_mail.public_refusal("scoped.example") == priority_mail.REFUSED, "a scoped link-local address is refused")

# ------------------------------------------------------------------------------------------------ not configured: nothing sent, no row, no marker; later sends
fresh()
CORE.email_is_configured = False
sweep([job(1)])
must(CORE.sent == [] and AUDIT_ROWS == [] and STORE.markers == [], "not configured: no send, no row, no marker")
must(len(STORE.toasts) == 3, "the in-app notice still goes out to the administrators and the requester")
must(not any(line.startswith("WARNING") for line in LOGS), "not configured is a DEBUG line only")
CORE.email_is_configured = True
sweep([job(1)])
must(sent_to() == ["root@example.test", "boss@example.test"] and len(AUDIT_ROWS) == 1, (sent_to(), AUDIT_ROWS))

# ------------------------------------------------------------------------------------------------ the public path: one send per administrator
fresh()
sweep([job(2)])
must(sent_to() == ["root@example.test", "boss@example.test"], sent_to())
for item in CORE.sent:
    must(len(item["override_recipients"]) == 1 and item["test"] is True, item)
    must(item["subject"].isascii() and "\n" not in item["subject"] and "\r" not in item["subject"], item["subject"])
    must("patching" in item["subject"] and "could not be enabled" in item["body"] and "techxflow.co.za" in item["body"], item)
must(AUDIT_ROWS == [(job(2)["id"], {"recipients": 2, "sent": 2, "refused": 0, "outcome": "sent", "code": "none", "requested_by": "scheduler", "private_relay": False})],
     AUDIT_ROWS)
sweep([job(2)])
must(len(CORE.sent) == 2 and len(AUDIT_ROWS) == 1, "a second sweep never sends again and writes no second row")
must(STORE.markers and all(c == f"module-job-failed-email:{job(2)['id']}" for c, _, _ in STORE.markers), STORE.markers)

# ------------------------------------------------------------------------------------------------ the requester is emailed only when an administrator
fresh()
sweep([job(3, requested_by="alice")])
must("alice@example.test" not in sent_to() and set(sent_to()) <= ADMIN_ADDRESSES, sent_to())
must(any(row["client_id"] == f"module-job-failed:{job(3)['id']}" and row["message"] for row in STORE.toast_rows), "alice still gets the toast")
must(any(pk == ALICE.pk for _, pk in STORE.toasts), "the toast went to alice")
ALICE_ADMIN = user(4, "alice@example.test")
fresh(admins=[ROOT_USER, BOSS, ALICE_ADMIN])
sweep([job(4, requested_by="alice")])
must("alice@example.test" in sent_to(), "a requester who is an administrator gets the email")

# ------------------------------------------------------------------------------------------------ every refused mail server name: one count-only row, marked, no send
REFUSED_HOSTS = {
    "lo.example": ["127.0.0.1"], "v6lo.example": ["::1"], "linklocal.example": ["169.254.10.10"], "meta.example": ["169.254.169.254"],
    "ecs.example": ["fd00:ec2::254"], "alicloud.example": ["100.100.100.200"], "aws2.example": ["169.254.170.2"],
    "ten.example": ["10.0.0.5"], "lan.example": ["192.168.1.20"], "cgnat.example": ["100.64.0.9"], "mapped.example": ["::ffff:10.0.0.5"],
    "nat64.example": ["64:ff9b::a00:5"], "sixtofour.example": ["2002:a00:5::1"], "multi.example": ["93.184.216.34", "10.1.1.1"],
    "unspec.example": ["0.0.0.0"], "mcast.example": ["224.0.0.1"], "linklocal6.example": ["fe80::1%eth0"],
}
for host_name, addresses in REFUSED_HOSTS.items():
    fresh()
    RESOLVE[host_name] = addresses
    CORE.smtp_host = host_name
    sweep([job(5)])
    must(CORE.sent == [], (host_name, "nothing is sent"))
    must(AUDIT_ROWS == [(job(5)["id"], {"recipients": 2, "sent": 0, "refused": 2, "outcome": "refused", "code": "mail_host_refused",
                                        "requested_by": "scheduler", "private_relay": False})], (host_name, AUDIT_ROWS))
    must(len(STORE.markers) == 2, (host_name, "both recipients marked as tried"))
    resolves = len(RESOLVE_CALLS)
    sweep([job(5)])
    must(CORE.sent == [] and len(AUDIT_ROWS) == 1 and len(RESOLVE_CALLS) == resolves, (host_name, "a later tick does not look again"))
# an empty name and an unresolvable name: refused, count-only, marked
for host_name in ("", "nope.invalid"):
    fresh()
    CORE.smtp_host = host_name
    sweep([job(6)])
    must(CORE.sent == [] and AUDIT_ROWS and AUDIT_ROWS[0][1]["code"] == "mail_host_refused" and len(STORE.markers) == 2, (host_name, AUDIT_ROWS))
must("" not in RESOLVE_CALLS, "an empty name is never looked up")
# a public name passes (the host check ran once for the job)
for host_name in ("mail.example.test", "v6.example"):
    fresh()
    RESOLVE[host_name] = ["93.184.216.34"] if host_name == "mail.example.test" else ["2606:2800:220:1:248:1893:25c8:1946"]
    CORE.smtp_host = host_name
    sweep([job(7)])
    must(len(CORE.sent) == 2 and RESOLVE_CALLS.count(host_name) == 1, (host_name, CORE.sent, RESOLVE_CALLS))
# the resolver is not called when nothing is to be sent (every recipient already marked)
fresh()
sweep([job(8)])
resolved_once = RESOLVE_CALLS.count("mail.example.test")
sweep([job(8)])
must(RESOLVE_CALLS.count("mail.example.test") == resolved_once, "no lookup without something to send")

# ------------------------------------------------------------------------------------------------ addresses that are refused never reach the sender
fresh([user(10, "a,b@x.test"), user(11, "a b@x.test"), user(12, "a\nb@x.test"), user(13, "a@@x.test"), user(14, ""),
       user(15, "q" * 250 + "@x.test"), user(16, "a'b@x.test"), user(17, "a<b@x.test"), user(18, "root@example.test")])
sweep([job(9)])
must(sent_to() == ["root@example.test"], sent_to())
must(all(c != f"module-job-failed-email:{job(9)['id']}" or pk == 18 for c, pk, _ in STORE.markers), "bad addresses are not marked")
must(all(item["override_recipients"] == ["root@example.test"] for item in CORE.sent), "no comma-joined recipient list")

# duplicate addresses collapse (case-insensitive): one send
fresh([user(20, "Admin@X.test"), user(21, "admin@x.test"), user(22, "ADMIN@x.TEST")])
sweep([job(10)])
must(len(CORE.sent) == 1 and CORE.sent[0]["override_recipients"] == ["Admin@X.test"], CORE.sent)

# at most 20 recipients per job: the first 20 are tried, the rest are not considered
fresh([user(100 + i, f"adm{i}@x.test") for i in range(25)])
sweep([job(11)])
must(len(CORE.sent) == 20 and sent_to() == [f"adm{i}@x.test" for i in range(20)], len(CORE.sent))
must(all(pk < 120 for _, pk, _ in STORE.markers), "the 21st to 25th administrators are not marked")

# ------------------------------------------------------------------------------------------------ the hourly cap
fresh()
for i in range(20):  # twenty email markers written 10 minutes ago: the hour is full
    STORE.markers.append((f"module-job-failed-email:00000000-0000-4000-8000-{900 + i:012d}", 900 + i, NOW - timedelta(minutes=10)))
sweep([job(12)])
must(CORE.sent == [] and AUDIT_ROWS == [], "over the cap: nothing sent, no row")
must(not any(c == f"module-job-failed-email:{job(12)['id']}" for c, _, _ in STORE.markers), "over the cap: nothing marked")
must(any(line.startswith("WARNING") and "cap reached" in line for line in LOGS), "the cap is logged at WARNING")
must(len(STORE.toasts) == 3, "the in-app notice still goes out over the cap")
CLOCK["now"] = NOW + timedelta(minutes=61)  # the old markers leave the rolling hour
sweep([job(12)])
must(sent_to() == ["root@example.test", "boss@example.test"], "a later hour sends the held failure, inside the seven-day window")

# the budget is read once per sweep and spent across jobs
fresh()
for i in range(19):
    STORE.markers.append((f"module-job-failed-email:00000000-0000-4000-8000-{800 + i:012d}", 800 + i, NOW - timedelta(minutes=5)))
sweep([job(13), job(14)])
must(sent_to() == ["root@example.test"], ("one spare email this hour, spent once", sent_to()))
must(len([m for m in STORE.markers if m[0] == f"module-job-failed-email:{job(14)['id']}"]) == 0, "the second job was held")

# ------------------------------------------------------------------------------------------------ one send_mail call per recipient, and a failure stops the job
fresh()
CORE.reply = ("refused by the relay for tec-admin", False)
sweep([job(15)])
must(len(CORE.sent) == 1, CORE.sent)
must(AUDIT_ROWS == [(job(15)["id"], {"recipients": 2, "sent": 0, "refused": 2, "outcome": "failed", "code": "send_failed",
                                     "requested_by": "scheduler", "private_relay": False})], AUDIT_ROWS)
must(len(STORE.markers) == 2, "the rest of the job is marked as tried, so a broken server is not retried every minute")
CORE.reply = ("ok", True)
sweep([job(15)])
must(len(CORE.sent) == 1, "a broken server is not retried on the next tick")

# a send that raises is a failed send and never escapes
fresh()
CORE.error = RuntimeError("relay said " + TACTICAL_TEXT)
sweep([job(16)])
must(AUDIT_ROWS and AUDIT_ROWS[0][1]["code"] == "send_failed", AUDIT_ROWS)
CORE.error = None

# ------------------------------------------------------------------------------------------------ Tactical's text and the password never leave the send path
fresh()
CORE.reply = (TACTICAL_TEXT, False)
result = sweep([job(17)])
mfn_return = mfn.send_p1_email(mfn.notice_for_job(job(18)), ADMINS, state={"budget": 20, "deferred": 0}, host=lambda: "mail.example.test",
                               send=lambda a, s, b: False, have=lambda ids: set(), mark=lambda u, c: None,
                               audit=lambda j, m: AUDIT_ROWS.append((j, m)), server="shtf-dev.example.test", now=NOW)
must(isinstance(result, int) and isinstance(mfn_return, int), "the sweep returns a count")
surfaces = repr(AUDIT_ROWS) + repr(AUDIT_CALLS) + repr(STORE.markers) + repr(STORE.toast_rows) + repr(LOGS) + repr(result) + repr(mfn_return)
must(SECRET not in surfaces and "mail.example.test" not in surfaces and "tec-admin" not in surfaces, "Tactical's text never leaves the send path")
for line in LOGS:
    must(SECRET not in line and "mail.example.test" not in line, line)
# the real sender: a Tactical failure text is discarded; only the boolean comes back
must(priority_mail.send_one("root@example.test", "s", "b") is False, "a reported failure is False")
CORE.reply = ("ok", True)
must(priority_mail.send_one("root@example.test", "s", "b") is True, "a reported success is True")
CORE.error = RuntimeError(TACTICAL_TEXT)
must(priority_mail.send_one("root@example.test", "s", "b") is False and SECRET not in repr(LOGS), "an exception is a False, with the class name only")
CORE.error = None

# ------------------------------------------------------------------------------------------------ the audit row: service provenance, counts and a code only
fresh()
mfn._default_audit(job(19)["id"], {"recipients": 1, "sent": 1, "refused": 0, "outcome": "sent", "code": "none", "requested_by": "scheduler", "private_relay": False})
row = AUDIT_CALLS[-1]
must(row["module_id"] == "core" and row["action"] == "custom:priority-mail" and row["object_type"] == "module_job_email", row)
must(row["object_id"] == job(19)["id"] and row["strict"] is False and row["actor"].kind == "service" and row["actor"].module_id == "core", row)
must(set(row["metadata"]) == {"recipients", "sent", "refused", "outcome", "code", "requested_by", "private_relay"}, row["metadata"])
must(row["metadata"]["code"] in {"mail_host_refused", "send_failed", "none"}, row["metadata"])
must(all(isinstance(value, (int, str, bool)) for value in row["metadata"].values()), "counts and codes only")

# ------------------------------------------------------------------------------------------------ the entry points never raise
fresh()
must(mfn.send_p1_email(job(20), None, configured=lambda: True) == 0, "garbage recipients do not raise")
must(mfn.send_p1_email(None, ADMINS, configured=lambda: True) == 0, "a garbage notice does not raise")
boom = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))  # noqa: E731
must(mfn.send_p1_email(mfn.notice_for_job(job(21)), ADMINS, configured=lambda: True, recent=boom, have=lambda ids: set()) == 0,
     "a broken count does not raise")
must(sweep([job(22)], configured=boom) >= 0, "a broken configured flag does not stop the sweep")
must(sweep([job(23)], recent=boom) >= 0 and len(STORE.toasts) >= 2, "a broken count keeps the in-app notice")
must(sweep([job(24)], audit=boom) >= 0, "a broken audit writer does not raise")
fresh()
must(sweep([job(25)], mark_sent=boom) >= 0, "a broken marker does not raise")

# ------------------------------------------------------------------------------------------------ source: Core reads only the three Tactical fields, and no SMTP client exists in Core
mail_source = (APP / "priority_mail.py").read_text(encoding="utf-8")
read_fields = set(re.findall(r"get_core_settings\(\)\.(\w+)", mail_source))
must(read_fields == {"email_is_configured", "smtp_host", "send_mail"}, read_fields)
for path in APP.rglob("*.py"):
    text = path.read_text(encoding="utf-8", errors="replace")
    for forbidden in ("smtplib", "smtp_host_password", "smtp_from_email", "smtp_host_user", "SMTP_SSL"):
        must(forbidden not in text, (str(path.relative_to(ROOT)), forbidden))
notice_source = (APP / "module_failure_notices.py").read_text(encoding="utf-8")
must("_mail_settings" not in notice_source and "_smtp_send" not in notice_source and "EmailMessage" not in notice_source, "the old sender is gone")

# ------------------------------------------------------------------------------------------------ the docs say what the email does
caller = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("its own SMTP path" not in caller and "Tactical's own sender" in caller, "docs/caller-identity.md")
replacement = (ROOT / "docs" / "module-replacement.md").read_text(encoding="utf-8")
for needle in ("Tactical's own sender", "20 emails", "public-address", "administrators"):
    must(needle in replacement, ("docs/module-replacement.md", needle))

print("[TEST] PASS priority mail 1.17.25")
