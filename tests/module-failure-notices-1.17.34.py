#!/usr/bin/env python3
"""1.17.34 regression: old "Module job failed" notices must not come back (Johan, 14 October 2026). Django-free part.

Runs the real ``module_failure_notices.py`` with Django and the Linux-only modules stubbed, and a fake world behind the seams: the
person's notice rows (which "Clear read" deletes), the old email marker rows (which it deleted too), the new notice ledger (which neither
Clear read nor the 30 day pruning touches), a mail sender and a clock.

Covered: (1) a notice and its Priority 1 email are raised once; the person presses Clear read (notice rows and old marker rows gone);
the next sweeps store nothing and send nothing, even inside the window; (2) a failed job finished 7 hours or 3 days ago gives no notice,
no toast row and no email, and is counted as skipped_old; (3) a job inside the window is raised once per recipient; (4) a recipient who
appears later still gets a job inside the window and not one outside it; (5) the hourly email cap counts ledger rows, not marker rows;
(6) notice rows or old marker rows without ledger rows still count as raised (nothing to migrate), and the sweep backfills the ledger;
(7) a ledger read or write failure never raises and never double-sends an email: a failed email read or mark sends nothing; (8) the
ledger is pruned past fourteen days and the window is seven days (1.17.38); (9) the report counts what the sweep left alone; (10) source checks: the
default mark writes the ledger and no notice row, Clear read and the 30 day pruning do not touch the ledger, migration 0030 is additive,
and the scheduler tick reports the counts. The database part is tests/module-failure-notices-ledger-runtime-1.17.34.py (dev server).
"""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
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

from tec_tac import module_failure_notices as mfn  # noqa: E402
from tec_tac import priority_mail  # noqa: E402

mfn.logger.disabled = True
priority_mail.resolve_addresses = lambda name: ["93.184.216.34"]

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
CLOCK = {"now": NOW}


def stamp(hours=0, minutes=0, days=0):
    return (CLOCK["now"] - timedelta(days=days, hours=hours, minutes=minutes)).isoformat()


def job(n, **extra):
    base = {"id": f"00000000-0000-4000-8000-{n:012d}", "status": "failed", "action": "enable", "plugin_id": "patching",
            "finished_at": stamp(minutes=n), "error": "the lifecycle step failed", "requested_by": "alice"}
    base.update(extra)
    return base


def cid(n):
    return mfn.client_id_for(job(n)["id"])


def key(n):
    return job(n)["id"]


PEOPLE = {
    "root": types.SimpleNamespace(pk=1, email="root@example.test"),
    "boss": types.SimpleNamespace(pk=2, email="boss@example.test"),
    "alice": types.SimpleNamespace(pk=3, email="alice@example.test"),
    "carol": types.SimpleNamespace(pk=4, email="carol@example.test"),
}


class World:
    """The tables behind the seams."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.notice_rows: set = set()      # (client_id, pk): TecTacUserNotice rows that Clear read can delete
        self.markers: set = set()          # (email client id, pk): the old read marker rows (1.17.33 and earlier)
        self.marker_times: dict = {}
        self.ledger: dict = {}             # (kind, key, pk) -> created_at
        self.sent: list = []               # (address, subject)
        self.audience = ["root", "boss"]   # the administrators
        self.fail = set()                  # names of seams that raise
        self.prune_calls = 0

    # the people
    def recipients_for(self, requested_by):
        names = list(self.audience)
        if requested_by in PEOPLE and requested_by not in names:
            names.append(requested_by)
        if requested_by == "":
            return [PEOPLE[n] for n in self.audience]
        return [PEOPLE[n] for n in names]

    # the notice rows
    def publish(self, recipients, notice):
        created = 0
        for user in recipients:
            if (notice["client_id"], user.pk) not in self.notice_rows:
                self.notice_rows.add((notice["client_id"], user.pk))
                created += 1
        return created

    def existing(self, ids):
        return {pair for pair in self.notice_rows if pair[0] in ids}

    def clear_read(self):
        """The UI's "Clear read": every read row of the person goes, and so do the read email marker rows. The ledger stays."""
        self.notice_rows.clear()
        self.markers.clear()
        self.marker_times.clear()

    # the ledger
    def ledger_have(self, kind, keys):
        if "ledger_have" in self.fail:
            raise RuntimeError("ledger read failed")
        return {(k, pk) for (kd, k, pk) in self.ledger if kd == kind and k in keys}

    def ledger_add(self, kind, key_, users, *, created_at=None):  # created_at: the 1.17.35 keyword (unused by this release's fake)
        if "ledger_add" in self.fail:
            raise RuntimeError("ledger write failed")
        for user in users:
            self.ledger.setdefault((kind, key_, user.pk), CLOCK["now"])
        return len(users)

    def ledger_prune(self):
        self.prune_calls += 1
        cutoff = CLOCK["now"] - timedelta(days=14)
        for item in [k for k, at in self.ledger.items() if at < cutoff]:
            del self.ledger[item]
        return 0

    # the email
    def email_have(self, client_ids):
        if "email_have" in self.fail:
            raise RuntimeError("email read failed")
        pairs = {pair for pair in self.markers if pair[0] in client_ids}
        for kd, k, pk in self.ledger:
            if kd == "email" and f"{mfn.EMAIL_CLIENT_ID_PREFIX}{k}" in client_ids:
                pairs.add((f"{mfn.EMAIL_CLIENT_ID_PREFIX}{k}", pk))
        return pairs

    def mark_sent(self, user, client_id):
        if "mark_sent" in self.fail:
            raise RuntimeError("ledger write failed")
        self.ledger.setdefault(("email", mfn._job_id_of(client_id), user.pk), CLOCK["now"])

    def recent(self, since):
        return sum(1 for (kd, _, _), at in self.ledger.items() if kd == "email" and at >= since)

    def send(self, address, subject, body):
        self.sent.append((address, subject))
        return True


W = World()


def sweep(jobs, report=None, **overrides):
    seams = dict(now=CLOCK["now"], jobs=jobs, recipients_for=W.recipients_for, publish=W.publish, existing=W.existing,
                 configured=lambda: True, host=lambda: "smtp.example.com", send=W.send, recent=W.recent, audit=lambda j, m: None,
                 email_have=W.email_have, mark_sent=W.mark_sent, ledger_have=W.ledger_have, ledger_add=W.ledger_add,
                 ledger_prune=W.ledger_prune, report=report if report is not None else {})
    seams.update(overrides)
    return mfn.sweep_failed_jobs(**seams)


def fresh():
    W.reset()
    CLOCK["now"] = NOW


# ------------------------------------------------------------------------------------------------ 1. Clear read does not bring it back
fresh()
report = {}
must(sweep([job(1)], report) == 3, "first sweep: the two administrators and the requester get the notice")
must(len(W.notice_rows) == 3 and len(W.sent) == 2, f"two emails to the two administrators, got {len(W.sent)}")
must(report["stored"] == 3 and report["emailed"] == 2, report)
must({("notice", key(1), 1), ("notice", key(1), 2), ("notice", key(1), 3), ("email", key(1), 1), ("email", key(1), 2)} == set(W.ledger),
     f"the ledger holds the notices and the emails: {sorted(W.ledger)}")
W.clear_read()  # the toasted notice is marked read at once, so Clear read deletes it, and the email marker rows with it
must(not W.notice_rows and not W.markers, "Clear read removed the notice rows")
sent_before = len(W.sent)
report = {}
must(sweep([job(1)], report) == 0, "the next sweep stores nothing")
must(not W.notice_rows and len(W.sent) == sent_before, "no row came back and no email was sent again, inside the window")
must(report["skipped_notified"] == 1 and report["emailed"] == 0 and report["stored"] == 0, report)
for _ in range(5):
    sweep([job(1)])
must(not W.notice_rows and len(W.sent) == sent_before, "five more ticks change nothing")
# the 30 day or 500 row pruning of the notice rows is the same: only the ledger decides
fresh()
sweep([job(1)])
W.notice_rows.clear()
W.markers.clear()
sweep([job(1)])
must(not W.notice_rows and len(W.sent) == 2, "deleted rows (any cause) are not raised again")

# ------------------------------------------------------------------------------------------------ 2. old jobs give nothing
fresh()
report = {}
old = [job(2, finished_at=stamp(days=7, hours=1)), job(3, finished_at=stamp(days=8)), job(4, finished_at=stamp(days=30))]
must(sweep(old, report) == 0, "jobs older than the window store nothing")
must(not W.notice_rows and not W.sent and not W.ledger, "no notice row, no email, no ledger row for an old job")
must(report["skipped_old"] == 3, report)
fresh()
report = {}
sweep([job(5, finished_at="garbage"), job(6, finished_at=None), job(7, status="succeeded", finished_at=stamp(days=3))], report)
must(not W.notice_rows and not W.sent, "a job with no readable finished_at owes nothing")
must(report["skipped_old"] == 2, "the two unreadable ones are counted, the successful one is not a failure")
# the edges of the window
fresh()
must(mfn.NOTICE_WINDOW_HOURS == 168 and mfn.NOTICE_WINDOW == timedelta(days=7), "the window is seven days (1.17.38)")
must(sweep([job(8, finished_at=stamp(days=6, hours=23, minutes=59))]) == 3, "6 days 23 hours 59 minutes is inside")
fresh()
must(sweep([job(9, finished_at=stamp(days=7, hours=1))]) == 0 and not W.sent, "7 days 1 hour is outside")
must(not hasattr(mfn, "WINDOW_DAYS"), "the seven day constant is gone")

# ------------------------------------------------------------------------------------------------ 3. once per recipient
fresh()
sweep([job(10)])
sweep([job(10)])
must(sorted(pk for (c, pk) in W.notice_rows if c == cid(10)) == [1, 2, 3], "one notice per recipient")
must(sorted(a for a, _ in W.sent) == ["boss@example.test", "root@example.test"], "one email per administrator, never the requester who is not one")

# ------------------------------------------------------------------------------------------------ 4. a recipient who appears later
fresh()
F11, F12 = stamp(hours=1), stamp(days=8)  # fixed times: one hour and eight days before NOW
sweep([job(11, finished_at=F11), job(12, finished_at=F12)])
must({pk for (c, pk) in W.notice_rows if c == cid(11)} == {1, 2, 3} and not any(c == cid(12) for (c, _) in W.notice_rows), "the old job is not raised")
W.audience = ["root", "boss", "carol"]  # carol becomes an administrator
CLOCK["now"] = NOW + timedelta(minutes=30)
W.sent.clear()
sweep([job(11, finished_at=F11), job(12, finished_at=F12)])
must((cid(11), 4) in W.notice_rows, "the new person gets the job that is inside the window")
must(not any(c == cid(12) for (c, _) in W.notice_rows), "and not the job outside it")
must([a for a, _ in W.sent] == ["carol@example.test"], f"only the new administrator is emailed: {W.sent}")
# later still the job leaves the window: nobody new gets it
CLOCK["now"] = NOW + timedelta(days=7)
W.audience = ["root", "boss", "carol", "alice"]
W.sent.clear()
before = set(W.notice_rows)
sweep([job(11, finished_at=F11)])
must(W.notice_rows == before and not W.sent, "once outside the window a job is raised for no one")

# ------------------------------------------------------------------------------------------------ 5. the cap counts ledger rows
fresh()
for n in range(20):  # 20 ledger email rows in the last hour: the cap is used up
    W.ledger[("email", f"other-{n}", 1)] = CLOCK["now"] - timedelta(minutes=10)
must(W.recent(CLOCK["now"] - mfn.EMAIL_WINDOW) == 20, "ledger rows are counted")
sweep([job(13)])
must(not W.sent, "over the cap nothing is sent")
must(len(W.notice_rows) == 3, "the notice still goes out")
must(not any(kd == "email" and k == key(13) for (kd, k, _) in W.ledger), "nothing is marked for what was held back")
CLOCK["now"] = NOW + timedelta(hours=2)
for item in [k for k in W.ledger if k[1].startswith("other-")]:
    del W.ledger[item]  # an hour later the old rows no longer count
sweep([job(13, finished_at=stamp(hours=2, minutes=-1))])
must(len(W.sent) == 2, f"a later tick sends the held emails while the job is inside the window: {len(W.sent)}")
fresh()
for n in range(25):  # 25 old marker rows in the last hour and no ledger rows: markers no longer count
    W.markers.add((f"{mfn.EMAIL_CLIENT_ID_PREFIX}old-{n}", 1))
    W.marker_times[n] = CLOCK["now"]
sweep([job(14)])
must(len(W.sent) == 2, "marker rows do not count against the cap")

# ------------------------------------------------------------------------------------------------ 6. what was raised before 1.17.34 still counts
fresh()
W.notice_rows |= {(cid(15), 1), (cid(15), 2), (cid(15), 3)}  # raised by 1.17.33, no ledger rows
must(sweep([job(15)], configured=lambda: False) == 0, "notice rows are read: nothing is raised again")
must({("notice", key(15), 1), ("notice", key(15), 2), ("notice", key(15), 3)} <= set(W.ledger), "the sweep backfills the ledger for the notices that exist")
W.clear_read()
must(sweep([job(15)], configured=lambda: False) == 0 and not W.notice_rows, "after Clear read the backfilled ledger still holds it back")
# the old marker rows alone (notice rows gone, no ledger) still stop the email
fresh()
W.markers |= {(f"{mfn.EMAIL_CLIENT_ID_PREFIX}{key(16)}", 1), (f"{mfn.EMAIL_CLIENT_ID_PREFIX}{key(16)}", 2)}
sweep([job(16)])
must(not W.sent, "old marker rows are read as already sent")

# the real default email read copies an old marker row into the ledger, so Clear read cannot make the email look unsent
fresh()
fake_notices = types.ModuleType("tec_tac.notices")
fake_notices.ledger_have = W.ledger_have
fake_notices.ledger_add = lambda kind, key_, users, *, created_at=None: W.ledger_add(
    kind, key_, [u if hasattr(u, "pk") else types.SimpleNamespace(pk=u) for u in users])
sys.modules["tec_tac.notices"] = fake_notices
saved_existing = mfn._default_existing
saved_times = mfn._default_marker_times  # 1.17.35: the email read takes the marker rows with their times
mfn._default_existing = lambda ids: {pair for pair in W.markers if pair[0] in ids}
mfn._default_marker_times = lambda ids: {pair: None for pair in W.markers if pair[0] in ids}
try:
    W.markers |= {(f"{mfn.EMAIL_CLIENT_ID_PREFIX}{key(27)}", 1), (f"{mfn.EMAIL_CLIENT_ID_PREFIX}{key(27)}", 2)}
    W.notice_rows |= {(cid(27), 1), (cid(27), 2), (cid(27), 3)}
    sweep([job(27)], email_have=mfn._default_email_have)
    must(not W.sent and {("email", key(27), 1), ("email", key(27), 2)} <= set(W.ledger), f"old email markers are copied into the ledger: {sorted(W.ledger)}")
    W.clear_read()
    sweep([job(27)], email_have=mfn._default_email_have)
    must(not W.sent and not W.notice_rows, "after Clear read the copied ledger rows still stop the email")
finally:
    mfn._default_existing = saved_existing
    mfn._default_marker_times = saved_times
    del sys.modules["tec_tac.notices"]

# ------------------------------------------------------------------------------------------------ 7. failures never raise and never double-send
fresh()
W.fail = {"ledger_have"}
must(sweep([job(17)]) == 3, "a ledger read failure: the notice rows still work, nothing raises")
must(len(W.sent) == 2, "the email step reads through its own seam and goes on")
before = (len(W.notice_rows), len(W.sent))
sweep([job(17)])
must((len(W.notice_rows), len(W.sent)) == before, "and the next tick still adds nothing")
fresh()
W.fail = {"ledger_add"}
must(sweep([job(18)]) == 3, "a ledger write failure for notices does not stop the toast")
must(len(W.sent) == 2, "the email is marked through the mark seam, so it still goes out once")
sweep([job(18)])
must(len(W.sent) == 2, "and is not sent again")
fresh()
W.fail = {"mark_sent"}
must(sweep([job(19)]) == 3, "a failed email mark never raises")
must(not W.sent, "an email that could not be recorded is not sent (a late email beats a second one)")
for _ in range(3):
    sweep([job(19)])
must(not W.sent, "and the next ticks do not send it either while the ledger cannot be written")
W.fail = set()
sweep([job(19)])
must(len(W.sent) == 2, "once the ledger works again it is sent, once")
sweep([job(19)])
must(len(W.sent) == 2, "and not again")
fresh()
W.fail = {"email_have"}
must(sweep([job(20)]) == 3 and not W.sent, "an email read that fails sends nothing and never raises")
fresh()
W.fail = {"ledger_have", "ledger_add", "email_have", "mark_sent"}
mfn.logger.disabled = True
must(sweep([job(21)]) == 3 and not W.sent, "every ledger seam failing: the notices go out, no email, no raise")
fresh()
W.ledger_prune = lambda: (_ for _ in ()).throw(RuntimeError("prune failed"))
must(sweep([job(22)]) == 3, "a failing prune never stops the sweep")
W.ledger_prune = World.ledger_prune.__get__(W)
# send_p1_email on its own: the mark comes before the send
order = []
fresh()
users = [PEOPLE["root"]]
mfn.send_p1_email(mfn.notice_for_job(job(23)), users, configured=lambda: True, host=lambda: "smtp.example.com",
                  send=lambda a, s, b: order.append("send") or True, recent=lambda since: 0, audit=lambda j, m: None,
                  have=lambda ids: set(), mark=lambda u, c: order.append("mark"))
must(order == ["mark", "send"], f"the try is recorded before the send: {order}")

# ------------------------------------------------------------------------------------------------ 8. prune
fresh()
W.ledger[("notice", "ancient", 1)] = CLOCK["now"] - timedelta(days=15)
W.ledger[("email", "ancient", 1)] = CLOCK["now"] - timedelta(days=15)
W.ledger[("notice", "kept", 1)] = CLOCK["now"] - timedelta(days=13)
W.ledger[("notice", "recent", 1)] = CLOCK["now"] - timedelta(days=2)
sweep([])
must(W.prune_calls == 1 and ("notice", "ancient", 1) not in W.ledger and ("email", "ancient", 1) not in W.ledger and ("notice", "recent", 1) in W.ledger and ("notice", "kept", 1) in W.ledger,
     "rows older than fourteen days are pruned, newer ones kept")
must(mfn.NOTICE_WINDOW == timedelta(days=7) and 14 > mfn.NOTICE_WINDOW.days, "the ledger outlives the window (14 days against 7)")

# ------------------------------------------------------------------------------------------------ 9. the report
fresh()
report = {}
sweep([job(24), job(25, finished_at=stamp(days=8)), job(26, finished_at=stamp(days=9))], report)
must(report == {"stored": 3, "skipped_old": 2, "skipped_notified": 0, "emailed": 2}, report)
report = {}
sweep([job(24), job(25, finished_at=stamp(days=8)), job(26, finished_at=stamp(days=9))], report)
must(report == {"stored": 0, "skipped_old": 2, "skipped_notified": 1, "emailed": 0}, report)
must(mfn.sweep_failed_jobs(now=NOW, jobs=[], ledger_prune=lambda: 0) == 0, "the report is optional")

# ------------------------------------------------------------------------------------------------ 10. source checks
source = (ROOT / "framwork/tec_tac/module_failure_notices.py").read_text(encoding="utf-8")
default_mark = source[source.index("def _default_mark_sent("):source.index("def _email_text(")]
must("import TecTacUserNotice" not in default_mark and "get_or_create" not in default_mark and "ledger_add(LEDGER_EMAIL" in default_mark,
     "the default mark writes the ledger and no notice row")
default_recent = source[source.index("def _default_recent("):source.index("def _job_id_of(")]
must("ledger_count_since" in default_recent and "TecTacUserNotice" not in default_recent, "the default cap count reads the ledger")
notices_src = (ROOT / "framwork/tec_tac/notices.py").read_text(encoding="utf-8")
for name in ("def clear_read(", "def _prune_user("):
    start = notices_src.index(name)
    end = notices_src.find("\n\n\n", start)
    body = notices_src[start:end if end != -1 else len(notices_src)]
    must("Ledger" not in body and "ledger" not in body, f"{name} never touches the ledger")
for name in ("def ledger_have(", "def ledger_add(", "def ledger_count_since(", "def ledger_prune("):
    must(name in notices_src, name)
must("LEDGER_RETENTION_DAYS = 14" in notices_src, "the ledger keeps fourteen days (1.17.38)")
models_src = (ROOT / "framwork/tec_tac/models.py").read_text(encoding="utf-8")
must("class TecTacNoticeLedger(models.Model):" in models_src and 'fields=("user", "kind", "key"), name="tectac_nledger_unique"' in models_src, "the model and its unique key")
migration = (ROOT / "framwork/tec_tac/migrations/0030_notice_ledger.py").read_text(encoding="utf-8")
must('("tec_tac", "0029_priority_mail_private_relay")' in migration and "CreateModel" in migration and "TecTacNoticeLedger" in migration, "migration 0030 follows 0029")
must("RemoveField" not in migration and "AlterField" not in migration and "DeleteModel" not in migration and "RunPython" not in migration,
     "migration 0030 is additive: no data is copied")
must('name="tectac_nledger_unique"' in migration and "on_delete=django.db.models.deletion.CASCADE" in migration, "unique key and cascade in the migration")
tick = (ROOT / "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
for needle in ("module_failure_notices={failure_notices}", "module_failure_skipped_old=", "module_failure_already_notified=", "module_failure_emails=", "report=failure_report"):
    must(needle in tick, f"the tick reports {needle}")

print("[TEST] PASS module failure notices 1.17.34")
