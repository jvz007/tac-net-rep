#!/usr/bin/env python3
"""1.17.38 regression (Johan CQ104): the failed-job notice window is seven days, and a failure is announced once per person.

The real ``module_failure_notices.py`` runs with its Django-free imports and light stubs (the same as tests/module-failure-notices-1.17.34.py),
behind fake seams: the person's notice rows, the notice ledger, the email markers, a mail sender and a clock. Nothing else is faked.

Covered: the window is 168 hours (seven days); a job 6 days 23 hours 59 minutes old is inside and 7 days 1 hour old is outside; a failed job
with no readable finished_at is skipped and counted; a job finished 3 days ago and never announced is announced once per recipient, with one
email per administrator; eight simulated days of hourly ticks raise nothing more (one notice and one email per person in total); after
"Clear read", and after a simulated reinstall or upgrade (the same job id and the same ledger, with the notice rows gone), nothing comes back;
a person added inside the window is announced once and never again; the ledger keeps rows for two weeks (LEDGER_RETENTION_DAYS, read from
notices.py) which is more than the window plus a day, so a row for a job still inside the window survives the prune; and the source and the
docs say seven days, with no line that still says six hours for the window (history lines name 1.17.34).
"""
from __future__ import annotations

import re
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
RETENTION_SOURCE = (ROOT / "framwork/tec_tac/notices.py").read_text(encoding="utf-8")
RETENTION_DAYS = int(re.search(r"^LEDGER_RETENTION_DAYS = (\d+)", RETENTION_SOURCE, re.M).group(1))


def stamp(days=0, hours=0, minutes=0):
    return (CLOCK["now"] - timedelta(days=days, hours=hours, minutes=minutes)).isoformat()


def job(n, **extra):
    base = {"id": f"00000000-0000-4000-8000-{n:012d}", "status": "failed", "action": "enable", "plugin_id": "patching",
            "finished_at": stamp(minutes=n), "error": "the lifecycle step failed", "requested_by": "alice"}
    base.update(extra)
    return base


def cid(n):
    return mfn.client_id_for(job(n)["id"])


PEOPLE = {
    "root": types.SimpleNamespace(pk=1, email="root@example.test"),
    "boss": types.SimpleNamespace(pk=2, email="boss@example.test"),
    "alice": types.SimpleNamespace(pk=3, email="alice@example.test"),
    "carol": types.SimpleNamespace(pk=4, email="carol@example.test"),
}


class World:
    """The tables behind the seams: notice rows (Clear read deletes them), the ledger (kept), email markers and a sender."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.notice_rows: set = set()
        self.markers: set = set()
        self.ledger: dict = {}          # (kind, key, pk) -> created_at
        self.sent: list = []
        self.audience = ["root", "boss"]
        self.prune_cutoffs: list = []

    def recipients_for(self, requested_by):
        if requested_by == "":
            return [PEOPLE[n] for n in self.audience]
        names = list(self.audience)
        if requested_by in PEOPLE and requested_by not in names:
            names.append(requested_by)
        return [PEOPLE[n] for n in names]

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
        self.notice_rows.clear()
        self.markers.clear()

    def ledger_have(self, kind, keys):
        return {(k, pk) for (kd, k, pk) in self.ledger if kd == kind and k in keys}

    def ledger_add(self, kind, key_, users, *, created_at=None):
        for user in users:
            self.ledger.setdefault((kind, key_, getattr(user, "pk", user)), CLOCK["now"])
        return len(users)

    def ledger_prune(self):
        """The real prune keeps rows newer than LEDGER_RETENTION_DAYS (read from notices.py above)."""
        cutoff = CLOCK["now"] - timedelta(days=RETENTION_DAYS)
        self.prune_cutoffs.append(cutoff)
        for item in [k for k, at in self.ledger.items() if at < cutoff]:
            del self.ledger[item]
        return 0

    def email_have(self, client_ids):
        pairs = {pair for pair in self.markers if pair[0] in client_ids}
        for kd, k, pk in self.ledger:
            if kd == "email" and f"{mfn.EMAIL_CLIENT_ID_PREFIX}{k}" in client_ids:
                pairs.add((f"{mfn.EMAIL_CLIENT_ID_PREFIX}{k}", pk))
        return pairs

    def mark_sent(self, user, client_id):
        self.ledger.setdefault(("email", mfn._job_id_of(client_id), user.pk), CLOCK["now"])

    def recent(self, since):
        return sum(1 for (kd, _, _), at in self.ledger.items() if kd == "email" and at >= since)

    def send(self, address, subject, body):
        self.sent.append((address, subject))
        return True


W = World()


def sweep(jobs, report=None):
    seams = dict(now=CLOCK["now"], jobs=jobs, recipients_for=W.recipients_for, publish=W.publish, existing=W.existing,
                 configured=lambda: True, host=lambda: "smtp.example.com", send=W.send, recent=W.recent, audit=lambda j, m: None,
                 email_have=W.email_have, mark_sent=W.mark_sent, ledger_have=W.ledger_have, ledger_add=W.ledger_add,
                 ledger_prune=W.ledger_prune, report=report if report is not None else {})
    return mfn.sweep_failed_jobs(**seams)


def fresh():
    W.reset()
    CLOCK["now"] = NOW


# ------------------------------------------------------------------------------------------------ 1. the window is seven days, with its edges
fresh()
must(mfn.NOTICE_WINDOW_HOURS == 168 and mfn.NOTICE_WINDOW == timedelta(days=7), "the window is 168 hours (seven days)")
must(sweep([job(1, finished_at=stamp(days=6, hours=23, minutes=59))]) == 3, "6 days 23 hours 59 minutes is inside")
fresh()
must(sweep([job(2, finished_at=stamp(days=7, hours=1))]) == 0 and not W.sent and not W.notice_rows, "7 days 1 hour is outside")
fresh()
report = {}
must(sweep([job(3, finished_at="garbage"), job(4, finished_at=None)], report) == 0, "a job with no readable finished_at owes nothing")
must(report["skipped_old"] == 2 and not W.notice_rows and not W.sent, report)

# ------------------------------------------------------------------------------------------------ 2. announced once, then never again: eight days of hourly ticks
fresh()
F = stamp(days=3)  # the job finished three days ago and was never announced
report = {}
must(sweep([job(10, finished_at=F)], report) == 3, "the first tick raises it for the two administrators and the requester")
must(report["emailed"] == 2 and len(W.sent) == 2, f"two emails, one per administrator: {report} {W.sent}")
for hour in range(8 * 24):
    CLOCK["now"] = NOW + timedelta(hours=hour + 1)
    sweep([job(10, finished_at=F)])
must(len(W.notice_rows) == 3, f"eight days of hourly ticks leave one notice per person: {len(W.notice_rows)}")
must(len(W.sent) == 2, f"and one email per administrator in total, no daily reminder: {len(W.sent)}")
must(sorted(a for a, _ in W.sent) == ["boss@example.test", "root@example.test"], "the emails go to the two administrators")

# ------------------------------------------------------------------------------------------------ 3. Clear read, and a reinstall or upgrade, bring nothing back
CLOCK["now"] = NOW + timedelta(days=1)
W.clear_read()  # the person cleared the notice rows; the ledger keeps the record
must(not W.notice_rows, "Clear read removed the notice rows")
must(sweep([job(10, finished_at=F)]) == 0 and not W.notice_rows, "the next tick raises nothing after Clear read")
W.notice_rows.clear()  # a reinstall or upgrade: the same job id, the same ledger, no notice rows
W.sent.clear()
must(sweep([job(10, finished_at=F)]) == 0 and not W.notice_rows and not W.sent, "a fresh sweep after a simulated reinstall or upgrade raises and sends nothing")

# ------------------------------------------------------------------------------------------------ 4. a person added inside the window is announced once, and never again
fresh()
F5 = stamp(days=1)
sweep([job(20, finished_at=F5)])
W.sent.clear()
CLOCK["now"] = NOW + timedelta(days=2)
W.audience = ["root", "boss", "carol"]  # carol becomes an administrator; the job is 3 days old, inside the window
sweep([job(20, finished_at=F5)])
must((cid(20), 4) in W.notice_rows, "the new administrator is announced the job inside the window")
must([a for a, _ in W.sent] == ["carol@example.test"], f"and emailed once, and only her: {W.sent}")
for hour in range(3 * 24):
    CLOCK["now"] = NOW + timedelta(days=2, hours=hour + 1)
    sweep([job(20, finished_at=F5)])
must(sum(1 for (c, pk) in W.notice_rows if c == cid(20) and pk == 4) == 1, "carol holds one notice")
must([a for a, _ in W.sent] == ["carol@example.test"], "carol is never emailed again")

# ------------------------------------------------------------------------------------------------ 5. the ledger keeps the rows the window needs
must(RETENTION_DAYS == 14, f"the ledger keeps fourteen days (notices.py), found {RETENTION_DAYS}")
must(RETENTION_DAYS >= mfn.NOTICE_WINDOW.days + 1, "the retention is at least a day longer than the window")
fresh()
finished = stamp(days=6, hours=23, minutes=59)  # finished 6 days 23 hours 59 minutes before the first sweep
sweep([job(30, finished_at=finished)])
CLOCK["now"] = NOW + timedelta(minutes=1)  # the job is now exactly seven days old: the last moment it is still inside the window
W.ledger_prune()
must(any(k[0] == "notice" and k[1] == job(30)["id"] for k in W.ledger), "a ledger row for a job inside the window survives the prune")
fresh()
W.ledger[("notice", "ancient", 1)] = NOW - timedelta(days=RETENTION_DAYS + 1)
W.ledger_prune()
must(("notice", "ancient", 1) not in W.ledger, "a row older than the retention is pruned")

# ------------------------------------------------------------------------------------------------ 6. the source and the docs say seven days, and no window line still says six hours
WINDOW_FILES = [
    "framwork/tec_tac/module_failure_notices.py",
    "framwork/tec_tac/notices.py",
    "framwork/tec_tac/models.py",
    "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py",
    "docs/module-replacement.md",
]
for rel in WINDOW_FILES:
    text = (ROOT / rel).read_text(encoding="utf-8")
    for line in text.splitlines():
        lowered = line.lower()
        if "six hour" in lowered or "6 hour" in lowered:
            must(any(word in lowered for word in ("1.17.34", "was ", "before", "from 1.17.34")),
                 f"{rel} still says six hours for the window: {line.strip()[:120]}")
must("NOTICE_WINDOW_HOURS = 7 * 24" in (ROOT / "framwork/tec_tac/module_failure_notices.py").read_text(encoding="utf-8"),
     "the constant is seven days")
must("seven days" in (ROOT / "framwork/tec_tac/module_failure_notices.py").read_text(encoding="utf-8"), "the module says seven days")
must("14 day" in (ROOT / "framwork/tec_tac/module_failure_notices.py").read_text(encoding="utf-8"), "the sweep says the 14 day retention")
must("fourteen days" in (ROOT / "framwork/tec_tac/models.py").read_text(encoding="utf-8"), "the ledger model says fourteen days")
must("7 day window" in (ROOT / "docs/module-replacement.md").read_text(encoding="utf-8"), "the replacement doc says the 7 day window")
must("no daily reminder" in (ROOT / "docs/module-replacement.md").read_text(encoding="utf-8"), "the replacement doc says no daily reminder")

print("[TEST] PASS module failure notices window 1.17.38")
