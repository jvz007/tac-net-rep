#!/usr/bin/env python3
"""1.17.35 regression: the ledger copy of an old email marker keeps the marker's own time (the 1.17.34 review, held Low).

Before 1.17.35 the copy of an old "Email notice sent" marker into the notice ledger got created_at = now, so 25 old markers counted
toward the Priority 1 hourly cap (20 an hour) for an hour, and held back a fresh email. Now each copied row carries the marker's own
created_at, ledger_add takes an optional created_at (a datetime, or a mapping of user id to datetime), and a marker with no readable
time falls back to now. Django-free part.

The real ``notices.ledger_add``, ``ledger_have``, ``ledger_count_since`` and ``ledger_prune`` are extracted from notices.py with ast and
run on a small fake table that behaves like the model for the lookups used (exact, in, gte, lt), update, delete and get_or_create (which
sets created_at to now on the first save, as auto_now_add does). The real ``module_failure_notices`` functions run on top of them, with
only the seams that touch the database or the mail server replaced. The real ORM part (the .update(created_at=) on the table, and the
rollback) is tests/module-failure-notices-ledger-runtime-1.17.35.py, run on the dev server.

Covered: (1) 25 old markers 3 hours old are copied with their own time, count 0 toward the last hour, and a fresh email for a new job is
sent (not held back); (2) a marker from 10 minutes ago counts exactly once, also after repeated reads; (3) the copied row keeps the
marker's time, not now; (4) a second read copies nothing (idempotent, no ledger_add call); (5) a marker with created_at None falls back
to now; (6) a failing ledger_add still returns the marker pairs and logs one warning; (7) ledger_add with no created_at behaves as before,
and never changes an existing row; (8) a failure inside one ledger_add leaves none of its rows behind; (9) source checks.
"""
from __future__ import annotations

import ast
import sys
import types
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
NOTICES = ROOT / "framwork/tec_tac/notices.py"
FAILURE = ROOT / "framwork/tec_tac/module_failure_notices.py"


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

from tec_tac import module_failure_notices as mfn
from tec_tac import priority_mail

priority_mail.resolve_addresses = lambda name: ["93.184.216.34"]

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
CLOCK = {"now": NOW}
FLAGS = {"add_fails": False, "update_fails": False}


# ------------------------------------------------------------------------------------------------ a fake table with the model's behaviour
class Row(types.SimpleNamespace):
    pass


class Query:
    def __init__(self, table, rows):
        self.table, self.rows = table, rows

    def filter(self, **kw):
        rows = self.rows
        for lookup, want in kw.items():
            field, _, op = lookup.partition("__")
            op = op or "exact"
            if op == "exact":
                rows = [r for r in rows if getattr(r, field) == want]
            elif op == "in":
                rows = [r for r in rows if getattr(r, field) in want]
            elif op == "gte":
                rows = [r for r in rows if getattr(r, field) >= want]
            elif op == "lt":
                rows = [r for r in rows if getattr(r, field) < want]
            else:
                raise AssertionError(f"lookup {lookup} is not in the fake")
        return Query(self.table, rows)

    def values_list(self, *fields):
        return [tuple(getattr(r, f) for f in fields) for r in self.rows]

    def count(self):
        return len(self.rows)

    def update(self, **kw):
        if FLAGS["update_fails"]:
            raise RuntimeError("update failed")
        for r in self.rows:
            r.__dict__.update(kw)
        return len(self.rows)

    def delete(self):
        ids = {id(r) for r in self.rows}
        self.table.rows = [r for r in self.table.rows if id(r) not in ids]
        return len(ids), {}


class Table:
    def __init__(self):
        self.reset()
        self.objects = self

    def reset(self):
        self.rows: list = []
        self.pk = 0

    def filter(self, **kw):
        return Query(self, list(self.rows)).filter(**kw)

    def get_or_create(self, user_id, kind, key):
        for r in self.rows:
            if (r.user_id, r.kind, r.key) == (user_id, kind, key):
                return r, False
        self.pk += 1
        row = Row(pk=self.pk, user_id=user_id, kind=kind, key=key, created_at=CLOCK["now"])  # auto_now_add: now on the first save
        self.rows.append(row)
        return row, True


TABLE = Table()


class FakeModel:
    KIND_NOTICE = "notice"
    KIND_EMAIL = "email"
    objects = TABLE


class Atomic:
    """A transaction: a failure inside restores the rows the call had before it."""

    def __enter__(self):
        self.saved = ([Row(**r.__dict__) for r in TABLE.rows], TABLE.pk)
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            TABLE.rows, TABLE.pk = self.saved
        return False


# ------------------------------------------------------------------------------------------------ the real ledger functions, extracted
WANTED = {"LEDGER_KINDS", "LEDGER_RETENTION_DAYS", "_ledger_kind", "ledger_have", "ledger_add", "ledger_count_since", "ledger_prune"}
tree = ast.parse(NOTICES.read_text(encoding="utf-8"))
nodes = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in WANTED:
        nodes.append(node)
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in WANTED for t in node.targets):
        nodes.append(node)
must({getattr(n, "name", None) or n.targets[0].id for n in nodes} == WANTED, "every ledger function is found in notices.py")
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)


class NoticeError(ValueError):
    pass


ns = {
    "TecTacNoticeLedger": FakeModel, "transaction": types.SimpleNamespace(atomic=Atomic), "Mapping": Mapping,
    "NoticeError": NoticeError, "timezone": types.SimpleNamespace(now=lambda: CLOCK["now"]), "timedelta": timedelta,
}
exec(compile(module, str(NOTICES), "exec"), ns)  # noqa: S102 - test-only: the real ledger functions of notices.py

fake_notices = types.ModuleType("tec_tac.notices")
for name in ("ledger_have", "ledger_add", "ledger_count_since", "ledger_prune"):
    setattr(fake_notices, name, ns[name])
sys.modules["tec_tac.notices"] = fake_notices  # mfn does ``from . import notices`` inside its defaults

ADD_CALLS: list = []
_real_add = fake_notices.ledger_add


def counting_add(*args, **kwargs):
    ADD_CALLS.append(args)
    if FLAGS["add_fails"]:
        raise RuntimeError("ledger write failed")
    return _real_add(*args, **kwargs)


fake_notices.ledger_add = counting_add

WARNINGS: list = []
mfn.logger.warning = lambda *a, **k: WARNINGS.append(a[0] if a else "")

MARKERS: dict = {}  # (email client id, user id) -> created_at: what the real _default_marker_times would read
mfn._default_marker_times = lambda client_ids: {pair: at for pair, at in MARKERS.items() if pair[0] in client_ids}


def reset():
    TABLE.reset()
    MARKERS.clear()
    ADD_CALLS.clear()
    WARNINGS.clear()
    FLAGS.update(add_fails=False, update_fails=False)
    CLOCK["now"] = NOW


def email_cid(job_id):
    return f"{mfn.EMAIL_CLIENT_ID_PREFIX}{job_id}"


def ledger_rows(job_id, kind="email"):
    return [r for r in TABLE.rows if r.kind == kind and r.key == job_id]


OLD = "00000000-0000-4000-8000-00000000a001"
NEW = "00000000-0000-4000-8000-00000000a002"
FRESH = "00000000-0000-4000-8000-00000000a003"
ONE = "00000000-0000-4000-8000-00000000a004"
TWO = "00000000-0000-4000-8000-00000000a005"
THREE = "00000000-0000-4000-8000-00000000a006"

# ------------------------------------------------------------------------------------------------ 1. 25 old markers do not hold back a new email
reset()
for user_id in range(1, 26):
    MARKERS[(email_cid(OLD), user_id)] = NOW - timedelta(hours=3)
pairs = mfn._default_email_have([email_cid(OLD)])
must(len(pairs) == 25, f"the 25 markers are read as already tried: {len(pairs)}")
must(len(ledger_rows(OLD)) == 25, "the 25 markers are copied into the ledger")
must(all(r.created_at == NOW - timedelta(hours=3) for r in ledger_rows(OLD)), "each copy keeps the marker's own time, three hours ago")
must(mfn._default_recent(NOW - mfn.EMAIL_WINDOW) == 0, "the hourly cap counts none of them")

sent = []
report = {}
recipients = [types.SimpleNamespace(pk=1, email="root@example.test"), types.SimpleNamespace(pk=2, email="boss@example.test")]
freshly = {"id": FRESH, "status": "failed", "action": "enable", "plugin_id": "patching", "finished_at": (NOW - timedelta(minutes=10)).isoformat(),
           "error": "the lifecycle step failed", "requested_by": "alice"}
mfn.sweep_failed_jobs(now=NOW, jobs=[freshly], recipients_for=lambda requested_by: list(recipients),
                      publish=lambda rcpts, notice: len(rcpts), existing=lambda ids: set(), configured=lambda: True,
                      host=lambda: "smtp.example.com", send=lambda address, subject, body: sent.append(address) or True,
                      audit=lambda job, message: None, report=report)
must(len(sent) == 2 and report.get("emailed") == 2, f"a fresh email for a new job is not held back: sent={sent} report={report}")

# ------------------------------------------------------------------------------------------------ 2. a marker from 10 minutes ago counts once
reset()
MARKERS[(email_cid(TWO), 1)] = NOW - timedelta(minutes=10)
mfn._default_email_have([email_cid(TWO)])
mfn._default_email_have([email_cid(TWO)])
mfn._default_email_have([email_cid(TWO)])
must(len(ledger_rows(TWO)) == 1, "one row, however often it is read")
must(mfn._default_recent(NOW - mfn.EMAIL_WINDOW) == 1, "it counts exactly once toward the last hour")
must(ledger_rows(TWO)[0].created_at == NOW - timedelta(minutes=10), "it keeps the time the email went")

# ------------------------------------------------------------------------------------------------ 3. the copy is idempotent
reset()
MARKERS[(email_cid(ONE), 4)] = NOW - timedelta(hours=2)
first = mfn._default_email_have([email_cid(ONE)])
calls_after_first = len(ADD_CALLS)
second = mfn._default_email_have([email_cid(ONE)])
must(first == second == {(email_cid(ONE), 4)}, "the same pairs both times")
must(len(ADD_CALLS) == calls_after_first, f"a second read copies nothing: {len(ADD_CALLS)} vs {calls_after_first}")
must(len(ledger_rows(ONE)) == 1 and ledger_rows(ONE)[0].created_at == NOW - timedelta(hours=2), "one row, its time unchanged")

# ------------------------------------------------------------------------------------------------ 4. a marker with no readable time falls back to now
reset()
MARKERS[(email_cid(THREE), 7)] = None
mfn._default_email_have([email_cid(THREE)])
must(len(ledger_rows(THREE)) == 1 and ledger_rows(THREE)[0].created_at == NOW, "created_at None falls back to now")
must(mfn._default_recent(NOW - mfn.EMAIL_WINDOW) == 1, "and counts toward the hour, as an email sent now would")

# ------------------------------------------------------------------------------------------------ 5. a failing copy: pairs kept, one warning
reset()
MARKERS[(email_cid(OLD), 1)] = NOW - timedelta(hours=1)
MARKERS[(email_cid(OLD), 2)] = NOW - timedelta(hours=1)
MARKERS[(email_cid(ONE), 3)] = NOW - timedelta(hours=1)
FLAGS["add_fails"] = True
pairs = mfn._default_email_have([email_cid(OLD), email_cid(ONE)])
must(pairs == {(email_cid(OLD), 1), (email_cid(OLD), 2), (email_cid(ONE), 3)}, f"the marker pairs are still returned: {pairs}")
must(len(WARNINGS) == 1, f"one warning, not one per job: {WARNINGS}")
must(not TABLE.rows, "nothing was written")
FLAGS["add_fails"] = False
mfn._default_email_have([email_cid(OLD), email_cid(ONE)])
must(len(ledger_rows(OLD)) == 2 and len(ledger_rows(ONE)) == 1, "the next read copies them")

# ------------------------------------------------------------------------------------------------ 6. ledger_add: the keyword and the old behaviour
reset()
must(ns["ledger_add"]("email", "job-x", [11, 12]) == 2, "no created_at: two rows created")
must(all(r.created_at == NOW for r in ledger_rows("job-x")), "no created_at: rows get now, as before")
must(ns["ledger_add"]("email", "job-x", [11], created_at={11: NOW - timedelta(hours=5)}) == 0, "an existing row is not created again")
must(ledger_rows("job-x")[0].created_at == NOW, "and its time is never changed")
must(ns["ledger_add"]("email", "job-x", [13], created_at={}) == 1 and ledger_rows("job-x")[-1].created_at == NOW,
     "a user missing from the mapping gets now")
must(ns["ledger_add"]("email", "job-y", [21], created_at=NOW - timedelta(hours=2)) == 1, "one datetime for every user is accepted")
must(ledger_rows("job-y")[0].created_at == NOW - timedelta(hours=2), "and used for the new row")
must(ns["ledger_add"]("notice", "job-y", [21]) == 1 and ledger_rows("job-y", "notice")[0].created_at == NOW, "kind notice works the same")
try:
    ns["ledger_add"]("other", "job-z", [1])
except NoticeError:
    pass
else:
    raise AssertionError("an unknown kind is still refused")

# ------------------------------------------------------------------------------------------------ 7. a failure inside one call leaves no row
reset()
FLAGS["update_fails"] = True
try:
    ns["ledger_add"]("email", "job-w", [31, 32], created_at={31: NOW - timedelta(hours=1), 32: NOW - timedelta(hours=1)})
except RuntimeError:
    pass
else:
    raise AssertionError("the failed update raises")
FLAGS["update_fails"] = False
must(not ledger_rows("job-w"), "the rows the call created are rolled back with it")
must(ns["ledger_add"]("email", "job-w", [31]) == 1, "a later call creates them again")

# ------------------------------------------------------------------------------------------------ 8. ledger_count_since and prune unchanged
reset()
ns["ledger_add"]("email", "job-old", [41], created_at=NOW - timedelta(days=8))
ns["ledger_add"]("email", "job-new", [42], created_at=NOW - timedelta(minutes=5))
must(ns["ledger_count_since"]("email", NOW - timedelta(hours=1)) == 1, "the count sees only the recent row")
must(ns["ledger_prune"](7) == 1 and len(TABLE.rows) == 1, "a copied row older than 7 days is pruned as before")

# ------------------------------------------------------------------------------------------------ 9. source checks
notices_src = NOTICES.read_text(encoding="utf-8")
failure_src = FAILURE.read_text(encoding="utf-8")
add_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "ledger_add")
kwonly = [a.arg for a in add_node.args.kwonlyargs]
must(kwonly == ["created_at"] and add_node.args.kw_defaults[0] is not None and isinstance(add_node.args.kw_defaults[0], ast.Constant)
     and add_node.args.kw_defaults[0].value is None, "ledger_add has a keyword-only created_at defaulting to None")
must(".update(created_at=when)" in notices_src and "transaction.atomic()" in notices_src, "the time is written with an update inside a transaction")
must("def _default_marker_times(" in failure_src and "marker_times" in failure_src, "the email read takes the marker times")
must("created_at=times" in failure_src and "            break  # one warning per tick" in failure_src, "the copy passes the per-person times and stops after one failure")
print("[TEST] PASS module failure notices 1.17.35")
