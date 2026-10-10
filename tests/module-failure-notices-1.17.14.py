#!/usr/bin/env python3
"""1.17.14 regression: notices for failed module jobs (Johan CQ36 and CQ41, 9 October 2026). Django-free part.

Runs the real ``module_failure_notices.py`` and ``module_replacement.py`` with Django and the Linux-only modules stubbed. It covers:
the job-to-notice text (plain English, printable ASCII, no paths, cut short), which jobs owe a notice, the dedupe key, the bounds
(seven days, 200 jobs, newest first), one notice per job and recipient, that a notice that exists is not written again, that a
failing step never raises, and the shape of ``tec_tac.notices.publish_system_notice`` and the scheduler tick call (read as text).
The database part is tests/module-failure-notices-runtime-1.17.14.py (a dev-server script).
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

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def stamp(days=0, minutes=0):
    return (NOW - timedelta(days=days, minutes=minutes)).isoformat()


def job(n, **extra):
    base = {"id": f"00000000-0000-4000-8000-{n:012d}", "status": "failed", "action": "enable", "plugin_id": "patching",
            "finished_at": stamp(minutes=n), "error": "the lifecycle step failed", "requested_by": "alice"}
    base.update(extra)
    return base


# ------------------------------------------------------------------------------------------ the text
note = mfn.notice_for_job(job(1))
must(note["client_id"] == "module-job-failed:00000000-0000-4000-8000-000000000001" and len(note["client_id"]) <= 64, note)
must(note["level"] == "error" and note["title"] == "Module job failed" and note["action_route"] == "/modules" and note["action_label"] == "Open Modules", note)
must(note["requested_by"] == "alice" and note["message"].startswith("Module patching could not be enabled."), note)
must("Nothing was changed." in note["message"] and note["message"].endswith("Error: the lifecycle step failed"), note["message"])
for action, verb in (("enable", "enabled"), ("disable", "disabled"), ("install", "installed")):
    must(f"could not be {verb}." in mfn.notice_for_job(job(2, action=action))["message"], action)
must("could not be updated." in mfn.notice_for_job(job(2, action="install", replace=True))["message"], "an upgrade says updated")
must(mfn.notice_for_job(job(3, action="batch_install", plugin_id="batch"))["message"].startswith("The batch install could not be installed."), "batch")
must(mfn.notice_for_job(job(4, action="bundle_install", plugin_id="pack"))["message"].startswith("The bundle install of module pack could not be installed."), "bundle")
# a failed switch says whether the flags were put back, from what the helper recorded
switch = dict(action="enable", disable_modules=["patchmanagement"], stage="runtime-sync")
must("The flags were put back as they were." in mfn.notice_for_job(job(5, rolled_back=True, **switch))["message"], "rolled back")
must("could not put the flags back" in mfn.notice_for_job(job(5, rollback_error="read-only", **switch))["message"], "rollback error")
must("The outcome is not confirmed" in mfn.notice_for_job(job(5, **switch))["message"], "stage alone is not proof")
must("Nothing was changed." in mfn.notice_for_job(job(5, action="disable", stage="lifecycle"))["message"], "nothing changed")
# sanitising: ascii only, no paths, one line, cut
dirty = mfn.notice_for_job(job(6, error="boom \u00e9\u4e2d at /var/lib/tec-tac/module-manager/jobs/x.json and C:\\temp\\y.log\nline two\x00" + "z" * 900))["message"]
must(dirty.isascii() and "\n" not in dirty and "\x00" not in dirty, repr(dirty))
must("/var/lib" not in dirty and "C:\\" not in dirty and "[path]" in dirty and len(dirty) <= mfn.MESSAGE_MAX, dirty)
must(mfn.notice_for_job(job(7, error=None))["message"].endswith("Error: no error was recorded"), "no error text")
must(mfn.notice_for_job(job(7, plugin_id="x/../y"))["message"].startswith("Module [path] could not"), "a path-like id is not echoed")
# which jobs owe a notice
for bad in (job(8, status="succeeded"), job(8, status="running"), job(8, action="visibility"), job(8, action="remove"), job(8, id="bad id!"), job(8, id=""), "x", None):
    must(mfn.notice_for_job(bad) is None, bad)
must(mfn.client_id_for("../etc") is None and mfn.client_id_for("a" * 41) is None and mfn.client_id_for("abc-1") == "module-job-failed:abc-1", "key")

# ------------------------------------------------------------------------------------------ the sweep
PEOPLE = {"root": types.SimpleNamespace(pk=1), "alice": types.SimpleNamespace(pk=2), "bob": types.SimpleNamespace(pk=3)}
STORE: set = set()
PUBLISHED: list = []


def recipients_for(requested_by):
    people = [PEOPLE["root"]]  # every effective superuser
    if requested_by in PEOPLE and PEOPLE[requested_by] not in people:
        people.append(PEOPLE[requested_by])
    return people


def publish(recipients, notice):
    created = 0
    for user in recipients:
        if (notice["client_id"], user.pk) not in STORE:
            STORE.add((notice["client_id"], user.pk))
            created += 1
    PUBLISHED.append((notice["client_id"], [user.pk for user in recipients]))
    return created


def existing(ids):
    return {pair for pair in STORE if pair[0] in ids}


def run(jobs, **kw):
    PUBLISHED.clear()
    return mfn.sweep_failed_jobs(now=NOW, jobs=jobs, recipients_for=recipients_for, publish=publish, existing=existing, **kw)


# one notice per job and recipient: the superuser and the requester
must(run([job(1)]) == 2 and STORE == {(mfn.client_id_for(job(1)["id"]), 1), (mfn.client_id_for(job(1)["id"]), 2)}, STORE)
# the next tick adds nothing and writes nothing
must(run([job(1)]) == 0 and PUBLISHED == [], PUBLISHED)
# the requester is the superuser: one notice, not two
STORE.clear()
must(run([job(2, requested_by="root")]) == 1, STORE)
# a requester that is not a user (the reconcile job's "system") and a missing one: superusers only
STORE.clear()
must(run([job(3, requested_by="system"), job(4, requested_by=None)]) == 2, STORE)
# a new recipient that has no notice yet gets one, the others are left alone
STORE.clear()
run([job(5, requested_by="alice")])
PEOPLE["carol"] = types.SimpleNamespace(pk=4)
recipients_for = lambda requested_by: [PEOPLE["root"], PEOPLE["alice"], PEOPLE["carol"]]  # noqa: E731
must(run([job(5, requested_by="alice")]) == 1 and PUBLISHED[0][1] == [4], PUBLISHED)
recipients_for = lambda requested_by: [PEOPLE["root"]] + ([PEOPLE[requested_by]] if requested_by in PEOPLE else [])  # noqa: E731
# jobs that did not fail, and jobs outside the window, owe nothing
STORE.clear()
must(run([job(6, status="succeeded"), job(7, status="running"), job(8, finished_at=stamp(days=8)), job(9, finished_at=None), job(10, finished_at="garbage")]) == 0, STORE)
must(run([job(11, finished_at=stamp(days=6))]) == 2, "inside the seven days")
# at most 200 jobs per tick, newest first
STORE.clear()
many = [job(n, requested_by="system", finished_at=stamp(minutes=n)) for n in range(1, 251)]
must(run(many) == 200, len(STORE))
kept = {pair[0] for pair in STORE}
must(mfn.client_id_for(many[0]["id"]) in kept and mfn.client_id_for(many[199]["id"]) in kept and mfn.client_id_for(many[200]["id"]) not in kept, "newest 200")
# the lookup of who already has a notice is one read for the whole tick
reads = []
run([job(1)], ) if False else None
mfn.sweep_failed_jobs(now=NOW, jobs=many[:5], recipients_for=recipients_for, publish=publish, existing=lambda ids: reads.append(list(ids)) or set())
must(len(reads) == 1 and len(reads[0]) == 5, reads)
# no failed job: no database read at all
reads.clear()
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1, status="succeeded")], existing=lambda ids: reads.append(ids) or set()) == 0 and reads == [], reads)

# never raises: a failing job source, store, recipients lookup and existence lookup
def boom(*args, **kwargs):
    raise RuntimeError("database is down")


def exploding_jobs():
    yield job(1)
    raise OSError("disk")


mfn.logger.disabled = True
must(mfn.sweep_failed_jobs(now=NOW, jobs=exploding_jobs(), recipients_for=recipients_for, publish=publish, existing=existing) in (0, 2), "a failing job source")
STORE.clear()
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=recipients_for, publish=boom, existing=existing) == 0, "a failing store")
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=boom, publish=publish, existing=existing) == 0, "a failing recipients lookup")
must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1)], recipients_for=recipients_for, publish=publish, existing=boom) == 0, "a failing existence lookup")
# one failing job does not stop the next one
calls = []


def flaky(recipients, notice):
    calls.append(notice["client_id"])
    if len(calls) == 1:
        raise RuntimeError("first store fails")
    return len(recipients)


must(mfn.sweep_failed_jobs(now=NOW, jobs=[job(1), job(2)], recipients_for=recipients_for, publish=flaky, existing=lambda ids: set()) == 2 and len(calls) == 2, calls)
mfn.logger.disabled = False

# ------------------------------------------------------------------------------------------ the store and the tick (read as text)
notices_src = (ROOT / "framwork/tec_tac/notices.py").read_text(encoding="utf-8")
must("def publish_system_notice(" in notices_src and "get_or_create(user=user, client_id=key" in notices_src, "stored once per recipient, never reset")
must("def system_notice_recipients(" in notices_src and "is_installer_user=False" in notices_src and "role__is_superuser=True" in notices_src, "recipients")
body = notices_src[notices_src.index("def publish_system_notice("):notices_src.index("def list_notices(")]
must("update_or_create" not in body and "read_at\": None" in body and 'level: str = "error"' in body and 'source: str = "core"' in body, "a read notice is not reset")
tick = (ROOT / "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("sweep_failed_jobs" in tick and tick.index("audit_finished_jobs") < tick.index("sweep_failed_jobs") and "except Exception as exc:" in tick[tick.index("sweep_failed_jobs"):], "called next to audit_finished_jobs and never raises")
must("module_failure_notices={failure_notices}" in tick, "the tick output reports it")
# the dedupe key fits the notice client_id rule
import re  # noqa: E402

must(re.fullmatch(r"^[A-Za-z0-9._:-]{1,64}$", mfn.client_id_for("00000000-0000-4000-8000-000000000001")), "client_id rule")

print("[TEST] PASS module failure notices 1.17.14")
