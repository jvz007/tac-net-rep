#!/usr/bin/env python3
"""1.17.13 regression: the two findings held from the 1.17.12 review.

* Medium: the switch-failed audit row no longer claims the flags were put back when no rollback ran. The sentence follows what the
  root helper recorded (``rolled_back``, ``rollback_error``), never the stage name. A job file written by 1.17.12 has neither field,
  so a failure at runtime-sync or rollback then says the outcome is not confirmed.
* Low: the duplicate-row check no longer depends on the audit metadata. Every queued and outcome row carries the correlation id
  ``module-replacement:<action>:<job id>``, which the audit writer's size fitting never drops, and the lookup still finds a row
  written by 1.17.12 by its metadata job id. The unbounded ``error`` is cut to 300 characters and ``planned`` to 10 ids.

Builds on the stubs of tests/module-replacement-audit-1.17.12.py (executed from that file, so the two cannot drift). The real
AuditLog JSON lookup needs a server: see tests/module-replacement-handback-runtime-1.17.13.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "module-replacement-audit-1.17.12.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("# ------------------------------------------------------------------------------------------ queue time: a request, not a change")
source = source[:cut].replace("mr._audit_already_written = fake_lookup", "REAL_LOOKUP = mr._audit_already_written\nmr._audit_already_written = fake_lookup")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source, str(BASE), "exec"), G)
mr, LOG, world, finished, actions, must, NOW, audit_stub = (G[k] for k in ("mr", "LOG", "world", "finished", "actions", "must", "NOW", "audit_stub"))
REAL_LOOKUP = G["REAL_LOOKUP"]


def failed(job_id="j-1", **extra):
    base = dict(id=job_id, status="failed", action="enable", plugin_id="patching", disable_modules=["patchmanagement"], replacement_confirmed=True,
                stage="runtime-sync", error="Tactical graceful reload failed with status 1")
    base.update(extra)
    return finished(**base)


def rows_for(job):
    return mr._outcome_rows(job, lambda module_id: "")


# ------------------------------------------------------------------------------------------ the sentence follows what happened
# the review's example: a confirmed disable that the plan no longer needs, then the sync fails. Nothing recorded a restore.
[row] = rows_for(failed())
must(row["action"] == "custom:module-replacement-switch-failed" and row["object_id"] == "patching", row)
must("The outcome is not confirmed" in row["message"] and "stage runtime-sync" in row["message"] and "Check the module state" in row["message"], row["message"])
must("put back" not in row["message"] and "Nothing was changed" not in row["message"], "it never claims a restore, and never claims no change")
must(row["metadata"]["rolled_back"] is None and row["metadata"]["stage"] == "runtime-sync", row["metadata"])
# a 1.17.12 job file at the rollback stage has neither field: not confirmed either
[row] = rows_for(failed(stage="rollback", disabled_modules=["patchmanagement"]))
must("not confirmed" in row["message"] and "stage rollback" in row["message"] and "put back" not in row["message"] and row["metadata"]["rolled_back"] is None, row)
# the helper restored the flags
[row] = rows_for(failed(stage="rollback", rolled_back=True))
must("The flags were put back as they were." in row["message"] and row["metadata"]["rolled_back"] is True, row)
[row] = rows_for(failed(stage="runtime-sync", rolled_back=True))
must("The flags were put back as they were." in row["message"] and row["metadata"]["rolled_back"] is True, row)
# restoring them raised
[row] = rows_for(failed(stage="rollback", rollback_error="PermissionError: module-state.json"))
must("Core could not put the flags back" in row["message"] and "Modules page" in row["message"] and "put back as they were" not in row["message"], row["message"])
must(row["metadata"]["rolled_back"] is False, row["metadata"])
[row] = rows_for(failed(stage="rollback", rolled_back=True, rollback_error="x"))
must("could not put the flags back" in row["message"], "an error wins over a flag")
for value in ("true", 1, None, False, "yes"):  # only the boolean True counts as a restore
    [row] = rows_for(failed(stage="rollback", rolled_back=value))
    must("put back as they were" not in row["message"], value)
# a failure before anything changed
for stage in ("lifecycle", "dispatched", "failed", "", None):
    [row] = rows_for(failed(stage=stage))
    must("Nothing was changed." in row["message"] and row["metadata"]["rolled_back"] is False, (stage, row["message"]))
# the other direction (hand-back) reads the same fields
[row] = rows_for(finished(id="j-hb", status="failed", action="disable", plugin_id="patchmanagement", enable_modules=["patching"], stage="runtime-sync", error="boom"))
must("not confirmed" in row["message"], row["message"])
[row] = rows_for(finished(id="j-hb", status="failed", action="disable", plugin_id="patchmanagement", enable_modules=["patching"], stage="rollback", rolled_back=True, error="boom"))
must("put back as they were" in row["message"], row["message"])
# no planned list, no row, as before
must(rows_for(failed(disable_modules=[], enable_modules=[])) == [], "not a switch")

# ------------------------------------------------------------------------------------------ bounded text
long_error = "x" * 5000 + "\n\x00\x1b[31mred" + "é" * 100
[row] = rows_for(failed(error=long_error))
must(len(row["metadata"]["error"]) == 300 and row["metadata"]["error"] == "x" * 300, len(row["metadata"]["error"]))
must(all(32 <= ord(ch) < 127 for ch in row["message"]), "the message is printable ASCII")
must(len(row["message"].encode("utf-8")) < 800, len(row["message"]))
[row] = rows_for(failed(error="Réseau \x00 down\n"))
must(row["metadata"]["error"] == "Rseau  down", row["metadata"]["error"])
many = [f"m{i:02d}" for i in range(40)]
[row] = rows_for(failed(disable_modules=many))
must(row["metadata"]["planned"] == many[:10] and "m09" in row["message"] and "m10" not in row["message"], row["metadata"]["planned"])
[row] = rows_for(failed(error=None))
must("Error: no error was recorded" in row["message"] and row["metadata"]["error"] == "no error was recorded", row)
[row] = rows_for(failed(error=12345, stage="x" * 200))
must(row["metadata"]["error"] == "12345" and len(row["metadata"]["stage"]) == 40, row["metadata"])

# ------------------------------------------------------------------------------------------ correlation ids
must(mr.correlation_id_for("custom:module-replacement-disabled", "j1") == "module-replacement:disabled:j1", "disabled")
must(mr.correlation_id_for("custom:module-replacement-switch-failed", "j1") == "module-replacement:switch-failed:j1", "failed")
must(mr.correlation_id_for(mr.ACTION_SWITCH_QUEUED, None) == "module-replacement:switch-queued:", "no job id")
must(len(mr.correlation_id_for(mr.ACTION_DISABLED, "j" * 1000)) == 255, "bounded")
del LOG[:]
world(patching=False, pm=True)
mr.audit_finished_jobs(now=NOW, jobs=[
    finished(id="j-ok", action="enable", plugin_id="patching", disabled_modules=["patchmanagement"], replacement_confirmed=True),
    finished(id="j-bk", action="disable", plugin_id="patchmanagement", enabled_modules=["patching"]),
    finished(id="j-rc", action="enable", plugin_id="patching", reconciled_modules=["patchmanagement"]),
    failed("j-fail", stage="rollback", rolled_back=True),
])
by_action = {row["action"]: row for row in LOG}
must(by_action["custom:module-replacement-disabled"]["correlation_id"] == "module-replacement:disabled:j-ok", by_action)
must(by_action["custom:module-replacement-enabled"]["correlation_id"] == "module-replacement:enabled:j-bk", by_action)
must(by_action["custom:module-replacement-conflict-resolved"]["correlation_id"] == "module-replacement:conflict-resolved:j-rc", by_action)
must(by_action["custom:module-replacement-switch-failed"]["correlation_id"] == "module-replacement:switch-failed:j-fail", by_action)
del LOG[:]
mr.audit_switch_queued(SimpleNamespace(username="alice"), "patching", "job-7", disabled=["patchmanagement"])
must(LOG[0]["correlation_id"] == "module-replacement:switch-queued:job-7" and LOG[0]["metadata"]["job_id"] == "job-7", LOG)
del LOG[:]

# ------------------------------------------------------------------------------------------ the real lookup, with a fake AuditLog
class Q:
    """Enough of django.db.models.Q for the lookup: keyword conditions and |."""

    def __init__(self, **conditions):
        self.conditions, self.parts = conditions, None

    def __or__(self, other):
        joined = Q()
        joined.parts = (self, other)
        return joined

    def matches(self, row):
        if self.parts:
            return any(part.matches(row) for part in self.parts)
        return all(_dig(row, path) == value for path, value in self.conditions.items())


def _dig(row, path):
    value = row
    for part in path.split("__"):
        value = value.get(part) if isinstance(value, dict) else None
    return value


class Found:
    def __init__(self, hit):
        self.hit = hit

    def exists(self):
        return self.hit


STORE = []


class Manager:
    def filter(self, *queries, **conditions):
        def hit(row):
            return all(q.matches(row) for q in queries) and all(_dig(row, path) == value for path, value in conditions.items())
        return Found(any(hit(row) for row in STORE))


class FakeAuditLog:
    objects = Manager()


models = ModuleType("django.db.models")
models.Q = Q
django_db = ModuleType("django.db")
django_db.models = models
django = sys.modules.get("django") or ModuleType("django")
sys.modules.update({"django": django, "django.db": django_db, "django.db.models": models})
audit_stub._auditlog_model = lambda: FakeAuditLog
FAILING = {"on": False}


def store_row(action, object_id, correlation_id=None, metadata=None):
    STORE.append({"action": action, "debug_info": {"object_id": object_id, "correlation_id": correlation_id, "metadata": metadata or {}}})


MARKER = {"error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES", "original_bytes": 99999}
# a row whose metadata was replaced by the size marker is still found: by its correlation id
store_row("custom:module-replacement-switch-failed", "patching", "module-replacement:switch-failed:j-big", MARKER)
must(REAL_LOOKUP("custom:module-replacement-switch-failed", "patching", "j-big") is True, "found by correlation id")
# a row written by 1.17.12 has only metadata.job_id
store_row("custom:module-replacement-disabled", "patchmanagement", None, {"job_id": "j-old", "replacement": "x", "replaced": "y"})
must(REAL_LOOKUP("custom:module-replacement-disabled", "patchmanagement", "j-old") is True, "found by metadata job id (a 1.17.12 row)")
# a row that matches the action and object but another job is not a match
must(REAL_LOOKUP("custom:module-replacement-switch-failed", "patching", "j-other") is False, "another job")
must(REAL_LOOKUP("custom:module-replacement-switch-failed", "other", "j-big") is False, "another object")
must(REAL_LOOKUP("custom:module-replacement-disabled", "patching", "j-big") is False, "another action")
must(REAL_LOOKUP("custom:module-replacement-disabled", "patching", "") is False, "an empty job id matches nothing")
store_row("custom:module-replacement-disabled", "patching", "module-replacement:disabled:", {})
# (an empty job id never reaches the lookup in practice: a job without an id is not written, see below)
STORE.pop()

# the whole sweep with the real lookup: write once, then a second sweep (after the writer has replaced the metadata) writes nothing
del STORE[:], LOG[:]
mr._audit_already_written = REAL_LOOKUP


def to_store(rows):
    for row in rows:
        store_row(row["action"], row["object_id"], row.get("correlation_id"), row["metadata"])


big_job = failed("j-huge", stage="rollback", rolled_back=True, error="E" * 5000)
jobs = [big_job, finished(id="j-ok2", action="enable", plugin_id="patching", disabled_modules=["patchmanagement"], replacement_confirmed=True)]
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 2, LOG)
to_store(LOG)
must(len(STORE) == 2, STORE)
# the audit writer replaces oversized metadata with its marker, and drops nothing else
for row in STORE:
    row["debug_info"]["metadata"] = dict(MARKER)
del LOG[:]
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 0 and LOG == [], "a second sweep finds both rows by correlation id and writes nothing")
# rows written by 1.17.12 (metadata job_id, no correlation id) are still found
del STORE[:]
store_row("custom:module-replacement-switch-failed", "patching", None, {"job_id": "j-huge"})
store_row("custom:module-replacement-disabled", "patchmanagement", None, {"job_id": "j-ok2"})
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 0 and LOG == [], "1.17.12 rows are found by metadata job id")
# a broken lookup still writes nothing
del STORE[:]
audit_stub._auditlog_model = lambda: (_ for _ in ()).throw(RuntimeError("audit table unreadable"))
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 0 and LOG == [], "a broken lookup writes nothing")
audit_stub._auditlog_model = lambda: FakeAuditLog
# and a lookup that works but finds nothing writes once
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 2 and len(LOG) == 2, LOG)

print("[TEST] PASS module replacement audit 1.17.13")
