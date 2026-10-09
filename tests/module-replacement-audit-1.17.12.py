#!/usr/bin/env python3
"""1.17.12 regression: audit follows what actually happened (the two findings held from the 1.17.11 review).

* The queue-time row is a request, ``custom:module-replacement-switch-queued``, and claims no change. The old name
  ``custom:module-replacement-disabled`` is written only when the job has finished and its job file says the module was disabled.
* ``module_replacement.audit_finished_jobs()`` (called from the scheduler tick) writes one outcome row per module the job changed:
  disabled_modules, enabled_modules (hand-back) and reconciled_modules (the helper-side reconcile, the held Medium), and a
  ``switch-failed`` row for a failed job that had a planned list. Bounded to 7 days and 200 jobs a tick, idempotent, never raises.

Runs the real module_replacement.py and module_manager_v2.py with the audit writer stubbed (an in-memory log, with the same
action/object/job_id lookup the real AuditLog query does). The real AuditLog JSON lookup needs a server: see
tests/module-replacement-handback-runtime-1.17.12.py.
"""
from __future__ import annotations

import io
import importlib.util
import json
import logging
import re
import sys
import tempfile
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

from tec_tac import module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry  # noqa: E402

records = []


class Capture(logging.Handler):
    def emit(self, record):
        records.append((record.levelname, record.getMessage()))


_logger = logging.getLogger("tec_tac.module_replacement")
_logger.addHandler(Capture())
_logger.propagate = False
TMP = Path(tempfile.mkdtemp(prefix="tectac-audit-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for _folder in (EXT, REP, JOBS):
    _folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins

# ------------------------------------------------------------------------------------------ an in-memory audit log
LOG = []
audit_stub = types.ModuleType("tec_tac.audit")
audit_stub.service_audit_actor = lambda **kw: ("service-actor", kw)


def fake_record(**kw):
    if audit_stub.fail:
        raise RuntimeError("audit down")
    LOG.append(kw)
    return {"recorded": True}


audit_stub.record = fake_record
audit_stub.fail = False
sys.modules["tec_tac.audit"] = audit_stub
import tec_tac  # noqa: E402

tec_tac.audit = audit_stub
LOOKUP = {"fail": False, "calls": 0}


def fake_lookup(action, object_id, job_id):
    """The same question the real AuditLog JSON query asks: is there a row with this action, object and metadata job_id."""
    LOOKUP["calls"] += 1
    if LOOKUP["fail"]:
        raise RuntimeError("the audit table cannot be read")
    return any(row["action"] == action and str(row["object_id"]) == object_id and row["metadata"].get("job_id") == job_id for row in LOG)


mr._audit_already_written = fake_lookup


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", "name": module_id, **extra}), encoding="utf-8")


def world(*, patching=False, pm=True):
    for folder in list(EXT.iterdir()):
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()
    for job in JOBS.iterdir():
        job.unlink()
    STATE["modules"] = {"patching": {"enabled": patching}, "patchmanagement": {"enabled": pm}}
    manifest("patching", category="core", capabilities={"patching.windows": "1.2.0"})
    manifest("patchmanagement", replaces="patching", capabilities={"patching.windows": "1.2.0"})


def actions():
    return [row["action"] for row in LOG]


NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def finished(minutes_ago=5, **job):
    return {"id": job.pop("id", "job-x"), "status": "succeeded", "requested_by": "alice", "finished_at": (NOW - timedelta(minutes=minutes_ago)).isoformat(), **job}


# ------------------------------------------------------------------------------------------ queue time: a request, not a change
captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}
actor = types.SimpleNamespace(username="alice")
world(patching=False, pm=True)
v2.queue_set_enabled("patching", True, requested_by="alice", disable_replaced=["patchmanagement"], actor=actor, confirm_replacement_switch=True)
must(len(LOG) == 1, LOG)
row = LOG[0]
must(row["action"] == "custom:module-replacement-switch-queued" and row["actor"] is actor and row["module_id"] == "core" and row["strict"] is False, row)
must(row["object_type"] == "module" and row["object_id"] == "patching", row)
must(row["message"] == "Module patching was asked to switch: job job-1 will disable patchmanagement.", row["message"])
must(row["metadata"] == {"job_id": "job-1", "disable": ["patchmanagement"], "enable": []}, row["metadata"])
must("custom:module-replacement-disabled" not in actions(), "no row claims a change before it happens")
must(re.fullmatch(r"custom:[a-z0-9][a-z0-9_-]{0,63}", row["action"]), "the action matches the audit vocabulary")
LOG.clear()
v2.queue_set_enabled("patchmanagement", False, requested_by="alice", actor=actor)  # the hand-back direction
must(len(LOG) == 1 and LOG[0]["metadata"] == {"job_id": "job-2", "disable": [], "enable": ["patching"]}, LOG)
must(LOG[0]["message"] == "Module patchmanagement was asked to switch: job job-2 will enable patching.", LOG[0]["message"])
LOG.clear()
mr.audit_switch_queued(actor, "x", "job-3", disabled=["b", "a"], enabled=["c"])
must(LOG[0]["message"] == "Module x was asked to switch: job job-3 will disable a, b and enable c.", LOG[0]["message"])
LOG.clear()
mr.audit_switch_queued(actor, "x", "job-4")  # nothing to switch: nothing to say
must(LOG == [], LOG)
# a job that plans nothing writes no row (a plain disable, a plain enable)
manifest("bystander")
STATE["modules"]["bystander"] = {"enabled": True}
v2.queue_set_enabled("bystander", False, actor=actor)
must(LOG == [], LOG)
# the install paths write the same request row, one per action that disables something
plan = {"actions": [{"id": "patchmanagement", "will_disable": ["patching"]}, {"id": "other", "will_disable": []}]}
v2._audit_plan_disables(actor, plan, {"id": "job-9"})
must(len(LOG) == 1 and LOG[0]["action"] == "custom:module-replacement-switch-queued" and LOG[0]["object_id"] == "patchmanagement", LOG)
must(LOG[0]["metadata"]["job_id"] == "job-9" and LOG[0]["metadata"]["disable"] == ["patching"], LOG[0])
LOG.clear()
# a failing audit write never fails the queue
audit_stub.fail = True
v2.queue_set_enabled("patchmanagement", False, actor=actor)
audit_stub.fail = False
must(LOG == [], "the row was lost, the job was still queued")

# ------------------------------------------------------------------------------------------ outcome rows: succeeded jobs
world(patching=True, pm=False)
reconciled_job = finished(id="j-rec", action="enable", plugin_id="bystander", disabled_modules=[], reconciled_modules=["patchmanagement"])
must(mr.audit_finished_jobs(now=NOW, jobs=[reconciled_job]) == 1, LOG)
must(len(LOG) == 1, LOG)
row = LOG[0]
must(row["action"] == "custom:module-replacement-conflict-resolved" and row["object_id"] == "patchmanagement" and row["module_id"] == "core" and row["strict"] is False, row)
must(row["actor"][0] == "service-actor" and row["actor"][1]["module_id"] == "core", "the actor is the system service")
must(row["metadata"] == {"job_id": "j-rec", "requested_by": "alice", "replacement": "patchmanagement", "replaced": "patching"}, row["metadata"])
must("patchmanagement" in row["message"] and "disabled" in row["message"], row["message"])
# a second sweep never duplicates it
must(mr.audit_finished_jobs(now=NOW, jobs=[reconciled_job]) == 0 and len(LOG) == 1, "idempotent")
# the replaced module's id is read from the manifests; unknown stays empty
LOG.clear()
mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-rec2", action="enable", plugin_id="b", reconciled_modules=["nosuch"])])
must(LOG[0]["metadata"]["replaced"] == "", LOG)
LOG.clear()

# the reconcile job itself already has its queue-time row; the outcome sweep adds none for it
sys_job = finished(id="j-sys", action="disable", plugin_id="patchmanagement", reason="replacement_conflict", requested_by="system", reconciled_modules=["patchmanagement"])
must(mr.audit_finished_jobs(now=NOW, jobs=[sys_job]) == 0 and LOG == [], "the reconcile path keeps its single queue-time row")
# an enable job whose queue-time conflict row already exists is not duplicated either
LOG.append({"action": "custom:module-replacement-conflict-resolved", "object_id": "patchmanagement", "metadata": {"job_id": "j-q"}})
must(mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-q", action="enable", plugin_id="bystander", reconciled_modules=["patchmanagement"])]) == 0 and len(LOG) == 1, LOG)
LOG.clear()

# disabled and enabled modules: one row per module
both = finished(id="j-two", action="batch_install", plugin_id="batch", disabled_modules=["patching", "backups"], enabled_modules=["x"],
                plan={"actions": [{"id": "patchmanagement", "will_disable": ["patching"]}, {"id": "altbackups", "will_disable": ["backups"]}]})
must(mr.audit_finished_jobs(now=NOW, jobs=[both]) == 3 and len(LOG) == 3, LOG)
by = {(row["action"], row["object_id"]): row for row in LOG}
must(set(by) == {("custom:module-replacement-disabled", "patching"), ("custom:module-replacement-disabled", "backups"), ("custom:module-replacement-enabled", "x")}, sorted(by))
must(by[("custom:module-replacement-disabled", "patching")]["message"] == "Module patching was disabled because replacement patchmanagement was enabled.", by)
must(by[("custom:module-replacement-disabled", "backups")]["metadata"] == {"job_id": "j-two", "requested_by": "alice", "replacement": "altbackups", "replaced": "backups"}, by)
must(by[("custom:module-replacement-enabled", "x")]["metadata"]["job_id"] == "j-two", by)
LOG.clear()
# the enable direction of the hand-back: the replacement was switched off because the replaced module was enabled again
switch = finished(id="j-sw", action="enable", plugin_id="patching", disabled_modules=["patchmanagement"], replacement_confirmed=True)
mr.audit_finished_jobs(now=NOW, jobs=[switch])
must(len(LOG) == 1 and LOG[0]["object_id"] == "patchmanagement" and LOG[0]["action"] == "custom:module-replacement-disabled", LOG)
must(LOG[0]["message"] == "Replacement patchmanagement was disabled because the module it replaces, patching, was enabled again.", LOG[0]["message"])
must(LOG[0]["metadata"]["replacement"] == "patchmanagement" and LOG[0]["metadata"]["replaced"] == "patching", LOG[0]["metadata"])
LOG.clear()
# the hand-back direction of a disable job
back = finished(id="j-bk", action="disable", plugin_id="patchmanagement", enabled_modules=["patching"])
mr.audit_finished_jobs(now=NOW, jobs=[back])
must(len(LOG) == 1 and LOG[0]["action"] == "custom:module-replacement-enabled" and LOG[0]["object_id"] == "patching", LOG)
must(LOG[0]["message"] == "Module patching was enabled again because its replacement patchmanagement was disabled.", LOG[0]["message"])
must(LOG[0]["metadata"] == {"job_id": "j-bk", "requested_by": "alice", "replacement": "patchmanagement", "replaced": "patching"}, LOG[0]["metadata"])
LOG.clear()
# a plain job writes nothing
mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-plain", action="enable", plugin_id="bystander", disabled_modules=[], reconciled_modules=[])])
must(LOG == [], "nothing was switched")

# ------------------------------------------------------------------------------------------ outcome rows: failed jobs
failed = finished(id="j-f1", status="failed", action="enable", plugin_id="patching", disable_modules=["patchmanagement"], replacement_confirmed=True,
                  stage="rollback", error="Tactical graceful reload failed with status 1", disabled_modules=["patchmanagement"])
must(mr.audit_finished_jobs(now=NOW, jobs=[failed]) == 1, LOG)
row = LOG[0]
must(row["action"] == "custom:module-replacement-switch-failed" and row["object_id"] == "patching", row)
must("graceful reload" in row["message"] and "rollback" in row["message"] and "put back" in row["message"] and "patchmanagement" in row["message"], row["message"])
must(row["metadata"]["stage"] == "rollback" and row["metadata"]["job_id"] == "j-f1" and "graceful reload" in row["metadata"]["error"], row["metadata"])
must("custom:module-replacement-disabled" not in actions(), "a failed job never claims a disable")
LOG.clear()
failed_early = finished(id="j-f2", status="failed", action="disable", plugin_id="patchmanagement", enable_modules=["patching"], stage="lifecycle",
                        error="module replacement rule refuses enabling patching as a hand-back: it is enabled already")
mr.audit_finished_jobs(now=NOW, jobs=[failed_early])
must(len(LOG) == 1 and "Nothing was changed" in LOG[0]["message"] and "stage lifecycle" in LOG[0]["message"], LOG)
LOG.clear()
# a failed job with no planned list is not a switch: no row (the rule is "planned list")
mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-f3", status="failed", action="enable", plugin_id="bystander", disable_modules=[], error="boom")])
must(LOG == [], LOG)
# a failure with no error recorded still says so
mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-f4", status="failed", action="disable", plugin_id="p", enable_modules=["q"], error=None, stage=None)])
must(len(LOG) == 1 and "no error was recorded" in LOG[0]["message"] and "stage unknown" in LOG[0]["message"], LOG)
LOG.clear()

# ------------------------------------------------------------------------------------------ window, status, already audited
jobs = [
    finished(id="j-old", minutes_ago=8 * 24 * 60, action="disable", plugin_id="p", enabled_modules=["q"]),       # older than 7 days
    finished(id="j-edge", minutes_ago=7 * 24 * 60 - 1, action="disable", plugin_id="p", enabled_modules=["e"]),  # inside the window
    finished(id="j-run", status="running", action="disable", plugin_id="p", enabled_modules=["r"]),
    finished(id="j-queued", status="queued", action="disable", plugin_id="p", enabled_modules=["r"]),
    finished(id="j-dispatch", status="dispatch_failed", action="disable", plugin_id="p", enable_modules=["r"]),
    {"id": "j-nodate", "status": "succeeded", "action": "disable", "plugin_id": "p", "enabled_modules": ["n"]},
    finished(id="j-baddate", action="disable", plugin_id="p", enabled_modules=["b"]) | {"finished_at": "not a date"},
    finished(id="j-ok", action="disable", plugin_id="p", enabled_modules=["ok"]),
]
must(mr.audit_finished_jobs(now=NOW, jobs=jobs) == 2, LOG)
must(sorted(row["object_id"] for row in LOG) == ["e", "ok"], LOG)
# a naive timestamp (the job writer's own format) is read as UTC
LOG.clear()
naive = finished(id="j-naive", action="disable", plugin_id="p", enabled_modules=["nv"]) | {"finished_at": (NOW - timedelta(minutes=1)).replace(tzinfo=None).isoformat()}
must(mr.audit_finished_jobs(now=NOW, jobs=[naive]) == 1, LOG)
# a row that is already in the audit log is skipped, the others are still written
LOG.clear()
LOG.append({"action": "custom:module-replacement-enabled", "object_id": "a1", "metadata": {"job_id": "j-pre"}})
pre = finished(id="j-pre", action="disable", plugin_id="p", enabled_modules=["a1", "a2"])
must(mr.audit_finished_jobs(now=NOW, jobs=[pre]) == 1 and sorted(row["object_id"] for row in LOG) == ["a1", "a2"], LOG)
# at most 200 jobs a tick, newest first
LOG.clear()
many = [finished(id=f"m{i}", minutes_ago=i + 1, action="disable", plugin_id="p", enabled_modules=[f"mod{i}"]) for i in range(205)]
must(mr.audit_finished_jobs(now=NOW, jobs=many) == 200 and len(LOG) == 200, len(LOG))
must("mod0" in {row["object_id"] for row in LOG} and "mod204" not in {row["object_id"] for row in LOG}, "the newest 200")
LOG.clear()

# ------------------------------------------------------------------------------------------ the real job files
for old in JOBS.glob("*.json"):
    old.unlink()
fin = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
(JOBS / "a.json").write_text(json.dumps({"id": "a", "status": "succeeded", "action": "disable", "plugin_id": "patchmanagement", "enabled_modules": ["patching"],
                                          "requested_by": "alice", "finished_at": fin}), encoding="utf-8")
(JOBS / "broken.json").write_text("{not json", encoding="utf-8")
(JOBS / "list.json").write_text("[1, 2]", encoding="utf-8")
must(mr.audit_finished_jobs() == 1 and LOG[0]["metadata"]["job_id"] == "a", LOG)  # reads the job files itself, skipping the bad ones
must(mr.audit_finished_jobs() == 0 and len(LOG) == 1, "the next tick adds nothing")

# ------------------------------------------------------------------------------------------ never raises
LOG.clear()
records.clear()
bad_jobs = [
    None, 7, "text", [],
    {"id": "b1", "status": "succeeded", "finished_at": NOW.isoformat(), "disabled_modules": "not a list", "enabled_modules": [1, None, ""], "reconciled_modules": {"a": 1}},
    {"id": "b2", "status": "failed", "finished_at": NOW.isoformat(), "disable_modules": "x", "enable_modules": 5},
    finished(id="b3", action="disable", plugin_id=None, enabled_modules=["good"], plan="not a dict"),
]
must(mr.audit_finished_jobs(now=NOW, jobs=bad_jobs) == 1 and LOG[0]["object_id"] == "good", LOG)  # the bad ones are skipped, the good one is written
LOG.clear()
audit_stub.fail = True  # the audit writer is down
must(mr.audit_finished_jobs(now=NOW, jobs=[back]) == 0, "an audit failure is not a row")
must(any("Could not write" in text for _, text in records), records)
audit_stub.fail = False
must(mr.audit_finished_jobs(now=NOW, jobs=[back]) == 1, "and the next tick tries again, because nothing was recorded")
LOG.clear()
records.clear()
LOOKUP["fail"] = True  # the AuditLog lookup fails: nothing is written, so a broken lookup can never duplicate a row every tick
must(mr.audit_finished_jobs(now=NOW, jobs=[back, switch]) == 0 and LOG == [], LOG)
must(sum("Could not look up" in text for _, text in records) == 2, records)
LOOKUP["fail"] = False
# a generator that dies half way, and an unreadable model, are swallowed


def dying():
    yield back
    raise RuntimeError("disk gone")


must(mr.audit_finished_jobs(now=NOW, jobs=dying()) == 0 and any("sweep failed" in text for _, text in records), records)
real_live = mr.live_model
mr.live_model = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no registry"))
LOG.clear()
must(mr.audit_finished_jobs(now=NOW, jobs=[finished(id="j-nm", action="enable", plugin_id="b", reconciled_modules=["z"])]) == 1 and LOG[0]["metadata"]["replaced"] == "", "an unreadable model leaves replaced empty")
mr.live_model = real_live

# ------------------------------------------------------------------------------------------ the scheduler tick
for _name, _attrs in {
    "django": {}, "django.core": {}, "django.core.management": {},
    "django.core.management.base": {"BaseCommand": type("BaseCommand", (), {})},
    "tec_tac.scheduler": {"dispatch_due_schedules": lambda: {"checked": 3, "queued": [1], "skipped": [], "cleaned": 0, "now": "NOW"}},
    "tec_tac.session_security": {"cleanup_session_history_if_due": lambda: {"ran": False}, "sweep_expired_sessions": lambda: {"revoked": 0}},
}.items():
    module = sys.modules.get(_name) or types.ModuleType(_name)
    module.__dict__.update(_attrs)
    sys.modules[_name] = module
spec = importlib.util.spec_from_file_location("tick", ROOT / "framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py")
tick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tick)


def run_tick():
    command = tick.Command()
    command.stdout, command.stderr = io.StringIO(), io.StringIO()
    command.handle()
    return command.stdout.getvalue(), command.stderr.getvalue()


for old in JOBS.glob("*.json"):
    old.unlink()
LOG.clear()
(JOBS / "a.json").write_text(json.dumps({"id": "a", "status": "succeeded", "action": "disable", "plugin_id": "patchmanagement", "enabled_modules": ["patching"],
                                          "requested_by": "alice", "finished_at": fin}), encoding="utf-8")
out, err = run_tick()
must(" replacement_conflicts_queued=0 replacement_audit_rows=1" in out and err == "" and len(LOG) == 1, (out, err))  # the old fields keep their order; the new one is appended
out, err = run_tick()
must("replacement_audit_rows=0" in out and len(LOG) == 1, "the second tick writes nothing")
mr.audit_finished_jobs = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
out, err = run_tick()
must("replacement_audit_rows=0" in out and "replacement audit sweep failed" in err and "checked=3" in out, (out, err))  # the tick carries on

print("[TEST] PASS module replacement audit 1.17.12")
