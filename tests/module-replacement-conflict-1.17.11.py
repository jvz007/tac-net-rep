#!/usr/bin/env python3
"""1.17.11 regression: state shows a replacement and the module it replaces both enabled (AD-20 amendment 2).

Core drops the replacement from what it loads (bootstrap), reports it as not enabled (module_status and the Modules catalog),
and queues one disable job per pair from the scheduler tick, audited, at most once an hour, never raising and never stopping
Tactical. The real bootstrap.py, module_runtime.py, module_replacement.py, module_manager_v2.py and the tick command run against
stubs for Django, the audit writer and the dispatch. The real dispatch and audit write need a server: see
tests/module-replacement-reconcile-runtime-1.17.11.py.
"""
from __future__ import annotations

import json
import logging
import sys
import tempfile
import types
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

logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())
TMP = Path(tempfile.mkdtemp(prefix="tectac-replacement-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for _folder in (EXT, REP, JOBS):
    _folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins


def manifest(module_id, root=EXT, **extra):
    folder = root / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension" if root is EXT else "reportset", "version": "1.0.0", "name": module_id}
    payload.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


def reset(**state):
    for folder in list(EXT.iterdir()) + list(REP.iterdir()):
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()
    for job in JOBS.iterdir():
        job.unlink()
    STATE["modules"] = {name: {"enabled": on} for name, on in state.items()}


PATCHING_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
PM_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.1.0", "patching.extra": "1.0.0"}


def world(*, patching_caps=PATCHING_CAPS, pm_caps=PM_CAPS, patching=False, pm=True, **more):
    reset(patching=patching, patchmanagement=pm, **more)
    core = {"category": "core"}
    if patching_caps is not None:
        core["capabilities"] = patching_caps
    manifest("patching", **core)
    manifest("patchmanagement", replaces="patching", capabilities=pm_caps)


def candidate(module_id, version="1.0.0", **extra):
    item = {"id": module_id, "extension_version": version, "dependencies": {}, "optional_dependencies": {}, "requires": {},
            "runtime_requirements": [], "category": "", "replaces": None, "capabilities": None, "migration": {}}
    item.update(extra)
    return item


def rows():
    return {row["id"]: row for row in v2.installed_catalog_v2()}


import importlib.util
import io
from datetime import datetime, timedelta, timezone

# Linux-only chmod/chown in the atomic writer: a plain write is enough for a job file here.
module_manager._atomic_json = v2._atomic_json = lambda path, payload: path.write_text(json.dumps(payload), encoding="utf-8")
logging.getLogger("tec_tac.module_runtime").addHandler(logging.NullHandler())
records = []


class Catch(logging.Handler):
    def emit(self, record):
        records.append((record.name, record.levelno, record.getMessage()))


for _name in ("tec_tac.module_replacement", "tec_tac.bootstrap"):
    logging.getLogger(_name).addHandler(Catch())

# ------------------------------------------------------------------------------------------ detection
world(patching=True, pm=True)
must(mr.conflicted_replacements(mr.live_model()) == [("patchmanagement", "patching")], "both enabled")
for flags in ({"patching": True, "pm": False}, {"patching": False, "pm": True}, {"patching": False, "pm": False}):
    world(**flags)
    must(mr.conflicted_replacements(mr.live_model()) == [], flags)
world(patching=True, pm=True)
manifest("patching")  # not a core or server module: nothing to protect, no conflict
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS)
must(mr.conflicted_replacements(mr.live_model()) == [], "the replaced module is not core or server")
world(patching=True, pm=True)
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
must(mr.conflicted_replacements(mr.live_model()) == [("patchmanagement", "patching"), ("rival", "patching")], "every enabled replacement of the pair")

# ------------------------------------------------------------------------------------------ bootstrap: the replacement is dropped at load
django = types.ModuleType("django")
django_apps = types.ModuleType("django.apps")
django_registry = types.ModuleType("django.apps.registry")
LOADED = []


class Apps:
    def populate(self, installed_apps=None):
        LOADED.append(list(installed_apps or []))
        return "populated"


django_registry.Apps = Apps
django_apps.apps = Apps()
django.apps = django_apps
sys.modules.update({"django": django, "django.apps": django_apps, "django.apps.registry": django_registry})
ORIGINAL = Apps.populate
from tec_tac import bootstrap  # noqa: E402


def boot():
    """Run load_extensions() on a fresh Apps.populate and return the apps Django was asked to populate."""
    Apps.populate = ORIGINAL
    LOADED.clear()
    bootstrap.load_extensions()
    result = django_apps.apps.populate(["tactical.apps"])
    must(result == "populated", result)
    return LOADED[0]


def with_apps(*, patching=True, pm=True):
    world(patching=patching, pm=pm)
    manifest("patching", category="core", capabilities=PATCHING_CAPS, django_apps=["patching.apps.PatchingConfig"])
    manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS, django_apps=["patchmanagement.apps.PmConfig"])


records.clear()
with_apps(patching=True, pm=True)
apps = boot()
must("patching.apps.PatchingConfig" in apps and "patchmanagement.apps.PmConfig" not in apps, apps)  # the replaced module loads, the replacement is dropped
must("tec_tac.apps.TecTacFrameworkConfig" in apps, "Core still loads")
warned = [text for name, level, text in records if name == "tec_tac.bootstrap" and level == logging.WARNING]
must(len(warned) == 1 and "patchmanagement" in warned[0] and "both are enabled" in warned[0], records)  # one warning per pair
must(json.dumps(STATE, sort_keys=True) == json.dumps({"schema": 1, "modules": {"patching": {"enabled": True}, "patchmanagement": {"enabled": True}}}, sort_keys=True), "state untouched")
# no conflict: both load as the state says
for flags, expect in (({"patching": False, "pm": True}, {"patchmanagement.apps.PmConfig"}), ({"patching": True, "pm": False}, {"patching.apps.PatchingConfig"}),
                      ({"patching": False, "pm": False}, set())):
    with_apps(**flags)
    got = {app for app in boot() if app.startswith(("patching.", "patchmanagement."))}
    must(got == expect, (flags, got))
# a corrupt state file or an unreadable registry never stops Tactical
with_apps(patching=True, pm=True)
STATE["_corrupt"] = True
must(boot() == ["tactical.apps", "tec_tac.apps.TecTacFrameworkConfig"], "corrupt state: Core only, no exception")
del STATE["_corrupt"]
real_load_state = module_state.load_state


def broken_state():
    raise module_state.ModuleStateError("unreadable")


module_state.load_state = broken_state
must(boot() == ["tactical.apps", "tec_tac.apps.TecTacFrameworkConfig"], "unreadable state: Core only, no exception")
module_state.load_state = real_load_state
real_conflicted = mr.conflicted_replacements
mr.conflicted_replacements = lambda model: (_ for _ in ()).throw(RuntimeError("boom"))
apps = boot()
must("patching.apps.PatchingConfig" in apps and "patchmanagement.apps.PmConfig" in apps, "a failing check loads every enabled module as before")
must(any("could not check" in text for _, _, text in records), "and says so in the log")
mr.conflicted_replacements = real_conflicted

# ------------------------------------------------------------------------------------------ snapshot: the effective state
from tec_tac import module_runtime  # noqa: E402

module_runtime.load_state = lambda: STATE
with_apps(patching=True, pm=True)
snap = {row["id"]: row for row in module_runtime.module_runtime_snapshot(registry.get_plugins())}
must(snap["patchmanagement"]["enabled"] is False and snap["patchmanagement"]["active"] is False, snap["patchmanagement"])
must(snap["patching"]["enabled"] is True and snap["patching"]["active"] is True, snap["patching"])
must(snap["patchmanagement"]["replaces"] == "patching" and snap["patching"]["replaces"] is None, "declared replaces")
with_apps(patching=False, pm=True)
snap = {row["id"]: row for row in module_runtime.module_runtime_snapshot(registry.get_plugins())}
must(snap["patchmanagement"]["enabled"] is True and snap["patching"]["enabled"] is False, "no conflict: the stored state")
# the Modules catalog reports the conflict on the replacement object
with_apps(patching=True, pm=True)
must(rows()["patchmanagement"]["replacement"]["conflict"] is True and rows()["patchmanagement"]["replacement"]["honoured"] is False, rows()["patchmanagement"]["replacement"])
must(rows()["patchmanagement"]["replacement"]["reason"] == "target-enabled" and "disables the replacement" in rows()["patchmanagement"]["replacement"]["message"], "wording")
must(all("disables neither" not in text for _, _, text in records), "the 1.17.9 wording is gone")
mr._WARNED.clear()
records.clear()
mr.honoured_replacement("patchmanagement")
text = " ".join(t for _, _, t in records)
must("queues a job that disables patchmanagement and keeps patching" in text and "disables neither" not in text, text)

# ------------------------------------------------------------------------------------------ reconcile
audit_rows = []
audit_stub = types.ModuleType("tec_tac.audit")
audit_stub.service_audit_actor = lambda **kw: ("service-actor", kw)
audit_stub.record = lambda **kw: audit_rows.append(kw) or {"recorded": True}
sys.modules["tec_tac.audit"] = audit_stub
import tec_tac  # noqa: E402

tec_tac.audit = audit_stub
dispatched = []


def dispatch_ok(job_id):
    dispatched.append(job_id)


v2._dispatch_v2 = dispatch_ok


def job_files():
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(JOBS.glob("*.json"))]


with_apps(patching=True, pm=True)
rows_ = mr.reconcile_conflicts()
must(len(rows_) == 1 and rows_[0]["queued"] is True and rows_[0]["replacement"] == "patchmanagement" and rows_[0]["replaced"] == "patching", rows_)
jobs = job_files()
must(len(jobs) == 1 and dispatched == [jobs[0]["id"]], (jobs, dispatched))
job = jobs[0]
must(job["action"] == "disable" and job["plugin_id"] == "patchmanagement" and job["affected_modules"] == ["patchmanagement"], job)
must(job["requested_by"] == "system" and job["reason"] == "replacement_conflict" and job["cascade"] is False and job["status"] == "queued", job)
must(len(audit_rows) == 1, audit_rows)
row = audit_rows[0]
must(row["module_id"] == "core" and row["action"] == "custom:module-replacement-conflict-resolved" and row["strict"] is False, row)
must(row["metadata"] == {"replacement": "patchmanagement", "replaced": "patching", "job_id": job["id"]} and row["actor"][0] == "service-actor", row)
must(row["actor"][1]["module_id"] == "core" and row["object_id"] == "patchmanagement" and row["object_type"] == "module", row)
import re  # noqa: E402

must(re.fullmatch(r"custom:[a-z0-9][a-z0-9_-]{0,63}", row["action"]), "the action matches the audit vocabulary")
must(any("Queued job" in text for _, _, text in records), "a warning is logged")
# the queued job already counts: the next tick queues nothing
must(mr.reconcile_conflicts() == [] and len(job_files()) == 1, "a pending disable job is skipped")
# the job ran but the state is still both enabled: at most one job per pair per hour
path = next(JOBS.glob("*.json"))
body = json.loads(path.read_text(encoding="utf-8"))
body["status"] = "failed"
path.write_text(json.dumps(body), encoding="utf-8")
must(mr.reconcile_conflicts() == [] and len(job_files()) == 1, "the hourly limit holds after a failed job")
# an hour later it tries again
body["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
path.write_text(json.dumps(body), encoding="utf-8")
again = mr.reconcile_conflicts()
must(len(again) == 1 and again[0]["queued"] and len(job_files()) == 2, again)
# state resolved: nothing to do
world(patching=True, pm=False)
must(mr.reconcile_conflicts() == [], "no conflict")
# a plain user job for the same module is not a reconcile job and does not use the hourly allowance
with_apps(patching=True, pm=True)
for old in JOBS.glob("*.json"):
    old.unlink()
(JOBS / "u.json").write_text(json.dumps({"id": "u", "action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "status": "failed", "created_at": datetime.now(timezone.utc).isoformat(), "requested_by": "alice"}), encoding="utf-8")
must(len(mr.reconcile_conflicts()) == 1, "a user's failed job does not stop the reconcile")

# a failing dispatch is logged, never raised, the job is recorded as failed, and the hourly limit still holds
for old in JOBS.glob("*.json"):
    old.unlink()
audit_rows.clear()
records.clear()


def dispatch_fails(job_id):
    raise v2.ModuleManagerV2Error("sudo is not allowed")


v2._dispatch_v2 = dispatch_fails
failed = mr.reconcile_conflicts()
must(len(failed) == 1 and failed[0]["queued"] is False and "sudo is not allowed" in failed[0]["error"], failed)
must(job_files()[0]["status"] == "dispatch_failed" and audit_rows == [], "the job records the failure and nothing is audited as resolved")
must(any("Could not queue" in text for _, _, text in records), records)
must(mr.reconcile_conflicts() == [] and len(job_files()) == 1, "a failing dispatch cannot loop every minute")
# a broken model never raises
v2._dispatch_v2 = dispatch_ok
real_live = mr.live_model
mr.live_model = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no registry"))
must(mr.reconcile_conflicts() == [], "an unreadable model is logged, not raised")
mr.live_model = real_live
# a failing audit write does not undo the queued job
for old in JOBS.glob("*.json"):
    old.unlink()
audit_stub.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit down"))
done = mr.reconcile_conflicts()
must(len(done) == 1 and done[0]["queued"] is True and len(job_files()) == 1, done)
audit_stub.record = lambda **kw: audit_rows.append(kw) or {"recorded": True}

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
out, err = run_tick()
must(out.startswith("TEC-TAC scheduler tick: checked=3 queued=1 skipped=0 cleaned=0 session_history_cleanup=not_due session_expiry_sweep=ran"), out)
must(" now=NOW replacement_conflicts_queued=1" in out and err == "", (out, err))  # the old fields keep their order; the new one is appended
out, err = run_tick()
must("replacement_conflicts_queued=0" in out, "the next tick queues nothing")
mr.reconcile_conflicts = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
out, err = run_tick()
must("replacement_conflicts_queued=0" in out and "replacement conflict check failed" in err and "checked=3" in out, (out, err))  # the tick carries on

print("[TEST] PASS module replacement conflict 1.17.11")
