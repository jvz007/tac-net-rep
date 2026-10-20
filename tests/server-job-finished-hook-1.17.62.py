#!/usr/bin/env python3
"""1.17.62 regression (R-22 part 2): Core hands a finished server-maintenance job to the module that owns it, once, with no page open.

The real server_job_hooks.py, event_jobs.py (its publish_for_core path), event_jobs_policy.py, server_maintenance.py (job files in a temporary
folder) and scheduler_completion.py (the payload helper) run against stubs: Django, the registry, the module state, audit and the row
store. The hook's own table is replaced by an in-memory stand-in that keeps the same rules (unique claim, a retry row is taken once); the
real table is proved on the dev server by tests/server-job-finished-runtime-1.17.62.py, and the model and migration by
tests/server-job-hook-migration-0035-1.17.62.py.

Covered: a job that finishes with no page open reaches the module's event job exactly once, with the payload job id, action id, status,
exit code and failure classification and nothing else; a second tick sends nothing; a disabled, removed or not-honoured module is skipped
with one audit row and never retried; a module that registered no hook, and a job with no owner, are ignored; another module's job id is
never delivered to this module's job and the internal publish path refuses a job of another module and a caller outside Core's hooks;
the payload carries no output text and no parameter; a store failure is retried on the next ticks, three tries in all, then abandoned with
one audit row; a claim left claiming is abandoned and never sent again; an old job file is not looked at; a running job waits; at most 50
files are read a tick; a hand-damaged job file and a state Core cannot read never raise; the tick wraps the step and its output line is
unchanged.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
import tempfile
import time
import types
import uuid
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
MARKER = "SECRET-MARKER-62a1"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-serverjobhook-"))
EXT = TMP / "extensions"
JOBS_ROOT = TMP / "state" / "jobs"
EXT.mkdir()
JOBS_ROOT.mkdir(parents=True)
PLUGINS: dict = {}
ENABLED: dict = {}
HONOURED: dict = {}
STATE = {"registry_error": False, "state_error": False}
AUDITS: list = []
MONO = [1000.0]


def plugin(plugin_id, *, enabled=True, replaces=""):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=False, replaces=replaces)
    ENABLED[plugin_id] = enabled
    return root


def discover_plugins():
    if STATE["registry_error"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def load_state():
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return {"schema": 1, "modules": {}}


def is_enabled(module_id, state=None):
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return ENABLED.get(module_id, True)


CONNECTION = SimpleNamespace(in_atomic_block=False, vendor="sqlite")
mod("django")
mod("django.db", IntegrityError=type("IntegrityError", (Exception,), {}), connection=CONNECTION, transaction=SimpleNamespace(atomic=lambda: None, on_commit=lambda fn: fn()))
mod("django.utils")
mod("django.utils.timezone", now=lambda: datetime(2026, 10, 20, 12, 0, tzinfo=dt_timezone.utc))
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.registry", discover_plugins=discover_plugins)
mod("tec_tac.module_state", load_state=load_state, is_enabled=is_enabled)
mod("tec_tac.module_replacement", honoured_replacement=lambda module_id: HONOURED.get(module_id))
mod("tec_tac.capabilities", register_capability=lambda **kw: SimpleNamespace(**kw),
    build_operation_context=lambda **kw: {k: v for k, v in kw.items()})
mod("tec_tac.config", load_layout=lambda: {"TEC_TAC_SERVER_MAINTENANCE_ROOT": str(TMP / "state")})
mod("tec_tac.safe_files", atomic_json=lambda *a, **k: None)
mod("tec_tac.models", TecTacScheduleRun=SimpleNamespace(Status=SimpleNamespace(RUNNING="running", SUCCEEDED="succeeded", FAILED="failed")))


class _Audit:
    @staticmethod
    def service_audit_actor(**kw):
        return SimpleNamespace(**kw)

    @staticmethod
    def record(**kw):
        AUDITS.append(kw)


mod("tec_tac.audit", record=_Audit.record, service_audit_actor=_Audit.service_audit_actor)
pkg.audit = sys.modules["tec_tac.audit"]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    setattr(pkg, name.split(".")[-1], m)
    return m


ci = load("tec_tac.caller_identity", "caller_identity.py")
policy = load("tec_tac.event_jobs_policy", "event_jobs_policy.py")
ej = load("tec_tac.event_jobs", "event_jobs.py")
sm = load("tec_tac.server_maintenance", "server_maintenance.py")
completion = load("tec_tac.scheduler_completion", "scheduler_completion.py")
hooks = load("tec_tac.server_job_hooks", "server_job_hooks.py")
for clocked in (ej._RECENT, ej._RATE, ej._BREAKER, ej._GAUGES, ej._ENABLED):
    clocked.clock = lambda: MONO[0]
ej.time = SimpleNamespace(monotonic=lambda: MONO[0], time=time.time, sleep=time.sleep)

# ---- the event job store: what would be stored. Core's real publish_for_core runs; only the row write is replaced.
STORED: list = []
STORE_RESULT = {"value": "queued"}
ej._persist_safely = lambda definition, key, payload: (STORED.append((definition.id, key, payload)) if STORE_RESULT["value"] == "queued" else None) or STORE_RESULT["value"]

# ---- the hook table: an in-memory stand-in with the same rules as the real table
NOW = [datetime(2026, 10, 20, 12, 0, tzinfo=dt_timezone.utc)]
HOOKS: dict = {}  # job id -> {state, attempts, reason, module_id, updated}
hooks._now = lambda: NOW[0]


def _settled_ids(job_ids):
    return {j for j in job_ids if j in HOOKS and HOOKS[j]["state"] != "retry"}


def _claim(job_id, *, module_id, action_id, job_status):
    row = HOOKS.get(job_id)
    if row is None:
        HOOKS[job_id] = {"state": "claiming", "attempts": 1, "reason": "", "module_id": module_id, "updated": NOW[0]}
        return True
    if row["state"] != "retry":
        return False
    row.update(state="claiming", attempts=row["attempts"] + 1, updated=NOW[0])
    return True


def _set_state(job_id, state, *, reason="", module_id="", action_id="", job_status=""):
    row = HOOKS.setdefault(job_id, {"state": state, "attempts": 0, "reason": reason, "module_id": module_id, "updated": NOW[0]})
    row.update(state=state, reason=reason, updated=NOW[0])


def _expire_stale_claims(now):
    n = 0
    for row in HOOKS.values():
        if row["state"] == "claiming" and row["updated"] < now - hooks.CLAIM_STALE:
            row.update(state="abandoned", reason="claim_stale")
            n += 1
    return n


hooks._settled_ids, hooks._claim, hooks._set_state = _settled_ids, _claim, _set_state
hooks._attempts = lambda job_id: HOOKS.get(job_id, {}).get("attempts", 0)
hooks._expire_stale_claims = _expire_stale_claims
hooks._prune = lambda now: None


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


HANDLED = []
HOOK_SRC = "def on_finished(context):\n    HANDLED.append(context)\n"


def register(module_id, *, replaces=""):
    root = plugin(module_id, replaces=replaces)
    ns = {"HANDLED": HANDLED, "__name__": "probe"}
    exec(compile(HOOK_SRC, str(root / "hooks.py"), "exec"), ns)  # noqa: S102 - a handler whose code lies in the module's own folder
    return ej.register_event_job(id=hooks.hook_job_id(module_id), module_id=module_id, label="Record a finished server job", handler=ns["on_finished"])


def job_file(job_id, *, owner="certificatemanagement", status="succeeded", action="certificatemanagement.renew", exit_code=0, classification=None, age=0.0):
    record = {
        "schema": 1, "id": job_id, "action": action, "owner_module": owner, "status": status, "stage": "done",
        "created_at": "2026-10-20T11:00:00+00:00", "finished_at": "2026-10-20T11:30:00+00:00",
        "context": {"source_module": "certificatemanagement", "source_action": "renew", "requested_by": "alice", "source_run_id": None},
        "parameters": {"password": MARKER}, "public_parameters": {"password": "<redacted>"},
        "exit_result": {"success": status == "succeeded", "exit_code": exit_code, "signal": None, "timed_out": False},
        "failure": {"classification": classification, "message": f"failed with {MARKER}"} if classification else None,
    }
    path = JOBS_ROOT / f"{job_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    moment = NOW[0].timestamp() - age
    os.utime(path, (moment, moment))
    return record


def new_id():
    return str(uuid.uuid4())


def reset():
    ej._clear_for_tests()
    HOOKS.clear()
    del STORED[:], AUDITS[:], HANDLED[:]
    for path in JOBS_ROOT.glob("*"):
        path.unlink()
    STORE_RESULT["value"] = "queued"
    STATE.update(registry_error=False, state_error=False)
    PLUGINS.clear()
    ENABLED.clear()
    HONOURED.clear()
    CONNECTION.in_atomic_block = False
    NOW[0] = datetime(2026, 10, 20, 12, 0, tzinfo=dt_timezone.utc)
    MONO[0] += 1000


def tick():
    NOW[0] += timedelta(minutes=1)
    MONO[0] += 61
    return hooks.deliver_finished_server_jobs()


def hook_audits():
    return [a for a in AUDITS if a["action"] in (hooks.ACTION_SKIPPED, hooks.ACTION_ABANDONED)]


# ---- (1) a job finishes with no page open: the module's event job is stored once, with the right payload
reset()
register("certificatemanagement")
jid = new_id()
job_file(jid, status="failed", exit_code=3, classification="script_failed")
counts = tick()
must(counts["delivered"] == 1 and counts["errors"] == 0 and len(STORED) == 1, (counts, STORED))
event_id, key, payload = STORED[0]
must(event_id == "certificatemanagement.server_job_finished" and key == f"server-job:{jid}", (event_id, key))
must(payload == {"job_id": jid, "action_id": "certificatemanagement.renew", "status": "failed", "exit_code": 3, "classification": "script_failed"}, payload)
must(HOOKS[jid]["state"] == "queued", HOOKS)
definition = ej._JOBS[event_id]
definition.handler({"payload": payload})  # the worker runs the handler once for the stored row
must(len(HANDLED) == 1 and HANDLED[0]["payload"]["job_id"] == jid, HANDLED)
print("       a job that finishes with no page open is stored once for its module, and its handler runs once with the pinned payload")

# ---- (2) a second tick sends nothing; two ticks racing on the same job claim it once
counts = tick()
must(counts["checked"] == 0 and counts["delivered"] == 0 and len(STORED) == 1, (counts, STORED))
must(_claim(jid, module_id="certificatemanagement", action_id="x", job_status="failed") is False, "a handled job cannot be claimed again")
reset()
register("certificatemanagement")
jid = new_id()
job_file(jid)
must(_claim(jid, module_id="certificatemanagement", action_id="a", job_status="succeeded") is True, "another process claimed it first")
counts = tick()
must(counts["delivered"] == 0 and not STORED, "the tick that lost the claim stores nothing")
print("       a second tick sends nothing, and a tick that loses the claim race stores nothing")

# ---- (3) the payload: succeeded, no classification, and no output or parameter anywhere
reset()
register("certificatemanagement")
jid = new_id()
job_file(jid, status="succeeded", exit_code=0)
tick()
must(STORED[0][2] == {"job_id": jid, "action_id": "certificatemanagement.renew", "status": "succeeded", "exit_code": 0}, STORED[0][2])
must(MARKER not in repr(STORED) and MARKER not in repr(AUDITS), "no parameter and no job text reach the event or the audit trail")
reset()
register("certificatemanagement")
jid = new_id()
job_file(jid, status="failed", exit_code=1, classification="Not A Code; DROP")
tick()
must("classification" not in STORED[0][2], "a classification that is not a short code is dropped")
for status in ("cancelled", "dispatch_failed"):
    reset()
    register("certificatemanagement")
    jid = new_id()
    job_file(jid, status=status, exit_code=None, classification=status)
    tick()
    must(STORED and STORED[0][2]["status"] == status and STORED[0][2]["exit_code"] is None, (status, STORED))
print("       the payload is job id, action id, status, exit code and a short failure code; never output text, never parameters")

# ---- (4) a running job waits; a queued job waits
for status in ("queued", "running", "dispatched", "waiting_for_lock", "cancelling"):
    reset()
    register("certificatemanagement")
    job_file(new_id(), status=status)
    counts = tick()
    must(counts["waiting"] == 1 and not STORED and not HOOKS, (status, counts))
print("       a job that has not finished is left for a later tick, with no row")

# ---- (5) a disabled module: skipped, one audit row, not retried
reset()
register("certificatemanagement")
ENABLED["certificatemanagement"] = False
jid = new_id()
job_file(jid)
counts = tick()
must(counts["skipped"] == 1 and not STORED and HOOKS[jid]["state"] == "skipped" and HOOKS[jid]["reason"] == "module_unavailable", (counts, HOOKS))
rows = hook_audits()
must(len(rows) == 1 and rows[0]["action"] == hooks.ACTION_SKIPPED and rows[0]["object_type"] == "server_maintenance_job" and rows[0]["object_id"] == jid, AUDITS)
must(rows[0]["metadata"] == {"requested_by": "server-job-hook", "job_id": jid, "action_id": "certificatemanagement.renew",
                             "owner_module": "certificatemanagement", "reason": "module_unavailable"}, rows[0]["metadata"])
ENABLED["certificatemanagement"] = True
counts = tick()
must(counts["checked"] == 0 and not STORED and len(hook_audits()) == 1, "enabling the module later does not retry a skipped job, and no second audit row")
print("       a disabled module's job is skipped with one audit row and is not retried when the module comes back")

# ---- (6) disabled between Core's check and the store; replacement not honoured; module state unreadable
reset()
register("certificatemanagement")
real_status = ej.module_status_for_core
ENABLED["certificatemanagement"] = False
hooks._events().module_status_for_core = lambda module_id: ej.RUNNABLE  # Core's check said runnable; the store's own check does not
jid = new_id()
job_file(jid)
counts = tick()
hooks._events().module_status_for_core = real_status
must(counts["skipped"] == 1 and not STORED and HOOKS[jid]["state"] == "skipped" and len(hook_audits()) == 1, (counts, HOOKS))

reset()
register("patchmanagement", replaces="patching")
jid = new_id()
job_file(jid, owner="patchmanagement", action="patchmanagement.sync")
counts = tick()
must(counts["skipped"] == 1 and not STORED and HOOKS[jid]["reason"] == "not_honoured" and len(hook_audits()) == 1, (counts, HOOKS))
reset()
register("patchmanagement", replaces="patching")
HONOURED["patchmanagement"] = "patching"
job_file(new_id(), owner="patchmanagement", action="patchmanagement.sync")
counts = tick()
must(counts["delivered"] == 1 and len(STORED) == 1, "the honoured replacement gets its job")

reset()
register("certificatemanagement")
STATE["state_error"] = True
jid = new_id()
job_file(jid)
counts = tick()
must(counts["unreadable"] == 1 and not STORED and not HOOKS and counts["errors"] == 0, (counts, HOOKS))
STATE["state_error"] = False
counts = tick()
must(counts["delivered"] == 1 and len(STORED) == 1, "an unreadable module state leaves the job for the next tick, which delivers it")
reset()
register("certificatemanagement")
job_file(new_id())
STATE["registry_error"] = True  # the module list cannot be read: the job waits, nothing is sent
counts = hooks.deliver_finished_server_jobs()
STATE["registry_error"] = False
must(counts["errors"] == 0 and not STORED, counts)
print("       a module that is disabled in the meantime, a replacement that is not honoured and an unreadable state never send, never raise and never retry for ever")

# ---- (7) no hook, no owner, another module's job: ignored, and never delivered to another module's event job
reset()
register("certificatemanagement")
plugin("backups")
a, b, c = new_id(), new_id(), new_id()
job_file(a, owner="backups", action="backups.run")  # the owner registered no hook
job_file(b)
rec = json.loads((JOBS_ROOT / f"{b}.json").read_text(encoding="utf-8"))
rec.pop("owner_module")
(JOBS_ROOT / f"{b}.json").write_text(json.dumps(rec), encoding="utf-8")  # a job of 1.17.16 or earlier: no owner recorded
job_file(c, owner="../etc")  # a bad owner value
counts = tick()
must(counts["ignored"] == 3 and not STORED, (counts, STORED))
must({HOOKS[a]["state"], HOOKS[b]["state"], HOOKS[c]["state"]} == {"ignored"} and not hook_audits(), HOOKS)
must(HOOKS[a]["reason"] == "no_hook" and HOOKS[b]["reason"] == "no_owner" and HOOKS[c]["reason"] == "no_owner", HOOKS)
counts = tick()
must(counts["checked"] == 0, "an ignored job is not read again every tick")
reset()
register("certificatemanagement")
register("securitywaf")
d = new_id()
job_file(d, owner="securitywaf", action="securitywaf.rotate")
tick()
must([s[0] for s in STORED] == ["securitywaf.server_job_finished"], "a job reaches only its own module's event job")
print("       a module with no hook, a job with no owner and a bad owner value are ignored once; a job never reaches another module's event job")

# ---- (8) the internal publish path: another module's job, a foreign caller, an unregistered job
reset()
register("certificatemanagement")
plugin("backups")
direct = ej.publish_for_core("certificatemanagement.server_job_finished", module_id="certificatemanagement", key="server-job:x", payload={})
must(direct.outcome == "error" and direct.reason == "not Core's own caller" and not STORED, direct)
core = compile_as(str(APP / "server_job_hooks.py"), "def go(ej, **kw):\n    return ej.publish_for_core(**kw)\n")
other = compile_as(str(EXT / "backups" / "x.py"), "def go(ej, **kw):\n    return ej.publish_for_core(**kw)\n")
r = other["go"](ej, job_id="certificatemanagement.server_job_finished", module_id="certificatemanagement", key="server-job:x", payload={})
must(r.outcome == "error" and not STORED, "a module cannot use Core's publish path")
r = core["go"](ej, job_id="certificatemanagement.server_job_finished", module_id="backups", key="server-job:x", payload={})
must(r.outcome == "error" and r.reason == "not a registered event job of this module" and not STORED, "another module's job id is refused")
r = core["go"](ej, job_id="backups.server_job_finished", module_id="backups", key="server-job:x", payload={})
must(r.outcome == "error" and not STORED, "a job nobody registered is refused")
r = core["go"](ej, job_id="certificatemanagement.server_job_finished", module_id="certificatemanagement", key="bad key!", payload={})
must(r.outcome == "error" and not STORED, "a bad key is refused")
r = core["go"](ej, job_id="certificatemanagement.server_job_finished", module_id="certificatemanagement", key="server-job:x", payload={"text": "x" * 5000})
must(r.outcome == "error" and not STORED, "a payload over 2 KiB is refused")
r = core["go"](ej, job_id="certificatemanagement.server_job_finished", module_id="certificatemanagement", key="server-job:x", payload={"ok": 1})
must(r.outcome == "queued" and len(STORED) == 1, r)
print("       the internal publish path serves Core's hooks only, refuses another module's job and bad data, and stores a good one")

# ---- (9) a store failure is retried, three tries in all, then abandoned with one audit row
reset()
register("certificatemanagement")
STORE_RESULT["value"] = "error"
jid = new_id()
job_file(jid)
c1 = tick()
must(c1["retry"] == 1 and HOOKS[jid]["state"] == "retry" and HOOKS[jid]["attempts"] == 1 and not hook_audits(), (c1, HOOKS))
c2 = tick()
must(c2["retry"] == 1 and HOOKS[jid]["attempts"] == 2, (c2, HOOKS))
STORE_RESULT["value"] = "queued"
c3 = tick()
must(c3["delivered"] == 1 and HOOKS[jid]["state"] == "queued" and HOOKS[jid]["attempts"] == 3 and len(STORED) == 1, (c3, HOOKS))
reset()
register("certificatemanagement")
STORE_RESULT["value"] = "error"
jid = new_id()
job_file(jid)
for _ in range(3):
    tick()
must(HOOKS[jid]["state"] == "abandoned" and HOOKS[jid]["reason"] == "store_failed" and HOOKS[jid]["attempts"] == 3, HOOKS)
rows = hook_audits()
must(len(rows) == 1 and rows[0]["action"] == hooks.ACTION_ABANDONED and rows[0]["metadata"]["reason"] == "store_failed", AUDITS)
STORE_RESULT["value"] = "queued"
tick()
must(not STORED and len(hook_audits()) == 1, "an abandoned job is never tried again and writes no second row")
print("       a failed store is retried on the next ticks, three tries in all, then abandoned with one audit row and never tried again")

# ---- (10) a claim left claiming is abandoned, never sent again; an old job file is not looked at
reset()
register("certificatemanagement")
jid = new_id()
job_file(jid)
HOOKS[jid] = {"state": "claiming", "attempts": 1, "reason": "", "module_id": "certificatemanagement", "updated": NOW[0]}
tick()
must(HOOKS[jid]["state"] == "claiming" and not STORED, "a fresh claim is left alone")
NOW[0] += timedelta(minutes=20)
hooks.deliver_finished_server_jobs()
must(HOOKS[jid]["state"] == "abandoned" and HOOKS[jid]["reason"] == "claim_stale" and not STORED, HOOKS)
reset()
register("certificatemanagement")
old = new_id()
job_file(old, age=7 * 3600)
counts = tick()
must(counts["checked"] == 0 and not STORED and not HOOKS, "a job file untouched for more than six hours is not looked at")
fresh = new_id()
job_file(fresh, age=5 * 3600)
counts = tick()
must(counts["delivered"] == 1, "a file touched within the window is delivered")
print("       a stale claim is abandoned and not re-sent; a job file older than six hours is not looked at")

# ---- (11) the cost: at most 50 job files read a tick, oldest first; a hand-damaged file never raises
reset()
register("certificatemanagement")
ids = [new_id() for _ in range(120)]
for n, jid in enumerate(ids):
    job_file(jid, age=3000 - n * 10)  # ids[0] is the oldest
reads = []
real_read = sm._read_job
sm._read_job = lambda job_id: reads.append(job_id) or real_read(job_id)
counts = tick()
must(counts["checked"] == 50 and len(reads) == 50 and len(STORED) == 50, (counts, len(reads)))
must(reads == ids[:50], "oldest first")
tick()
tick()
must(len(STORED) == 120 and len(reads) == 120, "the rest follow on the next ticks, each file read once")
sm._read_job = real_read
reset()
register("certificatemanagement")
(JOBS_ROOT / f"{new_id()}.json").write_text("{not json", encoding="utf-8")
(JOBS_ROOT / f"{new_id()}.json").write_text("[1, 2]", encoding="utf-8")
(JOBS_ROOT / "not-a-job.json").write_text("{}", encoding="utf-8")
(JOBS_ROOT / f"{new_id()}.txt").write_text("{}", encoding="utf-8")
job_file(new_id())
counts = tick()
must(counts["unreadable"] == 2 and counts["delivered"] == 1 and counts["errors"] == 0, counts)
import shutil

shutil.rmtree(JOBS_ROOT)
must(hooks.deliver_finished_server_jobs()["checked"] == 0, "a missing job folder is an empty tick")
JOBS_ROOT.mkdir(parents=True)
broken = hooks._recent_job_ids
hooks._recent_job_ids = lambda now: (_ for _ in ()).throw(RuntimeError("disk"))
counts = hooks.deliver_finished_server_jobs()
hooks._recent_job_ids = broken
must(counts["errors"] == 1, "the step never raises")
print("       the tick reads at most 50 job files, oldest first; damaged files, a missing folder and a fault never raise")

# ---- (12) the tick wraps the step and its own output line is unchanged
tick_src = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("from tec_tac.server_job_hooks import deliver_finished_server_jobs" in tick_src, "the tick calls the hook step")
at = tick_src.index("deliver_finished_server_jobs()")
block = tick_src[at - 900: at + 400]
must("try:" in block and "except Exception:" in block and 'logging.getLogger("tec_tac.server_job_hooks")' in block, "the step has its own try/except and logs")
after = tick_src[at: tick_src.index("sweep_state = ")]
must("self.stdout" not in after and "self.stderr" not in after, "the step writes nothing to the output")
LINE = ("TEC-TAC scheduler tick: checked={checked} queued={queued} skipped={skipped} cleaned={cleaned} session_history_cleanup={session_cleanup} "
        "session_expiry_sweep={sweep_state} sweep_revoked={sweep_revoked} sweep_skipped_no_digest={sweep_skipped} sweep_orphan_tokens={sweep_orphans} "
        "now={now} replacement_conflicts_queued={replacement_queued} replacement_audit_rows={replacement_audit} module_failure_notices={failure_notices} "
        "module_failure_skipped_old={failure_old} module_failure_already_notified={failure_known} module_failure_emails={failure_emails} "
        "repository_defaults_seeded={repo_seeded} repository_sync_schedule_created={repo_schedule_created}")
must(LINE in tick_src, "the tick's own output line is unchanged")
# the step runs after the settle step and neither depends on the other
must(tick_src.index("settle_server_job_runs()") < at, "the hook step runs after the settle step")
print("       the tick wraps the step in its own try/except, writes nothing, and its output line is byte-for-byte unchanged")

# ---- (13) no module code runs in the tick, and the source holds the rules the docs state
src = (APP / "server_job_hooks.py").read_text(encoding="utf-8")
must("handler(" not in src and "register_event_job" not in src.split('"""', 2)[2], "the step runs no module code and registers nothing")
must("publish_for_core" in src and "TecTacServerJobHook" in src, "the step stores the event on Core's authority behind the unique claim")
must("output" in src.lower() and "parameters" in src.lower(), "the docstring states the payload rule")
claim_at, publish_at = src.index("if not _claim(job_id, **common):\n        counts[\"duplicate\"]"), src.index("events.publish_for_core(hook_job_id(owner)")
must(claim_at < publish_at, "the claim is written before the event is published")
ej_src = (APP / "event_jobs.py").read_text(encoding="utf-8")
must("def publish_for_core(" in ej_src and "_core_caller_ok()" in ej_src.split("def publish_for_core(")[1][:900], "the internal path checks its caller first")
# start, get_job, cancel, list_jobs and the job file are unchanged by this release
sm_src = (APP / "server_maintenance.py").read_text(encoding="utf-8")
for needle in ("def start(self, *, action: str, parameters: dict | None = None, context: dict, user=None) -> dict:",
               "def get_job(self, *, job_id: str, context: dict) -> dict:",
               "def cancel(self, *, job_id: str, context: dict, user=None) -> dict:",
               'operations=("start", "get_job", "cancel", "list_jobs", "list_actions"),', 'CAPABILITY_VERSION = "1.1.0"'):
    must(needle in sm_src, needle)
print("       no module code runs in the tick; the claim is written before the event; start, get_job, cancel and list_jobs keep their signatures")

print("PASS server job finished hook 1.17.62")
