#!/usr/bin/env python3
"""1.17.112 regression: a per-job input channel for core.server_maintenance (1.1.0 -> 1.2.0), request of certificatemanagement 0.4.1.

A module can post a fixed-name signal (``continue`` or ``abort``) to a running server-maintenance job. Covered here:

* server_maintenance.py ``send_signal``: a name outside the fixed set, a bad or unknown job id, a caller without the action permission
  (one ``deny`` row, no request file, no dispatch), a job that is not running, an action that does not list the name and a job that
  started before the upgrade are all refused; a superuser and a holder pass; the request file is written, removed again when dispatch
  fails, and one Core audit row (``run``, never the parameters) is written; the public job and ``list_actions`` carry the new keys;
  the capability reports 1.2.0 with ``send_signal`` and keeps its first five operations;
* the root helper ``signal_job`` (``--signal``): the accepted names come from the ROOT registry even when the job file is edited to
  claim another, the second send is a no-op and never overwrites, the file is created exclusively (0600 where the platform has modes,
  at most 512 bytes), a symlink or a FIFO at the request path is refused without blocking, a request that names another job is ignored,
  a job that is not running is refused, and the claimed job records what was sent;
* ``run_job`` sets TEC_TAC_SERVER_MAINTENANCE_JOB_ID and TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR for an action that lists signals and
  changes nothing else in the child's environment; an action without signals gets the plain inherited environment;
* registry.py: ``signals`` of at most two different fixed names is accepted and carried; a third name, a duplicate, a non-list and a
  non-string are refused.

What cannot run here: the helper as root through sudo and systemd, O_EXCL on the real state folder and the root-only folder modes.
See tests/server-maintenance-signals-runtime-1.17.112.sh (dev server only).
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import stat
import sys
import tempfile
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
logging.disable(logging.CRITICAL)
IS_POSIX_MODES = os.name != "nt"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


TMP = tempfile.TemporaryDirectory()
BASE = Path(TMP.name)
STATE, REGISTRY = BASE / "state", BASE / "registry"
for folder in ("jobs", "signal-requests", "cancel-requests", "logs", "running"):
    (STATE / folder).mkdir(parents=True)
REGISTRY.mkdir()
ENABLED = {"sigmod": True}
AUDITS, DISPATCHES = [], []
DISPATCH_FAIL = []


def atomic_json(path, payload, *, mode=0o660, default=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, default=default), encoding="utf-8")


class User:
    is_authenticated = True

    def __init__(self, username, *grants, superuser=False):
        self.username, self.grants, self.is_superuser = username, set(grants), superuser


def has_extension_permission(user, code):
    return bool(user.is_superuser or code in user.grants)


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.safe_files", atomic_json=atomic_json)
mod("tec_tac.capabilities", build_operation_context=lambda *, source_module, source_action, source_run_id=None, requested_by=None, **extra: {
    "source_module": str(source_module or "").strip(), "source_action": str(source_action or "").strip(),
    "source_run_id": source_run_id, "requested_by": str(requested_by) if requested_by else None, **extra},
    register_capability=lambda **kw: SimpleNamespace(**kw))
mod("tec_tac.config", load_layout=lambda: {"TEC_TAC_SERVER_MAINTENANCE_ROOT": str(STATE), "TEC_TAC_SERVER_MAINTENANCE_REGISTRY_ROOT": str(REGISTRY)})
mod("tec_tac.module_state", is_enabled=lambda module_id: ENABLED.get(module_id, False))
mod("tec_tac.rbac", has_extension_permission=has_extension_permission)
audit = mod("tec_tac.audit", record=lambda **kw: AUDITS.append(kw) or {"recorded": True},
            service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw))
pkg.audit = audit

sm = load("tec_tac.server_maintenance", APP / "server_maintenance.py")


def stub_dispatch(command, job_id):
    request = STATE / "signal-requests"
    DISPATCHES.append((command, job_id, sorted(p.name for p in request.glob("*.json"))))
    if DISPATCH_FAIL:
        raise sm.ServerMaintenanceError("sudo refused", job_id=job_id, classification="dispatch_failed")


sm._dispatch = stub_dispatch
provider = sm.get_server_maintenance_provider()


def register(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "description": action_id, "executable": "/x", "argv": [], "timeout_seconds": 600, "parameters": {
        "note": {"type": "string", "required": False, "max_length": 40}}}
    manifest.update(extra)
    (REGISTRY / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


register("sigmod.renew", permission="sigmod.renew", owner_module="sigmod", signals=["continue"], waits_for_person=True)
register("sigmod.both", permission="sigmod.renew", owner_module="sigmod", signals=["continue", "abort"])
register("sigmod.plain", permission="sigmod.renew", owner_module="sigmod")
register("sigmod.badsignals", permission="sigmod.renew", owner_module="sigmod", signals=["stop"])
register("sigmod.dup", permission="sigmod.renew", owner_module="sigmod", signals=["continue", "continue"])
register("open.signal", signals=["continue"])

ctx = {"source_module": "sigmod", "source_action": "sigmod.continue", "requested_by": "tester"}
alice = User("alice", "sigmod.renew")
bob = User("bob")
boss = User("boss", superuser=True)


def job_path(job_id):
    return STATE / "jobs" / f"{job_id}.json"


def set_status(job_id, status, **extra):
    data = json.loads(job_path(job_id).read_text(encoding="utf-8"))
    data["status"] = status
    data.update(extra)
    job_path(job_id).write_text(json.dumps(data), encoding="utf-8")


def started(action, status="running", user=boss):
    job = provider.start(action=action, context=ctx, user=user)
    set_status(job["id"], status)
    return job["id"]


def refuse(call, error, classification=None):
    try:
        call()
    except error as exc:
        if classification is not None:
            must(getattr(exc, "classification", None) == classification, (classification, getattr(exc, "classification", None), str(exc)))
        return exc
    raise AssertionError("call was accepted")


def signal_dispatches():
    return [d for d in DISPATCHES if d[0] == "--signal"]


def requests_left():
    return sorted(p.name for p in (STATE / "signal-requests").glob("*.json"))


def audits(action):
    return [a for a in AUDITS if a["action"] == action]


# ------------------------------------------------------------------------------------------------ the capability
registered = sm.register_core_server_maintenance_capability()
must(tuple(map(int, sm.CAPABILITY_VERSION.split("."))) >= (1, 2, 0) and sm.CAPABILITY_VERSION.startswith("1.") and registered.version == sm.CAPABILITY_VERSION and registered.id == "core.server_maintenance", registered.version)  # 1.3.0 since 1.17.113
must(registered.operations[:5] == ("start", "get_job", "cancel", "list_jobs", "list_actions") and "send_signal" in registered.operations, registered.operations)
must(registered.metadata["signal_names"] == ["continue", "abort"] and registered.metadata["waits_for_person_actions"] is True, registered.metadata)
must(registered.metadata["per_action_permission"] is True and registered.metadata["global_lock"] is True, "earlier metadata stays")
must(all(hasattr(provider, n) for n in ("start", "get_job", "cancel", "list_jobs", "list_actions", "send_signal")), "operations are methods")

# ------------------------------------------------------------------------------------------------ start records the action's signals
jid = started("sigmod.renew", status="queued")
stored = json.loads(job_path(jid).read_text(encoding="utf-8"))
must(stored["action_signals"] == ["continue"] and stored["action_waits_for_person"] is True and stored["signals"] == [], stored)
public = provider.get_job(job_id=jid, context=ctx)
must(public["accepts_signals"] == ["continue"] and public["signals"] == [] and public["waits_for_person"] is True, public)
must(all(k in public for k in ("id", "action", "status", "stage", "lock", "permission", "stdout", "stderr", "logs")), "every earlier key stays")
plain_job = provider.start(action="sigmod.plain", context=ctx, user=boss)
must(plain_job["accepts_signals"] == [] and plain_job["waits_for_person"] is False, plain_job)
must(json.loads(job_path(provider.start(action="sigmod.badsignals", context=ctx, user=boss)["id"]).read_text())["action_signals"] == [], "a manifest value outside the fixed set means none")
must(json.loads(job_path(provider.start(action="sigmod.dup", context=ctx, user=boss)["id"]).read_text())["action_signals"] == [], "a duplicate means none (fail closed)")
rows = {row["id"]: row for row in provider.list_actions(context=ctx)}
must(rows["sigmod.renew"]["signals"] == ["continue"] and rows["sigmod.renew"]["waits_for_person"] is True, rows["sigmod.renew"])
must(rows["sigmod.plain"]["signals"] == [] and rows["sigmod.plain"]["waits_for_person"] is False and rows["sigmod.plain"]["permission"] == "sigmod.renew", rows["sigmod.plain"])
set_status(jid, "running", signals=[{"name": "continue", "sent_at": "2026-11-10T10:00:00+00:00"}, {"name": "junk", "sent_at": "x"}, "bad"])
must(provider.get_job(job_id=jid, context=ctx)["signals"] == [{"name": "continue", "sent_at": "2026-11-10T10:00:00+00:00"}], "only fixed names are shown")
set_status(jid, "running", signals=[])

# ------------------------------------------------------------------------------------------------ send_signal refusals
running = started("sigmod.renew")
before = (len(signal_dispatches()), len(AUDITS))
for bad in ("stop", "", "CONTINUE", " continue", None, 5, ["continue"], "continue/../x", "../continue"):
    refuse(lambda bad=bad: provider.send_signal(job_id=running, name=bad, context=ctx, user=boss), sm.ServerMaintenanceValidationError, "validation_failed")
refuse(lambda: provider.send_signal(job_id="not-a-uuid", name="continue", context=ctx, user=boss), sm.ServerMaintenanceValidationError, "validation_failed")
refuse(lambda: provider.send_signal(job_id=running, name="continue", context={}, user=boss), sm.ServerMaintenanceValidationError, "validation_failed")
refuse(lambda: provider.send_signal(job_id=str(uuid.uuid4()), name="continue", context=ctx, user=boss), sm.ServerMaintenanceNotFound, "not_found")
must((len(signal_dispatches()), len(AUDITS)) == before and requests_left() == [], "nothing dispatched, audited or written for a refused call")

# permission: the same check cancel makes
for who in (bob, None):
    exc = refuse(lambda who=who: provider.send_signal(job_id=running, name="continue", context=ctx, user=who), sm.ServerMaintenancePermissionDenied, "permission_denied")
    must(exc.permission == "sigmod.renew", exc.permission)
must(len(signal_dispatches()) == before[0] and requests_left() == [], "a denied caller dispatches nothing and writes no request file")
denies = audits("deny")
must(len(denies) == 2 and denies[0]["metadata"]["operation"] == "signal" and denies[0]["metadata"]["job_id"] == running and denies[0]["object_id"] == "sigmod.renew", denies)
must(not audits("run"), "no run row for a denied call")

# state and acceptance
for status in ("queued", "dispatched", "waiting_for_lock", "cancelling", "succeeded", "failed", "cancelled", "dispatch_failed"):
    other = started("sigmod.renew", status=status)
    refuse(lambda other=other: provider.send_signal(job_id=other, name="continue", context=ctx, user=boss), sm.ServerMaintenanceValidationError, "job_not_running")
no_signals = started("sigmod.plain")
refuse(lambda: provider.send_signal(job_id=no_signals, name="continue", context=ctx, user=boss), sm.ServerMaintenanceValidationError, "signal_not_accepted")
refuse(lambda: provider.send_signal(job_id=running, name="abort", context=ctx, user=boss), sm.ServerMaintenanceValidationError, "signal_not_accepted")
old_job = started("sigmod.both")
data = json.loads(job_path(old_job).read_text(encoding="utf-8"))
for key in ("action_signals", "action_waits_for_person", "signals"):
    data.pop(key, None)
job_path(old_job).write_text(json.dumps(data), encoding="utf-8")
refuse(lambda: provider.send_signal(job_id=old_job, name="continue", context=ctx, user=boss), sm.ServerMaintenanceValidationError, "signal_not_accepted")
must(provider.get_job(job_id=old_job, context=ctx)["accepts_signals"] == [] and provider.get_job(job_id=old_job, context=ctx)["signals"] == [], "a job from before the upgrade reads with empty new keys")
must(len(signal_dispatches()) == before[0] and requests_left() == [], "refusals dispatch nothing")

# ------------------------------------------------------------------------------------------------ send_signal success
result = provider.send_signal(job_id=running, name="continue", context=ctx, user=boss)
must(result["id"] == running and signal_dispatches()[-1][:2] == ("--signal", running), DISPATCHES[-1])
must(signal_dispatches()[-1][2] == [f"{running}.continue.json"], "the request file existed when the helper was called")
request = json.loads((STATE / "signal-requests" / f"{running}.continue.json").read_text(encoding="utf-8"))
must(set(request) == {"job_id", "name", "requested_at", "context"} and request["job_id"] == running and request["name"] == "continue" and request["context"]["requested_by"] == "tester", request)
rows = audits("run")
must(len(rows) == 1 and rows[0]["module_id"] == "core" and rows[0]["object_type"] == "server_maintenance_job" and rows[0]["object_id"] == running, rows)
must(rows[0]["metadata"] == {"job_id": running, "action": "sigmod.renew", "name": "continue", "owner_module": "sigmod"}, rows[0]["metadata"])
must(rows[0]["actor"] is boss and "parameters" not in json.dumps(rows[0]["metadata"]), "a person is the actor; no parameters")
(STATE / "signal-requests" / f"{running}.continue.json").unlink()

holder_job = started("sigmod.both")
must(provider.send_signal(job_id=holder_job, name="abort", context=ctx, user=alice)["id"] == holder_job, "a holder of the permission passes")
must(signal_dispatches()[-1][:2] == ("--signal", holder_job), DISPATCHES[-1])
open_job = started("open.signal", user=None)
must(provider.send_signal(job_id=open_job, name="continue", context=ctx)["id"] == open_job, "an action with no permission needs no user, as start does")
for p in (STATE / "signal-requests").glob("*.json"):
    p.unlink()

# dispatch failure removes the request file and writes no run row
DISPATCH_FAIL.append(True)
runs_before = len(audits("run"))
refuse(lambda: provider.send_signal(job_id=running, name="continue", context=ctx, user=boss), sm.ServerMaintenanceError, "dispatch_failed")
must(requests_left() == [] and len(audits("run")) == runs_before, "request file removed, no audit row, when dispatch fails")
DISPATCH_FAIL.clear()

# ------------------------------------------------------------------------------------------------ the root helper
for name, attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None}, "grp": {}, "pwd": {"getpwnam": lambda n: SimpleNamespace(pw_gid=0)}}.items():
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            mod(name, **attrs)
for shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, shim):
        setattr(os, shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000
if not hasattr(os, "getgid"):
    os.getgid = lambda: 0
h = load("sm_helper_signals_1_17_112", ROOT / "scripts" / "server-maintenance-helper.py")

HSTATE, HREG, HACT = BASE / "hstate", BASE / "hreg", BASE / "hact"
for p in (HSTATE, HREG, HACT):
    p.mkdir()
h.STATE_ROOT, h.JOBS_ROOT, h.CANCEL_ROOT = HSTATE, HSTATE / "jobs", HSTATE / "cancel-requests"
h.LOGS_ROOT, h.RUNNING_ROOT, h.AUDIT_FILE, h.LOCK_FILE = HSTATE / "logs", HSTATE / "running", HSTATE / "audit.jsonl", HSTATE / "server-maintenance.lock"
h.REGISTRY_ROOT, h.ACTION_ROOT = HREG, HACT
h.validate_executable = lambda value: Path(str(value))
h.load_config = dict
for p in (h.JOBS_ROOT, h.CANCEL_ROOT, h.LOGS_ROOT, h.RUNNING_ROOT, h.signal_request_root()):
    p.mkdir()
EXE = HACT / "run.sh"
EXE.write_bytes(b"#!/bin/sh\nexit 0\n")


def hregister(action_id, **extra):
    import hashlib

    manifest = {"id": action_id, "revision": "1", "executable": str(EXE), "argv": [], "timeout_seconds": 600, "success_exit_codes": [0], "enabled": True,
                "owner_module": "sigmod", "registered_by": "module-manifest", "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest()}
    manifest.update(extra)
    (HREG / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


hregister("sigmod.renew", permission="sigmod.renew", signals=["continue"])
hregister("sigmod.plain", permission="sigmod.renew")
hregister("sigmod.both", permission="sigmod.renew", signals=["continue", "abort"])


def claimed(action, status="running", **extra):
    job_id = str(uuid.uuid4())
    job = {"schema": 1, "id": job_id, "action": action, "action_revision": "1", "status": status, "stage": status, "context": ctx, "parameters": {}, "public_parameters": {},
           "lock": {"scope": "global", "state": "acquired", "acquired_at": None}, "exit_result": None, "failure": None}
    job.update(extra)
    root = h.claimed_dir(job_id)
    root.mkdir(parents=True)
    h.claimed_job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    h.job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    return job_id


def hrequest(job_id, name, *, claim_job=None, claim_name=None, context=None):
    path = h.signal_request_root() / f"{job_id}.{name}.json"
    path.write_text(json.dumps({"job_id": claim_job or job_id, "name": claim_name or name, "requested_at": "2026-11-10T10:00:00+00:00", "context": context or ctx}), encoding="utf-8")
    return path


def audit_events():
    if not h.AUDIT_FILE.is_file():
        return []
    return [json.loads(line) for line in h.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]


def sig_file(job_id, name):
    return h.claimed_dir(job_id) / "signals" / name


# accepted: the root registry lists continue
j1 = claimed("sigmod.renew")
req = hrequest(j1, "continue")
h.signal_job(j1)
target = sig_file(j1, "continue")
must(target.is_file() and not req.exists(), "signal file created, request file removed")
body = target.read_bytes()
must(len(body) <= h.SIGNAL_MAX_BYTES == 512, len(body))
sent = json.loads(body)
must(set(sent) == {"name", "sent_at", "requested_by"} and sent["name"] == "continue" and sent["requested_by"] == "tester", sent)
if IS_POSIX_MODES:
    must(stat.S_IMODE(target.stat().st_mode) == 0o600, oct(target.stat().st_mode))
    must(stat.S_IMODE(target.parent.stat().st_mode) == 0o700, "the signals folder is root-only")
rec = json.loads(h.claimed_job_path(j1).read_text(encoding="utf-8"))
must([row["name"] for row in rec["signals"]] == ["continue"] and rec["signals"][0]["sent_at"] == sent["sent_at"], rec.get("signals"))
must(json.loads(h.job_path(j1).read_text(encoding="utf-8"))["signals"] == rec["signals"], "the mirror shows the signal")
must(any(e["event"] == "job.signal_sent" and e["detail"] == {"name": "continue"} and e["job_id"] == j1 for e in audit_events()), audit_events())

# the second send is a no-op and never overwrites
req = hrequest(j1, "continue", context={**ctx, "requested_by": "someone-else"})
h.signal_job(j1)
must(target.read_bytes() == body and not req.exists(), "the second send did not overwrite and the request file is gone")
must(len(json.loads(h.claimed_job_path(j1).read_text(encoding="utf-8"))["signals"]) == 1, "recorded once")
must(any(e["event"] == "job.signal_already_sent" for e in audit_events()), "audited as already sent")

# names come from the ROOT registry, not from the job file
j2 = claimed("sigmod.renew", action_signals=["continue", "abort"], signals=[])
req = hrequest(j2, "abort")
h.signal_job(j2)
must(not sig_file(j2, "abort").exists() and not req.exists(), "abort is not in the root registry for this action, whatever the job file claims")
must(any(e["event"] == "job.signal_refused" and e["job_id"] == j2 and e["detail"]["name"] == "abort" for e in audit_events()), "refusal audited")
j3 = claimed("sigmod.plain", action_signals=["continue"])
hrequest(j3, "continue")
h.signal_job(j3)
must(not sig_file(j3, "continue").exists(), "an action with no signals accepts none, even if the job file says so")
j4 = claimed("sigmod.both")
hrequest(j4, "continue")
hrequest(j4, "abort")
h.signal_job(j4)
must(sig_file(j4, "continue").is_file() and sig_file(j4, "abort").is_file(), "both names, one file each")
must([row["name"] for row in json.loads(h.claimed_job_path(j4).read_text(encoding="utf-8"))["signals"]] == ["continue", "abort"], "both recorded")

# a name outside the fixed set is never looked at (no request path exists for it)
junk = h.signal_request_root() / f"{j4}.stop.json"
junk.write_text(json.dumps({"job_id": j4, "name": "stop"}), encoding="utf-8")
j5 = claimed("sigmod.both")
try:
    h.signal_job(j5)
    raise AssertionError("no request was found, expected a refusal")
except RuntimeError as exc:
    must("no signal request" in str(exc), str(exc))
must(not (h.claimed_dir(j5) / "signals" / "stop").exists(), "no file for an unknown name")
junk.unlink()

# a job that is not running, or a request that names another job
for status in ("waiting_for_lock", "dispatched", "succeeded", "failed", "cancelled"):
    jx = claimed("sigmod.renew", status=status)
    hrequest(jx, "continue")
    try:
        h.signal_job(jx)
        raise AssertionError("accepted for " + status)
    except RuntimeError as exc:
        must("not running" in str(exc), str(exc))
    must(not sig_file(jx, "continue").exists(), status)
j6 = claimed("sigmod.renew")
other = str(uuid.uuid4())
req = hrequest(j6, "continue", claim_job=other)
try:
    h.signal_job(j6)
    raise AssertionError("a request that names another job was used")
except RuntimeError:
    pass
must(not sig_file(j6, "continue").exists() and not req.exists(), "ignored, and removed")
req = hrequest(j6, "continue", claim_name="abort")
try:
    h.signal_job(j6)
    raise AssertionError("a request that names another signal was used")
except RuntimeError:
    pass
must(not sig_file(j6, "continue").exists(), "ignored")
(h.signal_request_root() / f"{j6}.continue.json").write_text("{not json", encoding="utf-8")
try:
    h.signal_job(j6)
    raise AssertionError("bad json was used")
except RuntimeError:
    pass
must(not sig_file(j6, "continue").exists(), "bad json ignored")
try:
    h.signal_job(str(uuid.uuid4()))
    raise AssertionError("unknown job accepted")
except RuntimeError:
    pass
try:
    h.signal_job("../etc")
    raise AssertionError("bad id accepted")
except RuntimeError:
    pass

# size: a long or non-ASCII requested_by cannot push the file over 512 bytes
j7 = claimed("sigmod.renew")
hrequest(j7, "continue", context={**ctx, "requested_by": "é中\U0001f600" * 400})
h.signal_job(j7)
must(0 < len(sig_file(j7, "continue").read_bytes()) <= 512, len(sig_file(j7, "continue").read_bytes()))
j8 = claimed("sigmod.renew")
hrequest(j8, "continue", context={**ctx, "requested_by": "A" * 5000})
h.signal_job(j8)
must(len(sig_file(j8, "continue").read_bytes()) <= 512 and len(json.loads(sig_file(j8, "continue").read_bytes())["requested_by"]) == 100, "capped")

# a symlink at the request path is removed, never followed; a symlink at the signal path is never written through
secret = BASE / "secret.json"
secret.write_text(json.dumps({"job_id": "x", "name": "continue"}), encoding="utf-8")
j9 = claimed("sigmod.renew")
link = h.signal_request_root() / f"{j9}.continue.json"
try:
    os.symlink(secret, link)
    linked = True
except (OSError, NotImplementedError, AttributeError):
    linked = False
if linked:
    try:
        h.signal_job(j9)
        raise AssertionError("a symlink request was used")
    except RuntimeError:
        pass
    must(not os.path.lexists(link) and secret.is_file() and not sig_file(j9, "continue").exists(), "the symlink is gone, its target untouched")
    victim = BASE / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    (h.claimed_dir(j9) / "signals").mkdir(exist_ok=True)
    os.symlink(victim, sig_file(j9, "continue"))
    hrequest(j9, "continue")
    h.signal_job(j9)
    must(victim.read_text(encoding="utf-8") == "keep", "a symlink at the signal path is not written through")
else:
    print("       symlink cases skipped on this platform (the dev-server run covers them)")
if hasattr(os, "mkfifo"):
    j10 = claimed("sigmod.renew")
    fifo = h.signal_request_root() / f"{j10}.continue.json"
    os.mkfifo(fifo)
    try:
        h.signal_job(j10)
        raise AssertionError("a FIFO request was used")
    except RuntimeError:
        pass
    must(not os.path.lexists(fifo) and not sig_file(j10, "continue").exists(), "a FIFO is removed without being opened (no hang)")
else:
    print("       FIFO case skipped on this platform (the dev-server run covers it)")

# the command line: --signal takes the same three argv as the others, so main() is unchanged
src = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
must('elif mode == "--signal": signal_job(value)' in src and "--cancel|--signal <job-id>" in src and "len(sys.argv) != 3" in src, "--signal wired into main and usage")

# ------------------------------------------------------------------------------------------------ run_job environment
POPEN = []


class FakeChild:
    def __init__(self, argv, **kw):
        POPEN.append({"argv": argv, **kw})
        self.returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass


h.subprocess = SimpleNamespace(Popen=FakeChild, run=h.subprocess.run, TimeoutExpired=h.subprocess.TimeoutExpired, DEVNULL=h.subprocess.DEVNULL, PIPE=h.subprocess.PIPE)
h.fcntl = SimpleNamespace(flock=lambda *a: None, LOCK_EX=2, LOCK_UN=8)


def run(action):
    job_id = claimed(action, status="dispatched")
    h.run_job(job_id)
    return job_id


jr = run("sigmod.renew")
env = POPEN[-1]["env"]
signal_dir = h.claimed_dir(jr) / "signals"
must(env is not None and env["TEC_TAC_SERVER_MAINTENANCE_JOB_ID"] == jr and env["TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR"] == str(signal_dir), env and {k: v for k, v in env.items() if k.startswith("TEC_TAC")})
must(signal_dir.is_dir(), "the signal folder exists before the child starts")
must({k: v for k, v in env.items() if not k.startswith("TEC_TAC_SERVER_MAINTENANCE_")} == {k: v for k, v in os.environ.items() if not k.startswith("TEC_TAC_SERVER_MAINTENANCE_")}, "nothing else in the environment changes")
must("TEC_TAC_SERVER_MAINTENANCE_LOCK" not in env, "an action that does not wait for a person gets no lock variable")
must(json.loads(h.claimed_job_path(jr).read_text(encoding="utf-8"))["status"] == "succeeded", "the job ends succeeded")
jp = run("sigmod.plain")
must(POPEN[-1]["env"] is None and not (h.claimed_dir(jp) / "signals").exists(), "an action without signals gets the plain inherited environment")

# ------------------------------------------------------------------------------------------------ registry.py
reg = load("tec_tac_registry_signals", APP / "registry.py")
PLUGIN = BASE / "plugin"
(PLUGIN / "server_maintenance" / "actions").mkdir(parents=True)
(PLUGIN / "server_maintenance" / "actions" / "renew.sh").write_bytes(b"#!/bin/sh\n")


def entry(**over):
    value = {"id": "sigmod.renew", "permission": "sigmod.renew", "executable": "server_maintenance/actions/renew.sh", "timeout_seconds": 600}
    value.update(over)
    return value


def parse_actions(*entries):
    payload = {"server_maintenance_actions": list(entries)}
    return reg._server_maintenance_actions(payload, "extension", "sigmod", PLUGIN, (("Group", ("sigmod.renew",)),), ("server_maintenance.register",))


def refused(**over):
    try:
        parse_actions(entry(**over))
    except reg.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"accepted {over!r}")


must("signals" in reg._SM_ACTION_KEYS and "waits_for_person" in reg._SM_ACTION_KEYS, "keys known")
must(parse_actions(entry())[0]["signals"] == [] and parse_actions(entry())[0]["waits_for_person"] is False, "defaults")
must(parse_actions(entry(signals=["continue"]))[0]["signals"] == ["continue"], "one name")
must(parse_actions(entry(signals=["continue", "abort"]))[0]["signals"] == ["continue", "abort"], "two names")
must(parse_actions(entry(signals=[]))[0]["signals"] == [], "empty list")
for bad in (["continue", "abort", "continue"], ["continue", "continue"], ["abort", "abort"], "continue", {"continue": True}, None, 5, ["stop"], ["Continue"], [1], [None], [["continue"]], ["continue", "abort", "go"]):
    must("signals" in refused(signals=bad), repr(bad))

print("[TEST] PASS server maintenance signals 1.17.112")
