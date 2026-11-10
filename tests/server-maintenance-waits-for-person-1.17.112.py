#!/usr/bin/env python3
"""1.17.112 regression: a server-maintenance action that waits for a person must not hold the global lock (request of certificatemanagement 0.4.1).

An action may declare ``waits_for_person: true`` in a signed module's manifest. Then Core's helper does not queue it for the global
lock: the job is ``running`` at once with lock state ``program_managed`` and the action program takes ``flock`` itself on the file
named by TEC_TAC_SERVER_MAINTENANCE_LOCK. An action without the key behaves exactly as before. Covered here:

* registry.py and the helper's ``validate_manifest``: the key is accepted as a bool, refused as anything else, refused with a
  timeout_seconds above 14400, accepted at 14400 and at certificatemanagement's 8400;
* an administrator's hand registration (``--register``) that carries the key is refused, and a registry file that says waits_for_person
  without being a module-manifest registration is still run with the ordinary lock (fail closed);
* ``run_job``: an ordinary action goes through ``waiting_for_lock`` and takes the flock on the lock file before it runs; a
  waits_for_person action never queues, never flocks that file itself, shows lock state ``program_managed`` while its child runs, gets
  TEC_TAC_SERVER_MAINTENANCE_LOCK in the child's environment (an ordinary child does not), and ends with lock state ``released``;
  another job finishes while the waiting job's child is still running; cancel before execution still works;
* the public job and ``list_actions`` carry ``waits_for_person`` (covered with the signals test too);
* where the platform has real ``fcntl``: a held lock on the file does not stop a waits_for_person job.

What cannot run here: the real flock contention between two systemd units as root. See
tests/server-maintenance-waits-runtime-1.17.112.sh (dev server only).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


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


try:
    import fcntl as REAL_FCNTL
except ImportError:
    REAL_FCNTL = None
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

TMP = tempfile.TemporaryDirectory()
BASE = Path(TMP.name)
h = load("sm_helper_waits_1_17_112", ROOT / "scripts" / "server-maintenance-helper.py")
HSTATE, HREG, HACT = BASE / "state", BASE / "reg", BASE / "act"
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
ctx = {"source_module": "waitmod", "source_action": "waitmod.renew", "requested_by": "tester"}


def hregister(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "executable": str(EXE), "argv": [], "timeout_seconds": 600, "success_exit_codes": [0], "enabled": True,
                "owner_module": "waitmod", "permission": "waitmod.renew", "registered_by": "module-manifest",
                "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest()}
    manifest.update(extra)
    (HREG / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


hregister("waitmod.ordinary")
hregister("waitmod.waits", waits_for_person=True, timeout_seconds=8400)
hregister("waitmod.waitsfalse", waits_for_person=False)
hregister("waitmod.hand", waits_for_person=True, registered_by=None, executable_sha256=None)


def claimed(action):
    job_id = str(uuid.uuid4())
    job = {"schema": 1, "id": job_id, "action": action, "action_revision": "1", "status": "dispatched", "stage": "dispatched", "context": ctx, "parameters": {},
           "public_parameters": {}, "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None}
    h.claimed_dir(job_id).mkdir(parents=True)
    h.claimed_job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    h.job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    return job_id


def record(job_id):
    return json.loads(h.claimed_job_path(job_id).read_text(encoding="utf-8"))


def refused_by(call, part):
    try:
        call()
    except RuntimeError as exc:
        must(part in str(exc), (part, str(exc)))
        return
    raise AssertionError(f"accepted, expected a refusal naming {part!r}")


# ------------------------------------------------------------------------------------------------ the helper's validators
base = {"id": "waitmod.waits", "executable": "/x", "argv": [], "parameters": {}}
good = h.validate_manifest({**base, "waits_for_person": True, "timeout_seconds": 14400}, require_executable=False)
must(good["waits_for_person"] is True and good["signals"] == [], good)
must(h.validate_manifest({**base, "waits_for_person": True, "timeout_seconds": 8400}, require_executable=False)["timeout_seconds"] == 8400, "8400 is allowed")
must(h.validate_manifest(base, require_executable=False)["waits_for_person"] is False, "absent means false")
must(h.validate_manifest({**base, "waits_for_person": False, "timeout_seconds": 100000}, require_executable=False)["timeout_seconds"] == 100000, "the cap applies only to a waiting action")
for bad in ("true", 1, 0, None, [], {}, "yes"):
    refused_by(lambda bad=bad: h.validate_manifest({**base, "waits_for_person": bad}, require_executable=False), "waits_for_person")
refused_by(lambda: h.validate_manifest({**base, "waits_for_person": True, "timeout_seconds": 14401}, require_executable=False), "timeout_seconds of at most 14400")
must(h.validate_manifest({**base, "waits_for_person": True}, require_executable=False)["timeout_seconds"] == 3600, "the default timeout is under the cap")
refused_by(lambda: h.validate_manifest({**base, "signals": ["continue", "abort", "continue"]}, require_executable=False), "signals")
refused_by(lambda: h.validate_manifest({**base, "signals": ["go"]}, require_executable=False), "signals")
refused_by(lambda: h.validate_manifest({**base, "signals": "continue"}, require_executable=False), "signals")
must(h.validate_manifest({**base, "signals": ["continue", "abort"]}, require_executable=False)["signals"] == ["continue", "abort"], "two fixed names")

# module registration passes the keys through; an unknown key is still refused
manifest = {"id": "waitmod", "type": "extension", "version": "1.0.0", "publisher_permissions": ["server_maintenance.register"],
            "permission_groups": {"G": ["waitmod.renew"]},
            "server_maintenance_actions": [{"id": "waitmod.waits", "permission": "waitmod.renew", "executable": "server_maintenance/actions/a.sh", "waits_for_person": True, "signals": ["continue"]}]}
_, entries = h._module_actions_from_manifest("waitmod", manifest)
must(entries[0]["waits_for_person"] is True and entries[0]["signals"] == ["continue"], entries)
manifest["server_maintenance_actions"][0]["colour"] = "red"
refused_by(lambda: h._module_actions_from_manifest("waitmod", manifest), "documented keys")

# an administrator's hand registration may not set the key
hand = BASE / "hand.json"
for value in (True, False):
    hand.write_text(json.dumps({"id": "hand.action", "executable": str(EXE), "waits_for_person": value}), encoding="utf-8")
    refused_by(lambda: h.register_manifest(str(hand)), "only by a module manifest")
must(not (HREG / "hand.action.json").exists(), "nothing was registered")

# ------------------------------------------------------------------------------------------------ registry.py
reg = load("tec_tac_registry_waits", APP / "registry.py")
PLUGIN = BASE / "plugin"
(PLUGIN / "server_maintenance" / "actions").mkdir(parents=True)
(PLUGIN / "server_maintenance" / "actions" / "renew.sh").write_bytes(b"#!/bin/sh\n")


def entry(**over):
    value = {"id": "waitmod.waits", "permission": "waitmod.renew", "executable": "server_maintenance/actions/renew.sh"}
    value.update(over)
    return value


def parse(**over):
    payload = {"server_maintenance_actions": [entry(**over)]}
    return reg._server_maintenance_actions(payload, "extension", "waitmod", PLUGIN, (("G", ("waitmod.renew",)),), ("server_maintenance.register",))[0]


def refused(**over):
    try:
        parse(**over)
    except reg.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"accepted {over!r}")


must(parse(waits_for_person=True, timeout_seconds=8400)["waits_for_person"] is True, "certificatemanagement's 8400")
must(parse(waits_for_person=True, timeout_seconds=14400)["waits_for_person"] is True, "the cap itself")
must(parse(waits_for_person=True)["timeout_seconds"] == 3600, "default under the cap")
must(parse(waits_for_person=False, timeout_seconds=100000)["waits_for_person"] is False, "cap applies only when waiting")
must(parse()["waits_for_person"] is False, "absent is false")
for bad in ("true", 1, 0, None, [], "false"):
    must("waits_for_person" in refused(waits_for_person=bad), repr(bad))
must("14400" in refused(waits_for_person=True, timeout_seconds=14401), "above the cap")
must("14400" in refused(waits_for_person=True, timeout_seconds=7 * 24 * 3600), "a week")

# ------------------------------------------------------------------------------------------------ run_job
STAGE = []
FLOCKS = []
INNER = []
CHILDREN = []


class FakeChild:
    def __init__(self, argv, **kw):
        CHILDREN.append({"argv": argv, **kw})
        self.returncode = 0
        for hook in INNER[:]:
            hook()

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass


def flock(fd, op):
    try:
        on_lock = os.fstat(fd).st_ino == os.stat(h.LOCK_FILE).st_ino
    except OSError:
        on_lock = False
    if on_lock:
        status = [json.loads(p.read_text(encoding="utf-8"))["status"] for p in h.RUNNING_ROOT.glob("*/job.json")]
        FLOCKS.append((op, sorted(status)))


h.subprocess = SimpleNamespace(Popen=FakeChild, run=h.subprocess.run, TimeoutExpired=h.subprocess.TimeoutExpired, DEVNULL=h.subprocess.DEVNULL, PIPE=h.subprocess.PIPE)
h.fcntl = SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_UN=8)

# an ordinary action: waiting_for_lock, then the flock, then it runs
ordinary = claimed("waitmod.ordinary")
FLOCKS.clear()
seen = {}
INNER[:] = [lambda: seen.update(record(ordinary))]
h.run_job(ordinary)
INNER.clear()
must(FLOCKS and FLOCKS[0][0] == 2 and "waiting_for_lock" in FLOCKS[0][1], FLOCKS)
must(any(op == 8 for op, _ in FLOCKS), "released again")
must(seen["status"] == "running" and seen["lock"]["state"] == "acquired" and seen["lock"]["acquired_at"], seen["lock"])
must(CHILDREN[-1]["env"] is None, "an ordinary child inherits the environment unchanged")
final = record(ordinary)
must(final["status"] == "succeeded" and final["lock"]["state"] == "released", final)
events = [json.loads(line)["event"] for line in h.AUDIT_FILE.read_text(encoding="utf-8").splitlines()]
must("job.waiting_for_lock" in events, "the ordinary job is audited as waiting")
must(record(claimed("waitmod.waitsfalse"))["status"] == "dispatched", "setup")
FLOCKS.clear()
off = claimed("waitmod.waitsfalse")
h.run_job(off)
must(FLOCKS and FLOCKS[0][0] == 2 and CHILDREN[-1]["env"] is None, "waits_for_person false behaves as an ordinary action")

# a waits_for_person action: no queue, no flock by Core, program_managed, lock path in the child's environment
waiting = claimed("waitmod.waits")
other = claimed("waitmod.ordinary")
FLOCKS.clear()
mid, other_final = {}, {}


def while_child_runs():
    if mid:
        return
    mid.update(record(waiting))
    mid["lock_file_exists"] = h.LOCK_FILE.is_file()
    INNER.clear()
    h.run_job(other)  # another job finishes while the waiting job's child is still running
    other_final.update(record(other))


INNER[:] = [while_child_runs]
h.run_job(waiting)
INNER.clear()
must(mid["status"] == "running" and mid["stage"] == "running" and mid["lock"] == {"scope": "global", "state": "program_managed", "acquired_at": None}, mid["lock"])
must(mid["lock_file_exists"], "the lock file exists so the program can open it")
waits_env = [c for c in CHILDREN if c.get("env") and "TEC_TAC_SERVER_MAINTENANCE_LOCK" in c["env"]]
must(len(waits_env) == 1 and waits_env[0]["env"]["TEC_TAC_SERVER_MAINTENANCE_LOCK"] == str(h.LOCK_FILE), "only the waiting child gets the lock path")
must({k: v for k, v in waits_env[0]["env"].items() if not k.startswith("TEC_TAC_SERVER_MAINTENANCE_")} == {k: v for k, v in os.environ.items() if not k.startswith("TEC_TAC_SERVER_MAINTENANCE_")}, "nothing else changes")
must("TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR" not in waits_env[0]["env"], "no signal variables for an action that lists no signals")
must(other_final.get("status") == "succeeded", other_final)
status_at_flock = [statuses for op, statuses in FLOCKS if op == 2]
must(len(status_at_flock) == 1 and "running" in status_at_flock[0], "only the other, ordinary job took the lock: " + repr(FLOCKS))
final = record(waiting)
must(final["status"] == "succeeded" and final["lock"]["state"] == "released" and final["lock"]["acquired_at"] is None, final)
events = [(json.loads(line)["event"], json.loads(line)["job_id"]) for line in h.AUDIT_FILE.read_text(encoding="utf-8").splitlines()]
must(("job.waiting_for_lock", waiting) not in events and ("job.started", waiting) in events, "the waiting job never queues")

# a registry file that says waits_for_person but was not written by a module registration is not trusted with the lock
hand_job = claimed("waitmod.hand")
FLOCKS.clear()
h.run_job(hand_job)
must(FLOCKS and FLOCKS[0][0] == 2 and CHILDREN[-1]["env"] is None, "an action without a module-manifest registration takes the ordinary lock")

# cancel before execution still works for an ordinary action (unchanged path)
cancelled = claimed("waitmod.ordinary")
data = record(cancelled)
data["cancel_requested_at"] = "2026-11-10T10:00:00+00:00"
h.claimed_job_path(cancelled).write_text(json.dumps(data), encoding="utf-8")
before = len(CHILDREN)
h.run_job(cancelled)
must(len(CHILDREN) == before and record(cancelled)["status"] == "cancelled" and record(cancelled)["lock"]["state"] == "released", record(cancelled))

# real fcntl, where the platform has it: a held lock does not stop a waiting job
if REAL_FCNTL is not None:
    h.fcntl = REAL_FCNTL
    h.LOCK_FILE.touch()
    with open(h.LOCK_FILE, "a+") as held:
        REAL_FCNTL.flock(held.fileno(), REAL_FCNTL.LOCK_EX)
        try:
            real = claimed("waitmod.waits")
            h.run_job(real)
            must(record(real)["status"] == "succeeded", "a waits_for_person job runs while another holds the lock")
        finally:
            REAL_FCNTL.flock(held.fileno(), REAL_FCNTL.LOCK_UN)
else:
    print("       real flock case skipped on this platform (the dev-server run covers it)")

print("[TEST] PASS server maintenance waits for person 1.17.112")
