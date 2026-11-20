#!/usr/bin/env python3
"""1.18.29 regression: after a module's server-maintenance action job ends, Core re-verifies that module's sandbox runners.

scripts/server-maintenance-helper.py (the root worker) calls ``/usr/local/sbin/tec-tac-sandbox --verify-module <owner>`` once the action's
program has ended, on every end path (success, non-zero exit, timeout, cancel, worker error), before the job is marked finished. A hand
registration or an action with no owner triggers nothing. A missing helper is a silent no-op, a helper that is group or world writable is
refused, and a failing, raising or hanging helper only adds a lifecycle line and an audit row: the job's status, exit_result and failure
stay exactly as without the hook. Uses the fake layer of tests/server-maintenance-waits-for-person-1.17.112.py (no real systemd or root).
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
h = load("sm_helper_reverify_1_18_29", ROOT / "scripts" / "server-maintenance-helper.py")
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
ctx = {"source_module": "revmod", "source_action": "revmod.renew", "requested_by": "tester"}


def hregister(action_id, **extra):
    manifest = {"id": action_id, "revision": "1", "executable": str(EXE), "argv": [], "timeout_seconds": 600, "success_exit_codes": [0], "enabled": True,
                "owner_module": "revmod", "permission": "revmod.renew", "registered_by": "module-manifest",
                "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest()}
    manifest.update(extra)
    (HREG / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


hregister("revmod.ordinary")
hregister("revmod.waits", waits_for_person=True, timeout_seconds=8400)
hregister("revmod.waitsfalse", waits_for_person=False)
hregister("revmod.hand", waits_for_person=True, registered_by=None, executable_sha256=None)


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


hregister("revmod.act", timeout_seconds=1)
hregister("revmod.hand", registered_by=None, executable_sha256=None)
hregister("revmod.noowner", owner_module=None)

HELPER = "/usr/local/sbin/tec-tac-sandbox"
DEFAULTS = {"exit": 0, "child_rc": 0, "hang": False, "raise": None, "present": True, "uid": 0, "mode": 0o100755, "cancel": False, "error_child": False}
STATE = dict(DEFAULTS)
CALLS, SEEN = [], []
CURRENT = {}


class FakeHelperPath:
    def is_file(self):
        return STATE["present"]

    def stat(self):
        return SimpleNamespace(st_uid=STATE["uid"], st_mode=STATE["mode"])

    def __str__(self):
        return HELPER


class FakeChild:
    def __init__(self, argv, **kw):
        if STATE["error_child"]:
            raise OSError("cannot start")
        self.terminated = False
        self.job = CURRENT["job"]
        if STATE["cancel"]:
            data = record(self.job)
            data["cancel_requested_at"] = "2026-11-20T10:00:00+00:00"
            h.claimed_job_path(self.job).write_text(json.dumps(data), encoding="utf-8")

    def poll(self):
        if STATE["child_rc"] == "hang" and not self.terminated:
            return None
        return 0

    def wait(self, timeout=None):
        return -15 if STATE["child_rc"] == "hang" else STATE["child_rc"]

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


def fake_run(argv, **kw):
    CALLS.append({"argv": list(argv), **kw})
    SEEN.append(record(CURRENT["job"])["status"])
    if STATE["raise"]:
        raise STATE["raise"]
    if STATE["hang"]:
        raise h.subprocess.TimeoutExpired(argv, kw["timeout"])
    return SimpleNamespace(returncode=STATE["exit"])


h.subprocess = SimpleNamespace(Popen=FakeChild, run=fake_run, TimeoutExpired=h.subprocess.TimeoutExpired, DEVNULL=h.subprocess.DEVNULL, PIPE=h.subprocess.PIPE, STDOUT=h.subprocess.STDOUT)
h.fcntl = SimpleNamespace(flock=lambda *a: None, LOCK_EX=2, LOCK_UN=8)
h.SANDBOX_HELPER = FakeHelperPath()
h.time = SimpleNamespace(monotonic=h.time.monotonic, sleep=lambda s: None)


def reset(**over):
    STATE.clear()
    STATE.update(DEFAULTS)
    STATE.update(over)
    CALLS.clear()
    SEEN.clear()


def run(action="revmod.act", expect_error=False):
    job_id = claimed(action)
    CURRENT["job"] = job_id
    try:
        h.run_job(job_id)
    except Exception:
        if not expect_error:
            raise
    return job_id


def outcome(job_id):
    rec = record(job_id)
    return {k: rec.get(k) for k in ("status", "stage", "exit_result", "failure")}


def audit_rows(job_id, event="job.sandbox_reverify"):
    rows = [json.loads(line) for line in h.AUDIT_FILE.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if r["event"] == event and r["job_id"] == job_id]


def lifecycle(job_id):
    return (h.LOGS_ROOT / f"{job_id}.log").read_text(encoding="utf-8")


EXPECT_ARGV = [HELPER, "--verify-module", "revmod"]

# success: exact argv, bound, called while the job is still running (before the final status write)
reset()
job = run()
must(len(CALLS) == 1 and CALLS[0]["argv"] == EXPECT_ARGV, CALLS)
must(CALLS[0]["timeout"] == 120 and CALLS[0]["stdin"] is h.subprocess.DEVNULL and not CALLS[0].get("check"), CALLS[0])
must(SEEN == ["running"], "called before the final status write: " + repr(SEEN))
base_ok = outcome(job)
must(base_ok["status"] == "succeeded", base_ok)
must("sandbox_reverify module=revmod ok=True" in lifecycle(job), lifecycle(job))
rows = audit_rows(job)
must(len(rows) == 1 and rows[0]["detail"] == {"module": "revmod", "ok": True, "exit_code": 0}, rows)
order = [json.loads(line)["event"] for line in h.AUDIT_FILE.read_text(encoding="utf-8").splitlines() if json.loads(line)["job_id"] == job]
must(order.index("job.sandbox_reverify") < order.index("job.finished"), order)

# non-zero exit of the action
reset(child_rc=3)
job = run()
must(len(CALLS) == 1 and CALLS[0]["argv"] == EXPECT_ARGV and SEEN == ["running"], (CALLS, SEEN))
must(outcome(job)["status"] == "failed" and outcome(job)["failure"]["classification"] == "execution_failed", outcome(job))

# timeout of the action
reset(child_rc="hang")
job = run()
must(len(CALLS) == 1 and CALLS[0]["argv"] == EXPECT_ARGV and SEEN == ["running"], (CALLS, SEEN))
must(outcome(job)["failure"]["classification"] == "timeout", outcome(job))

# cancel
reset(cancel=True)
job = run()
must(len(CALLS) == 1 and CALLS[0]["argv"] == EXPECT_ARGV and SEEN == ["running"], (CALLS, SEEN))
must(outcome(job)["status"] == "cancelled", outcome(job))

# worker error (the child cannot start): run_job's finally calls it, once
reset(error_child=True)
job = run(expect_error=True)
must(len(CALLS) == 1 and CALLS[0]["argv"] == EXPECT_ARGV, CALLS)
must(outcome(job)["failure"]["classification"] == "worker_error", outcome(job))
must(len(audit_rows(job)) == 1, "once, not twice")

# cancelled before execution: the program never ran, nothing to re-verify
reset()
job_id = claimed("revmod.act")
CURRENT["job"] = job_id
data = record(job_id)
data["cancel_requested_at"] = "2026-11-20T10:00:00+00:00"
h.claimed_job_path(job_id).write_text(json.dumps(data), encoding="utf-8")
h.run_job(job_id)
must(not CALLS and record(job_id)["status"] == "cancelled", CALLS)

# a hand registration, an action with no owner trigger nothing
for action_id in ("revmod.hand", "revmod.noowner"):
    reset()
    job = run(action_id)
    must(not CALLS and not audit_rows(job) and outcome(job)["status"] == "succeeded", (action_id, CALLS))

# a missing helper: silent no-op
reset(present=False)
job = run()
must(not CALLS and not audit_rows(job) and "sandbox_reverify" not in lifecycle(job) and outcome(job) == base_ok, "missing helper")

# a helper that is group or world writable, or not root-owned, is refused and never run
for label, over in (("group writable", {"mode": 0o100775}), ("world writable", {"mode": 0o100757}), ("not root", {"uid": 1000})):
    reset(**over)
    job = run()
    rows = audit_rows(job)
    must(not CALLS and len(rows) == 1 and rows[0]["detail"]["ok"] is False and "refused" in lifecycle(job) and outcome(job) == base_ok, (label, CALLS, rows))

# a failing, raising or hanging helper leaves the job exactly as without the hook
for label, over, expect in (("exit 1", {"exit": 1}, 1), ("raises", {"raise": RuntimeError("boom")}, None), ("hangs", {"hang": True}, None)):
    reset(**over)
    job = run()
    rows = audit_rows(job)
    must(len(CALLS) == 1 and len(rows) == 1 and rows[0]["detail"] == {"module": "revmod", "ok": False, "exit_code": expect}, (label, CALLS, rows))
    must("sandbox_reverify module=revmod ok=False" in lifecycle(job), (label, lifecycle(job)))
    must(outcome(job) == base_ok, (label, outcome(job), base_ok))
    got = record(job)
    must(got["status"] == "succeeded" and got["failure"] is None and got["exit_result"]["success"] is True, got)
reset(hang=True)
job = run()
must(CALLS[0]["timeout"] == 120 and "timed out after 120 s" in lifecycle(job), lifecycle(job))

# a failing hook never rescues or worsens a failed job either
reset(child_rc=3, exit=1)
job = run()
must(outcome(job)["status"] == "failed" and outcome(job)["failure"]["classification"] == "execution_failed", outcome(job))

# the source mirrors sync_sandbox_runners: no shell, the exact verb, the bound
text = (ROOT / "scripts" / "server-maintenance-helper.py").read_text(encoding="utf-8")
must('"--verify-module", owner_module' in text and "SANDBOX_REVERIFY_TIMEOUT_SECONDS = 120" in text and "shell=True" not in text, "source")

print("[TEST] PASS server maintenance sandbox reverify 1.18.29")
