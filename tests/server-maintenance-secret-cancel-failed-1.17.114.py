#!/usr/bin/env python3
"""1.17.114 regression (held Low of 1.17.113): a failed ``systemctl stop`` must not leave the secret folder of a possibly running unit to
the next sweep, and the sweep must not remove the folder of a unit that still runs.

Real scripts/server-maintenance-helper.py against temporary folders; subprocess.run is a recording fake that answers
``systemctl stop`` and ``systemctl is-active``. Covered:

1. stop fails and is-active says active: the job ends failed/cancel_failed, the folder and its file remain, cancel_job still raises;
2. the sweep keeps that folder while the unit is active (activating, deactivating and reloading count as running too);
3. the same sweep removes it once is-active says inactive (a failed unit counts as gone);
4. stop fails but is-active says inactive: the folder is removed at once;
5. stop succeeds: the folder is removed and the job is cancelled;
6. systemctl cannot be run (OSError): the folder is removed, no traceback;
7. the sweep removes the folder of an unknown or malformed job name without calling systemctl for it, and keeps a running job's folder
   without calling systemctl either.
"""
from __future__ import annotations

import base64
import importlib.util
import io
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
VALUE = "CANCEL-TEST-SECRET-do-not-leak"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


for name, attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None}, "grp": {}, "pwd": {"getpwnam": lambda n: SimpleNamespace(pw_gid=0)}}.items():
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            shim_module = types.ModuleType(name)
            shim_module.__dict__.update(attrs)
            sys.modules[name] = shim_module
for shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, shim):
        setattr(os, shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000
if not hasattr(os, "getgid"):
    os.getgid = lambda: 0

spec = importlib.util.spec_from_file_location("sm_helper_cancel_failed_1_17_114", ROOT / "scripts" / "server-maintenance-helper.py")
h = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = h
spec.loader.exec_module(h)

TMP = tempfile.TemporaryDirectory()
BASE = Path(TMP.name)
HSTATE, HREG, HACT, HRUN = BASE / "hstate", BASE / "hreg", BASE / "hact", BASE / "run" / "secrets"
for p in (HSTATE, HREG, HACT):
    p.mkdir()
h.STATE_ROOT, h.JOBS_ROOT, h.CANCEL_ROOT = HSTATE, HSTATE / "jobs", HSTATE / "cancel-requests"
h.LOGS_ROOT, h.RUNNING_ROOT, h.AUDIT_FILE, h.LOCK_FILE = HSTATE / "logs", HSTATE / "running", HSTATE / "audit.jsonl", HSTATE / "server-maintenance.lock"
h.REGISTRY_ROOT, h.ACTION_ROOT, h.SECRETS_ROOT = HREG, HACT, HRUN
h.validate_executable = lambda value: Path(str(value))
h.load_config = dict
for p in (h.JOBS_ROOT, h.CANCEL_ROOT, h.LOGS_ROOT, h.RUNNING_ROOT, h.signal_request_root()):
    p.mkdir()
EXE = HACT / "run.sh"
EXE.write_bytes(b"#!/bin/sh\nexit 0\n")

# --- a recording fake for subprocess.run ---------------------------------------------------------------------------------------
CALLS = []
STOP = {"returncode": 0, "stderr": ""}
ACTIVE = {"state": "active", "error": None}


def fake_run(command, **kw):
    CALLS.append(list(command))
    if command[:2] == ["systemctl", "is-active"]:
        if ACTIVE["error"]:
            raise ACTIVE["error"]
        return SimpleNamespace(returncode=0, stdout=ACTIVE["state"] + "\n", stderr="")
    if command[:2] == ["systemctl", "stop"]:
        return SimpleNamespace(returncode=STOP["returncode"], stdout="", stderr=STOP["stderr"])
    return SimpleNamespace(returncode=0, stdout="", stderr="")  # systemd-run


h.subprocess = SimpleNamespace(run=fake_run, DEVNULL=-3, PIPE=-1, TimeoutExpired=Exception, SubprocessError=Exception, Popen=None)
h.fcntl = SimpleNamespace(flock=lambda *a: None, LOCK_EX=2, LOCK_UN=8)
real_sys = h.sys


def stdin_of(data):
    stream = io.BytesIO(json.dumps(data).encode("utf-8"))
    h.sys = SimpleNamespace(stdin=SimpleNamespace(buffer=stream), stderr=real_sys.stderr, argv=real_sys.argv, exit=real_sys.exit)


def hregister(action_id, **extra):
    import hashlib

    manifest = {"id": action_id, "revision": "1", "executable": str(EXE), "argv": [], "timeout_seconds": 600, "success_exit_codes": [0], "enabled": True,
                "owner_module": "sigmod", "registered_by": "module-manifest", "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest()}
    manifest.update(extra)
    (HREG / f"{action_id}.json").write_text(json.dumps(manifest), encoding="utf-8")


hregister("sigmod.cert", permission="sigmod.renew", secret_inputs=[{"name": "dns-token", "required": True}])
ctx = {"source_module": "sigmod", "source_action": "sigmod.renew", "requested_by": "tester"}


def dispatched():
    job_id = str(uuid.uuid4())
    job = {"schema": 1, "id": job_id, "action": "sigmod.cert", "action_revision": "1", "status": "queued", "stage": "queued", "context": ctx, "parameters": {},
           "public_parameters": {}, "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None}
    h.job_path(job_id).write_text(json.dumps(job), encoding="utf-8")
    stdin_of({"dns-token": base64.b64encode(VALUE.encode()).decode()})
    h.dispatch(job_id)
    return job_id


def claimed(job_id):
    return json.loads(h.claimed_job_path(job_id).read_text(encoding="utf-8"))


def folder_of(job_id):
    return h.SECRETS_ROOT / job_id


def cancel(job_id):
    try:
        h.cancel_job(job_id)
    except RuntimeError as exc:
        return exc
    return None


def state_text():
    return "\n".join(p.read_bytes().decode("utf-8", "replace") for root in (HSTATE, HREG) for p in root.rglob("*") if p.is_file())


def is_active_calls():
    return [c for c in CALLS if c[:2] == ["systemctl", "is-active"]]


# 1. stop fails and the unit is still active: the folder stays, the job ends cancel_failed, cancel_job still raises
STOP.update(returncode=1, stderr="Failed to stop: unit is busy")
ACTIVE.update(state="active", error=None)
j1 = dispatched()
CALLS.clear()
exc = cancel(j1)
must(exc is not None and "busy" in str(exc), "cancel_job still raises when the stop fails")
job = claimed(j1)
must(job["status"] == "failed" and job["failure"]["classification"] == "cancel_failed", job)
must(folder_of(j1).is_dir() and (folder_of(j1) / "dns-token").read_bytes() == VALUE.encode(), "the folder and its file remain while the unit may still run")
must(["systemctl", "is-active", h._systemd_unit(j1)] in CALLS, "is-active was asked about the exact unit")
must(VALUE not in state_text(), "no value in the job files or the helper audit file")

# 2. the sweep keeps it while the unit is running
for running_state in ("active", "activating", "deactivating", "reloading"):
    ACTIVE["state"] = running_state
    h.sweep_secret_dirs()
    must(folder_of(j1).is_dir(), f"{running_state} counts as running: the sweep keeps the folder")

# 3. once the unit is gone the sweep removes it
ACTIVE["state"] = "inactive"
h.sweep_secret_dirs()
must(not folder_of(j1).exists(), "the sweep removes the folder as soon as the unit is gone")
ACTIVE["state"] = "failed"
j3 = dispatched()
cancel(j3)
must(not folder_of(j3).exists(), "a failed unit counts as gone")

# 4. stop fails but the unit is inactive: the folder is removed at once, the job is still failed, cancel_job still raises
ACTIVE["state"] = "inactive"
j4 = dispatched()
exc = cancel(j4)
must(exc is not None and claimed(j4)["failure"]["classification"] == "cancel_failed" and not folder_of(j4).exists(), "removed at once when the unit is inactive")

# 5. stop succeeds: the folder is removed and the job is cancelled
STOP.update(returncode=0, stderr="")
ACTIVE["state"] = "active"
j5 = dispatched()
must(cancel(j5) is None and claimed(j5)["status"] == "cancelled" and not folder_of(j5).exists(), "a successful stop removes the folder")

# 6. systemctl cannot be run: removed, no traceback
STOP.update(returncode=1, stderr="busy")
ACTIVE["error"] = OSError("systemctl not found")
j6 = dispatched()
exc = cancel(j6)
must(isinstance(exc, RuntimeError) and not folder_of(j6).exists(), "an unreadable systemctl counts as gone")
j6b = dispatched()
data = claimed(j6b)
data["status"] = "failed"
h.claimed_job_path(j6b).write_text(json.dumps(data), encoding="utf-8")
h.sweep_secret_dirs()
must(not folder_of(j6b).exists(), "the sweep also removes it when systemctl cannot be run")
ACTIVE["error"] = None

# 7. an unknown or malformed name is removed without asking systemctl
ghost = str(uuid.uuid4())
h.write_secret_dir(ghost, {"dns-token": b"GHOST"})
(h.SECRETS_ROOT / "not-a-job").mkdir()
ACTIVE["state"] = "active"
CALLS.clear()
h.sweep_secret_dirs()
must(not folder_of(ghost).exists() and not (h.SECRETS_ROOT / "not-a-job").exists(), "unknown and malformed folders are removed")
must(not is_active_calls(), "systemctl is not asked about them")

# a running job's folder is kept by the sweep, with no systemctl call
j8 = dispatched()
CALLS.clear()
h.sweep_secret_dirs()
must(folder_of(j8).is_dir() and not is_active_calls(), "a running job's folder is kept without asking systemctl")
h.finish_secrets(j8)

h.sys = real_sys
print("[TEST] PASS server maintenance secret cancel_failed 1.17.114")
