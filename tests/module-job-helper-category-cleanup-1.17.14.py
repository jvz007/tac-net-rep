#!/usr/bin/env python3
"""1.17.14 regression: a category-refused v1 install runs the job's end-of-run cleanup (held Low from the 1.17.13-1 review).

scripts/module-job-helper.py ``run_job``: the AD-21 check on an install used to ``return`` early. That left the root-private package
snapshot ``RUNNING_ROOT/<job id>`` (copied by ``claim_job``) on disk and the log without its ``0o640`` mode. It now sets the failed status
and the error and falls through to the shared tail, which chmods the log, removes the running request and removes ``RUNNING_ROOT/<job id>``.
The refusal itself (install only, CQ38) is unchanged, and an allowed install runs exactly as before.

The helper is loaded the way tests/module-category-helper-1.17.13.py loads the v2 helper (the stubs of tests/module-replacement-helper-
handback-1.17.12.py supply ``fcntl`` and friends). Its lifecycle scripts, state folders and root-ownership checks are replaced by temporary
folders and stubs. What cannot run here: the helper as root, a real install script, a real dispatch.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
HARNESS = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
source = HARNESS.read_text(encoding="utf-8")
H = {"__name__": "stubs", "__file__": str(HARNESS)}
exec(compile(source[:source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")], str(HARNESS), "exec"), H)
must, ROOT = H["must"], H["ROOT"]

V1_PATH = ROOT / "scripts" / "module-job-helper.py"
helper = types.ModuleType("module_job_helper_cleanup")
helper.__file__ = str(V1_PATH)
for _name in ("pwd",):
    sys.modules.setdefault(_name, types.ModuleType(_name))
exec(compile(V1_PATH.read_text(encoding="utf-8").replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(V1_PATH), "exec"), helper.__dict__)

TMP = Path(tempfile.mkdtemp(prefix="tectac-v1-cleanup-"))
RUNNING, REQUESTS, LOGS, JOBS = TMP / "running", TMP / "running" / "requests", TMP / "logs", TMP / "jobs"
REPO = TMP / "repo"
for folder in (RUNNING, REQUESTS, LOGS, JOBS, REPO / "scripts"):
    folder.mkdir(parents=True, exist_ok=True)
for script in ("install-extension.sh", "remove-extension.sh"):
    (REPO / "scripts" / script).write_text("#!/bin/bash\n", encoding="utf-8")
helper.RUNNING_ROOT, helper.RUNNING_REQUEST_ROOT, helper.LOGS_ROOT, helper.JOBS_ROOT = RUNNING, REQUESTS, LOGS, JOBS

JOB_ID = "00000000-0000-4000-8000-0000000000c1"
WRITES = []
CHMODS = []
RUNS = []
STATE = {"development": False, "category": ""}

helper.load_config = lambda: {"REPO_ROOT": str(REPO), "UI_SYNC_SCRIPT": str(TMP / "no-such-sync.sh"), "TEC_TAC_ENVIRONMENT": "production"}
helper.acquire_lifecycle_lock = lambda: None
helper._privileged_verify_package = lambda config, job: None
helper.privileged_env = lambda extra=None: {}
helper.development_server = lambda: STATE["development"]
helper.package_category = lambda package, plugin_id: STATE["category"]
helper.remember_category = lambda plugin_id, category: WRITES.append(("remember", plugin_id, category))
helper.atomic_json = lambda path, payload, mode=0o640, **kw: WRITES.append(("json", dict(payload)))
helper.subprocess = types.SimpleNamespace(run=lambda command, **kw: RUNS.append(command) or types.SimpleNamespace(returncode=0), PIPE=subprocess.PIPE, STDOUT=subprocess.STDOUT)
real_chmod = os.chmod
os.chmod = lambda path, mode, *a, **k: CHMODS.append((str(path), mode))
real_stat = Path.stat


class RootOwned:
    """Stands in for the root-ownership check of the lifecycle scripts: a root-owned file nobody else can write."""
    st_uid, st_mode = 0, 0o100755


def fake_stat(self, *a, **k):
    return RootOwned() if str(self).startswith(str(REPO)) else real_stat(self, *a, **k)


Path.stat = fake_stat


def stage_job(action="install"):
    """What claim_job leaves behind: the running request, the root-private package snapshot and the job file."""
    run_dir = RUNNING / JOB_ID
    run_dir.mkdir(exist_ok=True)
    package = run_dir / "package.zip"
    package.write_bytes(b"PK-not-a-real-package")
    request = {"id": JOB_ID, "action": action, "plugin_id": "demo", "replace": False, "package_path": str(package), "upload_id": JOB_ID}
    (REQUESTS / f"{JOB_ID}.json").write_text(json.dumps(request), encoding="utf-8")
    helper.load_job = lambda job_id: (JOBS / f"{JOB_ID}.json", {"id": JOB_ID, "action": action, "status": "dispatched", "stage": "dispatched", "created_at": "2026-10-09"})
    helper.load_running_request = lambda job_id: (REQUESTS / f"{JOB_ID}.json", dict(request))
    del WRITES[:], CHMODS[:], RUNS[:]
    return run_dir, package


def last_job():
    return [item[1] for item in WRITES if item[0] == "json"][-1]


try:
    # ------------------------------------------------------------------------------------------ a refused install, off a development server
    for category in ("", "test"):
        STATE.update(development=False, category=category)
        run_dir, package = stage_job()
        helper.run_job(JOB_ID)
        job = last_job()
        must(job["status"] == "failed" and job["error_type"] == "CategoryRefused" and "not a development server" in job["error"], job)
        must(job["finished_at"], "the job records when it finished")
        must(not run_dir.exists(), "RUNNING_ROOT/<job id>, the package snapshot, is removed")
        must(not (REQUESTS / f"{JOB_ID}.json").exists(), "the running request is removed")
        must((str(LOGS / f"{JOB_ID}.log"), 0o640) in CHMODS, CHMODS)
        must(RUNS == [] and not any(item[0] == "remember" for item in WRITES), "nothing was installed and no category was remembered")
        log = (LOGS / f"{JOB_ID}.log").read_text(encoding="utf-8")
        must("category check failed" in log and "started" not in log, log)
        (LOGS / f"{JOB_ID}.log").unlink()
    # an unreadable package fails closed the same way, and also cleans up
    helper.package_category = lambda package, plugin_id: (_ for _ in ()).throw(RuntimeError("module manifest is unreadable"))
    run_dir, package = stage_job()
    helper.run_job(JOB_ID)
    job = last_job()
    must(job["status"] == "failed" and job["error_type"] == "CategoryRefused" and "unreadable" in job["error"] and not run_dir.exists(), job)
    must(not (REQUESTS / f"{JOB_ID}.json").exists() and (str(LOGS / f"{JOB_ID}.log"), 0o640) in CHMODS, "cleanup ran")
    (LOGS / f"{JOB_ID}.log").unlink()
    helper.package_category = lambda package, plugin_id: STATE["category"]

    # ------------------------------------------------------------------------------------------ an allowed install is unchanged
    for development, category in ((True, ""), (False, "core"), (False, "premium")):
        STATE.update(development=development, category=category)
        run_dir, package = stage_job()
        helper.run_job(JOB_ID)
        job = last_job()
        must(job["status"] == "succeeded" and job["stage"] == "complete" and job["error"] is None and job["error_type"] is None, (development, category, job))
        must(len(RUNS) == 1 and RUNS[0][1].endswith("install-extension.sh") and RUNS[0][2] == str(package), RUNS)
        must(("remember", "demo", category) in WRITES, "the category is written after a successful install")
        must(not run_dir.exists() and not package.exists() and not (REQUESTS / f"{JOB_ID}.json").exists(), "the same cleanup as before")
        must((str(LOGS / f"{JOB_ID}.log"), 0o640) in CHMODS, CHMODS)
        (LOGS / f"{JOB_ID}.log").unlink()
    # a failing lifecycle command is still a failure with its own error, and still cleans up
    STATE.update(development=True, category="")
    helper.subprocess.run = lambda command, **kw: types.SimpleNamespace(returncode=7)
    run_dir, package = stage_job()
    helper.run_job(JOB_ID)
    job = last_job()
    must(job["status"] == "failed" and job["error_type"] == "LifecycleCommandError" and "status 7" in job["error"] and not run_dir.exists(), job)
    (LOGS / f"{JOB_ID}.log").unlink()
    # a remove job never judges a category
    helper.subprocess.run = lambda command, **kw: RUNS.append(command) or types.SimpleNamespace(returncode=0)
    STATE.update(development=False, category="")
    run_dir, package = stage_job("remove")
    helper.forget_module_state = lambda plugin_id, log=None: None
    helper.run_job(JOB_ID)
    must(last_job()["status"] == "succeeded" and RUNS and RUNS[0][1].endswith("remove-extension.sh"), last_job())
finally:
    os.chmod = real_chmod
    Path.stat = real_stat

# the source has no early return left after the category check
text = V1_PATH.read_text(encoding="utf-8")
block = text[text.index("# AD-21 (1.17.13): re-check the category from the root-private package"):text.index("rc = 1\n    if command is not None:")]
must(not re.search(r"^\s+return", block, re.M), "the category check no longer returns early")
must("category_failed = True" in block and "CategoryRefused" in block, "the failure falls through to the shared tail")

print("[TEST] PASS module job helper category cleanup 1.17.14")
