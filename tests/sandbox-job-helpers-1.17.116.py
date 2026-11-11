#!/usr/bin/env python3
"""1.17.116 regression: the two module job helpers register and unregister sandbox runners (core.sandbox Patch 1, part 3).

Same stub harness as server-maintenance-module-actions-1.17.17.py. Covered, for module-v2-job-helper.py and module-job-helper.py:

* ``manifest_declares_sandbox_runners`` is lenient and only decides (true, quiet, empty, broken, missing);
* ``sync_sandbox_runners`` asks the root helper for --register-module when the manifest declares runners and for --unregister-module when it
  declares none (that is how an upgrade drops stale runners) or on removal; a failure raises a plain message that names the module;
* helper missing and nothing declared: no call and no error, so a module without runners and a server without the helper are not touched;
  helper missing and runners declared: a plain error so the job fails; a writable or non-root helper is never run;
* flows: v2 install registers the sandbox runners after the server-maintenance actions, a failed registration fails the job and the rollback
  restores and re-registers (or unregisters), v1 install registers after the server-maintenance step and uninstall unregisters;
* the existing server-maintenance calls and their order are unchanged.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
HARNESS = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
_source = HARNESS.read_text(encoding="utf-8")
G = {"__name__": "stubs", "__file__": str(HARNESS)}
exec(compile(_source[: _source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")], str(HARNESS), "exec"), G)
must, ROOT = G["must"], G["ROOT"]
v2 = G["helper"]
BASE = Path(tempfile.mkdtemp(prefix="tectac-sandbox-jobs-"))
v1_path = ROOT / "scripts" / "module-job-helper.py"
v2_path = ROOT / "scripts" / "module-v2-job-helper.py"
v1 = types.ModuleType("module_job_helper_sandbox")
v1.__file__ = str(v1_path)
exec(compile(v1_path.read_text(encoding="utf-8").replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(v1_path), "exec"), v1.__dict__)


class Log:
    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass


class RootOwned:
    st_uid, st_mode = 0, 0o100755


for label, mod in (("v2", v2), ("v1", v1)):
    repo = BASE / f"repo-{label}"
    for name, declares in (("declares", True), ("quiet", False)):
        folder = repo / "extensions" / name
        folder.mkdir(parents=True, exist_ok=True)
        payload = {"id": name, "type": "extension", "version": "1.0.0"}
        if declares:
            payload["sandbox_runners"] = [{"id": f"{name}.run", "description": "x", "executable": "sandbox/runners/run.sh"}]
        (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")
    for name, text in (("empty", json.dumps({"id": "empty", "sandbox_runners": []})), ("broken", "{not json"),
                       ("notlist", json.dumps({"id": "notlist", "sandbox_runners": "yes"})), ("only_maintenance", json.dumps({"id": "only_maintenance", "server_maintenance_actions": [{"id": "x"}]}))):
        (repo / "extensions" / name).mkdir(parents=True, exist_ok=True)
        (repo / "extensions" / name / "tec_tac.json").write_text(text, encoding="utf-8")
    must(mod.manifest_declares_sandbox_runners(repo, "declares") is True, label)
    must(all(mod.manifest_declares_sandbox_runners(repo, name) is False for name in ("quiet", "empty", "broken", "notlist", "only_maintenance", "missing")), label)
    must(mod.manifest_declares_server_actions(repo, "only_maintenance") is True and mod.manifest_declares_server_actions(repo, "declares") is False, "the two decisions are independent")

    RUNS = []
    mod.privileged_env = lambda extra=None: {}
    helper_file = BASE / f"sandbox-helper-{label}"
    helper_file.write_text("#!/bin/sh\n", encoding="utf-8")
    mod.SANDBOX_HELPER = helper_file
    result = {"rc": 0}
    mod.subprocess = types.SimpleNamespace(run=lambda command, **kw: RUNS.append(command) or types.SimpleNamespace(returncode=result["rc"]), PIPE=-1, STDOUT=-2)
    real_path_stat = Path.stat
    Path.stat = lambda self, *a, **k: RootOwned() if self == helper_file else real_path_stat(self, *a, **k)
    try:
        log = Log()
        mod.sync_sandbox_runners(repo, "declares", log)
        must(RUNS[-1] == [str(helper_file), "--register-module", "declares"], RUNS)
        must("[TEC-TAC-SANDBOX] registering sandbox runners of declares" in log.text, log.text)
        # not declared but the helper is there: --unregister-module (an upgrade drops stale runners; a module that now declares none loses all)
        mod.sync_sandbox_runners(repo, "quiet", log)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "quiet"], RUNS)
        mod.sync_sandbox_runners(repo, "empty", log)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "empty"], RUNS)
        mod.sync_sandbox_runners(repo, "broken", log)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "broken"], "an unreadable manifest is never registered")
        # remove: always unregister, even if the manifest still declares
        mod.sync_sandbox_runners(repo, "declares", log, remove=True)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "declares"], RUNS)
        # a failure raises a plain message that names the module and points at the log
        result["rc"] = 3
        for kwargs, word in (({}, "registration"), ({"remove": True}, "removal")):
            try:
                mod.sync_sandbox_runners(repo, "declares", log, **kwargs)
                raise AssertionError("a helper failure must fail the job")
            except RuntimeError as exc:
                must(word in str(exc) and "declares" in str(exc) and "status 3" in str(exc) and "job log" in str(exc) and "sandbox" in str(exc), exc)
        result["rc"] = 0
        # the sandbox helper is not installed: a module that declares nothing is not touched, one that declares is refused plainly
        mod.SANDBOX_HELPER = BASE / "no-such-helper"
        before_runs = len(RUNS)
        mod.sync_sandbox_runners(repo, "quiet", log)
        mod.sync_sandbox_runners(repo, "declares", log, remove=True)
        mod.sync_sandbox_runners(repo, "missing", log)
        must(len(RUNS) == before_runs, "nothing runs when there is nothing to do and no helper")
        try:
            mod.sync_sandbox_runners(repo, "declares", log)
            raise AssertionError("a declaring module needs the helper")
        except RuntimeError as exc:
            must("not installed" in str(exc) and "declares" in str(exc) and "sandbox" in str(exc), exc)
        # a helper that is not root-owned, or is writable, is never run
        mod.SANDBOX_HELPER = helper_file
        RootOwned.st_uid = 1000
        before_runs = len(RUNS)
        try:
            mod.sync_sandbox_runners(repo, "declares", log)
            raise AssertionError("a non-root helper must be refused")
        except RuntimeError as exc:
            must("non-root-owned" in str(exc), exc)
        RootOwned.st_uid = 0
        RootOwned.st_mode = 0o100775
        try:
            mod.sync_sandbox_runners(repo, "quiet", log, remove=True)
            raise AssertionError("a writable helper must be refused")
        except RuntimeError as exc:
            must("writable" in str(exc), exc)
        must(len(RUNS) == before_runs, "a refused helper is never run")
    finally:
        Path.stat = real_path_stat
        RootOwned.st_uid, RootOwned.st_mode = 0, 0o100755
    text = (v1_path if label == "v1" else v2_path).read_text(encoding="utf-8")
    must('SANDBOX_HELPER = Path("/usr/local/sbin/tec-tac-sandbox")' in text, label)
    must(text.index("def sync_server_maintenance_actions(") < text.index("def sync_sandbox_runners("), "the sandbox companion sits after the existing one")
    # the existing helper constant and the existing calls are untouched
    must('SERVER_MAINTENANCE_HELPER = Path("/usr/local/sbin/tec-tac-server-maintenance")' in text, label)

# ---- v2 flow: order, rollback, plain failure
EVENTS = []
v2_log_dir = BASE / "v2-flow"
v2_log_dir.mkdir()
v2.LOGS_ROOT = v2_log_dir
v2.RUNNING_ROOT = v2_log_dir / "running"
v2.BACKUP_ROOT = v2_log_dir / "backup"
v2.RUNNING_ROOT.mkdir()
v2.BACKUP_ROOT.mkdir()
JOB = "00000000-0000-4000-8000-0000000000f3"
JOBS = {}
FAIL_ON = {"module": None, "kind": None}
repo_flow = BASE / "repo-flow"
(repo_flow / "extensions").mkdir(parents=True)
v2.load_job = lambda job_id: (v2_log_dir / "job.json", {"status": "dispatched", "stage": "dispatched", "created_at": "2026-11-11"})
v2.load_running_request = lambda job_id: (None, {"id": JOB, "action": "batch_install", "plugin_id": "a", "package_sha256": "x"})
v2.acquire_lifecycle_lock = lambda: None
v2.load_config = lambda: {"REPO_ROOT": str(repo_flow)}
v2._snapshot_v2_job_artifacts = lambda job_id, job, running: job
v2._verify_v2_job_trust = lambda config, job: None
v2.batch_packages = lambda job, running, trust: [{"id": "a", "path": "a.zip"}, {"id": "b", "path": "b.zip"}]
v2._validate_install_plan_against_signed_artifacts = lambda job, packages, trust: (["a", "b"], [{"id": "a", "action": "install", "version": "1.0.0"}, {"id": "b", "action": "install", "version": "1.0.0"}])
v2.read_installed_manifests = lambda repo_root: {}
v2.verify_install_disables = lambda *a, **k: []
v2.verify_install_categories = lambda *a, **k: {}
v2.remember_version = lambda *a, **k: EVENTS.append("remember")
v2.cleanup_successful_stage = lambda job, log: EVENTS.append("cleanup")
v2._cleanup_claimed_job_inputs = lambda job_id: None
v2._confirmed_disable_modules = lambda job: []
v2.install_packages = lambda repo_root, packages, order, actions, log, backup, prepare=None: EVENTS.append("install") or list(order)
v2.sync_and_reload = lambda config, log, **kw: EVENTS.append("sync")
v2.restore_modules = lambda repo_root, ids, backup, log: EVENTS.append(("restore", list(ids)))
v2.atomic_json = lambda path, payload, mode=0o640, **kw: JOBS.__setitem__("last", dict(payload))


def v2_maint(repo_root, module_id, log, *, remove=False):
    EVENTS.append(("maint-remove" if remove else "maint-register", module_id))


def v2_sandbox(repo_root, module_id, log, *, remove=False):
    EVENTS.append(("sandbox-remove" if remove else "sandbox-register", module_id))
    if FAIL_ON["module"] == module_id and not remove:
        raise RuntimeError(f"sandbox runner registration failed for module {module_id} (status 5). See the job log for the reason.")


v2.sync_server_maintenance_actions = v2_maint
v2.sync_sandbox_runners = v2_sandbox
real_os_chown = getattr(os, "chown", None)
real_os_chmod = os.chmod
os.chown, os.chmod = (lambda *a, **k: None), (lambda *a, **k: None)
try:
    v2.run_job(JOB)
    job = JOBS["last"]
    must(job["status"] == "succeeded", job)
    must(EVENTS == ["install", "remember", "remember", "sync", ("maint-register", "a"), ("maint-register", "b"), ("sandbox-register", "a"), ("sandbox-register", "b"), "cleanup"], EVENTS)
    # a registration failure fails the job with a plain message and takes the rollback: restore, then re-register or remove (both families)
    del EVENTS[:]
    (repo_flow / "extensions" / "a").mkdir()
    (repo_flow / "extensions" / "a" / "tec_tac.json").write_text("{}", encoding="utf-8")   # a restored version of a exists, b has none
    FAIL_ON["module"] = "b"
    shutil.rmtree(v2.RUNNING_ROOT / JOB)
    v2.run_job(JOB)
    job = JOBS["last"]
    must(job["status"] == "failed" and "sandbox runner registration failed for module b" in job["error"] and "job log" in job["error"], job)
    tail = EVENTS[EVENTS.index(("sandbox-register", "b")) + 1:]
    must(tail[0] == ("restore", ["a", "b"]), tail)
    must(tail[1:3] == [("maint-register", "a"), ("maint-remove", "b")], tail)       # the existing restore, unchanged
    must(tail[3:5] == [("sandbox-register", "a"), ("sandbox-remove", "b")], tail)   # the new companion, right after it
    must("cleanup" not in EVENTS, "a failed job keeps its staged files")
    # a restore step that itself fails never hides the original error
    del EVENTS[:]
    v2.sync_sandbox_runners = lambda repo_root, module_id, log, *, remove=False: (_ for _ in ()).throw(RuntimeError("helper down"))
    log = Log()
    v2.restore_sandbox_runners(repo_flow, ["a", "b"], log)
    must("restoring sandbox runners of a failed" in log.text and "restoring sandbox runners of b failed" in log.text, log.text)
finally:
    if real_os_chown is not None:
        os.chown = real_os_chown
    os.chmod = real_os_chmod

# source checks that the flow above does not stage (a rename), and the ordering in the file
v2_text = v2_path.read_text(encoding="utf-8")
start = v2_text.index('job["stage"] = "sandbox-runners"')
block = v2_text[start:v2_text.index("cleanup_successful_stage(job, log)", start)]
must('action.get("action") == "rename"' in block and "remove=True" in block and "for module_id in order:" in block, "a rename drops the old id's runners")
must(v2_text.index('job["stage"] = "server-maintenance-actions"') < start, "sandbox registration comes after the server-maintenance step")
must(v2_text.index("restore_server_maintenance_actions(repo_root, backup_ids, log)\n                    restore_sandbox_runners(repo_root, backup_ids, log)") > 0, "rollback re-registers after the existing restore")
must(v2_text.index("sync_and_reload(config, log, refresh_workers=True)\n                    # 1.17.17") < start, "registration comes after the runtime sync")

# ---- v1 flow: install registers after the server-maintenance step, uninstall unregisters, a failure fails the job
v1_text = v1_path.read_text(encoding="utf-8")
inst = v1_text.index('job["stage"] = "sandbox-runners"')
must(v1_text.index("sync_server_maintenance_actions(repo_root, job[\"plugin_id\"], log)\n") < inst < v1_text.index("except Exception as exc:", inst), "install registers after the server-maintenance step")
must('sync_server_maintenance_actions(repo_root, job["plugin_id"], log, remove=True)\n                    # 1.17.116: and its sandbox runners.\n                    sync_sandbox_runners(repo_root, job["plugin_id"], log, remove=True)' in v1_text, "uninstall unregisters")
V1_TMP = Path(tempfile.mkdtemp(prefix="tectac-v1-sandbox-"))
RUNNING, REQUESTS, LOGS, JOBS_DIR = V1_TMP / "running", V1_TMP / "running" / "requests", V1_TMP / "logs", V1_TMP / "jobs"
REPO1 = V1_TMP / "repo"
for folder in (RUNNING, REQUESTS, LOGS, JOBS_DIR, REPO1 / "scripts", REPO1 / "extensions" / "demo"):
    folder.mkdir(parents=True, exist_ok=True)
for script in ("install-extension.sh", "remove-extension.sh"):
    (REPO1 / "scripts" / script).write_text("#!/bin/bash\n", encoding="utf-8")
v1.RUNNING_ROOT, v1.RUNNING_REQUEST_ROOT, v1.LOGS_ROOT, v1.JOBS_ROOT = RUNNING, REQUESTS, LOGS, JOBS_DIR
V1_WRITES, V1_EVENTS = [], []
v1.load_config = lambda: {"REPO_ROOT": str(REPO1), "UI_SYNC_SCRIPT": str(V1_TMP / "no-sync.sh"), "TEC_TAC_ENVIRONMENT": "development"}
v1.acquire_lifecycle_lock = lambda: None
v1._privileged_verify_package = lambda config, job: None
v1.privileged_env = lambda extra=None: {}
v1.development_server = lambda: True
v1.package_category = lambda package, plugin_id: "server"
v1.remember_category = lambda plugin_id, category: None
v1.forget_module_state = lambda plugin_id, log=None: V1_EVENTS.append("forget")
v1.plan_remove_hand_back = lambda repo_root, plugin_id, enable: []
v1.atomic_json = lambda path, payload, mode=0o640, **kw: V1_WRITES.append(dict(payload))
v1.subprocess = types.SimpleNamespace(run=lambda command, **kw: V1_EVENTS.append(("lifecycle", Path(command[1]).name)) or types.SimpleNamespace(returncode=0), PIPE=-1, STDOUT=-2)
real_stat_v1, real_chmod_v1 = Path.stat, os.chmod


class V1Root:
    st_uid, st_mode = 0, 0o100755


Path.stat = lambda self, *a, **k: V1Root() if str(self).startswith(str(REPO1)) else real_stat_v1(self, *a, **k)
os.chmod = lambda *a, **k: None
FAIL_V1 = {"on": False}


def stage(action):
    run_dir = RUNNING / JOB
    run_dir.mkdir(exist_ok=True)
    package = run_dir / "package.zip"
    package.write_bytes(b"PK")
    request = {"id": JOB, "action": action, "plugin_id": "demo", "replace": False, "package_path": str(package), "upload_id": JOB}
    (REQUESTS / f"{JOB}.json").write_text(json.dumps(request), encoding="utf-8")
    v1.load_job = lambda job_id: (JOBS_DIR / f"{JOB}.json", {"id": JOB, "action": action, "status": "dispatched", "stage": "dispatched", "created_at": "2026-11-11"})
    v1.load_running_request = lambda job_id: (REQUESTS / f"{JOB}.json", dict(request))
    del V1_WRITES[:], V1_EVENTS[:]


v1.sync_server_maintenance_actions = lambda repo_root, module_id, log, *, remove=False: V1_EVENTS.append(("maint-remove" if remove else "maint-register", module_id))


def v1_sandbox(repo_root, module_id, log, *, remove=False):
    V1_EVENTS.append(("sandbox-remove" if remove else "sandbox-register", module_id))
    if FAIL_V1["on"]:
        raise RuntimeError("sandbox runner registration failed for module demo (status 9). See the job log for the reason.")


v1.sync_sandbox_runners = v1_sandbox
try:
    stage("install")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "succeeded" and V1_EVENTS == [("lifecycle", "install-extension.sh"), ("maint-register", "demo"), ("sandbox-register", "demo")], (V1_WRITES[-1], V1_EVENTS))
    stage("remove")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "succeeded" and V1_EVENTS == [("lifecycle", "remove-extension.sh"), "forget", ("maint-remove", "demo"), ("sandbox-remove", "demo")], V1_EVENTS)
    FAIL_V1["on"] = True
    stage("install")
    v1.run_job(JOB)
    job = V1_WRITES[-1]
    must(job["status"] == "failed" and "sandbox runner registration failed for module demo" in job["error"] and "job log" in job["error"], job)
    stage("remove")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "failed" and "demo" in V1_WRITES[-1]["error"], "a failed removal of the runners fails the job")
finally:
    Path.stat, os.chmod = real_stat_v1, real_chmod_v1

# the CRLF guard: both helpers stay LF only
for path in (v1_path, v2_path, ROOT / "scripts" / "sandbox-helper.py"):
    must(b"\r" not in path.read_bytes(), f"{path.name} has a carriage return")

print("[TEST] PASS sandbox job helpers 1.17.116")
