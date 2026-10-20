#!/usr/bin/env python3
"""1.17.59 regression: a confirmed replacement installs with its replaced module already disabled (CQ169).

dev02 saw it: installing Advanced Patch Management 0.11.2 while Windows Patching was enabled failed with status 1. Both modules
were enabled during the install shell, Core's loader dropped the replacement, and the migration shell raised
ModuleNotFoundError. The fix moves the confirmed disable BEFORE the replacement's own install-extension.sh run, inside the same
root job, after the backup of code and module state. The rollback re-enables it on any failure.

This test loads scripts/module-v2-job-helper.py with the Linux-only pieces stubbed (the loader and stubs of
tests/module-replacement-helper-1.17.11.py), but runs the REAL install_packages. subprocess.run is replaced by a fake of
install-extension.sh that copies the manifest into the temporary repo and then FAILS with status 1 and
"ModuleNotFoundError: No module named" when the module state shows the replacement and its replaced module both enabled.
On 1.17.58 this test fails. What cannot run here: the helper as root, the real install-extension.sh with Django, a real reload.
"""
from __future__ import annotations

import ast
import io
import itertools
import json
import os
import sys
import tarfile
import tempfile
import types
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


for _name, _attrs in {"fcntl": dict(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, LOCK_NB=4, flock=lambda *a: None),
                      "pwd": dict(getpwnam=lambda name: types.SimpleNamespace(pw_gid=0))}.items():
    _module = types.ModuleType(_name)
    _module.__dict__.update(_attrs)
    sys.modules.setdefault(_name, _module)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    sys.modules.setdefault(_name, types.ModuleType(_name))
sys.modules.setdefault("cryptography.hazmat.primitives.serialization", types.ModuleType("cryptography.hazmat.primitives.serialization"))
_ed = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
_ed.Ed25519PublicKey = object
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.ed25519", _ed)
_exc = types.ModuleType("cryptography.exceptions")
_exc.InvalidSignature = Exception
sys.modules.setdefault("cryptography.exceptions", _exc)
for _shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, _shim):
        setattr(os, _shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 0

# ------------------------------------------------------------------------------------------ load the helper
HELPER = ROOT / "scripts" / "module-v2-job-helper.py"
source = HELPER.read_text(encoding="utf-8")
LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"
must(source.count(LOOKUP) == 1, "the trusted-bash lookup line moved; update this test")
helper = types.ModuleType("module_v2_job_helper")
helper.__file__ = str(HELPER)
exec(compile(source.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(HELPER), "exec"), helper.__dict__)
helper.development_server = lambda: True

TMP = Path(tempfile.mkdtemp(prefix="tectac-order-"))
REPO = TMP / "repo"
(REPO / "extensions").mkdir(parents=True)
(REPO / "scripts").mkdir()
(REPO / "scripts" / "install-extension.sh").write_text("#!/bin/bash\n", encoding="utf-8")
PACKAGES = TMP / "packages"
PACKAGES.mkdir()
STATE_FILE = TMP / "module-state.json"
helper.MODULE_STATE = STATE_FILE
helper.STATE_ROOT = TMP / "mm"
helper.JOBS_ROOT = helper.STATE_ROOT / "jobs"
helper.RUNNING_ROOT = helper.STATE_ROOT / "running-v2"
helper.LOGS_ROOT = helper.STATE_ROOT / "logs"
helper.BACKUP_ROOT = helper.STATE_ROOT / "bundle-backups"
for _folder in (helper.JOBS_ROOT, helper.RUNNING_ROOT, helper.LOGS_ROOT, helper.BACKUP_ROOT):
    _folder.mkdir(parents=True)


class Handle:
    def fileno(self):
        return 0

    def close(self):
        pass


helper.module_state_lock = lambda exclusive=True: Handle()
helper.atomic_json = lambda path, payload, mode=0o640, **kw: Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
helper._manifest_stat_ok = lambda info: True  # this PC has no root-owned files; the reader's rule is tested in 1.17.11
helper.require_root_owned = lambda path: None
helper.acquire_lifecycle_lock = lambda: None
helper.load_config = lambda: {"REPO_ROOT": str(REPO)}
helper._snapshot_v2_job_artifacts = lambda job_id, job, root: job
helper._verify_v2_job_trust = lambda config, job: [{}]
helper._cleanup_claimed_job_inputs = lambda job_id: None
helper.cleanup_successful_stage = lambda job, log: EVENTS.append("cleanup")
helper.sync_server_maintenance_actions = lambda *a, **k: EVENTS.append("actions")
helper.restore_server_maintenance_actions = lambda *a, **k: None

EVENTS = []
SYNC = {"fail_first": 0}
FAIL_SCRIPT = set()  # module ids whose install shell fails outright
SCRIPTS = []  # (module id, replaced module's flag at the time the script ran)

PATCHING_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
PM_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.1.0", "patching.extra": "1.0.0"}


def manifest(module_id, **more):
    return {"id": module_id, "type": "extension", "version": "1.0.0", **more}


def put(module_id, **more):
    folder = REPO / "extensions" / module_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps(manifest(module_id, **more)), encoding="utf-8")


def zip_package(module_id, payload=None, name=None):
    path = PACKAGES / f"{module_id}-{next(COUNTER)}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name or f"extensions/{module_id}/tec_tac.json", json.dumps(payload if payload is not None else manifest(module_id)))
    return path


COUNTER = itertools.count(1)
PACKAGE_OF = {}  # module id -> package path used by the stubbed package readers


def flags():
    return {name: record.get("enabled") for name, record in json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"].items()}


def world(state, extensions):
    for folder in list((REPO / "extensions").iterdir()):
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()
    for module_id, more in extensions.items():
        put(module_id, **more)
    STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {name: {"enabled": on} for name, on in state.items()}}), encoding="utf-8")


def read_flag(module_id):
    modules = json.loads(STATE_FILE.read_text(encoding="utf-8")).get("modules", {})
    return bool((modules.get(module_id) or {}).get("enabled", True))


def fake_run(command, stdout=None, stderr=None, text=None, env=None, **kw):
    """A fake of install-extension.sh: copy the manifest in, then fail the way dev02 saw it when both modules are enabled."""
    package = Path(command[2])
    with zipfile.ZipFile(package) as archive:
        name = next(n for n in archive.namelist() if n.endswith("tec_tac.json"))
        payload = json.loads(archive.read(name).decode("utf-8"))
    module_id = payload["id"]
    EVENTS.append(f"script:{module_id}")
    replaced = payload.get("replaces")
    SCRIPTS.append((module_id, read_flag(replaced) if replaced else None))
    target = REPO / "extensions" / module_id
    if "--replace" in command and target.exists():
        for child in target.iterdir():
            child.unlink()
        target.rmdir()
    target.mkdir(parents=True, exist_ok=True)
    (target / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")
    if module_id in FAIL_SCRIPT:
        stdout.write("[TEC-TAC] the install shell broke\n")
        return types.SimpleNamespace(returncode=1)
    if replaced and read_flag(replaced) and read_flag(module_id):
        stdout.write("Traceback (most recent call last):\nModuleNotFoundError: No module named 'tec_tac_modules.%s'\n" % module_id)
        return types.SimpleNamespace(returncode=1)
    return types.SimpleNamespace(returncode=0)


helper.subprocess = types.SimpleNamespace(run=fake_run, PIPE=-1, STDOUT=-2)


def fake_sync(config, log, *, refresh_workers=False):
    EVENTS.append("sync")
    if SYNC["fail_first"]:
        SYNC["fail_first"] -= 1
        raise RuntimeError("Tactical graceful reload failed with status 1")


helper.sync_and_reload = fake_sync


def fake_packages(job, running, root_trust):
    return [{"id": item["id"], "path": str(PACKAGE_OF[item["id"]]), "source": None} for item in job["plan"]["actions"]]


helper.batch_packages = fake_packages
helper.bundle_packages = fake_packages
helper._validate_install_plan_against_signed_artifacts = lambda job, packages, root_trust: (list(job["plan"]["order"]), [dict(a) for a in job["plan"]["actions"]])

_real_backup, _real_verify, _real_remember, _real_prepare = (helper.backup_modules, helper.verify_install_disables, helper.remember_version,
                                                            helper.apply_install_prepare_disable)


def spy_backup(*a, **k):
    EVENTS.append("backup")
    return _real_backup(*a, **k)


def spy_verify(*a, **k):
    EVENTS.append("verify")
    return _real_verify(*a, **k)


def spy_remember(*a, **k):
    EVENTS.append("remember")
    return _real_remember(*a, **k)


def spy_prepare(*a, **k):
    done = _real_prepare(*a, **k)
    if done:
        EVENTS.append("pre-disable")
    return done


helper.backup_modules, helper.verify_install_disables, helper.remember_version, helper.apply_install_prepare_disable = (
    spy_backup, spy_verify, spy_remember, spy_prepare)


def run(job):
    job_id = "00000000-0000-4000-8000-%012d" % next(COUNTER)
    job = {"id": job_id, **job}
    path = helper.JOBS_ROOT / f"{job_id}.json"
    status = {"id": job_id, "action": job["action"], "status": "dispatched", "stage": "dispatched", "created_at": "2026-10-20T10:00:00"}
    path.write_text(json.dumps(status), encoding="utf-8")
    helper.load_job = lambda jid: (path, dict(status))
    helper.load_running_request = lambda jid: (None, dict(job))
    EVENTS.clear()
    SCRIPTS.clear()
    helper.run_job(job_id)
    return json.loads(path.read_text(encoding="utf-8"))


def plan(*items):
    return {"order": [i[0] for i in items], "actions": [{"id": i[0], "action": i[1], "version": "1.0.0"} for i in items]}


def stage(*ids, **manifests):
    for module_id in ids:
        PACKAGE_OF[module_id] = zip_package(module_id, manifest(module_id, **manifests.get(module_id, {})))


APM = {"replaces": "patching", "capabilities": PM_CAPS}
PATCHING = {"category": "core", "capabilities": PATCHING_CAPS}


def job(kind="batch_install", disable=("patching",), **more):
    return {"action": kind, "plugin_id": "x", "disable_modules": list(disable), **more}


# ------------------------------------------------------------------------------------------ 1. the dev02 case
world({"patching": True}, {"patching": PATCHING})
stage("patchmanagement", patchmanagement=APM)
result = run(job(plan=plan(("patchmanagement", "install"))))
must(result["status"] == "succeeded", ("1: the job must succeed", result.get("error"), EVENTS))
must(flags() == {"patching": False, "patchmanagement": True}, ("1: flags", flags()))
must(result["disabled_modules"] == ["patching"], ("1: disabled_modules", result.get("disabled_modules")))
must(EVENTS == ["backup", "pre-disable", "script:patchmanagement", "verify", "remember", "sync", "actions", "cleanup"], ("1: event order", EVENTS))
must(SCRIPTS == [("patchmanagement", False)], ("1: the replaced module was already off when the script ran", SCRIPTS))

# the same state the bug needs, without the pre-disable: the fake shell fails exactly as dev02 did
world({"patching": True}, {"patching": PATCHING})
os_run = fake_run(["bash", "x", str(PACKAGE_OF["patchmanagement"])], stdout=io.StringIO())
must(os_run.returncode == 1, "the fake shell reproduces the dev02 failure when both modules are enabled")
world({"patching": True}, {"patching": PATCHING})

# ------------------------------------------------------------------------------------------ 2. failures re-enable the replaced module
# 2a. the install shell fails (rc 1)
world({"patching": True}, {"patching": PATCHING})
FAIL_SCRIPT.add("patchmanagement")
result = run(job(plan=plan(("patchmanagement", "install"))))
FAIL_SCRIPT.discard("patchmanagement")
must(result["status"] == "failed" and result["stage"] == "rollback", ("2a: failed in rollback", result))
must(flags() == {"patching": True}, ("2a: patching enabled again, no stuck flag", flags()))
must(not (REPO / "extensions" / "patchmanagement").exists(), "2a: the fresh extension folder was removed")
must("disabled_modules" not in result, ("2a: nothing is reported as disabled", result))
# 2b. the runtime sync fails after a good install
world({"patching": True}, {"patching": PATCHING})
SYNC["fail_first"] = 1
result = run(job(plan=plan(("patchmanagement", "install"))))
must(result["status"] == "failed" and result["stage"] == "rollback", ("2b", result))
must(flags() == {"patching": True} and not (REPO / "extensions" / "patchmanagement").exists(), ("2b", flags()))
# 2c. a rule refused after the install (capability parity): the verify raises and everything goes back
world({"patching": True}, {"patching": PATCHING})
stage("patchmanagement", patchmanagement={"replaces": "patching", "capabilities": {"patching.windows": "1.2.0"}})
result = run(job(plan=plan(("patchmanagement", "install"))))
must(result["status"] == "failed" and "capability-missing" in result["error"] and flags() == {"patching": True}, ("2c", result, flags()))
stage("patchmanagement", patchmanagement=APM)

# ------------------------------------------------------------------------------------------ 3. unconfirmed
world({"patching": True, "bystander": True}, {"patching": PATCHING, "bystander": {}})
stage("patchmanagement", "bystander", patchmanagement=APM)
(REPO / "extensions" / "bystander" / "keep.txt").write_text("kept", encoding="utf-8")
result = run(job(disable=(), plan=plan(("patchmanagement", "install"), ("bystander", "replace"))))
must(result["status"] == "failed" and "did not confirm" in result["error"], ("3: refused", result))
must(not any(e.startswith("script:") for e in EVENTS), ("3: no script ran", EVENTS))
must("backup" in EVENTS and EVENTS.index("backup") < len(EVENTS), ("3: the backup came first", EVENTS))
must(flags() == {"patching": True, "bystander": True}, ("3: nothing disabled", flags()))
must((REPO / "extensions" / "bystander" / "keep.txt").read_text(encoding="utf-8") == "kept", "3: the other module's code is intact")
must(not (REPO / "extensions" / "patchmanagement").exists(), "3: nothing installed")

# ------------------------------------------------------------------------------------------ 4. no pre-disable
# 4a. an upgrade (the replacement is installed already, switched off): the replaced module stays on
world({"patching": True, "patchmanagement": False}, {"patching": PATCHING, "patchmanagement": APM})
result = run(job(plan=plan(("patchmanagement", "replace"))))
must("pre-disable" not in EVENTS and flags()["patching"] is True, ("4a: upgrade", EVENTS, flags()))
# 4b. an install action for a module that is installed already (pre_installed)
world({"patching": True, "patchmanagement": False}, {"patching": PATCHING, "patchmanagement": APM})
result = run(job(plan=plan(("patchmanagement", "install"))))
must("pre-disable" not in EVENTS and flags()["patching"] is True, ("4b: already installed", EVENTS, flags()))
# 4c. the unit rules: replaced module already off, not core or server, not installed, in the same batch
world({"patching": False}, {"patching": PATCHING})
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patchmanagement"]) is False and flags() == {"patching": False}, "4c: already disabled")
world({"patching": True}, {"patching": {"category": "premium"}})
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patchmanagement"]) is False and flags() == {"patching": True}, "4c: not core or server")
world({"patching": True}, {"patching": {}})
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patchmanagement"]) is False and flags() == {"patching": True}, "4c: no category")
world({}, {})
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patchmanagement"]) is False, "4c: not installed")
world({"patching": True}, {"patching": PATCHING})
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patching", "patchmanagement"]) is False and flags() == {"patching": True}, "4c: same batch")
record = []
must(helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["patchmanagement"], record) is True and record == ["patching"] and flags() == {"patching": False}, "4c: the confirmed case")
world({"patching": True, "server1": True}, {"patching": PATCHING, "server1": {"category": "server"}})
try:
    helper.apply_install_prepare_disable(REPO, "server1", ["patching"], ["x"])
    raise AssertionError("4c: an unconfirmed server module was disabled")
except RuntimeError as exc:
    must("did not confirm" in str(exc) and flags()["server1"] is True, ("4c", exc))
# 4d. a corrupt state file is never overwritten
world({"patching": True}, {"patching": PATCHING})
STATE_FILE.write_text("{nope", encoding="utf-8")
try:
    helper.apply_install_prepare_disable(REPO, "patching", ["patching"], ["x"])
    raise AssertionError("4d: a corrupt state file was overwritten")
except RuntimeError:
    must(STATE_FILE.read_text(encoding="utf-8") == "{nope", "4d: untouched")

# ------------------------------------------------------------------------------------------ 5. bundle and batch take the same path
world({"patching": True}, {"patching": PATCHING})
stage("patchmanagement", patchmanagement=APM)
result = run(job(kind="bundle_install", plan=plan(("patchmanagement", "install")), bundle_path="b.tar"))
must(result["status"] == "succeeded" and flags() == {"patching": False, "patchmanagement": True}, ("5a: bundle", result.get("error")))
must(EVENTS[:3] == ["backup", "pre-disable", "script:patchmanagement"], ("5a", EVENTS))
# a batch with a dependency plus the replacement: the disable comes right before the replacement's own script
world({"patching": True}, {"patching": PATCHING})
stage("dep", "patchmanagement", patchmanagement=APM)
result = run(job(plan=plan(("dep", "install"), ("patchmanagement", "install"))))
must(result["status"] == "succeeded" and flags() == {"patching": False, "dep": True, "patchmanagement": True}, ("5b", result.get("error"), flags()))
must(EVENTS[:4] == ["backup", "script:dep", "pre-disable", "script:patchmanagement"], ("5b: disable right before the replacement's script", EVENTS))
must(SCRIPTS[0] == ("dep", None), SCRIPTS)
# a batch failing after the dependency went in: the dependency's code and the replaced flag both go back
world({"patching": True}, {"patching": PATCHING})
FAIL_SCRIPT.add("patchmanagement")
result = run(job(plan=plan(("dep", "install"), ("patchmanagement", "install"))))
FAIL_SCRIPT.discard("patchmanagement")
must(result["status"] == "failed" and flags() == {"patching": True} and not (REPO / "extensions" / "dep").exists(), ("5c", result, flags()))

# ------------------------------------------------------------------------------------------ 6. package_replaces
def tar_package(entries):
    path = PACKAGES / f"t-{next(COUNTER)}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def zip_entries(entries):
    path = PACKAGES / f"z-{next(COUNTER)}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return path


def blob(module_id="patchmanagement", **more):
    return json.dumps(manifest(module_id, **more)).encode("utf-8")


def refused(call, needle):
    try:
        call()
    except RuntimeError as exc:
        must(needle in str(exc), exc)
        return
    raise AssertionError("package_replaces accepted it: " + needle)


for maker in (zip_entries, tar_package):
    ok = maker([("extensions/patchmanagement/tec_tac.json", blob(replaces="patching")), ("extensions/patchmanagement/app.py", b"x")])
    must(helper.package_replaces(ok, "patchmanagement") == "patching", maker.__name__)
    nested = maker([("pkg/extensions/patchmanagement/tec_tac.json", blob(replaces=" patching "))])
    must(helper.package_replaces(nested, "patchmanagement") == "patching", "a leading folder is allowed and the value is trimmed")
    must(helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", blob())]), "patchmanagement") == "", "no replaces key")
    refused(lambda: helper.package_replaces(maker([("README", b"x")]), "patchmanagement"), "found 0")
    refused(lambda: helper.package_replaces(maker([("extensions/a/tec_tac.json", blob("a")), ("extensions/b/tec_tac.json", blob("b"))]), "a"), "found 2")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", blob("other"))]), "patchmanagement"), "does not match")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", blob(replaces="bad id"))]), "patchmanagement"), "invalid replaces")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", blob(replaces=["patching"]))]), "patchmanagement"), "invalid replaces")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", blob(replaces=""))]), "patchmanagement"), "invalid replaces")
    big = json.dumps(manifest("patchmanagement", pad="x" * (helper.MAX_MANIFEST_BYTES + 10))).encode("utf-8")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", big)]), "patchmanagement"), "too large")
    refused(lambda: helper.package_replaces(maker([("extensions/patchmanagement/tec_tac.json", b"{nope")]), "patchmanagement"), "unreadable")
    for bad in ("../extensions/patchmanagement/tec_tac.json", "extensions/../extensions/patchmanagement/tec_tac.json", "/extensions/patchmanagement/tec_tac.json"):
        refused(lambda bad=bad: helper.package_replaces(maker([(bad, blob(replaces="patching"))]), "patchmanagement"), "unsafe path")
refused(lambda: helper.package_replaces(PACKAGES / "missing.zip", "patchmanagement"), "cannot be read")
junk = PACKAGES / "junk.zip"
junk.write_bytes(b"not a zip")
refused(lambda: helper.package_replaces(junk, "patchmanagement"), "cannot be read")

# ------------------------------------------------------------------------------------------ 7. static
tree = ast.parse(source)
run_job = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "run_job")
calls = [n for n in ast.walk(run_job) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "install_packages"]
must(len(calls) == 1, ("run_job calls install_packages once", len(calls)))
must([k.arg for k in calls[0].keywords] == ["prepare"], "install_packages gets prepare=")
install_fn = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "install_packages")
must("prepare" in [a.arg for a in install_fn.args.args], "install_packages takes prepare")
v1 = (ROOT / "scripts" / "module-job-helper.py").read_text(encoding="utf-8")
for word in ("disable_modules", "verify_install_disables", "apply_install_prepare_disable", "prepare="):
    must(word not in v1, f"the v1 plain-install helper has no disable step ({word})")
must(source.count("install_packages(") == 2, "the definition and the one call in the v2 helper")

print("[TEST] PASS module replacement install order 1.17.59")
