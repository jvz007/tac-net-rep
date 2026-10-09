#!/usr/bin/env python3
"""1.17.13 regression (precheck round): AD-21 conditions 4 and 5 on the v1 install path.

* ``module_manager.queue_install`` (POST /api/tfd/modules/packages/<id>/install/) refuses a package whose manifest has no category,
  or category test, on a server that is not a development server. The preview says ``installable: false`` with the plain reason.
* ``module_manager_v2.queue_v2_install`` of a local single package (which hands over to the v1 worker) refuses the same way.
* scripts/module-job-helper.py (the v1 root worker) reads the category from the root-private package itself, refuses before it
  installs anything, fails closed on a missing or unknown category, and writes the category into the module state entry.

Real module_manager.py, module_manager_v2.py and module_category.py; the development flag is switched by replacing
module_category.is_development_server. What cannot run here: the worker as root, sudo dispatch.
"""
from __future__ import annotations

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


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, LOCK_NB=4, flock=lambda *a: None)
_stub("pwd")
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import module_category as mc
from tec_tac import module_manager, module_state, registry
from tec_tac import module_manager_v2 as v2

DEV = {"on": False}
mc.is_development_server = lambda: DEV["on"]
TMP = Path(tempfile.mkdtemp(prefix="tectac-install-route-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for _folder in (EXT, REP, JOBS):
    _folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins

DISPATCHED = []
CREATED = []


def _fake_job(payload):
    job = {"id": f"job{len(CREATED)}", "status": "queued", "stage": "queued", **payload}
    CREATED.append(job)
    return job


module_manager._new_job = _fake_job  # the real one writes with os.fchmod, which Windows does not have
module_manager._dispatch = lambda job_id: DISPATCHED.append(job_id)
STAGES = {}
module_manager._load_stage = v2._load_stage = lambda upload_id: STAGES[upload_id]
module_manager._verify_stage_trust = v2._verify_stage_trust = lambda *a, **k: {"state": "unsigned"}
v2._enforce_candidate_licensing = lambda candidate: {}


def package(name, **extra):
    """A real zip package: extensions/<name>/tec_tac.json."""
    payload = {"id": name, "type": "extension", "version": "1.0.0", "name": name}
    payload.update(extra)
    path = TMP / f"{name}-{len(STAGES)}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"extensions/{name}/tec_tac.json", json.dumps(payload))
    upload_id = f"up{len(STAGES)}"
    STAGES[upload_id] = {"package_path": str(path), "filename": path.name, "sha256": "0" * 64}
    return upload_id


def refused(call, upload_id):
    try:
        call(upload_id)
    except (module_manager.ModuleManagerError, v2.ModuleManagerV2Error) as exc:
        must("not a development server" in str(exc), str(exc))
        return
    raise AssertionError("install was queued")


# ------------------------------------------------------------------------------------------ v1 route, off a development server
DEV["on"] = False
for extra in ({}, {"category": "test"}, {"category": " TEST "}):
    upload = package("modx", **extra)
    preview = module_manager.inspect_archive(Path(STAGES[upload]["package_path"]))
    must(preview["installable"] is False and preview["install_block_reason"] == mc.REFUSED_MESSAGE, preview)
    refused(module_manager.queue_install, upload)
    refused(v2.queue_v2_install, upload)
    must(DISPATCHED == [] and CREATED == [], "nothing queued, no job created")
for category in ("core", "server", "premium"):
    upload = package(f"m{category}", category=category)
    must(module_manager.inspect_archive(Path(STAGES[upload]["package_path"]))["installable"] is True, category)
    job = module_manager.queue_install(upload)
    must(job["status"] == "queued" and len(DISPATCHED) == 1, job)
    DISPATCHED.clear()
    v2.queue_v2_install(upload)  # a local single package goes to the v1 worker
    must(len(DISPATCHED) == 1, "local single-package install still queues")
    DISPATCHED.clear()

# ------------------------------------------------------------------------------------------ v1 route, development server
DEV["on"] = True
for extra in ({}, {"category": "test"}):
    upload = package("devmod", **extra)
    must(module_manager.inspect_archive(Path(STAGES[upload]["package_path"]))["installable"] is True, extra)
    module_manager.queue_install(upload)
    v2.queue_v2_install(upload)
    DISPATCHED.clear()
DEV["on"] = False

# ------------------------------------------------------------------------------------------ the root worker
HELPER = ROOT / "scripts" / "module-job-helper.py"
raw = HELPER.read_text(encoding="utf-8")
LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"
must(LOOKUP in raw, "lookup line moved")
helper = types.ModuleType("module_job_helper_pure")
helper.__file__ = str(HELPER)
exec(compile(raw.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(HELPER), "exec"), helper.__dict__)

CONFIGS = {"value": {}}
helper.load_config = lambda: CONFIGS["value"]
for value, expected in (({"TEC_TAC_ENVIRONMENT": "development"}, True), ({"TEC_TAC_ENVIRONMENT": "production"}, False), ({}, False)):
    CONFIGS["value"] = value
    must(helper.development_server() is expected, value)


def _unreadable():
    raise RuntimeError("unreadable")


helper.load_config = _unreadable
must(helper.development_server() is False, "fails closed")
for development in (True, False):
    for category, is_refused in (("", not development), (None, not development), ("test", not development), ("core", False), ("server", False), ("premium", False)):
        must(helper.category_refused(category, development) is is_refused, (development, category))


def worker_package(name, kind, **extra):
    payload = {"id": name, "type": "extension", "version": "1.0.0", **extra}
    path = TMP / f"w-{name}{kind}"
    if kind == ".zip":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(f"extensions/{name}/tec_tac.json", json.dumps(payload))
    else:
        manifest = TMP / "manifest.json"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with tarfile.open(path, "w:gz") as archive:
            archive.add(manifest, arcname=f"extensions/{name}/tec_tac.json")
    return path


for kind in (".zip", ".tar.gz"):
    must(helper.package_category(worker_package("a", kind), "a") == "", kind)
    must(helper.package_category(worker_package("a", kind, category=" Premium "), "a") == "premium", kind)
    must(helper.package_category(worker_package("a", kind, category="test"), "a") == "test", kind)
    for bad in ("bogus", 5, None):
        try:
            helper.package_category(worker_package("a", kind, category=bad), "a")
        except RuntimeError as exc:
            must("unknown category" in str(exc), str(exc))
        else:
            raise AssertionError(f"accepted {bad!r}")
    try:
        helper.package_category(worker_package("a", kind), "other")
    except RuntimeError as exc:
        must("does not match" in str(exc), str(exc))
    else:
        raise AssertionError("an id mismatch was accepted")
empty = TMP / "empty.zip"
with zipfile.ZipFile(empty, "w") as archive:
    archive.writestr("readme.txt", "no manifest")
try:
    helper.package_category(empty, "a")
except RuntimeError as exc:
    must("exactly one" in str(exc), str(exc))
else:
    raise AssertionError("a package with no manifest was accepted")

# the state write: the category lands in the module entry and other fields stay
helper.STATE_ROOT = TMP / "state"
helper.STATE_FILE = helper.STATE_ROOT / "module-state.json"
helper.MODULE_STATE_LOCK = helper.STATE_ROOT / "module-state.lock"
helper.os = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith("__")})
helper.os.chown = helper.os.fchmod = lambda *a, **k: None
helper.remember_category("keep", "premium")
helper.STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"keep": {"enabled": False, "version": "2"}}}), encoding="utf-8")
helper.remember_category("keep", "core")
helper.remember_category("fresh", "")
saved = json.loads(helper.STATE_FILE.read_text(encoding="utf-8"))["modules"]
must(saved["keep"] == {"enabled": False, "version": "2", "category": "core"} and saved["fresh"] == {"category": ""}, saved)

# run_job refuses before the install script runs
start = raw.index("    command = None\n    declared_category = None")
chunk = raw[start:raw.index("    rc = 1\n    try:", start)]
must('package_category(package, job["plugin_id"])' in chunk and "category_refused(declared_category)" in chunk and "return" in chunk, "run_job checks the category")
must(chunk.index("category_refused") < chunk.index("command = [TRUSTED_BASH, str(install_script)"), "the check comes before the install command")
print("module-category-install-route-1.17.13: ok")
