#!/usr/bin/env python3
"""1.17.11 regression: installing a replacement names the module it will disable and disables it in the same job (AD-20 amendment 1b).

Covers the plan and action will_disable, the valid plan, the refusal without the confirmed list for a single package, a bundle and a
batch, a single local package routed to the v2 worker, the replaced module in the same batch, and an upgrade of an installed
replacement. Real registry, module_state, module_replacement and module_manager_v2; staging, trust and queueing are stubbed.
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
from tec_tac import module_category  # noqa: E402
module_category.is_development_server = lambda: True  # AD-21 (1.17.13): these tests are about replacement, not about the category gate

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
    if "replaces" in extra:
        payload.setdefault("category", "premium")  # AD-21 (1.17.13): a replacement is a premium module
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


PM = dict(replaces="patching", capabilities=PM_CAPS)


def plan(*items):
    return v2.resolve_install_plan(list(items))


def action_of(result, module_id):
    return next(item for item in result["actions"] if item["id"] == module_id)


# ------------------------------------------------------------------------------------------ the plan
world(patching=True, pm=False)
reset(patching=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
result = plan(candidate("patchmanagement", **PM))
must(result["valid"] is True and result["problems"] == [], result)
must(result["will_disable"] == ["patching"] and action_of(result, "patchmanagement")["will_disable"] == ["patching"], result)
# a core module disables nothing, and a plain candidate neither
manifest("bystander")
result = plan(candidate("patchmanagement", **PM), candidate("bystander"))
must(action_of(result, "bystander")["will_disable"] == [] and result["will_disable"] == ["patching"], result)
# the target is installed but already disabled: nothing to name
STATE["modules"]["patching"]["enabled"] = False
result = plan(candidate("patchmanagement", **PM))
must(result["valid"] is True and result["will_disable"] == [], result)
# parity and a missing target still refuse
STATE["modules"]["patching"]["enabled"] = True
result = plan(candidate("patchmanagement", replaces="patching", capabilities={"patching.windows": "1.2.0"}))
must(not result["valid"] and result["problems"][0]["type"] == "replacement_incomplete" and result["will_disable"] == [], result)
must(not plan(candidate("patchmanagement", replaces="nosuch", capabilities={}))["valid"], "a missing target refuses")
# a rival enabled replacement refuses too
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
result = plan(candidate("patchmanagement", **PM))
must(not result["valid"] and result["problems"][0]["reason"] == "competing-replacement", result)
del STATE["modules"]["rival"]
(EXT / "rival" / "tec_tac.json").unlink()
(EXT / "rival").rmdir()
# the replaced module installed in the same batch stays refused (it would start enabled next to the replacement)
reset()
result = plan(candidate("patching", category="core", capabilities=PATCHING_CAPS), candidate("patchmanagement", **PM))
must(not result["valid"] and result["problems"][0]["type"] == "replacement_conflict" and result["problems"][0]["reason"] == "target-enabled" and result["will_disable"] == [], result)
# an upgrade of the installed replacement is unchanged: it names nothing
world(patching=False, pm=True)
result = plan(candidate("patchmanagement", "1.1.0", **PM))
must(result["valid"] is True and result["will_disable"] == [] and action_of(result, "patchmanagement")["action"] == "replace", result)
# an upgrade of a DISABLED replacement next to an enabled target keeps being refused, as in 1.17.10
world(patching=True, pm=False)
result = plan(candidate("patchmanagement", "1.1.0", **PM))
must(not result["valid"] and result["problems"][0]["reason"] == "target-enabled" and result["will_disable"] == [], result)
# a server-module target works the same way
reset(backups=True)
manifest("backups", category="server", capabilities={"backups.run": "1.0.0"})
result = plan(candidate("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"}))
must(result["valid"] is True and result["will_disable"] == ["backups"], result)

# ------------------------------------------------------------------------------------------ queueing
captured, audited, v1_calls = [], [], []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}
module_manager.queue_install = lambda *args, **kwargs: v1_calls.append((args, kwargs)) or {"v1": True}
# 1.17.12: the queue-time row is audit_switch_queued (a request, not a change)
mr.audit_switch_queued = lambda actor, subject, job_id, disabled=(), enabled=(): audited.append((actor, subject, list(disabled), job_id))
v2._enforce_candidate_licensing = lambda candidate_: candidate_
v2._verify_stage_trust = lambda *args, **kwargs: {"state": "unsigned"}
META = {}
v2._load_stage = lambda upload_id: dict(META["stage"])
v2._package_metadata = lambda path: dict(META["preview"])


def single(item, **extra):
    META["stage"] = {"package_path": "pm.zip", "sha256": "abc", "source_provenance": extra.pop("source", None)}
    META["preview"] = {**item, "installable": True, "already_installed": extra.pop("already", False), "installed_version": None, "publisher_permissions": []}


def refused_install(call):
    try:
        call()
    except v2.ModuleManagerV2Error as exc:
        return exc
    raise AssertionError("the install was queued")


reset(patching=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
single(candidate("patchmanagement", **PM))
alice = types.SimpleNamespace(username="alice")
for bad in (None, [], ["other"]):
    exc = refused_install(lambda: v2.queue_v2_install("u1", requested_by="alice", disable_replaced=bad))
    must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and exc.will_disable == ["patching"], (bad, exc))
    must(exc.as_payload()["code"] == "replacement_confirmation_required", exc.as_payload())
must(captured == [] and v1_calls == [] and audited == [], "a refusal queues nothing")
# confirmed: it goes through the v2 worker (the v1 worker cannot disable in the same job)
job = v2.queue_v2_install("u1", requested_by="alice", disable_replaced=["patching"], actor=alice)
must(job["queued"] is True and v1_calls == [] and len(captured) == 1, (captured, v1_calls))
payload = captured[0]
must(payload["action"] == "batch_install" and payload["disable_modules"] == ["patching"], payload)
must(payload["plan"]["actions"][0]["will_disable"] == ["patching"] and payload["plan"]["actions"][0]["action"] == "install", payload["plan"])
must(payload["plan"]["order"] == ["patchmanagement"] and payload["packages"][0]["id"] == "patchmanagement", payload)
must(audited == [(alice, "patchmanagement", ["patching"], "job-1")], audited)
# a single package that disables nothing still uses the v1 worker, as before
reset(patching=False)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
single(candidate("patchmanagement", **PM))
captured.clear()
must(v2.queue_v2_install("u1", requested_by="alice") == {"v1": True} and captured == [], "no disable: v1 worker")
single(candidate("bystander"))
must(v2.queue_v2_install("u1", requested_by="alice") == {"v1": True}, "a plain package: v1 worker")
# an upgrade of the installed replacement: v1 worker, nothing named
world(patching=False, pm=True)
single(candidate("patchmanagement", "1.1.0", **PM), already=True)
must(v2.queue_v2_install("u1", requested_by="alice", disable_replaced=["patching"]) == {"v1": True} and captured == [], "an upgrade names nothing")
# an online (provenance) package that disables is confirmed the same way
reset(patching=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
single(candidate("patchmanagement", **PM), source={"repository": "r"})
refused_install(lambda: v2.queue_v2_install("u1", requested_by="alice"))
v2.queue_v2_install("u1", requested_by="alice", disable_replaced=["patching"])
must(captured[-1]["disable_modules"] == ["patching"] and captured[-1]["packages"][0]["source"] == {"repository": "r"}, captured[-1])

# ------------------------------------------------------------------------------------------ bundle
single_plan = plan(candidate("patchmanagement", **PM))
BUNDLE = {"bundle_path": "b.zip", "filename": "b.zip", "preview": {"id": "bundle1"}, "sha256": "x"}


def raise_missing(upload_id):
    raise module_manager.ModuleManagerError("not a single package")


v2._load_stage = raise_missing
v2._load_bundle = lambda upload_id: dict(BUNDLE)
v2._inspect_bundle = lambda path: {"id": "bundle1", "packages": [candidate("patchmanagement", **PM)], "plan": plan(candidate("patchmanagement", **PM)), "package_files": []}
captured.clear()
audited.clear()
exc = refused_install(lambda: v2.queue_v2_install("b1", requested_by="alice"))
must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and exc.will_disable == ["patching"], exc)
refused_install(lambda: v2.queue_v2_install("b1", requested_by="alice", disable_replaced=["wrong"]))
must(captured == [], "nothing queued")
v2.queue_v2_install("b1", requested_by="alice", disable_replaced=["patching"], actor=alice)
must(captured[0]["action"] == "bundle_install" and captured[0]["disable_modules"] == ["patching"], captured[0])
must(captured[0]["plan"]["will_disable"] == ["patching"] and audited[0][2] == ["patching"], (captured[0]["plan"], audited))

# ------------------------------------------------------------------------------------------ batch
v2._load_stage = lambda upload_id: dict(META["stage"])
v2._load_batch = lambda batch_id: {"artifacts": [{"kind": "package", "upload_id": "u1"}]}
single(candidate("patchmanagement", **PM))
captured.clear()
audited.clear()
exc = refused_install(lambda: v2.queue_batch_install("batch1", requested_by="alice"))
must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and exc.will_disable == ["patching"], exc)
refused_install(lambda: v2.queue_batch_install("batch1", requested_by="alice", disable_replaced=[]))
v2.queue_batch_install("batch1", requested_by="alice", disable_replaced=["patching"], actor=alice)
must(captured[0]["action"] == "batch_install" and captured[0]["plugin_id"] == "batch" and captured[0]["disable_modules"] == ["patching"], captured[0])
must(captured[0]["plan"]["actions"][0]["will_disable"] == ["patching"] and audited == [(alice, "patchmanagement", ["patching"], "job-1")], audited)
# a batch with no replacement carries an empty list
single(candidate("bystander"))
v2.queue_batch_install("batch1", requested_by="alice")
must(captured[-1]["disable_modules"] == [], captured[-1])
# the replaced module installed fresh in the same batch is refused outright, not a confirmation question
reset()
v2._load_batch = lambda batch_id: {"artifacts": [{"kind": "package", "upload_id": "u1"}, {"kind": "package", "upload_id": "u2"}]}
metas = iter([candidate("patching", category="core", capabilities=PATCHING_CAPS), candidate("patchmanagement", **PM)])
v2._package_metadata = lambda path: {**next(metas), "installable": True, "already_installed": False, "publisher_permissions": []}
exc = refused_install(lambda: v2.queue_batch_install("batch1", requested_by="alice", disable_replaced=["patching"]))
must(not isinstance(exc, v2.ModuleReplacementConfirmationRequired) and "not satisfiable" in str(exc), exc)

print("[TEST] PASS module replacement install 1.17.11")
