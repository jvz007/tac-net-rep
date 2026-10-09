#!/usr/bin/env python3
"""1.17.11 regression: enabling a replacement names the module it will disable and disables it in the same job (AD-20 amendment 1a).

Runs the real registry.py, module_state.py, module_replacement.py, capabilities.py, module_manager.py, module_manager_v2.py and
module_v2_views.py against a temporary folder of real manifests. Django and the Linux-only ``fcntl`` and ``cryptography`` are
stubbed, the module state is a dict and queueing is captured. The root job helper is in tests/module-replacement-helper-1.17.11.py.
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


captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}
audited = []
mr.audit_replaced_disabled = lambda actor, replacement, disabled, job_id: audited.append((actor, replacement, list(disabled), job_id))


def refused_enable(module_id, **kwargs):
    try:
        v2.queue_set_enabled(module_id, True, **kwargs)
    except v2.ModuleManagerV2Error as exc:
        return exc
    raise AssertionError(f"enable of {module_id} was queued: {kwargs}")


# ------------------------------------------------------------------------------------------ catalog rows and validate_enable
world(patching=True, pm=False)
table = rows()
must(table["patchmanagement"]["will_disable"] == ["patching"], table["patchmanagement"]["will_disable"])
must(table["patching"]["will_disable"] == [], "a core module disables nothing")
must(all("will_disable" in row for row in table.values()), "every row carries will_disable")
must(table["patchmanagement"]["replacement"]["conflict"] is False, table["patchmanagement"]["replacement"])
check = v2.validate_enable("patchmanagement")
must(check == {"valid": True, "problems": [], "will_disable": ["patching"]}, check)
must(v2.validate_enable("patching")["will_disable"] == [], "enabling the core module names nothing")

world(patching=False, pm=False)
must(rows()["patchmanagement"]["will_disable"] == [] and v2.validate_enable("patchmanagement")["will_disable"] == [], "nothing enabled to replace")
world(patching=True, pm=True)
must(rows()["patchmanagement"]["will_disable"] == [], "already enabled: nothing to enable, nothing to name")
must(rows()["patchmanagement"]["replacement"]["conflict"] is True, "both enabled is reported as a conflict")
world(patching=True, pm=False, pm_caps={"patching.windows": "1.2.0"})  # parity lost
must(rows()["patchmanagement"]["will_disable"] == [], "an incomplete replacement names nothing")
incomplete = v2.validate_enable("patchmanagement")
must(not incomplete["valid"] and incomplete["will_disable"] == [] and incomplete["problems"][0]["type"] == "replacement_incomplete", incomplete)
world(patching=True, pm=False, patching_caps=None)  # the replaced module hides its capabilities
must(not v2.validate_enable("patchmanagement")["valid"], "capabilities-undeclared still refuses")

# ------------------------------------------------------------------------------------------ confirmation
world(patching=True, pm=False)
captured.clear()
for bad in (None, [], ["other"], ["patching", "other"], "patching", 7):
    exc = refused_enable("patchmanagement", disable_replaced=bad)
    must(isinstance(exc, v2.ModuleReplacementConfirmationRequired), (bad, exc))
    must(exc.will_disable == ["patching"] and "patching" in str(exc) and "patchmanagement" in str(exc), exc)
    payload = exc.as_payload()
    must(payload["code"] == "replacement_confirmation_required" and payload["will_disable"] == ["patching"] and payload["detail"] == str(exc), payload)
must(captured == [] and audited == [], "a refusal queues nothing and audits nothing")
must(issubclass(v2.ModuleReplacementConfirmationRequired, v2.ModuleManagerV2Error), "old callers that catch the v2 error still see a refusal")

actor = types.SimpleNamespace(username="alice")
job = v2.queue_set_enabled("patchmanagement", True, requested_by="alice", disable_replaced=["patching"], actor=actor)
must(job["queued"] is True and len(captured) == 1, captured)
payload = captured[0]
must(payload["action"] == "enable" and payload["plugin_id"] == "patchmanagement" and payload["affected_modules"] == ["patchmanagement"], payload)
must(payload["disable_modules"] == ["patching"] and payload["requested_by"] == "alice", payload)
must(audited == [(actor, "patchmanagement", ["patching"], "job-1")], audited)  # actor is the requesting user, object is the replaced module
v2.queue_set_enabled("patchmanagement", True, disable_replaced=["patching", "patching"])  # a repeated id names the same list
must(captured[-1]["disable_modules"] == ["patching"], captured[-1])

# a list for a module that would disable nothing is ignored, never passed on
world(patching=False, pm=False)
captured.clear()
v2.queue_set_enabled("patchmanagement", True, disable_replaced=["patching"])
must(captured[0]["disable_modules"] == [], captured[0])
# a plain module: the field is empty and nothing is asked
manifest("bystander")
v2.queue_set_enabled("bystander", True)
must(captured[-1]["disable_modules"] == [], captured[-1])
# disabling never carries the field
v2.queue_set_enabled("bystander", False)
must("disable_modules" not in captured[-1], captured[-1])

# ------------------------------------------------------------------------------------------ what stays refused
world(patching=False, pm=True)
exc = refused_enable("patching")
must(not isinstance(exc, v2.ModuleReplacementConfirmationRequired) and "patchmanagement" in str(exc), exc)
result = v2.validate_enable("patching")
must(not result["valid"] and result["problems"][0]["type"] == "replacement_conflict" and result["problems"][0]["replaced_by"] == "patchmanagement", result)
must(result["will_disable"] == [], result)
# a rival enabled replacement of the same module is still refused (the target would be disabled, the rival still competes)
world(patching=True, pm=False)
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
result = v2.validate_enable("patchmanagement")
must(not result["valid"] and result["problems"][0]["reason"] == "competing-replacement" and result["will_disable"] == [], result)
exc = refused_enable("patchmanagement", disable_replaced=["patching"])
must("Only one replacement" in str(exc), exc)
# the replaced module is not a core or server module: refused
world(patching=True, pm=False)
manifest("patching")
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS)
result = v2.validate_enable("patchmanagement")
must(not result["valid"] and result["problems"][0]["reason"] == "target-not-core", result)
# the replaced module is not installed
world(patching=True, pm=False)
manifest("patchmanagement", replaces="nosuch", capabilities=PM_CAPS)
must(v2.validate_enable("patchmanagement")["problems"][0]["reason"] == "target-missing", "target missing")

# ------------------------------------------------------------------------------------------ pending jobs
# 1.17.9-1 still holds: a queued job counts as done, and now so does the disable it carries
world(patching=True, pm=False)
captured.clear()
(JOBS / "a.json").write_text(json.dumps({"id": "a", "action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "disable_modules": ["patching"], "status": "queued", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
model = v2._model_with_pending_jobs(mr.live_model())
must(model["patchmanagement"].enabled is True and model["patching"].enabled is False, "the pending job enables the replacement and disables the core module")
must(not v2.validate_enable("patching")["valid"], "a second queued job cannot enable the core module next to the queued replacement")
must(v2.validate_enable("patching")["problems"][0]["replaced_by"] == "patchmanagement", v2.validate_enable("patching"))
must(rows()["patchmanagement"]["will_disable"] == [], "the replacement is already enabled in the pending model")
(JOBS / "a.json").write_text(json.dumps({"id": "a", "action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "disable_modules": ["patching"], "status": "succeeded", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
must(v2._model_with_pending_jobs(mr.live_model())["patching"].enabled is True, "a finished job is already in the live state")
# a pending install that disables the replaced module counts too
(JOBS / "a.json").write_text(json.dumps({"id": "a", "action": "batch_install", "plugin_id": "batch", "disable_modules": ["patching"],
                                          "status": "dispatched", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
must(v2._model_with_pending_jobs(mr.live_model())["patching"].enabled is False, "a pending install job applies its disable")
(JOBS / "a.json").unlink()

# ------------------------------------------------------------------------------------------ the view
for _name in ("drf_spectacular", "rest_framework"):
    sys.modules[_name] = types.ModuleType(_name)


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


for _name, _attrs in {
    "drf_spectacular.utils": {"extend_schema": lambda **kw: (lambda target: target), "extend_schema_view": lambda **kw: (lambda target: target)},
    "rest_framework.parsers": {"FormParser": object, "MultiPartParser": object},
    "rest_framework.response": {"Response": Response},
    "rest_framework.views": {"APIView": object},
    "tec_tac.session_security": {"SessionAuthenticated": object},
    "tec_tac.views": {"_can_manage_modules": lambda user: True, "_require_module_manager": lambda user: None},
}.items():
    sys.modules[_name] = types.ModuleType(_name)
    sys.modules[_name].__dict__.update(_attrs)
import tec_tac.module_v2_views as views  # noqa: E402

world(patching=True, pm=False)
captured.clear()
audited.clear()
alice = types.SimpleNamespace(username="alice")


def post(data, plugin="patchmanagement"):
    return views.ModuleV2StateView().post(types.SimpleNamespace(data=data, user=alice), plugin)


answer = post({"enabled": True})
must(answer.status_code == 400 and answer.data["code"] == "replacement_confirmation_required" and answer.data["will_disable"] == ["patching"], answer.data)
must("patching" in answer.data["detail"], answer.data)
answer = post({"enabled": True, "disable_replaced": ["stale"]})
must(answer.status_code == 400 and answer.data["will_disable"] == ["patching"], "a stale list gets the fresh one")
answer = post({"enabled": True, "disable_replaced": "patching"})
must(answer.status_code == 400 and "array" in answer.data["detail"] and "code" not in answer.data, answer.data)
must(captured == [], "nothing queued so far")
answer = post({"enabled": True, "disable_replaced": ["patching"]})
must(answer.status_code == 202 and captured[0]["disable_modules"] == ["patching"] and captured[0]["requested_by"] == "alice", (answer.data, captured))
must(audited[0][0] is alice and audited[0][1] == "patchmanagement", audited)
answer = post({"enabled": "yes"})
must(answer.status_code == 400 and answer.data["detail"] == "enabled must be true or false.", answer.data)  # the existing contract
world(patching=False, pm=True)
answer = post({"enabled": True, "disable_replaced": ["patching"]}, "patching")  # the core module next to its enabled replacement
must(answer.status_code == 400 and "code" not in answer.data and "patchmanagement" in answer.data["detail"], answer.data)  # an ordinary refusal keeps the old shape

print("[TEST] PASS module replacement enable 1.17.11")
