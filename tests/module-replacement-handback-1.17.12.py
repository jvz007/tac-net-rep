#!/usr/bin/env python3
"""1.17.12 regression: the AD-20 hand-back (Johan CQ32 and CQ33, 9 October 2026).

CQ32: enabling the replaced module while its replacement is enabled is no longer refused. It names the replacement, needs two
confirmations in order (the disable_replaced list, then confirm_replacement_switch: true), and switches the replacement off in the same
job. CQ33: disabling a replacement switches the replaced module back on in the same job, when it can come back.

Runs the real registry.py, module_state.py, module_replacement.py, capabilities.py, module_manager.py, module_manager_v2.py and
module_v2_views.py against a temporary folder of real manifests. Django and the Linux-only ``fcntl`` and ``cryptography`` are stubbed,
the module state is a dict and queueing is captured, the same way as tests/module-replacement-enable-1.17.11.py. The root job helper
is in tests/module-replacement-helper-handback-1.17.12.py.
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
TMP = Path(tempfile.mkdtemp(prefix="tectac-handback-"))
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


def world(*, patching_caps=PATCHING_CAPS, pm_caps=PM_CAPS, patching=False, pm=True, patching_extra=None, **more):
    reset(patching=patching, patchmanagement=pm, **more)
    core = {"category": "core", **(patching_extra or {})}
    if patching_caps is not None:
        core["capabilities"] = patching_caps
    manifest("patching", **core)
    manifest("patchmanagement", replaces="patching", capabilities=pm_caps)


def rows():
    return {row["id"]: row for row in v2.installed_catalog_v2()}


captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}
queued_rows = []
mr.audit_switch_queued = lambda actor, subject, job_id, disabled=(), enabled=(), skipped=(): queued_rows.append((actor, subject, job_id, sorted(disabled), sorted(enabled)))
mr._audit_replacement = lambda *a, **k: None  # the reconcile row is covered elsewhere


def refused(call, kind=Exception):
    try:
        call()
    except v2.ModuleManagerV2Error as exc:
        return exc
    raise AssertionError("the call was accepted")


# ------------------------------------------------------------------------------------------ CQ32: enabling the replaced module
world(patching=False, pm=True)
check = v2.validate_enable("patching")
must(check == {"valid": True, "problems": [], "will_disable": ["patchmanagement"], "replacement_dependants": []}, check)  # 1.17.14 adds replacement_dependants
table = rows()
must(table["patching"]["will_disable"] == ["patchmanagement"] and table["patching"]["second_confirmation_required"] is True, table["patching"])
must(table["patchmanagement"]["will_disable"] == [] and table["patchmanagement"]["second_confirmation_required"] is False, "enabling a replacement keeps one confirmation")
must(all("will_enable" in row and "second_confirmation_required" in row for row in table.values()), "every row carries the new fields")
must(mr.enable_problems(mr.live_model(), "patching") == [], "the 1.17.9 'Disable X first' problem is gone for this direction")

# the first confirmation: the list, exactly
captured.clear()
for bad in (None, [], ["other"], ["patchmanagement", "other"], "patchmanagement", 7):
    exc = refused(lambda: v2.queue_set_enabled("patching", True, disable_replaced=bad, confirm_replacement_switch=True))
    must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and exc.will_disable == ["patchmanagement"], (bad, exc))
must(captured == [], "nothing queued")
# no list and no flag: the first confirmation comes first
exc = refused(lambda: v2.queue_set_enabled("patching", True))
must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and not isinstance(exc, v2.ModuleReplacementSecondConfirmationRequired), exc)

# the second confirmation: the list is right, the flag is not
for flag in (None, False, "true", 1, "yes", [True]):
    exc = refused(lambda: v2.queue_set_enabled("patching", True, disable_replaced=["patchmanagement"], confirm_replacement_switch=flag))
    must(isinstance(exc, v2.ModuleReplacementSecondConfirmationRequired), (flag, exc))
    payload = exc.as_payload()
    must(payload["code"] == "replacement_second_confirmation_required" and payload["will_disable"] == ["patchmanagement"] and payload["module"] == "patching", payload)
    must(payload["detail"] == str(exc) and "patchmanagement" in payload["detail"] and "switch" in payload["detail"] and "off" in payload["detail"], payload)
must(not issubclass(v2.ModuleReplacementSecondConfirmationRequired, v2.ModuleReplacementConfirmationRequired), "two distinct refusals")
must(issubclass(v2.ModuleReplacementSecondConfirmationRequired, v2.ModuleManagerV2Error), "old callers that catch the v2 error still see a refusal")
must(captured == [] and queued_rows == [], "a refusal queues nothing and audits nothing")

# both confirmations: queued, and the job carries both
actor = types.SimpleNamespace(username="alice")
job = v2.queue_set_enabled("patching", True, requested_by="alice", disable_replaced=["patchmanagement"], actor=actor, confirm_replacement_switch=True)
must(job["queued"] is True and len(captured) == 1, captured)
payload = captured[0]
must(payload["action"] == "enable" and payload["plugin_id"] == "patching" and payload["affected_modules"] == ["patching"], payload)
must(payload["disable_modules"] == ["patchmanagement"] and payload["replacement_confirmed"] is True and payload["requested_by"] == "alice", payload)
must(queued_rows == [(actor, "patching", "job-1", ["patchmanagement"], [])], queued_rows)

# enabling a replacement keeps its single 1.17.11 confirmation and sends no second flag
world(patching=True, pm=False)
captured.clear()
v2.queue_set_enabled("patchmanagement", True, disable_replaced=["patching"])
must(captured[0]["disable_modules"] == ["patching"] and captured[0]["replacement_confirmed"] is False, captured[0])
exc = refused(lambda: v2.queue_set_enabled("patchmanagement", True))
must(isinstance(exc, v2.ModuleReplacementConfirmationRequired), exc)
# a flag that nothing needs is harmless, and a plain module needs neither
v2.queue_set_enabled("patchmanagement", True, disable_replaced=["patching"], confirm_replacement_switch=True)
must(captured[-1]["replacement_confirmed"] is False, "the flag is carried only when the switch needs it")
world(patching=False, pm=False)
manifest("bystander")
captured.clear()
v2.queue_set_enabled("bystander", True)
must(captured[0]["disable_modules"] == [] and captured[0]["replacement_confirmed"] is False, captured[0])
# the core module with no enabled replacement: nothing to confirm
v2.queue_set_enabled("patching", True)
must(captured[-1]["disable_modules"] == [] and captured[-1]["replacement_confirmed"] is False, captured[-1])
must(rows()["patching"]["second_confirmation_required"] is False, "no replacement enabled")

# a stale list is refused with the fresh one
world(patching=False, pm=True)
exc = refused(lambda: v2.queue_set_enabled("patching", True, disable_replaced=["stale"], confirm_replacement_switch=True))
must(isinstance(exc, v2.ModuleReplacementConfirmationRequired) and exc.will_disable == ["patchmanagement"], exc)

# a rival replacement: both are switched off, and every one is named
world(patching=False, pm=True)
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
must(v2.validate_enable("patching")["will_disable"] == ["patchmanagement", "rival"], v2.validate_enable("patching"))

# the replaced module must still pass its own rules: a missing dependency refuses the enable
world(patching=False, pm=True, patching_extra={"dependencies": {"missingdep": "*"}})
check = v2.validate_enable("patching")
must(not check["valid"] and check["problems"][0]["type"] == "missing_dependency" and check["will_disable"] == [], check)

# ------------------------------------------------------------------------------------------ CQ35: dependants of the replacement
world(patching=False, pm=True)
manifest("consumer", dependencies={"patchmanagement": "*"})
STATE["modules"]["consumer"] = {"enabled": True}
check = v2.validate_enable("patching")
# 1.17.14 (CQ35): a dependant of the replacement is a warning in the second confirmation, no longer a refusal.
must(check["valid"] is True and check["will_disable"] == ["patchmanagement"], check)
must(check["replacement_dependants"] == [{"replacement": "patchmanagement", "modules": ["consumer"]}], check)
must(not any(p.get("type") == "replacement_has_dependants" for p in check["problems"]), "replacement_has_dependants is gone")
captured.clear()
exc = refused(lambda: v2.queue_set_enabled("patching", True, disable_replaced=["patchmanagement"]))
must(isinstance(exc, v2.ModuleReplacementSecondConfirmationRequired), exc)
must(exc.as_payload()["dependants"] == [{"replacement": "patchmanagement", "modules": ["consumer"]}] and "consumer" in str(exc), exc.as_payload())
must(captured == [], "nothing queued before the confirmation")
v2.queue_set_enabled("patching", True, disable_replaced=["patchmanagement"], confirm_replacement_switch=True)
must(captured[0]["disable_modules"] == ["patchmanagement"] and captured[0]["replacement_confirmed"] is True, "no cascade: the job is the same as before")
STATE["modules"]["consumer"]["enabled"] = False  # a disabled dependant is not listed
must(v2.validate_enable("patching")["replacement_dependants"] == [], "a disabled dependant is not listed")
# a dependant of the replaced module itself stays satisfied by the module that comes on
manifest("consumer", dependencies={"patching": "*"})
STATE["modules"]["consumer"]["enabled"] = True
must(v2.validate_enable("patching")["valid"] is True, "a dependant of the replaced module is unaffected")

# a queued job that disables the replacement counts as done, so two queued jobs cannot both pass
world(patching=False, pm=True)
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": False}
(JOBS / "a.json").write_text(json.dumps({"id": "a", "action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "disable_modules": [], "status": "queued", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
check = v2.validate_enable("rival")
must(not check["valid"] and check["problems"][0]["reason"] == "competing-replacement", check)
(JOBS / "a.json").unlink()
# a queued switch (enable patching, disable patchmanagement) is already in the state the next job is judged against
world(patching=False, pm=True)
(JOBS / "a.json").write_text(json.dumps({"id": "a", "action": "enable", "plugin_id": "patching", "affected_modules": ["patching"],
                                          "disable_modules": ["patchmanagement"], "replacement_confirmed": True, "status": "queued",
                                          "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
model = v2._model_with_pending_jobs(mr.live_model())
must(model["patching"].enabled is True and model["patchmanagement"].enabled is False, "the queued switch is applied")
must(rows()["patching"]["will_disable"] == [] and rows()["patching"]["second_confirmation_required"] is False, "nothing left to switch for a second job")
must(rows()["patchmanagement"]["will_enable"] == [], "and nothing to hand back: the replacement is off in the pending model")
(JOBS / "a.json").unlink()

# ------------------------------------------------------------------------------------------ CQ33: hand_back_plan truth table
core = mr.Node(id="patching", category="core", enabled=False, capabilities={})
repl = mr.Node(id="repl", enabled=True, replaces="patching", capabilities={})
must(mr.hand_back_plan({"patching": core, "repl": repl}, "repl") == ["patching"], "replacement enabled, target installed and disabled")
must(mr.hand_back_plan({"patching": mr._with_enabled({"patching": core}, {"patching": True})["patching"], "repl": repl}, "repl") == [], "both enabled (the reconcile case): nothing to hand back")
must(mr.hand_back_plan({"repl": repl}, "repl") == [], "target not installed")
must(mr.hand_back_plan({"patching": core, "repl": mr.Node(id="repl", enabled=False, replaces="patching")}, "repl") == [], "replacement already disabled")
must(mr.hand_back_plan({"patching": core, "repl": repl, "rival": mr.Node(id="rival", enabled=True, replaces="patching")}, "repl") == [], "a rival replacement stays enabled")
must(mr.hand_back_plan({"patching": core, "repl": repl, "rival": mr.Node(id="rival", enabled=False, replaces="patching")}, "repl") == ["patching"], "a disabled rival does not block it")
must(mr.hand_back_plan({"patching": mr.Node(id="patching", category="", enabled=False), "repl": repl}, "repl") == [], "target not a core or server module")
must(mr.hand_back_plan({"patching": mr.Node(id="patching", category="server", enabled=False), "repl": repl}, "repl") == ["patching"], "a server module comes back too")
must(mr.hand_back_plan({"patching": core}, "patching") == [] and mr.hand_back_plan({}, "nosuch") == [], "no replaces, no module")

# ------------------------------------------------------------------------------------------ CQ33: disabling the replacement
world(patching=False, pm=True)
check = v2.validate_disable("patchmanagement")
must(check == {"valid": True, "problems": [], "will_enable": ["patching"], "hand_back_unavailable": [], "hand_back_confirmation_required": False}, check)
table = rows()
must(table["patchmanagement"]["will_enable"] == ["patching"] and table["patching"]["will_enable"] == [], table)
captured.clear()
queued_rows.clear()
job = v2.queue_set_enabled("patchmanagement", False, requested_by="alice", actor=actor)
payload = captured[0]
must(payload["action"] == "disable" and payload["plugin_id"] == "patchmanagement" and payload["affected_modules"] == ["patchmanagement"], payload)
must(payload["enable_modules"] == ["patching"] and "disable_modules" not in payload and payload["cascade"] is False, payload)
must(queued_rows == [(actor, "patchmanagement", "job-1", [], ["patching"])], queued_rows)
# no confirmation is asked for this direction (CQ36 assumption)
v2.queue_set_enabled("patchmanagement", False, disable_replaced=None, confirm_replacement_switch=None)

# both enabled (the reconcile case): nothing is handed back
world(patching=True, pm=True)
must(v2.validate_disable("patchmanagement")["will_enable"] == [] and rows()["patchmanagement"]["will_enable"] == [], "target already enabled")
captured.clear()
v2.queue_set_enabled("patchmanagement", False)
must(captured[0]["enable_modules"] == [], captured[0])
# a plain module: an empty list, and no audit row
manifest("bystander")
STATE["modules"]["bystander"] = {"enabled": True}
queued_rows.clear()
v2.queue_set_enabled("bystander", False)
must(captured[-1]["enable_modules"] == [] and queued_rows == [], captured[-1])

# the reconcile job never hands back: the replaced module is already enabled in that state
world(patching=True, pm=True)
captured.clear()
result = mr.reconcile_conflicts()
must(len(result) == 1 and result[0]["queued"] is True, result)
must(captured[0]["action"] == "disable" and captured[0]["reason"] == "replacement_conflict" and "enable_modules" not in captured[0], captured[0])

# dependants: the replaced module's own dependants stay satisfied, the replacement's dependants still need cascade
world(patching=False, pm=True)
manifest("consumer", dependencies={"patching": "*"})
STATE["modules"]["consumer"] = {"enabled": True}
manifest("direct", dependencies={"patchmanagement": "*"})
STATE["modules"]["direct"] = {"enabled": False}
captured.clear()
v2.queue_set_enabled("patchmanagement", False)
must(captured[0]["affected_modules"] == ["patchmanagement"] and captured[0]["enable_modules"] == ["patching"], "consumer needs patching, which comes back: no cascade")
STATE["modules"]["direct"]["enabled"] = True
exc = refused(lambda: v2.queue_set_enabled("patchmanagement", False))
must("direct" in str(exc) and "cascade" in str(exc) and "consumer" not in str(exc), exc)
captured.clear()
v2.queue_set_enabled("patchmanagement", False, cascade=True)
must(captured[0]["affected_modules"] == ["direct", "patchmanagement"] and captured[0]["enable_modules"] == ["patching"], captured[0])

# the replaced module cannot come back: 1.17.14 (CQ34) replaces the refusal with a warning and a confirmation.
# The full set of cases is in tests/module-replacement-warnings-1.17.14.py.
for extra, needle in (({"dependencies": {"missingdep": "*"}}, "missingdep"), ({"requires": {"nosuch": ">=1"}}, "runtime")):
    world(patching=False, pm=True, patching_extra=extra)
    captured.clear()
    check = v2.validate_disable("patchmanagement")
    must(check["valid"] is True and check["will_enable"] == [] and check["hand_back_confirmation_required"] is True, check)
    must(check["hand_back_unavailable"][0]["module"] == "patching" and needle in " ".join(check["hand_back_unavailable"][0]["reasons"]), check)
    exc = refused(lambda: v2.queue_set_enabled("patchmanagement", False))
    must(isinstance(exc, v2.ModuleReplacementHandBackConfirmationRequired) and needle in str(exc) and "hand_back_blocked" not in str(exc), exc)
    must(captured == [], "nothing queued without the confirmation")
world(patching=False, pm=True, patching_extra={"dependencies": {"helper": "*"}})
manifest("helper")
STATE["modules"]["helper"] = {"enabled": False}
must(v2.validate_disable("patchmanagement")["hand_back_confirmation_required"] is True, "a disabled dependency of the replaced module is a warning")
exc = refused(lambda: v2.queue_set_enabled("patchmanagement", False))
must("helper" in str(exc) and "disabled" in str(exc), exc)
STATE["modules"]["helper"]["enabled"] = True
must(v2.validate_disable("patchmanagement")["hand_back_confirmation_required"] is False, "enabled: it can come back")
# an unrelated disable is never blocked by this
manifest("bystander")
STATE["modules"]["bystander"] = {"enabled": True}
v2.queue_set_enabled("bystander", False)

# a second queued job sees the post-job state
world(patching=False, pm=True)
(JOBS / "b.json").write_text(json.dumps({"id": "b", "action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "enable_modules": ["patching"], "status": "dispatched", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
model = v2._model_with_pending_jobs(mr.live_model())
must(model["patching"].enabled is True and model["patchmanagement"].enabled is False, "the queued hand-back is applied")
must(rows()["patchmanagement"]["will_enable"] == [] and rows()["patching"]["will_disable"] == [], "a second job has nothing to switch")
(JOBS / "b.json").write_text(json.dumps({"id": "b", "action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "enable_modules": ["patching"], "status": "succeeded", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
must(v2._model_with_pending_jobs(mr.live_model())["patching"].enabled is False, "a finished job is already in the live state, not overlaid")
(JOBS / "b.json").unlink()

# a server module is handed back the same way
reset(backups=False, altbackups=True)
manifest("backups", category="server", capabilities={"backups.run": "1.0.0"})
manifest("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"})
must(v2.validate_disable("altbackups")["will_enable"] == ["backups"], v2.validate_disable("altbackups"))
reset(backups=False, altbackups=True)
manifest("backups", category="server", capabilities={"backups.run": "1.0.0"})
manifest("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"})
must(rows()["backups"]["will_disable"] == ["altbackups"] and rows()["backups"]["second_confirmation_required"] is True, rows()["backups"])

# the public job shows what the root helper switched
public = module_manager.public_job({"id": "00000000-0000-4000-8000-000000000001", "status": "succeeded", "action": "disable", "plugin_id": "patchmanagement",
                                    "disabled_modules": ["x"], "enabled_modules": ["patching"], "reconciled_modules": ["y"], "disable_modules": ["secret"],
                                    "enable_modules": ["secret"], "replacement_confirmed": True})
must(public["enabled_modules"] == ["patching"] and public["disabled_modules"] == ["x"] and public["reconciled_modules"] == ["y"], public)
must("disable_modules" not in public and "enable_modules" not in public and "replacement_confirmed" not in public, "the request fields stay private")

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

world(patching=False, pm=True)
captured.clear()
alice = types.SimpleNamespace(username="alice")


def post(data, plugin="patching"):
    return views.ModuleV2StateView().post(types.SimpleNamespace(data=data, user=alice), plugin)


answer = post({"enabled": True})
must(answer.status_code == 400 and answer.data["code"] == "replacement_confirmation_required" and answer.data["will_disable"] == ["patchmanagement"], answer.data)
answer = post({"enabled": True, "disable_replaced": ["patchmanagement"]})
must(answer.status_code == 400 and answer.data["code"] == "replacement_second_confirmation_required", answer.data)
must(answer.data["will_disable"] == ["patchmanagement"] and answer.data["module"] == "patching" and "patchmanagement" in answer.data["detail"], answer.data)
answer = post({"enabled": True, "disable_replaced": ["patchmanagement"], "confirm_replacement_switch": False})
must(answer.status_code == 400 and answer.data["code"] == "replacement_second_confirmation_required", "false is not a confirmation")
for bad in ("true", 1, "yes", [True], {}):
    answer = post({"enabled": True, "disable_replaced": ["patchmanagement"], "confirm_replacement_switch": bad})
    must(answer.status_code == 400 and "code" not in answer.data and "confirm_replacement_switch" in answer.data["detail"], (bad, answer.data))
must(captured == [], "nothing queued so far")
answer = post({"enabled": True, "disable_replaced": ["patchmanagement"], "confirm_replacement_switch": True})
must(answer.status_code == 202 and captured[0]["disable_modules"] == ["patchmanagement"] and captured[0]["replacement_confirmed"] is True, (answer.data, captured))
# the disable direction asks nothing and sends the hand-back list
captured.clear()
answer = post({"enabled": False}, "patchmanagement")
must(answer.status_code == 202 and captured[0]["enable_modules"] == ["patching"], (answer.data, captured))
# the replaced module cannot come back: 1.17.14 answers with its own code until the request confirms
world(patching=False, pm=True, patching_extra={"dependencies": {"missingdep": "*"}})
captured.clear()
answer = post({"enabled": False}, "patchmanagement")
must(answer.status_code == 400 and answer.data["code"] == "replacement_hand_back_confirmation_required" and "missingdep" in answer.data["detail"] and captured == [], answer.data)
answer = post({"enabled": "yes"})
must(answer.status_code == 400 and answer.data["detail"] == "enabled must be true or false.", answer.data)  # the existing contract

print("[TEST] PASS module replacement hand-back 1.17.12")
