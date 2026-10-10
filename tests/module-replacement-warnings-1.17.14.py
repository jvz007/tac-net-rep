#!/usr/bin/env python3
"""1.17.14 regression: replacement warnings instead of refusals (Johan CQ34, CQ35, CQ36, 9 October 2026).

CQ34: disabling a replacement whose replaced module cannot come back no longer raises. The catalogue row lists only the modules
that can come back in ``will_enable``, names the ones that cannot in ``hand_back_unavailable`` (plain-English reasons and the
required modules), and says ``hand_back_confirmation_required``. ``queue_set_enabled`` refuses with the new
``ModuleReplacementHandBackConfirmationRequired`` (code ``replacement_hand_back_confirmation_required``) until the request carries
``confirm_without_hand_back: true``; then the job disables the replacement and hands back only what can come back.
CQ35: an enabled module that names the replacement directly no longer refuses the enable of the replaced module. It is listed in
``replacement_dependants`` and in the second confirmation. CQ36: a replacement disabled in a deliberate cascade hands back too;
a reconcile job and a failed job never hand back.

It uses the stub harness of tests/module-replacement-handback-1.17.12.py (that file's setup is executed from it, so the two cannot
drift): the real registry, module_state, module_replacement, module_manager, module_manager_v2 and module_v2_views run against
manifests in a temporary folder. Django and the Linux-only modules are stubbed. What cannot run here: a real job on the server.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "module-replacement-handback-1.17.12.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("# ------------------------------------------------------------------------------------------ CQ32: enabling the replaced module")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
v2, mr, module_manager, STATE, manifest, world, rows, captured, JOBS, must, refused, reset = (
    G[k] for k in ("v2", "mr", "module_manager", "STATE", "manifest", "world", "rows", "captured", "JOBS", "must", "refused", "reset"))
PM_CAPS, PATCHING_CAPS = G["PM_CAPS"], G["PATCHING_CAPS"]
queued = []
mr.audit_switch_queued = lambda actor, subject, job_id, disabled=(), enabled=(), skipped=(): queued.append(
    (subject, sorted(disabled), sorted(enabled), sorted(skipped)))
alice = types.SimpleNamespace(username="alice")


def blocked_world(kind):
    """patching (core, disabled) is replaced by patchmanagement (enabled); patching cannot come back for ``kind``."""
    if kind == "missing":
        world(patching=False, pm=True, patching_extra={"dependencies": {"missingdep": "*"}})
        return "missingdep"
    if kind == "disabled":
        world(patching=False, pm=True, patching_extra={"dependencies": {"helper": "*"}})
        manifest("helper", category="core")
        STATE["modules"]["helper"] = {"enabled": False}
        return "helper"
    if kind == "version":
        world(patching=False, pm=True, patching_extra={"dependencies": {"helper": ">=2.0.0"}})
        manifest("helper", category="core")
        STATE["modules"]["helper"] = {"enabled": True}
        return "helper"
    if kind == "runtime":
        world(patching=False, pm=True, patching_extra={"requires": {"nosuch": ">=1"}})
        return None
    raise AssertionError(kind)


# ------------------------------------------------------------------------------------------ CQ34: the warning, per cause
REASON = {"missing": "not installed", "disabled": "disabled", "version": ">=2.0.0", "runtime": "runtime requirement"}
for kind in ("missing", "disabled", "version", "runtime"):
    required = blocked_world(kind)
    check = v2.validate_disable("patchmanagement")
    must(check["valid"] is True and check["will_enable"] == [] and check["hand_back_confirmation_required"] is True, (kind, check))
    [row] = check["hand_back_unavailable"]
    must(row["module"] == "patching" and REASON[kind] in " ".join(row["reasons"]), (kind, row))
    must(row["required_modules"] == ([required] if required else []), (kind, row))
    must(all(isinstance(text, str) and text.isascii() for text in row["reasons"]), "plain printable text")
    must(check["problems"][0]["type"] == "hand_back_unavailable" and "hand_back_blocked" not in json.dumps(check), (kind, check["problems"]))
    table = rows()
    must(table["patchmanagement"]["will_enable"] == [] and table["patchmanagement"]["hand_back_unavailable"] == [row], (kind, table["patchmanagement"]))
    must(table["patchmanagement"]["hand_back_confirmation_required"] is True and table["patching"]["hand_back_unavailable"] == [], kind)
    # the first request is refused with the new code and queues nothing
    captured.clear()
    queued.clear()
    exc = refused(lambda: v2.queue_set_enabled("patchmanagement", False, requested_by="alice", actor=alice))
    must(isinstance(exc, v2.ModuleReplacementHandBackConfirmationRequired) and isinstance(exc, v2.ModuleManagerV2Error), (kind, exc))
    payload = exc.as_payload()
    must(payload["code"] == "replacement_hand_back_confirmation_required" and payload["module"] == "patchmanagement", payload)
    must(payload["will_enable"] == [] and payload["hand_back_unavailable"] == [row] and payload["detail"] == str(exc), payload)
    must(captured == [] and queued == [], "a refusal queues and audits nothing")
    # a flag that is not exactly true does not confirm
    for flag in (None, False):
        refused(lambda: v2.queue_set_enabled("patchmanagement", False, confirm_without_hand_back=flag))
    must(captured == [], "false and absent are not a confirmation")
    # the confirmed request queues a plain disable and records what was skipped
    job = v2.queue_set_enabled("patchmanagement", False, requested_by="alice", actor=alice, confirm_without_hand_back=True)
    must(job["queued"] is True and len(captured) == 1, captured)
    must(captured[0]["action"] == "disable" and captured[0]["plugin_id"] == "patchmanagement" and captured[0]["affected_modules"] == ["patchmanagement"], captured[0])
    must(captured[0]["enable_modules"] == [] and captured[0]["hand_back_skipped"] == ["patching"] and "disable_modules" not in captured[0], captured[0])
    must(queued == [("patchmanagement", [], [], ["patching"])], queued)

# a job with nothing skipped records an empty list
world(patching=False, pm=True)
captured.clear()
v2.queue_set_enabled("patchmanagement", False)
must(captured[0]["enable_modules"] == ["patching"] and captured[0]["hand_back_skipped"] == [], captured[0])
must(rows()["patchmanagement"]["hand_back_unavailable"] == [] and rows()["patchmanagement"]["hand_back_confirmation_required"] is False, "can come back: no warning")
# the flag is harmless when nothing needs it
captured.clear()
v2.queue_set_enabled("patchmanagement", False, confirm_without_hand_back=True)
must(captured[0]["enable_modules"] == ["patching"] and captured[0]["hand_back_skipped"] == [], "the flag is only used when something cannot come back")

# not manageable: the replaced module is protected, so it cannot be switched from the UI
world(patching=False, pm=True)
module_manager.PROTECTED_PLUGIN_IDS = frozenset({"example", "patching"})
try:
    check = v2.validate_disable("patchmanagement")
    must(check["hand_back_confirmation_required"] is True and check["will_enable"] == [], check)
    must("cannot be enabled or disabled" in check["hand_back_unavailable"][0]["reasons"][0] and check["hand_back_unavailable"][0]["required_modules"] == [], check)
finally:
    module_manager.PROTECTED_PLUGIN_IDS = frozenset({"example"})

# a partly blocked case: two replacements are disabled together (a cascade), one replaced module can come back and one cannot
reset(patching=False, backups=False, pm=True, altbackups=True, mm=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
manifest("backups", category="server", capabilities={"backups.run": "1.0.0"}, dependencies={"missingdep": "*"})
manifest("mm", category="core")
manifest("pm", replaces="patching", capabilities=PM_CAPS, dependencies={"mm": "*"})
manifest("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"}, dependencies={"mm": "*"})
check = v2.validate_disable("mm", affected=["pm", "altbackups"])
must(check["will_enable"] == ["patching"] and [r["module"] for r in check["hand_back_unavailable"]] == ["backups"], check)
captured.clear()
exc = refused(lambda: v2.queue_set_enabled("mm", False, cascade=True))
must(isinstance(exc, v2.ModuleReplacementHandBackConfirmationRequired) and exc.will_enable == ["patching"], exc)
v2.queue_set_enabled("mm", False, cascade=True, confirm_without_hand_back=True)
must(sorted(captured[0]["affected_modules"]) == ["altbackups", "mm", "pm"] and captured[0]["enable_modules"] == ["patching"]
     and captured[0]["hand_back_skipped"] == ["backups"], captured[0])

# ------------------------------------------------------------------------------------------ CQ36: cascade hands back, others never
world(patching=False, pm=True)
manifest("mm", category="core")
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS, dependencies={"mm": "*"})
STATE["modules"]["mm"] = {"enabled": True}
captured.clear()
exc = refused(lambda: v2.queue_set_enabled("mm", False))
must("patchmanagement" in str(exc), "without cascade the dependant still needs it")
v2.queue_set_enabled("mm", False, cascade=True)
must(captured[0]["affected_modules"] == ["patchmanagement", "mm"] and captured[0]["enable_modules"] == ["patching"], captured[0])
# a reconcile job (replacement_conflict) and a failed job never hand back
world(patching=True, pm=True)
captured.clear()
result = mr.reconcile_conflicts()
must(result and captured[0]["reason"] == "replacement_conflict" and "enable_modules" not in captured[0], captured)
world(patching=False, pm=True)
(JOBS / "f.json").write_text(json.dumps({"id": "f", "action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"],
                                          "enable_modules": ["patching"], "status": "failed", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
model = v2._model_with_pending_jobs(mr.live_model())
must(model["patching"].enabled is False and model["patchmanagement"].enabled is True, "a failed job changed nothing")
(JOBS / "f.json").unlink()

# ------------------------------------------------------------------------------------------ CQ35: dependants are a warning
world(patching=False, pm=True)
manifest("consumer", category="core", dependencies={"patchmanagement": "*"})
manifest("viaold", category="core", dependencies={"patching": "*"})
STATE["modules"]["consumer"] = {"enabled": True}
STATE["modules"]["viaold"] = {"enabled": True}
dependants = [{"replacement": "patchmanagement", "modules": ["consumer"]}]
check = v2.validate_enable("patching")
must(check["valid"] is True and check["problems"] == [] and check["will_disable"] == ["patchmanagement"] and check["replacement_dependants"] == dependants, check)
must(rows()["patching"]["replacement_dependants"] == dependants and rows()["patchmanagement"]["replacement_dependants"] == [], rows()["patching"])
must(all("replacement_dependants" in row for row in rows().values()), "every row carries the field")
captured.clear()
exc = refused(lambda: v2.queue_set_enabled("patching", True, disable_replaced=["patchmanagement"]))
must(isinstance(exc, v2.ModuleReplacementSecondConfirmationRequired), exc)
payload = exc.as_payload()
must(payload["dependants"] == dependants and payload["code"] == "replacement_second_confirmation_required" and "consumer" in payload["detail"], payload)
must(payload["will_disable"] == ["patchmanagement"] and captured == [], "nothing queued")
v2.queue_set_enabled("patching", True, disable_replaced=["patchmanagement"], confirm_replacement_switch=True)
must(captured[0]["disable_modules"] == ["patchmanagement"] and captured[0]["replacement_confirmed"] is True and captured[0]["affected_modules"] == ["patching"], captured[0])
must("consumer" not in captured[0]["affected_modules"] and captured[0].get("cascade") is not True, "no cascade")
# a module that depends only on the replaced module is not listed
STATE["modules"]["consumer"]["enabled"] = False
must(v2.validate_enable("patching")["replacement_dependants"] == [] and rows()["patching"]["replacement_dependants"] == [], "viaold depends on patching, not on the replacement")
# a payload without dependants keeps the old fields for old callers
old = v2.ModuleReplacementSecondConfirmationRequired(["patchmanagement"], "patching")
must(old.as_payload()["dependants"] == [] and set(old.as_payload()) == {"detail", "code", "will_disable", "module", "dependants"}, old.as_payload())

# ------------------------------------------------------------------------------------------ the view
for _name in ("drf_spectacular", "rest_framework"):
    sys.modules.setdefault(_name, types.ModuleType(_name))


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


def post(data, plugin="patchmanagement"):
    return views.ModuleV2StateView().post(types.SimpleNamespace(data=data, user=alice), plugin)


blocked_world("missing")
captured.clear()
answer = post({"enabled": False})
must(answer.status_code == 400 and answer.data["code"] == "replacement_hand_back_confirmation_required", answer.data)
must(answer.data["module"] == "patchmanagement" and answer.data["will_enable"] == [] and answer.data["hand_back_unavailable"][0]["module"] == "patching", answer.data)
must("missingdep" in answer.data["hand_back_unavailable"][0]["required_modules"] and captured == [], answer.data)
for bad in ("true", 1, "yes", [True], {}, 0):
    answer = post({"enabled": False, "confirm_without_hand_back": bad})
    must(answer.status_code == 400 and "code" not in answer.data and "confirm_without_hand_back" in answer.data["detail"], (bad, answer.data))
answer = post({"enabled": False, "confirm_without_hand_back": False})
must(answer.status_code == 400 and answer.data["code"] == "replacement_hand_back_confirmation_required", "false is not a confirmation")
must(captured == [], "nothing queued yet")
answer = post({"enabled": False, "confirm_without_hand_back": True})
must(answer.status_code == 202 and captured[0]["hand_back_skipped"] == ["patching"] and captured[0]["enable_modules"] == [], (answer.data, captured))
# an old caller on a module that can come back sees nothing new
world(patching=False, pm=True)
captured.clear()
answer = post({"enabled": False})
must(answer.status_code == 202 and captured[0]["enable_modules"] == ["patching"], answer.data)
# the public job shows what was skipped
public = module_manager.public_job({"id": "00000000-0000-4000-8000-000000000002", "status": "succeeded", "action": "disable", "plugin_id": "patchmanagement",
                                    "hand_back_skipped": ["patching"], "enable_modules": []})
must(public["hand_back_skipped"] == ["patching"] and "enable_modules" not in public, public)

# ------------------------------------------------------------------------------------------ the audit rows (the real functions)
rows_ = mr._outcome_rows({"id": "j1", "plugin_id": "patchmanagement", "action": "disable", "status": "succeeded", "hand_back_skipped": ["patching"]}, lambda module_id: "")
must(rows_ and "stayed off" in rows_[0]["message"] and rows_[0]["metadata"]["hand_back_skipped"] == ["patching"], rows_)

print("[TEST] PASS module replacement warnings 1.17.14")
