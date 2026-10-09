#!/usr/bin/env python3
"""1.17.12 regression: the root job helper and the AD-20 hand-back (Johan CQ32 and CQ33, 9 October 2026).

scripts/module-v2-job-helper.py carries its own copy of the replacement rules (it runs as root and never imports the Tactical-writable
tree). This test loads the helper source the way tests/module-replacement-helper-1.17.11.py does and covers the 1.17.12 additions:

* enabling a replaced module switches its enabled replacement off only with the confirmed list AND ``replacement_confirmed`` (the second
  confirmation), and fails with nothing changed otherwise, after a state change, or when the runtime sync fails (flags rolled back);
* disabling a replacement switches the confirmed replaced module back on in ONE state write (``apply_disable_job``), re-checks every
  hand-back against root-owned manifests, refuses an unconfirmed or rule-breaking one with nothing changed, and rolls both flags back
  when the sync fails;
* the drift guard: Core's ``disable_plan`` and ``hand_back_plan`` and the helper's copy give the same answer over one scenario matrix.

What cannot run here: the helper as root, sudo dispatch, a real reload (see tests/module-replacement-handback-runtime-1.17.12.py).
"""
from __future__ import annotations

import itertools
import json
import os
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

from tec_tac import module_replacement as mr  # noqa: E402

# ------------------------------------------------------------------------------------------ load the helper
HELPER = ROOT / "scripts" / "module-v2-job-helper.py"
source = HELPER.read_text(encoding="utf-8")
LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"
must(source.count(LOOKUP) == 1, "the trusted-bash lookup line moved; update this test")
helper = types.ModuleType("module_v2_job_helper")
helper.__file__ = str(HELPER)
exec(compile(source.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(HELPER), "exec"), helper.__dict__)

TMP = Path(tempfile.mkdtemp(prefix="tectac-helper-"))
REPO = TMP / "repo"
(REPO / "extensions").mkdir(parents=True)
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
helper.atomic_json = lambda path, payload, mode=0o640, **kw: path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
helper._manifest_stat_ok = lambda info: True  # this PC has no root-owned files; the rule itself is tested below
SAVES = []
_real_save = helper.save_module_state_unlocked


def counting_save(state):
    SAVES.append(json.loads(json.dumps(state)))
    return _real_save(state)


helper.save_module_state_unlocked = counting_save

PATCHING_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
PM_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.1.0", "patching.extra": "1.0.0"}


def put(module_id, **manifest):
    folder = REPO / "extensions" / module_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", **manifest}), encoding="utf-8")


def drop(module_id):
    folder = REPO / "extensions" / module_id
    for child in folder.iterdir():
        child.unlink()
    folder.rmdir()


def world(*, patching=True, pm=False, pm_caps=PM_CAPS, patching_caps=PATCHING_CAPS, **more):
    for folder in list((REPO / "extensions").iterdir()):
        drop(folder.name)
    put("patching", category="core", **({"capabilities": patching_caps} if patching_caps is not None else {}))
    put("patchmanagement", replaces="patching", capabilities=pm_caps)
    flags = {"patching": patching, "patchmanagement": pm, **more}
    STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {name: {"enabled": on} for name, on in flags.items()}}), encoding="utf-8")
    SAVES.clear()


def flags():
    return {name: record.get("enabled") for name, record in json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"].items()}


def refused(call, needle=""):
    try:
        call()
    except RuntimeError as exc:
        must(needle in str(exc), exc)
        return str(exc)
    raise AssertionError("the helper accepted it")

EVENTS = []
helper.acquire_lifecycle_lock = lambda: None
helper.load_config = lambda: {"REPO_ROOT": str(REPO)}
helper._snapshot_v2_job_artifacts = lambda job_id, job, root: job
helper._verify_v2_job_trust = lambda config, job: []
helper._cleanup_claimed_job_inputs = lambda job_id: None
SYNC = {"fail_first": 0, "calls": 0}


def fake_sync(config, log, *, refresh_workers=False):
    SYNC["calls"] += 1
    EVENTS.append("sync")
    if SYNC["fail_first"]:
        SYNC["fail_first"] -= 1
        raise RuntimeError("Tactical graceful reload failed with status 1")


helper.sync_and_reload = fake_sync
COUNTER = itertools.count(1)


def run(job):
    job_id = "00000000-0000-4000-8000-%012d" % next(COUNTER)
    job = {"id": job_id, **job}
    path = helper.JOBS_ROOT / f"{job_id}.json"
    status = {"id": job_id, "action": job["action"], "status": "dispatched", "stage": "dispatched", "created_at": "2026-10-09T10:00:00"}
    path.write_text(json.dumps(status), encoding="utf-8")
    helper.load_job = lambda jid: (path, dict(status))
    helper.load_running_request = lambda jid: (None, dict(job))
    EVENTS.clear()
    SYNC["calls"] = 0
    helper.run_job(job_id)
    return json.loads(path.read_text(encoding="utf-8"))


def enable_job(**extra):
    """Enable the replaced module patching while its replacement patchmanagement is enabled (CQ32)."""
    return {"action": "enable", "plugin_id": "patching", "affected_modules": ["patching"], "disable_modules": ["patchmanagement"],
            "replacement_confirmed": True, **extra}


def disable_job(**extra):
    """Disable the replacement patchmanagement; the replaced module patching comes back (CQ33)."""
    return {"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "enable_modules": ["patching"], **extra}


# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off
world(patching=False, pm=True)
before = STATE_FILE.read_bytes()
# both confirmations are needed
refused(lambda: helper.apply_enable_job(REPO, ["patching"], []), "did not confirm: patchmanagement")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"]), "did not confirm the switch")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], False), "did not confirm the switch")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], "true"), "did not confirm the switch")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], 1), "did not confirm the switch")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], [], True), "did not confirm: patchmanagement")  # the flag alone is not the list
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["other"], True), "did not confirm: patchmanagement")
must(STATE_FILE.read_bytes() == before and SAVES == [], "nothing written")
disabled, reconciled, previous = helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True)
must(disabled == ["patchmanagement"] and reconciled == [] and previous == {"patching": False, "patchmanagement": True}, (disabled, reconciled, previous))
must(flags() == {"patching": True, "patchmanagement": False}, flags())
must(len(SAVES) == 1 and SAVES[0]["modules"]["patching"]["enabled"] is True and SAVES[0]["modules"]["patchmanagement"]["enabled"] is False, "one state write carries both flags")
helper.restore_enabled_flags(previous)
must(flags() == {"patching": False, "patchmanagement": True}, "rollback puts both back")
# a longer confirmed list is fine (the computed list only has to be a subset)
helper.apply_enable_job(REPO, ["patching"], ["patchmanagement", "spare"], True)
must(flags() == {"patching": True, "patchmanagement": False}, flags())
# enabling a replacement keeps its single confirmation: the second flag is neither needed nor checked
world(patching=True, pm=False)
must(helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"])[0] == ["patching"] and flags() == {"patching": False, "patchmanagement": True}, flags())
# nothing to switch (the replacement is off): no second confirmation either
world(patching=False, pm=False)
must(helper.apply_enable_job(REPO, ["patching"], [])[0] == [] and flags()["patching"] is True, flags())
# a rival replacement is switched off too, and every one must be in the list
world(patching=False, pm=True)
put("rival", replaces="patching", capabilities=PM_CAPS)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": False}, "patchmanagement": {"enabled": True}, "rival": {"enabled": True}}}), encoding="utf-8")
before = STATE_FILE.read_bytes()
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True), "did not confirm: rival")
must(STATE_FILE.read_bytes() == before, "nothing changed")
helper.apply_enable_job(REPO, ["patching"], ["patchmanagement", "rival"], True)
must(flags() == {"patching": True, "patchmanagement": False, "rival": False}, flags())
# the replaced module and its replacement cannot be enabled by one job
world(patching=False, pm=True)
refused(lambda: helper.apply_enable_job(REPO, ["patching", "patchmanagement"], ["patchmanagement"], True), "same job")
# the race: the state changed after the confirmation
world(patching=False, pm=False)  # the replacement was switched off by hand: nothing to switch
must(helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True)[0] == [] and flags()["patching"] is True, flags())
world(patching=True, pm=True)  # the replaced module was enabled by hand: the pair is settled the 1.17.11 way
disabled, reconciled, previous = helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True)
must(disabled == [] and reconciled == ["patchmanagement"] and flags() == {"patching": True, "patchmanagement": False}, (disabled, reconciled))
world(patching=False, pm=True)  # a manifest changed after the confirmation: a second module now replaces patching and is enabled
put("late", replaces="patching", capabilities=PM_CAPS)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": False}, "patchmanagement": {"enabled": True}, "late": {"enabled": True}}}), encoding="utf-8")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True), "did not confirm: late")
world(patching=False, pm=True)
drop("patching")
helper.apply_enable_job(REPO, ["patching"], [], False)  # no manifest and no list: an ordinary enable, as in 1.17.11
world(patching=False, pm=True)
drop("patching")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True), "cannot verify")  # a confirmed list for a module with no trusted manifest
must(flags() == {"patching": False, "patchmanagement": True}, "unchanged")
world(patching=False, pm=True)
put("patching", capabilities=PATCHING_CAPS)  # no longer a core module: nothing replaces it any more, so there is nothing to confirm
must(helper.apply_enable_job(REPO, ["patching"], [], False)[0] == [], "not a core or server module: not a replaced module")

# run_job: both confirmations come from the root-owned copy of the job
world(patching=False, pm=True)
result = run(enable_job())
must(result["status"] == "succeeded" and result["disabled_modules"] == ["patchmanagement"] and result["reconciled_modules"] == [], result)
must(flags() == {"patching": True, "patchmanagement": False} and len(SAVES) == 1 and SYNC["calls"] == 1, (flags(), len(SAVES)))
for missing in ({"replacement_confirmed": False}, {"replacement_confirmed": "true"}, {"replacement_confirmed": None}, {"disable_modules": []}):
    world(patching=False, pm=True)
    result = run(enable_job(**missing))
    must(result["status"] == "failed" and "did not confirm" in result["error"] and SYNC["calls"] == 0 and SAVES == [], (missing, result))
    must(flags() == {"patching": False, "patchmanagement": True}, "unchanged")
world(patching=False, pm=True)
job = enable_job()
del job["replacement_confirmed"]  # an old caller that never sent the flag
result = run(job)
must(result["status"] == "failed" and "did not confirm the switch" in result["error"] and flags() == {"patching": False, "patchmanagement": True}, result)
# the sync fails: the flags go back, the sync is tried once more
world(patching=False, pm=True)
SYNC["fail_first"] = 1
result = run(enable_job())
must(result["status"] == "failed" and result["stage"] == "rollback" and "graceful reload" in result["error"], result)
must(flags() == {"patching": False, "patchmanagement": True} and SYNC["calls"] == 2, "the replacement is enabled again")
must(result["disabled_modules"] == ["patchmanagement"], "the job file keeps what it planned, for the audit sweep")
world(patching=False, pm=True)
SYNC["fail_first"] = 2
result = run(enable_job())
must(result["status"] == "failed" and flags() == {"patching": False, "patchmanagement": True}, result)

# ------------------------------------------------------------------------------------------ CQ33: disable hands the replaced module back
world(patching=False, pm=True)
before = STATE_FILE.read_bytes()
enabled, previous = helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"])
must(enabled == ["patching"] and previous == {"patchmanagement": True, "patching": False}, (enabled, previous))
must(flags() == {"patching": True, "patchmanagement": False}, flags())
must(len(SAVES) == 1 and SAVES[0]["modules"]["patching"]["enabled"] is True and SAVES[0]["modules"]["patchmanagement"]["enabled"] is False, "ONE state write carries both flags")
helper.restore_enabled_flags(previous)
must(flags() == {"patching": False, "patchmanagement": True}, "rollback puts both back")
# without a list it is exactly the old disable, and it reads no manifest
world(patching=False, pm=True)
drop("patching")
drop("patchmanagement")
must(helper.apply_disable_job(REPO, ["patchmanagement"], [])[0] == [] and flags() == {"patching": False, "patchmanagement": False}, flags())
# the cascade: more modules are disabled in the same write
world(patching=False, pm=True, consumer=True)
put("consumer", dependencies={"patchmanagement": "*"})
enabled, previous = helper.apply_disable_job(REPO, ["consumer", "patchmanagement"], ["patching"])
must(enabled == ["patching"] and flags() == {"patching": True, "patchmanagement": False, "consumer": False} and len(SAVES) == 1, flags())


def untouched(call, needle):
    before_bytes = STATE_FILE.read_bytes()
    del SAVES[:]
    refused(call, needle)
    must(STATE_FILE.read_bytes() == before_bytes and SAVES == [], "nothing changed")


# it enables only what the job confirmed: an empty list never hands back (the reconcile job and old-format jobs)
world(patching=False, pm=True)
must(helper.apply_disable_job(REPO, ["patchmanagement"], [])[0] == [] and flags() == {"patching": False, "patchmanagement": False}, "an old-format or reconcile job never hands back")
# a hand-back that breaks a rule fails with nothing changed
world(patching=False, pm=True)
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["bystander"]), "no trusted manifest")
put("bystander")
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["bystander"]), "not a core or server module")
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patchmanagement"]), "not a core or server module")  # the replacement is not a replaced module
put("othercore", category="core", capabilities={})
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": False}, "patchmanagement": {"enabled": True}, "othercore": {"enabled": False}}}), encoding="utf-8")
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["othercore"]), "no enabled replacement of it is being disabled")  # a core module nothing replaces
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching", "othercore"]), "no enabled replacement of it is being disabled")
# state changes after the confirmation
world(patching=True, pm=True)  # the replaced module was enabled by hand
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "enabled already")
world(patching=False, pm=False)  # the replacement was disabled by hand
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "no enabled replacement")
world(patching=False, pm=True)  # a rival replacement is enabled now
put("rival", replaces="patching", capabilities=PM_CAPS)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": False}, "patchmanagement": {"enabled": True}, "rival": {"enabled": True}}}), encoding="utf-8")
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "rival also replaces it")
# the rival is part of the same cascade: both leave, so the module can come back
enabled, _ = helper.apply_disable_job(REPO, ["patchmanagement", "rival"], ["patching"])
must(enabled == ["patching"] and flags() == {"patching": True, "patchmanagement": False, "rival": False}, flags())
world(patching=False, pm=True)  # the replaced module changed category
put("patching", capabilities=PATCHING_CAPS)
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "not a core or server module")
world(patching=False, pm=True)  # the replaced module was removed
drop("patching")
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "no trusted manifest")
world(patching=False, pm=True)  # a manifest the reader cannot trust
helper._manifest_stat_ok = lambda info: False
untouched(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"]), "no trusted manifest")
helper._manifest_stat_ok = lambda info: True
# a corrupt state file is never overwritten
world(patching=False, pm=True)
STATE_FILE.write_text("{not json", encoding="utf-8")
try:
    helper.apply_disable_job(REPO, ["patchmanagement"], ["patching"])
    raise AssertionError("a corrupt state file was overwritten")
except RuntimeError as exc:
    must("unreadable" in str(exc), exc)
must(STATE_FILE.read_text(encoding="utf-8") == "{not json", "untouched")
# a server module is handed back the same way
world(patching=False, pm=False)
put("backups", category="server", capabilities={"backups.run": "1.0.0"})
put("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"})
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"backups": {"enabled": False}, "altbackups": {"enabled": True}}}), encoding="utf-8")
must(helper.apply_disable_job(REPO, ["altbackups"], ["backups"])[0] == ["backups"] and flags() == {"backups": True, "altbackups": False}, flags())

# the job field is validated like disable_modules
for good in ([], ["patching"]):
    must(helper._confirmed_enable_modules({"enable_modules": good}) == good, good)
must(helper._confirmed_enable_modules({}) == [], "absent is empty")
for bad in ("patching", ["pat ching"], [1], {"a": 1}):
    try:
        helper._confirmed_enable_modules({"enable_modules": bad})
        raise AssertionError(f"accepted {bad!r}")
    except RuntimeError as exc:
        must("invalid enable_modules" in str(exc), exc)

# run_job: the disable branch
world(patching=False, pm=True)
result = run(disable_job())
must(result["status"] == "succeeded" and result["enabled_modules"] == ["patching"] and "disabled_modules" not in result, result)
must(flags() == {"patching": True, "patchmanagement": False} and len(SAVES) == 1 and SYNC["calls"] == 1, (flags(), len(SAVES)))
# an unconfirmed or rule-breaking hand-back: the job fails before anything is written or synced
world(patching=False, pm=True)
result = run(disable_job(enable_modules=["bystander"]))
must(result["status"] == "failed" and "no trusted manifest" in result["error"] and SYNC["calls"] == 0 and SAVES == [], result)
must(flags() == {"patching": False, "patchmanagement": True}, "unchanged")
for bad in ("patching", ["pat ching"], [1]):
    world(patching=False, pm=True)
    result = run(disable_job(enable_modules=bad))
    must(result["status"] == "failed" and "invalid enable_modules" in result["error"] and SAVES == [] and flags()["patchmanagement"] is True, (bad, result))
# the 1.17.11 reconcile job and an old-format job never hand back
world(patching=True, pm=True)
result = run({"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "reason": "replacement_conflict", "requested_by": "system"})
must(result["status"] == "succeeded" and result["enabled_modules"] == [] and flags() == {"patching": True, "patchmanagement": False}, result)
world(patching=False, pm=True)
result = run({"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"]})
must(result["status"] == "succeeded" and flags() == {"patching": False, "patchmanagement": False}, "no list, no hand-back")
# the sync fails after the write: both flags go back and the sync is tried once more (the disable branch had no rollback before)
world(patching=False, pm=True)
SYNC["fail_first"] = 1
result = run(disable_job())
must(result["status"] == "failed" and result["stage"] == "rollback" and "graceful reload" in result["error"], result)
must(flags() == {"patching": False, "patchmanagement": True} and SYNC["calls"] == 2, flags())
must(result["enabled_modules"] == ["patching"], "the job file keeps what it planned")
world(patching=False, pm=True)
SYNC["fail_first"] = 2
result = run(disable_job())
must(result["status"] == "failed" and flags() == {"patching": False, "patchmanagement": True}, result)
# a plain disable with a failing sync keeps its old behaviour: no rollback, the flag stays off
world(patching=False, pm=False, bystander=True)
put("bystander")
SYNC["fail_first"] = 1
result = run({"action": "disable", "plugin_id": "bystander", "affected_modules": ["bystander"]})
must(result["status"] == "failed" and flags()["bystander"] is False and SYNC["calls"] == 1, result)

# ------------------------------------------------------------------------------------------ drift guard (1.17.12 rules)
TARGET_CATEGORIES = ("core", "server", "", None)
REPLACEMENT_CAPS = {"same": dict(PATCHING_CAPS), "missing": {"patching.windows": "1.2.0"}, "none": None}
cases = 0
for category, target_enabled, replacement_enabled, caps_key, rival in itertools.product(
        TARGET_CATEGORIES, (False, True), (False, True), REPLACEMENT_CAPS, ("none", "enabled", "disabled")):
    specs = {}
    if category is not None:
        specs["target"] = dict(category=category, enabled=target_enabled, replaces="", capabilities=dict(PATCHING_CAPS))
    specs["repl"] = dict(category="", enabled=replacement_enabled, replaces="target", capabilities=REPLACEMENT_CAPS[caps_key])
    if rival != "none":
        specs["rival"] = dict(category="", enabled=rival == "enabled", replaces="target", capabilities=dict(PATCHING_CAPS))
    core_model = {name: mr.Node(id=name, **spec) for name, spec in specs.items()}
    helper_model = {name: {"id": name, **spec} for name, spec in specs.items()}
    if "target" in specs:
        # CQ32: enabling the target. Core names the replacements it switches off; the helper computes the same list.
        want = mr.disable_plan(core_model, "target")
        try:
            got = helper.plan_enable_disables(helper_model, ["target"], ["repl", "rival", "spare"], True)
        except RuntimeError:
            got = None
        if not specs["target"]["enabled"]:
            must(got is not None and got == want, ("enable", category, replacement_enabled, caps_key, rival, want, got))
            must(mr.switches_replacement(core_model, "target") == bool(want), ("switches", want))
            if want:
                refused(lambda: helper.plan_enable_disables(helper_model, ["target"], ["repl", "rival", "spare"], False), "did not confirm the switch")
                refused(lambda: helper.plan_enable_disables(helper_model, ["target"], [], True), "did not confirm:")
            else:
                must(helper.plan_enable_disables(helper_model, ["target"], [], False) == [], "nothing to confirm")
        # CQ33: disabling the replacement. Core plans the hand-back; the helper accepts exactly that.
        plan = mr.hand_back_plan(core_model, "repl")
        try:
            accepted = helper.plan_hand_back(helper_model, ["repl"], ["target"])
        except RuntimeError:
            accepted = None
        must((plan == ["target"]) == (accepted == ["target"]), ("hand back", category, target_enabled, replacement_enabled, caps_key, rival, plan, accepted))
        if plan:
            must(helper.plan_hand_back(helper_model, ["repl"], plan) == plan and helper.plan_hand_back(helper_model, ["repl"], []) == [], plan)
    else:
        must(mr.hand_back_plan(core_model, "repl") == [], "target not installed")
        refused(lambda: helper.plan_hand_back(helper_model, ["repl"], ["target"]), "no trusted manifest")
    cases += 1
# a rival that leaves in the same job does not block the hand-back on the helper side (Core plans it only when the rival is off already)
core_model = {"target": mr.Node(id="target", category="core", enabled=False, capabilities={}), "repl": mr.Node(id="repl", enabled=True, replaces="target", capabilities={}),
              "rival": mr.Node(id="rival", enabled=True, replaces="target", capabilities={})}
helper_model = {"target": {"id": "target", "category": "core", "enabled": False, "replaces": "", "capabilities": {}},
                "repl": {"id": "repl", "category": "", "enabled": True, "replaces": "target", "capabilities": {}},
                "rival": {"id": "rival", "category": "", "enabled": True, "replaces": "target", "capabilities": {}}}
must(mr.hand_back_plan(core_model, "repl") == [] and helper.plan_hand_back(helper_model, ["repl", "rival"], ["target"]) == ["target"], "the cascade disables both")
refused(lambda: helper.plan_hand_back(helper_model, ["repl"], ["target"]), "rival also replaces it")
must(cases == len(TARGET_CATEGORIES) * 2 * 2 * len(REPLACEMENT_CAPS) * 3, cases)

print(f"[TEST] PASS module replacement helper hand-back 1.17.12 ({cases} drift-guard scenarios)")
