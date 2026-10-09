#!/usr/bin/env python3
"""1.17.11 regression: the root job helper re-checks the module replacement rules and holds an enable or install job to the confirmed list.

scripts/module-v2-job-helper.py runs as root and must never import the Tactical-writable tree, so it carries its own copy of the
AD-20 rules and its own manifest reader. This test loads the helper source with the Linux-only pieces stubbed (fcntl, pwd, the
trusted-bash lookup that needs a root-owned bash, chown, the module-state lock) and runs it against a temporary repo root and module
state file. It covers: a confirmed disable, an unconfirmed one, a race (state or manifest changed after the confirmation), the
atomic two-flag write, the rollback of the disable, the install path (verify before any state is written, one write, re-enable on
rollback), the manifest reader's safety rules, and a drift guard that runs Core's module_replacement and the helper's copy over the
same scenario matrix and asserts the same reason codes. What cannot run here: the helper as root, sudo dispatch, a real reload.
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

from tec_tac import module_replacement as mr, registry  # noqa: E402

# ------------------------------------------------------------------------------------------ load the helper
HELPER = ROOT / "scripts" / "module-v2-job-helper.py"
source = HELPER.read_text(encoding="utf-8")
LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"
must(source.count(LOOKUP) == 1, "the trusted-bash lookup line moved; update this test")
helper = types.ModuleType("module_v2_job_helper")
helper.__file__ = str(HELPER)
exec(compile(source.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(HELPER), "exec"), helper.__dict__)
mr._module_category.is_development_server = lambda: True
helper.development_server = lambda: True  # AD-21 (1.17.13): these tests are about replacement, not about the category gate

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


# ------------------------------------------------------------------------------------------ the manifest reader
world()
nodes = helper.read_installed_manifests(REPO)
must(set(nodes) == {"patching", "patchmanagement"} and nodes["patchmanagement"]["replaces"] == "patching", nodes)
must(nodes["patching"]["category"] == "core" and nodes["patching"]["capabilities"] == PATCHING_CAPS and nodes["patching"]["replaces"] == "", nodes)
# manifests that break Core's own rules are treated as not installed
put("badcat", category="bogus")
put("coreswap", category="core", replaces="patching")
put("badprefix", category="core", capabilities={"other.thing": "1.0.0"})
put("badver", capabilities={"badver.x": "1.0"})
put("selfie", replaces="selfie")
put("serverswap", category="server", replaces="patching")
put("emptyreplaces", replaces="")
(REPO / "extensions" / "idmismatch").mkdir()
(REPO / "extensions" / "idmismatch" / "tec_tac.json").write_text(json.dumps({"id": "other"}), encoding="utf-8")
(REPO / "extensions" / "notjson").mkdir()
(REPO / "extensions" / "notjson" / "tec_tac.json").write_text("[1, 2]", encoding="utf-8")
(REPO / "extensions" / "empty").mkdir()
must(set(helper.read_installed_manifests(REPO)) == {"patching", "patchmanagement"}, sorted(helper.read_installed_manifests(REPO)))
# an invalid manifest is one that Core's registry refuses as well
for bad_id, payload in (("badcat", {"category": "bogus"}), ("coreswap", {"category": "core", "replaces": "patching"}), ("badprefix", {"category": "core", "capabilities": {"other.thing": "1.0.0"}}),
                        ("badver", {"capabilities": {"badver.x": "1.0"}}), ("selfie", {"replaces": "selfie"}), ("serverswap", {"category": "server", "replaces": "patching"})):
    tmp = Path(tempfile.mkdtemp(prefix="tectac-reg-"))
    (tmp / bad_id).mkdir()
    (tmp / bad_id / "tec_tac.json").write_text(json.dumps({"id": bad_id, "type": "extension", "version": "1.0.0", **payload}), encoding="utf-8")
    saved = registry.EXTENSIONS_ROOT
    registry.EXTENSIONS_ROOT = tmp
    try:
        registry.get_plugins()
        raise AssertionError(f"the registry accepted {bad_id}")
    except registry.RegistryError:
        pass
    finally:
        registry.EXTENSIONS_ROOT = saved
for folder in ("badcat", "coreswap", "badprefix", "badver", "selfie", "serverswap", "emptyreplaces"):
    drop(folder)
for folder in ("idmismatch", "notjson"):
    (REPO / "extensions" / folder / "tec_tac.json").unlink()
    (REPO / "extensions" / folder).rmdir()
(REPO / "extensions" / "empty").rmdir()
# a symlink is never followed (skipped where this PC cannot create one)
try:
    (REPO / "extensions" / "linked").symlink_to(REPO / "extensions" / "patching", target_is_directory=True)
    must("linked" not in helper.read_installed_manifests(REPO), "a symlinked folder is ignored")
    (REPO / "extensions" / "linked").unlink()
except (OSError, NotImplementedError):
    pass
# the trust rule: root-owned, not writable by group or others
rule = types.SimpleNamespace
exec_ns = {}
exec(compile(source[source.index("def _manifest_stat_ok"):source.index("def _read_manifest_nofollow")], "rule", "exec"), exec_ns)
ok = exec_ns["_manifest_stat_ok"]
must(ok(rule(st_uid=0, st_mode=0o100644)) and ok(rule(st_uid=0, st_mode=0o040755)), "root-owned, 644 and 755")
must(not ok(rule(st_uid=1000, st_mode=0o100644)), "owned by Tactical")
must(not ok(rule(st_uid=0, st_mode=0o100664)) and not ok(rule(st_uid=0, st_mode=0o100666)) and not ok(rule(st_uid=0, st_mode=0o040777)), "writable by group or others")
must(not ok(rule(st_uid=0, st_mode=0o100620)), "group-writable")
# a manifest the reader cannot trust makes the module "not installed", which every rule treats as a refusal
helper._manifest_stat_ok = lambda info: False
must(helper.read_installed_manifests(REPO) == {}, "nothing is trusted when the files are not root-owned")
helper._manifest_stat_ok = lambda info: True

# ------------------------------------------------------------------------------------------ enable: confirmed, unconfirmed
world(patching=True, pm=False)
before = STATE_FILE.read_bytes()
disabled, reconciled, previous = helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"])
must(disabled == ["patching"] and reconciled == [] and previous == {"patchmanagement": False, "patching": True}, (disabled, reconciled, previous))
must(flags() == {"patching": False, "patchmanagement": True}, flags())
must(len(SAVES) == 1 and SAVES[0]["modules"]["patching"]["enabled"] is False and SAVES[0]["modules"]["patchmanagement"]["enabled"] is True,
     "atomic: one state write carries both flags")  # the enable and the disable are never saved apart
# rollback puts the flags back
helper.restore_enabled_flags(previous)
must(flags() == {"patching": True, "patchmanagement": False}, flags())
# an unconfirmed disable changes nothing
world(patching=True, pm=False)
before = STATE_FILE.read_bytes()
for confirmed in ([], ["other"]):
    refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], confirmed), "did not confirm")
    must(STATE_FILE.read_bytes() == before and SAVES == [], "nothing written")
# a longer confirmed list is fine: the computed list only has to be a subset
helper.apply_enable_job(REPO, ["patchmanagement"], ["patching", "patching", "spare"])
must(flags() == {"patching": False, "patchmanagement": True}, flags())
# nothing to disable: the empty list is enough
world(patching=False, pm=False)
must(helper.apply_enable_job(REPO, ["patchmanagement"], [])[0] == [] and flags() == {"patching": False, "patchmanagement": True}, flags())
# a plain module is untouched by any of this, with or without a list
world(patching=True, pm=False, bystander=False)
put("bystander")
must(helper.apply_enable_job(REPO, ["bystander"], [])[:2] == ([], []) and flags()["bystander"] is True and flags()["patching"] is True, flags())
# a module the helper cannot read a manifest for cannot be enabled on a replacement's confirmation
world(patching=True, pm=False)
drop("patchmanagement")
must(flags()["patching"] is True, "setup")
helper.apply_enable_job(REPO, ["patchmanagement"], [])  # no list: an ordinary enable of a module with no readable manifest
must(flags()["patchmanagement"] is True and flags()["patching"] is True, "an ordinary enable is not blocked")
world(patching=True, pm=False)
drop("patchmanagement")
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "cannot verify")
must(flags() == {"patching": True, "patchmanagement": False}, "unchanged")

# ------------------------------------------------------------------------------------------ enable: the race
# 1. the replaced module was disabled by hand after the confirmation: nothing to disable, the enable goes through
world(patching=False, pm=False)
must(helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"])[0] == [] and flags()["patchmanagement"] is True, flags())
# 2. a rival replacement was enabled after the confirmation
world(patching=True, pm=False)
put("rival", replaces="patching", capabilities=PM_CAPS)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": True}, "patchmanagement": {"enabled": False}, "rival": {"enabled": True}}}), encoding="utf-8")
before = STATE_FILE.read_bytes()
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "competing-replacement")
must(STATE_FILE.read_bytes() == before, "nothing changed")
# 3. the manifest lost a capability after the confirmation (parity)
world(patching=True, pm=False)
put("patchmanagement", replaces="patching", capabilities={"patching.windows": "1.2.0"})
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "capability-missing")
must(flags() == {"patching": True, "patchmanagement": False}, "unchanged")
# 4. the manifest now replaces a different module than the one the operator confirmed
world(patching=True, pm=False, other=True)
put("other", category="core", capabilities={})
put("patchmanagement", replaces="other", capabilities={})
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "did not confirm: other")
must(flags()["other"] is True and flags()["patching"] is True, "unchanged")
# 5. the replaced module was removed
world(patching=True, pm=False)
drop("patching")
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "target-missing")
# 6. the replaced module changed category (no longer core or server)
world(patching=True, pm=False)
put("patching", capabilities=PATCHING_CAPS)
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "target-not-core")
# 7. the core module is enabled while an enabled replacement points at it. 1.17.12 (CQ32): that is a switch, not a refusal,
# but it needs the confirmed list and the second confirmation (tests/module-replacement-helper-handback-1.17.12.py)
world(patching=False, pm=True)
refused(lambda: helper.apply_enable_job(REPO, ["patching"], []), "did not confirm: patchmanagement")
refused(lambda: helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"]), "did not confirm the switch")
must(flags() == {"patching": False, "patchmanagement": True}, "unchanged")
# 8. the replaced module hid its capabilities
world(patching=True, pm=False, patching_caps=None)
refused(lambda: helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"]), "capabilities-undeclared")
# 9. a server module is replaced the same way
world(patching=True, pm=False)
put("backups", category="server", capabilities={"backups.run": "1.0.0"})
put("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"})
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"backups": {"enabled": True}, "altbackups": {"enabled": False}, "patching": {"enabled": False}, "patchmanagement": {"enabled": False}}}), encoding="utf-8")
must(helper.apply_enable_job(REPO, ["altbackups"], ["backups"])[0] == ["backups"] and flags()["backups"] is False and flags()["altbackups"] is True, flags())
# 10. a corrupt state file is never overwritten
world()
STATE_FILE.write_text("{not json", encoding="utf-8")
try:
    helper.apply_enable_job(REPO, ["patchmanagement"], ["patching"])
    raise AssertionError("a corrupt state file was overwritten")
except RuntimeError as exc:
    must("unreadable" in str(exc), exc)
must(STATE_FILE.read_text(encoding="utf-8") == "{not json", "untouched")

# ------------------------------------------------------------------------------------------ enable: a pair already in the state
world(patching=True, pm=True, bystander=False)
put("bystander")
disabled, reconciled, previous = helper.apply_enable_job(REPO, ["bystander"], [])
must(disabled == [] and reconciled == ["patchmanagement"] and flags() == {"patching": True, "patchmanagement": False, "bystander": True}, (disabled, reconciled, flags()))
must(previous["patchmanagement"] is True and len(SAVES) == 1, "settled in the same write; the previous flag is kept for rollback")

# ------------------------------------------------------------------------------------------ run_job: enable
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
    return {"action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "disable_modules": ["patching"], **extra}


world(patching=True, pm=False)
result = run(enable_job())
must(result["status"] == "succeeded" and result["disabled_modules"] == ["patching"], result)
must(flags() == {"patching": False, "patchmanagement": True} and len(SAVES) == 1 and SYNC["calls"] == 1, (flags(), len(SAVES)))
# the runtime sync fails: the flags go back, the sync is tried once more, the job fails
world(patching=True, pm=False)
SYNC["fail_first"] = 1
result = run(enable_job())
must(result["status"] == "failed" and result["stage"] == "rollback" and "graceful reload" in result["error"], result)
must(flags() == {"patching": True, "patchmanagement": False}, "rolled back: the replaced module is enabled again and so is the state")
must(SYNC["calls"] == 2, "a second sync after the rollback")
# the rollback sync fails as well: still no exception out of the job, and the flags are right
world(patching=True, pm=False)
SYNC["fail_first"] = 2
result = run(enable_job())
must(result["status"] == "failed" and flags() == {"patching": True, "patchmanagement": False}, result)
# unconfirmed: the job fails before anything is written or synced
world(patching=True, pm=False)
result = run(enable_job(disable_modules=[]))
must(result["status"] == "failed" and "did not confirm" in result["error"] and SYNC["calls"] == 0 and SAVES == [], result)
must(flags() == {"patching": True, "patchmanagement": False}, "unchanged")
# a malformed list fails closed
for bad in ("patching", ["pat ching"], [1]):
    world(patching=True, pm=False)
    result = run(enable_job(disable_modules=bad))
    must(result["status"] == "failed" and "invalid disable_modules" in result["error"] and SAVES == [], (bad, result))
# an ordinary enable with a failing sync keeps its old behaviour: the flag stays
world(patching=False, pm=False, bystander=False)
put("bystander")
SYNC["fail_first"] = 1
result = run({"action": "enable", "plugin_id": "bystander", "affected_modules": ["bystander"]})
must(result["status"] == "failed" and flags()["bystander"] is True and SYNC["calls"] == 1, result)
# a disable job never needs a list
world(patching=False, pm=True)
result = run({"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "reason": "replacement_conflict", "requested_by": "system"})
must(result["status"] == "succeeded" and flags()["patchmanagement"] is False and flags()["patching"] is False, result)

# ------------------------------------------------------------------------------------------ run_job: install
INSTALLED = {}


def fake_batch_packages(job, running, root_trust):
    return [{"id": item["id"], "path": "x", "source": None} for item in job["plan"]["actions"]]


def fake_validate(job, packages, root_trust):
    return list(job["plan"]["order"]), [dict(item) for item in job["plan"]["actions"]]


def fake_install_packages(repo_root, packages, order, actions, log, backup_root):
    EVENTS.append("install")
    helper.backup_modules(repo_root, order, backup_root)  # the real backup of the code and the module state
    for module_id in order:
        INSTALLED[module_id](module_id)
    return list(order)


helper.batch_packages = fake_batch_packages
helper._validate_install_plan_against_signed_artifacts = fake_validate
helper.install_packages = fake_install_packages
helper.cleanup_successful_stage = lambda job, log: EVENTS.append("cleanup")
_real_verify, _real_remember, _real_set = helper.verify_install_disables, helper.remember_version, helper.set_enabled


def spy_verify(*args, **kwargs):
    EVENTS.append("verify")
    return _real_verify(*args, **kwargs)


def spy_remember(*args, **kwargs):
    EVENTS.append("remember")
    return _real_remember(*args, **kwargs)


SET_CALLS = []


def spy_set(module_ids, enabled):
    SET_CALLS.append((list(module_ids), enabled))
    EVENTS.append(f"set-{'on' if enabled else 'off'}")
    return _real_set(module_ids, enabled)


helper.verify_install_disables, helper.remember_version, helper.set_enabled = spy_verify, spy_remember, spy_set
PLAN = {"order": ["patchmanagement"], "actions": [{"id": "patchmanagement", "action": "install", "version": "1.0.0", "will_disable": ["patching"]}]}


def install_job(**extra):
    return {"action": "batch_install", "plugin_id": "batch", "plan": PLAN, "disable_modules": ["patching"], **extra}


def install_pm(module_id):
    put("patchmanagement", replaces="patching", capabilities=PM_CAPS)


INSTALLED["patchmanagement"] = install_pm


def fresh_install_world(**more):
    world(patching=True, pm=False, **more)
    drop("patchmanagement")
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    state["modules"].pop("patchmanagement", None)
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    SET_CALLS.clear()
    SAVES.clear()


fresh_install_world()
result = run(install_job())
must(result["status"] == "succeeded" and result["disabled_modules"] == ["patching"], result)
must(EVENTS == ["install", "verify", "remember", "set-off", "sync", "cleanup"], EVENTS)  # verified before any state is written, one disable, then the sync
must(SET_CALLS == [(["patching"], False)], SET_CALLS)
must(flags() == {"patching": False, "patchmanagement": True}, flags())
state = json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"]
must(state["patchmanagement"]["version"] == "1.0.0", state)
# unconfirmed: the verify raises before any state is written, and the existing rollback runs
fresh_install_world()
result = run(install_job(disable_modules=[]))
must(result["status"] == "failed" and "did not confirm" in result["error"] and result["stage"] == "rollback", result)
must(EVENTS[:2] == ["install", "verify"] and "remember" not in EVENTS and SET_CALLS == [], EVENTS)
must(flags() == {"patching": True} and not (REPO / "extensions" / "patchmanagement").exists(), "the fresh install was rolled back and nothing was disabled")
# a rule violation found after the packages landed (the target is in the same install) fails the same way
fresh_install_world()
plan_both = {"order": ["patching", "patchmanagement"], "actions": [{"id": "patching", "action": "install", "version": "1.0.0"}, {"id": "patchmanagement", "action": "install", "version": "1.0.0"}]}
INSTALLED["patching"] = lambda module_id: put("patching", category="core", capabilities=PATCHING_CAPS)
drop("patching")
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {}}), encoding="utf-8")
result = run(install_job(plan=plan_both, disable_modules=["patching"]))
must(result["status"] == "failed" and "target-enabled" in result["error"], result)
del INSTALLED["patching"]
# the sync fails after the disable: the rollback re-enables what this job disabled
fresh_install_world()
SYNC["fail_first"] = 1
result = run(install_job())
must(result["status"] == "failed" and result["stage"] == "rollback", result)
must(SET_CALLS == [(["patching"], False), (["patching"], True)], SET_CALLS)  # off, then the rollback puts it back on
must(flags() == {"patching": True} and not (REPO / "extensions" / "patchmanagement").exists(), flags())
must(EVENTS[-3:] == ["sync", "set-on", "sync"], EVENTS)
# an upgrade of an installed replacement names nothing, so nothing is disabled even with a list
world(patching=True, pm=False)
SET_CALLS.clear()
upgrade = {"order": ["patchmanagement"], "actions": [{"id": "patchmanagement", "action": "replace", "version": "1.1.0"}]}
result = run(install_job(plan=upgrade))
must(result["status"] == "succeeded" and SET_CALLS == [] and flags()["patching"] is True and "disabled_modules" not in result, result)  # Core refuses this upgrade before queueing; the worker never disables for it
# an install with no replacement does not touch the new code path
world(patching=True, pm=False, bystander=False)
INSTALLED["bystander"] = lambda module_id: put("bystander")
SET_CALLS.clear()
result = run({"action": "batch_install", "plugin_id": "batch", "disable_modules": [],
              "plan": {"order": ["bystander"], "actions": [{"id": "bystander", "action": "install", "version": "1.0.0"}]}})
must(result["status"] == "succeeded" and SET_CALLS == [] and "disabled_modules" not in result, result)

# ------------------------------------------------------------------------------------------ install verification on its own
world(patching=True, pm=False)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": True}}}), encoding="utf-8")  # a fresh install has no record yet
before = STATE_FILE.read_bytes()
actions = [{"id": "patchmanagement", "action": "install"}]
must(helper.verify_install_disables(REPO, ["patchmanagement"], actions, set(), ["patching"]) == ["patching"], "confirmed")
refused(lambda: helper.verify_install_disables(REPO, ["patchmanagement"], actions, set(), []), "did not confirm")
must(helper.verify_install_disables(REPO, ["patchmanagement"], actions, {"patchmanagement"}, []) == [], "installed before: an upgrade names nothing")
must(helper.verify_install_disables(REPO, ["patchmanagement"], [{"id": "patchmanagement", "action": "replace"}], set(), []) == [], "action replace names nothing")
must(STATE_FILE.read_bytes() == before and SAVES == [], "verification is read-only")
put("patchmanagement", replaces="patching", capabilities={"patching.windows": "1.2.0"})
refused(lambda: helper.verify_install_disables(REPO, ["patchmanagement"], actions, set(), ["patching"]), "capability-missing")

# ------------------------------------------------------------------------------------------ drift guard
# Core's rules and the helper's copy, over one scenario matrix. The reason code must be identical, and so must the enable and install decisions.
TARGET_CATEGORIES = ("core", "server", "", None)
REPLACEMENT_CAPS = {"same": dict(PATCHING_CAPS), "extra": {**PATCHING_CAPS, "patching.more": "3.0.0"}, "missing": {"patching.windows": "1.2.0"},
                    "lower": {"patching.windows": "1.1.9", "patching.scan": "1.0.0"}, "major": {"patching.windows": "2.0.0", "patching.scan": "1.0.0"},
                    "major-low": {"patching.windows": "0.9.0", "patching.scan": "1.0.0"}, "higher": {"patching.windows": "1.9.0", "patching.scan": "1.0.5"},
                    "none": None, "empty": {}}
TARGET_CAPS = {"declared": dict(PATCHING_CAPS), "empty": {}, "undeclared": None}
RIVALS = ("none", "enabled", "disabled")
cases = 0
for category, target_enabled, target_caps, replacement_enabled, caps_key, rival in itertools.product(
        TARGET_CATEGORIES, (False, True), TARGET_CAPS, (False, True), REPLACEMENT_CAPS, RIVALS):
    specs = {}
    if category is not None:
        specs["target"] = dict(category=category, enabled=target_enabled, replaces="", capabilities=TARGET_CAPS[target_caps])
    specs["repl"] = dict(category="", enabled=replacement_enabled, replaces="target", capabilities=REPLACEMENT_CAPS[caps_key])
    if rival != "none":
        specs["rival"] = dict(category="", enabled=rival == "enabled", replaces="target", capabilities=dict(PATCHING_CAPS))
    core_model = {name: mr.Node(id=name, **spec) for name, spec in specs.items()}
    helper_model = {name: {"id": name, **spec} for name, spec in specs.items()}
    for assume in (False, True):
        for name in specs:
            if not specs[name]["replaces"]:
                continue
            want = mr.check(core_model, name, assume_enabled=assume)[0]
            got = helper.replacement_check(helper_model, name, assume_enabled=assume)
            must(want == got, (category, target_enabled, target_caps, replacement_enabled, caps_key, rival, name, assume, want, got))
    # the enable decision: the same refusal or the same list
    if "repl" in specs:
        problems = mr.enable_problems(core_model, "repl")
        want_disables = mr.disable_plan(core_model, "repl")
        try:
            got_disables = helper.plan_enable_disables(helper_model, ["repl"], ["target", "repl", "rival"])
            got_ok = True
        except RuntimeError:
            got_disables, got_ok = [], False
        must((not problems) == got_ok, ("enable", category, target_enabled, target_caps, replacement_enabled, caps_key, rival, problems, got_ok))
        if got_ok and not specs["repl"]["enabled"]:
            must(want_disables == got_disables, ("enable list", want_disables, got_disables, category, target_enabled, replacement_enabled))
    # the install decision, with the helper reading the same facts from "disk"
    if "repl" in specs:
        fresh_model = dict(core_model)
        fresh_model["repl"] = mr.Node(id="repl", category="", enabled=True, replaces="target", capabilities=REPLACEMENT_CAPS[caps_key])
        want_problems = mr.install_problems(fresh_model, ["repl"], installed_ids=())
        want_names = mr.install_disables(fresh_model, ["repl"], ())
        manifests = {name: {k: v for k, v in spec.items() if k != "enabled"} | {"id": name} for name, spec in specs.items()}
        manifests["repl"] = {"id": "repl", "category": "", "replaces": "target", "capabilities": REPLACEMENT_CAPS[caps_key]}
        state = {"modules": {name: {"enabled": spec["enabled"]} for name, spec in specs.items() if name != "repl"}}
        saved = helper.read_installed_manifests, helper.load_module_state
        helper.read_installed_manifests, helper.load_module_state = (lambda root: manifests), (lambda: state)
        try:
            got_names = helper.verify_install_disables(REPO, ["repl"], [{"id": "repl", "action": "install"}], set(), ["target", "repl", "rival"])
            got_ok = True
        except RuntimeError:
            got_names, got_ok = [], False
        finally:
            helper.read_installed_manifests, helper.load_module_state = saved
        must((not want_problems) == got_ok, ("install", category, target_enabled, target_caps, caps_key, rival, want_problems, got_ok))
        if got_ok:
            must(want_names.get("repl", []) == got_names, ("install list", want_names, got_names))
    cases += 1
# the core module being enabled next to its enabled replacement
for category in ("core", "server"):
    core_model = {"target": mr.Node(id="target", category=category, enabled=False, capabilities={}), "repl": mr.Node(id="repl", enabled=True, replaces="target", capabilities={})}
    helper_model = {"target": {"id": "target", "category": category, "enabled": False, "replaces": "", "capabilities": {}},
                    "repl": {"id": "repl", "category": "", "enabled": True, "replaces": "target", "capabilities": {}}}
    # 1.17.12 (CQ32): not a refusal any more. Both sides name the replacement, and the helper needs both confirmations.
    must(mr.enable_problems(core_model, "target") == [] and mr.disable_plan(core_model, "target") == ["repl"], category)
    refused(lambda: helper.plan_enable_disables(helper_model, ["target"], []), "did not confirm: repl")
    refused(lambda: helper.plan_enable_disables(helper_model, ["target"], ["repl"]), "did not confirm the switch")
    must(helper.plan_enable_disables(helper_model, ["target"], ["repl"], True) == ["repl"], category)
# AD-21 (1.17.13): the replacement's category, on a development server and off one. Core and the helper must agree.
for dev in (True, False):
    mr._module_category.is_development_server = lambda d=dev: d
    helper.development_server = lambda d=dev: d
    for repl_category in ("", "premium", "test", "core", "server"):
        core_model = {"target": mr.Node(id="target", category="core", enabled=False, capabilities=dict(PATCHING_CAPS)),
                      "repl": mr.Node(id="repl", category=repl_category, enabled=True, replaces="target", capabilities=dict(PATCHING_CAPS))}
        helper_model = {"target": {"id": "target", "category": "core", "enabled": False, "replaces": "", "capabilities": dict(PATCHING_CAPS)},
                        "repl": {"id": "repl", "category": repl_category, "enabled": True, "replaces": "target", "capabilities": dict(PATCHING_CAPS)}}
        want = mr.check(core_model, "repl")[0]
        got = helper.replacement_check(helper_model, "repl")
        must(want == got, (dev, repl_category, want, got))
        honoured = repl_category == "premium" or (repl_category == "" and dev)
        must((want is None) == honoured and (honoured or want == "replacement-category"), (dev, repl_category, want))
mr._module_category.is_development_server = lambda: True
helper.development_server = lambda: True
# the shared version rule: every pair of versions gives the same answer
for declared, registered in itertools.product(("1.2.0", "1.0.0", "0.0.1", "2.3.4"), ("1.2.0", "1.2.1", "1.1.9", "2", "2.0", "2.0.0-1", "1.2.0-3", "0.9.0", "garbage", "", "3.0.0")):
    must(mr.version_within_declared(declared, registered) == helper._version_within_declared(declared, registered), (declared, registered))
must(cases == len(TARGET_CATEGORIES) * 2 * len(TARGET_CAPS) * 2 * len(REPLACEMENT_CAPS) * len(RIVALS), cases)
must(mr.REPLACEABLE_CATEGORIES == helper.REPLACEABLE_CATEGORIES, "the replaceable categories agree")

print(f"[TEST] PASS module replacement helper 1.17.11 ({cases} drift-guard scenarios)")
