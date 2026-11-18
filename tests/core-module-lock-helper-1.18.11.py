#!/usr/bin/env python3
"""Regression: Core 1.18.11, the root helpers re-check the core-module lock (Johan, 18 November 2026).

The job files are Tactical-writable, so Core's queue check is not enough. scripts/module-v2-job-helper.py (disable) and
scripts/module-job-helper.py (remove) read the category from root-owned manifests and module state, never from the job.
Harness: tests/module-replacement-helper-handback-1.17.12.py (stubbed state and manifests, no root, no sudo).
What cannot run here: the helpers as root and a real reload."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
HARNESS = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
source = HARNESS.read_text(encoding="utf-8")
cut = source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")
H = {"__name__": "stubs", "__file__": str(HARNESS)}
exec(compile(source[:cut], str(HARNESS), "exec"), H)
helper, put, drop, flags, run, must, world, refused = (H[k] for k in ("helper", "put", "drop", "flags", "run", "must", "world", "refused"))
REPO, STATE_FILE, SAVES, SYNC = (H[k] for k in ("REPO", "STATE_FILE", "SAVES", "SYNC"))
ROOT = H["ROOT"]
DEV = {"on": False}
_world = world


def world(**kw):
    """The harness world, with the replacement signed as premium (a replacement with no category counts only on a development server)."""
    _world(**kw)
    put("patchmanagement", category="premium", replaces="patching", capabilities=H["PM_CAPS"])


helper.development_server = lambda: DEV["on"]
SENTENCE = "always stays installed and on"

# ------------------------------------------------------------------------------------------------ v2 helper: disable
DEV["on"] = False
world(patching=True, pm=False)
before = STATE_FILE.read_bytes()
text = refused(lambda: helper.apply_disable_job(REPO, ["patching"], []), SENTENCE)
must("patching is a core module" in text, text)
must(STATE_FILE.read_bytes() == before and SAVES == [], "nothing written")
# a cascade that reaches a core module, and a forged job that lists one
world(patching=True, pm=False)
put("extra")
refused(lambda: helper.apply_disable_job(REPO, ["extra", "patching"], []), SENTENCE)
must(flags()["patching"] is True, "no state change")
world(patching=True, pm=False)
result = run({"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement", "patching"], "category": "premium"})
must(result["status"] == "failed" and SENTENCE in result["error"] and flags()["patching"] is True, result)
result = run({"action": "disable", "plugin_id": "patching", "affected_modules": ["patching"], "category": "premium", "enabled": False})
must(result["status"] == "failed" and SENTENCE in result["error"] and flags()["patching"] is True and SYNC["calls"] == 0, result)
# the category in the job is ignored: the root-owned manifest decides
result = run({"action": "disable", "plugin_id": "patching", "affected_modules": ["patching"], "category": "test"})
must(result["status"] == "failed", result)
# a premium module recorded as core in module state is locked too (fails closed)
world(patching=True, pm=False)
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"patching": {"enabled": True}, "patchmanagement": {"enabled": True, "category": "core"}}}), encoding="utf-8")
refused(lambda: helper.apply_disable_job(REPO, ["patchmanagement"], []), SENTENCE)
# server, premium and test modules are not locked
world(patching=True, pm=True)
put("srv", category="server")
put("tst", category="test")
helper.apply_disable_job(REPO, ["srv", "tst"], [])
must(flags()["srv"] is False or True, "state written")
state = json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"]
must(state["srv"]["enabled"] is False and state["tst"]["enabled"] is False, state)
# development server
DEV["on"] = True
world(patching=True, pm=False)
helper.apply_disable_job(REPO, ["patching"], [])
must(flags()["patching"] is False, "development lets a core module go")
DEV["on"] = False
# honoured replacement: patchmanagement enabled, patching off (a core module the replacement already switched off)
world(patching=False, pm=True)
helper.apply_disable_job(REPO, ["patching"], [])
must(flags()["patching"] is False, "an honoured replacement lifts the lock")
# replacement installed but off, or a conflict (both on): locked
world(patching=True, pm=False)
refused(lambda: helper.apply_disable_job(REPO, ["patching"], []), SENTENCE)
world(patching=True, pm=True)
refused(lambda: helper.apply_disable_job(REPO, ["patching"], []), SENTENCE)

# ------------------------------------------------------------------------------------------------ the replacement flow is untouched
world(patching=True, pm=False)
result = run({"action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "disable_modules": ["patching"]})
must(result["status"] == "succeeded" and flags() == {"patching": False, "patchmanagement": True}, (result, flags()))
result = run({"action": "disable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "enable_modules": ["patching"]})
must(result["status"] == "succeeded" and flags() == {"patching": True, "patchmanagement": False}, (result, flags()))
world(patching=False, pm=True)
disabled, reconciled, _ = helper.apply_enable_job(REPO, ["patching"], ["patchmanagement"], True)
must(disabled == ["patchmanagement"], "enable of a core module is never refused")
world(patching=False, pm=False)
helper.apply_enable_job(REPO, ["patching"], [])
must(flags()["patching"] is True, "enable stays open")
text_v2 = (ROOT / "scripts/module-v2-job-helper.py").read_text(encoding="utf-8")
for name in ("def apply_enable_job(", "def apply_install_prepare_disable(", "def verify_install_disables("):
    start = text_v2.index(name)
    body = text_v2[start:text_v2.index("\ndef ", start + 10)]
    must("core_lock" not in body, name)

# ------------------------------------------------------------------------------------------------ v1 helper: remove
V1_PATH = ROOT / "scripts" / "module-job-helper.py"
v1_source = V1_PATH.read_text(encoding="utf-8")
v1 = types.ModuleType("module_job_helper_v1")
v1.__file__ = str(V1_PATH)
exec(compile(v1_source.replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(V1_PATH), "exec"), v1.__dict__)
v1._trusted_stat = lambda info: True
v1.STATE_FILE = STATE_FILE
v1.development_server = lambda: DEV["on"]
put("srv", category="server")
put("halo", category="premium")


def state_of(**enabled):
    STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {k: {"enabled": v} for k, v in enabled.items()}}), encoding="utf-8")


DEV["on"] = False
state_of(patching=True, patchmanagement=False, srv=True, halo=True)
try:
    v1.plan_remove_core_lock(REPO, "patching")
except RuntimeError as exc:
    must(SENTENCE in str(exc) and "patching" in str(exc), exc)
else:
    raise AssertionError("a core module was removable")
v1.plan_remove_core_lock(REPO, "srv")
v1.plan_remove_core_lock(REPO, "halo")
v1.plan_remove_core_lock(REPO, "not-installed")
state_of(patching=False, patchmanagement=True, srv=True, halo=True)
v1.plan_remove_core_lock(REPO, "patching")  # an honoured replacement is installed and on
state_of(patching=False, patchmanagement=False, srv=True, halo=True)
refused_v1 = False
try:
    v1.plan_remove_core_lock(REPO, "patching")
except RuntimeError:
    refused_v1 = True
must(refused_v1, "a replacement that is off does not lift the lock")
state_of(patching=True, patchmanagement=True, srv=True, halo=True)
try:
    v1.plan_remove_core_lock(REPO, "patching")
except RuntimeError:
    pass
else:
    raise AssertionError("a conflict is not an honoured replacement")
DEV["on"] = True
state_of(patching=True, patchmanagement=False, srv=True, halo=True)
v1.plan_remove_core_lock(REPO, "patching")
DEV["on"] = False
# the state category alone locks
STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {"halo": {"enabled": True, "category": "core"}}}), encoding="utf-8")
try:
    v1.plan_remove_core_lock(REPO, "halo")
except RuntimeError:
    pass
else:
    raise AssertionError("state category core must lock")
# the check runs before the hand-back plan, with the manifest category (never the job) deciding
body = v1_source[v1_source.index("def run_job(job_id):"):]
must(body.index("plan_remove_core_lock(repo_root, job[\"plugin_id\"])") < body.index("plan_remove_hand_back(repo_root, job[\"plugin_id\"]"), "order")
must("sudoers" not in v1_source[v1_source.index("def plan_remove_core_lock"):v1_source.index("def set_module_enabled")], "no new surface")
print("[TEST] PASS core module lock helpers 1.18.11")
