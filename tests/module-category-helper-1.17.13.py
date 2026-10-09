#!/usr/bin/env python3
"""1.17.13 regression: the root job helper and AD-21 (module categories), plus the rollback record of a failed switch.

scripts/module-v2-job-helper.py runs as root and carries its own copy of the rules (it never imports the Tactical-writable tree).
This test loads the helper the way tests/module-replacement-helper-handback-1.17.12.py does (that file's harness is executed from
it, so the two cannot drift) and covers:

* the manifest reader accepts core, server, premium and test, refuses anything else, and refuses ``replaces`` on a test module;
* ``development_server()`` reads the root-owned ``TEC_TAC_ENVIRONMENT`` from the root config and fails closed;
* enabling and installing a test module (or one with no category) is refused off a development server, re-checked from root-owned
  manifests, and the install writes the manifest category into the module's state entry in the same state write;
* a failed enable or disable records what actually happened: ``rolled_back`` only after the flags were restored, ``rollback_error``
  when restoring raised, and neither when nothing was changed (Medium held from the 1.17.12 review).

What cannot run here: the helper as root, sudo dispatch, a real reload (see tests/module-replacement-handback-runtime-1.17.13.py).
"""
from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)
helper, world, put, drop, flags, refused, run, enable_job, disable_job, must = (
    G[k] for k in ("helper", "world", "put", "drop", "flags", "refused", "run", "enable_job", "disable_job", "must"))
REPO, STATE_FILE, SAVES, SYNC, EVENTS = (G[k] for k in ("REPO", "STATE_FILE", "SAVES", "SYNC", "EVENTS"))
ROOT = G["ROOT"]

# a second copy of the helper with nothing patched, for the pure functions
HELPER_PATH = ROOT / "scripts" / "module-v2-job-helper.py"
raw = HELPER_PATH.read_text(encoding="utf-8")
LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"
pure = types.ModuleType("module_v2_job_helper_pure")
pure.__file__ = str(HELPER_PATH)
exec(compile(raw.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(HELPER_PATH), "exec"), pure.__dict__)

# ------------------------------------------------------------------------------------------ the manifest reader
PLUGIN = "demo"
for value in ("core", "server", "premium", "test", "", " Premium ", "TEST"):
    node = pure.manifest_node({"id": PLUGIN, "category": value})
    must(node is not None and node["category"] == value.strip().lower(), value)
must(pure.manifest_node({"id": PLUGIN})["category"] == "", "no category stays empty")
for bad in ("bogus", "retired", "premium,test", "tests", 5, None, ["premium"]):
    must(pure.manifest_node({"id": PLUGIN, "category": bad}) is None, bad)
must(pure.manifest_node({"id": PLUGIN, "category": "premium", "replaces": "patching"})["replaces"] == "patching", "premium may replace")
must(pure.manifest_node({"id": PLUGIN, "replaces": "patching"})["replaces"] == "patching", "no category may replace (a development server honours it)")
for category in ("test", "core", "server"):
    must(pure.manifest_node({"id": PLUGIN, "category": category, "replaces": "patching"}) is None, f"{category} may never replace")
must(pure.manifest_node({"id": PLUGIN, "category": "premium", "capabilities": {"other.thing": "1.0.0"}}) is not None, "the prefix rule stays for core and server only")
must(pure.manifest_node({"id": PLUGIN, "category": "test", "capabilities": {"other.thing": "1.0.0"}}) is not None, "the prefix rule stays for core and server only")
must(pure.manifest_node({"id": PLUGIN, "category": "core", "capabilities": {"other.thing": "1.0.0"}}) is None, "core keeps the prefix rule")
must(pure.KNOWN_CATEGORIES == {"", "core", "server", "premium", "test"}, pure.KNOWN_CATEGORIES)

# ------------------------------------------------------------------------------------------ the development flag
CONFIGS = {"value": {}}


def config():
    value = CONFIGS["value"]
    if isinstance(value, Exception):
        raise value
    return value


pure.load_config = config
for value, expected in (({"TEC_TAC_ENVIRONMENT": "development"}, True), ({"TEC_TAC_ENVIRONMENT": " Development "}, True), ({"TEC_TAC_ENVIRONMENT": "production"}, False),
                        ({}, False), ({"TEC_TAC_ENVIRONMENT": ""}, False), ({"TEC_TAC_ENVIRONMENT": "dev"}, False), ({"TEC_TAC_ENVIRONMENT": "staging"}, False),
                        (RuntimeError("Tec-Tac config must be root-owned and not group/world writable"), False)):
    CONFIGS["value"] = value
    must(pure.development_server() is expected, (value, expected))
# only the root-owned config decides: an environment variable of the calling process is never read
import os  # noqa: E402

os.environ["TEC_TAC_ENVIRONMENT"] = "development"
CONFIGS["value"] = {}
must(pure.development_server() is False, "the process environment is not the root config")
del os.environ["TEC_TAC_ENVIRONMENT"]
for development in (True, False):
    for category, refused_value in (("", not development), (None, not development), ("test", not development), ("core", False), ("server", False), ("premium", False)):
        must(pure.category_refused(category, development) is refused_value, (development, category))
    must(pure.replacement_category_ok("premium", development) is True and pure.replacement_category_ok("", development) is development, development)
    for other in ("test", "core", "server", "bogus"):
        must(pure.replacement_category_ok(other, development) is False, other)

# ------------------------------------------------------------------------------------------ enable
DEV = {"on": False}
helper.development_server = lambda: DEV["on"]


def plain_world(**flags_):
    for folder in list((REPO / "extensions").iterdir()):
        drop(folder.name)
    put("plain")
    put("tagged", category="core")
    put("pre", category="premium")
    put("tst", category="test")
    STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {name: {"enabled": False} for name in ("plain", "tagged", "pre", "tst")}}), encoding="utf-8")
    SAVES.clear()


plain_world()
for module_id in ("plain", "tst"):
    before = STATE_FILE.read_bytes()
    refused(lambda: helper.apply_enable_job(REPO, [module_id], []), "not a development server")
    must(STATE_FILE.read_bytes() == before and SAVES == [], "nothing written")
for module_id in ("tagged", "pre"):
    helper.apply_enable_job(REPO, [module_id], [])
    must(flags()[module_id] is True, module_id)
plain_world()
DEV["on"] = True
for module_id in ("plain", "tst", "tagged", "pre"):
    helper.apply_enable_job(REPO, [module_id], [])
    must(flags()[module_id] is True, module_id)
DEV["on"] = False
# the whole job: refused with nothing changed and no sync
plain_world()
result = run({"action": "enable", "plugin_id": "plain", "affected_modules": ["plain"]})
must(result["status"] == "failed" and "not a development server" in result["error"] and SYNC["calls"] == 0 and flags()["plain"] is False, result)
must("rolled_back" not in result and "rollback_error" not in result, "nothing was changed, so nothing is recorded as rolled back")
plain_world()
must(run({"action": "enable", "plugin_id": "tagged", "affected_modules": ["tagged"]})["status"] == "succeeded", "a core module enables")
# a module with no manifest the helper can trust is not judged by category (the existing rule handles it)
plain_world()
drop("plain")
helper.apply_enable_job(REPO, ["plain"], [])

# ------------------------------------------------------------------------------------------ install
plain_world()
for development, order, ok in ((False, ["plain"], False), (False, ["tst"], False), (False, ["tagged", "pre"], True), (False, ["tagged", "plain"], False),
                               (True, ["plain", "tst"], True), (True, ["tagged"], True)):
    DEV["on"] = development
    if ok:
        categories = helper.verify_install_categories(REPO, order)
        must(set(categories) == set(order), categories)
    else:
        refused(lambda: helper.verify_install_categories(REPO, order), "not a development server")
DEV["on"] = False
categories = helper.verify_install_categories(REPO, ["tagged", "pre"])
must(categories == {"tagged": "core", "pre": "premium"}, categories)
must(helper.verify_install_categories(REPO, ["nosuchmodule"]) == {}, "a module with no readable manifest is left to the other install checks")
# the state entry takes the manifest category in the same write
plain_world()
SAVES.clear()
helper.remember_version("pre", "1.2.3", None, "premium")
must(len(SAVES) == 1 and SAVES[0]["modules"]["pre"]["category"] == "premium" and SAVES[0]["modules"]["pre"]["version"] == "1.2.3", SAVES)
helper.remember_version("plain", "1.0.0", None, "")
must(json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"]["plain"]["category"] == "", "no category is recorded as an empty string, not a guess")
helper.remember_version("tagged", "1.0.1")
must(json.loads(STATE_FILE.read_text(encoding="utf-8"))["modules"]["tagged"].get("category") is None, "a caller that passes none leaves the record as it was")
# run_job hands the verified categories to remember_version, and checks them before any state is written
text = HELPER_PATH.read_text(encoding="utf-8")
must(text.index("verify_install_categories(repo_root, order)") < text.index("remember_version(action[\"id\"]"), "checked before the state write")
must('categories.get(action["id"])' in text, "the state write carries the category")

# ------------------------------------------------------------------------------------------ the rollback record
SOURCE_RUN = text[text.index("def run_job(job_id):"):]
block = SOURCE_RUN[SOURCE_RUN.index("sync_and_reload(config, log, refresh_workers=True)\n                except Exception:"):SOURCE_RUN.index('elif job["action"] == "visibility":')]
must(block.index("restore_enabled_flags(previous)") < block.index('job["rolled_back"] = True'), "rolled_back is set only after restore_enabled_flags returns")
must('job["rollback_error"]' in block and "except (OSError, RuntimeError, ValueError) as restore_exc" in block, "an error while restoring is recorded")
must(block.index('job["rolled_back"] = True') < block.index("sync_and_reload", block.index("restore_enabled_flags")), "the second sync comes after the restore")

# a plain failing sync with nothing switched: no rollback ran, so neither field exists
world(patching=False, pm=False)
SYNC["fail_first"] = 1
result = run({"action": "enable", "plugin_id": "patching", "affected_modules": ["patching"]})
must(result["status"] == "failed" and result["stage"] == "runtime-sync" and "rolled_back" not in result and "rollback_error" not in result, result)
# the flags were switched and put back
world(patching=False, pm=True)
SYNC["fail_first"] = 1
result = run(enable_job())
must(result["status"] == "failed" and result["stage"] == "rollback" and result["rolled_back"] is True and "rollback_error" not in result, result)
must(flags() == {"patching": False, "patchmanagement": True} and SYNC["calls"] == 2, "restored, and the sync was tried once more")
world(patching=False, pm=True)
SYNC["fail_first"] = 2  # the second sync fails too: the flags are still back
result = run(enable_job())
must(result["status"] == "failed" and result["rolled_back"] is True and flags() == {"patching": False, "patchmanagement": True}, result)
# the hand-back direction
world(patching=False, pm=True)
SYNC["fail_first"] = 1
result = run(disable_job())
must(result["status"] == "failed" and result["rolled_back"] is True and flags() == {"patching": False, "patchmanagement": True}, result)
# restoring the flags raises: the error is recorded, rolled_back is not, and no second sync runs
world(patching=False, pm=True)
SYNC["fail_first"] = 1
real_restore = helper.restore_enabled_flags
helper.restore_enabled_flags = lambda previous: (_ for _ in ()).throw(OSError("module-state.json is read-only\n\x00"))
result = run(enable_job())
helper.restore_enabled_flags = real_restore
must(result["status"] == "failed" and "rolled_back" not in result and result["rollback_error"] == "module-state.json is read-only", result)
must(SYNC["calls"] == 1, "no second sync after a failed restore")
must(flags() == {"patching": True, "patchmanagement": False}, "the switch stands, and the record says so")
world(patching=False, pm=True)
SYNC["fail_first"] = 1
helper.restore_enabled_flags = lambda previous: (_ for _ in ()).throw(RuntimeError("x" * 1000))
result = run(enable_job())
helper.restore_enabled_flags = real_restore
must(len(result["rollback_error"]) == 300, len(result["rollback_error"]))
# the audit row reads those fields
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import module_replacement as mr  # noqa: E402

[row] = mr._outcome_rows({**result, "id": "j", "plugin_id": "patching"}, lambda module_id: "")
must("could not put the flags back" in row["message"] and row["metadata"]["rolled_back"] is False, row)
world(patching=False, pm=True)
SYNC["fail_first"] = 1
result = run(enable_job())
[row] = mr._outcome_rows({**result, "id": "j", "plugin_id": "patching"}, lambda module_id: "")
must("put back as they were" in row["message"] and row["metadata"]["rolled_back"] is True, row)
must(re.fullmatch(r"[a-z-]+", result["stage"]), result["stage"])

print("[TEST] PASS module category helper 1.17.13")
