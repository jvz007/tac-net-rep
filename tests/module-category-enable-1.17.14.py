#!/usr/bin/env python3
"""1.17.14 regression: the AD-21 refusal for a module with no category applies at install only (Johan CQ38, 9 October 2026).

A test module (or one with no category) is refused at the install plan, by the v1 package check and by the v2 install check
(``verify_install_categories``) on a server that is not a development server. An enable is never refused for the category any more, on
the web side (``validate_enable``, ``queue_set_enabled``) or in the root helper (``apply_enable_job``). A test module that is already
installed (for example one installed off a development server) can be enabled. The status fields are unchanged apart from their text,
and a development server behaves as before.

The root-helper half uses the harness of tests/module-replacement-helper-handback-1.17.12.py (as tests/module-category-helper-1.17.13.py
does); the web half runs the real registry, module_category, module_replacement and module_manager_v2 against manifests in a temporary
folder. What cannot run here: the helpers as root, and a real job.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
HELPER_HARNESS = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
source = HELPER_HARNESS.read_text(encoding="utf-8")
cut = source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")
H = {"__name__": "stubs", "__file__": str(HELPER_HARNESS)}
exec(compile(source[:cut], str(HELPER_HARNESS), "exec"), H)
helper, put, drop, flags, run, must = (H[k] for k in ("helper", "put", "drop", "flags", "run", "must"))
REPO, STATE_FILE, SAVES, SYNC = (H[k] for k in ("REPO", "STATE_FILE", "SAVES", "SYNC"))
ROOT = H["ROOT"]
sys.path.insert(0, str(ROOT / "framwork"))


def refused(call, needle):
    try:
        call()
    except RuntimeError as exc:
        must(needle in str(exc), str(exc))
        return
    raise AssertionError("the call was accepted")


# ------------------------------------------------------------------------------------------------ the v2 root helper
DEV = {"on": False}
helper.development_server = lambda: DEV["on"]


def installed_world():
    for folder in list((REPO / "extensions").iterdir()):
        drop(folder.name)
    put("plain")
    put("tst", category="test")
    put("tagged", category="core")
    STATE_FILE.write_text(json.dumps({"schema": 1, "modules": {name: {"enabled": False} for name in ("plain", "tst", "tagged")}}), encoding="utf-8")
    SAVES.clear()


for development in (False, True):
    DEV["on"] = development
    installed_world()
    for module_id in ("plain", "tst", "tagged"):
        helper.apply_enable_job(REPO, [module_id], [])
        must(flags()[module_id] is True, (development, module_id))
    # the whole job
    installed_world()
    result = run({"action": "enable", "plugin_id": "tst", "affected_modules": ["tst"]})
    must(result["status"] == "succeeded" and flags()["tst"] is True and SYNC["calls"] >= 1, (development, result))
# the install check is unchanged: refused off a development server, allowed on one
installed_world()
DEV["on"] = False
for order in (["plain"], ["tst"], ["tagged", "plain"]):
    refused(lambda: helper.verify_install_categories(REPO, order), "not a development server")
must(helper.verify_install_categories(REPO, ["tagged"]) == {"tagged": "core"}, "a tagged module installs")
DEV["on"] = True
must(set(helper.verify_install_categories(REPO, ["plain", "tst"])) == {"plain", "tst"}, "a development server installs both")
DEV["on"] = False
helper_text = (ROOT / "scripts/module-v2-job-helper.py").read_text(encoding="utf-8")
body = helper_text[helper_text.index("def apply_enable_job("):helper_text.index("def apply_disable_job(") if "def apply_disable_job(" in helper_text[helper_text.index("def apply_enable_job("):] else None]
must("category_refused" not in body and "refusing to enable" not in body, "apply_enable_job no longer judges the category")
must("category_refused(node[\"category\"], development)" in helper_text and "refusing to install it" in helper_text, "the install check stays")

# ------------------------------------------------------------------------------------------------ the v1 root helper
V1_PATH = ROOT / "scripts" / "module-job-helper.py"
v1 = types.ModuleType("module_job_helper_v1")
v1.__file__ = str(V1_PATH)
exec(compile(V1_PATH.read_text(encoding="utf-8").replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(V1_PATH), "exec"), v1.__dict__)
for category, expected in (("", True), (None, True), ("test", True), ("core", False), ("server", False), ("premium", False)):
    must(v1.category_refused(category, False) is expected, (category, "off a development server"))
    must(v1.category_refused(category, True) is False, (category, "on a development server"))
v1_text = V1_PATH.read_text(encoding="utf-8")
must('job["action"] == "install"' in v1_text and "refusing to install it" in v1_text and "refusing to enable" not in v1_text, "the v1 helper judges installs only")

# ------------------------------------------------------------------------------------------------ the web side
for _name, _attrs in {"fcntl": dict(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)}.items():
    sys.modules.setdefault(_name, types.ModuleType(_name)).__dict__.update(_attrs)
from tec_tac import module_category as mc, module_manager, module_manager_v2 as v2, module_runtime, module_state, registry  # noqa: E402

logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.module_runtime").addHandler(logging.NullHandler())
mc.is_development_server = lambda: DEV["on"]
TMP = Path(tempfile.mkdtemp(prefix="tectac-category-enable-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for _folder in (EXT, REP, JOBS):
    _folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {"plain": {"enabled": False}, "testone": {"enabled": False}, "tagged": {"enabled": False}}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_runtime.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins
for module_id, extra in (("plain", {}), ("testone", {"category": "test"}), ("tagged", {"category": "core"})):
    folder = EXT / module_id
    folder.mkdir()
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", "name": module_id, **extra}), encoding="utf-8")
queued = []
v2._queue_v2 = lambda payload: queued.append(payload) or {"id": f"job-{len(queued)}", "queued": True}


def candidate(module_id, **extra):
    item = {"id": module_id, "extension_version": "1.0.0", "dependencies": {}, "optional_dependencies": {}, "requires": {},
            "runtime_requirements": [], "category": "", "replaces": None, "capabilities": None, "migration": {}}
    item.update(extra)
    return item


DEV["on"] = False
# install: refused as before
plan = v2.resolve_install_plan([candidate("fresh")])
refusal = next(p for p in plan["problems"] if p["type"] == "category_refused")
must(plan["valid"] is False and refusal["module"] == "fresh" and "install" in refusal["message"] and "enable" not in refusal["message"].lower(), plan)
must(v2.resolve_install_plan([candidate("fresh", category="test")])["valid"] is False, "an explicit test module is refused at install too")
must(v2.resolve_install_plan([candidate("fresh", category="premium")])["valid"] is True, "premium installs")
# enable: validates, queues, and the row still carries the warning
for module_id in ("plain", "testone", "tagged"):
    check = v2.validate_enable(module_id)
    must(check["valid"] is True and check["problems"] == [], (module_id, check))
    del queued[:]
    job = v2.queue_set_enabled(module_id, True)
    must(job["queued"] is True and queued[0]["action"] == "enable" and queued[0]["plugin_id"] == module_id, (module_id, queued))
rows = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows["plain"]["category_refused"] is True and rows["plain"]["category_missing"] is True and rows["plain"]["effective_category"] == "test", rows["plain"])
must("does not state its category" in rows["plain"]["category_warning"] and "refuses to install it" in rows["plain"]["category_warning"], rows["plain"]["category_warning"])
must(rows["testone"]["category_warning"] == mc.WARNING_TEST and "enable" not in mc.WARNING_TEST.lower(), rows["testone"]["category_warning"])
must(rows["tagged"]["category_refused"] is False and rows["tagged"]["category_warning"] is None, rows["tagged"])
# the status fields are the same set as before
for row in rows.values():
    must({"category", "effective_category", "category_missing", "category_refused", "category_warning"} <= set(row), row)
# the texts say install only
for text in (mc.WARNING_MISSING, mc.WARNING_MISSING_DEV, mc.WARNING_TEST, mc.REFUSED_MESSAGE):
    must("install or enable" not in text and "install and enables" not in text, text)
must("install" in mc.WARNING_MISSING and "refuses to install it" in mc.WARNING_MISSING, mc.WARNING_MISSING)
# a development server is unchanged
DEV["on"] = True
must(v2.resolve_install_plan([candidate("fresh")])["valid"] is True, "a development server installs a module with no category")
must(v2.validate_enable("plain")["valid"] is True and rows["plain"]["category_warning"], "and enables it")
must(v2.installed_catalog_v2() and {row["id"]: row for row in v2.installed_catalog_v2()}["plain"]["category_refused"] is False, "not refused there")
DEV["on"] = False
# the enable path never asks module_category for a refusal
v2_text = (ROOT / "framwork/tec_tac/module_manager_v2.py").read_text(encoding="utf-8")
must(v2_text.count("module_category.refusal_problem(") == 1 and v2_text.index("module_category.refusal_problem(") < v2_text.index("def _enable_problems"), "the only caller is the install plan")
must('"category_refused"' not in v2_text[v2_text.index("def _enable_problems"):v2_text.index("def _replacement_dependants")], "_enable_problems has no category problem")
# the docs and the contract say install only
docs = (ROOT / "docs/module-categories.md").read_text(encoding="utf-8")
must("Install only (CQ38, 1.17.14)" in docs and "Enabling or disabling an installed module is never refused for its category" in docs, "docs")
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
must("Core refuses to install or enable" not in contracts and "install-only since 1.17.14" in contracts, "contract text")

print("[TEST] PASS module category enable 1.17.14")
