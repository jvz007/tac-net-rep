#!/usr/bin/env python3
"""1.17.13 regression: signed module categories (AD-21, Johan, 9 October 2026).

Manifest category accepts core, server, premium and test (anything else is refused). A missing category is treated as test,
with a plain-English warning. Core refuses to install or enable a test module on a server that is not a development server,
and refuses a premium, server or test module every Tactical route even where the owner table lists its id. An AD-20
replacement must be premium, or have no category on a development server. Status rows (module_status of the runtime context and
the modules/v2 catalog) carry the new fields.

Real registry.py, module_category.py, module_replacement.py, module_runtime.py, module_manager.py and module_manager_v2.py; the
development flag is switched by replacing module_category.is_development_server, as the root-owned config would on a server.
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

from tec_tac import module_category as mc, module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry  # noqa: E402

logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.module_runtime").addHandler(logging.NullHandler())
from tec_tac import module_runtime  # noqa: E402

DEV = {"on": False}
mc.is_development_server = lambda: DEV["on"]

TMP = Path(tempfile.mkdtemp(prefix="tectac-category-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for _folder in (EXT, REP, JOBS):
    _folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_runtime.load_state = lambda: STATE
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


def refused_manifest(module_id, root=EXT, **extra):
    manifest(module_id, root, **extra)
    try:
        registry.get_plugins()
    except registry.RegistryError as exc:
        reset()
        return str(exc)
    raise AssertionError(f"manifest accepted: {extra}")


def candidate(module_id, **extra):
    item = {"id": module_id, "extension_version": "1.0.0", "dependencies": {}, "optional_dependencies": {}, "requires": {},
            "runtime_requirements": [], "category": "", "replaces": None, "capabilities": None, "migration": {}}
    item.update(extra)
    return item


def plan_types(*candidates):
    return [problem["type"] for problem in v2.resolve_install_plan(list(candidates))["problems"]]


# ------------------------------------------------------------------------------------------------ the manifest
reset()
for value in ("core", "server", "premium", "test", " Premium ", "TEST"):
    manifest("m", category=value)
    must(registry.get_plugins()[0].category == value.strip().lower(), value)
    reset()
manifest("none")
must(registry.get_plugins()[0].category == "", "a missing category stays empty in the spec; Core treats it as test where it decides")
reset()
for bad in ("bogus", "retired", "Core module", "premium,test", "tests", "1"):
    must("category must be" in refused_manifest("m", category=bad), bad)
for bad in (None, 5, ["premium"], {"a": 1}):
    must("category must be a string" in refused_manifest("m", category=bad), bad)
must("may not declare category" in refused_manifest("rs", REP, category="premium"), "a reportset still may not declare a category")
must("may not declare replaces" in refused_manifest("t", category="test", replaces="patching"), "a test module may never replace")
manifest("p", category="premium", replaces="patching", capabilities={"patching.windows": "1.0.0"})  # premium may
reset()
manifest("p", category="premium", capabilities={"other.thing": "1.0.0"})  # the prefix rule stays for core and server only
manifest("tt", category="test", capabilities={"other.too": "1.0.0"})
registry.get_plugins()
reset()
must("prefix" in refused_manifest("c", category="core", capabilities={"other.thing": "1.0.0"}), "core keeps the prefix rule")
must("prefix" in refused_manifest("s", category="server", capabilities={"other.thing": "1.0.0"}), "server keeps the prefix rule")
must(set(mc.CATEGORIES) == {"core", "server", "premium", "test"} and mc.NEW_CATEGORIES == ("premium", "test") and mc.FRAMEWORK_FOR_NEW_CATEGORIES == "1.17.13", "constants")

# ------------------------------------------------------------------------------------------------ the rules
must(mc.effective_category("") == "test" and mc.effective_category(None) == "test" and mc.effective_category(" Core ") == "core" and mc.effective_category("premium") == "premium", "effective")
for development in (True, False):
    for category, refused in (("", not development), (None, not development), ("test", not development), ("core", False), ("server", False), ("premium", False)):
        must(mc.refused(category, development=development) is refused, (development, category))
    must(mc.replacement_category_ok("premium", development=development) is True, "premium replaces everywhere")
    must(mc.replacement_category_ok("", development=development) is development, "no category: on a development server only")
    for other in ("test", "core", "server", "bogus"):
        must(mc.replacement_category_ok(other, development=development) is False, other)
# the status fields and the warning text
row = mc.describe("", development=False)
must(row == {"category": None, "effective_category": "test", "category_missing": True, "category_refused": True, "category_warning": mc.WARNING_MISSING}, row)
must("does not state its category" in row["category_warning"] and "treats it as Test" in row["category_warning"] and "not a development server" in row["category_warning"]
     and "refuses to install or enable" in row["category_warning"] and "next release" in row["category_warning"], row["category_warning"])
row = mc.describe("", development=True)
must(row["category_missing"] is True and row["category_refused"] is False and "still runs on this development server" in row["category_warning"], row)
for category in ("core", "server", "premium"):
    row = mc.describe(category, development=False)
    must(row == {"category": category, "effective_category": category, "category_missing": False, "category_refused": False, "category_warning": None}, row)
row = mc.describe("test", development=False)
must(row["category_refused"] is True and row["category_missing"] is False and row["category_warning"] == mc.WARNING_TEST, row)
must(mc.describe("test", development=True)["category_refused"] is False and mc.describe("test", development=True)["category_warning"] is None, "test on a development server")
must(mc.refusal_problem("m", "", development=True) is None and mc.refusal_problem("m", "core", development=False) is None, "no problem")
problem = mc.refusal_problem("m", "", development=False)
must(problem["type"] == "category_refused" and problem["module"] == "m" and problem["effective_category"] == "test" and problem["category"] is None and problem["message"] == mc.REFUSED_MESSAGE, problem)
# the plain-English rule: short sentences, no filler
for text in (mc.WARNING_MISSING, mc.WARNING_MISSING_DEV, mc.WARNING_TEST, mc.REFUSED_MESSAGE):
    must("kindly" not in text.lower() and "don't hesitate" not in text.lower() and "Test" in text, text)
# the real setting is read through trust_policy and fails closed
import importlib  # noqa: E402

fresh_mc = importlib.reload(mc)
must(fresh_mc.is_development_server() is False, "an unreadable environment is not a development server")
trust = types.ModuleType("tec_tac.trust_policy")
_package = sys.modules["tec_tac"]
_real_trust = getattr(_package, "trust_policy", None)
sys.modules["tec_tac.trust_policy"] = trust
_package.trust_policy = trust
trust._server_environment = lambda: "development"
must(fresh_mc.is_development_server() is True, "development")
trust._server_environment = lambda: "production"
must(fresh_mc.is_development_server() is False, "production")
trust._server_environment = lambda: (_ for _ in ()).throw(RuntimeError("config unreadable"))
must(fresh_mc.is_development_server() is False, "an error fails closed")
del sys.modules["tec_tac.trust_policy"]
if _real_trust is not None:
    _package.trust_policy = _real_trust
else:
    del _package.trust_policy
must(fresh_mc is mc, "a reload keeps the one module object every caller holds")
mc.is_development_server = lambda: DEV["on"]

# ------------------------------------------------------------------------------------------------ status rows
reset(plain=True, tagged=True, premiumone=True, testone=True)
manifest("plain")
manifest("tagged", category="core")
manifest("premiumone", category="premium")
manifest("testone", category="test")
legacy = types.SimpleNamespace(plugin_id="oldplugin", plugin_type="legacy", legacy=True, version="3.1", permission_groups=(), audit_events=(), replaces=None)
for development in (False, True):
    DEV["on"] = development
    plugins = list(registry.get_plugins()) + [legacy]
    snapshot = {row["id"]: row for row in module_runtime.module_runtime_snapshot(plugins)}
    must(snapshot["plain"]["category"] is None and snapshot["plain"]["effective_category"] == "test" and snapshot["plain"]["category_missing"] is True, snapshot["plain"])
    must(snapshot["plain"]["category_refused"] is (not development) and snapshot["plain"]["category_warning"], snapshot["plain"])
    must(snapshot["tagged"]["category"] == "core" and snapshot["tagged"]["category_warning"] is None and snapshot["tagged"]["category_refused"] is False, snapshot["tagged"])
    must(snapshot["premiumone"]["effective_category"] == "premium" and snapshot["testone"]["category_refused"] is (not development), snapshot)
    must(snapshot["oldplugin"]["category"] is None and snapshot["oldplugin"]["effective_category"] is None and snapshot["oldplugin"]["category_missing"] is False
         and snapshot["oldplugin"]["category_refused"] is False and snapshot["oldplugin"]["category_warning"] is None, snapshot["oldplugin"])
    for row in snapshot.values():
        must({"category", "effective_category", "category_missing", "category_refused", "category_warning"} <= set(row), row)
# a refused row is still reported as installed and enabled: already-installed modules keep loading
DEV["on"] = False
snapshot = {row["id"]: row for row in module_runtime.module_runtime_snapshot(registry.get_plugins())}
must(snapshot["plain"]["installed"] is True and snapshot["plain"]["enabled"] is True and snapshot["plain"]["active"] is True, snapshot["plain"])
# the modules/v2 catalog
STATE["modules"]["tagged"] = {"enabled": True, "category": "core"}
STATE["modules"]["premiumone"] = {"enabled": True, "category": "server"}  # a state entry that disagrees with the manifest
rows = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows["plain"]["effective_category"] == "test" and rows["plain"]["category_missing"] is True and rows["plain"]["category_refused"] is True, rows["plain"])
must(rows["plain"]["category"] is None and rows["tagged"]["category"] == "core" and rows["premiumone"]["category"] == "premium", [rows[k]["category"] for k in rows])
must(rows["tagged"]["category_state"] == "core" and rows["tagged"]["category_mismatch"] is False, rows["tagged"])
must(rows["premiumone"]["category_state"] == "server" and rows["premiumone"]["category_mismatch"] is True, "the manifest is read first and a mismatch is flagged")
must(rows["plain"]["category_state"] is None and rows["plain"]["category_mismatch"] is False, "no state category: nothing to flag")
must(rows["premiumone"]["effective_category"] == "premium", "the manifest wins over the state entry")

# ------------------------------------------------------------------------------------------------ install and enable
for development in (False, True):
    DEV["on"] = development
    must(("category_refused" in plan_types(candidate("fresh"))) is (not development), (development, "no category"))
    must(("category_refused" in plan_types(candidate("fresh", category="test"))) is (not development), (development, "test"))
    for category in ("core", "server", "premium"):
        must("category_refused" not in plan_types(candidate("fresh", category=category)), (development, category))
DEV["on"] = False
plan = v2.resolve_install_plan([candidate("fresh")])
refusal = next(p for p in plan["problems"] if p["type"] == "category_refused")
must(plan["valid"] is False and refusal["module"] == "fresh" and refusal["effective_category"] == "test" and "development server" in refusal["message"], plan)
must(v2.resolve_install_plan([candidate("fresh", category="premium")])["valid"] is True, "a premium module installs")
# enabling an installed module
reset(plain=False, tagged=False, premiumone=False, testone=False)
manifest("plain")
manifest("tagged", category="core")
manifest("premiumone", category="premium")
manifest("testone", category="test")
for development in (False, True):
    DEV["on"] = development
    for module_id, refused in (("plain", not development), ("testone", not development), ("tagged", False), ("premiumone", False)):
        check = v2.validate_enable(module_id)
        types_ = [p["type"] for p in check["problems"]]
        must(("category_refused" in types_) is refused and check["valid"] is (not refused), (development, module_id, check))
DEV["on"] = False
try:
    v2.queue_set_enabled("plain", True)
except v2.ModuleManagerV2Error as exc:
    must("cannot be enabled" in str(exc), exc)
else:
    raise AssertionError("queue_set_enabled queued a test module off a development server")
must(not list(JOBS.iterdir()), "nothing was queued")

# ------------------------------------------------------------------------------------------------ AD-20 replacement
PATCHING = {"patching.windows": "1.2.0"}


def world(replacement_category):
    reset(patching=False, patchmanagement=True)
    manifest("patching", category="core", capabilities=PATCHING)
    extra = {} if replacement_category is None else {"category": replacement_category}
    manifest("patchmanagement", replaces="patching", capabilities=PATCHING, **extra)


for development in (False, True):
    DEV["on"] = development
    for category, honoured in (("premium", True), (None, development), ("", development)):
        world(category)
        model = mr.live_model()
        reason = mr.check(model, "patchmanagement")[0]
        must((reason is None) is honoured and (honoured or reason == "replacement-category"), (development, category, reason))
        must((mr.honoured_replacement("patchmanagement", model=model) == "patching") is honoured, (development, category))
        status = mr.replacement_status("patchmanagement", model=model, check_registered=False)
        must(status["honoured"] is honoured and (honoured or ("Premium" in status["message"] and status["reason"] == "replacement-category")), status)
# a replacement with the wrong category cannot be enabled or installed as one
DEV["on"] = False
world(None)
STATE["modules"]["patchmanagement"] = {"enabled": False}
problems = mr.enable_problems(mr.live_model(), "patchmanagement")
must(problems and problems[0]["reason"] == "replacement-category" and problems[0]["type"] == "replacement_incomplete", problems)
must(mr.install_problems({**mr.live_model(), "x": mr.Node(id="x", category="test", enabled=True, replaces="patching", capabilities=PATCHING)}, ["x"], installed_ids=())[0]["reason"] == "replacement-category", "install")
# the replacement no longer owns the replaced module's routes, and satisfies no dependency, when it is not honoured
world(None)
model = mr.live_model()
must(mr.satisfies_dependency(model, "patching") is None, "not honoured: no dependency is satisfied")
DEV["on"] = True
must(mr.satisfies_dependency(mr.live_model(), "patching") == "patchmanagement", "no category on a development server: honoured")

# ------------------------------------------------------------------------------------------------ the docs and contract text
doc = (ROOT / "docs" / "module-categories.md").read_text(encoding="utf-8")
for needle in ("core", "server", "premium", "test", "effective_category", "category_missing", "category_refused", "category_warning", ">=1.17.13", "TEC_TAC_ENVIRONMENT",
               "development server", "replacement-category"):
    must(needle in doc, f"docs/module-categories.md lacks {needle!r}")
for name in ("docs/tactical-operations.md", "docs/module-replacement.md"):
    must("1.17.13" in (ROOT / name).read_text(encoding="utf-8") and "AD-21" in (ROOT / name).read_text(encoding="utf-8"), name)
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
for needle in ("effective_category", "category_refused", "category_warning", "category_missing"):
    must(needle in contracts, f"the contract text lacks {needle}")

print("[TEST] PASS module category 1.17.13")
