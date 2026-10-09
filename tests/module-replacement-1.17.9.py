#!/usr/bin/env python3
"""1.17.9 regression: AD-20 honoured module replacement (manifest keys, honoured state, enable and install refusal).

Runs the real registry.py, module_state.py, module_replacement.py, capabilities.py, module_manager.py and
module_manager_v2.py against a temporary extensions folder of real manifests. Django is not needed. The Linux-only
``fcntl`` and the ``cryptography`` package are stubbed so the modules import on the development PC, and the module state file
is replaced by a dict. The root job helper and a running server are not exercised.
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

from tec_tac import capabilities, module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry  # noqa: E402
from tec_tac import module_category  # noqa: E402
module_category.is_development_server = lambda: True  # AD-21 (1.17.13): these tests are about replacement, not about the category gate

logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())
TMP = Path(tempfile.mkdtemp(prefix="tectac-replacement-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
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
    STATE["modules"] = {name: {"enabled": on} for name, on in state.items()}


def refused_manifest(module_id, **extra):
    manifest(module_id, **extra)
    try:
        registry.get_plugins()
    except registry.RegistryError as exc:
        text = str(exc)
        (EXT / module_id / "tec_tac.json").unlink()
        (EXT / module_id).rmdir()
        return text
    raise AssertionError(f"manifest accepted: {extra}")


PATCHING_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
PM_CAPS = {"patching.windows": "1.2.0", "patching.scan": "1.1.0", "patching.extra": "1.0.0"}


def world(*, patching_caps=PATCHING_CAPS, pm_caps=PM_CAPS, patching=False, pm=True, **more):
    reset(patching=patching, patchmanagement=pm, **more)
    core = {"category": "core"}
    if patching_caps is not None:
        core["capabilities"] = patching_caps
    manifest("patching", **core)
    manifest("patchmanagement", replaces="patching", capabilities=pm_caps)


def status(module_id="patchmanagement"):
    return mr.replacement_status(module_id)


# ------------------------------------------------------------------------------------------ manifest parsing
reset()
manifest("plain")
manifest("coreplain", category="core")
specs = {p.plugin_id: p for p in registry.get_plugins()}
must(specs["plain"].replaces == "" and specs["plain"].capabilities == () and specs["plain"].capabilities_declared is False, "a manifest without the new keys parses as before")
must(specs["coreplain"].capabilities_declared is False, "no capabilities key means undeclared")
manifest("emptycaps", category="core", capabilities={})
must({p.plugin_id: p for p in registry.get_plugins()}["emptycaps"].capabilities_declared is True, "an empty capabilities object is declared")
reset()
for key in ("replaces", "capabilities"):
    must(key in registry.SUPPORTED_KEYS, key)
must("replaces" in registry.PluginSpec.__dataclass_fields__ and "capabilities" in registry.PluginSpec.__dataclass_fields__, "PluginSpec fields")
must("may not declare replaces" in refused_manifest("coremod", category="core", replaces="patching"), "replaces on a core module")
must("replace itself" in refused_manifest("selfie", replaces="selfie"), "replaces itself")
refused_manifest("blank", replaces="")
refused_manifest("listy", replaces=["patching"])
refused_manifest("badid", replaces="pat ching")
refused_manifest("capslist", capabilities=["a.b"])
refused_manifest("capsbadid", capabilities={"nodot": "1.0.0"})
refused_manifest("capsbadver", capabilities={"a.b": "1.0"})
refused_manifest("capsbadver2", capabilities={"a.b": "v1.0.0"})
refused_manifest("capsnonstr", capabilities={"a.b": 1})
must("prefix" in refused_manifest("corecaps", category="core", capabilities={"other.thing": "1.0.0"}), "a core module declares only its own prefix")
manifest("okreplace", replaces="patching", capabilities={"patching.x": "1.0.0", "okreplace.y": "1.0.0"})
registry.get_plugins()
reset()
# a reportset declaring either key is refused
manifest("owner")
manifest("owner", root=REP, capabilities={"owner.x": "1.0.0"})
try:
    registry.get_plugins()
    raise AssertionError("reportset capabilities accepted")
except registry.RegistryError as exc:
    must("Reportset" in str(exc), exc)
(REP / "owner" / "tec_tac.json").unlink()
manifest("owner", root=REP, replaces="x")
try:
    registry.get_plugins()
    raise AssertionError("reportset replaces accepted")
except registry.RegistryError as exc:
    must("Reportset" in str(exc), exc)
reset()

# ------------------------------------------------------------------------------------------ honouring
world()
must(mr.honoured_replacement("patchmanagement") == "patching", status())
must(mr.replaced_by("patching") == "patchmanagement" and mr.replaced_by("patchmanagement") is None, "replaced_by")
must(mr.honoured_replacement("patching") is None and mr.honoured_replacement("nosuch") is None, "a core module and an unknown id replace nothing")
row = status()
must(row["honoured"] is True and row["reason"] is None and row["replaces"] == "patching", row)
must(row["capabilities"]["expected"] == ["patching.scan", "patching.windows"] and row["capabilities"]["failed"] == [], row)
must(status("patching") is None and mr.replacement_status("nosuch") is None, "no status for a module that declares no replaces")
must([r["module_id"] for r in mr.replacement_status()] == ["patchmanagement"], "list form")

# refusals, one reason code each
world(patching=True)
must(mr.honoured_replacement("patchmanagement") is None and status()["reason"] == "target-enabled", status())
world(pm=False)
must(mr.honoured_replacement("patchmanagement") is None and status()["reason"] == "replacement-disabled", status())
reset(patchmanagement=True)
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS)
must(status()["reason"] == "target-missing" and mr.honoured_replacement("patchmanagement") is None, "target absent")
world()
manifest("patching")  # not a core module any more
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS)
must(status()["reason"] == "target-not-core", status())
world(patching_caps=None)
must(status()["reason"] == "capabilities-undeclared" and mr.honoured_replacement("patchmanagement") is None, "a core module cannot hide its contracts")
world(patching_caps={})
must(mr.honoured_replacement("patchmanagement") == "patching", "an empty capabilities object is allowed")
world(pm_caps={"patching.windows": "1.2.0"})
must(status()["reason"] == "capability-missing" and status()["capabilities"]["failed"][0]["capability"] == "patching.scan", status())
world(pm_caps={"patching.windows": "1.2.0", "patching.scan": "0.9.0"})
must(status()["reason"] == "capability-major-mismatch", "a lower major")
world(pm_caps={"patching.windows": "2.0.0", "patching.scan": "1.0.0"})
must(status()["reason"] == "capability-major-mismatch", "a higher major")
world(pm_caps={"patching.windows": "1.1.9", "patching.scan": "1.0.0"})
must(status()["reason"] == "capability-version-lower", status())
world(pm_caps={"patching.windows": "1.2.0", "patching.scan": "1.0.0"})
must(mr.honoured_replacement("patchmanagement") == "patching", "an equal version is accepted")
world(pm_caps={"patching.windows": "1.9.0", "patching.scan": "1.0.5", "patching.more": "3.0.0"})
must(mr.honoured_replacement("patchmanagement") == "patching", "a higher minor and extra capabilities are accepted")

# two enabled replacements of the same module: neither is honoured
world()
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
must(mr.honoured_replacement("patchmanagement") is None and mr.honoured_replacement("rival") is None, "competing replacements")
must(status()["reason"] == "competing-replacement", status())
STATE["modules"]["rival"] = {"enabled": False}
must(mr.honoured_replacement("patchmanagement") == "patching", "the rival is disabled")

# both enabled at start-up (hand-edited state): not honoured, nothing disabled, a warning, no exception
world(patching=True)
before = json.dumps(STATE, sort_keys=True)
records = []


class Catch(logging.Handler):
    def emit(self, record):
        records.append(record)


handler = Catch()
logging.getLogger("tec_tac.module_replacement").addHandler(handler)
mr._WARNED.clear()
must(mr.honoured_replacement("patchmanagement") is None, "both enabled: not honoured")
must(any(r.levelno == logging.WARNING for r in records), "a warning is logged")
must(json.dumps(STATE, sort_keys=True) == before, "nothing was disabled or enabled")
must(status()["reason"] == "target-enabled" and status()["enabled"] is True, status())
logging.getLogger("tec_tac.module_replacement").removeHandler(handler)

# disabling the replacement drops honouring at once; the core module can come back
world()
must(mr.honoured_replacement("patchmanagement") == "patching", "honoured")
STATE["modules"]["patchmanagement"]["enabled"] = False
must(mr.honoured_replacement("patchmanagement") is None and mr.replaced_by("patching") is None, "disabled replacement: dropped")
STATE["modules"]["patching"]["enabled"] = True
must(v2.validate_enable("patching")["valid"] is True, "hand back: with the replacement disabled the core module may be enabled")
# corrupt state fails closed
STATE["_corrupt"] = True
must(mr.honoured_replacement("patchmanagement") is None, "corrupt state")
del STATE["_corrupt"]

# degraded is informational: a declared capability that is not registered at run time never blocks
world()
capabilities._clear_capabilities_for_tests()
row = status()
must(row["honoured"] is True and row["degraded"] is True and row["unregistered"] == ["patching.scan", "patching.windows"], row)
capabilities.register_capability(id="patching.windows", module_id="patchmanagement", version="1.2.0", provider=object())
row = status()
must(row["honoured"] is True and row["degraded"] is True and row["unregistered"] == ["patching.scan"], row)
capabilities._clear_capabilities_for_tests()

# ------------------------------------------------------------------------------------------ enable refusals
def problems(module_id):
    return v2.validate_enable(module_id)


world(patching=True, pm=False)
# 1.17.11 (AD-20 amendment 1a): enabling the replacement next to its enabled core module is no longer a refusal. It names
# the module it will disable, and it is queued only with that exact list (tests/module-replacement-enable-1.17.11.py).
result = problems("patchmanagement")
must(result["valid"] is True and result["will_disable"] == ["patching"], result)
captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"queued": True}
try:
    v2.queue_set_enabled("patchmanagement", True)
    raise AssertionError("enabling the replacement without confirming the disable was queued")
except v2.ModuleReplacementConfirmationRequired as exc:
    must("patching" in str(exc) and exc.will_disable == ["patching"], exc)
must(captured == [], "nothing queued")
# the other order: the core module while an enabled replacement points at it. 1.17.12 (CQ32): no longer a refusal. It names
# the replacement it will switch off and needs the two confirmations (tests/module-replacement-handback-1.17.12.py).
world(patching=False, pm=True)
result = problems("patching")
must(result["valid"] is True and result["will_disable"] == ["patchmanagement"], result)
try:
    v2.queue_set_enabled("patching", True)
    raise AssertionError("enabling the core module next to its enabled replacement was queued without confirmation")
except v2.ModuleReplacementConfirmationRequired as exc:
    must("patchmanagement" in str(exc), exc)
must(captured == [], "nothing queued")
# parity failure: incomplete
world(patching=False, pm=False, pm_caps={"patching.windows": "1.2.0"})
result = problems("patchmanagement")
must(not result["valid"] and result["problems"][0]["type"] == "replacement_incomplete" and result["problems"][0]["reason"] == "capability-missing", result)
try:
    v2.queue_set_enabled("patchmanagement", True)
    raise AssertionError("an incomplete replacement was queued")
except v2.ModuleManagerV2Error as exc:
    must("every capability" in str(exc), exc)
# the allowed sequence: core disabled first, then the replacement; and the way back
world(patching=False, pm=False)
must(problems("patchmanagement")["valid"] is True, problems("patchmanagement"))
must(v2.queue_set_enabled("patchmanagement", True) == {"queued": True} and captured[-1]["action"] == "enable", captured)
world(patching=False, pm=False)
must(problems("patching")["valid"] is True, "with the replacement disabled the core module can be enabled")
# disabling is never refused by this check
world(patching=False, pm=True)
v2.queue_set_enabled("patchmanagement", False)
must(captured[-1]["action"] == "disable", captured[-1])
# a module that has nothing to do with replacement is untouched
world()
manifest("bystander")
must(problems("bystander")["valid"] is True, "unrelated module")

# ------------------------------------------------------------------------------------------ install refusals
def candidate(module_id, version="1.0.0", **extra):
    item = {"id": module_id, "extension_version": version, "dependencies": {}, "optional_dependencies": {}, "requires": {},
            "runtime_requirements": [], "category": "", "replaces": None, "capabilities": None}
    item.update(extra)
    return item


def plan_types(*items):
    return [(p["type"], p.get("reason")) for p in v2.resolve_install_plan(list(items))["problems"] if p["type"].startswith("replacement")]


reset(patching=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
# 1.17.11: a fresh install while the target is enabled names it and disables it in the same job (no longer a problem)
must(plan_types(candidate("patchmanagement", replaces="patching", capabilities=PM_CAPS)) == [], "install while the target is enabled")
must(v2.resolve_install_plan([candidate("patchmanagement", replaces="patching", capabilities=PM_CAPS)])["will_disable"] == ["patching"], "names the target")
STATE["modules"]["patching"]["enabled"] = False
must(plan_types(candidate("patchmanagement", replaces="patching", capabilities=PM_CAPS)) == [], "install next to a disabled core module")
must(plan_types(candidate("patchmanagement", replaces="patching", capabilities={"patching.windows": "1.2.0"})) == [("replacement_incomplete", "capability-missing")], "parity fails")
must(plan_types(candidate("patchmanagement", replaces="patching", capabilities={"patching.windows": "2.0.0", "patching.scan": "1.0.0"})) == [("replacement_incomplete", "capability-major-mismatch")], "major")
must(plan_types(candidate("patchmanagement", replaces="nosuch", capabilities={})) == [("replacement_incomplete", "target-missing")], "install while the target is missing")
must(plan_types(candidate("patchmanagement")) == [], "an ordinary candidate is untouched")
must(v2.resolve_install_plan([candidate("patchmanagement", replaces="patching", capabilities=PM_CAPS)])["valid"] is True, "valid plan")
# the core module installed in the same plan: it is new, so it starts enabled, and the replacement cannot sit next to it
reset()
must(plan_types(candidate("patching", category="core", capabilities=PATCHING_CAPS), candidate("patchmanagement", replaces="patching", capabilities=PM_CAPS)) == [("replacement_conflict", "target-enabled")], "both new")
# an installed, enabled replacement: upgrading the disabled core module so that it drops a capability is refused
world()
must(plan_types(candidate("patching", "1.3.0", category="core", capabilities={"patching.windows": "1.2.0", "patching.scan": "1.0.0", "patching.new": "1.0.0"})) == [("replacement_incomplete", "capability-missing")], "core upgrade adds a capability the replacement lacks")
must(plan_types(candidate("patching", "1.1.0", category="core", capabilities=PATCHING_CAPS)) == [], "core upgrade that keeps parity")
# upgrading an enabled core module that already sits next to an enabled replacement does not get worse
world(patching=True)
must(plan_types(candidate("patching", "1.1.0", category="core", capabilities=PATCHING_CAPS)) == [], "existing both-enabled state is not blocked on upgrade")

# the manifest keys reach the package metadata with the registry's rules
reset()
folder = EXT / "patchmanagement"
folder.mkdir()
(folder / "tec_tac.json").write_text(json.dumps({"id": "patchmanagement", "replaces": "patching", "capabilities": PM_CAPS}), encoding="utf-8")
meta = v2._extension_metadata(folder)
must(meta["replaces"] == "patching" and meta["capabilities"] == PM_CAPS, meta)
(folder / "tec_tac.json").write_text(json.dumps({"id": "patchmanagement", "category": "core", "replaces": "patching"}), encoding="utf-8")
try:
    v2._extension_metadata(folder)
    raise AssertionError("a core module with replaces was read")
except v2.ModuleManagerV2Error:
    pass
(folder / "tec_tac.json").write_text(json.dumps({"id": "patchmanagement"}), encoding="utf-8")
meta = v2._extension_metadata(folder)
must(meta["replaces"] is None and meta["capabilities"] is None, "no keys: None")

# ------------------------------------------------------------------------------------------ catalog rows
world()
rows = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows["patchmanagement"]["replaces"] == "patching" and rows["patchmanagement"]["replaced_by"] is None, rows["patchmanagement"])
must(rows["patchmanagement"]["replacement"]["honoured"] is True and rows["patchmanagement"]["replacement"]["reason"] is None, rows["patchmanagement"]["replacement"])
must(rows["patching"]["replaces"] is None and rows["patching"]["replacement"] is None and rows["patching"]["replaced_by"] == "patchmanagement", rows["patching"])
must(rows["patching"]["capabilities"] == PATCHING_CAPS and rows["patchmanagement"]["capabilities"] == PM_CAPS, "capabilities in the row")
world(patching=True)
rows = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows["patchmanagement"]["replacement"]["reason"] == "target-enabled" and rows["patching"]["replaced_by"] is None, rows)
reset()
manifest("plain")
rows = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows["plain"]["replaces"] is None and rows["plain"]["replacement"] is None and rows["plain"]["replaced_by"] is None and rows["plain"]["capabilities"] is None, rows["plain"])

print("[TEST] PASS module replacement 1.17.9")


# 1.17.9-1: a queued enable counts at queue time, so two queued jobs cannot both pass into a both-enabled state
import json as _json

jobs = TMP / "jobs"
jobs.mkdir()
v2.JOBS_ROOT = jobs
world(patching=False, pm=False)
must(problems("patchmanagement")["valid"] is True and problems("patching")["valid"] is True, "both free before any job")
(jobs / "a.json").write_text(_json.dumps({"id": "a", "action": "enable", "plugin_id": "patching", "affected_modules": ["patching"], "status": "queued", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
result = problems("patchmanagement")
must(result["valid"] is True and result["will_disable"] == ["patching"], result)  # 1.17.11: it will disable it
(jobs / "a.json").write_text(_json.dumps({"id": "a", "action": "enable", "plugin_id": "patching", "affected_modules": ["patching"], "status": "succeeded", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
must(problems("patchmanagement")["valid"] is True and problems("patchmanagement")["will_disable"] == [], "a finished job is already in the live state, not overlaid")
# the other order: a queued enable of the replacement makes enabling the core module a conflict
(jobs / "a.json").write_text(_json.dumps({"id": "a", "action": "enable", "plugin_id": "patchmanagement", "affected_modules": ["patchmanagement"], "status": "queued", "created_at": "2026-10-09T10:00:00"}), encoding="utf-8")
result = problems("patching")
must(result["valid"] is True and result["will_disable"] == ["patchmanagement"], result)  # 1.17.12: it will switch the queued replacement off
print("[TEST] PASS pending-job enable recheck 1.17.9-1")
