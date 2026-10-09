#!/usr/bin/env python3
"""1.17.11 regression: the four Lows held from the 1.17.10 review.

(a) the contract rows name registered_mismatch, the registration-caused degraded and the conflict field; (b) a refused re-registration
drops an earlier registration of the same id by the same module under the capability lock, and never one owned by another module;
(c) the archived 1.17.10 note no longer claims that no manifest declares capabilities, and the 1.17.11 note states the Endpoints case;
(d) docs/capabilities.md says registered_mismatch covers only replacement version refusals. Real registry, module_state,
module_replacement and capabilities against a temporary folder of manifests.
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


import ast

logging.getLogger("tec_tac.capabilities").addHandler(logging.NullHandler())
logging.getLogger("tec_tac.capabilities").propagate = False
caps = capabilities


def register(cap, module, version="1.2.0"):
    return caps.register_capability(id=cap, module_id=module, version=version, provider=object())


def listed(module="patchmanagement"):
    return [(row["capability"], row["declared"], row["registered"], row["reason"]) for row in mr.replacement_status(module)["registered_mismatch"]]


# ------------------------------------------------------------------------------------------ (b) a refused re-registration drops the name
# a replacement: accepted at 1.2.0, refused at 2.0.0
world(patching=False, pm=True)
caps._clear_capabilities_for_tests()
mr._MISMATCHES.clear()
first = register("patching.windows", "patchmanagement", "1.2.0")
must(caps._registration("patching.windows") is first and listed() == [], "accepted at the declared version")
register("patching.windows", "patchmanagement", "2.0.0")
must(caps._registration("patching.windows") is None, "the earlier registration is gone, the name is unavailable")
state_row = caps.capability_status("patching.windows")
must(state_row["available"] is False and state_row["state"] != "available", state_row)
must(listed() == [("patching.windows", "1.2.0", "2.0.0", "capability-major-mismatch")], listed())  # and it is still listed in registered_mismatch
must(mr.replacement_status("patchmanagement")["degraded"] is True, "degraded")
# a later correct registration clears both
register("patching.windows", "patchmanagement", "1.2.0")
must(caps._registration("patching.windows") is not None and listed() == [], "a correct registration restores the name and clears the row")
# the version-lower refusal does the same
register("patching.windows", "patchmanagement", "1.1.0")
must(caps._registration("patching.windows") is None and listed()[0][3] == "capability-version-lower", listed())

# a core module: an id its manifest no longer declares
reset(patching=True)
manifest("patching", category="core", capabilities={**PATCHING_CAPS, "patching.extra": "1.0.0"})
caps._clear_capabilities_for_tests()
register("patching.extra", "patching", "1.0.0")
must(caps._registration("patching.extra") is not None, "declared: registered")
manifest("patching", category="core", capabilities=PATCHING_CAPS)  # a later version drops it from the manifest
register("patching.extra", "patching", "1.0.0")
must(caps._registration("patching.extra") is None, "the earlier registration is dropped with the refusal")
must(caps.capability_status("patching.extra")["available"] is False, "unavailable")

# the unhonoured replacement name (both enabled): another module's registration is never dropped
world(patching=True, pm=True)
caps._clear_capabilities_for_tests()
mine = register("patching.windows", "patching", "1.2.0")  # the core module's registration
must(caps._registration("patching.windows") is mine, "owned by the core module")
register("patching.windows", "patchmanagement", "1.2.0")  # not honoured: both enabled
must(caps._registration("patching.windows") is mine, "another module's registration is never dropped")
register("patching.windows", "patchmanagement", "2.0.0")
must(caps._registration("patching.windows") is mine, "still the core module's")
# the replacement's own registration, made while it was honoured, goes when it stops being honoured and registers again
world(patching=False, pm=True)
caps._clear_capabilities_for_tests()
register("patching.scan", "patchmanagement", "1.1.0")
must(caps._registration("patching.scan") is not None, "registered while honoured")
STATE["modules"]["patching"]["enabled"] = True  # the core module is enabled again, in a process that kept the registration
register("patching.scan", "patchmanagement", "1.1.0")
must(caps._registration("patching.scan") is None, "the replacement's own stale registration is dropped")
# an unrelated module's registration survives a refusal of a different id of its own
world(patching=False, pm=True)
caps._clear_capabilities_for_tests()
manifest("bystander", category="core", capabilities={"bystander.x": "1.0.0"})
STATE["modules"]["bystander"] = {"enabled": True}
other = register("bystander.x", "bystander", "1.0.0")
register("bystander.undeclared", "bystander", "1.0.0")
must(caps._registration("bystander.x") is other and caps._registration("bystander.undeclared") is None, "an unrelated registration is untouched")
# the core module's refusal is logged and is not listed in registered_mismatch
must(not any(row[0].startswith("bystander") for row in listed()), "not listed")

# ------------------------------------------------------------------------------------------ (a) the contract text
tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


purpose = next(row["purpose"] for row in literal("CORE_CONTRACTS") if row["name"] == "replacement_status")
for needle in ("registered_mismatch", "{capability, declared, registered, reason}", "degraded", "also when registered_mismatch is not empty", "conflict", "1.17.10", "undeclared-id"):
    must(needle in purpose, f"replacement_status row lacks {needle!r}")
http = literal("HTTP_CONTRACT_DETAILS")
catalog = http["/api/tfd/modules/v2/"]["response"]
text = catalog["modules[].replacement"]
must("registered_mismatch" in text and "degraded" in text and "conflict" in text and "1.17.10" in text and "1.17.11" in text, text)
for key in ("modules[].will_disable", "modules[].dependency_status[].satisfied_by"):
    must(key in catalog, key)
modules_errors = http["/api/tfd/modules/v2/"]["errors"]["400"]
must("replacement_conflict" in modules_errors and "replacement_incomplete" in modules_errors, modules_errors)
state_contract = http["/api/tfd/modules/v2/<str:plugin_id>/state/"]["POST"]
must("disable_replaced" in state_contract["request"] and "replacement_confirmation_required" in state_contract["errors"]["400"] and "will_disable" in state_contract["errors"]["400"], state_contract)
install_contract = http["/api/tfd/modules/v2/packages/<uuid:upload_id>/install/"]["POST"]
must("disable_replaced" in install_contract["request"] and "replacement_confirmation_required" in install_contract["errors"]["400"], install_contract)

# ------------------------------------------------------------------------------------------ (c) release notes and (d) docs
old_note = (ROOT / "docs/releases/RELEASE_NOTES_1.17.10.md").read_text(encoding="utf-8")
must("A scan of `modules/` finds no manifest that declares the key" not in old_note, "the archived 1.17.10 note still makes the wrong claim")
must("modules/endpoints" in old_note and '"capabilities": {}' in old_note, "the archived 1.17.10 note states the Endpoints case")
must(not (ROOT / "RELEASE_NOTES_1.17.10.md").exists(), "the 1.17.10 note moved out of the root")
version = "1.17.11"  # 1.17.12: the 1.17.11 note moved to docs/releases/, the root holds the current one
note = (ROOT / "docs" / "releases" / f"RELEASE_NOTES_{version}.md").read_text(encoding="utf-8")
for needle in ("Endpoints", "no capability id can be registered", "harmless", "Module-facing"):
    must(needle in note, f"the {version} note lacks {needle!r}")
docs = (ROOT / "docs/capabilities.md").read_text(encoding="utf-8")
must("`registered_mismatch` in `replacement_status` covers only replacement version refusals" in docs, "docs/capabilities.md wording")
must("logged once and nothing else" in docs, "docs/capabilities.md undeclared-id wording")

print("[TEST] PASS held Lows 1.17.11")
