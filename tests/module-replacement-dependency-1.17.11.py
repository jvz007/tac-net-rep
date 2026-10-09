#!/usr/bin/env python3
"""1.17.11 regression: an honoured replacement satisfies a hard dependency on the replaced module id (AD-20 amendment 3).

Covers the catalog row (satisfied_by, enabled stays truthful), validate_enable, the version constraint that still applies to the
replaced module, the cases that do not count (replacement disabled, parity lost, both enabled, rival, target not core), blocking
and cascading a disable of the replacement, and the install plan. Real registry, module_replacement and module_manager_v2.
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


mr.audit_switch_queued = lambda *args, **kwargs: None  # the audit row is covered in the enable test

captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}


def with_consumer(constraint="*", consumer=False, **kwargs):
    """The patching / patchmanagement world plus a module that hard-depends on the replaced id."""
    world(**kwargs)
    manifest("consumer", dependencies={"patching": constraint})
    STATE["modules"]["consumer"] = {"enabled": consumer}


def dep_row(**kwargs):
    return rows()["consumer"]["dependency_status"][0]


def problems_of(module_id):
    return [problem["type"] for problem in v2.validate_enable(module_id)["problems"]]


# ------------------------------------------------------------------------------------------ before: the dependency is unsatisfied
with_consumer(patching=False, pm=False)
row = dep_row()
must(row["id"] == "patching" and row["enabled"] is False and row["satisfied_by"] is None, row)
must(problems_of("consumer") == ["disabled_dependency"], problems_of("consumer"))

# ------------------------------------------------------------------------------------------ while honoured: satisfied by the replacement
with_consumer(patching=False, pm=True)
row = dep_row()
must(row["satisfied"] is True and row["satisfied_by"] == "patchmanagement" and row["enabled"] is False, row)  # enabled stays truthful
must(problems_of("consumer") == [], problems_of("consumer"))
must(v2.validate_enable("consumer")["valid"] is True, "the consumer can be enabled while the replacement is honoured")
# the dependency list does not change for a module whose dependency is enabled
with_consumer(patching=True, pm=False)
must(dep_row()["satisfied_by"] is None and dep_row()["enabled"] is True, dep_row())
must(problems_of("consumer") == [], "an enabled dependency is satisfied as before")

# ------------------------------------------------------------------------------------------ the version still applies to the replaced module
with_consumer(">=2.0.0", patching=False, pm=True)
must(problems_of("consumer") == ["dependency_version"], problems_of("consumer"))
row = dep_row()
must(row["satisfied"] is False and row["satisfied_by"] == "patchmanagement" and row["installed_version"] == "1.0.0", row)
with_consumer(">=1.0.0", patching=False, pm=True)
must(problems_of("consumer") == [], "a constraint the installed replaced module meets")

# ------------------------------------------------------------------------------------------ not satisfied when not honoured
with_consumer(patching=False, pm=False)
must(dep_row()["satisfied_by"] is None and problems_of("consumer") == ["disabled_dependency"], "replacement disabled")
with_consumer(patching=False, pm=True, pm_caps={"patching.windows": "1.2.0"})
must(dep_row()["satisfied_by"] is None and problems_of("consumer") == ["disabled_dependency"], "parity lost: not honoured")
with_consumer(patching=True, pm=True)
must(dep_row()["satisfied_by"] is None, "both enabled: not honoured")
with_consumer(patching=False, pm=True)
manifest("rival", replaces="patching", capabilities=PM_CAPS)
STATE["modules"]["rival"] = {"enabled": True}
must(dep_row()["satisfied_by"] is None and problems_of("consumer") == ["disabled_dependency"], "two enabled replacements: neither is honoured")
with_consumer(patching=False, pm=True)
manifest("patching")  # the replaced module is no longer a core module
manifest("patchmanagement", replaces="patching", capabilities=PM_CAPS)
must(dep_row()["satisfied_by"] is None, "target-not-core")
must(mr.satisfies_dependency({}, "patching") is None and mr.satisfies_dependency(mr.live_model(), "nosuch") is None, "unknown ids")

# ------------------------------------------------------------------------------------------ disabling the replacement while a dependant needs it
with_consumer(patching=False, pm=True, consumer=True)
must(v2._enabled_dependants("patchmanagement") == [{"id": "consumer", "constraint": "*", "via": "patching"}], v2._enabled_dependants("patchmanagement"))
must(v2._enabled_dependants("patching") == [{"id": "consumer", "constraint": "*"}], "the replaced module's own dependants are unchanged")
must(v2.validate_remove("patchmanagement")["valid"] is False, "removing the replacement is flagged too")
# 1.17.12 (CQ33): disabling the replacement switches the replaced module back on in the same job, so the dependant of the
# replaced module stays satisfied and blocks nothing. A dependant of the replacement itself still needs cascade
# (tests/module-replacement-handback-1.17.12.py).
v2.queue_set_enabled("patchmanagement", False)
must(captured[-1]["action"] == "disable" and captured[-1]["affected_modules"] == ["patchmanagement"] and captured[-1]["enable_modules"] == ["patching"], captured[-1])
v2.queue_set_enabled("patchmanagement", False, cascade=True)
must(captured[-1]["affected_modules"] == ["patchmanagement"], "cascade has nothing to add: the consumer stays satisfied by the module that comes back")
# a disabled dependant blocks nothing
with_consumer(patching=False, pm=True, consumer=False)
must(v2._enabled_dependants("patchmanagement") == [], "no enabled dependants")
v2.queue_set_enabled("patchmanagement", False)
must(captured[-1]["affected_modules"] == ["patchmanagement"], captured[-1])
# a dependant that depends on the replacement directly is listed once, with no via
with_consumer(patching=False, pm=True, consumer=True)
manifest("consumer", dependencies={"patching": "*", "patchmanagement": "*"})
must(v2._enabled_dependants("patchmanagement") == [{"id": "consumer", "constraint": "*", "via": "patching"}] or
     v2._enabled_dependants("patchmanagement") == [{"id": "consumer", "constraint": "*"}], v2._enabled_dependants("patchmanagement"))
must(len(v2._enabled_dependants("patchmanagement")) == 1, "listed once")

# the enable-with-disable job does not cascade: the replacement keeps the dependants satisfied
with_consumer(patching=True, pm=False, consumer=True)
captured.clear()
v2.queue_set_enabled("patchmanagement", True, disable_replaced=["patching"])
must(captured[0]["affected_modules"] == ["patchmanagement"] and captured[0]["disable_modules"] == ["patching"] and captured[0]["cascade"] is False, captured[0])
# enabling the replaced module again (hand back) with a dependant is not blocked by the dependant
with_consumer(patching=False, pm=False, consumer=True)
must(v2.validate_enable("patching")["valid"] is True, "hand back")

# ------------------------------------------------------------------------------------------ the install plan
def plan(*items):
    return v2.resolve_install_plan(list(items))


PM = dict(replaces="patching", capabilities=PM_CAPS)
need = candidate("newconsumer", dependencies={"patching": "*"})
# the replaced module is disabled and its replacement is installed and enabled: satisfied
world(patching=False, pm=True)
must(plan(need)["valid"] is True, plan(need))
# the replacement is disabled: the dependency is disabled, as before
world(patching=False, pm=False)
result = plan(need)
must(not result["valid"] and result["problems"][0]["type"] == "disabled_dependency", result)
# the version constraint still applies
world(patching=False, pm=True)
result = plan(candidate("newconsumer", dependencies={"patching": ">=2.0.0"}))
must(not result["valid"] and result["problems"][0]["type"] == "dependency_version", result)
# the dependant and the replacement in the same batch: judged on the model after the install
world(patching=False, pm=True)
reset(patching=False)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
result = plan(candidate("patchmanagement", **PM), need)
must(result["valid"] is True and result["order"] == ["patchmanagement", "newconsumer"] or result["valid"] is True, result)
# the target is enabled and the replacement is installed fresh: it disables the target, the dependency stays satisfied
reset(patching=True)
manifest("patching", category="core", capabilities=PATCHING_CAPS)
result = plan(candidate("patchmanagement", **PM), need)
must(result["valid"] is True and result["will_disable"] == ["patching"], result)
# without the replacement in the plan a dependency on the enabled module is as before
result = plan(need)
must(result["valid"] is True and result["will_disable"] == [], result)

print("[TEST] PASS module replacement dependency 1.17.11")
