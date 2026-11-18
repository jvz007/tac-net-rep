#!/usr/bin/env python3
"""Regression: Core 1.18.11, a core module cannot be disabled or uninstalled (Johan, 18 November 2026). Core's own queue functions.

Runs the real registry, module_category, module_replacement and module_manager_v2 against manifests in a temporary folder
(the harness of tests/module-category-enable-1.17.14.py). No Django views are imported: they are checked at source level.
What cannot run here: the browser routes and a real audit table (the audit writer is a recorder)."""
from __future__ import annotations

import json
import logging
import re
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


sys.modules.setdefault("fcntl", types.ModuleType("fcntl")).__dict__.update(dict(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None))
from tec_tac import module_category as mc, module_manager, module_manager_v2 as v2, module_runtime, module_state, registry  # noqa: E402

for name in ("tec_tac.module_replacement", "tec_tac.module_runtime", "tec_tac.module_manager_v2"):
    logging.getLogger(name).addHandler(logging.NullHandler())

# ----------------------------------------------------------------------------------------------- audit recorder
ROWS = []
audit = types.ModuleType("tec_tac.audit")
audit.service_audit_actor = lambda **kw: types.SimpleNamespace(kind="service", identity=kw.get("identity"))
audit.record = lambda **kw: ROWS.append(kw) or {"recorded": True}
sys.modules["tec_tac.audit"] = audit
PERSON = types.SimpleNamespace(username="sam", is_authenticated=True)

DEV = {"on": False}
mc.is_development_server = lambda: DEV["on"]
TMP = Path(tempfile.mkdtemp(prefix="tectac-core-lock-"))
EXT, REP, JOBS = TMP / "extensions", TMP / "reportsets", TMP / "jobs"
for folder in (EXT, REP, JOBS):
    folder.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
v2.JOBS_ROOT = module_manager.JOBS_ROOT = JOBS
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_runtime.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins
CAPS = {"patching.windows": "1.0.0"}
MANIFESTS = {
    "patching": {"category": "core", "name": "Windows Patching", "capabilities": CAPS},
    "patchmanagement": {"category": "premium", "name": "Patch Management", "replaces": "patching", "capabilities": CAPS},
    "needspatching": {"category": "premium", "name": "Needs Patching", "dependencies": {"patching": ">=1.0.0"}},
    "agents": {"category": "core", "name": "Agents"},
    "health": {"category": "server", "name": "Health"},
    "halo": {"category": "premium", "name": "Halo"},
    "tester": {"category": "test", "name": "Tester"},
}


def write_manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(exist_ok=True)
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", **extra}), encoding="utf-8")


for module_id, extra in MANIFESTS.items():
    write_manifest(module_id, **extra)
queued = []
v2._queue_v2 = lambda payload: queued.append(payload) or {"id": f"job-{len(queued)}", "queued": True}
v1_jobs = []
module_manager._new_job = lambda payload: dict(payload, id=f"v1-{len(v1_jobs)}", status="queued")
module_manager._dispatch = lambda job_id: v1_jobs.append(job_id)
module_manager.public_job = lambda job: job
module_manager._atomic_json = lambda *a, **k: None


def world(**enabled):
    STATE["modules"] = {name: {"enabled": enabled.get(name, True), "category": MANIFESTS[name]["category"]} for name in MANIFESTS}
    del queued[:], ROWS[:], v1_jobs[:]


def locked_call(call, module_id=None):
    try:
        call()
    except v2.ModuleCoreLockedError as exc:
        must(exc.code == "core_module_locked" and exc.as_payload() == {"detail": str(exc), "code": "core_module_locked"}, exc)
        must(module_id is None or exc.module_id == module_id, (exc.module_id, module_id))
        return str(exc)
    raise AssertionError("the call was accepted")


def deny_rows():
    return [r for r in ROWS if r["action"] == "deny"]


# ------------------------------------------------------------------------------------------- the shared rule
lock = mc.core_lifecycle_lock("agents", "core", None, name="Agents", development=False, replaced_by_honoured=None)
must(lock and lock["reason"] == "core_module_locked", lock)
must(lock["message"] == "Agents is a core module and always stays installed and on. A premium module that replaces it can take over, and a development server can switch it off.", lock)
must(mc.core_lifecycle_lock("agents", "core", None, development=True, replaced_by_honoured=None) is None, "development")
must(mc.core_lifecycle_lock("agents", "core", None, development=False, replaced_by_honoured="patchmanagement") is None, "honoured replacement")
for manifest, state in (("server", None), ("premium", "premium"), ("test", None), ("", None), (None, "")):
    must(mc.core_lifecycle_lock("x", manifest, state, development=False, replaced_by_honoured=None) is None, (manifest, state))
must(mc.core_lifecycle_lock("x", "premium", "core", development=False, replaced_by_honoured=None), "state says core: fails closed")
must(mc.core_lifecycle_lock("x", "core", "premium", development=False, replaced_by_honoured=None), "manifest says core: locked")
must(mc.core_lifecycle_lock("x", "", "core", development=False, replaced_by_honoured=None), "state alone locks")

# ------------------------------------------------------------------------------------------- disable
DEV["on"] = False
world()
sentence = locked_call(lambda: v2.queue_set_enabled("agents", False, requested_by="sam", actor=PERSON), "agents")
must("Windows" not in sentence and "Agents is a core module" in sentence, sentence)
must(queued == [] and len(deny_rows()) == 1, (queued, ROWS))
row = deny_rows()[0]
must(row["actor"] is PERSON and row["module_id"] == "core" and row["object_type"] == "module" and row["object_id"] == "agents", row)
must(row["metadata"] == {"module": "agents", "action": "disable", "reason": "core_module_locked"} and row["strict"] is False, row)
# the target with dependants and no cascade: the lock answers first
world()
locked_call(lambda: v2.queue_set_enabled("patching", False, actor=PERSON), "patching")
must(queued == [] and len(deny_rows()) == 1, (queued, ROWS))
# a premium target whose dependency is a core module: dependants go up, the core module is not in the list
world()
job = v2.queue_set_enabled("needspatching", False, actor=PERSON)
must(job["queued"] and queued[0]["affected_modules"] == ["needspatching"] and not deny_rows(), (queued, ROWS))
# a cascade whose affected list reaches a core module (agents depends on health)
write_manifest("agents", category="core", name="Agents", dependencies={"health": ">=1.0.0"})
world()
locked_call(lambda: v2.queue_set_enabled("health", False, cascade=True, actor=PERSON), "agents")
must(queued == [] and len(deny_rows()) == 1 and deny_rows()[0]["object_id"] == "agents", (queued, ROWS))
locked_call(lambda: v2.validate_disable("health", ["agents", "health"]), "agents")
write_manifest("agents", category="core", name="Agents")
# a system caller (no person) is refused too, with a service actor
world()
locked_call(lambda: v2.queue_set_enabled("agents", False))
must(len(deny_rows()) == 1 and deny_rows()[0]["actor"].identity == "system", ROWS)
# validate_disable raises
world()
locked_call(lambda: v2.validate_disable("agents"), "agents")
# the state category alone locks (mismatch fails closed): a premium manifest that state records as core
world()
STATE["modules"]["halo"]["category"] = "core"
locked_call(lambda: v2.queue_set_enabled("halo", False, actor=PERSON), "halo")

# ------------------------------------------------------------------------------------------- passes
for module_id in ("health", "halo", "tester", "needspatching"):
    world()
    job = v2.queue_set_enabled(module_id, False, actor=PERSON)
    must(job["queued"] and queued[0]["action"] == "disable" and not deny_rows(), (module_id, queued))
# development server
DEV["on"] = True
world()
job = v2.queue_set_enabled("agents", False, actor=PERSON)
must(job["queued"] and queued[0]["plugin_id"] == "agents" and not deny_rows(), queued)
must(v2.validate_disable("agents")["valid"] is True, "development validates")
DEV["on"] = False
# enable is never refused
world(agents=False)
job = v2.queue_set_enabled("agents", True, actor=PERSON)
must(job["queued"] and queued[0]["action"] == "enable" and not deny_rows(), queued)

# honoured replacement: patchmanagement enabled, patching off. A disable of patching is allowed.
world(patching=False, patchmanagement=True, needspatching=False)
must(v2.queue_set_enabled("patching", False, actor=PERSON)["queued"] and not deny_rows(), "an honoured replacement lifts the lock")
# disabling the replacement hands the core module back, and the lock does not touch it
world(patching=False, patchmanagement=True, needspatching=False)
job = v2.queue_set_enabled("patchmanagement", False, actor=PERSON)
must(job["queued"] and queued[0]["enable_modules"] == ["patching"] and not deny_rows(), queued)
# enabling the replacement while the core module is on still disables the core module (the flow, not the lock)
world(patching=True, patchmanagement=False, needspatching=False)
job = v2.queue_set_enabled("patchmanagement", True, actor=PERSON, disable_replaced=["patching"])
must(job["queued"] and queued[0]["disable_modules"] == ["patching"] and not deny_rows(), queued)
# replacement installed but off, core on: a direct disable of the core module is locked
world(patching=True, patchmanagement=False, needspatching=False)
locked_call(lambda: v2.queue_set_enabled("patching", False, actor=PERSON), "patching")
# replacement enabled next to the core module (a conflict): not honoured, still locked
world(patching=True, patchmanagement=True)
locked_call(lambda: v2.queue_set_enabled("patching", False, actor=PERSON), "patching")

# ------------------------------------------------------------------------------------------- uninstall
world()
locked_call(lambda: module_manager.queue_remove("agents", requested_by="sam", actor=PERSON), "agents")
must(v1_jobs == [] and len(deny_rows()) == 1, (v1_jobs, ROWS))
must(deny_rows()[0]["metadata"] == {"module": "agents", "action": "remove", "reason": "core_module_locked"}, ROWS)
check = v2.validate_remove("agents")
must(check["valid"] is True and check["dependants"] == [] and check["locked"] is True and "always stays installed" in check["message"], check)
for module_id in ("health", "halo", "tester"):
    world()
    must(module_manager.queue_remove(module_id, requested_by="sam", actor=PERSON)["action"] == "remove" and not deny_rows(), module_id)
    check = v2.validate_remove(module_id)
    must(check["locked"] is False and check["message"] is None, (module_id, check))
DEV["on"] = True
world()
must(module_manager.queue_remove("agents", actor=PERSON)["action"] == "remove" and v2.validate_remove("agents")["valid"] is True, "development")
DEV["on"] = False
world(patching=False, patchmanagement=True, needspatching=False)
must(module_manager.queue_remove("patching", actor=PERSON)["action"] == "remove", "an honoured replacement lets the core module go")
world(patching=True, patchmanagement=False, needspatching=False)
locked_call(lambda: module_manager.queue_remove("patching", actor=PERSON), "patching")

# ------------------------------------------------------------------------------------------- source checks
raw = (ROOT / "framwork/tec_tac/module_manager_v2.py").read_bytes().decode("utf-8")
must(raw.count("\r\n") == raw.count("\n"), "module_manager_v2.py keeps its CRLF line endings")
body = raw.replace("\r\n", "\n")
for name in ("def apply_enable_job", "apply_install_prepare_disable", "verify_install_disables"):
    must(name not in body or "enforce_core_lock" not in body[body.index(name):body.index(name) + 600], name)
must(body.index("def queue_set_enabled") < body.index("enforce_core_lock(catalog, [module_id]") < body.index("job = _queue_v2(payload)"), "lock runs before the job is queued")
must(body.count("enforce_core_lock(") >= 4, "target, cascade, validate_disable and the definition")
views = (ROOT / "framwork/tec_tac/module_v2_views.py").read_text(encoding="utf-8")
must(re.search(r"ModuleCoreLockedError\) as exc:\n\s+return Response\(exc.as_payload\(\), status=400\)", views), "state view answers 400 with code")
top = (ROOT / "framwork/tec_tac/views.py").read_text(encoding="utf-8")
must(re.search(r"ModuleCoreLockedError\) as exc:\n\s+return Response\(exc.as_payload\(\), status=400\)", top), "remove view answers 400 with code")
print("[TEST] PASS core module lock 1.18.11")
