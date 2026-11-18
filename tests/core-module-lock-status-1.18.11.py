#!/usr/bin/env python3
"""Regression: Core 1.18.11, the read-only status of the core-module lock on the module catalogue (Johan, 18 November 2026).

GET /api/tfd/modules/v2/ rows carry always_on, lifecycle_locked and lifecycle_lock_reason (additive). The real registry,
module_category, module_replacement and module_manager_v2 run against manifests in a temporary folder.
What cannot run here: the HTTP view (Django REST framework is not installed on this PC)."""
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


sys.modules.setdefault("fcntl", types.ModuleType("fcntl")).__dict__.update(dict(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None))
from tec_tac import module_category as mc, module_manager, module_manager_v2 as v2, module_runtime, module_state, registry  # noqa: E402

for name in ("tec_tac.module_replacement", "tec_tac.module_runtime", "tec_tac.module_manager_v2"):
    logging.getLogger(name).addHandler(logging.NullHandler())

DEV = {"on": False, "reads": 0}


def dev():
    DEV["reads"] += 1
    return DEV["on"]


mc.is_development_server = dev
TMP = Path(tempfile.mkdtemp(prefix="tectac-core-lock-status-"))
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
    "agents": {"category": "core", "name": "Agents"},
    "health": {"category": "server", "name": "Health"},
    "halo": {"category": "premium", "name": "Halo"},
}
for module_id, extra in MANIFESTS.items():
    folder = EXT / module_id
    folder.mkdir()
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0", **extra}), encoding="utf-8")


def rows(**enabled):
    STATE["modules"] = {name: {"enabled": enabled.get(name, True), "category": MANIFESTS[name]["category"]} for name in MANIFESTS}
    DEV["reads"] = 0
    return {row["id"]: row for row in v2.installed_catalog_v2()}


def fields(row):
    return row["always_on"], row["lifecycle_locked"], row["lifecycle_lock_reason"]


# production
DEV["on"] = False
data = rows()
must(fields(data["agents"])[:2] == (True, True) and "Agents is a core module and always stays installed and on" in data["agents"]["lifecycle_lock_reason"], fields(data["agents"]))
for module_id in ("health", "halo", "patchmanagement"):
    must(fields(data[module_id]) == (False, False, None), (module_id, fields(data[module_id])))
total = DEV["reads"]
DEV["reads"] = 0
module_manager.installed_catalog()
must(total - DEV["reads"] == 1, f"the lock reads the development flag once per catalogue build, not per row ({total} reads, {DEV['reads']} already made by the v1 rows)")
# a core module with an enabled replacement conflict stays locked
must(fields(rows(patching=True, patchmanagement=True)["patching"])[:2] == (True, True), "a conflict is not honoured")
# honoured replacement: always_on stays true, the lock is off
data = rows(patching=False, patchmanagement=True)
must(fields(data["patching"]) == (True, False, None), fields(data["patching"]))
# development
DEV["on"] = True
data = rows()
must(fields(data["agents"]) == (True, False, None), fields(data["agents"]))
DEV["on"] = False
# the state category alone sets always_on
data = rows()
STATE["modules"]["halo"]["category"] = "core"
data = {row["id"]: row for row in v2.installed_catalog_v2()}
must(fields(data["halo"])[:2] == (True, True), fields(data["halo"]))
# remove-check reports the lock
data = rows()
check = v2.validate_remove("agents")
must(check["valid"] is True and check["dependants"] == [] and check["locked"] is True and "always stays installed" in check["message"], check)
must(v2.validate_remove("health")["locked"] is False, "server module")

# legacy rows (source level: a legacy plugin has no manifest category)
text = (ROOT / "framwork/tec_tac/module_manager_v2.py").read_bytes().decode("utf-8")
must('"always_on": False, "lifecycle_locked": False, "lifecycle_lock_reason": None' in text, "legacy rows carry the three fields")
# contract text
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_bytes().decode("utf-8")
must(contracts.count("\r\n") == contracts.count("\n"), "contracts.py keeps its CRLF line endings")
for needle in ("core_module_locked", "always_on", "lifecycle_locked", "lifecycle_lock_reason", "remove-check", "Since 1.18.11"):
    must(needle in contracts, needle)
docs = (ROOT / "docs/module-categories.md").read_bytes().decode("utf-8")
must("tectac_module_state" in docs and "A core module always stays installed and on (1.18.11" in docs, "docs")
must("Enabling or disabling an installed module is never refused for its category" in docs, "the 1.17.14 sentence stays")
print("[TEST] PASS core module lock status 1.18.11")
