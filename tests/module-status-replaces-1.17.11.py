#!/usr/bin/env python3
"""1.17.11 regression: each module_status row of GET /api/tfd/ui/context/ carries replaces (UI request 0.12.88).

The row key set is exactly the old keys plus replaces (a string for a module that declares one, null for a plain module and for a legacy
plugin). The browser contract rows no longer say that UI 0.12.87 does not enforce the scoping rule, and the runtime-context and
module-status rows mention replaces. Real module_runtime.py, registry.py and module_replacement.py; the contract file is read as text.
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

from tec_tac import module_manager, module_manager_v2 as v2, module_state, registry  # noqa: E402

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

logging.getLogger("tec_tac.module_runtime").addHandler(logging.NullHandler())
from tec_tac import module_runtime  # noqa: E402

module_runtime.load_state = lambda: STATE
OLD_KEYS = {"id", "version", "installed", "enabled", "active", "legacy"}

world(patching=False, pm=True)
manifest("plain")
legacy = types.SimpleNamespace(plugin_id="oldplugin", plugin_type="legacy", legacy=True, version="3.1", permission_groups=(), audit_events=(), replaces="patching")
plugins = list(registry.get_plugins()) + [legacy]
snapshot = {row["id"]: row for row in module_runtime.module_runtime_snapshot(plugins)}
must(set(snapshot) == {"patching", "patchmanagement", "plain", "oldplugin"}, sorted(snapshot))
for module_id, row in snapshot.items():
    must(set(row) == OLD_KEYS | {"replaces"}, (module_id, sorted(row)))  # exactly the old keys plus replaces
must(snapshot["patchmanagement"]["replaces"] == "patching", snapshot["patchmanagement"])
must(snapshot["patching"]["replaces"] is None and snapshot["plain"]["replaces"] is None, "a module that declares none: null")
must(snapshot["oldplugin"]["replaces"] is None and snapshot["oldplugin"]["legacy"] is True and snapshot["oldplugin"]["enabled"] is True, snapshot["oldplugin"])
must(all(row["replaces"] is None or isinstance(row["replaces"], str) for row in snapshot.values()), "string or null")
# the declared value, not the honoured one: a disabled replacement and one that lost parity still carry it
world(patching=False, pm=False)
must({r["id"]: r for r in module_runtime.module_runtime_snapshot(registry.get_plugins())}["patchmanagement"]["replaces"] == "patching", "declared, not honoured")
world(patching=False, pm=True, pm_caps={"patching.windows": "1.2.0"})
must({r["id"]: r for r in module_runtime.module_runtime_snapshot(registry.get_plugins())}["patchmanagement"]["replaces"] == "patching", "declared, even without parity")
# the old values are unchanged for everything that is not a conflict
must(snapshot["patching"]["enabled"] is False and snapshot["patchmanagement"]["enabled"] is True and snapshot["patchmanagement"]["active"] is True, snapshot)
must(snapshot["plain"]["version"] == "1.0.0" and snapshot["plain"]["installed"] is True, snapshot["plain"])

# ------------------------------------------------------------------------------------------ the contract text
tree = ast.parse((ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8"))
assignment = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BROWSER_CONTRACTS" for t in node.targets))
by_id = {row["id"]: row for row in ast.literal_eval(assignment.value)}


def details(row_id):
    return " ".join(by_id[row_id]["details"])


op = details("ui.authenticated.tactical-operation")
for stale in ("UI 0.12.87 does not enforce", "does not enforce that scoping rule yet", "closes the held review finding does"):
    must(stale not in op, f"stale wording: {stale}")
for needle in ("From UI 0.12.88", "binds tacticalOperation to the calling module", "descriptor.replaces", "module_status", "module_status[].replaces", "Core 1.17.11",
               "refuses every call after a failed or timed-out register()", "fails closed when the row carries no replaces",
               "api, apiRaw, apiBlob or apiText", "held 0.12.88 review finding", "Core's own checks", "route is owned", "honoured"):
    must(needle in op, f"tactical-operation row lacks {needle!r}")
status_text = details("ui.authenticated.module-status")
for needle in ("replaces", "Core 1.17.11", "declared value, not the honoured one", "enabled false and active false"):
    must(needle in status_text, f"module-status row lacks {needle!r}")
runtime_text = details("ui.authenticated.runtime-context")
for needle in ("module_status[].replaces", "Core 1.17.11", "UI 0.12.88", "fails closed", "Additive"):
    must(needle in runtime_text, f"runtime-context row lacks {needle!r}")
must("Browser helpers" in (ROOT / "docs/tactical-operations.md").read_text(encoding="utf-8"), "docs pointer")
for doc in ("docs/tactical-operations.md", "docs/module-replacement.md"):
    text = (ROOT / doc).read_text(encoding="utf-8")
    must("module_status" in text and "replaces" in text and "0.12.88" in text, f"{doc} does not describe module_status[].replaces for UI 0.12.88")

print("[TEST] PASS module_status replaces 1.17.11")
