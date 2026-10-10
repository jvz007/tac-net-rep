#!/usr/bin/env python3
"""1.17.16 regression: ``description`` is an accepted manifest key (patching 0.4.0 round 7 request; module standard section 1).

A plain string of 1 to 500 characters with no control characters. Extensions and reportsets may both declare it, and no module
has to. It is parsed into ``PluginSpec.description`` and shown as ``description`` on the module catalogue rows, the package
inspect preview and the runtime snapshot rows, null when absent. The real registry.py, module_manager.py, module_manager_v2.py and
module_runtime.py run with the Linux-only and signing modules stubbed.
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
logging.disable(logging.CRITICAL)


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

from tec_tac import module_category, module_manager, module_manager_v2 as v2, module_runtime, module_state, registry  # noqa: E402

module_category.is_development_server = lambda: True
TMP = Path(tempfile.mkdtemp(prefix="tectac-description-"))
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


def write(module_id, root=EXT, **extra):
    folder = root / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension" if root is EXT else "reportset", "version": "1.0.0", "name": module_id}
    payload.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


def reset():
    for root in (EXT, REP):
        for folder in list(root.iterdir()):
            for child in folder.iterdir():
                child.unlink()
            folder.rmdir()
    STATE["modules"] = {}


def refused(**extra):
    reset()
    write("patching", **extra)
    try:
        registry.discover_plugins()
    except registry.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"accepted: {extra!r}")


# ---- a valid description is parsed
reset()
write("patching", description="  Scans and installs Windows updates for the endpoints you manage.  ", category="core")
spec = registry.discover_plugins()[0]
must(spec.description == "Scans and installs Windows updates for the endpoints you manage.", repr(spec.description))
write("patching", description="x" * 500)
must(len(registry.discover_plugins()[0].description) == 500, "500 characters is the limit")
write("patching", description="é and 中文 are fine")
must(registry.discover_plugins()[0].description == "é and 中文 are fine", "printable non-ASCII text is allowed")

# ---- refusals, with plain messages
for bad in ("", "   ", "x" * 501, 5, None, ["a"], {"a": 1}, True, "line\nbreak", "tab\there", "nul\x00byte", "bell\x07", "del\x7f"):
    message = refused(description=bad)
    must("description" in message and "patching" in message, message)
must("500" in refused(description="x" * 501), "the limit is named")
must("control" in refused(description="a\nb"), "control characters are named")

# ---- absent: loads as before, null on the rows
reset()
write("patching", category="core")
spec = registry.discover_plugins()[0]
must(spec.description == "", spec)
rows = {row["id"]: row for row in module_manager.installed_catalog()}
must(rows["patching"]["description"] is None, rows["patching"])
must(module_runtime.module_runtime_snapshot(registry.get_plugins())[0]["description"] is None, "runtime row")
must(v2._route_and_description_metadata({"id": "patching"})["description"] is None, "inspect")

# ---- shown on the catalogue (v1 and v2), the inspect metadata and the runtime snapshot
reset()
write("patching", description="Windows patching.", category="core")
write("alerts", category="core")
rows = {row["id"]: row for row in module_manager.installed_catalog()}
must(rows["patching"]["description"] == "Windows patching." and rows["alerts"]["description"] is None, (rows["patching"], rows["alerts"]))
rows2 = {row["id"]: row for row in v2.installed_catalog_v2()}
must(rows2["patching"]["description"] == "Windows patching." and rows2["alerts"]["description"] is None, "v2 catalogue rows")
snap = {row["id"]: row for row in module_runtime.module_runtime_snapshot(registry.get_plugins())}
must(snap["patching"]["description"] == "Windows patching." and snap["alerts"]["description"] is None, snap)
meta = v2._extension_metadata(EXT / "patching")
must(meta["description"] == "Windows patching.", meta)
# a package with a bad description is refused at inspect, with the registry's own text
try:
    v2._route_and_description_metadata({"id": "patching", "description": "x" * 501})
    raise AssertionError("inspect accepted a long description")
except v2.ModuleManagerV2Error as exc:
    must("500" in str(exc), str(exc))

# ---- a reportset may declare it too, and omitting it is fine
reset()
write("patching", category="core", description="Patching.")
write("patching", root=REP, description="Patching reports.")
plugins = registry.discover_plugins()
must({(p.plugin_type, p.description) for p in plugins} == {("extension", "Patching."), ("reportset", "Patching reports.")}, plugins)
reset()
write("patching", category="core")
write("patching", root=REP)
must(all(p.description == "" for p in registry.discover_plugins()), "both may omit it")

# ---- every earlier PluginSpec call shape still works
spec = registry.PluginSpec(plugin_id="x", plugin_type="extension", root=TMP)
must(spec.description == "" and spec.legacy is False, spec)

print("[TEST] PASS module manifest description 1.17.16")
