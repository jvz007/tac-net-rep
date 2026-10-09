#!/usr/bin/env python3
"""1.17.11 regression: server modules can be replaced as well as core modules (AD-20 amendment 4).

Manifest category server, the capability prefix rule, parity, enable and install with will_disable, hand back, and registration
for a server module and its replacement. A module with no category as the target is still target-not-core, and a reportset may
not declare a category. Real registry, module_state, module_replacement, capabilities and module_manager_v2.
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


logging.getLogger("tec_tac.module_runtime").addHandler(logging.NullHandler())
captured = []
v2._queue_v2 = lambda payload: captured.append(payload) or {"id": f"job-{len(captured)}", "queued": True}
mr.audit_replaced_disabled = lambda *args, **kwargs: None
BACKUP_CAPS = {"backups.run": "1.0.0", "backups.restore": "1.1.0"}
ALT_CAPS = {"backups.run": "1.0.0", "backups.restore": "1.2.0", "backups.cloud": "1.0.0"}


def refused_manifest(module_id, root=EXT, **extra):
    manifest(module_id, root=root, **extra)
    try:
        registry.get_plugins()
    except registry.RegistryError as exc:
        text = str(exc)
        (root / module_id / "tec_tac.json").unlink()
        (root / module_id).rmdir()
        return text
    raise AssertionError(f"manifest accepted: {extra}")


def server_world(*, backups=False, alt=True, server_caps=BACKUP_CAPS, alt_caps=ALT_CAPS):
    reset(backups=backups, altbackups=alt)
    manifest("backups", category="server", **({"capabilities": server_caps} if server_caps is not None else {}))
    manifest("altbackups", replaces="backups", capabilities=alt_caps)


# ------------------------------------------------------------------------------------------ manifest rules
reset()
manifest("srv", category="server")
manifest("corem", category="core")
specs = {p.plugin_id: p for p in registry.get_plugins()}
must(specs["srv"].category == "server" and specs["corem"].category == "core", "category server is accepted")
must("category must be 'core' or 'server'" in refused_manifest("other", category="premium"), "other values are still refused")
must("category" in refused_manifest("rs", root=REP, category="server"), "a reportset may not declare a category")
must("may not declare replaces" in refused_manifest("srv2", category="server", replaces="corem"), "a server module may not replace anything")
must("prefix" in refused_manifest("srv3", category="server", capabilities={"other.thing": "1.0.0"}), "a server module declares only its own prefix")
manifest("srv4", category="server", capabilities={"srv4.run": "1.0.0"})
registry.get_plugins()
reset()

# ------------------------------------------------------------------------------------------ honoured
server_world()
must(mr.honoured_replacement("altbackups") == "backups" and mr.replaced_by("backups") == "altbackups", mr.replacement_status("altbackups"))
status = mr.replacement_status("altbackups")
must(status["honoured"] is True and status["conflict"] is False and status["capabilities"]["expected"] == ["backups.restore", "backups.run"], status)
# a module with no category as the target is still target-not-core
reset(plainmod=True, altplain=True)
manifest("plainmod", capabilities={"plainmod.run": "1.0.0"})
manifest("altplain", replaces="plainmod", capabilities={"plainmod.run": "1.0.0"})
must(mr.replacement_status("altplain")["reason"] == "target-not-core" and mr.honoured_replacement("altplain") is None, mr.replacement_status("altplain"))
# parity applies to a server module the same way
for alt_caps, reason in (({"backups.run": "1.0.0"}, "capability-missing"), ({"backups.run": "1.0.0", "backups.restore": "2.0.0"}, "capability-major-mismatch"),
                         ({"backups.run": "1.0.0", "backups.restore": "1.0.0"}, "capability-version-lower")):
    server_world(alt_caps=alt_caps)
    must(mr.replacement_status("altbackups")["reason"] == reason, (alt_caps, mr.replacement_status("altbackups")))
server_world(server_caps=None)
must(mr.replacement_status("altbackups")["reason"] == "capabilities-undeclared", "a server module cannot hide its contracts")

# ------------------------------------------------------------------------------------------ enable with will_disable
server_world(backups=True, alt=False)
table = rows()
must(table["altbackups"]["will_disable"] == ["backups"] and table["backups"]["will_disable"] == [], table["altbackups"]["will_disable"])
try:
    v2.queue_set_enabled("altbackups", True)
    raise AssertionError("queued without confirmation")
except v2.ModuleReplacementConfirmationRequired as exc:
    must(exc.will_disable == ["backups"], exc)
v2.queue_set_enabled("altbackups", True, disable_replaced=["backups"])
must(captured[-1]["disable_modules"] == ["backups"] and captured[-1]["affected_modules"] == ["altbackups"], captured[-1])
# the server module next to its enabled replacement is refused (hand back is disable first)
server_world(backups=False, alt=True)
result = v2.validate_enable("backups")
must(not result["valid"] and result["problems"][0]["replaced_by"] == "altbackups", result)
# hand back: disable the replacement, then enable the server module
v2.queue_set_enabled("altbackups", False)
must(captured[-1]["action"] == "disable", captured[-1])
STATE["modules"]["altbackups"]["enabled"] = False
must(v2.validate_enable("backups")["valid"] is True and mr.honoured_replacement("altbackups") is None, "handed back")
# both enabled: a conflict, as for a core module
server_world(backups=True, alt=True)
must(mr.conflicted_replacements(mr.live_model()) == [("altbackups", "backups")] and mr.replacement_status("altbackups")["conflict"] is True, "conflict")

# ------------------------------------------------------------------------------------------ install with will_disable
reset(backups=True)
manifest("backups", category="server", capabilities=BACKUP_CAPS)
plan = v2.resolve_install_plan([candidate("altbackups", replaces="backups", capabilities=ALT_CAPS)])
must(plan["valid"] is True and plan["will_disable"] == ["backups"] and plan["actions"][0]["will_disable"] == ["backups"], plan)
bad = v2.resolve_install_plan([candidate("altbackups", replaces="backups", capabilities={"backups.run": "1.0.0"})])
must(not bad["valid"] and bad["will_disable"] == [], bad)
# the replaced server module installed in the same batch is refused
both = v2.resolve_install_plan([candidate("backups", category="server", capabilities=BACKUP_CAPS), candidate("altbackups", replaces="backups", capabilities=ALT_CAPS)])
must(not both["valid"] and both["problems"][0]["reason"] == "target-enabled", both)

# ------------------------------------------------------------------------------------------ capabilities
server_world()
capabilities._clear_capabilities_for_tests()
must(capabilities.register_capability(id="backups.run", module_id="altbackups", version="1.0.0", provider=object()).module_id == "altbackups", "the honoured replacement registers the name")
server_world(backups=True, alt=False)
capabilities._clear_capabilities_for_tests()
must(capabilities.register_capability(id="backups.run", module_id="backups", version="1.0.0", provider=object()).module_id == "backups", "the server module registers its declared id")
refused = capabilities.register_capability(id="backups.undeclared", module_id="backups", version="1.0.0", provider=object())
must(capabilities._registration("backups.undeclared") is None and refused.provider is not None, "an undeclared id of a server module is not registered")
capabilities._clear_capabilities_for_tests()

# ------------------------------------------------------------------------------------------ no Tactical route is joined
# A server module has no Tactical routes, so an honoured server-module replacement joins no owner rule. That runs against the
# route owner table in tests/module-replacement-server-owner-1.17.11.py.

# ------------------------------------------------------------------------------------------ Swagger group per category
# openapi._module_group names the group a module's routes sit under (server modules get their own, 1.17.11).
import importlib.util

_spec = importlib.util.spec_from_file_location("openapi_group_17_11", ROOT / "framwork" / "tec_tac" / "openapi.py")
_openapi = importlib.util.module_from_spec(_spec)
sys.modules["openapi_group_17_11"] = _openapi
_spec.loader.exec_module(_openapi)


def _plugin(category):
    return types.SimpleNamespace(plugin_id="demo", name="Demo", category=category)


must(_openapi._module_group(_plugin("server")) == "Server module · Demo", "server category group")
must(_openapi._module_group(_plugin("core")) == "Core module · Demo", "core category group")
must(_openapi._module_group(_plugin("premium")) == "Module · Demo", "premium category group")
must(_openapi._module_group(_plugin("")) == "Module · Demo", "no category group")

print("[TEST] PASS module replacement server modules 1.17.11")
