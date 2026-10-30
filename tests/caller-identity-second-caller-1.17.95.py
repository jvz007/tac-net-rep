#!/usr/bin/env python3
"""1.17.95 regression (AD-54 eighth amendment): the Core-private second-caller walk of tec_tac.caller_identity, and capabilities.provider_audit_callers.

The real caller_identity.py runs against a temporary extensions folder, in the style of tests/caller-identity-core-provider-1.17.27.py. The Core
provider is the real path of tec_tac/audit.py (a function compiled under that file name stands in for the audit writer). The provider module
(endpoint-comms) has frames at several depths (auditing.py, channel.py), and the caller (wapm) calls it. Covered: provider frames at any depth are
skipped and the calling module is found; a Core, library or generated frame between the provider and the caller gives None; a disabled, legacy or
non-extension caller gives None; a disabled, legacy or missing provider gives None; the first frame not in the provider module's own folder is
the caller, so the provider itself called directly gives None when nothing sits above it; a frame outside the through-module straight after Core's
provider gives None; a registry or state error gives None; the enabled state is read on every call; a bad argument gives None; the helper is
not a contract row. Also provider_audit_callers on the real capabilities module: the opt-in flag, the union over capabilities, other modules'
registrations ignored, a malformed list ignored, never raises.
"""
from __future__ import annotations

import importlib
import logging
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
AUDIT_FILE = str(APP / "audit.py")
SCHEDULER_FILE = str(APP / "scheduler.py")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-second-caller-"))
EXT, LIB = TMP / "extensions", TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}
STATE = {"registry_error": False, "state_error": False}
SCANS = [0]


def plugin(plugin_id, version="1.0.0", *, enabled=True, legacy=False, plugin_type="extension"):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type=plugin_type, root=root, version=version, legacy=legacy, category="premium")
    ENABLED[plugin_id] = enabled


def discover_plugins():
    SCANS[0] += 1
    if STATE["registry_error"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def is_enabled(module_id, state=None):
    if STATE["state_error"]:
        raise RuntimeError("state unreadable")
    return ENABLED.get(module_id, True)


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=discover_plugins, RegistryError=RuntimeError, get_plugin=lambda *a, **k: None)
pkg.module_state = mod("tec_tac.module_state", is_enabled=is_enabled, load_state=dict, ModuleStateError=RuntimeError, version_satisfies=lambda *a, **k: True)
ci = importlib.import_module("tec_tac.caller_identity")

for pid in ("endpoint-comms", "wapm", "other"):
    plugin(pid)
plugin("legacywapm", legacy=True)
plugin("shadow", plugin_type="legacy")


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


# Core's provider: audit.py asks who called the through-module that called it.
CORE = compile_as(AUDIT_FILE, f"""
def writer(ci, through="endpoint-comms"):
    return ci.core_provider_second_caller(provider_file={AUDIT_FILE!r}, through_module_id=through)

def writer_inner(ci, through="endpoint-comms"):
    return writer(ci, through)  # a second Core frame
""")
GO = "def go(fn, *args):\n    return fn(*args)\n"  # every stand-in frame only forwards, so each frame's code file is exactly the file it stands for
EC_FOLDER = EXT / "endpoint-comms"
EC = [compile_as(str(EC_FOLDER / name), GO)["go"] for name in ("patching.py", "channel.py", "auditing.py")]
wapm = compile_as(str(EXT / "wapm" / "service.py"), GO)["go"]
other = compile_as(str(EXT / "other" / "service.py"), GO)["go"]
legacywapm = compile_as(str(EXT / "legacywapm" / "service.py"), GO)["go"]
shadow = compile_as(str(EXT / "shadow" / "service.py"), GO)["go"]
core_handler = compile_as(SCHEDULER_FILE, GO)["go"]
lib = compile_as(str(LIB / "decorator.py"), GO)["go"]
generated = compile_as("<string>", GO)["go"]


def chain(caller, through="endpoint-comms", writer="writer", middle=None):
    """caller -> the module's frames (patching, channel, auditing) -> Core's writer."""
    frames = EC if middle is None else middle
    return caller(*frames, CORE[writer], ci, through)


def direct(caller, through="endpoint-comms"):
    return caller(CORE["writer"], ci, through)


# 1. wapm -> endpoint-comms (patching, channel, auditing) -> Core: the caller is wapm, whatever the depth
got = chain(wapm)
must(got == ci.CallerIdentity("wapm", "module", "1.0.0"), got)
must(chain(wapm, middle=EC[:1]).module_id == "wapm", "one provider-module frame")
must(chain(wapm, middle=[]) is None, "no provider-module frame at all")
must(chain(wapm, writer="writer_inner").module_id == "wapm", "two Core frames")
must(chain(other).module_id == "other", "another enabled module is identified as itself (the audit helper checks the list)")

# 2. a Core, library or generated frame in the caller position gives None; the walk never looks further up
must(chain(core_handler) is None, "a Core frame is never the caller")
must(chain(lib) is None, "a library frame")
must(chain(generated) is None, "a generated frame")
# a wapm frame above a Core frame is not found either
must(wapm(core_handler, *EC, CORE["writer"], ci, "endpoint-comms") is None, "a module above a Core frame is not skipped to")

# 3. a disabled, legacy or non-extension caller gives None; enabled again gives the identity (state read on every call)
ENABLED["wapm"] = False
must(chain(wapm) is None, "disabled caller")
ENABLED["wapm"] = True
must(chain(wapm).module_id == "wapm", "enabled again")
must(chain(legacywapm) is None and chain(shadow) is None, "legacy and non-extension callers")

# 4. the through module: disabled, legacy, missing or not the module in the frames
ENABLED["endpoint-comms"] = False
must(chain(wapm) is None, "disabled provider module")
ENABLED["endpoint-comms"] = True
PLUGINS["endpoint-comms"].legacy = True
must(chain(wapm) is None, "legacy provider module")
PLUGINS["endpoint-comms"].legacy = False
must(chain(wapm, through="not-installed") is None, "missing provider module")
must(chain(wapm, through="other") is None, "the first frame after Core is not in the named module's folder")
must(chain(wapm).module_id == "wapm", "restored")

# 5. nothing sits above the provider module's frames, or a frame of Core sits straight after Core's writer
must(CORE["writer"](ci) is None, "called directly: the test file is outside every module, and it is not the through module")
must(direct(core_handler) is None, "Core frame straight after Core's writer")
must(direct(wapm) is None, "wapm calls Core directly: it did not go through endpoint-comms")

# 6. errors give None and never raise
STATE["registry_error"] = True
must(chain(wapm) is None, "registry error")
STATE["registry_error"] = False
STATE["state_error"] = True
must(chain(wapm) is None, "state error")
STATE["state_error"] = False
for bad in (None, "", "  ", 5):
    must(direct(wapm, bad) is None, f"bad through_module_id {bad!r}")
must(ci.core_provider_second_caller(provider_file="", through_module_id="endpoint-comms") is None, "empty provider file")
must(ci.core_provider_second_caller(provider_file=(), through_module_id="endpoint-comms") is None, "empty provider tuple")
must(chain(wapm).module_id == "wapm", "the helper recovers")

# 7. nothing is cached: a module installed a moment ago is seen, and every call scans
SCANS[0] = 0
chain(wapm)
chain(wapm)
must(SCANS[0] >= 2, SCANS)
plugin("latecomer")
late = compile_as(str(EXT / "latecomer" / "service.py"), GO)["go"]
must(chain(late).module_id == "latecomer", "a module installed a moment ago is seen")

# 8. the existing helpers are unchanged and the new one is no contract
core_rows = (APP / "contracts.py").read_text(encoding="utf-8")
must("core_provider_second_caller" not in core_rows, "not a contract row")
PROV = compile_as(AUDIT_FILE, f"def f(ci):\n    return ci.calling_module_for_core_provider(provider_file={AUDIT_FILE!r})\n")
must(wapm(PROV["f"], ci) == ci.CallerIdentity("wapm", "module", "1.0.0"), "calling_module_for_core_provider unchanged")

# ---- capabilities.provider_audit_callers, on the real module
capabilities = importlib.import_module("tec_tac.capabilities")
capabilities._clear_capabilities_for_tests()
reg = capabilities.CapabilityRegistration


def put(cap_id, module_id, metadata):
    capabilities._CAPABILITIES[cap_id] = reg(id=cap_id, module_id=module_id, version="1.0.0", provider=object(), metadata=metadata)


put("endpoint-comms.patching", "endpoint-comms", {"allowed_callers": ["wapm"], "audit_person_for_allowed_callers": True})
put("endpoint-comms.status", "endpoint-comms", {"allowed_callers": ["groups", " ", 5], "audit_person_for_allowed_callers": True})
put("endpoint-comms.noflag", "endpoint-comms", {"allowed_callers": ["secret"]})
put("endpoint-comms.stringflag", "endpoint-comms", {"allowed_callers": ["secret2"], "audit_person_for_allowed_callers": "true"})
put("endpoint-comms.badlist", "endpoint-comms", {"allowed_callers": "wapm", "audit_person_for_allowed_callers": True})
put("patchmanagement.x", "patchmanagement", {"allowed_callers": ["maintenance"]})
put("other.y", "other", {"allowed_callers": ["evil"], "audit_person_for_allowed_callers": True})
must(capabilities.provider_audit_callers("endpoint-comms") == frozenset({"wapm", "groups"}), capabilities.provider_audit_callers("endpoint-comms"))
must(capabilities.provider_audit_callers("patchmanagement") == frozenset(), "allowed_callers alone is not counted")
must(capabilities.provider_audit_callers("other") == frozenset({"evil"}), "each provider's own registrations only")
must(capabilities.provider_audit_callers("") == frozenset() and capabilities.provider_audit_callers(None) == frozenset(), "empty id")
must(capabilities.provider_audit_callers("nobody") == frozenset(), "unknown provider")
capabilities._CAPABILITIES["broken"] = object()  # a corrupt entry never raises
must(capabilities.provider_audit_callers("endpoint-comms") == frozenset(), "a fault gives an empty set (fail closed)")
capabilities._clear_capabilities_for_tests()
print("[TEST] PASS caller identity second caller 1.17.95")
