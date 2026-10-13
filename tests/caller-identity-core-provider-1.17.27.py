#!/usr/bin/env python3
"""1.17.27 regression (AD-26, CQ87): the Core-internal caller helper for a Core provider (tec_tac.accounts).

The real tec_tac/caller_identity.py runs against a temporary extensions folder (same style as tests/caller-identity-server-module-1.17.26.py).
The provider is the real path of tec_tac/accounts.py: a function compiled under that file name stands in for create_user, because the real
accounts.py needs Django. The stand-in calls ``calling_module_for_core_provider`` directly, as accounts.py does, so every stack rule is
exercised with the real helper. Covered: an enabled userinvite frame is identified with its id and version, directly or through the
provider's own helper frames (any depth); a disabled userinvite, a legacy one and a different enabled module are identified or refused
exactly as the stack says (the allow-list that refuses alerts is in accounts.py, tests/accounts-contract-1.17.27.py); a Core frame (a
Scheduler-style handler), a functools.partial run by Core, a library frame between the module and the provider, a generated '<string>'
frame, the test file itself (outside every module), an empty or non-text provider file, and a registry or state error all give None; the
enabled state is read on every call; the helper is not a contract row and ``calling_module`` keeps its one operation.
"""
from __future__ import annotations

import functools
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
ACCOUNTS_FILE = str(APP / "accounts.py")
SCHEDULER_FILE = str(APP / "scheduler.py")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-core-provider-caller-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}
STATE = {"registry_error": False, "state_error": False}


def plugin(plugin_id, category, version, *, enabled=True, legacy=False, plugin_type="extension"):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type=plugin_type, root=root, version=version, legacy=legacy, category=category)
    ENABLED[plugin_id] = enabled
    return root


def discover_plugins():
    if STATE["registry_error"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def is_enabled(module_id, state=None):
    if STATE["state_error"]:
        raise RuntimeError("state unreadable")
    return ENABLED.get(module_id, True)


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=discover_plugins)
pkg.module_state = mod("tec_tac.module_state", is_enabled=is_enabled)
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kw: SimpleNamespace(**kw))
ci = importlib.import_module("tec_tac.caller_identity")

plugin("userinvite", "server", "0.9.0")
plugin("alerts", "premium", "1.0.0")
plugin("oldinvite", "server", "0.8.0", legacy=True)
plugin("userinvite-shadow", "server", "0.1.0", plugin_type="legacy")  # a non-extension plugin is never a caller
plugin("noversion", "server", None)


def compile_as(filename, source):
    """Code whose frames carry ``filename`` as their code file (the frame's real file is not read)."""
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


# The provider stand-in: a function in accounts.py's file name that asks Core who is calling, as accounts.py does.
PROVIDER = compile_as(ACCOUNTS_FILE, f"""
def create_user(ci):
    return ci.calling_module_for_core_provider(provider_file={ACCOUNTS_FILE!r})

def helper(ci):
    return create_user(ci)  # a second frame of the provider's own file

def helper_deep(ci):
    return helper(ci)
""")

CALL = "def call(fn, ci):\n    return fn(ci)\n"
RELAY = "def relay(fn, ci):\n    return fn(ci)\n"
userinvite = compile_as(str(EXT / "userinvite" / "service.py"), CALL)
alerts = compile_as(str(EXT / "alerts" / "service.py"), CALL)
oldinvite = compile_as(str(EXT / "oldinvite" / "service.py"), CALL)
shadow = compile_as(str(EXT / "userinvite-shadow" / "service.py"), CALL)
noversion = compile_as(str(EXT / "noversion" / "service.py"), CALL)
core_handler = compile_as(SCHEDULER_FILE, "def run(fn, ci):\n    return fn(ci)\n")  # a Core-owned file name (tec_tac/scheduler.py)
lib = compile_as(str(LIB / "decorator.py"), "def wrap(fn, ci):\n    return fn(ci)\n")  # a library outside every module
generated = compile_as("<string>", CALL)


def who(fn):
    return fn(PROVIDER["create_user"], ci)


# 1. an enabled userinvite frame calling the provider directly is identified with its id and version
got = userinvite["call"](PROVIDER["create_user"], ci)
must(got == ci.CallerIdentity("userinvite", "module", "0.9.0"), got)
# 2. through the provider's own helper frames, at any depth, the module is still the caller
must(userinvite["call"](PROVIDER["helper"], ci).module_id == "userinvite", "one helper frame of the provider")
must(userinvite["call"](PROVIDER["helper_deep"], ci).module_id == "userinvite", "two helper frames of the provider")
# 3. a module that is not the allow-listed one is identified as itself (accounts.py refuses it: caller_not_allowed)
must(alerts["call"](PROVIDER["create_user"], ci) == ci.CallerIdentity("alerts", "module", "1.0.0"), "alerts is identified as alerts")
# 4. a disabled userinvite gives None; enabled again gives the identity (the state is read on every call)
ENABLED["userinvite"] = False
must(userinvite["call"](PROVIDER["create_user"], ci) is None, "disabled userinvite refused")
ENABLED["userinvite"] = True
must(userinvite["call"](PROVIDER["create_user"], ci).module_id == "userinvite", "enabled again")
# 5. a legacy module, and a plugin that is not an extension, give None
must(oldinvite["call"](PROVIDER["create_user"], ci) is None, "legacy module refused")
must(shadow["call"](PROVIDER["create_user"], ci) is None, "a non-extension plugin refused")
# 6. a module with no version reads as 0.0.0
must(noversion["call"](PROVIDER["create_user"], ci) == ci.CallerIdentity("noversion", "module", "0.0.0"), "no version")
# 7. a Core frame (a Scheduler-style handler inside tec_tac) gives None: Core is never a caller
must(core_handler["run"](PROVIDER["create_user"], ci) is None, "a Core frame is never a caller")
# 8. a functools.partial that Core runs gives None; the same partial run from the module's own frame is the module
must(core_handler["run"](functools.partial(PROVIDER["create_user"]), ci) is None, "partial run by Core")
must(userinvite["call"](functools.partial(PROVIDER["create_user"]), ci).module_id == "userinvite", "partial run by the module")
# 9. a library frame between the module and the provider gives None (no gap is skipped)
must(lib["wrap"](PROVIDER["create_user"], ci) is None, "a library frame refused")
# 10. a generated frame ('<string>') gives None
must(generated["call"](PROVIDER["create_user"], ci) is None, "a generated frame refused")
# 11. this test file, outside every module, gives None
must(who(lambda fn, c: fn(c)) is None, "the test file is not a module")
# 12. an empty, missing or non-text provider file gives None; nothing above it is trusted
for bad in ("", "   ", None, 7):
    must(ci._core_provider_caller(sys._getframe(0), bad) is None, f"bad provider file {bad!r}")
must(ci.calling_module_for_core_provider(provider_file="") is None, "empty provider file")
# 13. a registry or state error fails closed
STATE["registry_error"] = True
must(userinvite["call"](PROVIDER["create_user"], ci) is None, "registry error refused")
STATE["registry_error"] = False
STATE["state_error"] = True
must(userinvite["call"](PROVIDER["create_user"], ci) is None, "state error refused")
STATE["state_error"] = False
must(userinvite["call"](PROVIDER["create_user"], ci).module_id == "userinvite", "healthy again")
# 14. the helper is not a contract: calling_module keeps its one operation and its own rule; no contract row names the helper
must(ci.caller_identity_contract_metadata()["operations"] == ["calling_module"], "calling_module keeps its operations")
contracts_src = (APP / "contracts.py").read_text(encoding="utf-8")
must("calling_module_for_core_provider" not in contracts_src, "the helper is not a contract row")
docs = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("calling_module_for_core_provider" in docs and "1.17.27" in docs and "AD-26 condition 2" in docs, "docs name the Core provider rule")

print("[TEST] PASS caller identity core provider 1.17.27")
