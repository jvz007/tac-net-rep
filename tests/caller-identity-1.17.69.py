#!/usr/bin/env python3
"""1.17.69 regression (AD-26, AD-43): a Core provider that spans two Core files (delegation.py and system_actions.py).

The real tec_tac/caller_identity.py on the same stub registry as tests/caller-identity-core-provider-1.17.27.py. ``provider_file`` may now be a
non-empty tuple of file paths: a frame of any of them is skipped and the first other frame is the caller. A plain string behaves exactly as
before; an empty tuple, a list, a tuple holding something that is not a path and an empty path cannot be verified and give None.
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



FILE_A, FILE_B = str(APP / "delegation.py"), str(APP / "system_actions.py")
PROVIDER = compile_as(FILE_B, """
def wrapper(ci, files):
    return inner(ci, files)

def inner_unused():
    pass
""")
PROVIDER.update(compile_as(FILE_A, """
def inner(ci, files):
    return ci.calling_module_for_core_provider(provider_file=files)
"""))
PROVIDER["wrapper"].__globals__["inner"] = PROVIDER["inner"]  # system_actions.py -> delegation.py, as the five wrappers do
CALL = "def call(fn, ci, files):" + chr(10) + "    return fn(ci, files)" + chr(10)
userinvite = compile_as(str(EXT / "userinvite" / "service.py"), CALL)
oldinvite = compile_as(str(EXT / "oldinvite" / "service.py"), CALL)
core_handler = compile_as(str(APP / "scheduler.py"), CALL)
BOTH = (FILE_A, FILE_B)

# 1. a tuple skips frames of both files: module -> system_actions.py -> delegation.py gives the module; module -> delegation.py directly too
must(userinvite["call"](PROVIDER["wrapper"], ci, BOTH).module_id == "userinvite", "wrapper then inner, both skipped")
must(userinvite["call"](PROVIDER["inner"], ci, BOTH).module_id == "userinvite", "inner only, both skipped")
# 2. one file alone stops at the other file's frame, which is Core code: refused (the reason the walker needed the tuple)
must(userinvite["call"](PROVIDER["wrapper"], ci, FILE_A) is None, "a string naming only delegation.py stops at system_actions.py, a Core frame")
must(userinvite["call"](PROVIDER["inner"], ci, FILE_A).module_id == "userinvite", "a string behaves exactly as before")
# 3. a Core caller, a disabled and a legacy module are refused with a tuple too
must(core_handler["call"](PROVIDER["wrapper"], ci, BOTH) is None, "a Core frame is never a caller")
ENABLED["userinvite"] = False
must(userinvite["call"](PROVIDER["wrapper"], ci, BOTH) is None, "disabled")
ENABLED["userinvite"] = True
must(oldinvite["call"](PROVIDER["wrapper"], ci, BOTH) is None, "legacy")
# 4. a tuple that cannot be verified gives None, and the checked form says unverifiable
for bad in ((), ("",), (FILE_A, 7), (FILE_A, None), [FILE_A, FILE_B], {FILE_A, FILE_B}):
    must(userinvite["call"](PROVIDER["inner"], ci, bad) is None, f"bad provider files {bad!r}")
    must(ci._checked_from(sys._getframe(0), bad, 0).unverifiable is True, f"{bad!r} is unverifiable")
must(ci._checked_from(sys._getframe(0), BOTH, 0).unverifiable is False, "a good tuple is a real answer")
# 5. the registry fault still fails closed with a tuple
STATE["registry_error"] = True
must(userinvite["call"](PROVIDER["wrapper"], ci, BOTH) is None, "registry error refused")
STATE["registry_error"] = False
must(userinvite["call"](PROVIDER["wrapper"], ci, BOTH).module_id == "userinvite", "healthy again")
docs = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("1.17.69" in docs and "tuple" in docs, "docs name the tuple form")

print("[TEST] PASS caller identity 1.17.69")
