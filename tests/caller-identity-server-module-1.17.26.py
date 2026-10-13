#!/usr/bin/env python3
"""1.17.26 regression (AD-30): core.caller_identity.calling_module verifies an enabled ``category: server`` module (User Invite first).

The identity keys on the enabled extension's folder, never on the manifest category. A temporary extensions folder holds a provider
(globalsettings) and a server-category caller (userinvite), a core-category and a premium-category caller. The server module that calls the
provider directly is identified with its own id and version. A disabled server module gives None and does not fall through. The identity
code never reads a ``category`` field.
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


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


TMP = Path(tempfile.mkdtemp(prefix="tectac-server-caller-"))
EXT = TMP / "extensions"
EXT.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}


def plugin(plugin_id, category, version, enabled=True):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version=version, legacy=False, category=category)
    ENABLED[plugin_id] = enabled
    return root


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=lambda: tuple(PLUGINS.values()))
pkg.module_state = mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: ENABLED.get(module_id, True))
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kw: SimpleNamespace(**kw))
ci = importlib.import_module("tec_tac.caller_identity")

PROVIDER_SRC = "def whoami(ci):\n    return ci.calling_module(provider_module_id='globalsettings')\n"
CALLER_SRC = "def call(fn, ci):\n    return fn(ci)\n"


def run_file(path, source):
    path.write_text(source, encoding="utf-8")
    ns = {"__name__": "mod_" + path.parent.name}
    exec(compile(source, str(path), "exec"), ns)  # noqa: S102 - test-only: real path inside the module folder
    return ns


plugin("globalsettings", "core", "0.4.4")
plugin("userinvite", "server", "0.1.0")
plugin("agents", "core", "0.3.0")
plugin("haloconnect", "premium", "0.2.0")
plugin("oldserver", "server", "0.0.9", enabled=False)
provider = run_file(EXT / "globalsettings" / "service.py", PROVIDER_SRC)
who = provider["whoami"]
callers = {pid: run_file(EXT / pid / "caller.py", CALLER_SRC) for pid in ("userinvite", "agents", "haloconnect", "oldserver")}

# an enabled server module is verified, with its own id and version, kind module
got = callers["userinvite"]["call"](who, ci)
must(got == ci.CallerIdentity("userinvite", "module", "0.1.0"), got)
# the category makes no difference: core and premium callers are identified the same way
must(callers["agents"]["call"](who, ci).module_id == "agents", "core module")
must(callers["haloconnect"]["call"](who, ci).module_id == "haloconnect", "premium module")
# a disabled server module is refused and does not fall through
must(callers["oldserver"]["call"](who, ci) is None, "disabled server module")
# the same server module, once disabled, is refused: the state is read on every call
ENABLED["userinvite"] = False
must(callers["userinvite"]["call"](who, ci) is None, "disabled now")
ENABLED["userinvite"] = True
must(callers["userinvite"]["call"](who, ci).module_id == "userinvite", "enabled again")
# the identity code never reads a category
source = (APP / "caller_identity.py").read_text(encoding="utf-8")
code_lines = [line for line in source.splitlines() if not line.lstrip().startswith(("#", '"', "*", "1.", "2.", "3.", "4."))]
must(".category" not in "\n".join(code_lines) and '"category"' not in "\n".join(code_lines), "calling_module keys on the enabled folder, not the category")
# the docs state it
docs = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("category: \"server\"" in docs and "User Invite" in docs and "AD-30" in docs, "docs/caller-identity.md names server modules")

print("[TEST] PASS caller identity server module 1.17.26")
