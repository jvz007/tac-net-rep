#!/usr/bin/env python3
"""1.17.9 regression: an honoured replacement takes over the replaced core module's capability names (AD-20 condition 3).

Runs the real registry.py, module_state.py, module_replacement.py and capabilities.py against a temporary folder of
real manifests (fcntl stubbed, module state a dict). Django is not needed.
"""
from __future__ import annotations

import ast
import json
import logging
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


fcntl = types.ModuleType("fcntl")
fcntl.__dict__.update(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
sys.modules.setdefault("fcntl", fcntl)

from tec_tac import capabilities as caps, module_state, registry  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="tectac-replacement-caps-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension", "version": "1.0.0"}
    payload.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


PATCHING = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
manifest("patching", category="core", capabilities=PATCHING)
manifest("patchmanagement", replaces="patching", capabilities={**PATCHING, "patching.extra": "1.0.0"})
manifest("stranger")
manifest("maintenance", category="core", capabilities={})


def state(patching, patchmanagement):
    STATE["modules"] = {"patching": {"enabled": patching}, "patchmanagement": {"enabled": patchmanagement}, "stranger": {"enabled": True}, "maintenance": {"enabled": True}}


def register(cap, module):
    return caps.register_capability(id=cap, module_id=module, version="1.2.0", provider=object())


def prefix_error(cap, module):
    try:
        register(cap, module)
    except ValueError as exc:
        must("must begin with provider module prefix" in str(exc), exc)
        return
    raise AssertionError(f"{module} registered {cap}")


caps._clear_capabilities_for_tests()
state(patching=False, patchmanagement=True)
# the honoured replacement registers the declared names, and only those
reg = register("patching.windows", "patchmanagement")
must(reg.module_id == "patchmanagement", reg)
register("patching.extra", "patchmanagement")  # declared by the replacement, under the replaced prefix
register("patchmanagement.own", "patchmanagement")  # its own prefix is never affected
prefix_error("patching.undeclared", "patchmanagement")
prefix_error("maintenance.thing", "patchmanagement")  # a prefix that is not the replaced module's
prefix_error("patching.scan", "stranger")  # a module that replaces nothing
prefix_error("patching.scan", "nosuchmodule")
register("stranger.ok", "stranger")
register("core.anything", "core")
register("tec-tac.anything", "tec-tac")
must(caps.register_capability(id="patching.windows", module_id="patchmanagement", version="1.2.0", provider=reg.provider, description="") is reg, "idempotent")

# consumers keep calling the same name and get whichever module is installed
row = caps.capability_status("patching.windows")
must(row["available"] is True and row["module_id"] == "patchmanagement" and row["replaces"] == "patching" and row["state"] == "available", row)
must(caps.get_capability("patching.windows") is reg.provider and caps.has_capability("patching.windows"), "resolves to the replacement")
must(caps.capability_status("stranger.ok")["replaces"] is None and caps.capability_status("patchmanagement.own")["replaces"] is None, "replaces is empty for ordinary capabilities")
must("replaces" in caps.capability_status("core.anything"), "the field is present on every row")
rows = {r["id"]: r for r in caps.list_capabilities()}
must(rows["patching.windows"]["replaces"] == "patching" and rows["stranger.ok"]["replaces"] is None, "list rows carry replaces")

# a name the replacement has not registered says so, and names the replacement
row = caps.capability_status("patching.scan")
must(row["available"] is False and row["state"] == "capability-unavailable" and "patchmanagement" in row["reason"] and "disabled and replaced" in row["reason"], row)
try:
    caps.get_capability("patching.scan")
    raise AssertionError("resolved")
except caps.CapabilityUnavailable as exc:
    must(not isinstance(exc, caps.CapabilityDisabled), "not the bare disabled error")

# the core module is enabled again, or the replacement is disabled, before the worker restarts
state(patching=True, patchmanagement=True)
row = caps.capability_status("patching.windows")
must(row["available"] is False and row["state"] == "capability-unavailable" and "no longer replaces" in row["reason"], row)
try:
    caps.get_capability("patching.windows")
    raise AssertionError("resolved")
except caps.CapabilityUnavailable:
    pass
state(patching=True, patchmanagement=False)
row = caps.capability_status("patching.windows")
must(row["available"] is False and row["state"] == "disabled", row)
# with no replacement and the core module disabled: the plain disabled answer, as before 1.17.9
state(patching=False, patchmanagement=False)
row = caps.capability_status("patching.scan")
must(row["state"] == "disabled" and row["reason"] == "Provider module 'patching' is disabled.", row)
# the replacement is not honoured now, so it may not register the names
caps._clear_capabilities_for_tests()
# 1.17.9-1: a declared name that is simply not honoured is skipped with a warning, never raised out of ready()
for flags in ((True, True), (False, False)):
    state(patching=flags[0], patchmanagement=flags[1])
    skipped_reg = register("patching.windows", "patchmanagement")
    must(skipped_reg.module_id == "patchmanagement" and caps._registration("patching.windows") is None, "not stored")
    must(caps.capability_status("patching.windows")["available"] is False, "still unavailable")
prefix_error("patching.undeclared", "patchmanagement")  # an undeclared name still fails
# the core module registers its own names as always, and an ordinary disabled module is unchanged
state(patching=True, patchmanagement=False)
register("patching.windows", "patching")
must(caps.capability_status("patching.windows")["available"] is True and caps.capability_status("patching.windows")["replaces"] is None, "the core module provides its own")
state(patching=False, patchmanagement=False)
must(caps.capability_status("patching.windows")["state"] == "disabled", "disabled as before")

# every capability the other modules in modules/ register keeps registering: the prefix rule is untouched for them
modules_root = ROOT.parents[1] / "modules"
checked = skipped = 0
if modules_root.is_dir():
    for path in sorted(modules_root.glob("*/package/**/*.py")):
        if "tests" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        consts = {t.id: n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
                  for t in n.targets if isinstance(t, ast.Name)}
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and getattr(call.func, "id", getattr(call.func, "attr", "")) == "register_capability"):
                continue
            values = {}
            for kw in call.keywords:
                if kw.arg in ("id", "module_id"):
                    node = kw.value
                    values[kw.arg] = node.value if isinstance(node, ast.Constant) else consts.get(getattr(node, "id", None))
            cap, owner = values.get("id"), values.get("module_id")
            if not isinstance(cap, str) or not isinstance(owner, str):
                skipped += 1
                continue
            checked += 1
            must(owner == "tec-tac" or cap.startswith(owner + "."), f"{path}: {cap} / {owner} would no longer register by the plain prefix rule")
    print(f"[TEST] modules/ scan: {checked} register_capability calls follow the plain prefix rule, {skipped} not resolvable statically")
else:
    print("[TEST] modules/ scan skipped: no modules folder next to this repository")

print("[TEST] PASS module replacement capabilities 1.17.9")
