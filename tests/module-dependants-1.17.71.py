#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.71 regression (Johan, 21 October 2026: Groups must not delete a group that is in use): PluginSpec dependency fields, tec_tac.module_dependants and the
capability core.module_dependants 1.0.0.

The REAL registry.py (manifests read from a temporary folder) and the REAL module_dependants.py and caller_identity.py on the stub harness of
scheduler-completion-harness-1.17.61.py, with module code compiled under each module's folder so the real frame walk names the caller. No Django.

Covered. (A) PluginSpec has both fields with () defaults and an old-style construction still works; _load_manifest reads both keys as sorted pairs and gives ()
for a missing key, a list instead of an object and a blank id, without raising; equality ignores the fields. (B) dependants() lists a required and an optional
dependant with the right relation and constraint, marks a disabled one enabled False, lists the capabilities its manifest declares, excludes the caller,
legacy modules and reportsets, sorts by id and caps at 200 (complete False); a row has exactly the documented keys; an unverified caller, Core, a disabled or a
legacy module is refused with DependantsRefused and the text names no module; the function answers only for the caller's own id; a registry or module-state
read that fails gives DependantsUnavailable and never an empty list. (C) The capability registers once with the operation dependants; apps.py registers it in
its own try block; the contract row exists with the documented text; the docs exist.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import logging
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input
logging.disable(logging.CRITICAL)

# ---- (A) the registry fields, on the real registry.py
rspec = importlib.util.spec_from_file_location("reg_deps_under_test", APP / "registry.py")
reg = importlib.util.module_from_spec(rspec)
sys.modules[rspec.name] = reg
rspec.loader.exec_module(reg)
MANIFESTS = Path(tempfile.mkdtemp(prefix="tectac-deps-"))
COUNT = [0]


def manifest(extra, plugin_id="groups"):
    COUNT[0] += 1
    folder = MANIFESTS / f"run{COUNT[0]}" / "extensions" / plugin_id
    folder.mkdir(parents=True)
    body = {"id": plugin_id, "type": "extension", "version": "1.0.0", "python_paths": ["."], "django_apps": [], "category": "premium"}
    body.update(extra)
    (folder / "tec_tac.json").write_text(json.dumps(body), encoding="utf-8")
    return reg._load_manifest("extension", folder)


old_style = reg.PluginSpec(plugin_id="a", plugin_type="extension", root=Path("."))
must(old_style.dependencies == () and old_style.optional_dependencies == (), "defaults are empty tuples")
must(reg.PluginSpec(plugin_id="a", plugin_type="extension", root=Path(".")) == old_style and "dependencies" not in repr(old_style), "equality and repr ignore the fields")
plain = manifest({})
must(plain.dependencies == () and plain.optional_dependencies == (), "a manifest without the keys gives ()")
both = manifest({"dependencies": {"zeta": ">=1.0.0", "groups": "*", "alpha": ""}, "optional_dependencies": {"beta": ">=0.2.0,<1.0.0"}}, plugin_id="patchmanagement")
must(both.dependencies == (("alpha", "*"), ("groups", "*"), ("zeta", ">=1.0.0")), both.dependencies)
must(both.optional_dependencies == (("beta", ">=0.2.0,<1.0.0"),), both.optional_dependencies)
must(manifest({"dependencies": ["groups"]}).dependencies == (), "a list instead of an object gives ()")
must(manifest({"dependencies": {" ": "*"}}).dependencies == (), "a blank id gives ()")
must(manifest({"dependencies": {"groups": "*"}, "optional_dependencies": "nope"}).optional_dependencies == (), "one bad key does not touch the other")
must(manifest({"dependencies": {"groups": "*"}, "optional_dependencies": "nope"}).dependencies == (("groups", "*"),), "the good key is kept")
must(manifest({"dependencies": {"groups": 5}}).dependencies == (("groups", "*"),), "a non-text constraint reads as any version")
must(reg._dependency_pairs({"dependencies": None}, "dependencies") == () and reg._dependency_pairs({}, "dependencies") == (), "None and missing give ()")
print("       PluginSpec carries sorted dependency pairs, empty when absent or malformed, and never raises")

# ---- (B) dependants()
md = load("tec_tac.module_dependants", "module_dependants.py")
def reset_world():
    PLUGINS.clear()
    ENABLED.clear()
    STATE_FAULT["registry"] = False


def add(plugin_id, *, deps=None, optional=None, enabled=True, legacy=False, caps=(), kind="extension", name=None, version="2.0.0"):
    root = plugin(plugin_id, enabled=enabled, legacy=legacy, category="premium")
    spec = PLUGINS[plugin_id]
    spec.plugin_type = kind
    spec.name = name or plugin_id.title()
    spec.version = version
    spec.dependencies = tuple(sorted((deps or {}).items()))
    spec.optional_dependencies = tuple(sorted((optional or {}).items()))
    spec.capabilities = tuple(caps)
    return root


def asker(module_id, *, filename=None):
    """A function compiled under that module's folder (or ``filename``) that calls the real dependants()."""
    path = filename or (EXT / module_id / "ask.py")
    return compile_as(path, "def ask():\n    return md.dependants()\ndef ask_with_context():\n    return md.dependants(context={'module': 'other'})\n", md=md)


def refused(fn):
    try:
        fn()
    except md.DependantsRefused as exc:
        return str(exc)
    raise AssertionError("accepted")


reset_world()
add("groups")
add("patchmanagement", deps={"groups": ">=0.4.0"}, caps=(("patchmanagement.groups_usage", "1.0.0"), ("patchmanagement.alpha", "2.1.0")), name="Advanced Patch Management", version="0.13.0")
add("reportmanager", optional={"groups": "*"}, name="Report Manager", version="1.1.0")
add("serverhealth", deps={"groups": "*"}, enabled=False, name="Server Health", version="0.9.0")
add("unrelated", deps={"somethingelse": "*"})
add("oldmod", deps={"groups": "*"}, legacy=True)
add("sets", deps={"groups": "*"}, kind="reportset")
add("other", deps={"reportmanager": "*"})
out = asker("groups")["ask"]()
must(out["module"] == "groups" and out["complete"] is True and set(out) == {"module", "dependants", "complete"}, out)
ids = [r["id"] for r in out["dependants"]]
must(ids == ["patchmanagement", "reportmanager", "serverhealth"], ids)
by = {r["id"]: r for r in out["dependants"]}
must(all(set(r) == set(md.ROW_KEYS) for r in out["dependants"]), "a row has exactly the documented keys")
must(by["patchmanagement"] == {"id": "patchmanagement", "name": "Advanced Patch Management", "version": "0.13.0", "relation": "required", "constraint": ">=0.4.0", "enabled": True,
                               "capabilities": [{"id": "patchmanagement.alpha", "version": "2.1.0"}, {"id": "patchmanagement.groups_usage", "version": "1.0.0"}]}, by["patchmanagement"])
must(by["reportmanager"]["relation"] == "optional" and by["reportmanager"]["constraint"] == "*" and by["reportmanager"]["capabilities"] == [], by["reportmanager"])
must(by["serverhealth"]["enabled"] is False and by["serverhealth"]["relation"] == "required", "a disabled dependant is listed with enabled False")
must("groups" not in ids and "oldmod" not in ids and "sets" not in ids and "unrelated" not in ids and "other" not in ids, "the caller, a legacy module, a reportset and non-dependants are left out")
print("       dependants lists required and optional dependants with constraint, enabled flag and declared capabilities, and leaves out the rest")

# the answer is only about the caller's own id
mine = asker("other")["ask"]()
must(mine["module"] == "other" and mine["dependants"] == [], mine)
rm = asker("reportmanager")["ask_with_context"]()
must(rm["module"] == "reportmanager" and [r["id"] for r in rm["dependants"]] == ["other"], rm)
must(list(inspect.signature(md.dependants).parameters) == ["context"], "no parameter can name another module")
must(asker("groups")["ask_with_context"]()["module"] == "groups", "a context naming another module changes nothing")
print("       the answer is about the calling module only, whatever the caller passes")

# both relations: required wins
add("both", deps={"groups": ">=1.0.0"}, optional={"groups": "*"})
must({r["id"]: r for r in asker("groups")["ask"]()["dependants"]}["both"]["relation"] == "required", "required wins")
del PLUGINS["both"]

# refused callers; the text names no module
texts = []
texts.append(refused(md.dependants))  # this test file is not a module: an unverified caller
texts.append(refused(asker("x", filename=APP / "scheduler.py")["ask"]))  # Core code
ENABLED["groups"] = False
texts.append(refused(asker("groups")["ask"]))  # a disabled module
ENABLED["groups"] = True
PLUGINS["groups"].legacy = True
texts.append(refused(asker("groups")["ask"]))  # a legacy module
PLUGINS["groups"].legacy = False
must(len(set(texts)) == 1 and not any(m in texts[0] for m in PLUGINS) and "groups" not in texts[0].lower(), texts)
must(asker("groups")["ask"]()["module"] == "groups", "the module works again once it is enabled and not legacy")
print("       an unverified caller, Core, a disabled module and a legacy module are refused with a text that names no module")

# fail closed
STATE_FAULT["registry"] = True
for fn in (asker("groups")["ask"],):
    try:
        fn()
    except md.DependantsUnavailable as exc:
        must(not any(m in str(exc) for m in PLUGINS), "the text names no module")
    else:
        raise AssertionError("an unreadable module list answered")
STATE_FAULT["registry"] = False
calls = {"n": 0}
real_discover = sys.modules["tec_tac.registry"].discover_plugins


def flaky_discover():
    calls["n"] += 1
    if calls["n"] >= 2:  # the caller check reads once; the listing then fails
        raise RuntimeError("registry unreadable")
    return real_discover()


sys.modules["tec_tac.registry"].discover_plugins = flaky_discover
try:
    asker("groups")["ask"]()
    raise AssertionError("an unreadable registry answered")
except md.DependantsUnavailable:
    pass
finally:
    sys.modules["tec_tac.registry"].discover_plugins = real_discover
real_state = sys.modules["tec_tac.module_state"].load_state
sys.modules["tec_tac.module_state"].load_state = lambda: (_ for _ in ()).throw(RuntimeError("state unreadable"))
try:
    asker("groups")["ask"]()
    raise AssertionError("an unreadable module state answered")
except md.DependantsUnavailable:
    pass
finally:
    sys.modules["tec_tac.module_state"].load_state = real_state
sys.modules["tec_tac.module_state"].load_state = lambda: {"schema": 1, "modules": {}, "_corrupt": True}
try:
    asker("groups")["ask"]()
    raise AssertionError("a corrupt module state answered")
except md.DependantsUnavailable:
    pass
finally:
    sys.modules["tec_tac.module_state"].load_state = real_state
print("       an unreadable module list or module state raises DependantsUnavailable and never answers an empty list")

# sorted and capped
reset_world()
add("groups")
for i in range(205):
    add(f"dep{i:03d}", deps={"groups": "*"})
big = asker("groups")["ask"]()
must(len(big["dependants"]) == 200 and big["complete"] is False, (len(big["dependants"]), big["complete"]))
must([r["id"] for r in big["dependants"]] == sorted(f"dep{i:03d}" for i in range(200)), "sorted by id, the first 200")
reset_world()
add("groups")
for i in (5, 3, 9, 1):
    add(f"m{i}", deps={"groups": "*"})
must([r["id"] for r in asker("groups")["ask"]()["dependants"]] == ["m1", "m3", "m5", "m9"], "sorted by id")
print("       rows are sorted by id and capped at 200 with complete False")

# ---- (C) the capability, the row, apps.py, the docs
registered = []
mod("tec_tac.capabilities", register_capability=lambda **kw: registered.append(kw) or kw)
md.register_core_module_dependants_capability()
md.register_core_module_dependants_capability()
must(len(registered) == 2 and all(r["id"] == "core.module_dependants" and r["version"] == "1.0.0" and r["module_id"] == "core" and tuple(r["operations"]) == ("dependants",) for r in registered), registered)
meta = registered[0]["metadata"]
must(meta == md.module_dependants_contract_metadata() and meta["requires_framework"] == ">=1.17.71" and meta["calls_provider_for_module"] is False and meta["returns"] == list(md.ROW_KEYS), meta)
json.dumps(meta)
must(callable(getattr(registered[0]["provider"], "dependants", None)), "the provider has the operation")

apps = (APP / "apps.py").read_text(encoding="utf-8")
must("from .module_dependants import register_core_module_dependants_capability" in apps, "ready() registers it")
before = apps.index("from .module_dependants import")
block = apps[apps.rindex("try:", 0, before):apps.index("except Exception:", before)]
must("patch_lockdown" not in block and "install_tactical_reporting_bridge" not in block, "in its own try block")

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CORE_CONTRACTS")
row = [r for r in rows if (r["import_path"], r["name"]) == ("tec_tac.module_dependants", "dependants")]
must(len(row) == 1 and row[0]["area"] == "module-dependants" and row[0]["audience"] == "consumer/backend" and row[0]["kind"] == "python", row)
for needle in ("core.module_dependants 1.0.0", "1.17.71", "relation", "constraint", "enabled", "capabilities", "DependantsRefused", "DependantsUnavailable", "complete", "own id only",
               "Groups declares core.module_dependants", "Core calls no provider", "PluginSpec.dependencies", "docs/module-dependants.md"):
    must(needle in row[0]["purpose"], f"the row lacks {needle!r}")
doc = (ROOT / "docs" / "module-dependants.md").read_text(encoding="utf-8")
for needle in ("dependants(", "core.module_dependants", "DependantsRefused", "DependantsUnavailable", "groups_usage", "PluginSpec"):
    must(needle in doc, f"the doc lacks {needle!r}")
must("core.module_dependants" in (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8"), "capabilities.md names it")
print("       the capability registers once with the operation dependants, ready() registers it in its own try block, the row and the doc exist")

print("PASS module dependants 1.17.71")
