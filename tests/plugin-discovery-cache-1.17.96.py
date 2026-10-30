#!/usr/bin/env python3
"""1.17.96 regression: plugin discovery is cached per process and fails closed.

dev02 profile (30 October 2026): 122 get_plugins calls read 10 614 manifests in one Django start-up. The registry now keeps the validated
PluginSpec tuple and checks a fingerprint of both roots on every call. This test builds 52 manifests (26 extensions, 26 reportsets) in a
temp tree and checks: (1) one manifest load per manifest for 122 get_plugins and 120 get_plugin calls; (2) results and errors equal the
uncached ones; (3) a changed (also same-size), added or removed manifest, a removed python_paths folder and a removed server-maintenance
executable are seen on the next call; (4) a corrupt manifest raises every call and is never cached, and fixing it recovers; (5) invalidate
forces one reload; (6) explicit roots are never cached; (7) a manifest changed within the racy window is not trusted; (8) threads agree;
(9) Core calls invalidate_plugin_cache where it changes modules. It prints the time of 122 get_plugins calls before (uncached) and after.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEC = ROOT / "framwork" / "tec_tac"
sys.dont_write_bytecode = True


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


spec = importlib.util.spec_from_file_location("tec_tac_registry_cache_test", TEC / "registry.py")
registry = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = registry
spec.loader.exec_module(registry)

tmp = Path(tempfile.mkdtemp())
EXT, REP = tmp / "extensions", tmp / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
COUNT = 26  # 26 extensions + 26 reportsets = 52 manifests
OLD = time.time() - 3600


def write_manifest(folder: Path, payload: dict, mtime: float | None = None):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "tec_tac.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    age(path, mtime)
    return path


def age(path: Path, mtime: float | None = None):
    os.utime(path, (mtime or OLD, mtime or OLD))


def age_tree(root: Path, mtime: float | None = None):
    for current, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            age(Path(current) / name, mtime)
        age(Path(current), mtime)


for index in range(COUNT):
    write_manifest(EXT / f"mod{index}", {"id": f"mod{index}", "version": "1.0.0", "django_apps": [f"app{index}"], "category": "core"})
    write_manifest(REP / f"mod{index}", {"id": f"mod{index}", "type": "reportset", "version": "1.0.0"})
# one module with a nested python path and a server-maintenance executable, to test the extra stats
special = EXT / "special"
(special / "lib" / "py").mkdir(parents=True)
(special / "server_maintenance" / "actions").mkdir(parents=True)
(special / "server_maintenance" / "actions" / "act.sh").write_text("#!/bin/sh\n", encoding="utf-8")
write_manifest(special, {
    "id": "special", "version": "1.0.0", "python_paths": [".", "lib/py"],
    "permission_groups": {"ops": ["special.run"]}, "publisher_permissions": ["server_maintenance.register"],
    "server_maintenance_actions": [{"id": "special.act", "permission": "special.run", "executable": "server_maintenance/actions/act.sh"}],
})
TOTAL_MANIFESTS = COUNT * 2 + 1
age_tree(tmp)

LOADS = [0]
real_load = registry._load_manifest


def counting_load(plugin_type, plugin_dir):
    LOADS[0] += 1
    return real_load(plugin_type, plugin_dir)


registry._load_manifest = counting_load


def uncached_get_plugins():
    return registry._validate_plugins(registry._discover_uncached(EXT, REP))


def uncached_get_plugin(plugin_id, plugin_type=None):
    matches = [p for p in uncached_get_plugins() if p.plugin_id == plugin_id and (plugin_type is None or p.plugin_type == plugin_type)]
    if not matches:
        raise registry.RegistryError(f"Plugin {plugin_id!r}{f' type={plugin_type!r}' if plugin_type else ''} was not found.")
    if len(matches) > 1:
        raise registry.RegistryError(f"Plugin ID {plugin_id!r} matches multiple plugin types; specify a type.")
    return matches[0]


def error_of(fn, *args):
    try:
        fn(*args)
    except registry.RegistryError as exc:
        return str(exc)
    return None


def reset():
    registry.invalidate_plugin_cache()
    LOADS[0] = 0


# (1) one load per manifest ---------------------------------------------------------------------------------------------------------
reset()
first = registry.get_plugins()
must(LOADS[0] == TOTAL_MANIFESTS, LOADS[0])
for _ in range(121):
    registry.get_plugins()
must(LOADS[0] == TOTAL_MANIFESTS, f"122 get_plugins calls loaded {LOADS[0]} manifests, expected {TOTAL_MANIFESTS}")
for index in range(120):
    registry.get_plugin(f"mod{index % COUNT}", "extension")
must(LOADS[0] == TOTAL_MANIFESTS, f"120 get_plugin calls loaded {LOADS[0]} manifests")
must(registry.get_plugins() is registry.get_plugins(), "the validated tuple is reused")

# (2) same results and errors as the uncached read ----------------------------------------------------------------------------------
base_loads = LOADS[0]
expected = uncached_get_plugins()
LOADS[0] = base_loads
must(first == expected and [p.plugin_id for p in first] == [p.plugin_id for p in expected], "same tuple, same order")
must(all(a.root == b.root and a.python_paths == b.python_paths and a.server_maintenance_actions == b.server_maintenance_actions for a, b in zip(first, expected)))
for pid, ptype in (("mod3", "extension"), ("mod3", "reportset"), ("special", None), ("nope", None), ("mod3", None)):
    got, want = error_of(registry.get_plugin, pid, ptype), error_of(uncached_get_plugin, pid, ptype)
    must(got == want, (pid, ptype, got, want))
    if got is None:
        must(registry.get_plugin(pid, ptype) == uncached_get_plugin(pid, ptype))
must("matches multiple plugin types" in error_of(registry.get_plugin, "mod3"), "id in an extension and a reportset needs a type")
must("was not found" in error_of(registry.get_plugin, "nope"))

# (3) changes are seen ----------------------------------------------------------------------------------------------------------------
reset()
registry.get_plugins()
path = EXT / "mod5" / "tec_tac.json"
text = path.read_text(encoding="utf-8")
path.write_text(text.replace("1.0.0", "2.0.0"), encoding="utf-8")  # same size, different mtime
age(path, OLD - 100)
before = LOADS[0]
must(registry.get_plugin("mod5", "extension").version == "2.0.0", "a same-size rewrite is seen")
must(LOADS[0] == before + TOTAL_MANIFESTS, "a change reloads once")
registry.get_plugins()
must(LOADS[0] == before + TOTAL_MANIFESTS, "and is cached again")
write_manifest(EXT / "added", {"id": "added", "version": "1.0.0"})
age_tree(EXT / "added")
age(EXT)
must(registry.get_plugin("added").version == "1.0.0", "an added module is seen")
shutil.rmtree(EXT / "added")
age(EXT, OLD - 50)
must("was not found" in error_of(registry.get_plugin, "added"), "a removed module is gone")
shutil.rmtree(REP / "mod7")
age(REP, OLD - 60)
must("was not found" in error_of(registry.get_plugin, "mod7", "reportset"), "a removed reportset is gone")
write_manifest(REP / "mod7", {"id": "mod7", "type": "reportset", "version": "1.0.0"})
age(REP / "mod7", OLD - 70)
age(REP, OLD - 80)
must(registry.get_plugin("mod7", "reportset").plugin_id == "mod7")
write_manifest(REP / "orphan", {"id": "orphan", "type": "reportset"})
age(REP / "orphan")
age(REP, OLD - 90)
must("without matching extension" in (error_of(registry.get_plugins) or ""), "an orphan reportset raises")
must("without matching extension" in (error_of(registry.get_plugins) or ""), "and raises again (never cached)")
shutil.rmtree(REP / "orphan")
age(REP, OLD - 95)
must(error_of(registry.get_plugins) is None, "removing it recovers")

# python_paths folder removed after caching (only lib changes, not the module folder)
reset()
registry.get_plugins()
shutil.rmtree(special / "lib" / "py")
age(special / "lib", OLD - 10)
must("python path does not exist" in (error_of(registry.get_plugins) or ""), "a removed python_paths folder is seen")
(special / "lib" / "py").mkdir()
age(special / "lib" / "py", OLD - 20)
age(special / "lib", OLD - 30)
must(error_of(registry.get_plugins) is None, "restoring it recovers")
# server-maintenance executable removed after caching
reset()
registry.get_plugins()
exe = special / "server_maintenance" / "actions" / "act.sh"
exe.unlink()
age(exe.parent, OLD - 40)
must("does not exist" in (error_of(registry.get_plugins) or ""), "a removed server-maintenance executable is seen")
exe.write_text("#!/bin/sh\n", encoding="utf-8")
age(exe, OLD - 50)
age(exe.parent, OLD - 60)
must(error_of(registry.get_plugins) is None, "restoring it recovers")

# (4) a corrupt manifest raises every call and is never cached -------------------------------------------------------------------------
reset()
registry.get_plugins()
path = EXT / "mod9" / "tec_tac.json"
good = path.read_text(encoding="utf-8")
path.write_text("{not json", encoding="utf-8")
age(path, OLD - 200)
loads_before = LOADS[0]
for _ in range(3):
    must("Unable to read" in (error_of(registry.get_plugins) or ""), "corrupt manifest raises")
must(LOADS[0] > loads_before + TOTAL_MANIFESTS, "a failed read is read again, never cached")
must("Unable to read" in (error_of(registry.get_plugin, "mod1") or ""), "get_plugin raises too")
path.write_text(good, encoding="utf-8")
age(path, OLD - 300)
must(error_of(registry.get_plugins) is None and registry.get_plugin("mod9", "extension").plugin_id == "mod9", "fixing it recovers")

# validation failures (duplicate Django app) raise every call and are not stored
path = EXT / "mod10" / "tec_tac.json"
good = path.read_text(encoding="utf-8")
path.write_text(good.replace('"app10"', '"app11"'), encoding="utf-8")
age(path, OLD - 400)
for _ in range(2):
    must("is registered by both" in (error_of(registry.get_plugins) or ""), "duplicate Django app raises each time")
path.write_text(good, encoding="utf-8")
age(path, OLD - 500)
must(error_of(registry.get_plugins) is None)

# (5) invalidate forces one reload --------------------------------------------------------------------------------------------------
registry.get_plugins()
before = LOADS[0]
registry.invalidate_plugin_cache()
registry.get_plugins()
registry.get_plugins()
must(LOADS[0] == before + TOTAL_MANIFESTS, "invalidate_plugin_cache forces exactly one reload")

# (6) explicit roots are never cached ------------------------------------------------------------------------------------------------
reset()
registry.discover_plugins(EXT, REP)
registry.discover_plugins(EXT, REP)
must(LOADS[0] == TOTAL_MANIFESTS * 2, "explicit roots read every call")
must(registry._DISCOVERY_CACHE is None, "and store nothing")
registry.discover_plugins(EXT)
must(registry._DISCOVERY_CACHE is None, "one explicit root is explicit too")

# (7) racy window: a file changed just now is not trusted --------------------------------------------------------------------------
reset()
fresh = EXT / "mod0" / "tec_tac.json"
fresh.write_text(fresh.read_text(encoding="utf-8"), encoding="utf-8")  # mtime = now
registry.get_plugins()
registry.get_plugins()
must(LOADS[0] == TOTAL_MANIFESTS * 2, "a manifest modified within the racy window is read again")
age(fresh)
age(fresh.parent)
registry.get_plugins()  # older now, stored
before = LOADS[0]
registry.get_plugins()
must(LOADS[0] == before, "once older than the window it is cached")

# a fingerprint read error bypasses the cache and is not stored
reset()
registry.get_plugins()
real_scandir = os.scandir


def broken_scandir(*args, **kwargs):
    raise PermissionError("denied")


registry.os.scandir = broken_scandir
try:
    before = LOADS[0]
    must(error_of(registry.get_plugins) is None, "fingerprint failure falls back to a plain read")
    must(LOADS[0] >= before + 1, "and reads the manifests")
finally:
    registry.os.scandir = real_scandir

# (8) threads ---------------------------------------------------------------------------------------------------------------------
reset()
results, problems = [], []


def worker():
    try:
        for _ in range(40):
            results.append(tuple(p.plugin_id for p in registry.get_plugins()))
            registry.get_plugin("special")
    except Exception as exc:  # noqa: BLE001 - report to the main thread
        problems.append(exc)


threads = [threading.Thread(target=worker) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
must(not problems, problems)
must(len(set(results)) == 1, "every thread saw the same plugins")
must(LOADS[0] == TOTAL_MANIFESTS, f"eight threads loaded {LOADS[0]} manifests, expected {TOTAL_MANIFESTS}")

# timing: 122 get_plugins calls, uncached (the old behaviour) and cached ------------------------------------------------------------
registry._load_manifest = real_load
start = time.perf_counter()
for _ in range(122):
    uncached_get_plugins()
uncached_seconds = time.perf_counter() - start
registry.invalidate_plugin_cache()
start = time.perf_counter()
for _ in range(122):
    registry.get_plugins()
cached_seconds = time.perf_counter() - start
print(f"TIMING 122 get_plugins calls over {TOTAL_MANIFESTS} manifests: uncached {uncached_seconds:.3f} s, cached {cached_seconds:.3f} s")
must(cached_seconds < uncached_seconds, "the cache is faster")

# (9) Core calls invalidate_plugin_cache where it changes modules --------------------------------------------------------------------
import re


def source(name):
    return (TEC / name).read_text(encoding="utf-8")


def body(text, name):
    match = re.search(rf"^def {name}\(.*?(?=^def )", text, re.DOTALL | re.MULTILINE)
    must(match is not None, name)
    return match.group(0)


must("invalidate_plugin_cache()" in body(source("module_manager.py"), "_dispatch"), "module_manager._dispatch")
must("invalidate_plugin_cache()" in body(source("module_manager_v2.py"), "_dispatch_v2"), "module_manager_v2._dispatch_v2 (install, upgrade, enable, disable, visibility, remove)")
must("invalidate_plugin_cache()" in body(source("module_hotfix.py"), "_dispatch"), "module_hotfix._dispatch")
state = source("module_state.py")
must("invalidate_plugin_cache()" in body(state, "save_state") or "_invalidate_plugin_cache()" in body(state, "save_state"), "module_state.save_state")
must("_invalidate_plugin_cache()" in body(state, "forget_module") or "invalidate_plugin_cache" in body(state, "forget_module"), "module_state.forget_module")
v2 = source("module_manager_v2.py")
for name in ("queue_set_enabled", "queue_set_visibility"):
    must("_queue_v2(" in body(v2, name), name + " goes through _queue_v2 and so through _dispatch_v2")
must("def invalidate_plugin_cache" in source("registry.py"))
must("scheduler._manifest_signature" not in source("registry.py"), "the scheduler's own signature cache is left alone")

shutil.rmtree(tmp, ignore_errors=True)
print("plugin discovery cache 1.17.96 ok")
