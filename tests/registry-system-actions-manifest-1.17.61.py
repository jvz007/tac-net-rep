#!/usr/bin/env python3
"""1.17.61 regression: the optional manifest key ``system_actions`` (R-20, AD-13 condition 1).

The real tec_tac/registry.py reads manifests from a temporary extensions folder. Covered: a manifest without the key loads exactly as
before (empty tuple); a valid list is kept in order; a bad shape (not a list, not text, another module's prefix, bad characters, a
repeat), more than 20 entries and a reportset that declares the key are RegistryErrors; the key is in SUPPORTED_KEYS, so an older
Core refuses a manifest that has it (the release notes name requires.framework >=1.17.61); PluginSpec equality and hashing ignore the
new field; and the root job helpers do not validate manifest keys, so they ignore the new one.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


spec = importlib.util.spec_from_file_location("reg_under_test", APP / "registry.py")
reg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reg
spec.loader.exec_module(reg)

TMP = Path(tempfile.mkdtemp(prefix="tectac-manifest-"))
COUNTER = [0]


def load(manifest_extra, *, plugin_type="extension", plugin_id="patching", category="core"):
    COUNTER[0] += 1
    root = TMP / f"run{COUNTER[0]}" / ("extensions" if plugin_type == "extension" else "reportsets")
    folder = root / plugin_id
    folder.mkdir(parents=True)
    manifest = {"id": plugin_id, "type": plugin_type, "version": "1.0.0", "python_paths": ["."], "django_apps": []}
    if plugin_type == "extension":
        manifest["category"] = category
    manifest.update(manifest_extra)
    (folder / "tec_tac.json").write_text(json.dumps(manifest), encoding="utf-8")
    return reg._load_manifest(plugin_type, folder)


def refused(extra, **kw):
    try:
        load(extra, **kw)
    except reg.RegistryError as exc:
        return str(exc)
    raise AssertionError(f"accepted {extra!r}")


must("system_actions" in reg.SUPPORTED_KEYS, "the key is supported")
spec_plain = load({})
must(spec_plain.system_actions == (), "a manifest without the key loads unchanged")
must(load({"capabilities": {"patching.windows": "1.0.0"}}).system_actions == (), "other optional keys are unaffected")
good = load({"system_actions": ["patching.scan", "patching.install"]})
must(good.system_actions == ("patching.scan", "patching.install"), good.system_actions)
must(load({"system_actions": []}).system_actions == (), "an empty list is allowed")
twenty = [f"patching.a{i}" for i in range(20)]
must(load({"system_actions": twenty}).system_actions == tuple(twenty), "exactly 20 are allowed")
print("       a manifest without the key loads unchanged; a valid list is kept in order; 20 entries are allowed")

for bad in ("patching.scan", {"patching.scan": True}, 5, None, [5], [None], [["patching.scan"]], ["scan"], ["other.scan"], ["patching."], ["patching.Scan"],
            ["patching.sc an"], ["patching.scan", "patching.scan"], ["patching.-scan"], ["patching." + "a" * 65], [""], ["patching.scan\n"]):
    message = refused({"system_actions": bad})
    must("system_actions" in message, (bad, message))
refused({"system_actions": [f"patching.a{i}" for i in range(21)]})
print("       a bad shape, another module's prefix, bad characters, a repeat and 21 entries are RegistryErrors")

message = refused({"system_actions": ["patching.scan"]}, plugin_type="reportset", category="")
must("Reportset" in message, message)
print("       a reportset may not declare the key")

# equality and hashing ignore the field, like server_maintenance_actions
a, b = load({"system_actions": ["patching.scan"]}), load({})
must(a.system_actions != b.system_actions and a.plugin_id == b.plugin_id, "the field differs")
must(hash(a) is not None and set(reg.PluginSpec.__dataclass_fields__) >= {"system_actions"})
must(reg.PluginSpec.__dataclass_fields__["system_actions"].compare is False, "left out of equality")

# the root job helpers do not validate manifest keys: they read the manifest as JSON and take only the keys they need
for name in ("module-v2-job-helper.py", "module-job-helper.py"):
    source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    must("SUPPORTED_KEYS" not in source and "unsupported keys" not in source, f"{name} has no allow-list of manifest keys")
v2 = (ROOT / "scripts" / "module-v2-job-helper.py").read_text(encoding="utf-8")
must(re.search(r'payload\.get\("(id|version|category)"', v2) or '"capabilities" in payload' in v2, "the helper reads named keys only")
print("       existing manifests load unchanged, and the root job helpers keep no allow-list of manifest keys")

print("PASS registry system_actions manifest key 1.17.61")
