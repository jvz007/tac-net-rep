#!/usr/bin/env python3
"""1.17.116 regression: the optional manifest key ``sandbox_runners`` (core.sandbox Patch 1, part 1).

Runs the real registry.py against temp module folders (no Django needed). Covered:

* a good manifest parses into ``PluginSpec.sandbox_runners`` with defaults filled in;
* every refusal of the plan: unknown key, ``allowed_hosts``, a relative/absolute/``..``/symlink/missing executable, an executable outside
  ``sandbox/runners/`` or too shallow, a wrong id prefix, a duplicate id, more than 4 entries, a reserved or secret-looking environment name,
  a limit above its ceiling or not a whole number, runtime_roots that are not absolute, hold ``..`` or whose tree file is missing or a
  symlink, more than 2 credential files, a bad credential name, credential_return without a name, a missing publisher permission, a
  missing or low ``requires.framework``, and a reportset that declares the key;
* a manifest without the key (or with an empty array) parses exactly as before and its PluginSpec compares equal to one built before;
* the plugin-cache fingerprint changes when a runner executable or a tree file changes on disk.
"""
from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry

BASE = Path(tempfile.mkdtemp(prefix="tectac-sandbox-reg-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def runner(runner_id="ai.claude", exe="claude.sh", **over):
    entry = {
        "id": runner_id, "description": "Run the Claude command line program", "executable": f"sandbox/runners/{exe}",
        "argv": ["--model", {"param": "model"}], "parameters": {"model": {"type": "enum", "choices": ["a", "b"]}},
        "environment": {"LANG": "C.UTF-8"},
        "runtime_roots": [{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/claude.sha256"}],
        "credential_files": ["auth"], "credential_return": True,
        "limits": {"memory_mb": 1536, "run_seconds": 300}, "revision": "3",
    }
    entry.update(over)
    return entry


def manifest(runners=None, **over):
    payload = {
        "id": "ai", "type": "extension", "version": "0.9.0", "category": "premium",
        "publisher_permissions": ["sandbox.register"], "requires": {"framework": ">=1.17.116"},
        "sandbox_runners": [runner()] if runners is None else runners,
    }
    payload.update(over)
    return {key: value for key, value in payload.items() if value is not None}


def make_module(root: Path, module_id="ai", payload=None, files=("sandbox/runners/claude.sh", "sandbox/claude.sha256"), kind="extensions"):
    folder = root / kind / module_id
    folder.mkdir(parents=True, exist_ok=True)
    for name in files:
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"#!/bin/sh\necho hi\n")
    (folder / "tec_tac.json").write_text(json.dumps(payload if payload is not None else manifest()), encoding="utf-8")
    return folder


DEEP = "sandbox/runners/claude.sh"
GOOD = {"files": (DEEP, "sandbox/claude.sha256")}


def parse(payload, files=GOOD["files"], kind="extension", module_id="ai"):
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="reg-"))
    folder = make_module(root, module_id, payload, files, kind="extensions" if kind == "extension" else "reportsets")
    return registry._load_manifest(kind, folder)


def good(**over):
    return runner(executable=DEEP, **over)


def refused(payload, part, **kw):
    try:
        parse(payload, **kw)
    except registry.RegistryError as exc:
        must(part in str(exc), (part, str(exc)))
        return
    raise AssertionError(f"manifest accepted, expected {part!r}: {json.dumps(payload)[:300]}")


# ---- a good manifest
spec = parse(manifest([good()]))
must("sandbox_runners" in registry.SUPPORTED_KEYS, "key supported")
must(len(spec.sandbox_runners) == 1, spec.sandbox_runners)
entry = spec.sandbox_runners[0]
must(entry["id"] == "ai.claude" and entry["executable"] == DEEP and entry["credential_return"] is True, entry)
must(entry["argv"] == ["--model", {"param": "model"}] and entry["credential_files"] == ["auth"] and entry["revision"] == "3", entry)
must(entry["limits"]["memory_mb"] == 1536 and entry["limits"]["run_seconds"] == 300, entry["limits"])
# defaults of plan 2.1 for everything not stated
must(entry["limits"]["cpu_percent"] == 100 and entry["limits"]["tasks"] == 256 and entry["limits"]["stdout_kib"] == 512
     and entry["limits"]["stderr_kib"] == 64 and entry["limits"]["scratch_mb"] == 64 and entry["limits"]["input_kib"] == 64
     and entry["limits"]["queue_seconds"] == 10, entry["limits"])
must(entry["runtime_roots"] == [{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/claude.sha256"}], entry["runtime_roots"])
must(isinstance(hash(spec), int), "a spec with runners stays hashable")
# the Core ceilings are accepted exactly
ceilings = {"memory_mb": 2048, "cpu_percent": 200, "tasks": 512, "run_seconds": 600, "stdout_kib": 1024, "stderr_kib": 64, "scratch_mb": 256, "input_kib": 256, "queue_seconds": 30}
must(parse(manifest([good(limits=ceilings)])).sandbox_runners[0]["limits"] == ceilings, "the ceilings are allowed")
# only id, description and executable are needed
minimal = parse(manifest([{"id": "ai.min", "description": "x", "executable": DEEP}])).sandbox_runners[0]
must(minimal["argv"] == [] and minimal["environment"] == {} and minimal["runtime_roots"] == [] and minimal["credential_files"] == []
     and minimal["credential_return"] is False and minimal["revision"] == "1", minimal)
# 4 entries are allowed
four = parse(manifest([good(runner_id=f"ai.r{i}") for i in range(4)]))
must(len(four.sandbox_runners) == 4, "4 entries")

# ---- a manifest without the key is unchanged
without = parse(manifest(None, sandbox_runners=None, publisher_permissions=["module.install"], requires=None))
must(without.sandbox_runners == (), "absent key: no runners")
empty = parse(manifest([], publisher_permissions=None, requires=None))
must(empty.sandbox_runners == (), "an empty array needs no permission and no framework floor")
again = registry._load_manifest("extension", make_module(Path(tempfile.mkdtemp(dir=BASE)), "ai", manifest(None, sandbox_runners=None, publisher_permissions=["module.install"], requires=None)))
must(dataclasses.replace(without, root=again.root, python_paths=again.python_paths) == again, "the same manifest gives an equal PluginSpec")
# the new field is outside equality: a spec built by hand without it equals one that carries runners
plain = registry.PluginSpec(plugin_id="ai", plugin_type="extension", root=spec.root)
must(plain.sandbox_runners == (), "the default is empty")
must(registry.PluginSpec(plugin_id="ai", plugin_type="extension", root=spec.root, sandbox_runners=spec.sandbox_runners) == plain, "compare=False")

# ---- refusals
refused(manifest([good(colour="red")]), "unsupported keys")
refused(manifest([good(allowed_hosts=["api.example.com"])]), "no host list")
refused(manifest([good(allowed_hosts=[])]), "no host list")
refused(manifest("nope"), "must be a JSON array")
refused(manifest(["nope"]), "must be a JSON object")
refused(manifest([good(runner_id=f"ai.r{i}") for i in range(5)]), "more than 4")
refused(manifest([good(runner_id="other.claude")]), "must begin with the module ID prefix")
refused(manifest([good(runner_id="ai.")]), "must begin with the module ID prefix")
refused(manifest([good(runner_id="aix.claude")]), "must begin with the module ID prefix")
refused(manifest([good(runner_id="ai.b d")]), "id must be")
refused(manifest([good(), good()]), "more than once")
for bad_exe in ("/etc/passwd", "/usr/bin/id", "C:/x.sh", "sandbox/runners/../../tec_tac.json", "sandbox/runners/x/..", "sandbox/runners/./x/a.sh",
                "sandbox/runners//x/a.sh", "sandbox/runners/", "sandbox/runners", "claude.sh", "other/runners/x/claude.sh",
                "sandbox\\runners\\x\\claude.sh", "sandbox/runners/x/a\x00b.sh", "", 5, None, ["a"]):
    refused(manifest([runner(executable=bad_exe)]), "executable")
refused(manifest([runner(executable="sandbox/runners/missing.sh")]), "does not exist")
for bad_desc in ("", "   ", "x" * 201, "a\nb", 5, None):
    refused(manifest([good(description=bad_desc)]), "description")
for bad_argv in ("--x", ["--x", 5], [{"param": "nope"}], [{"param": "model", "extra": 1}], [["a"]], ["a\x00b"], ["x" * 4097], ["a"] * 65):
    refused(manifest([good(argv=bad_argv)]), "argv")
for bad_params in ("x", {"a b": {"type": "string"}}, {"p": "string"}, {"p": {"type": "float"}}, {"p": {"type": "enum"}}, {"p": {"type": "string", "pattern": "("}}):
    refused(manifest([good(parameters=bad_params, argv=[])]), "parameter")
for reserved in ("HOME", "TMPDIR", "SSL_CERT_FILE", "SANDBOX_WORK", "SANDBOX_OUT"):
    refused(manifest([good(environment={reserved: "x"})]), "reserved")
for bad_env in ({"API_TOKEN": "x"}, {"MY_SECRET": "x"}, {"DB_PASSWORD": "x"}, {"LD_PRELOAD": "/x"}, {"1BAD": "x"}, {"A B": "x"}):
    refused(manifest([good(environment=bad_env)]), "environment name")
refused(manifest([good(environment={"A": 5})]), "environment value")
refused(manifest([good(environment={"A": "x" * 1025})]), "environment value")
refused(manifest([good(environment={f"E{i}": "x" for i in range(33)})]), "environment must be")
refused(manifest([good(environment=["A"])]), "environment must be")
for name, value in (("memory_mb", 2049), ("cpu_percent", 201), ("tasks", 513), ("run_seconds", 601), ("stdout_kib", 1025), ("stderr_kib", 65),
                    ("scratch_mb", 257), ("input_kib", 257), ("queue_seconds", 31)):
    refused(manifest([good(limits={name: value})]), "Core ceiling")
for bad in (0, -5, "100", 1.5, True, None):
    refused(manifest([good(limits={"memory_mb": bad})]), "limit memory_mb")
refused(manifest([good(limits={"colour": 1})]), "unsupported keys")
refused(manifest([good(limits=[1])]), "limits must be an object")
for bad_roots in ("x", [{"path": "relative/path", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt/x/../etc", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt//x", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt/x/", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt/x\x00y", "tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt/x"}], [{"tree_sha256_file": "sandbox/claude.sha256"}],
                  [{"path": "/opt/x", "tree_sha256_file": "sandbox/claude.sha256", "extra": 1}],
                  [{"path": "/opt/x", "tree_sha256_file": "sandbox/claude.sha256"}] * 2,
                  [{"path": f"/opt/r{i}", "tree_sha256_file": "sandbox/claude.sha256"} for i in range(9)]):
    refused(manifest([good(runtime_roots=bad_roots)]), "runtime_roots")
for bad_tree in ("/etc/passwd", "../x", "sandbox/../x", "sandbox/missing.sha256", "", None, "a\\b"):
    refused(manifest([good(runtime_roots=[{"path": "/opt/x/y", "tree_sha256_file": bad_tree}])]), "tree_sha256_file")
for bad_cred in (["a", "b", "c"], ["auth", "auth"], ["Auth"], ["a b"], [""], [5], "auth", ["x" * 65]):
    refused(manifest([good(credential_files=bad_cred)]), "credential_files")
refused(manifest([good(credential_files=[], credential_return=True)]), "credential_return needs")
refused(manifest([good(credential_return="yes")]), "credential_return must be")
refused(manifest([good(revision="")]), "revision")
refused(manifest([good(revision=True)]), "revision")
# the permission and the framework floor
refused(manifest(publisher_permissions=None), "publisher_permissions")
refused(manifest(publisher_permissions=["module.install"]), "sandbox.register")
refused(manifest(publisher_permissions=["server_maintenance.register"]), "sandbox.register")
refused(manifest(requires=None), "requires.framework")
refused(manifest(requires={"framework": ">=1.17.115"}), "requires.framework")
refused(manifest(requires={"framework": ">=1.16.200"}), "requires.framework")
refused(manifest(requires={"framework": ">=1.17.9"}), "requires.framework")
refused(manifest(requires={"framework": "1.17.116"}), "requires.framework")
must(len(parse(manifest(requires={"framework": ">=1.17.116"})).sandbox_runners) == 1, "the floor itself passes")
must(len(parse(manifest(requires={"framework": ">=1.18.0"})).sandbox_runners) == 1, "a higher floor passes")
must(len(parse(manifest(requires={"framework": ">=2.0.0"})).sandbox_runners) == 1, "a higher major floor passes")
# the permission itself is a known permission, an unknown one is still refused
must(parse(manifest(publisher_permissions=["module.install", "sandbox.register", "server_maintenance.register"])).publisher_permissions
     == ("module.install", "sandbox.register", "server_maintenance.register"), "all three are known")
refused(manifest(publisher_permissions=["sandbox.root"]), "unsupported permission")
# a reportset may not declare it
refused({"id": "ai", "type": "reportset", "version": "1.0.0", "sandbox_runners": [good()]}, "may not declare", kind="reportset")

# ---- a symlink: the executable itself, a folder on the way, or the tree file (reported by Path.is_symlink, so this runs where a symlink cannot be made)
_real_is_symlink, LINKS = Path.is_symlink, set()
Path.is_symlink = lambda self: str(self) in LINKS or _real_is_symlink(self)
try:
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="reg-link-"))
    folder = make_module(root, files=GOOD["files"])
    for linked in (folder / DEEP, folder / "sandbox" / "runners", folder / "sandbox", folder / "sandbox" / "claude.sha256"):
        LINKS.clear()
        LINKS.add(str(linked))
        try:
            registry._load_manifest("extension", folder)
            raise AssertionError(f"a symlink at {linked.name} was accepted")
        except registry.RegistryError as exc:
            must("symlink" in str(exc), exc)
    LINKS.clear()
    must(len(registry._load_manifest("extension", folder).sandbox_runners) == 1, "no symlink: accepted")
finally:
    Path.is_symlink = _real_is_symlink

# ---- the plugin-cache fingerprint covers the runner executable and the tree files
root = Path(tempfile.mkdtemp(dir=BASE, prefix="reg-fp-"))
folder = make_module(root, files=GOOD["files"])
spec = registry._load_manifest("extension", folder)
paths = registry._extra_paths([spec])
must(str(folder / DEEP) in paths and str(folder / "sandbox" / "claude.sha256") in paths, paths)
before = registry._extra_signature(paths, [])
must(before == registry._extra_signature(paths, []), "stable while nothing changes")
(folder / DEEP).write_bytes(b"#!/bin/sh\necho a different and longer program\n")
after = registry._extra_signature(paths, [])
must(after != before, "a swapped executable changes the fingerprint")
before = after
(folder / "sandbox" / "claude.sha256").write_bytes(b"changed tree list\n")
must(registry._extra_signature(paths, []) != before, "a changed tree file changes the fingerprint")
# a spec without runners adds nothing new to the extra paths
plain_spec = parse(manifest(None, sandbox_runners=None, publisher_permissions=["module.install"], requires=None))
must(registry._extra_paths([plain_spec]) == (), registry._extra_paths([plain_spec]))

print("[TEST] PASS sandbox registry 1.17.116")
