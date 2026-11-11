#!/usr/bin/env python3
"""1.17.119 regression: a runtime root path is one bind (held Medium finding on 1.17.118).

Both parsers (registry.py and scripts/sandbox-helper.py) accept only [A-Za-z0-9._-] in each path part and give the same answer; the unit
builder refuses a registry path that could split into more than one BindReadOnlyPaths= entry (runtime_unverified) and still binds a good
row exactly as 1.17.118 did; check_runner_ready and the sweep flag an old row with a bad path.

Not runnable here: real systemd.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_119a", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
sh, must, make_runner, BASE, ROOT = H.sh, H.must, H.make_runner, H.BASE, H.ROOT
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry

GOOD = ["/opt/tec-tac/runtimes/ai/claude", "/opt/tec-tac/runtimes/ai/a.b_c-d", "/opt/tec-tac/runtimes/ai/claude/bin/x-1.2"]
BAD = {
    "space": "/opt/tec-tac/runtimes/ai/x /rmm/api", "tab": "/opt/tec-tac/runtimes/ai/x\ty", "colon": "/opt/tec-tac/runtimes/ai/a:b",
    "colon bind": "/opt/tec-tac/runtimes/ai/x:/rmm/api", "newline": "/opt/tec-tac/runtimes/ai/x\n/rmm/api", "dot dot": "/opt/tec-tac/runtimes/ai/../x",
    "dot": "/opt/tec-tac/runtimes/ai/./x", "specifier": "/opt/tec-tac/runtimes/ai/%h", "variable": "/opt/tec-tac/runtimes/ai/$HOME",
    "quote": '/opt/tec-tac/runtimes/ai/"x"', "single quote": "/opt/tec-tac/runtimes/ai/'x'", "non-ascii": "/opt/tec-tac/runtimes/ai/caf\u00e9",
    "backslash": "/opt/tec-tac/runtimes/ai/a\\b", "other module": "/opt/tec-tac/runtimes/other/x", "no depth": "/opt/tec-tac/runtimes/ai",
    "empty part": "/opt/tec-tac/runtimes/ai//x", "relative": "opt/tec-tac/runtimes/ai/x", "long": "/opt/tec-tac/runtimes/ai/" + "a" * 600,
}


def helper_ok(path):
    try:
        sh._check_runtime_path(path, "t", "ai")
        return True
    except RuntimeError:
        return False


def registry_ok(path):
    try:
        registry._sandbox_runtime_path(path, "t", "ai")
        return True
    except registry.RegistryError:
        return False


for path in GOOD:
    must(helper_ok(path) and registry_ok(path), ("good path refused", path))
for label, path in BAD.items():
    must(not helper_ok(path), ("helper accepted", label))
    must(not registry_ok(path), ("registry accepted", label))

# _bind_path_safe
for path in ("/a/b", "/opt/x-1.2_y"):
    must(sh._bind_path_safe(path), path)
for path in ("/a b", "/a\tb", "/a:b", "/a%h", "/a$X", "/a\x01", "/a\\b", "", None, 7, "/a\u00a0b"):
    must(not sh._bind_path_safe(path), repr(path))

# build_properties
RUN_ID = "cd" * 16
EXISTS = lambda path: path != "/missing" and (str(path).startswith(str(BASE)) or str(path).startswith("/opt/tec-tac/runtimes/ai") or str(path) == str(sh.LAUNCHER_FILE))
TREE = {"tree_sha256_file": "sandbox/t.txt", "listing_sha256": "0" * 64}


def props_for(path):
    row = make_runner("ai.chat", roots=[{"path": path, **TREE}])
    return sh.build_properties(row, RUN_ID, credential_names=[], exists=EXISTS)


good = props_for("/opt/tec-tac/runtimes/ai/claude")
must("BindReadOnlyPaths=/opt/tec-tac/runtimes/ai/claude" in good, "good bind kept")
for path in ("/opt/tec-tac/runtimes/ai/x /rmm/api", "/opt/tec-tac/runtimes/ai/a:b", "/opt/tec-tac/runtimes/ai/x:/rmm/api", "/opt/tec-tac/runtimes/ai/x\ty",
             "/opt/tec-tac/runtimes/ai/%h", "/opt/tec-tac/runtimes/ai/$HOME"):
    try:
        props_for(path)
    except sh.Refusal as exc:
        must(exc.code == "runtime_unverified", exc.code)
    else:
        raise AssertionError(("build_properties accepted", path))

# an old row with a bad path: ready check and sweep
bad_row = make_runner("ai.chat", roots=[{"path": "/opt/tec-tac/runtimes/ai/x /rmm/api", **TREE}])
try:
    sh.check_runner_ready(bad_row)
except sh.Refusal as exc:
    must(exc.code == "runtime_unverified", exc.code)
else:
    raise AssertionError("check_runner_ready accepted a bad path")
reasons = sh._sweep_reasons({"owner_module": "ai", "runtime_roots": [{"path": "/opt/tec-tac/runtimes/ai/a:b", **TREE}]})
must(reasons != [], "sweep flags the bad path")
must("a:b" not in "".join(reasons), reasons)
print("[TEST] PASS sandbox path characters 1.17.119")
