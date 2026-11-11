#!/usr/bin/env python3
"""1.17.118 regression: the sweep judges a stored row's tree_sha256_file by the same syntax rule as registration (held Low of the 1.17.117 review).

A stored row whose tree_sha256_file is ``../x``, absolute, ``a//b``, ``a/./b``, has a backslash, is empty, is not text or is 600 characters
long gives ``unsafe_path`` for that root, and the listing file is not opened and the runtime folder is not walked (``_tree_listing`` and
``verify_runtime`` are patched to raise if called). A valid row verifies as before, a changed listing still gives ``listing_changed``, and
the other roots of the same row are still judged.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
# The shared set-up (fake file system, helper loaded as sh, fake systemd), loaded by path; the names it gives are taken explicitly.
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, make_runner, must, sh,) = (H.BASE, H.make_runner, H.must, H.sh,)

OWNER = "ai"
MODULE = sh.EXTENSIONS_ROOT / OWNER
(MODULE / "sandbox").mkdir(parents=True)
TREE = BASE / "tree-a"
TREE.mkdir()
(TREE / "run.js").write_text("console.log(1)\n", encoding="utf-8")
digest = hashlib.sha256((TREE / "run.js").read_bytes()).hexdigest()
listing_bytes = f"{digest}  run.js\n".encode()
(MODULE / "sandbox" / "tree-a.txt").write_bytes(listing_bytes)
(MODULE / "sandbox" / "tree-b.txt").write_bytes(listing_bytes)
RUNTIME_MAP = {"/opt/tec-tac/runtimes/ai/a": str(TREE), "/opt/tec-tac/runtimes/ai/b": str(TREE)}
real_verify = sh.verify_runtime
real_listing = sh._tree_listing
CALLS = {"listing": 0, "verify": 0}


def counting_listing(folder, relative):
    CALLS["listing"] += 1
    return real_listing(folder, relative)


def counting_verify(path, listing):
    CALLS["verify"] += 1
    return real_verify(RUNTIME_MAP.get(path, path), listing)


sh._tree_listing, sh.verify_runtime = counting_listing, counting_verify
LISTING_SHA = hashlib.sha256(listing_bytes).hexdigest()


def reasons(*roots):
    CALLS.update(listing=0, verify=0)
    return sh._sweep_reasons({"owner_module": OWNER, "runtime_roots": list(roots)})


def root(name, tree_file, recorded=LISTING_SHA):
    return {"path": f"/opt/tec-tac/runtimes/ai/{name}", "tree_sha256_file": tree_file, "listing_sha256": recorded}


# a valid stored row behaves as before
must(reasons(root("a", "sandbox/tree-a.txt")) == [] and CALLS == {"listing": 1, "verify": 1}, "valid")
# a changed listing (the file no longer hashes to the recorded value) is still listing_changed and the folder is not walked
must("listing_changed" in "".join(reasons(root("a", "sandbox/tree-a.txt", "f" * 64))) and CALLS["verify"] == 0, "changed listing")
BAD = {
    "dot dot": "../x", "absolute": "/etc/passwd", "double slash": "a//b", "dot part": "a/./b", "dot dot inside": "sandbox/../x",
    "backslash": "sandbox\\tree-a.txt", "empty": "", "an integer": 7, "none": None, "a list": ["sandbox/tree-a.txt"], "nul": "sandbox/tree\x00.txt",
    "600 characters": "a" * 600, "trailing slash": "sandbox/",
}
for label, value in BAD.items():
    got = reasons(root("a", value))
    must(len(got) == 1 and got[0].startswith("root 1: unsafe_path (") and "unsafe_path" in got[0], (label, got))
    must(CALLS == {"listing": 0, "verify": 0}, (label, "the listing was opened or the folder walked", CALLS))
    must(value is None or str(value)[:20] not in got[0] or value == "", (label, "the bad value is not echoed", got))
    must("/" not in got[0].split("(", 1)[0] and "Traceback" not in got[0], got)
# a row that has no tree_sha256_file key at all is the same fixed refusal
got = reasons({"path": "/opt/tec-tac/runtimes/ai/a", "listing_sha256": LISTING_SHA})
must(len(got) == 1 and "unsafe_path" in got[0] and CALLS == {"listing": 0, "verify": 0}, got)
# the other roots of the same row are still judged: one bad, one good, one changed
got = reasons(root("a", "../x"), root("b", "sandbox/tree-b.txt"), root("a", "sandbox/tree-a.txt", "e" * 64))
must(len(got) == 2 and got[0].startswith("root 1: unsafe_path") and got[1].startswith("root 3: listing_changed"), got)
must(CALLS == {"listing": 2, "verify": 1}, CALLS)   # the bad root is never read; root 2 is read and walked; root 3 is read, changed, not walked
got = reasons(root("a", "../x"), root("b", "sandbox/tree-b.txt"))
must(len(got) == 1 and CALLS == {"listing": 1, "verify": 1}, (got, CALLS))
# the full sweep writes the fixed sentence into the row, and nothing else of the bad value
with contextlib.redirect_stdout(io.StringIO()):
    sh.ensure_layout()
row = make_runner("ai.sw", roots=[root("a", "../etc/shadow")])
saved = json.loads((sh.REGISTRY_ROOT / "ai.sw.json").read_text(encoding="utf-8"))
saved["runtime_roots"][0]["tree_sha256_file"] = "../etc/shadow"
(sh.REGISTRY_ROOT / "ai.sw.json").write_text(json.dumps(saved), encoding="utf-8")
CALLS.update(listing=0, verify=0)
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep()
after = json.loads((sh.REGISTRY_ROOT / "ai.sw.json").read_text(encoding="utf-8"))
must(after["runtime_verified"] is False and after["runtime_reason"].startswith("root 1: unsafe_path (") and "shadow" not in after["runtime_reason"], after["runtime_reason"])
must(CALLS == {"listing": 0, "verify": 0}, CALLS)

print("[TEST] PASS sandbox sweep tree file 1.17.118")
shutil.rmtree(BASE, ignore_errors=True)
