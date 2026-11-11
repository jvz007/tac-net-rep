#!/usr/bin/env python3
"""1.17.117 regression: core.sandbox runtime roots and the registration-time listing hash (fixes held on 1.17.116).

Covered: a runtime path must sit strictly below /opt/tec-tac/runtimes/<module id>/ and registry.py and sandbox-helper.py give the same
answer for the same manifests (table driven); runtime_reason is a fixed code plus a fixed sentence and never holds a file name, a path or
an error text (a planted SECRET_NAME_MARKER file never reaches the registry JSON or describe()); the sweep never walks a row whose path
is outside the module's own folder; registration records the SHA-256 of each tree listing file; a listing that changed after
registration gives listing_changed without a walk; registering again records the new hash; a row without a hash gives
listing_not_recorded; the runner.registered audit line carries the hashes.

The fake file layer is the one of sandbox-helper-register-1.17.116.py. Not runnable here: the helper as real root.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
sys.path.insert(0, str(ROOT / "framwork"))
BASE = Path(tempfile.mkdtemp(prefix="tectac-sandbox-helper-"))


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


# ------------------------------------------------------------------------------------------------ the fake file-system layer
def norm(path):
    return os.path.normcase(os.path.abspath(str(path)))


NOTROOT, WRITABLE, SYMLINKS, FD_PATH = set(), set(), set(), {}
CHMODS, CHOWNS = {}, {}
_real = {name: getattr(os, name) for name in ("stat", "lstat", "fstat", "open", "chmod", "replace")}
_VISIBLE = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")


def _fake(st, path, *, link=False):
    key = norm(path)
    kind = stat.S_IFLNK if (link and key in SYMLINKS) else stat.S_IFMT(st.st_mode)
    perms = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
    if key in WRITABLE:
        perms |= 0o020
    fields = list(st)[:10]
    fields[0], fields[4] = kind | perms, (1000 if key in NOTROOT else 0)
    extras = {name: getattr(st, name) for name in dir(st) if name.startswith("st_") and name not in _VISIBLE}
    return os.stat_result(fields, extras)


def _open(path, flags, *a, **k):
    fd = _real["open"](path, flags, *a, **k)
    FD_PATH[fd] = norm(path)
    return fd


def _replace(src, dst, *a, **k):
    _real["replace"](src, dst, *a, **k)
    CHMODS[norm(dst)], CHOWNS[norm(dst)] = CHMODS.get(norm(src)), CHOWNS.get(norm(src))


def _chmod(path, mode, *a, **k):
    CHMODS[norm(path)] = mode
    try:
        _real["chmod"](path, mode)
    except OSError:
        pass


os.stat = lambda path, *a, **k: _fake(_real["stat"](path, *a, **k), path)
os.lstat = lambda path, *a, **k: _fake(_real["lstat"](path, *a, **k), path, link=True)
os.fstat = lambda fd: _fake(_real["fstat"](fd), FD_PATH.get(fd, "?"))
os.open, os.replace, os.chmod = _open, _replace, _chmod
os.chown = lambda path, uid, gid, *a, **k: CHOWNS.__setitem__(norm(path), (uid, gid))
os.geteuid = lambda: 0

# ------------------------------------------------------------------------------------------------ load the helper and registry
HELPER = ROOT / "scripts" / "sandbox-helper.py"
sh = types.ModuleType("sandbox_helper_t")
sh.__file__ = str(HELPER)
exec(compile(HELPER.read_text(encoding="utf-8"), str(HELPER), "exec"), sh.__dict__)  # noqa: S102
from tec_tac import registry

EXT, LIB, STATE, RUN = BASE / "ext", BASE / "lib", BASE / "state", BASE / "run"
for folder in (EXT, LIB, STATE, RUN):
    folder.mkdir()
sh._ROOT_LAYOUT_ERROR = None
sh.EXTENSIONS_ROOT, sh.LIB_ROOT = EXT, LIB
sh.RUNNERS_ROOT, sh.REGISTRY_ROOT = LIB / "runners", LIB / "registry"
sh.STATE_ROOT, sh.RUN_ROOT = STATE, RUN
sh.STATUS_FILE, sh.AUDIT_FILE = STATE / "status.json", STATE / "audit.jsonl"

RUNTIME_MAP = {}
_real_verify = sh.verify_runtime
sh.verify_runtime = lambda path, listing: _real_verify(RUNTIME_MAP.get(path, path), listing)


def run_main(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = sh.main(list(args))
    return code, out.getvalue()


def register(module_id):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sh.register_module(module_id)
    return out.getvalue().strip()


def unregister(module_id):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sh.unregister_module(module_id)
    return out.getvalue().strip()


def refuses(call, part=""):
    try:
        call()
    except RuntimeError as exc:
        must(part in str(exc), (part, str(exc)))
        return
    raise AssertionError(f"accepted, expected a refusal containing {part!r}")


def audit_events():
    path = sh.AUDIT_FILE
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []


# ------------------------------------------------------------------------------------------------ module builders
RUNTIME = "/opt/tec-tac/runtimes/ai/claude"
EXE_BYTES = b"#!/bin/sh\necho run\n"


def runner(runner_id="ai.claude", exe="sandbox/runners/claude.sh", **over):
    entry = {
        "id": runner_id, "description": "Run the Claude program", "executable": exe,
        "argv": ["--model", {"param": "model"}], "parameters": {"model": {"type": "enum", "choices": ["a", "b"]}},
        "environment": {"LANG": "C.UTF-8"},
        "runtime_roots": [{"path": RUNTIME, "tree_sha256_file": "sandbox/claude.sha256"}],
        "credential_files": ["auth"], "credential_return": True, "limits": {"memory_mb": 1536}, "revision": "3",
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


def runtime_tree(name="claude"):
    """A runtime folder with three files; returns (folder, listing text)."""
    folder = BASE / f"runtime-{name}"
    if folder.exists():
        shutil.rmtree(folder)
    (folder / "bin").mkdir(parents=True)
    files = {"bin/claude": b"binary", "lib/a.js": b"console.log(1)", "README": b"hi"}
    lines = []
    for rel, data in files.items():
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
    return folder, "\n".join(lines) + "\n"


def put_module(module_id="ai", payload=None, listing="", exes=("sandbox/runners/claude.sh",), root=None):
    folder = (root or EXT) / module_id
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    for rel in exes:
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(EXE_BYTES)
    (folder / "sandbox").mkdir(exist_ok=True)
    (folder / "sandbox" / "claude.sha256").write_text(listing, encoding="utf-8")
    (folder / "tec_tac.json").write_text(json.dumps(payload if payload is not None else manifest()), encoding="utf-8")
    return folder


def reg_json(runner_id):
    return json.loads((sh.REGISTRY_ROOT / f"{runner_id}.json").read_text(encoding="utf-8"))


def reg_exists(runner_id):
    return (sh.REGISTRY_ROOT / f"{runner_id}.json").exists()


# ------------------------------------------------------------------------------------------------ helpers of this test
MARKER = "SECRET_NAME_MARKER"


def listing_file():
    return EXT / "ai" / "sandbox" / "claude.sha256"


def sweep_summary():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sh.sweep()
    return json.loads(out.getvalue())


class WalkCounter:
    """Counts os.walk calls: a row whose path or listing is not trusted must never reach the walk."""

    def __enter__(self):
        self.calls, self._orig = 0, os.walk

        def counting(*a, **k):
            self.calls += 1
            return self._orig(*a, **k)

        os.walk = counting
        return self

    def __exit__(self, *exc):
        os.walk = self._orig


def fresh(listing_text=None, mutate=None, listing_extra=""):
    """Register module ai against a new runtime tree. Returns (tree dir, listing text, registry row)."""
    tree_dir, good = runtime_tree()
    RUNTIME_MAP[RUNTIME] = str(tree_dir)
    if mutate:
        mutate(tree_dir)
    text = (good + listing_extra) if listing_text is None else listing_text
    put_module(payload=manifest(), listing=text)
    unregister("ai")
    must(register("ai") == "ai.claude", "registered whatever the runtime says")
    return tree_dir, text, reg_json("ai.claude")


def assert_no_names(row):
    blob = json.dumps(row) + (sh.AUDIT_FILE.read_text(encoding="utf-8") if sh.AUDIT_FILE.exists() else "")
    blob += run_main("--status")[1]
    for word in (MARKER, "a.js", "extra.txt", "/opt/tec-tac/runtimes/ai/claude/", "cannot read", "Errno", "Permission denied"):
        must(word not in row["runtime_reason"], (word, row["runtime_reason"]))
    must(MARKER not in blob, "the planted name never reaches the registry row, the audit log or --status")


# ------------------------------------------------------------------------------------------------ (a) the path rule, both parsers
def parser_answers(module_id, path):
    """(registry accepts, helper accepts) for a manifest of ``module_id`` whose one runner declares ``path`` as its runtime root."""
    entry = runner(f"{module_id}.claude", runtime_roots=[{"path": path, "tree_sha256_file": "sandbox/claude.sha256"}])
    payload = manifest([entry], id=module_id)
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="paths-"))
    mod_folder = put_module(module_id, payload=payload, listing="", root=root)
    try:
        registry._load_manifest("extension", mod_folder)
        reg_ok = True
    except registry.RegistryError:
        reg_ok = False
    try:
        sh.parse_runners(module_id, json.loads(mod_folder.joinpath("tec_tac.json").read_text(encoding="utf-8")), sh._check_installed_file(mod_folder))
        helper_ok = True
    except RuntimeError:
        helper_ok = False
    return reg_ok, helper_ok


BASE_DIR = "/opt/tec-tac/runtimes"
PATH_CASES = [
    ("ai", f"{BASE_DIR}/ai/claude", True),
    ("ai", f"{BASE_DIR}/ai/claude/lib/deeper", True),
    ("ai", f"{BASE_DIR}/ai/x", True),
    ("ai2", f"{BASE_DIR}/ai2/claude", True),
    ("ai", "/root", False),
    ("ai", "/etc/tec-tac/secrets", False),
    ("ai", "/opt/tec-tac/runtimes", False),
    ("ai", f"{BASE_DIR}/ai", False),
    ("ai", f"{BASE_DIR}/other/x", False),
    ("ai", f"{BASE_DIR}/ai/../other", False),
    ("ai", f"{BASE_DIR}/ai/x/../../other/y", False),
    ("ai", f"{BASE_DIR}/ai2/x", False),
    ("ai2", f"{BASE_DIR}/ai/x", False),
    ("ai", f"{BASE_DIR}/ai/claude/", False),
    ("ai", f"{BASE_DIR}//ai/claude", False),
    ("ai", f"{BASE_DIR}/ai/./claude", False),
    ("ai", f"{BASE_DIR}\\ai\\claude", False),
    ("ai", f"{BASE_DIR}/ai/cla\x01ude", False),
    ("ai", f"{BASE_DIR}/ai/cla\x00ude", False),
    ("ai", f"{BASE_DIR}/ai/" + "x" * 500, False),
    ("ai", "opt/tec-tac/runtimes/ai/claude", False),
    ("ai", "/OPT/tec-tac/runtimes/ai/claude", False),
    ("ai", 5, False),
]
for module_id, path, expect in PATH_CASES:
    got = parser_answers(module_id, path)
    must(got == (expect, expect), (module_id, path, "registry, helper", got, "expected", expect))
# the same refusal wording in both parsers (the registry ends its sentence with a full stop)
entry_bad = runner(runtime_roots=[{"path": "/etc/tec-tac/secrets", "tree_sha256_file": "sandbox/claude.sha256"}])
mod_bad = put_module(payload=manifest([entry_bad]), listing="", root=Path(tempfile.mkdtemp(dir=BASE, prefix="wording-")))
try:
    registry._load_manifest("extension", mod_bad)
    raise AssertionError("registry accepted /etc/tec-tac/secrets")
except registry.RegistryError as exc:
    registry_text = str(exc)
try:
    sh.parse_runners("ai", json.loads(mod_bad.joinpath("tec_tac.json").read_text(encoding="utf-8")), sh._check_installed_file(mod_bad))
    raise AssertionError("helper accepted /etc/tec-tac/secrets")
except RuntimeError as exc:
    helper_text = str(exc)
wording = "path must sit below /opt/tec-tac/runtimes/ai/ (at least one folder deeper)"
must(wording in registry_text and wording in helper_text, (registry_text, helper_text))

# ------------------------------------------------------------------------------------------------ (b) fixed reason codes, no names
_dir, _text, row = fresh()
must(row["runtime_verified"] is True and row["runtime_reason"] == "", row)

CODES = {
    "runtime_missing": "the runtime folder is not there yet; the module builds it after install",
    "unreadable": "the runtime folder or one of its files could not be read",
    "unsafe_path": "the runtime path is not inside the module's own runtime folder",
    "unsafe_entry": "a link, a special file, or an entry that is not root-owned or is writable by others was found in the runtime folder or its path",
    "extra_file": "the runtime folder holds a file that is not in the signed listing",
    "missing_file": "a file in the signed listing is missing from the runtime folder",
    "hash_mismatch": "a file in the runtime folder differs from the signed listing",
    "too_many_files": "the runtime folder holds too many files",
    "listing_empty": "the signed tree listing is empty",
    "listing_unreadable": "the signed tree listing could not be read",
    "listing_changed": "the signed tree listing changed after the module registered; the module must register again",
    "listing_not_recorded": "the signed tree listing was not recorded at registration; the module must register again",
}
must(sh.REASON_SENTENCES == CODES, "the sentence table is the documented one")
for code, sentence in CODES.items():
    must(sh.reason_text(code, 1) == f"root 1: {code} ({sentence})", code)
doc_text = (ROOT / "docs" / "sandbox-capability.md").read_text(encoding="utf-8")
must(all(f"`{code}`" in doc_text for code in CODES), "every code is documented")


def expect_reason(row, code):
    must(row["runtime_verified"] is False and row["runtime_reason"] == f"root 1: {code} ({CODES[code]})", row["runtime_reason"])
    assert_no_names(row)


def add_marker(tree_dir):
    (tree_dir / MARKER).write_bytes(b"x")


MARKER_X = f"{hashlib.sha256(b'x').hexdigest()}  {MARKER}\n"
# an extra file with a distinctive name
_d, _t, row = fresh(mutate=add_marker)
expect_reason(row, "extra_file")
# a listed file that is missing (the listing names the marker file; it is not on disk)
_d, _t, row = fresh(listing_extra=MARKER_X)
expect_reason(row, "missing_file")
# a listed file whose bytes differ
_d, _t, row = fresh(mutate=add_marker, listing_extra=f"{hashlib.sha256(b'other').hexdigest()}  {MARKER}\n")
expect_reason(row, "hash_mismatch")
# a symlink named with the marker
_d, _t, row = fresh(mutate=lambda d: (add_marker(d), SYMLINKS.add(norm(d / MARKER))), listing_extra=MARKER_X)
SYMLINKS.clear()
expect_reason(row, "unsafe_entry")
# not root-owned, writable folder, writable runtime folder, symlink in the path
for bucket, pick in ((NOTROOT, lambda d: d / "README"), (WRITABLE, lambda d: d / "bin"), (WRITABLE, lambda d: d), (SYMLINKS, lambda d: d)):
    _d, _t, row = fresh(mutate=lambda d, b=bucket, f=pick: b.add(norm(f(d))))
    for b in (NOTROOT, WRITABLE, SYMLINKS):
        b.clear()
    expect_reason(row, "unsafe_entry")
# the folder is not there yet
RUNTIME_MAP[RUNTIME] = str(BASE / f"no-such-{MARKER}")
put_module(payload=manifest(), listing=runtime_tree()[1])
unregister("ai")
register("ai")
expect_reason(reg_json("ai.claude"), "runtime_missing")
# too many files
saved_max = sh.MAX_TREE_FILES
sh.MAX_TREE_FILES = 3  # the listing (3 files) still parses; the tree (3 files and 2 folders) does not fit
try:
    _d, _t, row = fresh()
finally:
    sh.MAX_TREE_FILES = saved_max
expect_reason(row, "too_many_files")
# an empty listing
_d, _t, row = fresh(listing_text="")
expect_reason(row, "listing_empty")

# an unreadable entry: lstat fails for a name os.walk found, with an error text that holds the marker
real_lstat = sh._lstat


def failing_lstat(path, *a, **k):
    if str(path).endswith("README"):
        raise PermissionError(13, f"Permission denied {MARKER}", str(path))
    return real_lstat(path, *a, **k)


tree_dir, good_listing = runtime_tree()
RUNTIME_MAP[RUNTIME] = str(tree_dir)
put_module(payload=manifest(), listing=good_listing)
unregister("ai")
sh._lstat = failing_lstat
try:
    register("ai")
finally:
    sh._lstat = real_lstat
expect_reason(reg_json("ai.claude"), "unreadable")


# the folder itself cannot be read
def failing_folder_lstat(path, *a, **k):
    if str(path) == str(tree_dir):
        raise PermissionError(13, f"Permission denied {MARKER}", str(path))
    return real_lstat(path, *a, **k)


sh._lstat = failing_folder_lstat
try:
    unregister("ai")
    register("ai")
finally:
    sh._lstat = real_lstat
expect_reason(reg_json("ai.claude"), "unreadable")

# two roots: each reason carries only its number
second = RUNTIME + "2"
put_module(payload=manifest([runner(runtime_roots=[{"path": RUNTIME, "tree_sha256_file": "sandbox/claude.sha256"},
                                                   {"path": second, "tree_sha256_file": "sandbox/claude.sha256"}])]), listing=good_listing)
RUNTIME_MAP[RUNTIME] = str(tree_dir)
RUNTIME_MAP[second] = str(BASE / "nowhere")
unregister("ai")
register("ai")
row = reg_json("ai.claude")
must(row["runtime_reason"] == "root 2: runtime_missing (" + CODES["runtime_missing"] + ")", row["runtime_reason"])
must(len(row["runtime_roots"]) == 2 and all(re.fullmatch("[0-9a-f]{64}", r["listing_sha256"]) for r in row["runtime_roots"]), row["runtime_roots"])
unregister("ai")

# ------------------------------------------------------------------------------------------------ (c) the sweep and the recorded listing hash
tree_dir, good_listing, row = fresh()
must(row["runtime_verified"] is True, row)
roots = row["runtime_roots"]
must(len(roots) == 1 and set(roots[0]) == {"path", "tree_sha256_file", "listing_sha256"}, roots)
must(roots[0]["listing_sha256"] == hashlib.sha256(listing_file().read_bytes()).hexdigest(), "the hash is the SHA-256 of the raw listing bytes")
must(MARKER not in json.dumps(row) and "bin/claude" not in json.dumps(row), "the row holds a hash, no file names")
registered_event = [e for e in audit_events() if e["event"] == "runner.registered"][-1]
must(registered_event["detail"]["listing_sha256"] == [roots[0]["listing_sha256"]], registered_event)
# unchanged: verified, nothing changed, the walk happens
with WalkCounter() as walk:
    summary = sweep_summary()
must(summary["checked"] == 1 and summary["changed"] == [] and walk.calls == 1, (summary, walk.calls))
must(reg_json("ai.claude")["runtime_verified"] is True, "still verified")
# a hotfix model: the listing file is rewritten (a comment line keeps it parseable, and the runtime still matches it)
listing_file().write_text("# hotfix\n" + good_listing, encoding="utf-8")
with WalkCounter() as walk:
    summary = sweep_summary()
row = reg_json("ai.claude")
must(summary["changed"] == ["ai.claude"] and walk.calls == 0, (summary, walk.calls))
expect_reason(row, "listing_changed")
last_sweep = [e for e in audit_events() if e["event"] == "sweep"][-1]
must(last_sweep["detail"]["runtime_state_changed"] == ["ai.claude"], last_sweep)
# registering again records the new hash and the next sweep verifies
register("ai")
must(reg_json("ai.claude")["runtime_roots"][0]["listing_sha256"] == hashlib.sha256(listing_file().read_bytes()).hexdigest(), "new hash recorded")
must(reg_json("ai.claude")["runtime_roots"][0]["listing_sha256"] != roots[0]["listing_sha256"], "the hash changed")
must(reg_json("ai.claude")["runtime_verified"] is True, reg_json("ai.claude"))
with WalkCounter() as walk:
    must(sweep_summary()["changed"] == [] and walk.calls == 1, "verified again")
# a listing that cannot be read
listing_file().unlink()
with WalkCounter() as walk:
    sweep_summary()
expect_reason(reg_json("ai.claude"), "listing_unreadable")
must(walk.calls == 0, "no walk")

# a row with no recorded hash (written by Core 1.17.116) fails closed until the module registers again
tree_dir, good_listing, row = fresh()
legacy = json.loads(json.dumps(row))
for root_entry in legacy["runtime_roots"]:
    del root_entry["listing_sha256"]
(sh.REGISTRY_ROOT / "ai.claude.json").write_text(json.dumps(legacy), encoding="utf-8")
with WalkCounter() as walk:
    summary = sweep_summary()
must(summary["changed"] == ["ai.claude"] and walk.calls == 0, (summary, walk.calls))
expect_reason(reg_json("ai.claude"), "listing_not_recorded")
for bad_hash in (5, "", "A" * 64, "z" * 64, "a" * 63, None):
    legacy["runtime_roots"][0]["listing_sha256"] = bad_hash
    (sh.REGISTRY_ROOT / "ai.claude.json").write_text(json.dumps(legacy), encoding="utf-8")
    with WalkCounter() as walk:
        sweep_summary()
    now_row = reg_json("ai.claude")
    must(now_row["runtime_verified"] is False and "listing_not_recorded" in now_row["runtime_reason"] and walk.calls == 0, bad_hash)
register("ai")
must(reg_json("ai.claude")["runtime_verified"] is True, "registering again repairs the row")

# a row whose path is outside the module's runtime folder is never walked (an older registration, or a hand-edited row)
for outside in ("/etc", "/root/x", f"{BASE_DIR}/ai", f"{BASE_DIR}/other/x", f"{BASE_DIR}/ai2/x", f"{BASE_DIR}/ai/../other", RUNTIME + "/", 7):
    tree_dir, good_listing, row = fresh()
    hacked = json.loads(json.dumps(row))
    hacked["runtime_roots"][0]["path"] = outside
    (sh.REGISTRY_ROOT / "ai.claude.json").write_text(json.dumps(hacked), encoding="utf-8")
    with WalkCounter() as walk:
        summary = sweep_summary()
    must(walk.calls == 0 and summary["changed"] == ["ai.claude"], (outside, summary, walk.calls))
    expect_reason(reg_json("ai.claude"), "unsafe_path")
# a bad owner or a malformed root list is never walked either
hacked = json.loads(json.dumps(row))
hacked["owner_module"] = "../etc"
(sh.REGISTRY_ROOT / "ai.claude.json").write_text(json.dumps(hacked), encoding="utf-8")
with WalkCounter() as walk:
    sweep_summary()
bad_owner = reg_json("ai.claude")
must(walk.calls == 0 and bad_owner["runtime_verified"] is False and "unreadable" in bad_owner["runtime_reason"], bad_owner)
hacked = json.loads(json.dumps(row))
hacked["runtime_roots"] = ["not an object"]
(sh.REGISTRY_ROOT / "ai.claude.json").write_text(json.dumps(hacked), encoding="utf-8")
with WalkCounter() as walk:
    sweep_summary()
must(walk.calls == 0 and "unsafe_path" in reg_json("ai.claude")["runtime_reason"], reg_json("ai.claude"))
unregister("ai")

print("[TEST] PASS sandbox runtime roots 1.17.117")
