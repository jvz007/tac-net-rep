#!/usr/bin/env python3
"""1.17.116 regression: scripts/sandbox-helper.py, registration and the kill switch (core.sandbox Patch 1, part 2).

The helper's file-system answers (owner, mode, symlink) come from a fake layer limited to this test's temp folders, the technique of
server-maintenance-module-actions-1.17.17.py. The rule that reads them (``_untrusted``) is the helper's own.

Covered: the executable is copied root-owned 0755 with its SHA-256; the registry JSON content; a runner id owned by another module is
refused; an upgrade drops the stale runner and its executable, and a module that now declares none loses all; unregister removes only the
module's own; an untrusted manifest, executable, module folder or parent is refused; a symlink is refused; a runtime tree that matches is
verified, and a mismatch, an extra file, a missing file, a missing folder, a writable parent and a link inside give ``runtime_unverified``
(registered, with a plain reason); ``--start`` and ``--stop`` refuse with sandbox_disabled and read no stdin; SANDBOX_ENABLED is False; and
the helper's rules equal registry.py's for the same manifests (table driven, both parsers).

Not runnable here: the helper as real root (chown to a real root, systemd).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
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
exec(compile(HELPER.read_text(encoding="utf-8"), str(HELPER), "exec"), sh.__dict__)
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


# ------------------------------------------------------------------------------------------------ the kill switch
must(sh.SANDBOX_ENABLED is False, "SANDBOX_ENABLED is False")
must("SANDBOX_ENABLED = False" in HELPER.read_text(encoding="utf-8"), "a constant in the helper file itself")
must(sh.read_status()["enabled"] is False, "status is never enabled")


class NoStdin:
    def __getattr__(self, name):
        raise AssertionError(f"stdin was touched ({name})")


real_stdin = sys.stdin
sys.stdin = NoStdin()
try:
    for flag in ("--start", "--stop"):
        code, out = run_main(flag)
        must(code != 0, flag)
        must(json.loads(out) == {"t": "refused", "code": "sandbox_disabled"}, out)
        must(out.count("\n") == 1, "one frame")
finally:
    sys.stdin = real_stdin
# the refusal comes before the root check and before any file is touched
must(not (STATE / "audit.jsonl").exists() and not sh.REGISTRY_ROOT.exists(), "start and stop touch nothing")
# the sudo rule allows no arguments: an argument is a usage error, never a start
for bad in (["--start", "x"], ["--stop", "abc"], ["--bogus"], [], ["--status", "x"], ["--selftest", "x"], ["--sweep", "x"], ["--register-module"], ["--unregister-module"]):
    try:
        run_main(*bad)
        raise AssertionError(f"accepted {bad}")
    except SystemExit as exc:
        must(exc.code != 0, bad)

# ------------------------------------------------------------------------------------------------ registration
tree, listing = runtime_tree()
RUNTIME_MAP[RUNTIME] = str(tree)
folder = put_module(listing=listing)
ids = register("ai")
must(ids == "ai.claude", ids)
target = sh.RUNNERS_ROOT / "ai" / "claude.sh"
must(target.read_bytes() == EXE_BYTES, "executable copied")
must(CHMODS[norm(target)] == 0o755 and CHOWNS[norm(target)] == (0, 0), (CHMODS.get(norm(target)), CHOWNS.get(norm(target))))
record = reg_json("ai.claude")
must(CHMODS[norm(sh.REGISTRY_ROOT / "ai.claude.json")] == 0o644 and CHOWNS[norm(sh.REGISTRY_ROOT / "ai.claude.json")] == (0, 0), "registry file root-owned 0644")
must(record["owner_module"] == "ai" and record["version"] == "0.9.0" and record["registered_by"] == "module-manifest", record)
must(record["executable"] == str(target) and record["executable_sha256"] == hashlib.sha256(EXE_BYTES).hexdigest(), record)
must(record["limits"]["memory_mb"] == 1536 and record["limits"]["run_seconds"] == 240 and record["revision"] == "3", record["limits"])
must(record["credential_files"] == ["auth"] and record["credential_return"] is True and record["environment"] == {"LANG": "C.UTF-8"}, record)
must(record["runtime_verified"] is True and record["runtime_reason"] == "", record)
must(record["argv"] == ["--model", {"param": "model"}] and record["runtime_roots"][0]["path"] == RUNTIME, record)
events = [row["event"] for row in audit_events()]
must("runner.registered" in events and "module.runners_registered" in events, events)
must(all("credential" not in json.dumps(row).lower() or "credential_" in json.dumps(row).lower() for row in audit_events()), "no credential in the audit")
# a second registration is the same state
must(register("ai") == "ai.claude" and reg_json("ai.claude")["executable_sha256"] == record["executable_sha256"], "idempotent")

# ---- a runner id owned by another module is refused (a hand-written file; the id prefix rule already blocks a manifest naming it)
(sh.REGISTRY_ROOT / "ai.other.json").write_text(json.dumps({"id": "ai.other", "owner_module": "evil", "registered_by": "module-manifest"}), encoding="utf-8")
put_module(payload=manifest([runner(), runner("ai.other")]), listing=listing)
refuses(lambda: register("ai"), "already registered by another module")
must(reg_json("ai.other")["owner_module"] == "evil", "the other module's file is untouched")
(sh.REGISTRY_ROOT / "ai.other.json").unlink()

# ---- an upgrade drops the stale runner and its executable; a module that declares none loses all
put_module(payload=manifest([runner(), runner("ai.codex", exe="sandbox/runners/sub/codex.sh", runtime_roots=[])]),
           listing=listing, exes=("sandbox/runners/claude.sh", "sandbox/runners/sub/codex.sh"))
must(register("ai") == "ai.claude,ai.codex", "two runners")
must((sh.RUNNERS_ROOT / "ai" / "sub" / "codex.sh").is_file() and reg_exists("ai.codex"), "second registered")
put_module(payload=manifest([runner()]), listing=listing)
must(register("ai") == "ai.claude", "one runner")
must(not reg_exists("ai.codex") and not (sh.RUNNERS_ROOT / "ai" / "sub" / "codex.sh").exists() and not (sh.RUNNERS_ROOT / "ai" / "sub").exists(), "stale runner and executable dropped")
must(reg_exists("ai.claude") and target.is_file(), "the kept runner stays")
removed_events = [row for row in audit_events() if row["event"] == "runner.removed"]
must(any(row["detail"]["runner"] == "ai.codex" for row in removed_events), removed_events)
put_module(payload=manifest(None, sandbox_runners=None, publisher_permissions=["module.install"], requires=None), listing=listing)
must(register("ai") == "" and not reg_exists("ai.claude") and not (sh.RUNNERS_ROOT / "ai").exists(), "a module that now declares none loses all")
put_module(payload=manifest([]), listing=listing)
must(register("ai") == "", "an empty array registers nothing")

# ---- unregister removes only the module's own
put_module("ai", payload=manifest([runner(runtime_roots=[])]), listing=listing)
bee_payload = manifest([runner("bee.run", runtime_roots=[])], id="bee")
put_module("bee", payload=bee_payload, listing=listing)
register("ai")
register("bee")
(sh.REGISTRY_ROOT / "ai.byhand.json").write_text(json.dumps({"id": "ai.byhand", "owner_module": "ai", "registered_by": "an-admin"}), encoding="utf-8")
must(unregister("ai") == "ai.claude", "own runner removed")
must(not reg_exists("ai.claude") and not (sh.RUNNERS_ROOT / "ai").exists(), "own file and folder gone")
must(reg_exists("bee.run") and (sh.RUNNERS_ROOT / "bee" / "claude.sh").is_file(), "another module's runner untouched")
must(reg_exists("ai.byhand"), "a file the helper did not write is not removed")
(sh.REGISTRY_ROOT / "ai.byhand.json").unlink()
unregister("bee")
must(not reg_exists("bee.run"), "bee removed")
must(unregister("ghost") == "", "an unknown module is a no-op")
refuses(lambda: unregister("../x"), "module id")
refuses(lambda: register("a b"), "module id")
refuses(lambda: register(""), "module id")

# ---- untrusted inputs are refused and nothing is written
put_module(payload=manifest([runner(runtime_roots=[])]), listing=listing)
for label, victim in (("manifest", EXT / "ai" / "tec_tac.json"), ("module folder", EXT / "ai"), ("executable", EXT / "ai" / "sandbox" / "runners" / "claude.sh"),
                      ("executable parent", EXT / "ai" / "sandbox" / "runners"), ("extensions root parent", EXT / "ai" / "sandbox")):
    for bucket in (NOTROOT, WRITABLE):
        bucket.add(norm(victim))
        try:
            refuses(lambda: register("ai"), "")
        finally:
            bucket.discard(norm(victim))
        must(not reg_exists("ai.claude") and not (sh.RUNNERS_ROOT / "ai").exists(), f"{label}: nothing registered")
    SYMLINKS.add(norm(victim))
    try:
        refuses(lambda: register("ai"), "")
    finally:
        SYMLINKS.discard(norm(victim))
    must(not reg_exists("ai.claude"), f"{label}: nothing registered after a symlink")
must(register("ai") == "ai.claude", "all trust flags cleared: accepted again")
unregister("ai")
refuses(lambda: register("missing"), "not available")
# a manifest that fails a rule is refused before anything is changed
put_module(payload=manifest([runner(runtime_roots=[], limits={"memory_mb": 4096})]), listing=listing)
refuses(lambda: register("ai"), "limit memory_mb")
must(not reg_exists("ai.claude") and not (sh.RUNNERS_ROOT / "ai").exists(), "refused before any change")
put_module(payload=manifest([runner(runtime_roots=[], allowed_hosts=["a.example.com"])]), listing=listing)
refuses(lambda: register("ai"), "no host list")
put_module(payload=manifest(publisher_permissions=["module.install"]), listing=listing)
refuses(lambda: register("ai"), "sandbox.register")
put_module(payload=manifest(requires={"framework": ">=1.17.115"}), listing=listing)
refuses(lambda: register("ai"), "1.17.116")
put_module(payload=manifest(type="reportset"), listing=listing)
refuses(lambda: register("ai"), "extension")
put_module(payload=manifest(id="other"), listing=listing)
refuses(lambda: register("ai"), "does not match")
put_module(payload=manifest(sandbox_runners="nope"), listing=listing)
refuses(lambda: register("ai"), "JSON array")
put_module(payload=manifest(["nope"]), listing=listing)
refuses(lambda: register("ai"), "JSON object")
EXT.joinpath("ai", "tec_tac.json").write_text("{bad", encoding="utf-8")
refuses(lambda: register("ai"), "not valid JSON")
EXT.joinpath("ai", "tec_tac.json").write_text("[1]", encoding="utf-8")
refuses(lambda: register("ai"), "JSON object")
big = put_module(listing=listing)
big.joinpath("tec_tac.json").write_bytes(b" " * (sh.MAX_MANIFEST_BYTES + 10))
refuses(lambda: register("ai"), "larger than")

# ---- runtime verification: registered either way, with a plain reason when it fails
def registered_with(runtime_listing, mutate=None):
    tree_dir, good_listing = runtime_tree()
    RUNTIME_MAP[RUNTIME] = str(tree_dir)
    if mutate:
        mutate(tree_dir)
    put_module(payload=manifest(), listing=runtime_listing if runtime_listing is not None else good_listing)
    unregister("ai")
    must(register("ai") == "ai.claude", "registered whatever the runtime says")
    return reg_json("ai.claude")


rec = registered_with(None)
must(rec["runtime_verified"] is True, rec)
rec = registered_with(None, lambda d: (d / "lib" / "a.js").write_bytes(b"tampered"))
must(rec["runtime_verified"] is False and "differs from the signed listing: lib/a.js" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: (d / "extra.txt").write_bytes(b"x"))
must(rec["runtime_verified"] is False and "not in the signed listing: extra.txt" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: (d / "README").unlink())
must(rec["runtime_verified"] is False and "listed file is missing: README" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: WRITABLE.add(norm(d / "bin")))
WRITABLE.clear()
must(rec["runtime_verified"] is False and "writable by a group or anyone else" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: SYMLINKS.add(norm(d / "lib" / "a.js")))
SYMLINKS.clear()
must(rec["runtime_verified"] is False and "symlink inside the runtime folder" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: NOTROOT.add(norm(d / "README")))
NOTROOT.clear()
must(rec["runtime_verified"] is False and "root-owned" in rec["runtime_reason"], rec["runtime_reason"])
# a symlink or a writable folder in the path above the runtime
rec = registered_with(None, lambda d: WRITABLE.add(norm(d)))
WRITABLE.clear()
must(rec["runtime_verified"] is False and "writable by a group or anyone else" in rec["runtime_reason"], rec["runtime_reason"])
rec = registered_with(None, lambda d: SYMLINKS.add(norm(d)))
SYMLINKS.clear()
must(rec["runtime_verified"] is False and "symlink sits in the path" in rec["runtime_reason"], rec["runtime_reason"])
# the folder is not there yet: the normal first state, with its plain reason
RUNTIME_MAP[RUNTIME] = str(BASE / "no-such-runtime")
put_module(payload=manifest(), listing=listing)
unregister("ai")
register("ai")
rec = reg_json("ai.claude")
must(rec["runtime_verified"] is False and "not there yet" in rec["runtime_reason"], rec["runtime_reason"])
# an empty or malformed signed listing
rec = registered_with("")
must(rec["runtime_verified"] is False and "listing is empty" in rec["runtime_reason"], rec["runtime_reason"])
put_module(payload=manifest(), listing="not a listing line\n")
unregister("ai")
refuses(lambda: register("ai"), "tree listing")
put_module(payload=manifest(), listing=f"{'a' * 64}  ../escape\n")
refuses(lambda: register("ai"), "unsafe path")
put_module(payload=manifest(), listing=f"{'a' * 64}  a\n{'b' * 64}  a\n")
refuses(lambda: register("ai"), "repeats a path")
# parse_tree_listing on its own
must(sh.parse_tree_listing(f"# c\n\n{'a' * 64}  x/y\n{'b' * 64} *z\n".encode()) == {"x/y": "a" * 64, "z": "b" * 64}, "listing format")
refuses(lambda: sh.parse_tree_listing(b"\xff\xfe"), "UTF-8")

# ---- the sweep re-verifies and updates runtime_verified; it removes only stray selftest folders
tree_dir, good_listing = runtime_tree()
RUNTIME_MAP[RUNTIME] = str(BASE / "no-such-runtime")
put_module(payload=manifest(), listing=good_listing)
unregister("ai")
register("ai")
must(reg_json("ai.claude")["runtime_verified"] is False, "first state: unverified")
RUNTIME_MAP[RUNTIME] = str(tree_dir)   # ai.install-runtime built it
(RUN / "selftest-abc").mkdir()
(RUN / "keep-me").mkdir()
out = io.StringIO()
with contextlib.redirect_stdout(out):
    sh.sweep()
summary = json.loads(out.getvalue())
must(summary["checked"] == 1 and summary["changed"] == ["ai.claude"] and summary["removed"] == ["selftest-abc"], summary)
must(reg_json("ai.claude")["runtime_verified"] is True and reg_json("ai.claude")["runtime_reason"] == "", "the sweep verified the runtime")
must(not (RUN / "selftest-abc").exists() and (RUN / "keep-me").exists(), "only selftest folders are removed")
(tree_dir / "README").write_bytes(b"changed after the fact")
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep()
must(reg_json("ai.claude")["runtime_verified"] is False and "README" in reg_json("ai.claude")["runtime_reason"], "a later change is noticed")
must(any(row["event"] == "sweep" for row in audit_events()), "the sweep is audited")
unregister("ai")
# --status reads the registry and a missing status.json is a plain not-ready
put_module(payload=manifest([runner(runtime_roots=[])]), listing=good_listing)
register("ai")
status = json.loads(run_main("--status")[1])
must(status["status"]["ready"] is False and "selftest" in status["status"]["reason"] and status["status"]["enabled"] is False, status)
must([row["id"] for row in status["runners"]] == ["ai.claude"] and "executable_sha256" in status["runners"][0], status)
unregister("ai")

# ------------------------------------------------------------------------------------------------ the helper's rules equal registry.py's
must(sh.LIMITS == registry.SANDBOX_LIMITS, "limits and ceilings are the same constants")
must(sh.RESERVED_ENV == registry.SANDBOX_RESERVED_ENV and sh.RUNNERS_MAX == registry.SANDBOX_RUNNERS_MAX, "reserved names and entry cap")
must(sh.CREDENTIAL_FILES_MAX == registry.SANDBOX_CREDENTIAL_FILES_MAX and sh.RUNTIME_ROOTS_MAX == registry.SANDBOX_RUNTIME_ROOTS_MAX and sh.ENV_MAX == registry.SANDBOX_ENV_MAX, "caps")
must(sh.EXECUTABLE_PREFIX == registry.SANDBOX_EXECUTABLE_PREFIX and sh.MIN_FRAMEWORK == registry.SANDBOX_MIN_FRAMEWORK, "prefix and floor")
must(sh.REGISTER_PERMISSION == registry.SANDBOX_REGISTER_PERMISSION and sh.RUNNER_KEYS == registry._SANDBOX_RUNNER_KEYS, "permission and keys")
must(sh.CREDENTIAL_FILE_MAX_BYTES == 16 * 1024, "16 KiB per credential file")

DEEP = "sandbox/runners/claude.sh"
CASES = [
    ("good", manifest([runner()]), True),
    ("good minimal", manifest([{"id": "ai.m", "description": "x", "executable": DEEP}]), True),
    ("good four", manifest([runner(f"ai.r{i}") for i in range(4)]), True),
    ("empty", manifest([]), True),
    ("absent", manifest(None, sandbox_runners=None, publisher_permissions=None, requires=None), True),
    ("five", manifest([runner(f"ai.r{i}") for i in range(5)]), False),
    ("allowed_hosts", manifest([runner(allowed_hosts=["a.example.com"])]), False),
    ("unknown key", manifest([runner(colour="red")]), False),
    ("not a list", manifest("nope"), False),
    ("entry not object", manifest(["nope"]), False),
    ("wrong prefix", manifest([runner("other.claude")]), False),
    ("bare prefix", manifest([runner("ai.")]), False),
    ("bad id chars", manifest([runner("ai.a b")]), False),
    ("duplicate", manifest([runner(), runner()]), False),
    ("abs exe", manifest([runner(exe="/etc/passwd")]), False),
    ("dotdot exe", manifest([runner(exe="sandbox/runners/../x")]), False),
    ("outside prefix", manifest([runner(exe="server_maintenance/actions/claude.sh")]), False),
    ("backslash exe", manifest([runner(exe="sandbox\\runners\\claude.sh")]), False),
    ("missing exe", manifest([runner(exe="sandbox/runners/nope.sh")]), False),
    ("exe not text", manifest([runner(exe=5)]), False),
    ("empty desc", manifest([runner(description="")]), False),
    ("long desc", manifest([runner(description="x" * 201)]), False),
    ("ctl desc", manifest([runner(description="a\nb")]), False),
    ("argv not list", manifest([runner(argv="--x")]), False),
    ("argv unknown param", manifest([runner(argv=[{"param": "nope"}])]), False),
    ("argv long", manifest([runner(argv=["a"] * 65)]), False),
    ("param bad type", manifest([runner(parameters={"p": {"type": "float"}}, argv=[])]), False),
    ("param enum no choices", manifest([runner(parameters={"p": {"type": "enum"}}, argv=[])]), False),
    ("param bad pattern", manifest([runner(parameters={"p": {"type": "string", "pattern": "("}}, argv=[])]), False),
    ("reserved env", manifest([runner(environment={"HOME": "/x"})]), False),
    ("secret env", manifest([runner(environment={"API_TOKEN": "x"})]), False),
    ("loader env", manifest([runner(environment={"LD_PRELOAD": "x"})]), False),
    ("env value not text", manifest([runner(environment={"A": 5})]), False),
    ("limit over ceiling", manifest([runner(limits={"tasks": 513})]), False),
    ("limit string", manifest([runner(limits={"tasks": "10"})]), False),
    ("limit bool", manifest([runner(limits={"tasks": True})]), False),
    ("limit zero", manifest([runner(limits={"tasks": 0})]), False),
    ("limit unknown key", manifest([runner(limits={"colour": 1})]), False),
    ("root relative", manifest([runner(runtime_roots=[{"path": "opt/x/y", "tree_sha256_file": "sandbox/claude.sha256"}])]), False),
    ("root dotdot", manifest([runner(runtime_roots=[{"path": "/opt/x/../y", "tree_sha256_file": "sandbox/claude.sha256"}])]), False),
    ("root shallow", manifest([runner(runtime_roots=[{"path": "/opt", "tree_sha256_file": "sandbox/claude.sha256"}])]), False),
    ("root trailing slash", manifest([runner(runtime_roots=[{"path": "/opt/x/", "tree_sha256_file": "sandbox/claude.sha256"}])]), False),
    ("root missing tree", manifest([runner(runtime_roots=[{"path": "/opt/x/y", "tree_sha256_file": "sandbox/none.sha256"}])]), False),
    ("root tree dotdot", manifest([runner(runtime_roots=[{"path": "/opt/x/y", "tree_sha256_file": "../tec_tac.json"}])]), False),
    ("root extra key", manifest([runner(runtime_roots=[{"path": "/opt/x/y", "tree_sha256_file": "sandbox/claude.sha256", "x": 1}])]), False),
    ("root repeated", manifest([runner(runtime_roots=[{"path": "/opt/x/y", "tree_sha256_file": "sandbox/claude.sha256"}] * 2)]), False),
    ("three credentials", manifest([runner(credential_files=["a", "b", "c"])]), False),
    ("bad credential name", manifest([runner(credential_files=["Auth"])]), False),
    ("return without name", manifest([runner(credential_files=[], credential_return=True)]), False),
    ("return not bool", manifest([runner(credential_return="yes")]), False),
    ("bad revision", manifest([runner(revision="")]), False),
    ("no permission", manifest(publisher_permissions=["module.install"]), False),
    ("no permissions key", manifest(publisher_permissions=None), False),
    ("no framework", manifest(requires=None), False),
    ("low framework", manifest(requires={"framework": ">=1.17.115"}), False),
    ("exact framework", manifest(requires={"framework": "1.17.116"}), False),
    ("high framework", manifest(requires={"framework": ">=1.18.0"}), True),
]
for label, payload, accept in CASES:
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="parity-"))
    mod_folder = put_module(payload=payload, listing=listing, root=root)
    try:
        spec_runners = registry._load_manifest("extension", mod_folder).sandbox_runners
        registry_accepts = True
    except registry.RegistryError:
        spec_runners, registry_accepts = (), False
    try:
        _version, helper_runners = sh.parse_runners("ai", json.loads(mod_folder.joinpath("tec_tac.json").read_text(encoding="utf-8")), sh._check_installed_file(mod_folder))
        helper_accepts = True
    except (RuntimeError, TypeError):
        helper_runners, helper_accepts = [], False
    must(registry_accepts == accept and helper_accepts == accept, (label, "registry", registry_accepts, "helper", helper_accepts, "expected", accept))
    must(list(spec_runners) == helper_runners, (label, spec_runners, helper_runners))
# a reportset: registry refuses; the helper refuses a non-extension too
must(sh.parse_runners("ai", {"id": "ai", "type": "extension", "version": "1"}, lambda *a: None) == ("1", []), "no key, no runners")
refuses(lambda: sh.parse_runners("ai", {"id": "ai", "type": "reportset", "sandbox_runners": [runner()]}, lambda *a: None), "extension")

print("[TEST] PASS sandbox helper register 1.17.116")
