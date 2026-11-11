#!/usr/bin/env python3
"""1.17.116 regression: the public contract core.sandbox 1.0.0 (core.sandbox Patch 1, part 5).

Django-free. The real tec_tac/sandbox.py and tec_tac/caller_identity.py run against temp folders (the technique of
caller-identity-core-provider-1.17.27.py: a function compiled under a module's file name stands in for the module's code); contracts.py
and apps.py are read as source. The file-system answers (owner, mode, symlink) come from a fake layer limited to this test's temp folders.

Covered: status() from a good, missing, corrupt, oversize, symlinked, non-root-owned and world-writable status.json (the last four
are ready false, reason status_unreadable); the registry listing (a row of another writer, a mismatched id, a file that is not trusted
are skipped); describe: the owner is answered, another module, Core, an unknown caller and an id outside the caller's prefix get not_owner,
an unknown id with the caller's own prefix is runner_unknown; start, run and cancel raise sandbox_disabled and touch no file;
SANDBOX_ENABLED is False in sandbox.py and in the helper; the capability is registered with exactly the five operations at 1.0.0 and
its metadata; every contract row has its keys, additive wording and the framework floor; status() never holds a credential-like key.
"""
from __future__ import annotations

import ast
import importlib
import json
import logging
import os
import re
import stat
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SANDBOX_FILE = str(APP / "sandbox.py")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ the fake file-system layer
def norm_path(path):
    return os.path.normcase(os.path.abspath(str(path)))


NOTROOT, WRITABLE, SYMLINKS, FD_PATH = set(), set(), set(), {}
_real = {name: getattr(os, name) for name in ("stat", "lstat", "fstat", "open")}
_VISIBLE = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")
OPENED = []
FORBID = {"on": False}


def _fake(st, path, *, link=False):
    key = norm_path(path)
    kind = stat.S_IFLNK if (link and key in SYMLINKS) else stat.S_IFMT(st.st_mode)
    perms = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
    if key in WRITABLE:
        perms |= 0o002
    fields = list(st)[:10]
    fields[0], fields[4] = kind | perms, (1000 if key in NOTROOT else 0)
    extras = {name: getattr(st, name) for name in dir(st) if name.startswith("st_") and name not in _VISIBLE}
    return os.stat_result(fields, extras)


def _open(path, flags, *a, **k):
    if FORBID["on"]:
        raise AssertionError(f"a file was opened: {path}")
    fd = _real["open"](path, flags, *a, **k)
    FD_PATH[fd] = norm_path(path)
    OPENED.append(norm_path(path))
    return fd


def _lstat(path, *a, **k):
    if FORBID["on"]:
        raise AssertionError(f"a file was looked at: {path}")
    return _fake(_real["lstat"](path, *a, **k), path, link=True)


os.stat = lambda path, *a, **k: _fake(_real["stat"](path, *a, **k), path)
os.lstat = _lstat
os.fstat = lambda fd: _fake(_real["fstat"](fd), FD_PATH.get(fd, "?"))
os.open = _open


# ------------------------------------------------------------------------------------------------ stubs and the real modules
def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-sandbox-contract-"))
EXT = TMP / "extensions"
EXT.mkdir()
PLUGINS: dict = {}
REGISTERED = []


def plugin(plugin_id, category, *, enabled=True, legacy=False):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=legacy, category=category, enabled=enabled)


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=lambda: tuple(PLUGINS.values()))
pkg.module_state = mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: PLUGINS[module_id].enabled if module_id in PLUGINS else True)
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kw: REGISTERED.append(kw) or SimpleNamespace(**kw))
sandbox = importlib.import_module("tec_tac.sandbox")

plugin("ai", "premium")
plugin("halopsa", "premium")
plugin("offai", "premium", enabled=False)
plugin("oldai", "premium", legacy=True)


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


CALL = "def call(fn, *a, **k):\n    return fn(*a, **k)\n"
AI = compile_as(str(EXT / "ai" / "service.py"), CALL)["call"]
HALO = compile_as(str(EXT / "halopsa" / "service.py"), CALL)["call"]
OFF = compile_as(str(EXT / "offai" / "service.py"), CALL)["call"]
OLD = compile_as(str(EXT / "oldai" / "service.py"), CALL)["call"]
CORE = compile_as(str(APP / "scheduler.py"), CALL)["call"]       # Core code running the provider
GENERATED = compile_as("<string>", CALL)["call"]
TESTFILE = lambda fn, *a: fn(*a)

LIB = TMP / "lib"
REGISTRY, STATE = LIB / "registry", TMP / "state"
REGISTRY.mkdir(parents=True)
STATE.mkdir()
sandbox.REGISTRY_ROOT, sandbox.STATUS_FILE = REGISTRY, STATE / "status.json"
GOOD_STATUS = {"ready": True, "reason": "ready", "enabled": False, "systemd_version": 252, "address_filter_ok": True, "dns_ok": True, "resolver": "127.0.0.53",
               "selftest_at": "2026-11-11T10:00:00Z", "checks": {"dns": {"ok": True, "detail": "127.0.0.53 answered"}}}


def write_status(payload):
    sandbox.STATUS_FILE.write_text(json.dumps(payload) if not isinstance(payload, str) else payload, encoding="utf-8")


def write_runner(runner_id="ai.claude", owner="ai", **over):
    row = {
        "id": runner_id, "owner_module": owner, "version": "0.9.0", "revision": "3", "description": "Run the Claude program",
        "executable": "/usr/local/lib/tec-tac/sandbox/runners/ai/claude.sh", "executable_sha256": "a" * 64, "argv": ["--model"],
        "environment": {"LANG": "C.UTF-8"}, "credential_files": ["auth"], "credential_return": True,
        "limits": {"memory_mb": 1536, "run_seconds": 240, "tasks": 256}, "runtime_verified": False, "runtime_reason": "root 1: runtime_missing (the runtime folder is not there yet; the module builds it after install)",
        "runtime_roots": [{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/claude.sha256"}], "registered_by": "module-manifest",
    }
    row.update(over)
    (REGISTRY / f"{runner_id}.json").write_text(json.dumps(row), encoding="utf-8")


# ------------------------------------------------------------------------------------------------ the kill switch
must(sandbox.SANDBOX_ENABLED is False, "SANDBOX_ENABLED is False in sandbox.py")
must(re.search(r"^SANDBOX_ENABLED = False$", (APP / "sandbox.py").read_text(encoding="utf-8"), re.MULTILINE), "a constant in the file")
must(re.search(r"^SANDBOX_ENABLED = False$", (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8"), re.MULTILINE), "a constant in the helper")

# ------------------------------------------------------------------------------------------------ status()
# a good file
write_status(GOOD_STATUS)
answer = sandbox.status()
must(answer == {"enabled": False, "ready": True, "reason": "ready", "systemd_version": 252, "address_filter_ok": True, "dns_ok": True,
                "selftest_at": "2026-11-11T10:00:00Z", "slots_total": None, "slots_used": None, "canary_ok": False, "canary_at": None, "runners": []}, answer)
# a ready selftest never makes enabled true, and a status file cannot claim it
write_status({**GOOD_STATUS, "enabled": True})
must(sandbox.status()["enabled"] is False, "enabled comes from the constant")
# keys not in the contract are never copied (resolver, checks, anything a later helper adds)
write_status({**GOOD_STATUS, "token": "x", "credential": "y", "resolver": "10.0.0.1"})
must(set(sandbox.status()) == {"enabled", "ready", "reason", "systemd_version", "address_filter_ok", "dns_ok", "selftest_at", "slots_total", "slots_used", "canary_ok", "canary_at", "runners"}, sorted(sandbox.status()))  # 1.17.118: four additive keys
# a failed selftest keeps its plain reason
write_status({**GOOD_STATUS, "ready": False, "reason": "the server does not use the unified cgroup v2 hierarchy", "dns_ok": False})
answer = sandbox.status()
must(answer["ready"] is False and answer["reason"].startswith("the server does not use") and answer["dns_ok"] is False, answer)
# wrong types are never read as ready
for bad in ({"ready": "yes"}, {"ready": 1}, {"ready": None}, {"ready": []}):
    write_status({**GOOD_STATUS, **bad})
    must(sandbox.status()["ready"] is False, bad)
write_status({**GOOD_STATUS, "systemd_version": "252", "reason": 5, "selftest_at": [1]})
answer = sandbox.status()
must(answer["systemd_version"] is None and answer["reason"] == "ready" and answer["selftest_at"] is None, answer)
write_status({**GOOD_STATUS, "systemd_version": True})
must(sandbox.status()["systemd_version"] is None, "a bool is not a version")
write_status({**GOOD_STATUS, "ready": False, "reason": "x\x00y\nz" + "w" * 400})
must("\x00" not in sandbox.status()["reason"] and "\n" not in sandbox.status()["reason"] and len(sandbox.status()["reason"]) <= 300, "a plain, short reason")
# missing: selftest not run
sandbox.STATUS_FILE.unlink()
answer = sandbox.status()
must(answer["ready"] is False and answer["reason"] == "selftest_not_run" and answer["enabled"] is False and answer["runners"] == [], answer)
# corrupt
write_status("{not json")
answer = sandbox.status()
must(answer["ready"] is False and answer["reason"] == "status_unreadable", answer)
write_status("[1, 2]")
must(sandbox.status()["reason"] == "status_unreadable", "not an object")
write_status(b"\xff\xfe".decode("latin-1"))
sandbox.STATUS_FILE.write_bytes(b"\xff\xfe\x00")
must(sandbox.status()["reason"] == "status_unreadable", "not UTF-8")
# oversize
write_status({**GOOD_STATUS, "pad": "x" * (sandbox.MAX_STATUS_BYTES + 10)})
answer = sandbox.status()
must(answer["ready"] is False and answer["reason"] == "status_unreadable", answer)
# symlinked, not root-owned, world-writable: all unready, all status_unreadable, never trusted
for label, bucket in (("symlinked", SYMLINKS), ("non-root-owned", NOTROOT), ("world-writable", WRITABLE)):
    write_status(GOOD_STATUS)
    bucket.add(norm_path(sandbox.STATUS_FILE))
    try:
        answer = sandbox.status()
    finally:
        bucket.discard(norm_path(sandbox.STATUS_FILE))
    must(answer["ready"] is False and answer["reason"] == "status_unreadable" and answer["enabled"] is False, (label, answer))
write_status(GOOD_STATUS)
must(sandbox.status()["ready"] is True, "the same file is trusted again once the flag is gone")
# a group-writable file is refused too (0o020)
_old_fake = _fake


def group_fake(st, path, *, link=False):
    result = _old_fake(st, path, link=link)
    if norm_path(path) == norm_path(sandbox.STATUS_FILE):
        fields = list(result)[:10]
        fields[0] |= 0o020
        return os.stat_result(fields, {})
    return result


_fake = group_fake
try:
    must(sandbox.status()["reason"] == "status_unreadable", "group-writable")
finally:
    _fake = _old_fake
# a fault inside never raises
real_read = sandbox._read_json_trusted
sandbox._read_json_trusted = lambda *a, **k: (_ for _ in ()).throw(ValueError("boom"))
try:
    answer = sandbox.status()
    must(answer["ready"] is False and answer["runners"] == [], answer)
finally:
    sandbox._read_json_trusted = real_read

# ---- the registry listing
write_status(GOOD_STATUS)
write_runner("ai.claude", "ai")
write_runner("ai.codex", "ai", runtime_verified=True, version="0.9.1")
write_runner("halopsa.sync", "halopsa")
write_runner("evil.x", "ai", registered_by="an-admin")           # not written by the helper from a manifest
write_runner("mismatch.y", "ai")                                   # id does not start with the owner
(REGISTRY / "ai.liar.json").write_text(json.dumps({"id": "ai.other", "owner_module": "ai", "registered_by": "module-manifest"}), encoding="utf-8")  # id differs from the file
(REGISTRY / "broken.json").write_text("{nope", encoding="utf-8")
(REGISTRY / "readme.txt").write_text("not a row", encoding="utf-8")
write_runner("ai.untrusted", "ai")
NOTROOT.add(norm_path(REGISTRY / "ai.untrusted.json"))
rows = sandbox.status()["runners"]
NOTROOT.discard(norm_path(REGISTRY / "ai.untrusted.json"))
must(rows == [
    {"id": "ai.claude", "owner": "ai", "version": "0.9.0", "runtime_verified": False},
    {"id": "ai.codex", "owner": "ai", "version": "0.9.1", "runtime_verified": True},
    {"id": "halopsa.sync", "owner": "halopsa", "version": "0.9.0", "runtime_verified": False},
], rows)
for name in ("evil.x", "mismatch.y", "ai.untrusted"):
    (REGISTRY / f"{name}.json").unlink()
(REGISTRY / "ai.liar.json").unlink()
(REGISTRY / "broken.json").unlink()
must(len(sandbox.status()["runners"]) == 3, "clean registry")
# a symlinked registry folder lists nothing
SYMLINKS.add(norm_path(REGISTRY))
try:
    must(sandbox.status()["runners"] == [], "a symlinked registry is not listed")
finally:
    SYMLINKS.discard(norm_path(REGISTRY))
# no credential-like key anywhere in status(), whatever the files hold
write_runner("ai.claude", "ai", credentials="s3cret", token="t0ken", password="p")
CRED = re.compile(r"(secret|token|password|credential|apikey|api_key|private|key)", re.IGNORECASE)


def walk_keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.append(key)
            walk_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            walk_keys(item, found)
    return found


keys = walk_keys(sandbox.status(), [])
must(not [key for key in keys if CRED.search(key)], keys)
must("s3cret" not in json.dumps(sandbox.status()) and "t0ken" not in json.dumps(sandbox.status()), "no value leaks")
write_runner("ai.claude", "ai")

# ------------------------------------------------------------------------------------------------ describe()
described = AI(sandbox.describe, "ai.claude")
must(described["id"] == "ai.claude" and described["owner"] == "ai" and described["version"] == "0.9.0" and described["revision"] == "3", described)
must(described["limits"] == {"memory_mb": 1536, "tasks": 256, "run_seconds": 240}, described["limits"])
must(described["executable_sha256"] == "a" * 64 and described["credential_files"] == ["auth"] and described["credential_return"] is True, described)
must(described["runtime_verified"] is False and "runtime_missing" in described["runtime_reason"], described)
text = json.dumps(described)
must("/usr/local/lib" not in text and "/opt/tec-tac" not in text and "LANG" not in text and "--model" not in text, "no path, environment value or argument is returned")
must(set(described) == {"id", "owner", "version", "revision", "description", "limits", "executable_sha256", "credential_files", "credential_return", "runtime_verified", "runtime_reason"}, sorted(described))


def code_of(call, *a):
    try:
        call(*a)
    except sandbox.SandboxError as exc:
        return exc.code
    return None


must(code_of(HALO, sandbox.describe, "ai.claude") == "not_owner", "another module")
must(code_of(HALO, sandbox.describe, "halopsa.sync") is None, "halopsa owns its own runner")
must(code_of(AI, sandbox.describe, "halopsa.sync") == "not_owner", "an id outside the caller's own prefix")
must(code_of(AI, sandbox.describe, "ai.nothing") == "runner_unknown", "an unknown id with the caller's own prefix")
must(code_of(AI, sandbox.describe, "ai.") == "runner_unknown", "bare prefix")
must(code_of(CORE, sandbox.describe, "ai.claude") == "not_owner", "Core is never an owner")
must(code_of(GENERATED, sandbox.describe, "ai.claude") == "not_owner", "a generated frame")
must(code_of(TESTFILE, sandbox.describe, "ai.claude") == "not_owner", "code outside every module (an unverifiable caller)")
must(code_of(OFF, sandbox.describe, "offai.x") == "not_owner", "a disabled module")
must(code_of(OLD, sandbox.describe, "oldai.x") == "not_owner", "a legacy module")
for bad in (None, 5, "", "a b", "../x", "ai.x" * 40, b"ai.claude", ["ai.claude"]):
    must(code_of(AI, sandbox.describe, bad) == "invalid_input", repr(bad))
# a row whose owner is someone else is not described to a caller whose prefix matches the id (id prefix and owner must agree)
write_runner("ai.stolen", "halopsa")      # owner halopsa, id prefix ai: the row itself is refused as malformed
must(code_of(AI, sandbox.describe, "ai.stolen") == "runner_unknown", "malformed row")
must(code_of(HALO, sandbox.describe, "ai.stolen") == "not_owner", "not halopsa's prefix")
(REGISTRY / "ai.stolen.json").unlink()
# an untrusted row behaves like a missing one
NOTROOT.add(norm_path(REGISTRY / "ai.claude.json"))
try:
    must(code_of(AI, sandbox.describe, "ai.claude") == "runner_unknown", "untrusted row")
finally:
    NOTROOT.discard(norm_path(REGISTRY / "ai.claude.json"))
# with no caller module at all the answer is the same refusal (no information leaks)
must(code_of(CORE, sandbox.describe, "ai.nothing") == "not_owner", "Core asking about an unknown id")
# a registry fault never raises anything but SandboxError
must(code_of(AI, sandbox.describe, "ai.claude") is None, "still fine")
# the caller check is made by Core: describe takes no owner argument
import inspect

must(list(inspect.signature(sandbox.describe).parameters) == ["runner_id"], "describe takes only the runner id")

# ------------------------------------------------------------------------------------------------ start, run, cancel
FORBID["on"] = True
try:
    for call, args, kwargs in (
        (sandbox.start, (), {}), (sandbox.start, ("ai.claude",), {"input": b"x", "requested_by": "bob"}), (sandbox.start, ("../../etc/passwd",), {"credentials": {"auth": "x"}}),
        (sandbox.run, (), {}), (sandbox.run, ("ai.claude",), {"input": b"x", "parameters": {"model": "a"}, "user": object()}),
        (sandbox.cancel, (), {}), (sandbox.cancel, ("0" * 32,), {}),
    ):
        for caller in (AI, CORE, HALO, TESTFILE):
            try:
                caller(lambda c=call, a=args, k=kwargs: c(*a, **k))
            except sandbox.SandboxError as exc:
                must(exc.code == "sandbox_disabled" and exc.retry_after is None and "switched off" in exc.message, exc)
            else:
                raise AssertionError(f"{call.__name__} ran")
finally:
    FORBID["on"] = False
for name in ("start", "run", "cancel"):
    source = inspect.getsource(getattr(sandbox, name))
    body = source.split('"""')[2]
    must(body.lstrip().startswith("_check_enabled()") or (name == "run" and body.lstrip().startswith("handle = start(")), f"{name} checks the switch first (run through start)")
must("raise SandboxError" in inspect.getsource(sandbox._check_enabled) and "if not SANDBOX_ENABLED" in inspect.getsource(sandbox._check_enabled), "_check_enabled")
# 1.17.118: with the switch off, nothing is spawned either
sandbox._popen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a process was started while the switch is off"))
# 1.17.118: with the switch on (test only), the real checks run and a refusal never spawns a process
sandbox.SANDBOX_ENABLED = True
try:
    must(code_of(AI, sandbox.start) == "invalid_input" and code_of(CORE, sandbox.start, "ai.claude") == "not_owner" and code_of(HALO, sandbox.start, "ai.claude") == "not_owner", "caller and id checks")
    must(code_of(AI, sandbox.cancel) == "invalid_input" and code_of(CORE, sandbox.cancel, "0" * 32) == "not_owner" and code_of(AI, sandbox.cancel, "0" * 32) == "not_owner", "an unknown run is not_owner")
finally:
    sandbox.SANDBOX_ENABLED = False
# SandboxError
err = sandbox.SandboxError("busy", "Try again.", retry_after=7)
must(err.code == "busy" and err.message == "Try again." and err.retry_after == 7 and str(err) == "busy: Try again.", err)
must(sandbox.SandboxError("oom", "x").retry_after is None, "retry_after defaults to None")
must(sandbox.ERROR_CODES == ("sandbox_disabled", "sandbox_unavailable", "runner_unknown", "runner_disabled", "runtime_unverified", "not_owner", "invalid_input", "input_too_large",
                             "credential_invalid", "busy", "person_busy", "start_failed", "timeout", "output_limit", "oom", "cancelled"), sandbox.ERROR_CODES)

# ------------------------------------------------------------------------------------------------ the capability
del REGISTERED[:]
sandbox.register_core_sandbox_capability()
must(len(REGISTERED) == 1, REGISTERED)
cap = REGISTERED[0]
must(cap["id"] == "core.sandbox" and cap["module_id"] == "core" and cap["version"] == "1.0.0", cap)
must(tuple(cap["operations"]) == ("status", "describe", "start", "run", "cancel"), cap["operations"])
for operation in cap["operations"]:
    must(callable(getattr(cap["provider"], operation)), operation)
must(not [name for name in dir(cap["provider"]) if not name.startswith("_") and name not in cap["operations"]], "the provider offers only the five operations")
meta = cap["metadata"]
must(meta == sandbox.sandbox_contract_metadata() and meta["operations"] == list(cap["operations"]) and meta["version"] == "1.0.0" and meta["enabled"] is False, meta)
must(meta["requires_framework"] == ">=1.17.116" and meta["namespace"] == "tec_tac.sandbox" and "smaller sandbox" in meta["network"], meta)
must(meta["limits"]["memory_mb"] == {"default": 1024, "ceiling": 2048} and meta["limits"]["queue_seconds"] == {"default": 10, "ceiling": 30}, meta["limits"])
must(meta["errors"] == list(sandbox.ERROR_CODES), "errors in the metadata")
# the limits in the contract are the registry's
sys.modules.pop("tec_tac", None)
for name in [n for n in sys.modules if n.startswith("tec_tac.")]:
    sys.modules.pop(name)
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry as real_registry

must({name: (v["default"], v["ceiling"]) for name, v in sandbox.LIMITS.items()} == real_registry.SANDBOX_LIMITS, "contract limits equal the registry's")
apps_source = (APP / "apps.py").read_text(encoding="utf-8")
block = apps_source[apps_source.index("# 1.17.116: core.sandbox"):]
block = block[:block.index('logger.exception("Tec-Tac core.sandbox capability registration failed")')]
must("try:" in block and "from .sandbox import register_core_sandbox_capability" in block and "except Exception:" in block, "its own try/except in apps.py")
must(apps_source.index("core.secrets capability registration failed") < apps_source.index("core.sandbox capability registration failed"), "after core.secrets")

# ------------------------------------------------------------------------------------------------ contract rows
CONTRACTS = (APP / "contracts.py").read_text(encoding="utf-8")
tree = ast.parse(CONTRACTS)
rows = []
for node in ast.walk(tree):
    if isinstance(node, ast.Dict):
        pairs = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if "area" in pairs and isinstance(pairs["area"], ast.Constant) and pairs["area"].value == "sandbox":
            rows.append({k: ast.literal_eval(v) for k, v in pairs.items()})
must(sorted(row["name"] for row in rows) == ["RunHandle", "cancel", "describe", "run", "start", "status"], [row["name"] for row in rows])
for row in rows:
    must(set(row) == {"area", "import_path", "name", "kind", "purpose", "audience"}, row.keys())
    must(row["import_path"] == "tec_tac.sandbox" and row["kind"] == "python" and row["audience"] == "consumer/backend", row)
    floor = "1.17.118" if row["name"] == "RunHandle" else "1.17.116"
    must("additive" in row["purpose"] and "core.sandbox 1.0.0" in row["purpose"] and f"needs framework >={floor}" in row["purpose"] and "AD-63" in row["purpose"], row["name"])
    must(f". Since {floor}" in row["purpose"] and not re.search(r"[A-Za-z0-9)\].]Since 1\.17\.", row["purpose"]), (row["name"], "the 1.17.112 spacing rule"))
    must(hasattr(sandbox, row["name"]) or row["name"] == "RunHandle", row["name"])
by_name = {row["name"]: row["purpose"] for row in rows}
for needle in ("selftest_not_run", "status_unreadable", "enabled is False", "ready is True only when", "slots_total", "canary_ok", "added in 1.17.118, additive"):
    must(needle in by_name["status"], needle)
for needle in ("not_owner", "runner_unknown", "invalid_input", "AD-26"):
    must(needle in by_name["describe"], needle)
must("sandbox_disabled before it reads anything" in by_name["start"] and all(code in by_name["start"] for code in sandbox.ERROR_CODES), "start lists the codes")
for name in ("run", "cancel"):
    must("sandbox_disabled before it reads anything" in by_name[name], name)
for needle in ("events(timeout=None)", "wait(raise_on_failure=False)", "close()", "dead-man", "output_limit", "sandbox.run.ended"):
    must(needle in by_name["RunHandle"], needle)
for needle in ("strict audit row sandbox.run.started", "stdin only", "person_busy", "requested_by", "AD-26"):
    must(needle in by_name["start"], needle)
RULES = next(ast.literal_eval(node.value) for node in ast.parse(CONTRACTS).body if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "RULES")
rule = [text for text in RULES if isinstance(text, str) and text.startswith("Core sandbox (core.sandbox 1.0.0")]
must(len(rule) == 1 and "framework >=1.17.116" in rule[0] and "sandbox.register" in rule[0] and "docs/sandbox-capability.md" in rule[0], rule)
must("core.sandbox.view" in rule[0] and "core.sandbox.manage" in rule[0] and "No module uses core.sandbox yet" in rule[0], "1.17.118 permissions in the rule")
HTTP = next(ast.literal_eval(node.value) for node in ast.parse(CONTRACTS).body if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "HTTP_CONTRACT_DETAILS")
for route, method, perm in (("/api/tfd/system/sandbox/status/", "GET", "core.sandbox.view"), ("/api/tfd/system/sandbox/runs/<str:run_id>/cancel/", "POST", "core.sandbox.manage")):
    must(perm in HTTP[route][method]["authorization"] and "1.17.118" in " ".join(HTTP[route][method]["notes"]), route)
manifest_rule = [text for text in RULES if isinstance(text, str) and text.startswith("Manifest key added in 1.17.116: sandbox_runners")]
must(len(manifest_rule) == 1 and "allowed_hosts is refused" in manifest_rule[0] and "install.sh grants to nobody" in manifest_rule[0] and "A manifest without the key is unchanged." in manifest_rule[0], manifest_rule)
must(not re.search(r"[A-Za-z0-9)\].]Since 1\.17\.", manifest_rule[0] + rule[0]), "spacing")
# the 1.17.17 sentence is still there and the new one is its own sentence next to it
must('"Manifest key added in 1.17.17: server_maintenance_actions' in CONTRACTS, "the 1.17.17 sentence is unchanged")
# the documents
doc = (ROOT / "docs" / "sandbox-capability.md").read_text(encoding="utf-8")
for needle in ("core.sandbox", "sandbox_runners", "sandbox.register", "sandbox_disabled", "smaller sandbox", "allowed_hosts", "1.17.116", "AD-63", "1.17.118", "RunHandle", "core.sandbox.view", "system/sandbox/status"):
    must(needle in doc, needle)
must("docs/sandbox-capability.md" in (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8"), "pointer in capabilities.md")
must("sandbox.register" in (ROOT / "docs" / "trusted-publisher-verification.md").read_text(encoding="utf-8"), "the permission is listed")

print("[TEST] PASS sandbox contract 1.17.116")
