#!/usr/bin/env python3
"""1.18.28 regression: core.sandbox is switched on (shipped constant True) and fails closed (AD-65 amendment; Johan, 20 November 2026).

Django-free, sockets stubbed, nothing listens, no public address, nothing runs as root. The harness is the one of sandbox-django-launch-1.18.27.py
(the real sandbox.py and caller_identity.py against temp folders, a recording audit module, a fake sudo child).

Covered: both kill-switch constants are True; status() on a trusted ready file gives enabled, ready and active True; on a missing, untrusted or
not-ready file enabled True, ready False, active False and a plain reason; start() and run() with a not-ready status raise sandbox_not_ready, write
one sandbox.run.refused row with that code (not strict) and never call the helper; with ready True the same call reaches the helper stub and the strict
sandbox.run.started row is written first; cancel() and cancel_by_person() with a not-ready status still reach the helper's stop; the helper's
ready_status() raises sandbox_not_ready (a Django bug cannot skip the check) and keeps the skeleton_changed text; the helper's read_status() keeps
enabled True; the selftest status carries enabled from the constant; sandbox_views maps sandbox_not_ready to 503; the contract metadata says enabled
True at 1.1.0; install.sh no longer asserts the off state. Main stays held (said in the release notes).
"""
from __future__ import annotations

import base64
import importlib
import io
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


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ the fake file-system layer
def norm_path(path):
    return os.path.normcase(os.path.abspath(str(path)))


NOTROOT, FD_PATH, OPENED = set(), {}, []
FORBID = {"on": False}
_real = {name: getattr(os, name) for name in ("stat", "lstat", "fstat", "open")}
_VISIBLE = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")


def _fake(st, path):
    perms = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
    fields = list(st)[:10]
    fields[0], fields[4] = stat.S_IFMT(st.st_mode) | perms, (1000 if norm_path(path) in NOTROOT else 0)
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
    return _fake(_real["lstat"](path, *a, **k), path)


os.stat = lambda path, *a, **k: _fake(_real["stat"](path, *a, **k), path)
os.lstat = _lstat
os.fstat = lambda fd: _fake(_real["fstat"](fd), FD_PATH.get(fd, "?"))
os.open = _open


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


TMP = Path(tempfile.mkdtemp(prefix="tectac-sandbox-django-"))
EXT = TMP / "extensions"
EXT.mkdir()
PLUGINS = {}
AUDIT = []
AUDIT_FAIL = {"on": False}


def plugin(plugin_id, *, enabled=True):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="1.0.0", legacy=False, category="premium", enabled=enabled)


def audit_record(**kw):
    if AUDIT_FAIL["on"] and kw.get("strict"):
        raise RuntimeError("audit write failed")
    AUDIT.append(kw)
    return {"recorded": True}


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=lambda: tuple(PLUGINS.values()))
pkg.module_state = mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: PLUGINS[module_id].enabled if module_id in PLUGINS else True)
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kw: SimpleNamespace(**kw))
pkg.audit = mod("tec_tac.audit", record=audit_record, service_audit_actor=lambda **kw: SimpleNamespace(kind="service", **kw))
sandbox = importlib.import_module("tec_tac.sandbox")
plugin("ai")
plugin("halopsa")


def compile_as(filename, source):
    ns = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


CALL = "def call(fn, *a, **k):\n    return fn(*a, **k)\n"
AI = compile_as(str(EXT / "ai" / "service.py"), CALL)["call"]
HALO = compile_as(str(EXT / "halopsa" / "service.py"), CALL)["call"]
CORE = compile_as(str(APP / "scheduler.py"), CALL)["call"]
LIBRARY = compile_as(str(Path(importlib.__file__)), CALL)["call"]

LIB = TMP / "lib"
REGISTRY, STATE = LIB / "registry", TMP / "state"
REGISTRY.mkdir(parents=True)
STATE.mkdir()
sandbox.REGISTRY_ROOT, sandbox.STATUS_FILE, sandbox.CANARY_FILE = REGISTRY, STATE / "status.json", STATE / "canary.json"
sandbox.VERSION_FILE = STATE / "VERSION"


def write_status(**over):
    payload = {"ready": True, "reason": "ready", "enabled": False, "systemd_version": 252, "address_filter_ok": True, "dns_ok": True,
               "selftest_at": "2026-11-11T10:00:00Z", "slots_total": 3}
    payload.update(over)
    sandbox.STATUS_FILE.write_text(json.dumps(payload), encoding="utf-8")
    sandbox.VERSION_FILE.write_text("1.18.28\n", encoding="utf-8")
    sandbox.CANARY_FILE.write_text(json.dumps({"ok": True, "at": "2026-11-11T10:05:00Z", "core_version": "1.18.28",
                                               "selftest_at": payload.get("selftest_at") if isinstance(payload, dict) else None}), encoding="utf-8")  # active needs a canary for this build and selftest


def write_runner(runner_id="ai.claude", owner="ai", **over):
    row = {
        "id": runner_id, "owner_module": owner, "version": "0.9.0", "revision": "3", "description": "Run the Claude program",
        "executable": "/x/claude.sh", "executable_sha256": "a" * 64, "argv": [], "environment": {}, "credential_files": ["auth"], "credential_return": True,
        "limits": {"memory_mb": 1024, "input_kib": 1, "queue_seconds": 2}, "runtime_verified": True, "runtime_reason": "", "runtime_roots": [],
        "registered_by": "module-manifest",
    }
    row.update(over)
    (REGISTRY / f"{runner_id}.json").write_text(json.dumps(row), encoding="utf-8")


write_status()
write_runner()
RUN_ID = "0123456789abcdef" * 2


# ------------------------------------------------------------------------------------------------ a fake sudo child
class FakeStdin:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        if self.closed:
            raise ValueError("closed")
        self.data += data

    def flush(self):
        pass

    def close(self):
        self.closed = True


class FakeProc:
    def __init__(self, frames):
        lines = b"".join(json.dumps(f, separators=(",", ":")).encode() + b"\n" for f in frames)
        self.stdin = FakeStdin()
        self.stdout = io.BytesIO(lines)
        self.killed = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def b64(data):
    return base64.b64encode(data).decode()


def frames_ok(*mid, reason="exited", exit_code=0, cred=None):
    return [{"t": "started", "run_id": "x", "unit": "u"}, *mid,
            {"t": "end", "exit": exit_code, "reason": reason, "ms": 1200, "peak_mb": 40.5, "credential_b64": cred, "bytes_out": 5, "bytes_err": 0}]


SPAWNED = []


def fake_popen(frames):
    def popen(argv, **kwargs):
        proc = FakeProc(frames)
        proc.argv, proc.kwargs = argv, kwargs
        SPAWNED.append(proc)
        return proc
    return popen


def refusal(code, retry_after=None):
    frame = {"t": "refused", "code": code, "message": "x"}
    if retry_after is not None:
        frame["retry_after"] = retry_after
    return [frame]


def code_of(call, *a, **k):
    try:
        call(*a, **k)
    except sandbox.SandboxError as exc:
        return exc.code
    return None



import importlib.util
import inspect

SH = importlib.util.spec_from_file_location("sandbox_helper_switch_on", ROOT / "scripts" / "sandbox-helper.py")
helper = importlib.util.module_from_spec(SH)
SH.loader.exec_module(helper)

GOOD = {"requested_by": "alice@example.com", "input": b"hello", "parameters": {}, "credentials": {"auth": "tok-1"}}


def start_as(caller, runner="ai.claude", **kw):
    return caller(sandbox.start, runner, **kw)


# ---- the constants
# 1.18.28 (AD-65 amendment, Johan, 20 November 2026): the shipped kill switch is on. The 1.18.27 readiness gate is the guard. The off path is proven with the constants forced to False.
must(sandbox.SANDBOX_ENABLED is True and helper.SANDBOX_ENABLED is True, "both shipped constants are True (AD-65 amendment, Johan, 20 November 2026)")
for name, text in (("sandbox.py", (APP / "sandbox.py").read_text(encoding="utf-8")), ("sandbox-helper.py", (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8"))):
    must(re.search(r"^SANDBOX_ENABLED = True$", text, re.MULTILINE) and "SANDBOX_ENABLED = False" not in text, name)
# forced off: every call is refused with sandbox_disabled and nothing reaches the helper
sandbox.SANDBOX_ENABLED = False
helper.SANDBOX_ENABLED = False
SPAWNED_BEFORE = len(SPAWNED)
for fn, args in ((sandbox.start, ("ai.claude",)), (sandbox.run, ("ai.claude",)), (sandbox.cancel, ("run-1",))):
    must(code_of(fn, *args) == "sandbox_disabled", ("refused while off", fn.__name__))
must(len(SPAWNED) == SPAWNED_BEFORE, "nothing reached the helper while off")
FORCED_OFF_META = sandbox.sandbox_contract_metadata()
must(FORCED_OFF_META["enabled"] is False, "forced off, the contract metadata says enabled False")
sandbox.SANDBOX_ENABLED = True
helper.SANDBOX_ENABLED = True
must(sandbox.sandbox_contract_metadata()["enabled"] is True, "the shipped contract metadata says enabled True")
must(sandbox.CAPABILITY_VERSION == "1.1.0" and "sandbox_not_ready" in sandbox.ERROR_CODES, "capability 1.1.0 with the new code")

# ---- status(): enabled, ready, active
write_status()
answer = sandbox.status()
must(answer["enabled"] is True and answer["ready"] is True and answer["active"] is True and answer["reason"] == "ready", answer)
write_status(ready=False, reason="the server does not use the unified cgroup v2 hierarchy")
answer = sandbox.status()
must(answer["enabled"] is True and answer["ready"] is False and answer["active"] is False and answer["reason"].startswith("the server does not use"), answer)
sandbox.STATUS_FILE.unlink()
answer = sandbox.status()
must(answer["enabled"] is True and answer["ready"] is False and answer["active"] is False and answer["reason"] == "selftest_not_run", answer)
write_status()
NOTROOT.add(norm_path(sandbox.STATUS_FILE))
try:
    answer = sandbox.status()
finally:
    NOTROOT.discard(norm_path(sandbox.STATUS_FILE))
must(answer["enabled"] is True and answer["ready"] is False and answer["active"] is False and answer["reason"] == "status_unreadable", ("untrusted file", answer))
write_status(ready="yes")
must(sandbox.status()["active"] is False, "a wrong type is never ready")
write_status()
must(sandbox.status()["active"] is True, "trusted again")

# ---- start() and run() with a not-ready status: refused, audited, the helper never called
sandbox._popen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the helper was started for a not-ready server"))
for label, make_unready in (("ready false", lambda: write_status(ready=False, reason="no cgroup v2")), ("missing", lambda: sandbox.STATUS_FILE.unlink(missing_ok=True)),
                            ("unreadable", lambda: sandbox.STATUS_FILE.write_text("{nope", encoding="utf-8"))):
    for entry in ("start", "run"):
        AUDIT.clear()
        del SPAWNED[:]
        make_unready()
        call = getattr(sandbox, entry)
        try:
            AI(call, "ai.claude", **GOOD)
        except sandbox.SandboxError as exc:
            must(exc.code == "sandbox_not_ready" and exc.retry_after is None and exc.message, (label, entry, exc.code))
        else:
            raise AssertionError((label, entry, "ran on a not-ready server"))
        must(len(AUDIT) == 1, (label, entry, AUDIT))
        row = AUDIT[0]
        must(row["metadata"]["event"] == "sandbox.run.refused" and row["metadata"]["code"] == "sandbox_not_ready" and row["action"] == "deny" and not row.get("strict")
             and row["object_type"] == "sandbox_run" and re.fullmatch(r"[0-9a-f]{32}", row["object_id"]) and row["metadata"]["runner"] == "ai.claude"
             and row["metadata"]["owner_module"] == "ai", row)
        must("tok-1" not in json.dumps(row, default=str) and "hello" not in json.dumps(row, default=str), "no credential and no input in the row")
        must(not SPAWNED, "no helper process")
# a ready selftest is not enough: a passed canary for this build and selftest run is part of ready (AD-65)
CANARY_TEXT = "the sandbox canary has not passed on this server"
for label, make_canary in (("missing", lambda: sandbox.CANARY_FILE.unlink(missing_ok=True)),
                           ("ok false", lambda: sandbox.CANARY_FILE.write_text(json.dumps({"ok": False, "at": "2026-11-11T10:05:00Z"}), encoding="utf-8")),
                           ("ok not True", lambda: sandbox.CANARY_FILE.write_text(json.dumps({"ok": "yes"}), encoding="utf-8")),
                           ("unreadable", lambda: sandbox.CANARY_FILE.write_text("{nope", encoding="utf-8"))):
    for entry in ("start", "run"):
        write_status()
        make_canary()
        AUDIT.clear()
        del SPAWNED[:]
        try:
            AI(getattr(sandbox, entry), "ai.claude", **GOOD)
        except sandbox.SandboxError as exc:
            must(exc.code == "sandbox_not_ready" and CANARY_TEXT in exc.message, (label, entry, exc.code, exc.message))
        else:
            raise AssertionError((label, entry, "ran without a passed canary"))
        must(len(AUDIT) == 1 and AUDIT[0]["metadata"]["event"] == "sandbox.run.refused" and AUDIT[0]["metadata"]["code"] == "sandbox_not_ready" and not SPAWNED, (label, entry, AUDIT))
NOTROOT.add(norm_path(sandbox.CANARY_FILE))
write_status()
sandbox.CANARY_FILE.write_text(json.dumps({"ok": True}), encoding="utf-8")
NOTROOT.add(norm_path(sandbox.CANARY_FILE))
must(code_of(start_as, AI, **GOOD) == "sandbox_not_ready", "a canary file that is not root-owned is not believed")
NOTROOT.discard(norm_path(sandbox.CANARY_FILE))
write_status()  # a passed canary again
# another module still gets not_owner first (it learns nothing about readiness)
must(code_of(start_as, HALO, **GOOD) == "not_owner" and code_of(start_as, CORE, **GOOD) == "not_owner", "caller checks come before readiness")
# with ready True the same call reaches the helper stub, and the strict started row comes first
write_status()
AUDIT.clear()
sandbox._popen = fake_popen([{"t": "started"}])
handle = start_as(AI, **GOOD)
must(len(SPAWNED) == 1 and AUDIT and AUDIT[0]["metadata"]["event"] == "sandbox.run.started" and AUDIT[0].get("strict") is True, AUDIT)
handle.close()
AUDIT.clear()
sandbox._popen = fake_popen(frames_ok({"t": "out", "b": b64(b"hi")}))
result = AI(sandbox.run, "ai.claude", **GOOD)
must(result["reason"] == "exited" and AUDIT[0]["metadata"]["event"] == "sandbox.run.started", "run reaches the helper when ready")

# ---- cancel is never gated by readiness
STOPS = []


class Done:
    def __init__(self, out):
        self.stdout, self.returncode = out, 0


def fake_run(argv, **kwargs):
    STOPS.append((list(argv), kwargs))
    return Done(json.dumps({"t": "stopped", "run_id": kwargs["input"].decode().strip()}).encode() + b"\n")


class Person:
    is_authenticated = True
    pk = 7


real_run = sandbox.subprocess.run
sandbox.subprocess.run = fake_run
try:
    sandbox._popen = fake_popen([{"t": "started"}])
    live = start_as(AI, **GOOD)
    write_status(ready=False, reason="a run left a new entry in the skeleton")  # the state recheck_skeleton_after_run can leave behind
    AUDIT.clear()
    AI(sandbox.cancel, live.run_id)
    must(STOPS and STOPS[-1][1]["input"] == live.run_id.encode() + b"\n", "cancel() reached the helper's stop with a not-ready status")
    sandbox.cancel_by_person("f" * 32, user=Person())
    must(STOPS[-1][1]["input"] == b"f" * 32 + b"\n", "cancel_by_person() reached the helper's stop with a not-ready status")
    must([r["metadata"]["event"] for r in AUDIT] == ["sandbox.run.cancelled", "sandbox.run.cancelled"], AUDIT)
    live.close()
finally:
    sandbox.subprocess.run = real_run
    write_status()
# the cancel code has no readiness check at all
for name in ("cancel", "cancel_by_person"):
    must("status()" not in inspect.getsource(getattr(sandbox, name)), name + " does not read the status")
start_source = inspect.getsource(sandbox.start)
must(start_source.index("_registry_row(") < start_source.index("status()") < start_source.index("runtime_verified"), "readiness comes right after the caller and runner checks")

# ---- the helper: ready_status() cannot be skipped, read_status() keeps enabled True
real_read = helper.read_status
for payload in ({"ready": False, "reason": "x", "enabled": False}, {"reason": "no ready key"}, {"ready": "yes"}):
    helper.read_status = lambda p=payload: p
    try:
        helper.ready_status()
    except helper.Refusal as exc:
        must(exc.code == "sandbox_not_ready" and "selftest has not passed" in exc.message, (payload, exc.code, exc.message))
        must(exc.frame()["code"] == "sandbox_not_ready", "the frame carries the code")
    else:
        raise AssertionError(("ready_status passed", payload))
helper.read_status = lambda: {"ready": False, "skeleton_changed": True, "reason": "a run left the entry var/leftover in the sandbox root"}
try:
    helper.ready_status()
except helper.Refusal as exc:
    must(exc.code == "sandbox_not_ready" and exc.message == "a run left the entry var/leftover in the sandbox root", "the skeleton_changed text is kept")
else:
    raise AssertionError("skeleton_changed passed")
READY_STATUS = {"ready": True, "enabled": True, "selftest_at": "2026-11-11T10:00:00Z"}
helper.read_status = lambda: dict(READY_STATUS)
# the helper wants a passed canary for this Core build and selftest run too (a real --start); the canary's own launches ask for ready only
real_trusted_canary = helper._read_trusted_file
GOOD_CANARY = {"ok": True, "core_version": "1.18.28", "selftest_at": "2026-11-11T10:00:00Z"}


def fake_files(canary_text, version_text="1.18.28\n"):
    def trusted(path, what, max_bytes):
        text = version_text if Path(str(path)).name == "VERSION" else canary_text
        if text is None:
            raise OSError("missing")
        return text.encode()
    return trusted


for label, text in (("missing", None), ("ok false", json.dumps({**GOOD_CANARY, "ok": False})), ("corrupt", "{nope"), ("no version", json.dumps({"ok": True})),
                    ("other version", json.dumps({**GOOD_CANARY, "core_version": "1.18.27"})), ("other selftest", json.dumps({**GOOD_CANARY, "selftest_at": "2026-11-11T09:00:00Z"})),
                    ("version not text", json.dumps({**GOOD_CANARY, "core_version": 1})), ("selftest not text", json.dumps({**GOOD_CANARY, "selftest_at": 5}))):
    helper._read_trusted_file = fake_files(text)
    try:
        helper.ready_status()
    except helper.Refusal as exc:
        must(exc.code == "sandbox_not_ready" and exc.message == CANARY_TEXT, (label, exc.code, exc.message))
    else:
        raise AssertionError((label, "ready_status passed without a passed canary"))
    must(helper.ready_status(canary_required=False) == READY_STATUS, "the canary's own launch needs ready only: " + label)
helper._read_trusted_file = fake_files(json.dumps(GOOD_CANARY), version_text=None)  # an unreadable VERSION file fails closed
try:
    helper.ready_status()
except helper.Refusal as exc:
    must(exc.code == "sandbox_not_ready", exc.code)
else:
    raise AssertionError("passed with an unreadable VERSION file")
helper._read_trusted_file = fake_files(json.dumps(GOOD_CANARY))
must(helper.ready_status() == READY_STATUS, "ready passes with a canary for this build and selftest run")
helper._read_trusted_file = real_trusted_canary
helper.read_status = real_read
# read_status(): the constant counts, not the file
real_trusted = helper._read_trusted_file
helper._read_trusted_file = lambda path, what, max_bytes: json.dumps({"ready": True, "enabled": False}).encode()
try:
    must(helper.read_status()["enabled"] is True and helper.read_status()["ready"] is True, "read_status keeps enabled True even if the file says False")
finally:
    helper._read_trusted_file = real_trusted


def _unreadable(path, what, max_bytes):
    raise RuntimeError("unreadable")


helper._read_trusted_file = _unreadable
try:
    answer = helper.read_status()
    must(answer["enabled"] is True and answer["ready"] is False, "the unreadable answer says enabled True and not ready")
finally:
    helper._read_trusted_file = real_trusted
must("forced to False" in helper.refuse_disabled.__doc__, "the forced-off path is still in the file")

# ---- the selftest status carries enabled from the constant
selftest_text = (ROOT / "scripts" / "sandbox-selftest.py").read_text(encoding="utf-8")
must('"enabled": bool(H.SANDBOX_ENABLED)' in selftest_text and '"enabled": False' not in selftest_text, "enabled comes from the helper's constant")

# ---- the route maps the code to 503
views = (APP / "sandbox_views.py").read_text(encoding="utf-8")
must('"sandbox_not_ready": 503' in views and '"sandbox_unavailable": 503' in views and '"sandbox_disabled": 409' in views, "views")
must(views.count("PermissionDenied(") == 2 and "can_manage_sandbox" in views and "can_view_sandbox" in views, "no new permission, the same two checks")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must(urls.count("sandbox/") == 2 and "sandbox/toggle" not in urls and "sandbox/enable" not in urls, "no new route, no toggle")

# ---- the contract
meta = sandbox.sandbox_contract_metadata()
must(meta["enabled"] is True and FORCED_OFF_META["enabled"] is False and meta["version"] == "1.1.0" and "sandbox_not_ready" in meta["errors"] and "1.18.28: the kill switch is on" in meta["notes"] and "canary_ok" in meta["notes"], meta)
must("sandbox_disabled before they read anything" not in meta["notes"], "the old off wording is gone")
must(meta["requires_framework"] == ">=1.17.116" and set(meta["permissions"]) == {"core.sandbox.view", "core.sandbox.manage"} and len(meta["routes"]) == 2, "framework floor, permissions and routes unchanged")
doc = (ROOT / "docs" / "sandbox-capability.md").read_text(encoding="utf-8")
must("1.1.0" in doc and "sandbox_not_ready" in doc and "`active`" in doc and "Nothing runs in Core 1.17.118" not in doc and "still off" not in doc, "the document")
must("`SANDBOX_ENABLED` is `True`" in doc and "since Core 1.18.28" in doc, "the document says the switch is on")

# ---- install.sh
install = (ROOT / "install.sh").read_text(encoding="utf-8")
verify = install[install.index("VERIFY_SANDBOX_CODE="):]
verify = verify[:verify.index('"\nrun_verify_step "Core sandbox capability"')]
must("st['enabled'] is bool(SANDBOX_ENABLED)" in verify and "st['enabled'] is True" not in verify and "('not_owner' if SANDBOX_ENABLED else 'sandbox_disabled')" in verify, "VERIFY_SANDBOX_CODE")
must("The sandbox switch is on; a run can start only after the canary has passed for this Core build and this selftest run." in install, "the install log line says on")
must(b"\r" not in (ROOT / "install.sh").read_bytes(), "install.sh keeps its LF line endings")
for name in ("sandbox.py", "sandbox_views.py"):
    must(b"\r" not in (APP / name).read_bytes(), name + " keeps its LF line endings")
for name in ("sandbox-helper.py", "sandbox-selftest.py"):
    must(b"\r" not in (ROOT / "scripts" / name).read_bytes(), name + " keeps its LF line endings")
must(all(line.endswith(b"\r") for line in (APP / "contracts.py").read_bytes().split(b"\n")[:-1]), "contracts.py keeps its CRLF line endings")

print("[TEST] PASS sandbox switch on 1.18.28")
