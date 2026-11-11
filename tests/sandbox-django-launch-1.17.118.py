#!/usr/bin/env python3
"""1.17.118 regression: tec_tac/sandbox.py, the launch path on the Django side (core.sandbox Patch 2, part C).

Django-free. The real sandbox.py and caller_identity.py run against temp folders (the technique of sandbox-contract-1.17.116.py); the audit
module is a recorder; the sudo child is a fake process whose stdout carries scripted frames and whose stdin records what Core sends.

Covered: the disabled switch raises before any read or spawn; Core, a library and another module get not_owner; input and credential
limits; a strict audit row that cannot be written stops the start and spawns nothing; the header carries credentials on stdin only and never
in argv, environment or audit metadata; frame order, partial UTF-8 across frames, error mapping with retry_after; closing the handle closes
the helper's pipes (dead-man); wait and run results (credentials_out, truncated flags, raise_on_failure); cancel (owner only) and the
person cancel; status keys (additive, the live flag, canary); the two view files check their permissions; the rbac group; the routes.

Not runnable here: Django, sudo and the real helper.
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
import threading
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


def write_status(**over):
    payload = {"ready": True, "reason": "ready", "enabled": False, "systemd_version": 252, "address_filter_ok": True, "dns_ok": True,
               "selftest_at": "2026-11-11T10:00:00Z", "slots_total": 3}
    payload.update(over)
    sandbox.STATUS_FILE.write_text(json.dumps(payload), encoding="utf-8")


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


# ------------------------------------------------------------------------------------------------ disabled: nothing is read or spawned
sandbox._popen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a process was started"))
must(sandbox.SANDBOX_ENABLED is False, "off")
FORBID["on"] = True
try:
    for caller in (AI, CORE, HALO, LIBRARY):
        for call, args, kwargs in ((sandbox.start, ("ai.claude",), {"input": b"x", "requested_by": "bob"}), (sandbox.run, ("ai.claude",), {"credentials": {"auth": "x"}}),
                                   (sandbox.cancel, (RUN_ID,), {}), (sandbox.start, (), {}), (sandbox.cancel_by_person, (RUN_ID,), {"user": object()})):
            try:
                caller(lambda c=call, a=args, k=kwargs: c(*a, **k))
            except sandbox.SandboxError as exc:
                must(exc.code == "sandbox_disabled", exc.code)
            else:
                raise AssertionError("a launch call ran while the switch is off")
finally:
    FORBID["on"] = False
must(not AUDIT, "no audit row while disabled")
sandbox.SANDBOX_ENABLED = True   # from here on the switch is on, in this test only


def start_as(caller, runner="ai.claude", **kw):
    return caller(sandbox.start, runner, **kw)


GOOD = {"requested_by": "alice@example.com", "input": b"hello", "parameters": {"model": "a"}, "credentials": {"auth": "tok-1"}}
# ---- who may start
for who, name in ((CORE, "core"), (LIBRARY, "a library"), (HALO, "another module")):
    must(code_of(start_as, who, **GOOD) == "not_owner", name)
sandbox._popen = fake_popen([])
must(code_of(start_as, AI, "halopsa.x", **GOOD) == "not_owner" and code_of(start_as, AI, "ai.missing", **GOOD) == "runner_unknown", "ids")
must(code_of(start_as, AI, "../x", **GOOD) == "invalid_input" and code_of(start_as, AI, None, **GOOD) == "invalid_input" and code_of(start_as, AI, 7, **GOOD) == "invalid_input", "bad ids")
write_runner("halopsa.sync", "halopsa")
must(code_of(start_as, HALO, "ai.claude", **GOOD) == "not_owner" and code_of(start_as, AI, "halopsa.sync", **GOOD) == "not_owner", "a module cannot start another's runner")
must(not SPAWNED and not AUDIT, "nothing spawned or audited by those refusals")
# ---- readiness
write_status(ready=False, reason="no cgroup v2")
must(code_of(start_as, AI, **GOOD) == "sandbox_unavailable", "not ready")
write_status()
write_runner(runtime_verified=False)
must(code_of(start_as, AI, **GOOD) == "runtime_unverified", "unverified runtime")
write_runner()
# ---- input, parameters, credentials
must(code_of(start_as, AI, **{**GOOD, "input": b"x" * 1025}) == "input_too_large", "input over input_kib")
must(code_of(start_as, AI, **{**GOOD, "input": 5}) == "invalid_input" and code_of(start_as, AI, **{**GOOD, "input": ["x"]}) == "invalid_input", "input type")
must(code_of(start_as, AI, **{**GOOD, "parameters": ["x"]}) == "invalid_input", "parameters type")
must(code_of(start_as, AI, **{**GOOD, "credentials": {"other": "x"}}) == "credential_invalid", "undeclared credential")
must(code_of(start_as, AI, **{**GOOD, "credentials": {"auth": "x" * (16 * 1024 + 1)}}) == "credential_invalid", "credential over 16 KiB")
must(code_of(start_as, AI, **{**GOOD, "credentials": {"auth": 5}}) == "credential_invalid" and code_of(start_as, AI, **{**GOOD, "credentials": ["auth"]}) == "credential_invalid", "credential type")
must(code_of(start_as, AI, **{**GOOD, "credentials": {"Auth": "x"}}) == "credential_invalid", "credential name shape")
must(code_of(start_as, AI, **{k: v for k, v in GOOD.items() if k != "requested_by"}) == "invalid_input", "no person at all")
must(code_of(start_as, AI, **{**GOOD, "requested_by": "a\nb"}) == "invalid_input" and code_of(start_as, AI, **{**GOOD, "requested_by": "x" * 200}) == "invalid_input", "bad requested_by")
must(not SPAWNED and not AUDIT, "validation failures spawn and audit nothing")
# ---- the strict audit row stops the start
AUDIT_FAIL["on"] = True
must(code_of(start_as, AI, **GOOD) == "start_failed" and not SPAWNED, "a run that cannot be audited does not start")
AUDIT_FAIL["on"] = False
must(not [row for row in AUDIT if row["metadata"]["event"] == "sandbox.run.started"], "and no started row exists")

# ------------------------------------------------------------------------------------------------ a good run
FRAMES = frames_ok({"t": "out", "b": b64("héllo".encode()[:2]), "truncated": False}, {"t": "out", "b": b64("héllo".encode()[2:]), "truncated": False},
                   {"t": "err", "b": b64(b"warn"), "truncated": True}, cred=b64(b"refreshed-tok"))
sandbox._popen = fake_popen(FRAMES)
AUDIT.clear()
SECRET = "tok-" + os.urandom(8).hex()
handle = start_as(AI, requested_by="alice@example.com", input="hé".encode(), parameters={"model": "a"}, credentials={"auth": SECRET})
proc = SPAWNED[-1]
must(proc.argv == ["sudo", "-n", "/usr/local/sbin/tec-tac-sandbox", "--start"], proc.argv)
must(proc.kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"} and SECRET not in json.dumps(proc.argv) and SECRET not in json.dumps(proc.kwargs, default=str), "never in argv or env")
header_line, _, rest = proc.stdin.data.partition(b"\n")
header = json.loads(header_line)
must(rest == "hé".encode() and header["input_bytes"] == len(rest) and header["runner_id"] == "ai.claude" and header["parameters"] == {"model": "a"}, header)
must(re.fullmatch(r"[0-9a-f]{32}", header["run_id"]) and header["person"] == "by:alice@example.com", header)
must(base64.b64decode(header["credentials"]["auth"]).decode() == SECRET and set(header) == {"runner_id", "run_id", "person", "parameters", "credentials", "input_bytes"}, "credentials on stdin only")
must(proc.stdin.closed is False, "stdin stays open as the liveness line")
must(handle.run_id == header["run_id"] and handle.run_id in sandbox._RUNS, "tracked")
# the audit row before the launch, strict, without secret, input or output
started = [row for row in AUDIT if row["metadata"]["event"] == "sandbox.run.started"]
must(len(started) == 1 and started[0]["strict"] is True and started[0]["module_id"] == "core" and started[0]["object_type"] == "sandbox_run" and started[0]["object_id"] == handle.run_id, started)
must(started[0]["action"] == "run" and started[0]["metadata"]["credential_names"] == ["auth"] and started[0]["metadata"]["parameter_names"] == ["model"], started[0]["metadata"])
must(SECRET not in json.dumps(AUDIT, default=str) and "hé" not in json.dumps(AUDIT, default=str, ensure_ascii=False), "no credential or input in any audit row")
must(started[0]["actor"].kind == "service" and started[0]["actor"].module_id == "core", "service actor without a signed-in user")
# events in order, partial UTF-8 across frames
events = list(handle.events())
must([e["t"] for e in events] == ["started", "out", "out", "err", "end"], events)
must(b"".join(e["data"] for e in events if e["t"] == "out").decode("utf-8") == "héllo", "partial UTF-8 joins")
must(events[3]["truncated"] is True and events[1]["truncated"] is False, "truncated flag")
end = events[-1]
must(end["exit_code"] == 0 and end["reason"] == "exited" and end["duration_ms"] == 1200 and end["peak_mb"] == 40.5 and end["credentials_out"] == {"auth": "refreshed-tok"}, end)
must(proc.stdin.closed and handle.run_id not in sandbox._RUNS, "the pipes are closed at the end and the run is forgotten")
ended = [row for row in AUDIT if row["metadata"]["event"] == "sandbox.run.ended"]
must(len(ended) == 1 and ended[0]["action"] == "custom:sandbox-run-ended" and ended[0]["strict"] is False and ended[0]["metadata"]["reason"] == "exited" and ended[0]["metadata"]["exit_code"] == 0, ended)
must("refreshed-tok" not in json.dumps(AUDIT, default=str) and "bytes_out" in ended[0]["metadata"], "no output or credential in the ended row")
must(list(handle.events()) == [], "a finished run yields nothing more")
# wait()/run()
sandbox._popen = fake_popen(FRAMES)
result = AI(sandbox.run, "ai.claude", **GOOD)
must(result["stdout"] == "héllo" and result["stderr"] == "warn" and result["exit_code"] == 0 and result["reason"] == "exited" and result["credentials_out"] == {"auth": "refreshed-tok"}, result)
must(result["stderr_truncated"] is True and result["stdout_truncated"] is False and result["duration_ms"] == 1200 and result["peak_mb"] == 40.5 and result["run_id"], result)
must(set(result) == {"run_id", "exit_code", "stdout", "stderr", "reason", "duration_ms", "peak_mb", "credentials_out", "stdout_truncated", "stderr_truncated"}, result.keys())
must(SPAWNED[-1].stdin.closed and not SPAWNED[-1].killed, "run() closes the helper's pipes")
# every non-exited reason keeps the partial output and can raise
for reason in ("timeout", "output_limit", "oom", "cancelled"):
    sandbox._popen = fake_popen(frames_ok({"t": "out", "b": b64(b"part"), "truncated": reason == "output_limit"}, reason=reason, exit_code=None))
    h = start_as(AI, **GOOD)
    r = h.wait()
    must(r["reason"] == reason and r["stdout"] == "part" and r["exit_code"] is None, (reason, r))
    sandbox._popen = fake_popen(frames_ok(reason=reason, exit_code=None))
    h = start_as(AI, **GOOD)
    must(code_of(h.wait, raise_on_failure=True) == reason, reason)
sandbox._popen = fake_popen(frames_ok(reason="start_failed", exit_code=None))
h = start_as(AI, **GOOD)
must(h.wait()["reason"] == "start_failed" and code_of(start_as(AI, **GOOD).wait, raise_on_failure=True) == "start_failed", "start_failed")
sandbox._popen = fake_popen([{"t": "started"}, {"t": "end", "exit": "x", "reason": "weird", "ms": "x", "peak_mb": True, "credential_b64": 7}])
h = start_as(AI, **GOOD)
r = h.wait()
must(r["reason"] == "start_failed" and r["exit_code"] is None and r["duration_ms"] is None and r["peak_mb"] is None and r["credentials_out"] is None, r)
# junk frames are skipped; a helper that stops without an end is start_failed
sandbox._popen = fake_popen([{"t": "started"}, {"t": "bogus"}, {"t": "out", "b": "!!!notbase64", "truncated": False}, {"t": "out", "b": b64(b"ok"), "truncated": False}])
h = start_as(AI, **GOOD)
r = h.wait()
must(r["stdout"] == "ok" and r["reason"] == "start_failed", r)
# no credential_return: credentials_out stays None even if a frame carries one
write_runner("ai.nocred", credential_return=False)
sandbox._popen = fake_popen(frames_ok(cred=b64(b"smuggled")))
must(start_as(AI, "ai.nocred", requested_by="bob").wait()["credentials_out"] is None, "credentials_out only when the runner declares credential_return")
# events(timeout)
class Slow(FakeProc):
    def __init__(self):
        super().__init__([{"t": "started"}])
        self.gate = threading.Event()
        r_fd, w_fd = os.pipe()
        self.stdout = os.fdopen(r_fd, "rb")
        self._w = os.fdopen(w_fd, "wb")
        self._w.write(b'{"t":"started"}\n')
        self._w.flush()

    def finish(self):
        self._w.write(b'{"t":"end","exit":0,"reason":"exited","ms":1}\n')
        self._w.flush()
        self._w.close()


slow = Slow()
sandbox._popen = lambda argv, **k: slow
h = start_as(AI, **GOOD)
it = h.events(timeout=0.2)
must(next(it)["t"] == "started", "")
try:
    next(it)
    raise AssertionError("no timeout")
except TimeoutError:
    pass
slow.finish()
must([e["t"] for e in h.events(timeout=5)] == ["end"], "the run goes on after a TimeoutError")

# ------------------------------------------------------------------------------------------------ helper refusals map to codes
for code in ("busy", "person_busy"):
    AUDIT.clear()
    sandbox._popen = fake_popen(refusal(code, 7))
    try:
        start_as(AI, **GOOD)
        raise AssertionError("started")
    except sandbox.SandboxError as exc:
        must(exc.code == code and exc.retry_after == 7 and exc.message, exc)
    must(SPAWNED[-1].stdin.closed, "the helper is closed after a refusal")
    refused = [row for row in AUDIT if row["metadata"]["event"] == "sandbox.run.refused"]
    must(len(refused) == 1 and refused[0]["action"] == "deny" and refused[0]["metadata"]["code"] == code and refused[0]["metadata"]["retry_after"] == 7, refused)
for code in ("sandbox_unavailable", "runtime_unverified", "runner_unknown", "start_failed", "invalid_input", "input_too_large", "credential_invalid"):
    sandbox._popen = fake_popen(refusal(code, 5))
    try:
        start_as(AI, **GOOD)
        raise AssertionError("started")
    except sandbox.SandboxError as exc:
        must(exc.code == code and exc.retry_after is None, (code, exc.retry_after))   # retry_after only for busy and person_busy
sandbox._popen = fake_popen(refusal("made_up_code"))
must(code_of(start_as, AI, **GOOD) == "start_failed", "an unknown helper code is start_failed")
sandbox._popen = fake_popen([])
must(code_of(start_as, AI, **GOOD) == "start_failed", "a helper that says nothing")
sandbox._popen = fake_popen([{"t": "wat"}])
must(code_of(start_as, AI, **GOOD) == "start_failed", "an unexpected first frame")
sandbox._popen = lambda *a, **k: (_ for _ in ()).throw(OSError("no sudo"))
AUDIT.clear()
must(code_of(start_as, AI, **GOOD) == "start_failed" and any(r["metadata"]["event"] == "sandbox.run.refused" for r in AUDIT), "sudo missing")
# a mid-run refusal frame raises on events
sandbox._popen = fake_popen([{"t": "started"}, {"t": "refused", "code": "busy"}])
h = start_as(AI, **GOOD)
must(code_of(lambda: list(h.events())) == "busy", "")

# ------------------------------------------------------------------------------------------------ person for the per-person slot
class Person:
    is_authenticated = True
    pk = 41
    username = "carol"


sandbox._popen = fake_popen(frames_ok())
h = start_as(AI, requested_by="ignored", user=Person(), input=b"")
must(json.loads(SPAWNED[-1].stdin.data.partition(b"\n")[0])["person"] == "user:41", "the authenticated user wins over requested_by")
must(AUDIT[-1]["actor"].__class__ is Person or any(r["actor"].__class__ is Person for r in AUDIT[-3:]), "the user is the audit actor")
h.close()
sandbox._popen = fake_popen(frames_ok())
h = start_as(AI, user=type("Anon", (), {"is_authenticated": False, "pk": 1})(), requested_by="bob")
must(json.loads(SPAWNED[-1].stdin.data.partition(b"\n")[0])["person"] == "by:bob", "an anonymous user falls back to requested_by")
h.close()

# ------------------------------------------------------------------------------------------------ the dead-man switch: close()
sandbox._popen = fake_popen([{"t": "started"}])
h = start_as(AI, **GOOD)
proc = SPAWNED[-1]
must(proc.stdin.closed is False, "")
h.close()
must(proc.stdin.closed is True and h.run_id not in sandbox._RUNS, "closing the handle closes the helper's stdin: that stops the unit")
h.close()   # twice is safe
must([r["metadata"]["reason"] for r in AUDIT if r["metadata"]["event"] == "sandbox.run.ended"][-1] == "cancelled", "an unfinished run closed by its owner is recorded as cancelled")

# ------------------------------------------------------------------------------------------------ cancel
STOPS = []


class Done:
    def __init__(self, out):
        self.stdout, self.returncode = out, 0


def fake_run(argv, **kwargs):
    STOPS.append((list(argv), kwargs))
    return Done(json.dumps({"t": "stopped", "run_id": kwargs["input"].decode().strip()}).encode() + b"\n" if STOPS_MODE["v"] == "ok" else json.dumps({"t": "refused", "code": "runner_unknown"}).encode() + b"\n")


STOPS_MODE = {"v": "ok"}
real_run = sandbox.subprocess.run
sandbox.subprocess.run = fake_run
try:
    sandbox._popen = fake_popen([{"t": "started"}])
    h = start_as(AI, **GOOD)
    AUDIT.clear()
    must(code_of(CORE, sandbox.cancel, h.run_id) == "not_owner" and code_of(HALO, sandbox.cancel, h.run_id) == "not_owner" and code_of(AI, sandbox.cancel, "0" * 32) == "not_owner", "cancel is the owner's")
    must(code_of(AI, sandbox.cancel, "nope") == "invalid_input" and code_of(AI, sandbox.cancel, None) == "invalid_input", "bad ids")
    must(not STOPS, "no helper call for a refused cancel")
    AI(sandbox.cancel, h.run_id)
    must(STOPS[-1][0] == ["sudo", "-n", "/usr/local/sbin/tec-tac-sandbox", "--stop"] and STOPS[-1][1]["input"] == h.run_id.encode() + b"\n", "the id goes on stdin")
    cancelled = [r for r in AUDIT if r["metadata"]["event"] == "sandbox.run.cancelled"]
    must(len(cancelled) == 1 and cancelled[0]["action"] == "custom:sandbox-run-cancelled" and cancelled[0]["metadata"]["by"] == "module", cancelled)
    h.close()
    h2 = start_as(AI, **GOOD)
    h2.cancel()
    must(STOPS[-1][1]["input"] == h2.run_id.encode() + b"\n", "handle.cancel()")
    h2.close()
    # the person's cancel (the route): any run id, the person's audit row
    AUDIT.clear()
    sandbox.cancel_by_person("f" * 32, user=Person())
    must(AUDIT[-1]["metadata"]["by"] == "person" and AUDIT[-1]["actor"].__class__ is Person, AUDIT)
    must(code_of(sandbox.cancel_by_person, "../x", user=Person()) == "invalid_input", "")
    STOPS_MODE["v"] = "no"
    must(code_of(sandbox.cancel_by_person, "e" * 32, user=Person()) == "runner_unknown", "a run the helper does not know")
finally:
    sandbox.subprocess.run = real_run

# ------------------------------------------------------------------------------------------------ status keys
sandbox.SANDBOX_ENABLED = False
write_status(slots_total=4)
answer = sandbox.status()
must(set(answer) == {"enabled", "ready", "reason", "systemd_version", "address_filter_ok", "dns_ok", "selftest_at", "slots_total", "slots_used", "canary_ok", "canary_at", "runners"}, sorted(answer))
must(answer["slots_total"] == 4 and answer["slots_used"] is None and answer["canary_ok"] is False and answer["canary_at"] is None, answer)
(STATE / "canary.json").write_text(json.dumps({"ok": True, "at": "2026-11-12T08:00:00Z"}), encoding="utf-8")
answer = sandbox.status()
must(answer["canary_ok"] is True and answer["canary_at"] == "2026-11-12T08:00:00Z", answer)
(STATE / "canary.json").write_text(json.dumps({"ok": "yes", "at": 5}), encoding="utf-8")
answer = sandbox.status()
must(answer["canary_ok"] is False and answer["canary_at"] is None, "only True counts")
NOTROOT.add(norm_path(STATE / "canary.json"))
must(sandbox.status()["canary_ok"] is False, "a canary file that is not root-owned is not believed")
NOTROOT.discard(norm_path(STATE / "canary.json"))
(STATE / "canary.json").write_text("{nope", encoding="utf-8")
must(sandbox.status()["canary_ok"] is False, "corrupt canary file")
write_status(slots_total="many")
must(sandbox.status()["slots_total"] is None, "a non-number slots_total is None")
write_status(slots_total=-3)
must(sandbox.status()["slots_total"] is None, "")
# live: one sudo --status call, 3 s, slot numbers; without it None; failures leave None
calls = []


def live_run(argv, **kwargs):
    calls.append((list(argv), kwargs))
    return Done(json.dumps({"status": {"slots_total": 3, "slots_used": 2}, "runners": []}).encode().decode() if False else json.dumps({"status": {"slots_total": 3, "slots_used": 2}, "runners": []}))


sandbox.subprocess.run = lambda argv, **kwargs: (calls.append((list(argv), kwargs)), SimpleNamespace(stdout=json.dumps({"status": {"slots_total": 3, "slots_used": 2}}), returncode=0))[1]
try:
    answer = sandbox.status(live=True)
    must(answer["slots_total"] == 3 and answer["slots_used"] == 2 and len(calls) == 1, answer)
    must(calls[0][0] == ["sudo", "-n", "/usr/local/sbin/tec-tac-sandbox", "--status"] and calls[0][1]["timeout"] == 3, calls)
    calls.clear()
    must(sandbox.status()["slots_used"] is None and not calls, "no call without live")
    sandbox.subprocess.run = lambda argv, **kwargs: (_ for _ in ()).throw(OSError("no sudo"))
    must(sandbox.status(live=True)["slots_used"] is None, "a failed live call is None, never an exception")
    sandbox.subprocess.run = lambda argv, **kwargs: SimpleNamespace(stdout="not json", returncode=0)
    must(sandbox.status(live=True)["slots_used"] is None, "")
    sandbox.subprocess.run = lambda argv, **kwargs: SimpleNamespace(stdout=json.dumps({"status": {"slots_used": True}}), returncode=0)
    must(sandbox.status(live=True)["slots_used"] is None, "a bool is not a count")
finally:
    sandbox.subprocess.run = real_run
must("credential" not in json.dumps(sandbox.status()).lower() and "token" not in json.dumps(sandbox.status()).lower(), "status holds nothing credential-like")

# ------------------------------------------------------------------------------------------------ views, permissions, routes, rbac, contracts
views = (APP / "sandbox_views.py").read_text(encoding="utf-8")
must("can_view_sandbox(request.user)" in views and "can_manage_sandbox(request.user)" in views and views.count("PermissionDenied(") == 2, "each view checks its permission")
must(views.index("can_view_sandbox") < views.index("sandbox.status(live=True)") and views.index("can_manage_sandbox(request.user)") < views.index("sandbox.cancel_by_person"), "the check comes first")
must("SessionAuthenticated" in views and views.count("permission_classes = [SessionAuthenticated]") == 2, "signed in")
must('"sandbox_disabled": 409' in views and "status=202" in views, "codes")
urls = (APP / "urls.py").read_text(encoding="utf-8")
must('path("system/sandbox/status/", SandboxStatusView.as_view()' in urls and 'path("system/sandbox/runs/<str:run_id>/cancel/", SandboxRunCancelView.as_view()' in urls, "routes under system/")
must("core/sandbox" not in urls, "no core/ prefix")
rbac = (APP / "rbac.py").read_text(encoding="utf-8").replace("\r\n", "\n")
must('CORE_SANDBOX_VIEW_PERMISSION = "core.sandbox.view"' in rbac and 'CORE_SANDBOX_MANAGE_PERMISSION = "core.sandbox.manage"' in rbac, "codes")
must('"Sandbox": (CORE_SANDBOX_VIEW_PERMISSION, CORE_SANDBOX_MANAGE_PERMISSION),' in rbac, "the group")
must("def can_view_sandbox(user)" in rbac and "def can_manage_sandbox(user)" in rbac and "is_effective_superuser(user)" in rbac.split("def _has_core_permission")[1].split("def can_view_sandbox")[0], "superuser passes (AD-10)")
must(rbac.count("CORE_PERMISSION_GROUPS = {") == 1 and rbac.index('"Site resource management"') < rbac.index('"Sandbox"'), "existing groups first, unchanged")
for line in (APP / "rbac.py").read_bytes().split(b"\n")[:-1]:
    must(line.endswith(b"\r"), "rbac.py keeps its CRLF line endings")
for name in ("contracts.py",):
    must(all(line.endswith(b"\r") for line in (APP / name).read_bytes().split(b"\n")[:-1]), f"{name} keeps its CRLF line endings")
# the two permission codes are valid core permission names
must(re.fullmatch(r"core\.[a-z_.]+", "core.sandbox.view") and re.fullmatch(r"core\.[a-z_.]+", "core.sandbox.manage"), "")
# the provider and metadata
meta = sandbox.sandbox_contract_metadata()
must(meta["version"] == "1.0.0" and meta["enabled"] is False and set(meta["permissions"]) == {"core.sandbox.view", "core.sandbox.manage"} and len(meta["routes"]) == 2, meta)
must(meta["operations"] == ["status", "describe", "start", "run", "cancel"] and "1.17.118" in meta["notes"] and "1.17.118" in meta["audit"], meta)
must(sandbox.CAPABILITY_VERSION == "1.0.0" and sandbox.SANDBOX_ENABLED is False, "the contract version stays 1.0.0 and the switch is off")
must(re.search(r"^SANDBOX_ENABLED = False$", (APP / "sandbox.py").read_text(encoding="utf-8"), re.MULTILINE), "a constant in the file")
src = (APP / "sandbox.py").read_text(encoding="utf-8")
must("env={}" not in src and 'shell=True' not in src and "os.system" not in src, "no shell, no inherited environment")
must(src.count("_check_enabled()") >= 4, "every launch entry checks the switch")

print("[TEST] PASS sandbox django launch 1.17.118")
