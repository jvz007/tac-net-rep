#!/usr/bin/env python3
"""1.17.47 core.event_jobs 1.1.0: every publish verifies its caller (CQ134 b, AD-36), and the helper's opt-in snapshot.

The real tec_tac/event_jobs.py, event_jobs_policy.py and caller_identity.py run against a temporary extensions folder. Real frames are
compiled under a stub plugin's folder (the technique of tests/caller-identity-core-provider-1.17.27.py), so the real frame walk decides.
Stubbed: Django's transaction and connection, the registry, the module state, and the row store (``_persist_safely`` records what would
be stored). The database, broker and worker side are tests/event-jobs-1.17.45.py and tests/event-jobs-caller-runtime-1.17.47.py.

Covered: the owning module's own code publishes (queued); another module that calls the handle it got from the owner's private code, a test
file, a library frame, a generated frame, a Core frame (the Scheduler), functools.partial run by Core, a disabled module, a legacy module,
a registry fault and a state fault are all refused with ``error``, never raise, store nothing and touch neither _RECENT nor _RATE; a disabled
owner still answers ``disabled``; the check runs once in publish and not again in the commit hook; the refusal warning is throttled; the
snapshot: 100 publishes in a window cost one plugin scan and one state read, the next window one more of each, an unreadable state is read
once a window and fails closed, a module disabled mid-window is accepted until the window ends while the worker's uncached check still
refuses it, and ``cache_seconds=0`` re-reads on every call; the capability, the metadata, the contract rows and the docs; the cost, printed.
"""
from __future__ import annotations

import functools
import importlib.util
import json
import logging
import sys
import tempfile
import time
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
SCHEDULER_FILE = str(APP / "scheduler.py")


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


MONO = [1000.0]
TMP = Path(tempfile.mkdtemp(prefix="tectac-eventjobs-caller-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
ENABLED: dict = {}
STATE = {"registry_error": False, "state_error": False}
SCANS = [0]
STATE_READS = [0]  # is_enabled(module_id) with no state: the caller helper's read
LOADS = [0]  # load_state(): event_jobs' own read for its 5 second cache


def plugin(plugin_id, *, enabled=True, legacy=False):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="2.0.0", legacy=legacy)
    ENABLED[plugin_id] = enabled
    return root


def discover_plugins():
    SCANS[0] += 1
    if STATE["registry_error"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def load_state():
    LOADS[0] += 1
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return {"schema": 1, "modules": {}}


def is_enabled(module_id, state=None):
    if state is None:
        STATE_READS[0] += 1
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return ENABLED.get(module_id, True)


# ------------------------------------------------------------------------------------------------ Django stubs
CONNECTION = SimpleNamespace(in_atomic_block=False, vendor="sqlite")
COMMIT_HOOKS = []
mod("django")
mod("django.db", IntegrityError=type("IntegrityError", (Exception,), {}), connection=CONNECTION,
    transaction=SimpleNamespace(atomic=lambda: None, on_commit=COMMIT_HOOKS.append))
mod("django.utils")
mod("django.utils.timezone", now=lambda: None)
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.registry", discover_plugins=discover_plugins)
mod("tec_tac.module_state", load_state=load_state, is_enabled=is_enabled)
CAPS = []
mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or SimpleNamespace(**kw))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, APP / file)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ci = load("tec_tac.caller_identity", "caller_identity.py")
policy = load("tec_tac.event_jobs_policy", "event_jobs_policy.py")
ej = load("tec_tac.event_jobs", "event_jobs.py")
for clocked in (ej._RECENT, ej._RATE, ej._BREAKER, ej._GAUGES, ej._ENABLED):
    clocked.clock = lambda: MONO[0]
ci._clock = lambda: MONO[0]
ej.time = SimpleNamespace(monotonic=lambda: MONO[0], time=time.time, sleep=time.sleep)

STORED = []
ej._persist_safely = lambda definition, key, payload: STORED.append((definition.id, key)) or "queued"
CHECKS = [0]  # how often a publish reached the caller helper (a wrapper around the check itself would add a frame of this file)
_real_snapshot = ci._snapshot


def counting_snapshot(seconds):
    CHECKS[0] += 1
    return _real_snapshot(seconds)


ci._snapshot = counting_snapshot
_real_check = ej._verified_caller_ok


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


FIRE = "def fire(handle, key):\n    return handle.publish(key)\n"
alerts_root = plugin("alerts")
plugin("beta")
plugin("gamma", enabled=False)
plugin("oldmod", legacy=True)
alerts = compile_as(str(alerts_root / "signals.py"), FIRE + "def deliver(context):\n    return None\n")
beta = compile_as(str(EXT / "beta" / "x.py"), FIRE)
gamma = compile_as(str(EXT / "gamma" / "x.py"), FIRE)
oldmod = compile_as(str(EXT / "oldmod" / "x.py"), FIRE)
core_frame = compile_as(SCHEDULER_FILE, FIRE + "def run_partial(fn):\n    return fn()\n")  # a Core-owned file name
lib = compile_as(str(LIB / "decorator.py"), FIRE)
generated = compile_as("<string>", FIRE)

KEYN = [0]


def key():
    KEYN[0] += 1
    return f"k{KEYN[0]}"


def reset():
    ej._clear_for_tests()
    del STORED[:], COMMIT_HOOKS[:]
    CHECKS[0] = 0
    STATE.update(registry_error=False, state_error=False)
    ENABLED.update(alerts=True, beta=True, gamma=False, oldmod=True)
    CONNECTION.in_atomic_block = False
    MONO[0] += 1000
    SCANS[0] = STATE_READS[0] = LOADS[0] = 0


def register():
    return ej.register_event_job(id="alerts.deliver", module_id="alerts", label="Send an alert notice", handler=alerts["deliver"])


REFUSED = ("error", "the caller is not the module that owns this job")
UNVERIFIED = ("error", "the caller could not be verified")  # 1.17.48: a read fault is told apart from a foreign caller


def outcome(result):
    return (result.outcome, result.reason)


def untouched():
    return not ej._RECENT._seen and not ej._RATE._windows and not STORED and not COMMIT_HOOKS


# ------------------------------------------------------------------------------------------------ (1) the owner publishes, others do not
reset()
handle = register()
r = alerts["fire"](handle, key())
must(r.outcome == "queued" and len(STORED) == 1 and STORED[0][0] == "alerts.deliver", r)
print("       the owning module's own code publishes: queued")

for name, fn in (("another module", beta["fire"]), ("a library frame", lib["fire"]), ("a generated frame", generated["fire"]),
                 ("a Core frame (the Scheduler)", core_frame["fire"]), ("a disabled module", gamma["fire"]), ("a legacy module", oldmod["fire"])):
    reset()
    handle = register()
    before = list(ej._RECENT._seen)
    r = fn(handle, key())
    must(outcome(r) == REFUSED, (name, r))
    must(untouched() and list(ej._RECENT._seen) == before, f"{name}: nothing stored, nothing counted")
    must(not ej._COUNTERS, f"{name}: no counter")
print("       another module, a library, a generated frame, a Core frame, a disabled and a legacy module are refused with error")

reset()
handle = register()
r = handle.publish(key())  # this test file is outside every module
must(outcome(r) == REFUSED and untouched(), r)
print("       a publish from a test file (outside every module) is refused")

reset()
handle = register()
r = core_frame["run_partial"](functools.partial(handle.publish, key()))
must(outcome(r) == REFUSED and untouched(), r)
r = core_frame["run_partial"](functools.partial(alerts["fire"], handle, key()))  # a partial of the owner's code, run by Core: the owner's frame is the caller
must(r.outcome == "queued", r)
print("       a functools.partial run by Core is refused; a partial of the owner's own function is the owner's call")

# the module B that imported the owner's private code: B's own code calls the handle -> B is the caller
reset()
handle = register()
leaked = alerts["fire"]
r = beta["fire"](handle, key())
must(outcome(r) == REFUSED and untouched(), r)
print("       a module that obtained the handle from another module's private code is refused")

# faults never raise and refuse
reset()
handle = register()
STATE["registry_error"] = True
r = alerts["fire"](handle, key())
must(outcome(r) == UNVERIFIED and untouched(), r)
reset()
handle = register()
ej._ENABLED.set("alerts", True)  # event_jobs' own cache is warm, so the helper is the one that meets the state fault
STATE["state_error"] = True
r = alerts["fire"](handle, key())
must(outcome(r) == UNVERIFIED and untouched(), r)
print("       a registry fault and a state fault refuse the publish: no raise, nothing stored, nothing counted")

# a disabled owner still answers disabled, with no stack walk
reset()
handle = register()
ENABLED["alerts"] = False
CHECKS[0] = 0
r = alerts["fire"](handle, key())
must(r.outcome == "disabled" and CHECKS[0] == 0 and untouched(), (r, CHECKS[0]))
r = beta["fire"](handle, key())
must(r.outcome == "disabled" and CHECKS[0] == 0, "even another module's publish on a disabled owner answers disabled first")
print("       a disabled owner still answers disabled before any caller check")

# a foreign handle is still refused before the caller check
reset()
register()
r = ej._publish(object(), key(), None)
must(r.outcome == "error" and r.reason == "not a registered publisher" and CHECKS[0] == 0, r)
print("       a handle that is not a registered publisher is refused first")

# the check is in publish, not in the commit hook
reset()
handle = register()
CONNECTION.in_atomic_block = True
r = alerts["fire"](handle, key())
must(r.outcome == "queued" and not STORED and len(COMMIT_HOOKS) == 1 and CHECKS[0] == 1, (r, CHECKS[0]))
CONNECTION.in_atomic_block = False
for hook in COMMIT_HOOKS:  # the commit runs the hook from a Core-side frame; it must not be refused
    hook()
must(len(STORED) == 1 and CHECKS[0] == 1, "the row is stored at commit and the check did not run again")
reset()
handle = register()
CONNECTION.in_atomic_block = True
r = beta["fire"](handle, key())
must(outcome(r) == REFUSED and not COMMIT_HOOKS, "another module inside a transaction is refused, no hook is registered")
print("       the check runs once, in publish; the commit hook is not refused and does not run it again")

# the refusal warning is throttled
logs = []


class Catch(logging.Handler):
    def emit(self, record):
        logs.append(record.getMessage())


catch = Catch()
ej.logger.addHandler(catch)
ej.logger.setLevel(logging.WARNING)
logging.disable(logging.NOTSET)
try:
    reset()
    handle = register()
    for _ in range(50):
        beta["fire"](handle, key())
    lib["fire"](handle, key())
    refused_logs = [m for m in logs if "refused" in m]
    must(len(refused_logs) == 2, refused_logs)  # one for beta, one for the unverified library frame
    MONO[0] += 61
    beta["fire"](handle, key())
    must(len([m for m in logs if "refused" in m]) == 3, "a minute later it logs again")
    must(all(("k1" not in m) for m in logs), "the log line names no key")
finally:
    logging.disable(logging.CRITICAL)
    ej.logger.removeHandler(catch)
print("       the refusal warning is logged once per job and caller a minute at most")

# ------------------------------------------------------------------------------------------------ (2) the snapshot
reset()
handle = register()
SCANS[0] = STATE_READS[0] = 0
for _ in range(100):
    must(alerts["fire"](handle, key()).outcome == "queued", "accepted")
must(SCANS[0] == 1 and STATE_READS[0] == 1, (SCANS[0], STATE_READS[0]))
MONO[0] += 5
for _ in range(100):
    alerts["fire"](handle, key())
must(SCANS[0] == 2 and STATE_READS[0] == 2, (SCANS[0], STATE_READS[0]))
print("       100 publishes in a window cost 1 plugin scan and 1 state read; the next window 1 more of each")

# an unreadable state is read once per window, refused, and never raises
reset()
handle = register()
SCANS[0] = STATE_READS[0] = 0
STATE["state_error"] = True
for _ in range(20):
    ej._ENABLED.set("alerts", True)
    must(outcome(alerts["fire"](handle, key())) == UNVERIFIED, "could not be verified")
must(STATE_READS[0] == 1 and SCANS[0] == 1, (STATE_READS[0], SCANS[0]))
STATE["state_error"] = False
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED, "still inside the failed-read second: fail closed")
MONO[0] += 5
ej._ENABLED.set("alerts", True)
must(alerts["fire"](handle, key()).outcome == "queued" and STATE_READS[0] == 2, "the next window reads again and recovers")
# an unreadable registry is cached for the window too
reset()
handle = register()
SCANS[0] = 0
STATE["registry_error"] = True
for _ in range(20):
    alerts["fire"](handle, key())
must(SCANS[0] == 1, SCANS[0])
print("       an unreadable state or registry is read once a window, refused, and recovers in the next window")

# a module disabled mid-window is accepted until the window ends; the worker's uncached check refuses it at once
reset()
handle = register()
must(alerts["fire"](handle, key()).outcome == "queued", "warm")
ENABLED["alerts"] = False
must(alerts["fire"](handle, key()).outcome == "queued", "still recognised inside the window")
must(ej._module_status_now("alerts") == ej.UNAVAILABLE and ej._module_runnable_now("alerts") is False, "the worker's uncached check skips it")
MONO[0] += 5
must(alerts["fire"](handle, key()).outcome == "disabled", "after the window it answers disabled")
# a module installed in the last window is refused until the snapshot expires
reset()
handle = register()
must(alerts["fire"](handle, key()).outcome == "queued", "warm")
new_root = plugin("newcomer")
newcomer = compile_as(str(new_root / "x.py"), FIRE)
must(outcome(newcomer["fire"](handle, key())) == REFUSED, "refused: and it is not the owner anyway")
print("       a module disabled mid-window is accepted until the window ends and the worker still skips it")

# cache_seconds=0 reads on every call (the other four Core providers)
reset()
PROVIDER = compile_as(str(APP / "event_jobs.py"), f"def ask(ci, **kw):\n    return ci.calling_module_for_core_provider(provider_file={str(APP / 'event_jobs.py')!r}, **kw)\n")
CALL = compile_as(str(alerts_root / "svc.py"), "def call(fn, ci, **kw):\n    return fn(ci, **kw)\n")
SCANS[0] = STATE_READS[0] = 0
for _ in range(5):
    got = CALL["call"](PROVIDER["ask"], ci)
    must(got is not None and got.module_id == "alerts", got)
must(SCANS[0] == 5 and STATE_READS[0] == 5, (SCANS[0], STATE_READS[0]))
SCANS[0] = STATE_READS[0] = 0
for bad in (0, -3, "x", None, float("nan"), float("inf")):
    CALL["call"](PROVIDER["ask"], ci, cache_seconds=bad)
must(SCANS[0] == 6 and STATE_READS[0] == 6, "a zero, negative, non-number, NaN or infinite cache_seconds means no cache")
SCANS[0] = STATE_READS[0] = 0
for _ in range(5):
    CALL["call"](PROVIDER["ask"], ci, cache_seconds=5)
must(SCANS[0] == 1 and STATE_READS[0] == 1, "opt-in caches")
ci.clear_snapshot_for_tests()
CALL["call"](PROVIDER["ask"], ci, cache_seconds=5)
must(SCANS[0] == 2, "the test hook clears the snapshot")
print("       cache_seconds=0 (the default) re-reads on every call; a bad value means no cache")

# the public calling_module and every other provider never use the snapshot
src = (APP / "caller_identity.py").read_text(encoding="utf-8")
must("_snapshot(" not in src.split("def _calling_module")[1].split("def calling_module_for_core_provider")[0], "calling_module is never cached")
for name in ("accounts.py", "resources.py", "audit.py", "module_preferences.py", "tactical_websocket.py"):
    p = APP / name
    if p.exists():
        must("cache_seconds" not in p.read_text(encoding="utf-8"), f"{name} stays uncached")
must("cache_seconds=policy.ENABLED_CACHE_SECONDS" in (APP / "event_jobs.py").read_text(encoding="utf-8"), "event_jobs opts in with the 5 second window")
print("       the public calling_module and the other Core providers stay uncached; event_jobs opts in")

# ------------------------------------------------------------------------------------------------ (2b) 1.17.48: a short fault costs 1 second, not 5
def warm_owner():
    ej._ENABLED.set("alerts", True)  # event_jobs' own cache is warm, so the helper is the one that meets a state fault


# a scan fault at T refuses the owner with the new reason; T+0.5 still; T+1 re-scans and succeeds
reset()
handle = register()
SCANS[0] = STATE_READS[0] = 0  # registration scanned the registry once itself
STATE["registry_error"] = True
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED and SCANS[0] == 1, "scan fault at T")
STATE["registry_error"] = False
MONO[0] += 0.5
warm_owner()
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED and SCANS[0] == 1, "T+0.5 s is still the same fault, no new scan")
MONO[0] += 0.5
warm_owner()
must(alerts["fire"](handle, key()).outcome == "queued" and SCANS[0] == 2, "T+1 s re-scans and the owner publishes again")
MONO[0] += 4.5
alerts["fire"](handle, key())
must(SCANS[0] == 2, "the good snapshot then lasts its full 5 seconds")
print("       a scan fault costs the owner at most 1 second: refused at T and T+0.5, re-scanned and accepted at T+1")

# the same for a state-read fault
reset()
handle = register()
SCANS[0] = STATE_READS[0] = 0
warm_owner()
STATE["state_error"] = True
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED, "state fault at T")
STATE["state_error"] = False
MONO[0] += 0.5
warm_owner()
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED and STATE_READS[0] == 1, "T+0.5 s: no new read")
MONO[0] += 0.5
warm_owner()
must(alerts["fire"](handle, key()).outcome == "queued" and STATE_READS[0] == 2, "T+1 s reads again and accepts")
print("       a state-read fault costs the owner at most 1 second")

# a corrupt state is a fault, not 'disabled': the module reads as disabled and the state says _corrupt
CORRUPT = [False]
_real_load = load_state


def load_state_corrupt():
    LOADS[0] += 1
    return {"schema": 1, "modules": {}, "_corrupt": True} if CORRUPT[0] else {"schema": 1, "modules": {}}


sys.modules["tec_tac.module_state"].load_state = load_state_corrupt
sys.modules["tec_tac.module_state"].is_enabled = lambda module_id, state=None: (
    False if CORRUPT[0] else (STATE_READS.__setitem__(0, STATE_READS[0] + (state is None)) or ENABLED.get(module_id, True)))
reset()
handle = register()
warm_owner()
CORRUPT[0] = True
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED, "a corrupt state is a fault")
CORRUPT[0] = False
MONO[0] += 0.5
warm_owner()
must(outcome(alerts["fire"](handle, key())) == UNVERIFIED, "T+0.5 s")
MONO[0] += 0.5
warm_owner()
must(alerts["fire"](handle, key()).outcome == "queued", "T+1 s recovers")
sys.modules["tec_tac.module_state"].load_state = load_state
sys.modules["tec_tac.module_state"].is_enabled = is_enabled
print("       a corrupt module state is a fault (could not be verified), not 'disabled', and recovers after 1 second")

# a foreign caller still answers the foreign reason; a fault never does; the helper tells them apart
reset()
handle = register()
must(outcome(beta["fire"](handle, key())) == REFUSED, "foreign caller")
STATE["registry_error"] = True
ci.clear_snapshot_for_tests()
must(outcome(beta["fire"](handle, key())) == UNVERIFIED and outcome(alerts["fire"](handle, key())) == UNVERIFIED, "a fault answers the fault reason for any caller")
STATE["registry_error"] = False
MONO[0] += 1
CHECK_FILE = str(APP / "event_jobs.py")
ASK = compile_as(CHECK_FILE, f"def ask(ci, **kw):\n    return ci.core_provider_caller_checked(provider_file={CHECK_FILE!r}, **kw)\n")
CALLFROM = {name: compile_as(str(root / "svc.py"), "def call(fn, ci, **kw):\n    return fn(ci, **kw)\n") for name, root in
            (("alerts", alerts_root), ("beta", EXT / "beta"), ("gamma", EXT / "gamma"), ("oldmod", EXT / "oldmod"))}
CALLFROM["lib"] = compile_as(str(LIB / "svc.py"), "def call(fn, ci, **kw):\n    return fn(ci, **kw)\n")
CALLFROM["generated"] = compile_as("<string>", "def call(fn, ci, **kw):\n    return fn(ci, **kw)\n")
CALLFROM["core"] = compile_as(SCHEDULER_FILE, "def call(fn, ci, **kw):\n    return fn(ci, **kw)\n")
reset()
for who, ident, unv in (("alerts", "alerts", False), ("beta", "beta", False), ("gamma", None, False), ("oldmod", None, False),
                        ("lib", None, False), ("generated", None, False), ("core", None, False)):
    for seconds in (0, 5):
        ci.clear_snapshot_for_tests()
        got = CALLFROM[who]["call"](ASK["ask"], ci, cache_seconds=seconds)
        must((got.identity.module_id if got.identity else None) == ident and got.unverifiable is unv, (who, seconds, got))
for kind in ("registry_error", "state_error"):
    for seconds in (0, 5):
        STATE.update(registry_error=False, state_error=False)
        STATE[kind] = True
        ci.clear_snapshot_for_tests()
        got = CALLFROM["alerts"]["call"](ASK["ask"], ci, cache_seconds=seconds)
        must(got.identity is None and got.unverifiable is True, (kind, seconds, got))
        plain = CALLFROM["alerts"]["call"](PROVIDER["ask"], ci, cache_seconds=seconds)
        must(plain is None, "the old helper still answers None on a fault")
STATE.update(registry_error=False, state_error=False)
ci.clear_snapshot_for_tests()
got = CALLFROM["alerts"]["call"](PROVIDER["ask"], ci)
must(got is not None and got.module_id == "alerts", "the old helper still returns the identity for a good call")
print("       the private helper tells a read fault (unverifiable) from every real answer; calling_module_for_core_provider still answers None for both")

# the two warnings are separate and each throttled; a fault adds no audit tally
logs = []
catch = Catch()
logging.getLogger("tec_tac.caller_identity").addHandler(logging.NullHandler())  # the helper warns too; keep it off stderr
ej.logger.addHandler(catch)
ej.logger.setLevel(logging.WARNING)
logging.disable(logging.NOTSET)
try:
    reset()
    handle = register()
    beta["fire"](handle, key())
    ci.clear_snapshot_for_tests()
    STATE["registry_error"] = True
    for _ in range(30):
        MONO[0] += 0.01
        alerts["fire"](handle, key())
    STATE["registry_error"] = False
    unver = [m for m in logs if "could not be verified" in m]
    must(len(unver) == 1 and "alerts.deliver" in unver[0] and "was not stored" in unver[0], unver)
    must(len([m for m in logs if "was refused" in m]) == 1, "the foreign-caller warning was not hidden by the fault warning")
    MONO[0] += 61
    ci.clear_snapshot_for_tests()
    STATE["registry_error"] = True
    alerts["fire"](handle, key())
    must(len([m for m in logs if "could not be verified" in m]) == 2, "the fault warning is throttled to a minute")
    must(all("k1" not in m for m in logs), "no key in any warning")
finally:
    logging.disable(logging.CRITICAL)
    ej.logger.removeHandler(catch)
    STATE["registry_error"] = False
print("       the fault warning and the refusal warning are separate, each throttled to a minute, and name no key")

# ------------------------------------------------------------------------------------------------ (3) capability, metadata, docs
reset()
ej.register_core_event_jobs_capability()
must(CAPS[0]["version"] == "1.1.0" and policy.CAPABILITY_VERSION == "1.1.0" and ej.CAPABILITY_VERSION == "1.1.0", CAPS[0]["version"])
meta = CAPS[0]["metadata"]
must(meta["requires_framework"] == ">=1.17.47" and "AD-36" in meta["caller"] and "5 seconds" in meta["caller"], meta.get("caller"))
import ast

rows = {}
for node in ast.parse((APP / "contracts.py").read_text(encoding="utf-8")).body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "CORE_CONTRACTS" for t in node.targets):
        rows = {r["name"]: r for r in ast.literal_eval(node.value) if r.get("area") == "event-jobs"}
must(set(rows) == {"register_event_job", "EventJobPublisher", "verify_event_job_context"}, sorted(rows))
must("core.event_jobs 1.1.0" in rows["register_event_job"]["purpose"] and "requires.framework >=1.17.47" in rows["register_event_job"]["purpose"], "register row")
pub = rows["EventJobPublisher"]["purpose"]
must("1.1.0" in pub and "AD-36" in pub and "verifies its caller" in pub and "the caller is not the module that owns this job" in pub, "publisher row")
must("1.1.0" in rows["verify_event_job_context"]["purpose"], "verify row")
for name in ("event-jobs.md", "caller-identity.md"):
    doc = (ROOT / "docs" / name).read_text(encoding="utf-8")
    must("deliberately adds no verified-caller" not in doc and "AD-36" in doc, name)
doc = (ROOT / "docs" / "event-jobs.md").read_text(encoding="utf-8")
for phrase in ("1.1.0", ">=1.17.47", "calling_module_for_core_provider", "up to 5 seconds", "installed in the last 5 seconds", "tests/event-jobs-caller-1.17.47.py",
               "one to two minutes"):
    must(phrase in doc, f"event-jobs.md lacks {phrase}")
must("fifth" in (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8"), "caller-identity.md names the fifth provider")
must("no per-publish check" not in (APP / "event_jobs.py").read_text(encoding="utf-8").lower(), "stale docstring gone")
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"] == version, "VERSION and the package agree")
must((ROOT / f"RELEASE_NOTES_{version}.md").exists(), "release notes")
print("       capability 1.1.0, requires_framework >=1.17.47, the caller note, the contract rows and the docs agree")

# ------------------------------------------------------------------------------------------------ (4) the cost, printed (counts asserted, never time)
N = 2000


def timed(label, prepare, loops=N):
    reset()
    handle = register()
    ej._RATE.limit = 10**9
    ej._RECENT.maximum = 10**7
    keys = [f"c{i}" for i in range(loops)]
    SCANS[0] = STATE_READS[0] = 0
    start = time.perf_counter()
    for k in keys:
        prepare()
        alerts["fire"](handle, k)
    elapsed = time.perf_counter() - start
    micro = elapsed / loops * 1e6
    print(f"       cost  {label:<34} {micro:8.1f} microseconds per publish  (scans {SCANS[0]}, state reads {STATE_READS[0]})")
    return SCANS[0], STATE_READS[0]


ej._verified_caller_ok = lambda definition: ej.CALLER_OK
timed("no caller check", lambda: None)
ej._verified_caller_ok = _real_check
warm = timed("check, warm snapshot", lambda: None)
cold = timed("check, cold read every time", lambda: (ci.clear_snapshot_for_tests(), ej._ENABLED.clear()), loops=N // 4)
must(warm == (1, 1), warm)
must(cold == (N // 4, N // 4), cold)
print("       (stub reads on this PC: the real-disk cost is read by tests/event-jobs-caller-runtime-1.17.47.py on the dev server)")
print("[TEST] PASS event jobs caller 1.17.47")
