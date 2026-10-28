#!/usr/bin/env python3
"""1.17.49 core.event_jobs: a refused publish never touches the shared cache, and the hourly report survives a failed write.

Closes the two held findings of the 1.17.48 review. The real tec_tac/event_jobs.py, event_jobs_policy.py and caller_identity.py run with
the stubs of tests/event-jobs-refusal-audit-1.17.48.py (Django, the registry, the module state, the shared cache, ``audit.record``, the
stat model) plus a stub Celery send (``tec_tac.tasks.note_event_job_refusals``: ``SENT`` holds each message, ``FAIL_SEND`` makes it raise).
Django, Redis and Celery are not installed on this PC, so the task, the real cache and the real broker run only through these stubs.

Covered: with a blocking cache installed, 50 refused publishes make no cache call and finish fast; refusals inside one flush window cause
one send with the summed count, a refusal after the window a second send, two jobs two entries in one message; a failed send or an open
breaker keeps the entries (bounded) and the next window re-sends them; the worker function applies valid entries as one add and one
incr(count) and ignores an unknown job, a bad hour, an oversized list and a non-integer count, and a raising cache is swallowed; the tick
then reports the full count; flush_counters sends a pending buffer without a new refusal and never inside an open transaction;
CALLER_UNVERIFIABLE and the owner's accepted publishes add nothing; a failed audit write releases the claim so the next tick writes the
row once; a failing release, back-to-back ticks and a raising cache in the tick behave; the local fallback names are gone.
"""
from __future__ import annotations

import importlib.util
import logging
import re
import sys
import tempfile
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


MONO = [1000.0]
WALL = [1_800_000_000.0 - (1_800_000_000.0 % 3600)]  # the start of a clock hour
TMP = Path(tempfile.mkdtemp(prefix="tectac-eventjobs-refusal-bound-"))
EXT = TMP / "extensions"
LIB = TMP / "lib"
EXT.mkdir()
LIB.mkdir()
PLUGINS: dict = {}
STATE = {"registry_error": False, "state_error": False}


def plugin(plugin_id):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="2.0.0", legacy=False)
    return root


def discover_plugins():
    if STATE["registry_error"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def load_state():
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return {"schema": 1, "modules": {}}


def is_enabled(module_id, state=None):
    if STATE["state_error"]:
        raise OSError("state unreadable")
    return True


class FakeCache:
    def __init__(self):
        self.data: dict = {}
        self.raises = False
        self.ttls: list = []

    def _check(self):
        if self.raises:
            raise ConnectionError("cache down")

    def add(self, key, value, timeout=None):
        self._check()
        if key in self.data:
            return False
        self.data[key] = value
        self.ttls.append(timeout)
        return True

    def incr(self, key, delta=1):
        self._check()
        self.data[key] += delta
        return self.data[key]

    def delete(self, key):
        self._check()
        self.data.pop(key, None)

    def get(self, key, default=None):
        self._check()
        return self.data.get(key, default)


CACHE = FakeCache()
AUDIT = []
STATS: list = []
CONNECTION = SimpleNamespace(in_atomic_block=False, vendor="sqlite")
mod("django")
mod("django.db", IntegrityError=type("IntegrityError", (Exception,), {}), connection=CONNECTION,
    transaction=SimpleNamespace(atomic=lambda: None, on_commit=lambda fn: None))
mod("django.utils")
mod("django.utils.timezone", now=lambda: None)
mod("django.core")
mod("django.core.cache", cache=CACHE)
pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
mod("tec_tac.registry", discover_plugins=discover_plugins)
mod("tec_tac.module_state", load_state=load_state, is_enabled=is_enabled)
mod("tec_tac.capabilities", register_capability=lambda **kw: SimpleNamespace(**kw))
mod("tec_tac.audit", record=lambda **kw: (AUDIT.append(kw), {"recorded": True})[1],
    service_audit_actor=lambda **kw: dict(kw))


SENT: list = []


class FakeTask:
    app = SimpleNamespace(connection_for_write=lambda **kw: __import__("contextlib").nullcontext(object()))

    @staticmethod
    def apply_async(args, **kw):
        SENT.append(args[0])


mod("tec_tac.tasks", note_event_job_refusals=FakeTask)
mod("tec_tac.models", TecTacEventJobStat=SimpleNamespace(objects=SimpleNamespace(all=lambda: list(STATS))))


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
ej.time = SimpleNamespace(monotonic=lambda: MONO[0], time=lambda: WALL[0], sleep=time.sleep)
STORED = []
ej._persist_safely = lambda definition, key, payload: STORED.append((definition.id, key)) or "queued"


def compile_as(filename, source):
    ns: dict = {"__name__": "probe"}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test-only stand-ins with a chosen code file name
    return ns


FIRE = "def fire(handle, key):\n    return handle.publish(key)\n"
alerts_root = plugin("alerts")
plugin("beta")
alerts = compile_as(str(alerts_root / "signals.py"), FIRE + "def deliver(context):\n    return None\n")
alerts2 = compile_as(str(alerts_root / "signals2.py"), "def deliver(context):\n    return None\n")
beta = compile_as(str(EXT / "beta" / "x.py"), FIRE)
lib = compile_as(str(LIB / "decorator.py"), FIRE)
KEYN = [0]
SECRET = "SECRET-KEY-VALUE"


def key():
    KEYN[0] += 1
    return f"k{KEYN[0]}"


def reset():
    ej._clear_for_tests()
    del STORED[:], AUDIT[:], STATS[:], SENT[:]
    CACHE.data.clear()
    CACHE.ttls.clear()
    CACHE.raises = False
    STATE.update(registry_error=False, state_error=False)
    MONO[0] += 1000
    WALL[0] = 1_800_000_000.0 - (1_800_000_000.0 % 3600)


def register(job="deliver", handler=None):
    return ej.register_event_job(id=f"alerts.{job}", module_id="alerts", label="Send an alert notice", handler=handler or alerts["deliver"])


def settle():
    """Flush this process's buffer (the next window) and let the worker apply every message."""
    MONO[0] += 61
    ej._flush_refusals()
    while SENT:
        ej.apply_refusal_counts(SENT.pop(0))


def tick(now_wall):
    settle()
    out = {"refused_reported": 0}
    ej._tick_report_refusals(datetime.fromtimestamp(now_wall, tz=timezone.utc), out)
    return out




HOUR = 3600
rows = lambda: [a for a in AUDIT if a["action"] == ej.ACTION_REFUSED]
FAIL_SEND = [False]


class BlockingCache:
    calls = 0

    def _boom(self, *a, **kw):
        BlockingCache.calls += 1
        time.sleep(0.2)
        raise AssertionError("the publish path touched the shared cache")

    add = incr = get = delete = _boom


def send_apply(args, **kw):
    if FAIL_SEND[0]:
        raise ConnectionError("broker down")
    SENT.append(args[0])


FakeTask.apply_async = staticmethod(send_apply)
REAL_CACHE = sys.modules["django.core.cache"].cache


def window():
    MONO[0] += policy.REFUSAL_FLUSH_SECONDS + 1


def deliver():
    while SENT:
        ej.apply_refusal_counts(SENT.pop(0))


def tick_only(now_wall):
    out = {"refused_reported": 0}
    ej._tick_report_refusals(datetime.fromtimestamp(now_wall, tz=timezone.utc), out)
    return out


# (1) a blocking cache is never touched in publish
reset()
handle = register()
sys.modules["django.core.cache"].cache = BlockingCache()
BlockingCache.calls = 0
started = time.perf_counter()
for _ in range(50):
    r = beta["fire"](handle, key())
    must((r.outcome, r.reason) == ("error", "the caller is not the module that owns this job"), r)
elapsed = time.perf_counter() - started
sys.modules["django.core.cache"].cache = REAL_CACHE
must(not STORED and BlockingCache.calls == 0, BlockingCache.calls)
must(elapsed < 0.5, elapsed)
must(len(SENT) == 1 and SENT[0][0][3] == 1 and sum(ej._pending_refusals.values()) == 49, (SENT, ej._pending_refusals))
must(not CACHE.data, "the worker has not run, so no cache write yet")
print(f"       50 refused publishes: all error, nothing stored, 0 cache calls, {elapsed:.3f} s")

# (2) one send per window with the summed count
reset()
handle = register()
h2 = register("other", alerts["deliver"])
for _ in range(10):
    beta["fire"](handle, key())
must(len(SENT) == 1, "the first refusal sends at once; the rest wait for the window")
window()
beta["fire"](handle, key())
must(len(SENT) == 2 and SENT[1] == [["alerts", "alerts.deliver", int(WALL[0] // HOUR), 10]], SENT)
deliver()
ck = ej._refusal_key("alerts", "alerts.deliver", int(WALL[0] // HOUR))
must(CACHE.data[ck] == 11 and CACHE.ttls == [policy.REFUSAL_TTL_SECONDS], (CACHE.data, CACHE.ttls))
reset()
handle = register()
h2 = register("other", alerts["deliver"])
beta["fire"](handle, key())
beta["fire"](h2, key())
beta["fire"](h2, key())
beta["fire"](handle, key())
del SENT[:]
window()
must(ej._flush_refusals() is True and len(SENT) == 1 and len(SENT[0]) == 2, SENT)
got = {e[1]: e[3] for e in SENT[0]}
must(got == {"alerts.deliver": 1, "alerts.other": 2}, got)
must(all(len(e) == 4 and isinstance(e[0], str) and isinstance(e[3], int) for e in SENT[0]), "scalars only")
print("       refusals inside one window: one send with the summed count; after the window a second send; two jobs, two entries in one message")

# (3) a failed send or an open breaker keeps the entries, bounded, and the next window re-sends them
reset()
handle = register()
FAIL_SEND[0] = True
t0 = time.perf_counter()
for _ in range(5):
    must(beta["fire"](handle, key()).outcome == "error", "still answers")
must(time.perf_counter() - t0 < 0.5, "fast")
must(sum(ej._pending_refusals.values()) == 5 and not SENT, ej._pending_refusals)
FAIL_SEND[0] = False
must(ej._flush_refusals() is False, "inside the window nothing is sent")
window()
must(ej._flush_refusals() is True and SENT[0][0][3] == 5 and not ej._pending_refusals, SENT)
del SENT[:]
reset()
handle = register()
REAL_SEND = ej._send_refusals
ej._send_refusals = lambda entries: False  # an open breaker or a failed send, as far as the buffer is concerned
for _ in range(3):
    beta["fire"](handle, key())
must(sum(ej._pending_refusals.values()) == 3, ej._pending_refusals)
window()
beta["fire"](handle, key())
must(sum(ej._pending_refusals.values()) == 4, ej._pending_refusals)
ej._send_refusals = REAL_SEND
reset()
handle = register()
for n in range(300):
    ej._buffer_refusal(("m", f"j{n}", 1), 1)
must(len(ej._pending_refusals) <= policy.REFUSAL_BUFFER_KEYS, len(ej._pending_refusals))
ej._pending_refusals.clear()
for n in range(100):
    ej._buffer_refusal(("m", f"j{n}", 1), 1)
FAIL_SEND[0] = False
ej._LAST_REFUSAL_FLUSH[0] = None
must(ej._flush_refusals() is True and len(SENT[-1]) == policy.REFUSAL_MAX_ENTRIES and len(ej._pending_refusals) == 100 - policy.REFUSAL_MAX_ENTRIES, len(SENT[-1]))
del SENT[:]
print("       a failed send or open breaker keeps the entries (bounded to 256); the next window re-sends; a message holds at most 64 entries")

# real breaker open: the send is skipped and the entries stay
reset()
handle = register()
for _ in range(20):
    ej._BREAKER.failure()
beta["fire"](handle, key())
must(not SENT and sum(ej._pending_refusals.values()) == 1, (SENT, ej._pending_refusals))
ej._BREAKER.success()

# (4) the worker function
reset()
handle = register()
cur = int(WALL[0] // HOUR)
ok = ["alerts", "alerts.deliver", cur, 3]
must(ej.apply_refusal_counts([ok]) == 1, "applied")
ck = ej._refusal_key("alerts", "alerts.deliver", cur)
must(CACHE.data[ck] == 3 and CACHE.ttls == [policy.REFUSAL_TTL_SECONDS], CACHE.data)
ej.apply_refusal_counts([["alerts", "alerts.deliver", cur, 2]])
must(CACHE.data[ck] == 5, "a second message adds")
before = dict(CACHE.data)
bad = [
    ["alerts", "alerts.nope", cur, 1],  # unknown job
    ["other-module", "alerts.deliver", cur, 1],
    ["alerts", "alerts.deliver", cur - 3, 1],  # too old
    ["alerts", "alerts.deliver", cur + 1, 1],  # future
    ["alerts", "alerts.deliver", "x", 1],
    ["alerts", "alerts.deliver", True, 1],
    ["alerts", "alerts.deliver", cur, "7"],
    ["alerts", "alerts.deliver", cur, 1.5],
    ["alerts", "alerts.deliver", cur, True],
    ["alerts", "alerts.deliver", cur],
    [1, 2, 3, 4],
    "not a list",
    None,
]
for entry in bad:
    must(ej.apply_refusal_counts([entry]) == 0, entry)
must(ej.apply_refusal_counts("nope") == 0 and ej.apply_refusal_counts(None) == 0 and ej.apply_refusal_counts({"a": 1}) == 0, "not a list")
must(ej.apply_refusal_counts([ok] * (policy.REFUSAL_MAX_ENTRIES + 1)) == 0, "oversized list ignored whole")
must(CACHE.data == before, "nothing changed")
ej.apply_refusal_counts([["alerts", "alerts.deliver", cur, 10 ** 9]])
must(CACHE.data[ck] == 5 + policy.REFUSAL_COUNT_MAX, "clamped to the maximum")
ej.apply_refusal_counts([["alerts", "alerts.deliver", cur, -4]])
must(CACHE.data[ck] == 6 + policy.REFUSAL_COUNT_MAX, "clamped to at least 1")
CACHE.raises = True
must(ej.apply_refusal_counts([ok]) == 0, "a raising cache is swallowed")
CACHE.raises = False
reset()
handle = register()
for _ in range(7):
    beta["fire"](handle, key())
window()
ej._flush_refusals()
deliver()
out = tick_only(WALL[0] + HOUR + 5)
must(out["refused_reported"] == 1 and rows()[0]["metadata"]["count"] == 7, (out, AUDIT))
print("       worker: valid entries add; unknown job, bad hour, oversized list, non-int count are ignored; a raising cache is swallowed; the tick reports the full count")

# the task wrapper
tasks_src = (APP / "tasks.py").read_text(encoding="utf-8")
must('name="tec_tac.note_event_job_refusals"' in tasks_src and "apply_refusal_counts" in tasks_src, "task registered")

# (5) flush_counters sends a pending buffer with no new refusal, and never inside a transaction
reset()
handle = register()
beta["fire"](handle, key())
beta["fire"](handle, key())
del SENT[:]
must(sum(ej._pending_refusals.values()) == 1, ej._pending_refusals)
window()
CONNECTION.in_atomic_block = True
ej.flush_counters()
must(not SENT and sum(ej._pending_refusals.values()) == 1, "never inside an open transaction")
CONNECTION.in_atomic_block = False
ej.flush_counters()
must(len(SENT) == 1 and SENT[0][0][3] == 1 and not ej._pending_refusals, SENT)
del SENT[:]
ej.flush_counters()
must(not SENT, "nothing pending, nothing sent")
beta["fire"](handle, key())
ej.flush_counters()
must(not SENT, "inside the window flush_counters sends nothing")
print("       flush_counters sends a pending buffer without a new refusal, once a minute, and not inside an open transaction")

# (6) unverifiable callers and the owner add nothing
reset()
handle = register()
for _ in range(5):
    must(alerts["fire"](handle, key()).outcome == "queued", "owner accepted")
must(not ej._pending_refusals and not SENT, "accepted publishes add nothing")
ej._ENABLED.set("alerts", True)
STATE["registry_error"] = True
ci.clear_snapshot_for_tests()
r = alerts["fire"](handle, key())
must((r.outcome, r.reason) == ("error", "the caller could not be verified") and not ej._pending_refusals and not SENT, r)
STATE["registry_error"] = False
print("       the owner's accepted publishes and an unverifiable caller add nothing to the buffer")

# ------------------------------------------------------------------------------------------------ the tick
SWITCH = {"fail": 0}
real_record = sys.modules["tec_tac.audit"].record


def flaky_record(**kw):
    if SWITCH["fail"] > 0:
        SWITCH["fail"] -= 1
        raise RuntimeError("audit down")
    return real_record(**kw)


def counted_hour(n=3):
    reset()
    handle = register()
    for _ in range(n):
        beta["fire"](handle, key())
    window()
    ej._flush_refusals()
    deliver()


sys.modules["tec_tac.audit"].record = flaky_record
counted_hour(3)
SWITCH["fail"] = 1
rk = ej._refusal_key("alerts", "alerts.deliver", int(WALL[0] // HOUR), "reported")
must(tick_only(WALL[0] + HOUR + 5)["refused_reported"] == 0 and not rows(), "the failed write gives no row")
must(rk not in CACHE.data, "and the claim is released")
out = tick_only(WALL[0] + HOUR + 65)
must(out["refused_reported"] == 1 and len(rows()) == 1 and rows()[0]["metadata"]["count"] == 3, (out, AUDIT))
must(tick_only(WALL[0] + HOUR + 125)["refused_reported"] == 0 and len(rows()) == 1, "a third tick writes nothing")
print("       a failed audit write releases the claim; the next tick writes exactly one row with the full count; a third writes nothing")

# a cache.delete that raises does not break the tick
counted_hour(2)
SWITCH["fail"] = 1
real_delete = CACHE.delete


def bad_delete(key):
    raise ConnectionError("delete failed")


CACHE.delete = bad_delete
out = tick_only(WALL[0] + HOUR + 5)
CACHE.delete = real_delete
must(out["refused_reported"] == 0 and not rows(), "no row, no raise")
print("       a cache.delete that raises does not break the tick")

# back-to-back ticks with a healthy audit write one row
counted_hour(4)
tick_only(WALL[0] + HOUR + 5)
tick_only(WALL[0] + HOUR + 6)
must(len(rows()) == 1 and rows()[0]["metadata"]["count"] == 4, AUDIT)
print("       two ticks back to back write exactly one row")

# a raising cache in the tick: no row, no raise; a later tick with a working cache reports the hour
counted_hour(2)
CACHE.raises = True
out = tick_only(WALL[0] + HOUR + 5)
must(out["refused_reported"] == 0 and not rows(), "no row while the cache raises")
CACHE.raises = False
out = tick_only(WALL[0] + HOUR + 65)
must(out["refused_reported"] == 1 and rows()[0]["metadata"]["count"] == 2, (out, AUDIT))
# a cache that raises only on the claim skips the hour and does not fall back to a local claim
counted_hour(2)
real_add = CACHE.add


def add_fails_on_claim(key, value, timeout=None):
    if ":reported:" in key:
        raise ConnectionError("claim failed")
    return real_add(key, value, timeout)


CACHE.add = add_fails_on_claim
must(tick_only(WALL[0] + HOUR + 5)["refused_reported"] == 0 and not rows(), "a failed claim read skips the hour")
CACHE.add = real_add
must(tick_only(WALL[0] + HOUR + 65)["refused_reported"] == 1 and len(rows()) == 1, "the next tick reports it")
print("       a raising cache in the tick writes no row and raises nothing; a later tick with a working cache reports the hour")

sys.modules["tec_tac.audit"].record = real_record

# the local fallback names are gone
src = (APP / "event_jobs.py").read_text(encoding="utf-8")
for name in ("_local_refusals", "_local_reported"):
    must(not hasattr(ej, name) and name not in src, f"{name} is gone")
must(re.search(r"def _audit\(.*\) -> bool:", src, flags=re.DOTALL) is not None, "_audit answers a bool")
must(ej._audit("custom:x", module_id="alerts", job_id="alerts.deliver", message="m") is True, "an accepted write answers True")
print("       _local_refusals and _local_reported are gone; _audit answers True or False")

# ------------------------------------------------------------------------------------------------ contract, docs, no migration
reset()
meta = ej.event_jobs_contract_metadata()
must(ej.CAPABILITY_VERSION == "1.1.0" and meta["version"] == "1.1.0" and meta["requires_framework"] == ">=1.17.47", meta["version"])
must("no Redis call in publish" in meta["caller"] and "in bulk" in meta["caller"] and "a minute per process" in meta["caller"], meta["caller"])
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must("no Redis call in publish" in contracts and "one bounded broker message a minute per process" in contracts, "contracts.py row")
doc = (ROOT / "docs" / "event-jobs.md").read_text(encoding="utf-8")
for phrase in ("tec_tac.note_event_job_refusals", "one bounded broker message", "buffer", "wait in the web process's memory", "per-process cache",
               "the next tick, within", "never read", "a count is a count, not proof"):
    must(phrase in doc, f"event-jobs.md lacks {phrase!r}")
must(policy.REFUSAL_FLUSH_SECONDS == 60 and policy.REFUSAL_MAX_ENTRIES == 64 and policy.REFUSAL_BUFFER_KEYS == 256, "policy limits")
must(tuple(int(part) for part in (ROOT / "VERSION").read_text(encoding="utf-8").strip().split("-")[0].split(".")) >= (1, 17, 49), "VERSION")  # 1.17.50: at least 1.17.49
migrations = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must([m for m in migrations if m[:4] in {"0033", "0034", "0035", "0036", "0037"}] == ["0033_runtime_licensing_mode.py", "0034_scheduler_run_completion.py", "0035_server_job_hook.py", "0036_schedule_creator_name.py", "0037_creation_scope_and_delegation.py"], migrations)  # 1.17.58 added 0033; 1.17.61 added 0034; 1.17.62 added 0035; 1.17.63 added 0036; 1.17.68 added 0037  # 1.17.87: later migrations (0038 on) are allowed; the pin is that these five exist
print("       capability stays 1.1.0; contract row, capability text and docs agree; no migration")
print("[TEST] PASS event jobs refusal bound 1.17.49")
