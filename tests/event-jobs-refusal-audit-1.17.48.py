#!/usr/bin/env python3
"""1.17.48 core.event_jobs: an audit row for refused publishes, once per module and job and clock hour, with the count (Johan CQ138).

The real tec_tac/event_jobs.py, event_jobs_policy.py and caller_identity.py run against a temporary extensions folder, with real frames
compiled under stub plugin folders (the technique of tests/event-jobs-caller-1.17.47.py). Stubbed: Django's transaction and connection,
the registry, the module state, the shared cache (``CACHE``: add, incr, get, delete, with a switch that makes it raise), the Celery send (since 1.17.49 a refusal reaches the
cache through the buffer, one bounded broker message and the worker function ``apply_refusal_counts``, run by ``settle()``), ``audit.record`` and the
stat-row model. Django is not installed on this PC, so the real tick, cache and audit table run only through these stubs.

Covered: refusals of a foreign caller (another module, a library frame) are tallied and give no audit row before the hour ends; a tick
after the hour turns writes exactly one row per (module, job) with the total count, action custom:event-job-refused; a second tick writes
nothing more (the guard); a second job has its own row; a tick that missed an hour still reports it; a zero count writes no row; the row
holds no key and no payload; a raising cache never breaks the publish (it answers error, never raises and stores nothing) and the tick
then writes no row (1.17.49 dropped the local fallback); a registry or state fault adds no tally; the owner's accepted publishes add no tally; the capability stays 1.1.0 and lists
custom:event-job-refused; no migration is added and the stat model gains no field.
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
TMP = Path(tempfile.mkdtemp(prefix="tectac-eventjobs-refusal-"))
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

# ------------------------------------------------------------------------------------------------ the hourly row
reset()
handle = register()
for _ in range(5):
    must(beta["fire"](handle, SECRET).outcome == "error", "beta refused")
for _ in range(2):
    must(lib["fire"](handle, SECRET).outcome == "error", "a library frame refused")
must(not STORED, "nothing stored")
must(tick(WALL[0] + 10)["refused_reported"] == 0 and not rows(), "no row inside the hour")
must(tick(WALL[0] + HOUR - 1)["refused_reported"] == 0 and not rows(), "no row before the hour ends")
out = tick(WALL[0] + HOUR + 5)
must(out["refused_reported"] == 1 and len(rows()) == 1, (out, rows()))
row = rows()[0]
must(row["action"] == "custom:event-job-refused" == ej.ACTION_REFUSED, row["action"])
meta = row["metadata"]
must(meta["count"] == 7 and meta["owner_module"] == "alerts" and meta["job_id"] == "alerts.deliver", meta)
must(meta["window_seconds"] == 3600 and meta["hour_start"] == datetime.fromtimestamp(WALL[0], tz=timezone.utc).isoformat(), meta)
must(meta["error_type"] == "CallerRefused" and meta["key"] == "", meta)
must("7 publish(es)" in row["message"] and "caller was not the module that owns the job" in row["message"], row["message"])
blob = repr(row)
must(SECRET not in blob and "k1" not in blob and "payload" not in blob.replace("window_seconds", ""), "no key or payload in the row")
must(row["module_id"] == "core" and row["object_type"] == "event_job" and row["object_id"] == "alerts.deliver", row)
print("       7 refusals in one hour: no row before the hour ends, then exactly one row with count 7 and no key or payload")

# a second tick writes nothing more
must(tick(WALL[0] + HOUR + 65)["refused_reported"] == 0 and len(rows()) == 1, "the guard stops a second row")
must(tick(WALL[0] + 2 * HOUR + 5)["refused_reported"] == 0 and len(rows()) == 1, "a tick one hour later does not repeat it")
print("       a second tick, in the same hour or the next, writes nothing more")

# a second job has its own row; two ticks racing write one row
reset()
h1 = register("deliver")
h2 = register("other", alerts["deliver"])
beta["fire"](h1, key())
beta["fire"](h2, key())
beta["fire"](h2, key())
out = tick(WALL[0] + HOUR + 1)
got = {r["metadata"]["job_id"]: r["metadata"]["count"] for r in rows()}
must(out["refused_reported"] == 2 and got == {"alerts.deliver": 1, "alerts.other": 2}, got)
print("       a second job gets its own row and its own count")

# two workers ticking at once write one row (cache.add guard)
reset()
handle = register()
beta["fire"](handle, key())
tick(WALL[0] + HOUR + 1)
tick(WALL[0] + HOUR + 2)
must(len(rows()) == 1, "the shared cache guard, not the local set, stops the second worker")
print("       two ticks on different workers write one row (the shared guard)")

# a tick that missed an hour still reports it (two hours back), and the hours report separately
reset()
handle = register()
beta["fire"](handle, key())
beta["fire"](handle, key())
WALL[0] += HOUR
beta["fire"](handle, key())
out = tick(WALL[0] + HOUR + 5)  # the tick of hour 3 sees hours 1 and 2
must(out["refused_reported"] == 2 and sorted(r["metadata"]["count"] for r in rows()) == [1, 2], [r["metadata"] for r in rows()])
reset()
handle = register()
beta["fire"](handle, key())
must(tick(WALL[0] + 2 * HOUR + 5)["refused_reported"] == 1 and len(rows()) == 1, "a tick that missed the whole next hour still reports it")
reset()
handle = register()
beta["fire"](handle, key())
must(tick(WALL[0] + 3 * HOUR + 5)["refused_reported"] == 0, "three hours later it is out of reach (the tally has expired)")
print("       a tick that missed one hour still reports it; a missed second hour is the limit")

# a zero count writes no row
reset()
register()
must(tick(WALL[0] + HOUR + 5)["refused_reported"] == 0 and not AUDIT, "no refusals, no row")
print("       a zero count writes no row")

# the owner's accepted publishes add no tally
reset()
handle = register()
for _ in range(10):
    must(alerts["fire"](handle, key()).outcome == "queued", "owner accepted")
must(not CACHE.data and not ej._pending_refusals and tick(WALL[0] + HOUR + 5)["refused_reported"] == 0 and not SENT, "no tally for accepted publishes")
print("       the owner's accepted publishes add no tally")

# a registry or state fault adds no tally and writes no row
reset()
handle = register()
ej._ENABLED.set("alerts", True)
STATE["registry_error"] = True
ci.clear_snapshot_for_tests()
for _ in range(5):
    r = alerts["fire"](handle, key())
    must((r.outcome, r.reason) == ("error", "the caller could not be verified"), r)
must(not CACHE.data and not ej._pending_refusals, "a registry fault is not a refusal")
STATE["registry_error"] = False
MONO[0] += 5
ci.clear_snapshot_for_tests()
ej._ENABLED.set("alerts", True)
STATE["state_error"] = True
r = alerts["fire"](handle, key())
must((r.outcome, r.reason) == ("error", "the caller could not be verified") and not CACHE.data and not ej._pending_refusals, "a state fault is not a refusal")
must(tick(WALL[0] + HOUR + 5)["refused_reported"] == 0 and not AUDIT and not STORED, "no row, nothing stored")
print("       a registry or state fault (could not be verified) adds no tally and writes no row")

# a raising cache: the publish is untouched (it never calls the cache), the count is lost, the tick writes no row and raises nothing
reset()
handle = register()
CACHE.raises = True
for _ in range(4):
    r = beta["fire"](handle, key())
    must((r.outcome, r.reason) == ("error", "the caller is not the module that owns this job"), r)
must(not STORED, "nothing stored")
out = tick(WALL[0] + HOUR + 5)
must(out["refused_reported"] == 0 and not rows(), (out, AUDIT))
print("       a raising cache never breaks the publish; that hour's count is lost and the tick writes no row (the local fallback is gone)")

# the cache key and TTL
reset()
handle = register()
beta["fire"](handle, key())
settle()
(only_key,) = CACHE.data.keys()
must(only_key.startswith(policy.REFUSAL_CACHE_PREFIX) and "alerts" in only_key and "alerts.deliver" in only_key and SECRET not in only_key, only_key)
must(CACHE.ttls == [policy.REFUSAL_TTL_SECONDS] and 2 * 3600 < policy.REFUSAL_TTL_SECONDS <= 4 * 3600, CACHE.ttls)
must(policy.REFUSAL_WINDOW_SECONDS == 3600, "one hour")
print("       the tally key holds the owner module, the job and the hour, with a TTL of about 3 hours")

# the tick step is wired into recover_event_jobs, after the drops
steps = ("_tick_expire", "_tick_module_gate", "_tick_recover_running", "_tick_enqueue_overdue", "_tick_trim", "_tick_gauges", "_tick_report_drops", "_tick_prune")
for name in steps:
    setattr(ej, name, lambda now, out: None)
reset()
handle = register()
beta["fire"](handle, key())
ej.timezone = SimpleNamespace(now=lambda: datetime.fromtimestamp(WALL[0] + HOUR + 5, tz=timezone.utc))
settle()
result = ej.recover_event_jobs()
must(result["refused_reported"] == 1 and result["errors"] == 0 and len(rows()) == 1, result)
src = (APP / "event_jobs.py").read_text(encoding="utf-8")
must(src.index("_tick_report_drops, _tick_report_refusals, _tick_prune") > 0, "step order")
print("       recover_event_jobs runs the refusal step after the drop step and reports refused_reported")

# ------------------------------------------------------------------------------------------------ contract, docs, no migration
reset()
must(ej.CAPABILITY_VERSION == "1.1.0", "version")
meta = ej.event_jobs_contract_metadata()
must(meta["id"] == "core.event_jobs" and meta["version"] == "1.1.0" and policy.CAPABILITY_VERSION == "1.1.0", meta["version"])
must("custom:event-job-refused" in meta["audit_actions"] and "custom:event-job-dropped" in meta["audit_actions"], meta["audit_actions"])
must(meta["requires_framework"] == ">=1.17.47", meta["requires_framework"])
must("could not be verified" in meta["caller"] and "custom:event-job-refused" in meta["caller"] and "cache flush" in meta["caller"], meta["caller"])
must(list(meta["outcomes"]) == list(policy.OUTCOMES) and "error" in meta["outcomes"], meta["outcomes"])
contracts = (APP / "contracts.py").read_text(encoding="utf-8")
must("custom:event-job-refused" in contracts and "the caller could not be verified" in contracts and "1.17.48" in contracts, "contracts.py row")
doc = (ROOT / "docs" / "event-jobs.md").read_text(encoding="utf-8")
for phrase in ("custom:event-job-refused", "once", "clock hour", "shared cache", "cache flush", "a count is a count, not proof", "the caller could not be verified",
               "about 1 second", "per-process cache"):
    must(phrase in doc, f"event-jobs.md lacks {phrase!r}")
must("No audit row and no\n   counter record a refusal" not in doc, "the stale 'no audit row' sentence is gone")
cid = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("core_provider_caller_checked" in cid and "FAILED_READ_SECONDS" in cid, "caller-identity.md names the helper and the short window")

models = (APP / "models.py").read_text(encoding="utf-8")
stat_block = models.split("class TecTacEventJobStat", 1)[1].split("\nclass ", 1)[0]
fields = re.findall(r"^    (\w+) = models\.", stat_block, flags=re.MULTILINE)
must(fields and not [f for f in fields if "refus" in f or "caller" in f], fields)
must(len(fields) == 15, fields)  # the 1.17.45 field list, unchanged
migrations = sorted(p.name for p in (APP / "migrations").glob("0*.py"))
must(migrations[-3:] == ["0032_event_jobs.py", "0033_runtime_licensing_mode.py", "0034_scheduler_run_completion.py"], migrations[-3:])  # 1.17.58 added 0033 after the event jobs one; 1.17.61 added 0034
must("refus" not in (APP / "migrations" / migrations[-1]).read_text(encoding="utf-8").lower(), "the event jobs migration is untouched")
print("       capability stays 1.1.0 and lists custom:event-job-refused; contract rows and docs agree; no migration, no new column")
print("[TEST] PASS event jobs refusal audit 1.17.48")
