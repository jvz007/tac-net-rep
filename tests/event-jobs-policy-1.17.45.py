#!/usr/bin/env python3
"""1.17.45 core.event_jobs 1.0.0: the decisions in framwork/tec_tac/event_jobs_policy.py. Plain Python, no Django.

Covered: the key charset and length, the payload (size, JSON-only, depth, non-finite numbers, non-dict), the error and result cut, every
registration ceiling and refusal (each limit at, below and above its edge; a bool or float; the id prefix rule; the label; the backoff
cap), back-off doubling with its cap and jitter bounds, which failures give up at once and which retry, the expiry, stale-running and
overdue-pending decisions, the backlog gate (an absent gauge is open) and trim count, the per-process rate window, the in-process
duplicate memory, the circuit breaker, and the timed value that backs the backlog gauge and the enabled cache.
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("event_jobs_policy", ROOT / "framwork" / "tec_tac" / "event_jobs_policy.py")
P = importlib.util.module_from_spec(spec)
sys.modules["event_jobs_policy"] = P
spec.loader.exec_module(P)
Error = P.EventJobPolicyError


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def refuses(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Error as exc:
        return str(exc)
    raise AssertionError(f"accepted: {args} {kw}")


SENTINEL = "SENTINEL-VALUE-31"

# (1) key
for good in ("a", "alert:12:ack", "A.b_c-d@e/f", "x" * 128, "0"):
    must(P.clean_key(good) == good, good)
for bad in ("", "x" * 129, "has space", "new\nline", "naïve", "a;b", "a#b", "a?b", None, 5, b"x", ["x"]):
    refuses(P.clean_key, bad)
must(SENTINEL not in refuses(P.clean_key, f"{SENTINEL} space"), "a refused key is not echoed")
print("       key: 1 to 128 characters of letters, digits and . _ : @ / -")

# (2) payload
must(P.clean_payload(None) == {} and P.clean_payload({}) == {}, "none and empty")
sample = {"alert_id": 12, "state": "resolved", "ok": True, "none": None, "ratio": 1.5, "ids": [1, 2, 3], "nested": {"a": [1, {"b": 2}]}}
copy = P.clean_payload(sample)
must(copy == sample and copy is not sample and copy["ids"] is not sample["ids"], "an equal deep copy")
refuses(P.clean_payload, [1])
refuses(P.clean_payload, "text")
refuses(P.clean_payload, {"a": object()})
refuses(P.clean_payload, {"a": {1, 2}})
refuses(P.clean_payload, {"a": (1, 2)})
refuses(P.clean_payload, {1: "x"})
refuses(P.clean_payload, {"a": float("nan")})
refuses(P.clean_payload, {"a": float("inf")})
refuses(P.clean_payload, {"a": b"bytes"})
deep = {"a": {"a": {"a": {"a": {"a": 1}}}}}
refuses(P.clean_payload, deep)  # more than 4 levels
P.clean_payload({"a": {"a": {"a": {"a": 1}}}})  # exactly 4
class Sub(dict):
    pass
refuses(P.clean_payload, Sub(a=1))  # a dict subclass is not a plain dict
big = {"k": "x" * (P.PAYLOAD_MAX_BYTES - 8)}
P.clean_payload(big)
refuses(P.clean_payload, {"k": "x" * (P.PAYLOAD_MAX_BYTES - 7)})
refuses(P.clean_payload, {"k": "é" * 1100})  # 2 bytes each: size is in bytes
must(SENTINEL not in refuses(P.clean_payload, {"a": object(), "b": SENTINEL}), "a refused payload is not echoed")
must(SENTINEL not in refuses(P.clean_payload, {"k": SENTINEL * 400}), "an oversize payload is not echoed")
print("       payload: JSON object, 2 KiB, plain values, 4 levels, never echoed in an error")

# (3) short_error and cap_result
must(P.short_error(None) == "" and P.short_error(ValueError()) == "ValueError", "empty text keeps the class name")
text = P.short_error(RuntimeError("line one\nline two\r\n\ttabbed"))
must("\n" not in text and "\r" not in text and "\t" not in text and text.startswith("RuntimeError: line one"), text)
must(len(P.short_error(RuntimeError("x" * 1000))) == P.ERROR_MAX_CHARS, "cut to 200 characters")
must(P.cap_result(None) == {} and P.cap_result({"ok": 1}) == {"ok": 1}, "result")
must(P.cap_result({"k": "x" * 3000}) == {"truncated": True}, "a large dict is replaced")
must(P.cap_result({"k": object()}) == {"value": P.cap_result({"k": object()})["value"]} and "value" in P.cap_result({"k": object()}), "unsafe dict")
must(P.cap_result("done") == {"value": "done"} and P.cap_result(5) == {"value": "5"}, "non-dict")
must(len(P.cap_result("y" * 900)["value"]) == 200, "a non-dict result is cut")
print("       error text one line of 200 characters; a result is small, JSON-safe or cut")

# (4) registration
GOOD = dict(id="alerts.deliver", module_id="alerts", label="Send an alert notice")
s = P.clean_spec(**GOOD)
must((s.soft_time_limit_seconds, s.hard_time_limit_seconds, s.max_attempts, s.backoff_seconds, s.max_backoff_seconds, s.expires_seconds, s.max_backlog,
      s.dedupe_seconds, s.audit_success) == (30, 45, 3, 60, 3600, 1800, 500, 0, False), s)
for name, (low, default, high) in P.LIMITS.items():
    must(low <= default <= high, name)
EDGES = {"soft_time_limit_seconds": (5, 600), "max_attempts": (1, 10), "backoff_seconds": (5, 3600), "expires_seconds": (60, 86400),
         "max_backlog": (1, 5000), "dedupe_seconds": (0, 3600), "max_backoff_seconds": (5, 3600)}
for name, (low, high) in EDGES.items():
    side = {"backoff_seconds": 5} if name == "max_backoff_seconds" else {}  # the cap may not be below the base
    P.clean_spec(**GOOD, **side, **{name: low})
    P.clean_spec(**GOOD, **side, **{name: high})
    refuses(P.clean_spec, **GOOD, **side, **{name: low - 1})
    refuses(P.clean_spec, **GOOD, **side, **{name: high + 1})
    refuses(P.clean_spec, **GOOD, **side, **{name: True})
    refuses(P.clean_spec, **GOOD, **side, **{name: float(low)})
    refuses(P.clean_spec, **GOOD, **side, **{name: str(low)})
must(P.clean_spec(**GOOD, soft_time_limit_seconds=600).hard_time_limit_seconds == 615, "hard is soft plus 15")
refuses(P.clean_spec, **GOOD, backoff_seconds=120, max_backoff_seconds=60)
P.clean_spec(**GOOD, backoff_seconds=120, max_backoff_seconds=120)
refuses(P.clean_spec, **GOOD, audit_success="yes")
refuses(P.clean_spec, **GOOD, audit_success=1)
must(P.clean_spec(**GOOD, audit_success=True).audit_success is True, "audit_success")
text = refuses(P.clean_spec, id="other.deliver", module_id="alerts", label="x")
must("another module" in text, text)
refuses(P.clean_spec, id="alerts", module_id="alerts", label="x")
refuses(P.clean_spec, id="alerts.", module_id="alerts", label="x")
refuses(P.clean_spec, id="Alerts.deliver", module_id="alerts", label="x")
refuses(P.clean_spec, id="alerts.deliver.x y", module_id="alerts", label="x")
refuses(P.clean_spec, id="alertsx.deliver", module_id="alerts", label="x")
refuses(P.clean_spec, id="alerts.deliver", module_id="Alerts", label="x")
refuses(P.clean_spec, id="alerts.deliver", module_id="", label="x")
refuses(P.clean_spec, id=None, module_id="alerts", label="x")
refuses(P.clean_spec, id="alerts.deliver", module_id=None, label="x")
P.clean_spec(id="my-mod.deliver.v2", module_id="my-mod", label="x")
P.clean_spec(id="my_mod.deliver-it", module_id="my_mod", label="x")
for label in ("", "  ", "x" * 121, "two\nlines", None, 5):
    refuses(P.clean_spec, id="alerts.deliver", module_id="alerts", label=label)
must(P.clean_spec(id="alerts.deliver", module_id="alerts", label="  Padded  ").label == "Padded", "label is trimmed")
print("       registration: every ceiling accepted at its edge and refused one past it; id prefix; label; backoff cap")

# (5) back-off
for attempt, want in ((1, 60), (2, 120), (3, 240), (4, 480), (5, 960), (6, 1920), (7, 3600), (8, 3600), (50, 3600), (10**9, 3600)):
    low = P.backoff_delay(attempt, 60, 3600, lambda: 0.0)
    high = P.backoff_delay(attempt, 60, 3600, lambda: 1.0)
    must(low == want and abs(high - want * 1.2) < 1e-6, (attempt, low, high))
must(P.backoff_delay(0, 60, 3600, lambda: 0.0) == 60 and P.backoff_delay(-3, 60, 3600, lambda: 0.0) == 60, "attempt below 1 is attempt 1")
must(P.backoff_delay(1, 5, 5, lambda: 0.0) == 5 and P.backoff_delay(3, 5, 5, lambda: 0.0) == 5, "cap equal to base")
must(P.backoff_delay(1, 60, 3600, lambda: 7.0) == 72 and P.backoff_delay(1, 60, 3600, lambda: -3.0) == 60, "jitter is clamped to 0 to 20 percent")
for _ in range(200):
    value = P.backoff_delay(3, 60, 3600)
    must(240 <= value <= 288, value)
print("       back-off doubles, is capped, and adds 0 to 20 percent jitter")


# (6) which failures give up
class SchedulerPermanentError(RuntimeError):
    pass


class Derived(SchedulerPermanentError):
    pass


class SchedulerTransientError(RuntimeError):
    pass


class SoftTimeLimitExceeded(Exception):
    pass


for exc in (SchedulerPermanentError("x"), Derived("x"), ValueError("x"), TypeError("x"), KeyError("x"), UnicodeError("x")):
    must(P.failure_is_permanent(exc) is (not isinstance(exc, KeyError)), type(exc))
for exc in (SchedulerTransientError("x"), SoftTimeLimitExceeded(), RuntimeError("x"), OSError("x"), TimeoutError("x"), Exception("x")):
    must(P.failure_is_permanent(exc) is False, type(exc))
must(P.after_failure(RuntimeError(), 1, 3) == "retry" and P.after_failure(RuntimeError(), 2, 3) == "retry", "retry while attempts remain")
must(P.after_failure(RuntimeError(), 3, 3) == "give_up" and P.after_failure(RuntimeError(), 9, 3) == "give_up", "give up on the last attempt")
must(P.after_failure(ValueError(), 1, 3) == "give_up", "a permanent error gives up at once")
must(P.after_failure(SoftTimeLimitExceeded(), 1, 2) == "retry" and P.after_failure(SoftTimeLimitExceeded(), 2, 2) == "give_up", "soft limit retries")
must(P.after_failure(RuntimeError(), 1, 1) == "give_up", "one attempt means no retry")
print("       permanent errors give up at once; transient, soft limit and other errors retry until the last attempt")

# (7) expiry, stale running, overdue pending
now = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
must(P.is_expired(now, now) and P.is_expired(now, now - timedelta(seconds=1)) and not P.is_expired(now, now + timedelta(seconds=1)) and not P.is_expired(now, None), "expiry")
hard = 45
must(not P.is_stale_running(now, now - timedelta(seconds=hard + 299), hard), "inside the grace")
must(P.is_stale_running(now, now - timedelta(seconds=hard + 301), hard), "past hard limit plus five minutes")
must(P.is_stale_running(now, None, hard), "a running row with no start time is stale")
must(not P.is_stale_running(now, now, 615), "a fresh row")
old = now - timedelta(seconds=61)
must(P.is_overdue_pending(now, None, now) and P.is_overdue_pending(now, None, None), "never enqueued")
must(not P.is_overdue_pending(now, now - timedelta(seconds=5), now - timedelta(seconds=5)), "just enqueued")
must(P.is_overdue_pending(now, old, old), "next attempt passed more than 60 seconds ago and enqueued more than 60 seconds ago")
must(not P.is_overdue_pending(now, old, now + timedelta(seconds=600)), "a retry waiting for its countdown is not overdue")
must(P.is_overdue_pending(now, old, now - timedelta(seconds=3600)) and not P.is_overdue_pending(now, now - timedelta(seconds=10), old), "enqueue stamp inside 60 seconds")
print("       expiry, stale running (hard limit plus five minutes) and overdue pending (60 seconds)")

# (8) backlog gate
must(P.backlog_full(None, 500) is False, "an absent gauge is open")
must(P.backlog_full(499, 500) is False and P.backlog_full(500, 500) is True and P.backlog_full(900, 500) is True and P.backlog_full(0, 1) is False, "gate")
must(P.over_backlog(10, 500) == 0 and P.over_backlog(500, 500) == 0 and P.over_backlog(530, 500) == 30, "trim count")
print("       backlog gate and trim count")

# (9) rate window, duplicate memory, breaker, timed value
clock = [1000.0]
rate = P.RateWindow(limit=3, clock=lambda: clock[0])
must([rate.allow("a") for _ in range(5)] == [True, True, True, False, False], "three per minute")
must(rate.allow("b") is True, "per job")
clock[0] += 60
must(rate.allow("a") is True, "a new minute")
must(P.RATE_PER_MINUTE == 600 and P.RateWindow().limit == 600, "default 600 a minute")
recent = P.RecentKeys(seconds=3, clock=lambda: clock[0])
must(recent.seen(("j", "k")) is False and recent.seen(("j", "k")) is True and recent.seen(("j", "other")) is False, "remembered")
clock[0] += 2.9
must(recent.seen(("j", "k")) is True, "inside 3 seconds")
clock[0] += 0.2
must(recent.seen(("j", "k")) is False, "after 3 seconds")
small = P.RecentKeys(seconds=3, clock=lambda: clock[0], maximum=4)
for i in range(10):
    small.seen(("j", i))
must(len(small._seen) <= 4, "bounded memory")
breaker = P.CircuitBreaker(open_seconds=30, clock=lambda: clock[0])
must(breaker.allow(), "closed")
breaker.failure()
must(not breaker.allow(), "open after one failure")
clock[0] += 29
must(not breaker.allow(), "still open")
clock[0] += 1.5
must(breaker.allow(), "closed again after 30 seconds")
breaker.failure()
breaker.success()
must(breaker.allow(), "a success closes it")
timed = P.TimedValue(5, clock=lambda: clock[0])
must(timed.get("x") is None and timed.get("x", 7) == 7 and timed.age("x") is None, "absent")
timed.set("x", 3)
must(timed.get("x") == 3 and timed.age("x") == 0, "set")
clock[0] += 2
timed.adjust("x", 2)
must(timed.get("x") == 5 and timed.age("x") == 2, "adjust keeps the age")
timed.adjust("x", -50)
must(timed.get("x") == 0, "never below zero")
timed.adjust("absent", 1)
must(timed.get("absent") is None, "adjust of an absent value does nothing")
clock[0] += 4
must(timed.get("x") is None and timed.get("x", 9) == 9, "old counts as absent")
timed.set("y", 1)
timed.clear()
must(timed.get("y") is None, "clear")
print("       rate window, duplicate memory, circuit breaker and timed value")

# (10) the numbers the contract states
must(P.CAPABILITY_ID == "core.event_jobs" and P.CAPABILITY_VERSION == "1.0.0", "capability")
must(P.TICK_ROW_LIMIT == 200 and P.FINISHED_ROW_CAP == 20000 and P.PAYLOAD_MAX_BYTES == 2048 and P.KEY_MAX_LENGTH == 128, "limits")
must(P.IN_PROCESS_DEDUPE_SECONDS == 3 and P.ENABLED_CACHE_SECONDS == 5 and P.BREAKER_OPEN_SECONDS == 30 and P.BROKER_TIMEOUT_SECONDS == 2, "hot path")
must(P.STATEMENT_TIMEOUT_MS == 1000 and P.OVERDUE_SECONDS == 60 and P.STALE_RUNNING_GRACE_SECONDS == 300 and P.HARD_LIMIT_EXTRA_SECONDS == 15, "recovery")
must(set(P.ACTIVE_STATUSES) == {"pending", "running"} and set(P.FINISHED_STATUSES) == {"succeeded", "failed", "skipped", "expired"}, "statuses")
must(set(P.OUTCOMES) == {"queued", "duplicate", "dropped", "disabled", "error"}, "outcomes")
print("[TEST] PASS event jobs policy 1.17.45")
