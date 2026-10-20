"""The decisions behind event jobs (Core 1.17.45, capability core.event_jobs 1.1.0 since 1.17.47). No Django import, so a test can run them anywhere.

``tec_tac.event_jobs`` holds the registry, the database rows and the Celery task. Every rule that is a number or a yes/no lives
here: the key and payload checks, the registration limits Core enforces, the retry delay, the expiry, backlog and rate decisions, the
circuit breaker that keeps a broker outage from slowing a request, and the way a handler's error becomes a short audit text.

Core owns every ceiling in ``LIMITS``. A module may ask for less and never for more.
"""
from __future__ import annotations

import json
import math
import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

CAPABILITY_ID = "core.event_jobs"
CAPABILITY_VERSION = "1.1.0"

KEY_MAX_LENGTH = 128
KEY_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,128}$")
PAYLOAD_MAX_BYTES = 2048
PAYLOAD_MAX_DEPTH = 4
RESULT_MAX_BYTES = 2048
ERROR_MAX_CHARS = 200

# 1.17.63 (CQ183): the module part keeps the module id's own spelling (module ids are case-sensitive, docs/module-identifiers.md, and Core never
# case-folds one), so ``securityWAF.server_job_finished`` can register. The job part after the dot stays lowercase. ``clean_spec`` compares the
# module part with the module id exactly, so ``securitywaf.x`` and ``SecurityWAF.x`` cannot register for ``securityWAF``.
MODULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
JOB_ID_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_-]{0,63})\.([a-z0-9][a-z0-9._-]{0,79})$")
LABEL_MAX_CHARS = 120

# name: (minimum, default, maximum). Core's ceilings; a module cannot exceed the maximum.
LIMITS = {
    "soft_time_limit_seconds": (5, 30, 600),
    "max_attempts": (1, 3, 10),
    "backoff_seconds": (5, 60, 3600),
    "max_backoff_seconds": (5, 3600, 3600),
    "expires_seconds": (60, 1800, 86400),
    "max_backlog": (1, 500, 5000),
    "dedupe_seconds": (0, 0, 3600),
}
HARD_LIMIT_EXTRA_SECONDS = 15  # the hard time limit is the soft limit plus this
STALE_RUNNING_GRACE_SECONDS = 300  # a running row older than the hard limit plus this is a lost attempt
RETRY_JITTER_FRACTION = 0.2
OVERDUE_SECONDS = 60  # the tick enqueues a pending row whose next attempt passed this long ago
RATE_PER_MINUTE = 600  # publishes of one job one process accepts in a minute
IN_PROCESS_DEDUPE_SECONDS = 3
ENABLED_CACHE_SECONDS = 5
BACKLOG_GAUGE_SECONDS = 120  # a gauge older than this counts as absent (the gate is open)
BACKLOG_REFRESH_SECONDS = 30  # the publish path recounts the backlog at most this often per job
BREAKER_OPEN_SECONDS = 30
BROKER_TIMEOUT_SECONDS = 2
STATEMENT_TIMEOUT_MS = 1000
TICK_ROW_LIMIT = 200
FINISHED_ROW_CAP = 20000
PRUNE_BATCH = 1000
DROP_FLUSH_SECONDS = 60
REFUSAL_WINDOW_SECONDS = 3600  # refused publishes are tallied per clock hour and reported once, after the hour ends (1.17.48)
REFUSAL_CACHE_PREFIX = "tectac:eventjob-refused"  # the tally lives in Django's shared cache, never in the database
REFUSAL_TTL_SECONDS = 3 * 3600  # long enough for the tick after the hour, and for one that missed it
REFUSAL_FLUSH_SECONDS = 60  # a process sends its buffered refusal counts to the worker at most this often (1.17.49)
REFUSAL_MAX_ENTRIES = 64  # entries in one broker message; a longer list is refused by the worker
REFUSAL_BUFFER_KEYS = 256  # (module, job, hour) keys a process buffers before it clears the buffer
REFUSAL_COUNT_MAX = 100000  # the worker clamps one entry's count to 1..this
REFUSAL_BUCKET_AGE_HOURS = 3  # the worker takes only an hour no older than this

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_EXPIRED = "expired"
ACTIVE_STATUSES = (STATUS_PENDING, STATUS_RUNNING)
FINISHED_STATUSES = (STATUS_SUCCEEDED, STATUS_FAILED, STATUS_SKIPPED, STATUS_EXPIRED)

OUTCOMES = ("queued", "duplicate", "dropped", "disabled", "error")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


class EventJobPolicyError(ValueError):
    """A key, payload or registration argument Core refuses. The message is plain and never holds a payload value."""


# ------------------------------------------------------------------------------------------------ key and payload

def clean_key(key: Any) -> str:
    """The caller-supplied idempotency key: 1 to 128 characters of letters, digits and . _ : @ / -."""
    if not isinstance(key, str) or not KEY_RE.match(key):
        raise EventJobPolicyError(f"key must be 1 to {KEY_MAX_LENGTH} characters of letters, digits and . _ : @ / -.")
    return key


def _json_safe(value: Any, depth: int) -> bool:
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if depth >= PAYLOAD_MAX_DEPTH:
        return False
    if isinstance(value, list):
        return all(_json_safe(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _json_safe(v, depth + 1) for k, v in value.items())
    return False


def clean_payload(payload: Any) -> dict:
    """A JSON object of at most 2 KiB with scalar, list and dict values only. ``None`` is an empty object.

    Checked before anything is stored. The error text never holds a value: a payload is data, never logged, audited or listed."""
    if payload is None:
        return {}
    if type(payload) is not dict:
        raise EventJobPolicyError("payload must be a JSON object (a plain dict).")
    if not _json_safe(payload, 0):
        raise EventJobPolicyError(f"payload may hold only text, numbers, true, false, null, lists and objects, at most {PAYLOAD_MAX_DEPTH} levels deep.")
    try:
        size = len(json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        raise EventJobPolicyError("payload must be JSON.") from None
    if size > PAYLOAD_MAX_BYTES:
        raise EventJobPolicyError(f"payload is larger than {PAYLOAD_MAX_BYTES} bytes. Send ids, not text bodies.")
    return json.loads(json.dumps(payload))


def short_error(exc: BaseException | None) -> str:
    """One line of at most 200 characters for the audit row and the job row: the class name, then the text."""
    if exc is None:
        return ""
    text = _CONTROL_RE.sub(" ", str(exc)).strip()
    line = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
    return line[:ERROR_MAX_CHARS]


def cap_result(result: Any) -> dict:
    """What a handler returned, kept small. ``None`` is empty; a JSON-safe dict is kept up to 2 KiB; anything else is cut."""
    if result is None:
        return {}
    if isinstance(result, dict) and _json_safe(result, 0):
        encoded = json.dumps(result, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) <= RESULT_MAX_BYTES:
            return json.loads(encoded)
        return {"truncated": True}
    return {"value": _CONTROL_RE.sub(" ", str(result))[:ERROR_MAX_CHARS]}


# ------------------------------------------------------------------------------------------------ registration

@dataclass(frozen=True)
class EventJobSpec:
    """The checked arguments of one registration, without the handler (the registry adds it)."""

    id: str
    module_id: str
    label: str
    soft_time_limit_seconds: int
    hard_time_limit_seconds: int
    max_attempts: int
    backoff_seconds: int
    max_backoff_seconds: int
    expires_seconds: int
    max_backlog: int
    dedupe_seconds: int
    audit_success: bool


def _bounded_int(name: str, value: Any) -> int:
    low, _default, high = LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise EventJobPolicyError(f"{name} must be a whole number from {low} to {high}.")
    if value < low or value > high:
        raise EventJobPolicyError(f"{name} must be from {low} to {high}. Core keeps that ceiling.")
    return value


def clean_spec(*, id: Any, module_id: Any, label: Any, soft_time_limit_seconds: Any = None, max_attempts: Any = None,
               backoff_seconds: Any = None, max_backoff_seconds: Any = None, expires_seconds: Any = None, max_backlog: Any = None,
               dedupe_seconds: Any = None, audit_success: Any = False) -> EventJobSpec:
    """Check every registration argument but the handler and the module's own folder (``event_jobs`` does those)."""
    if not isinstance(module_id, str) or not MODULE_ID_RE.fullmatch(module_id):
        raise EventJobPolicyError("module_id must be the module's own id.")
    if not isinstance(id, str):
        raise EventJobPolicyError("id must be '<module_id>.<job>'.")
    match = JOB_ID_RE.fullmatch(id)  # fullmatch: a "$" alone also accepts one trailing newline (1.17.63)
    if match is None:
        raise EventJobPolicyError("id must be '<module_id>.<job>': the module id as it is spelled, then a dot, then the job part in lowercase letters, digits, - _ and .")
    if match.group(1) != module_id:
        raise EventJobPolicyError("id must start with the module's own id and a dot: a module cannot register under another module's id.")
    if not isinstance(label, str) or not label.strip() or len(label.strip()) > LABEL_MAX_CHARS or _CONTROL_RE.search(label):
        raise EventJobPolicyError(f"label must be one line of 1 to {LABEL_MAX_CHARS} characters.")
    if not isinstance(audit_success, bool):
        raise EventJobPolicyError("audit_success must be true or false.")

    def pick(name: str, value: Any) -> int:
        return LIMITS[name][1] if value is None else _bounded_int(name, value)

    soft = pick("soft_time_limit_seconds", soft_time_limit_seconds)
    backoff = pick("backoff_seconds", backoff_seconds)
    cap = pick("max_backoff_seconds", max_backoff_seconds)
    if cap < backoff:
        raise EventJobPolicyError("max_backoff_seconds must be at least backoff_seconds.")
    return EventJobSpec(
        id=id, module_id=module_id, label=label.strip(), soft_time_limit_seconds=soft, hard_time_limit_seconds=soft + HARD_LIMIT_EXTRA_SECONDS,
        max_attempts=pick("max_attempts", max_attempts), backoff_seconds=backoff, max_backoff_seconds=cap,
        expires_seconds=pick("expires_seconds", expires_seconds), max_backlog=pick("max_backlog", max_backlog),
        dedupe_seconds=pick("dedupe_seconds", dedupe_seconds), audit_success=audit_success,
    )


# ------------------------------------------------------------------------------------------------ retry, expiry, recovery

def backoff_delay(attempt: int, base: int, cap: int, rand: Callable[[], float] = random.random) -> float:
    """Seconds to wait after failed attempt number ``attempt`` (1-based): ``base`` doubling, capped at ``cap``, plus up to 20 percent jitter."""
    attempt = max(1, int(attempt))
    delay = min(float(cap), float(base) * (2 ** min(attempt - 1, 30)))
    return delay + delay * RETRY_JITTER_FRACTION * min(max(rand(), 0.0), 1.0)


def failure_is_permanent(exc: BaseException) -> bool:
    """SchedulerPermanentError, ValueError and TypeError give up at once. Everything else, including a transient error and
    Celery's SoftTimeLimitExceeded, is retried until the attempts are used up."""
    if isinstance(exc, (ValueError, TypeError)):
        return True
    return any(klass.__name__ == "SchedulerPermanentError" for klass in type(exc).__mro__)


def after_failure(exc: BaseException, attempt: int, max_attempts: int) -> str:
    """``retry`` or ``give_up`` for a failed attempt."""
    if failure_is_permanent(exc) or attempt >= max_attempts:
        return "give_up"
    return "retry"


def is_expired(now: datetime, expires_at: datetime | None) -> bool:
    return expires_at is not None and now >= expires_at


def is_stale_running(now: datetime, started_at: datetime | None, hard_limit_seconds: int) -> bool:
    """A running row older than its hard time limit plus five minutes: the worker was killed or lost."""
    if started_at is None:
        return True
    return now - started_at > timedelta(seconds=int(hard_limit_seconds) + STALE_RUNNING_GRACE_SECONDS)


def is_overdue_pending(now: datetime, last_enqueued_at: datetime | None, next_attempt_at: datetime | None) -> bool:
    """Should the tick enqueue this pending row? Never enqueued, or its next attempt passed more than 60 seconds ago and it was
    not enqueued in the last 60 seconds (a message that was lost, or a worker that never reached it)."""
    if last_enqueued_at is None:
        return True
    due = next_attempt_at or last_enqueued_at
    return now - due > timedelta(seconds=OVERDUE_SECONDS) and now - last_enqueued_at > timedelta(seconds=OVERDUE_SECONDS)


def backlog_full(pending: int | None, max_backlog: int) -> bool:
    """The publish gate: closed only when a fresh gauge says the job is at its backlog. An absent gauge (``None``) is open."""
    return pending is not None and pending >= max_backlog


def over_backlog(pending: int, max_backlog: int) -> int:
    """How many of the oldest pending rows the tick trims to bring a job back to its backlog."""
    return max(0, pending - max_backlog)


# ------------------------------------------------------------------------------------------------ hot-path helpers

class RateWindow:
    """At most ``limit`` accepted publishes per job per clock minute, per process. ``clock`` returns seconds."""

    def __init__(self, limit: int = RATE_PER_MINUTE, clock: Callable[[], float] = None):
        import time

        self.limit = limit
        self.clock = clock or time.monotonic
        self._windows: dict[Any, list] = {}

    def allow(self, name: Any) -> bool:
        minute = int(self.clock() // 60)
        window = self._windows.get(name)
        if window is None or window[0] != minute:
            window = self._windows[name] = [minute, 0]
        if window[1] >= self.limit:
            return False
        window[1] += 1
        return True


class RecentKeys:
    """A short in-process memory of (job, key) pairs: the same pair inside ``seconds`` is a duplicate with no query at all."""

    def __init__(self, seconds: float = IN_PROCESS_DEDUPE_SECONDS, clock: Callable[[], float] = None, maximum: int = 4096):
        import time

        self.seconds = seconds
        self.clock = clock or time.monotonic
        self.maximum = maximum
        self._seen: dict[Any, float] = {}

    def seen(self, name: Any) -> bool:
        """True when ``name`` was seen inside the window; otherwise remember it and return False."""
        now = self.clock()
        stamp = self._seen.get(name)
        if stamp is not None and now - stamp < self.seconds:
            return True
        if len(self._seen) >= self.maximum:
            for old in [k for k, v in self._seen.items() if now - v >= self.seconds]:
                del self._seen[old]
            if len(self._seen) >= self.maximum:
                self._seen.clear()
        self._seen[name] = now
        return False


class CircuitBreaker:
    """After one broker failure, skip the broker for ``open_seconds``. The row stays pending and the tick enqueues it."""

    def __init__(self, open_seconds: float = BREAKER_OPEN_SECONDS, clock: Callable[[], float] = None):
        import time

        self.open_seconds = open_seconds
        self.clock = clock or time.monotonic
        self._opened_at: float | None = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if self.clock() - self._opened_at >= self.open_seconds:
            self._opened_at = None
            return True
        return False

    def failure(self) -> None:
        self._opened_at = self.clock()

    def success(self) -> None:
        self._opened_at = None


class TimedValue:
    """One value kept for ``seconds``. ``get`` answers ``default`` once it is older or was never set."""

    def __init__(self, seconds: float, clock: Callable[[], float] = None):
        import time

        self.seconds = seconds
        self.clock = clock or time.monotonic
        self._items: dict[Any, tuple[float, Any]] = {}

    def set(self, name: Any, value: Any) -> None:
        self._items[name] = (self.clock(), value)

    def get(self, name: Any, default: Any = None) -> Any:
        item = self._items.get(name)
        if item is None or self.clock() - item[0] >= self.seconds:
            return default
        return item[1]

    def adjust(self, name: Any, delta: int) -> None:
        """Add ``delta`` to a number that is still fresh, keeping its age. Nothing happens for an absent or old value."""
        item = self._items.get(name)
        if item is not None and self.clock() - item[0] < self.seconds:
            self._items[name] = (item[0], max(0, item[1] + delta))

    def age(self, name: Any) -> float | None:
        item = self._items.get(name)
        return None if item is None else self.clock() - item[0]

    def clear(self) -> None:
        self._items.clear()
