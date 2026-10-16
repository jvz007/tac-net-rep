"""Event-started, time-limited system jobs (Core 1.17.45, capability ``core.event_jobs`` 1.0.0).

A module sometimes has to do a small piece of work because something happened: a Tactical alert was saved, a webhook arrived. It must
not do it inside the request, and it must not run its own thread, timer or private Celery task for it. This module is the one sanctioned
way. Core owns every limit, the retries, the backlog, the expiry and the audit.

How a module uses it (``AppConfig.ready()`` only; memory only, nothing is written to the database)::

    from tec_tac.event_jobs import register_event_job

    publisher = register_event_job(id="alerts.deliver", module_id="alerts", label="Send an alert notice", handler=deliver)
    ...
    publisher.publish(key=f"alert:{alert.pk}:{state}", payload={"alert_id": alert.pk})   # from a signal receiver

``register_event_job`` returns the one handle that can publish this job. Only the module that registered holds it. Registration is
bound to the module itself: ``module_id`` must be an installed, enabled extension read from the registry, the id must start with
``<module_id>.``, and the handler's code file must lie inside that module's own folder. A module cannot register under another
module's id, point an id at code that is not its own, or publish for another module (no other module is given the handle).

What the publish does. It never raises and never makes a network call but one bounded broker publish. It answers from memory first (the
registry, a five second module-enabled cache, a three second in-process duplicate check, a per-process rate cap, a cached backlog gauge)
and drops without a database query when any of them says no. Otherwise, after the caller's transaction commits (at once when none is
open), it stores one row (PostgreSQL: statement timeout 1000 ms) and sends one Celery message with a 2 second broker timeout and a 30
second circuit breaker. The row is the durable record. If the broker is down or a uWSGI worker is recycled, the row stays ``pending`` and
the Scheduler tick enqueues it, so nothing is lost.

What the worker does. ``tec_tac.execute_event_job`` claims the row (pending to running) under a row lock, so a duplicate delivery runs
nothing twice. It re-checks, uncached, that the module is still installed and enabled, that the handler is registered in this process
and that the job has not expired. The handler gets a Core-issued ``EventJobContext`` with no user fields. A handler runs at least once
and must be safe to run twice. Retries, back-off and give-up are Core's. See docs/event-jobs.md for the full contract and the limits.

The job runs as the module, not as a person. A handler cannot call ``run_tactical_operation`` (it needs a person's request), so an event
job cannot make a Tactical change. That is the AD-13 system-action contract, which is still open.
"""
from __future__ import annotations

import contextlib
import logging
import os
import random
import threading
import time
import weakref
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from . import event_jobs_policy as policy
from .event_jobs_policy import EventJobPolicyError, EventJobSpec

logger = logging.getLogger("tec_tac.event_jobs")

CAPABILITY_ID = policy.CAPABILITY_ID
CAPABILITY_VERSION = policy.CAPABILITY_VERSION
TASK_NAME = "tec_tac.execute_event_job"
ACTOR_SERVICE = "event-jobs"
REQUESTED_BY = "event-job"
OBJECT_TYPE = "event_job"

ACTION_FAILED = "custom:event-job-failed"
ACTION_SKIPPED = "custom:event-job-skipped"
ACTION_EXPIRED = "custom:event-job-expired"
ACTION_DROPPED = "custom:event-job-dropped"
ACTION_SUCCEEDED = "run"

DEFAULT_HARD_LIMIT = policy.LIMITS["soft_time_limit_seconds"][2] + policy.HARD_LIMIT_EXTRA_SECONDS


class EventJobError(RuntimeError):
    """Base of the errors this module raises."""


class EventJobRegistrationError(ValueError):
    """A registration Core refuses (a ValueError, like the other registration contracts). The message is plain and holds no payload."""


class EventJobContextInvalid(EventJobError):
    """``verify_event_job_context`` refused a context. The message is plain and names no ids."""


class EventJobLost(RuntimeError):
    """The synthetic failure of an attempt whose worker was killed or lost (recorded by the tick)."""


@dataclass(frozen=True)
class EventJobDefinition:
    """One registered job: the checked arguments and the handler."""

    spec: EventJobSpec
    handler: Callable

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def module_id(self) -> str:
        return self.spec.module_id


@dataclass(frozen=True)
class PublishResult:
    """What ``publish`` answers. ``outcome`` is one of queued, duplicate, dropped, disabled and error. It is never an exception."""

    outcome: str
    reason: str = ""


_LOCK = threading.RLock()
_JOBS: dict[str, EventJobDefinition] = {}
_HANDLES: dict[str, "EventJobPublisher"] = {}
_TOKEN = object()

# The hot-path memory. All of it is per process and none of it needs the database.
_RECENT = policy.RecentKeys()
_RATE = policy.RateWindow()
_BREAKER = policy.CircuitBreaker()
_GAUGES = policy.TimedValue(policy.BACKLOG_GAUGE_SECONDS)
_ENABLED = policy.TimedValue(policy.ENABLED_CACHE_SECONDS)
_COUNTERS: dict[tuple[str, str], dict[str, int]] = {}
_COUNTER_LOCK = threading.Lock()
_LAST_FLUSH = [0.0]
_rand: Callable[[], float] = random.random  # a test replaces it


# ------------------------------------------------------------------------------------------------ the places this module reads Core
# Each one is small so a test can replace it without Django.

def _plugins() -> tuple:
    from . import registry

    return tuple(registry.discover_plugins())


def _enabled_now(module_id: str) -> bool:
    from . import module_state

    return bool(module_state.is_enabled(module_id))


def _module_runnable_now(module_id: str) -> bool:
    """Authoritative and uncached: the module is an installed, non-legacy extension and enabled right now. Fails closed."""
    try:
        for plugin in _plugins():
            if plugin.plugin_id == module_id:
                return plugin.plugin_type == "extension" and not plugin.legacy and _enabled_now(module_id)
    except Exception:
        logger.warning("Could not read the state of module %s; treating it as unavailable.", module_id, exc_info=True)
    return False


def _module_enabled_cached(module_id: str) -> bool:
    """The publish path's check: the module-state read, kept for five seconds. A failed read counts as disabled."""
    known = _ENABLED.get(module_id)
    if known is not None:
        return known
    try:
        value = _enabled_now(module_id)
    except Exception:
        logger.warning("Could not read the enabled state of module %s; event jobs are not published.", module_id, exc_info=True)
        value = False
    _ENABLED.set(module_id, value)
    return value


def _norm(path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


# ------------------------------------------------------------------------------------------------ registration

def _verify_owner(module_id: str, handler: Callable) -> None:
    try:
        plugins = _plugins()
    except Exception:
        logger.warning("Event job registration: the installed modules could not be read.", exc_info=True)
        raise EventJobRegistrationError("Core could not read the installed modules to verify the owner.") from None
    plugin = next((p for p in plugins if p.plugin_id == module_id), None)
    if plugin is None or plugin.plugin_type != "extension" or plugin.legacy:
        raise EventJobRegistrationError("module_id is not an installed extension module.")
    try:
        enabled = _enabled_now(module_id)
    except Exception:
        raise EventJobRegistrationError("Core could not read whether the module is enabled.") from None
    if not enabled:
        raise EventJobRegistrationError("module_id is not enabled.")
    code = getattr(getattr(handler, "__func__", handler), "__code__", None)
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        raise EventJobRegistrationError("handler must be a function or method defined in the module's own code, not a partial, a built-in or generated code.")
    if not _under(_norm(filename), _norm(plugin.root)):
        raise EventJobRegistrationError("handler's code must lie inside the module's own folder: a module cannot point an event job at code that is not its own.")


def register_event_job(*, id, module_id, label, handler, soft_time_limit_seconds=None, max_attempts=None, backoff_seconds=None,
                       max_backoff_seconds=None, expires_seconds=None, max_backlog=None, dedupe_seconds=None, audit_success=False):
    """Register one event job and return the handle that publishes it. Call it from ``AppConfig.ready()``; it touches memory only.

    ``id`` is ``'<module_id>.<job>'``. ``handler(context)`` receives an ``EventJobContext`` and returns ``None`` or a small JSON-safe
    dict. Limits are Core's: ``soft_time_limit_seconds`` 5-600 (default 30; the hard limit is 15 seconds more), ``max_attempts`` 1-10
    (3), ``backoff_seconds`` 5-3600 (60, doubling, capped by ``max_backoff_seconds`` up to 3600), ``expires_seconds`` 60-86400 (1800: a
    job not started by then ends ``expired``), ``max_backlog`` 1-5000 (500), ``dedupe_seconds`` 0-3600 (0) and ``audit_success``
    (False). Registering the identical definition again returns the same handle; a different one is refused. A refusal raises
    ``EventJobRegistrationError`` (a ValueError): a module wraps the call, logs and goes on, so Tactical always starts.
    """
    try:
        spec = policy.clean_spec(
            id=id, module_id=module_id, label=label, soft_time_limit_seconds=soft_time_limit_seconds, max_attempts=max_attempts,
            backoff_seconds=backoff_seconds, max_backoff_seconds=max_backoff_seconds, expires_seconds=expires_seconds,
            max_backlog=max_backlog, dedupe_seconds=dedupe_seconds, audit_success=audit_success,
        )
    except EventJobPolicyError as exc:
        raise EventJobRegistrationError(str(exc)) from None
    if not callable(handler):
        raise EventJobRegistrationError("handler must be callable.")
    definition = EventJobDefinition(spec, handler)
    with _LOCK:
        previous = _JOBS.get(spec.id)
        if previous is not None:
            if previous == definition:
                return _HANDLES[spec.id]
            raise EventJobRegistrationError(f"event job {spec.id!r} is already registered with a different definition.")
    _verify_owner(spec.module_id, handler)  # reads the registry; kept outside the lock
    with _LOCK:
        previous = _JOBS.get(spec.id)
        if previous is not None:
            if previous == definition:
                return _HANDLES[spec.id]
            raise EventJobRegistrationError(f"event job {spec.id!r} is already registered with a different definition.")
        handle = EventJobPublisher(_TOKEN, spec.id, spec.module_id)
        _JOBS[spec.id] = definition
        _HANDLES[spec.id] = handle
    return handle


def registered_event_jobs() -> list[dict]:
    """The jobs registered in this process, as plain metadata rows (no handler, no handle)."""
    with _LOCK:
        jobs = sorted(_JOBS.values(), key=lambda d: (d.module_id, d.id))
    return [_describe(d) for d in jobs]


def _describe(definition: EventJobDefinition) -> dict:
    s = definition.spec
    return {
        "id": s.id, "module_id": s.module_id, "label": s.label, "soft_time_limit_seconds": s.soft_time_limit_seconds,
        "hard_time_limit_seconds": s.hard_time_limit_seconds, "max_attempts": s.max_attempts, "backoff_seconds": s.backoff_seconds,
        "max_backoff_seconds": s.max_backoff_seconds, "expires_seconds": s.expires_seconds, "max_backlog": s.max_backlog,
        "dedupe_seconds": s.dedupe_seconds, "audit_success": s.audit_success,
    }


def _definition_for(handle) -> EventJobDefinition | None:
    """The definition a handle may publish for, or None. The handle must be the very object ``register_event_job`` returned."""
    if type(handle) is not EventJobPublisher:
        return None
    job_id = object.__getattribute__(handle, "_job_id")
    with _LOCK:
        if _HANDLES.get(job_id) is not handle:
            return None
        return _JOBS.get(job_id)


class EventJobPublisher:
    """The handle that publishes one event job. Issued only by ``register_event_job``; it cannot be built, copied or pickled."""

    __slots__ = ("_job_id", "_module_id")

    def __init__(self, token, job_id, module_id):
        if token is not _TOKEN:
            raise TypeError("An event job publisher is issued by register_event_job only.")
        object.__setattr__(self, "_job_id", job_id)
        object.__setattr__(self, "_module_id", module_id)

    def __setattr__(self, name, value):
        raise AttributeError("An event job publisher cannot be changed.")

    @property
    def job_id(self) -> str:
        return self._job_id

    @property
    def module_id(self) -> str:
        return self._module_id

    def publish(self, key, payload=None) -> PublishResult:
        """Publish one event. Never raises. See the module text for what it does and what each outcome means."""
        return _publish(self, key, payload)

    def status(self) -> dict:
        """Counts, backlog, oldest pending age and last failure of this job only. Never a key or a payload. Never raises."""
        return _publisher_status(self)

    def __copy__(self):
        raise TypeError("An event job publisher cannot be copied.")

    def __deepcopy__(self, memo):
        raise TypeError("An event job publisher cannot be copied.")

    def __reduce_ex__(self, protocol):
        raise TypeError("An event job publisher cannot be pickled.")

    def __repr__(self):
        return f"<EventJobPublisher {self._job_id}>"


# ------------------------------------------------------------------------------------------------ counters

def _count(job: EventJobDefinition, name: str, amount: int = 1) -> None:
    with _COUNTER_LOCK:
        row = _COUNTERS.setdefault((job.module_id, job.id), {})
        row[name] = row.get(name, 0) + amount


@contextlib.contextmanager
def _bounded_atomic():
    """A transaction. On PostgreSQL its statements may take 1000 ms each at most (SET LOCAL ends with the transaction)."""
    with transaction.atomic():
        if getattr(connection, "vendor", "") == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute(f"SET LOCAL statement_timeout = {int(policy.STATEMENT_TIMEOUT_MS)}")
        yield


def _locked_stat(module_id: str, job_id: str):
    """The stat row of a job, locked for update, created when absent. Call inside a transaction."""
    from .models import TecTacEventJobStat

    stat = TecTacEventJobStat.objects.select_for_update().filter(module_id=module_id, job_id=job_id).first()
    if stat is not None:
        return stat
    try:
        with transaction.atomic():
            TecTacEventJobStat.objects.create(module_id=module_id, job_id=job_id)
    except IntegrityError:
        pass
    return TecTacEventJobStat.objects.select_for_update().filter(module_id=module_id, job_id=job_id).first()


def _bump_stat(module_id: str, job_id: str, now, **counts) -> None:
    """Add to a job's counters. ``dropped`` also feeds the 24 hour window. Call inside a transaction."""
    stat = _locked_stat(module_id, job_id)
    if stat is None:
        return
    for name, amount in counts.items():
        if name in ("last_failure_at", "last_error"):
            setattr(stat, name, amount)
        elif amount:
            setattr(stat, name, int(getattr(stat, name) or 0) + int(amount))
    dropped = int(counts.get("dropped", 0) or 0)
    if dropped:
        started = stat.dropped_day_started
        if started is None or now - started > timedelta(hours=24):
            stat.dropped_day, stat.dropped_day_started = dropped, now
        else:
            stat.dropped_day = int(stat.dropped_day or 0) + dropped
    stat.save()


def flush_counters(now=None, *, force: bool = False) -> int:
    """Write this process's hot-path counters (published, duplicate, dropped) to the stat rows. Never raises. At most once a minute
    unless ``force``, and never inside a caller's open transaction (it would hold the stat row's lock until that commits)."""
    try:
        if not force:
            if connection.in_atomic_block or time.monotonic() - _LAST_FLUSH[0] < policy.DROP_FLUSH_SECONDS:
                return 0
        with _COUNTER_LOCK:
            pending = {key: dict(value) for key, value in _COUNTERS.items() if any(value.values())}
            _COUNTERS.clear()
            _LAST_FLUSH[0] = time.monotonic()
        if not pending:
            return 0
        now = now or timezone.now()
        written = 0
        for (module_id, job_id), counts in pending.items():
            try:
                with _bounded_atomic():
                    _bump_stat(module_id, job_id, now, **counts)
                written += 1
            except Exception:
                logger.exception("Event job counters of %s could not be written; they are kept for the next try.", job_id)
                with _COUNTER_LOCK:
                    back = _COUNTERS.setdefault((module_id, job_id), {})
                    for name, amount in counts.items():
                        back[name] = back.get(name, 0) + amount
        return written
    except Exception:
        logger.exception("Event job counters could not be flushed.")
        return 0


# ------------------------------------------------------------------------------------------------ publish

def _publish(handle, key, payload) -> PublishResult:
    try:
        definition = _definition_for(handle)
        if definition is None:
            logger.warning("An event job publish came from a handle that is not a registered publisher; it was ignored.")
            return PublishResult("error", "not a registered publisher")
        if not _module_enabled_cached(definition.module_id):
            return PublishResult("disabled")
        try:
            key = policy.clean_key(key)
            payload = policy.clean_payload(payload)
        except EventJobPolicyError as exc:
            logger.warning("Event job %s: publish refused: %s", definition.id, exc)
            return PublishResult("error", str(exc))
        if _RECENT.seen((definition.id, key)):
            _count(definition, "duplicate")
            return PublishResult("duplicate")
        if not _RATE.allow(definition.id):
            _count(definition, "dropped")
            _maybe_flush_drops()
            return PublishResult("dropped", "rate")
        if policy.backlog_full(_GAUGES.get(definition.id), definition.spec.max_backlog):
            _count(definition, "dropped")
            _maybe_flush_drops()
            return PublishResult("dropped", "backlog")
        if connection.in_atomic_block:
            transaction.on_commit(lambda: _persist_safely(definition, key, payload))
            return PublishResult("queued")
        return PublishResult(_persist_safely(definition, key, payload))
    except Exception:
        logger.exception("An event job could not be published.")
        return PublishResult("error", "unexpected failure")


def _maybe_flush_drops() -> None:
    if not connection.in_atomic_block:
        flush_counters()


def _persist_safely(definition: EventJobDefinition, key: str, payload: dict) -> str:
    """Store the row and send the message. Never raises. Returns queued, duplicate or error."""
    try:
        outcome, row = _persist(definition, key, payload)
        if outcome == "duplicate":
            _count(definition, "duplicate")
            return "duplicate"
        _count(definition, "published")
        _GAUGES.adjust(definition.id, 1)
        if _GAUGES.age(definition.id) is None or _GAUGES.age(definition.id) > policy.BACKLOG_REFRESH_SECONDS:
            _refresh_gauge(definition.module_id, definition.id)
        if not _enqueue_row(row):
            _mark_not_enqueued(row)
        flush_counters()
        return "queued"
    except Exception:
        logger.exception("Event job %s could not be stored.", definition.id)
        return "error"


def _snapshot(spec: EventJobSpec) -> dict:
    return {
        "soft": spec.soft_time_limit_seconds, "hard": spec.hard_time_limit_seconds, "backoff": spec.backoff_seconds,
        "max_backoff": spec.max_backoff_seconds, "audit_success": spec.audit_success, "dedupe": spec.dedupe_seconds,
    }


def _persist(definition: EventJobDefinition, key: str, payload: dict):
    from .models import TecTacEventJob

    spec = definition.spec
    now = timezone.now()
    if spec.dedupe_seconds > 0:
        since = now - timedelta(seconds=spec.dedupe_seconds)
        if TecTacEventJob.objects.filter(
            module_id=spec.module_id, job_id=spec.id, key=key, status=policy.STATUS_SUCCEEDED, finished_at__gte=since,
        ).exists():
            return "duplicate", None
    try:
        with _bounded_atomic():
            row = TecTacEventJob.objects.create(
                module_id=spec.module_id, job_id=spec.id, key=key, payload=payload, policy=_snapshot(spec),
                status=policy.STATUS_PENDING, max_attempts=spec.max_attempts, next_attempt_at=now,
                expires_at=now + timedelta(seconds=spec.expires_seconds), last_enqueued_at=now,
            )
    except IntegrityError:
        return "duplicate", None
    return "queued", row


def _enqueue_row(row, *, countdown: float = 0, now=None) -> bool:
    """Send the Celery message that tells a worker to look at ``row``. One bounded attempt. Never raises. False when skipped or failed."""
    try:
        if not _BREAKER.allow():
            return False
        now = now or timezone.now()
        remaining = (row.expires_at - now).total_seconds() if row.expires_at else policy.LIMITS["expires_seconds"][1]
        if remaining <= 1:
            return False
        policy_row = row.policy if isinstance(row.policy, dict) else {}
        soft = int(policy_row.get("soft") or policy.LIMITS["soft_time_limit_seconds"][1])
        hard = int(policy_row.get("hard") or soft + policy.HARD_LIMIT_EXTRA_SECONDS)
        from .tasks import execute_event_job

        timeout = policy.BROKER_TIMEOUT_SECONDS
        options = {"socket_timeout": timeout, "socket_connect_timeout": timeout}
        with execute_event_job.app.connection_for_write(transport_options=options, connect_timeout=timeout) as broker:
            execute_event_job.apply_async(
                args=[str(row.pk)], countdown=max(0, countdown), connection=broker, retry=False, expires=max(1, remaining),
                ignore_result=True, soft_time_limit=soft, time_limit=hard,
            )
        _BREAKER.success()
        return True
    except Exception:
        _BREAKER.failure()
        logger.warning("Event job message could not be sent; the row stays pending and the Scheduler tick enqueues it.", exc_info=True)
        return False


def _mark_not_enqueued(row) -> None:
    """The broker did not take the message: clear the enqueue stamp so the next tick enqueues the row."""
    try:
        from .models import TecTacEventJob

        TecTacEventJob.objects.filter(pk=row.pk, status=policy.STATUS_PENDING).update(last_enqueued_at=None)
    except Exception:
        logger.exception("An event job row could not be marked for the tick; it will be enqueued when overdue.")


def _refresh_gauge(module_id: str, job_id: str) -> int | None:
    try:
        from .models import TecTacEventJob

        with _bounded_atomic():
            count = TecTacEventJob.objects.filter(module_id=module_id, job_id=job_id, status=policy.STATUS_PENDING).count()
        _GAUGES.set(job_id, count)
        return count
    except Exception:
        logger.warning("The backlog of event job %s could not be counted; the publish gate stays open.", job_id, exc_info=True)
        return None


# ------------------------------------------------------------------------------------------------ the handler's context

class EventJobContext(dict):
    """The handler context Core issues. A plain dict to every reader; Core knows the instances it issued. It has no user fields."""


_CONTEXT_LOCK = threading.Lock()
_ISSUED: dict[int, tuple[weakref.ref, str, str, str]] = {}


def _issue_context(fields: dict, *, run_id, module_id: str, job_id: str) -> EventJobContext:
    context = EventJobContext(fields)
    key = id(context)

    def _forget(_ref, key=key):
        with _CONTEXT_LOCK:
            entry = _ISSUED.get(key)
            if entry is not None and entry[0] is _ref:
                del _ISSUED[key]

    with _CONTEXT_LOCK:
        _ISSUED[key] = (weakref.ref(context, _forget), str(run_id), module_id, job_id)
    return context


def _issued(context):
    if type(context) is not EventJobContext:
        return None
    with _CONTEXT_LOCK:
        entry = _ISSUED.get(id(context))
    if entry is None or entry[0]() is not context:
        return None
    return entry


def is_core_issued_event_job_context(context) -> bool:
    """True when ``context`` is a context Core issued itself. Never raises."""
    try:
        return _issued(context) is not None
    except Exception:
        return False


@dataclass(frozen=True)
class VerifiedEventJob:
    """What Core confirmed about a running job. Built only by ``verify_event_job_context``."""

    run_id: str
    module_id: str
    job_id: str
    key: str
    attempt: int
    final_attempt: bool


def _load_row(run_id):
    from .models import TecTacEventJob

    return TecTacEventJob.objects.filter(pk=run_id).first()


def verify_event_job_context(context, *, expected_module_id, expected_job_id) -> VerifiedEventJob:
    """Confirm that ``context`` is a context Core issued for a job of this module and id that is still running.

    The handler passes its own module id and job id (both required, keyword-only, non-empty text). Core compares them with the module
    and job of the run it issued the context for. A plain dict, a copy of the context, a context issued for another module's or
    job's run, a run that is no longer running and an expected id that is missing or not text are all refused with
    ``EventJobContextInvalid`` and a message that names no ids."""
    if not isinstance(expected_module_id, str) or not expected_module_id or not isinstance(expected_job_id, str) or not expected_job_id:
        raise EventJobContextInvalid("The expected module id and job id are required.")
    entry = _issued(context)
    if entry is None:
        raise EventJobContextInvalid("This is not an event job context that Core issued.")
    _ref, run_id, module_id, job_id = entry
    if module_id != expected_module_id or job_id != expected_job_id:
        raise EventJobContextInvalid("This context belongs to another module or job.")
    try:
        row = _load_row(run_id)
        if row is None or str(row.status) != policy.STATUS_RUNNING or row.module_id != module_id or row.job_id != job_id:
            raise EventJobContextInvalid("This job is no longer running.")
        return VerifiedEventJob(str(row.pk), module_id, job_id, str(row.key), int(row.attempt), int(row.attempt) >= int(row.max_attempts))
    except EventJobContextInvalid:
        raise
    except Exception:
        logger.warning("An event job context could not be verified.", exc_info=True)
        raise EventJobContextInvalid("The job could not be verified.") from None


# ------------------------------------------------------------------------------------------------ audit

def _audit(action: str, *, module_id: str, job_id: str, key: str = "", attempt: int = 0, error_type: str = "", error: str = "",
           message: str, extra: dict | None = None) -> None:
    """One Core audit row for an event job outcome. Never the payload, never a secret. Best effort: a failed write is logged."""
    try:
        from . import audit

        metadata = {
            "owner_module": module_id, "job_id": job_id, "key": key, "attempt": attempt, "error_type": error_type,
            "error": error[: policy.ERROR_MAX_CHARS], "requested_by": REQUESTED_BY,
        }
        metadata.update(extra or {})
        audit.record(
            actor=audit.service_audit_actor(module_id="core", service=ACTOR_SERVICE, identity=job_id), module_id="core", action=action,
            object_type=OBJECT_TYPE, object_id=job_id, message=message, metadata=metadata,
        )
    except Exception:
        logger.exception("The Core audit row of event job %s could not be written.", job_id)


def _audit_row(action: str, row, message: str, extra: dict | None = None) -> None:
    _audit(action, module_id=row.module_id, job_id=row.job_id, key=str(row.key), attempt=int(row.attempt or 0),
           error_type=str(row.error_type or ""), error=str(row.error or ""), message=message, extra=extra)


# ------------------------------------------------------------------------------------------------ run

def _policy_of(row) -> dict:
    return row.policy if isinstance(row.policy, dict) else {}


def run_event_job(row_id, *, celery_task_id: str = "", now=None) -> str:
    """Run one job: claim it, re-check it, call the handler, record the outcome. Called by ``tec_tac.execute_event_job``.

    Returns a short plain status. A handler exception is caught and handled here (retry or give up); a fault of Core's own bookkeeping
    propagates, which leaves the row ``running`` for the tick to recover."""
    from .models import TecTacEventJob

    now = now or timezone.now()
    verdict = None
    with transaction.atomic():
        try:
            row = TecTacEventJob.objects.select_for_update().get(pk=row_id)
        except TecTacEventJob.DoesNotExist:
            return "job missing"
        if row.status != policy.STATUS_PENDING:
            return f"job already {row.status}"
        if row.next_attempt_at is not None and row.next_attempt_at > now + timedelta(seconds=5):
            return "job not due"
        with _LOCK:
            definition = _JOBS.get(row.job_id)
        if policy.is_expired(now, row.expires_at):
            verdict = (policy.STATUS_EXPIRED, "Expired", "The job was not started in time.", ACTION_EXPIRED, "expired")
        elif not _module_runnable_now(row.module_id):
            verdict = (policy.STATUS_SKIPPED, "ModuleUnavailable", "The module is disabled or no longer installed.", ACTION_SKIPPED, "skipped")
        elif definition is None or definition.module_id != row.module_id:
            verdict = (policy.STATUS_SKIPPED, "HandlerNotRegistered", "The handler is not registered in this worker.", ACTION_SKIPPED, "skipped")
        if verdict:
            status, error_type, text, _action, counter = verdict
            row.status, row.error_type, row.error, row.finished_at = status, error_type, text, now
            row.save()
            _bump_stat(row.module_id, row.job_id, now, **{counter: 1})
        else:
            row.status = policy.STATUS_RUNNING
            row.attempt = int(row.attempt or 0) + 1
            row.started_at = now
            row.finished_at = None
            row.celery_task_id = str(celery_task_id or "")[:80]
            row.error, row.error_type = "", ""
            row.save()
    if verdict:
        _audit_row(verdict[3], row, f"Event job {row.job_id} did not run: {verdict[2]}")
        return f"job {verdict[0]}"

    spec = definition.spec
    context = _issue_context({
        "job_id": row.job_id, "module_id": row.module_id, "key": row.key, "payload": _copy_payload(row.payload),
        "attempt": int(row.attempt), "max_attempts": int(row.max_attempts), "final_attempt": int(row.attempt) >= int(row.max_attempts),
        "enqueued_at": row.created_at, "run_id": str(row.pk),
    }, run_id=row.pk, module_id=row.module_id, job_id=row.job_id)
    try:
        result = definition.handler(context)
    except Exception as exc:
        status = _finish_failure(row.pk, exc, now=timezone.now(), spec_policy=_snapshot(spec))
    else:
        status = _finish_success(row.pk, result, now=timezone.now(), audit_success=spec.audit_success)
    _refresh_gauge(row.module_id, row.job_id)
    return status


def _copy_payload(payload) -> dict:
    import json

    return json.loads(json.dumps(payload)) if isinstance(payload, dict) else {}


def _finish_success(row_id, result, *, now, audit_success: bool) -> str:
    from .models import TecTacEventJob

    with transaction.atomic():
        row = TecTacEventJob.objects.select_for_update().get(pk=row_id)
        if row.status != policy.STATUS_RUNNING:
            return f"job no longer active: {row.status}"
        row.status = policy.STATUS_SUCCEEDED
        row.result = policy.cap_result(result)
        row.finished_at = now
        row.error, row.error_type = "", ""
        row.save()
        _bump_stat(row.module_id, row.job_id, now, succeeded=1)
    if audit_success:
        _audit_row(ACTION_SUCCEEDED, row, f"Event job {row.job_id} ran.")
    return "job succeeded"


def _finish_failure(row_id, exc: BaseException, *, now, spec_policy: dict | None = None) -> str:
    """A failed attempt: retry with back-off, or give up. Used by the worker and by the tick (a lost attempt)."""
    from .models import TecTacEventJob

    retry_row = None
    delay = 0.0
    with transaction.atomic():
        row = TecTacEventJob.objects.select_for_update().get(pk=row_id)
        if row.status != policy.STATUS_RUNNING:
            return f"job no longer active: {row.status}"
        info = {**_policy_of(row), **(spec_policy or {})}
        text = policy.short_error(exc)
        row.error, row.error_type = text, type(exc).__name__[:120]
        decision = policy.after_failure(exc, int(row.attempt), int(row.max_attempts))
        if policy.is_expired(now, row.expires_at) and decision == "retry":
            decision = "give_up"
        if decision == "give_up":
            row.status, row.finished_at = policy.STATUS_FAILED, now
            row.save()
            _bump_stat(row.module_id, row.job_id, now, failed=1, last_failure_at=now, last_error=text)
        else:
            delay = policy.backoff_delay(
                int(row.attempt), int(info.get("backoff") or policy.LIMITS["backoff_seconds"][1]),
                int(info.get("max_backoff") or policy.LIMITS["max_backoff_seconds"][1]), _rand,
            )
            row.status, row.next_attempt_at, row.last_enqueued_at = policy.STATUS_PENDING, now + timedelta(seconds=delay), now
            row.save()
            _bump_stat(row.module_id, row.job_id, now, last_failure_at=now, last_error=text)
            retry_row = row
    if retry_row is None:
        _audit_row(ACTION_FAILED, row, f"Event job {row.job_id} gave up after {row.attempt} attempt(s).")
        return "job failed"
    if not _enqueue_row(retry_row, countdown=delay, now=now):
        logger.info("Event job %s retry was not sent; the Scheduler tick enqueues it when it is due.", row.job_id)
    return "job will retry"


# ------------------------------------------------------------------------------------------------ the Scheduler tick

def recover_event_jobs(now=None) -> dict:
    """The tick's work for event jobs. Each step is bounded (200 rows) and isolated: a fault in one is logged and the next still runs.

    Expires pending rows past their expiry and those of a disabled or uninstalled module, recovers running rows older than the hard
    limit plus five minutes, enqueues pending rows that were never enqueued or are overdue, trims a backlog over its limit (oldest
    first, counted as dropped), refreshes the backlog gauges, flushes this process's counters, writes one audit row per job that
    dropped, and prunes finished rows."""
    now = now or timezone.now()
    out = {"expired": 0, "module_unavailable": 0, "stale_recovered": 0, "enqueued": 0, "trimmed": 0, "dropped_reported": 0, "pruned": 0, "errors": 0}
    for step in (_tick_expire, _tick_module_gate, _tick_recover_running, _tick_enqueue_overdue, _tick_trim, _tick_gauges,
                 _tick_report_drops, _tick_prune):
        try:
            step(now, out)
        except Exception:
            out["errors"] += 1
            logger.exception("Event job tick step %s failed.", step.__name__)
    return out


def _expire_rows(rows, now, *, error_type: str, text: str, action: str, counter: str, out_key: str, out: dict) -> None:
    """End pending rows as ``expired``, one transaction each, and write one audit row per job (with the count)."""
    from .models import TecTacEventJob

    per_job: dict[tuple[str, str], int] = {}
    for candidate in rows:
        with transaction.atomic():
            row = TecTacEventJob.objects.select_for_update().filter(pk=candidate.pk).first()
            if row is None or row.status != policy.STATUS_PENDING:
                continue
            row.status, row.error_type, row.error, row.finished_at = policy.STATUS_EXPIRED, error_type, text, now
            row.save()
            if counter == "dropped":
                _bump_stat(row.module_id, row.job_id, now, dropped=1)
            else:
                _bump_stat(row.module_id, row.job_id, now, expired=1)
        per_job[(row.module_id, row.job_id)] = per_job.get((row.module_id, row.job_id), 0) + 1
        out[out_key] += 1
    if action == ACTION_DROPPED:
        return  # drops are audited from the stat row, once per job (see _tick_report_drops)
    for (module_id, job_id), count in per_job.items():
        _audit(action, module_id=module_id, job_id=job_id, error_type=error_type, error=text,
               message=f"Event job {job_id}: {count} job(s) ended unstarted: {text}", extra={"count": count})


def _tick_expire(now, out) -> None:
    from .models import TecTacEventJob

    rows = list(TecTacEventJob.objects.filter(status=policy.STATUS_PENDING, expires_at__lte=now).order_by("created_at")[: policy.TICK_ROW_LIMIT])
    _expire_rows(rows, now, error_type="Expired", text="The job was not started in time.", action=ACTION_EXPIRED, counter="expired",
                 out_key="expired", out=out)


def _tick_module_gate(now, out) -> None:
    from .models import TecTacEventJob

    modules = sorted(set(TecTacEventJob.objects.filter(status=policy.STATUS_PENDING).values_list("module_id", flat=True)))
    budget = policy.TICK_ROW_LIMIT
    for module_id in modules:
        if budget <= 0 or _module_runnable_now(module_id):
            continue
        rows = list(TecTacEventJob.objects.filter(module_id=module_id, status=policy.STATUS_PENDING).order_by("created_at")[:budget])
        budget -= len(rows)
        _expire_rows(rows, now, error_type="ModuleUnavailable", text="The module is disabled or no longer installed.",
                     action=ACTION_SKIPPED, counter="expired", out_key="module_unavailable", out=out)


def _tick_recover_running(now, out) -> None:
    from .models import TecTacEventJob

    rows = list(TecTacEventJob.objects.filter(status=policy.STATUS_RUNNING).order_by("started_at")[: policy.TICK_ROW_LIMIT])
    for row in rows:
        hard = int(_policy_of(row).get("hard") or DEFAULT_HARD_LIMIT)
        if not policy.is_stale_running(now, row.started_at, hard):
            continue
        _finish_failure(row.pk, EventJobLost("The worker did not finish this attempt (it was stopped or lost)."), now=now)
        out["stale_recovered"] += 1


def _tick_enqueue_overdue(now, out) -> None:
    from .models import TecTacEventJob

    cutoff = now - timedelta(seconds=policy.OVERDUE_SECONDS)
    rows = list(TecTacEventJob.objects.filter(status=policy.STATUS_PENDING, last_enqueued_at__isnull=True).order_by("created_at")[: policy.TICK_ROW_LIMIT])
    room = policy.TICK_ROW_LIMIT - len(rows)
    if room > 0:
        rows += list(TecTacEventJob.objects.filter(
            status=policy.STATUS_PENDING, next_attempt_at__lt=cutoff, last_enqueued_at__lt=cutoff,
        ).order_by("next_attempt_at")[:room])
    for row in rows:
        if not policy.is_overdue_pending(now, row.last_enqueued_at, row.next_attempt_at):
            continue
        if not _enqueue_row(row, now=now):
            break  # the broker is down (the circuit breaker is open) or the row is past its expiry: try again next minute
        TecTacEventJob.objects.filter(pk=row.pk, status=policy.STATUS_PENDING).update(last_enqueued_at=now)
        out["enqueued"] += 1


def _known_jobs() -> list[tuple[str, str]]:
    """Every (module id, job id) with a stat row or a registration in this process."""
    from .models import TecTacEventJobStat

    found = {(stat.module_id, stat.job_id) for stat in TecTacEventJobStat.objects.all()[:500]}
    with _LOCK:
        found.update((d.module_id, d.id) for d in _JOBS.values())
    return sorted(found)


def _tick_trim(now, out) -> None:
    from .models import TecTacEventJob

    budget = policy.TICK_ROW_LIMIT
    for module_id, job_id in _known_jobs():
        with _LOCK:
            definition = _JOBS.get(job_id)
        if definition is None or budget <= 0:
            continue
        pending = TecTacEventJob.objects.filter(module_id=module_id, job_id=job_id, status=policy.STATUS_PENDING).count()
        excess = min(policy.over_backlog(pending, definition.spec.max_backlog), budget)
        if excess <= 0:
            continue
        rows = list(TecTacEventJob.objects.filter(module_id=module_id, job_id=job_id, status=policy.STATUS_PENDING).order_by("created_at")[:excess])
        budget -= len(rows)
        _expire_rows(rows, now, error_type="Dropped", text="The backlog was over its limit; the oldest job was dropped.",
                     action=ACTION_DROPPED, counter="dropped", out_key="trimmed", out=out)


def _tick_gauges(now, out) -> None:
    with _LOCK:
        definitions = list(_JOBS.values())
    for definition in definitions:
        _refresh_gauge(definition.module_id, definition.id)


def _tick_report_drops(now, out) -> None:
    """Flush this process's counters, then write one audit row per job whose drops have no row yet."""
    from .models import TecTacEventJobStat

    flush_counters(now, force=True)
    for stat in list(TecTacEventJobStat.objects.all()[:500]):
        if int(stat.dropped or 0) <= int(stat.dropped_reported or 0):
            continue
        with transaction.atomic():
            locked = TecTacEventJobStat.objects.select_for_update().filter(pk=stat.pk).first()
            if locked is None:
                continue
            count = int(locked.dropped or 0) - int(locked.dropped_reported or 0)
            if count <= 0:
                continue
            locked.dropped_reported = locked.dropped
            locked.save()
        _audit(ACTION_DROPPED, module_id=stat.module_id, job_id=stat.job_id, error_type="Dropped",
               message=f"Event job {stat.job_id}: {count} publish(es) were dropped because the job was over its backlog or rate limit.",
               extra={"count": count})
        out["dropped_reported"] += 1


def _retention_days() -> int:
    try:
        from .models import TecTacSchedulerConfig

        return max(1, min(int(TecTacSchedulerConfig.current().run_retention_days or 90), 3650))
    except Exception:
        return 90


def _tick_prune(now, out) -> None:
    from .models import TecTacEventJob

    cutoff = now - timedelta(days=_retention_days())
    old = list(TecTacEventJob.objects.filter(status__in=policy.FINISHED_STATUSES, finished_at__lt=cutoff).order_by("finished_at").values_list("pk", flat=True)[: policy.PRUNE_BATCH])
    if old:
        TecTacEventJob.objects.filter(pk__in=old).delete()
        out["pruned"] += len(old)
    total = TecTacEventJob.objects.filter(status__in=policy.FINISHED_STATUSES).count()
    if total > policy.FINISHED_ROW_CAP:
        excess = min(total - policy.FINISHED_ROW_CAP, policy.PRUNE_BATCH)
        extra = list(TecTacEventJob.objects.filter(status__in=policy.FINISHED_STATUSES).order_by("finished_at").values_list("pk", flat=True)[:excess])
        if extra:
            TecTacEventJob.objects.filter(pk__in=extra).delete()
            out["pruned"] += len(extra)


# ------------------------------------------------------------------------------------------------ status, health and listing

def _age_seconds(now, moment) -> int | None:
    return None if moment is None else max(0, int((now - moment).total_seconds()))


def _job_entry(module_id: str, job_id: str, now) -> dict:
    """One job's counts. Counts, ages and the last error only: never a payload, a key or a row id."""
    from .models import TecTacEventJob, TecTacEventJobStat

    with _LOCK:
        definition = _JOBS.get(job_id)
    jobs = TecTacEventJob.objects.filter(module_id=module_id, job_id=job_id)
    stat = TecTacEventJobStat.objects.filter(module_id=module_id, job_id=job_id).first()
    oldest = jobs.filter(status=policy.STATUS_PENDING).order_by("created_at").first()
    entry = {
        "module_id": module_id, "job_id": job_id, "label": definition.spec.label if definition else "", "registered": definition is not None,
        "pending": jobs.filter(status=policy.STATUS_PENDING).count(), "running": jobs.filter(status=policy.STATUS_RUNNING).count(),
        "oldest_pending_age_seconds": _age_seconds(now, oldest.created_at) if oldest else None,
        "published": int(stat.published) if stat else 0, "duplicate": int(stat.duplicate) if stat else 0,
        "dropped": int(stat.dropped) if stat else 0, "succeeded": int(stat.succeeded) if stat else 0,
        "failed": int(stat.failed) if stat else 0, "expired": int(stat.expired) if stat else 0, "skipped": int(stat.skipped) if stat else 0,
        "last_failure_at": stat.last_failure_at.isoformat() if stat and stat.last_failure_at else None,
        "last_error": str(stat.last_error) if stat else "",
        "max_backlog": definition.spec.max_backlog if definition else None,
    }
    return entry


def _publisher_status(handle) -> dict:
    try:
        definition = _definition_for(handle)
        if definition is None:
            return {}
        return _job_entry(definition.module_id, definition.id, timezone.now())
    except Exception:
        logger.exception("The status of an event job could not be read.")
        return {}


def list_event_jobs(now=None) -> dict:
    """Every known job with counts and its last error, and the totals. For the read route and the Scheduler page. Never a payload or key."""
    now = now or timezone.now()
    jobs = [_job_entry(module_id, job_id, now) for module_id, job_id in _known_jobs()]
    totals = {name: sum(int(item[name]) for item in jobs) for name in ("pending", "running", "published", "dropped", "succeeded", "failed", "expired", "skipped")}
    return {"jobs": jobs, "totals": totals, "limits": {name: {"minimum": low, "default": default, "maximum": high} for name, (low, default, high) in policy.LIMITS.items()}}


def event_jobs_health(now=None) -> dict:
    """The additive ``event_jobs`` block of ``scheduler_health()``. Never raises: a fault gives the zero block with ``error``."""
    now = now or timezone.now()
    block = {"registered": 0, "pending": 0, "running": 0, "failed_last_24h": 0, "dropped_last_24h": 0, "oldest_pending_age_seconds": None}
    with _LOCK:
        block["registered"] = len(_JOBS)
    try:
        from .models import TecTacEventJob, TecTacEventJobStat

        block["pending"] = TecTacEventJob.objects.filter(status=policy.STATUS_PENDING).count()
        block["running"] = TecTacEventJob.objects.filter(status=policy.STATUS_RUNNING).count()
        block["failed_last_24h"] = TecTacEventJob.objects.filter(status=policy.STATUS_FAILED, finished_at__gte=now - timedelta(hours=24)).count()
        block["dropped_last_24h"] = sum(
            int(stat.dropped_day or 0) for stat in TecTacEventJobStat.objects.filter(dropped_day_started__gte=now - timedelta(hours=24))
        )
        oldest = TecTacEventJob.objects.filter(status=policy.STATUS_PENDING).order_by("created_at").first()
        block["oldest_pending_age_seconds"] = _age_seconds(now, oldest.created_at) if oldest else None
    except Exception as exc:
        logger.exception("The event job health could not be read.")
        block["error"] = f"{type(exc).__name__}"
    return block


LIMITS_TEXT = (
    "Core owns every ceiling: soft time limit 5 to 600 seconds (the hard limit is 15 seconds more), 1 to 10 attempts, back-off 5 to 3600 seconds doubling up to 3600, "
    "expiry 60 to 86400 seconds, backlog 1 to 5000 pending rows per job, payload 2 KiB, key 128 characters; finished rows are kept for the Scheduler's run retention days with a hard cap of 20000 rows.",
    "A handler runs at least once and must be safe to run twice (a redelivery after a worker loss, a retry after a timeout).",
    "The job runs as the module, not as a person: the context has no user fields and a handler cannot call run_tactical_operation, so an event job cannot make a Tactical change (the AD-13 system-action contract is still open).",
    "Only the module that registered holds the publisher handle, and registration is bound to the module's own folder and registry entry. A module that imports another module's private code can still reach that module's handle: signed-module review (rule 3.4) is the defence, as for caller identity.",
    "The payload is data: JSON only, 2 KiB at most, ids and not text bodies or secrets. Core never logs, audits, lists or returns it. Exception text may reach the audit row, cut to one line of 200 characters, so a handler keeps secrets out of exception messages.",
    "Inside an open transaction the publish answers queued before the row is stored (it is stored when the transaction commits), so a duplicate key is then counted in the stats and not reported to the caller.",
)


def event_jobs_contract_metadata() -> dict:
    low = policy.LIMITS
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["register_event_job", "verify_event_job_context"],
        "python": (
            "tec_tac.event_jobs.register_event_job(*, id, module_id, label, handler, soft_time_limit_seconds=None, max_attempts=None, backoff_seconds=None, "
            "max_backoff_seconds=None, expires_seconds=None, max_backlog=None, dedupe_seconds=None, audit_success=False) -> EventJobPublisher; "
            "EventJobPublisher.publish(key, payload=None) -> PublishResult(outcome, reason); EventJobPublisher.status() -> dict; "
            "tec_tac.event_jobs.verify_event_job_context(context, *, expected_module_id, expected_job_id) -> VerifiedEventJob"
        ),
        "outcomes": list(policy.OUTCOMES),
        "limits": {name: {"minimum": a, "default": b, "maximum": c} for name, (a, b, c) in low.items()},
        "payload_max_bytes": policy.PAYLOAD_MAX_BYTES,
        "key": {"pattern": "[A-Za-z0-9._:@/-]", "max_length": policy.KEY_MAX_LENGTH},
        "rate_per_minute_per_process": policy.RATE_PER_MINUTE,
        "http": "GET /api/tfd/scheduler/event-jobs/ (server-maintenance authority; counts only, never a payload or key)",
        "celery_task": TASK_NAME,
        "migration": "0032_event_jobs",
        "handler_context_keys": ["job_id", "module_id", "key", "payload", "attempt", "max_attempts", "final_attempt", "enqueued_at", "run_id"],
        "handler_context_has_user": False,
        "tactical_write_from_handler": False,
        "delivery": "at least once",
        "audit_actions": [ACTION_FAILED, ACTION_SKIPPED, ACTION_EXPIRED, ACTION_DROPPED, ACTION_SUCCEEDED + " (only when audit_success is true)"],
        "limits_text": list(LIMITS_TEXT),
        "requires_framework": ">=1.17.45",
    }


class _EventJobsProvider:
    register_event_job = staticmethod(register_event_job)
    verify_event_job_context = staticmethod(verify_event_job_context)


_PROVIDER = _EventJobsProvider()


def register_core_event_jobs_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Event-started, time-limited system jobs a module publishes from a signal: Core stores, retries, limits and audits them.",
        operations=("register_event_job", "verify_event_job_context"),
        metadata=event_jobs_contract_metadata(),
    )


def _clear_for_tests() -> None:
    with _LOCK:
        _JOBS.clear()
        _HANDLES.clear()
    with _COUNTER_LOCK:
        _COUNTERS.clear()
    _RECENT._seen.clear()
    _RATE._windows.clear()
    _GAUGES.clear()
    _ENABLED.clear()
    _BREAKER.success()
    _LAST_FLUSH[0] = 0.0
