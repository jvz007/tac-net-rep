from __future__ import annotations

import calendar
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import RLock
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import TecTacSchedule, TecTacScheduleRun, TecTacSchedulerConfig, TecTacSchedulerState
from .scheduler_timing import queued_stale_deadline
from .scheduler_targets import SchedulerTargetShapeError, normalize_scheduler_targets


class SchedulerError(RuntimeError):
    pass


class SchedulerPermanentError(SchedulerError):
    """A failure that retries cannot reasonably correct."""


class SchedulerTransientError(SchedulerError):
    """A failure that may recover and may use the configured retry policy."""


class SchedulerNotAllowed(SchedulerError):
    """1.17.16: the user a module started a one-off run for may not run that action or touch those targets."""


logger = logging.getLogger("tec_tac.scheduler")

# 1.17.16: a one-off run is a disabled ONCE module-owned schedule whose owner_key starts with this prefix.
ONE_OFF_PREFIX = "one-off:"


DEFAULT_RETRY_DELAY_SECONDS = 60


def effective_retry_delay_seconds(value) -> int:
    """Return the one scheduler retry-delay fallback used by queue and worker paths."""
    try:
        delay = int(value or 0)
    except (TypeError, ValueError):
        delay = 0
    return delay if delay > 0 else DEFAULT_RETRY_DELAY_SECONDS


@dataclass(frozen=True)
class ScheduledAction:
    id: str
    module_id: str
    label: str
    handler: object
    description: str = ""
    target_types: tuple[str, ...] = ("none",)
    permission: str | None = None
    dangerous: bool = False
    timeout_seconds: int = 3600


_ACTIONS: dict[str, ScheduledAction] = {}
_ACTION_LOCK = RLock()


def register_scheduled_action(*, id: str, module_id: str, label: str, handler, description: str = "", target_types=("none",), permission: str | None = None, dangerous: bool = False, timeout_seconds: int = 3600):
    action_id = str(id or "").strip()
    module = str(module_id or "").strip()
    if not action_id or "." not in action_id:
        raise SchedulerError("Scheduled action id must be a namespaced value such as module.action.")
    if not module:
        raise SchedulerError("Scheduled action module_id is required.")
    if not callable(handler):
        raise SchedulerError("Scheduled action handler must be callable.")
    targets = tuple(str(v).strip() for v in target_types if str(v).strip()) or ("none",)
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise SchedulerError("Scheduled action timeout_seconds must be an integer.") from exc
    if timeout < 60 or timeout > 7 * 24 * 60 * 60:
        raise SchedulerError("Scheduled action timeout_seconds must be between 60 and 604800.")
    action = ScheduledAction(action_id, module, str(label or action_id), handler, str(description or ""), targets, permission, bool(dangerous), timeout)
    with _ACTION_LOCK:
        previous = _ACTIONS.get(action_id)
        if previous and previous != action:
            raise SchedulerError(f"Scheduled action {action_id!r} is already registered.")
        _ACTIONS[action_id] = action
    return action


def get_scheduled_action(action_id: str) -> ScheduledAction:
    try:
        return _ACTIONS[action_id]
    except KeyError as exc:
        raise SchedulerError(f"Scheduled action {action_id!r} is not registered in this runtime.") from exc


def scheduled_actions() -> list[ScheduledAction]:
    with _ACTION_LOCK:
        return sorted(_ACTIONS.values(), key=lambda a: (a.module_id, a.label.lower(), a.id))


def _test_handler(context):
    return {
        "ok": True,
        "message": str(context.get("parameters", {}).get("message") or "Tec-Tac scheduler test event executed."),
        "schedule_id": str(context.get("schedule_id")),
        "run_id": str(context.get("run_id")),
        "executed_at": timezone.now().isoformat(),
    }


register_scheduled_action(
    id="tec-tac.scheduler-test",
    module_id="tec-tac",
    label="Scheduler test event",
    description="Harmless framework action used to validate scheduling, Celery dispatch and execution history.",
    target_types=("none",),
    handler=_test_handler,
)


def _test_failure_handler(context):
    raise SchedulerPermanentError("Intentional scheduler self-test failure.")


def _test_retry_handler(context):
    if int(context.get("attempt") or 1) < 2:
        raise SchedulerTransientError("Intentional first-attempt failure for retry validation.")
    return {
        "ok": True,
        "message": "Scheduler retry self-test recovered on retry.",
        "attempt": int(context.get("attempt") or 1),
        "run_id": str(context.get("run_id")),
    }


register_scheduled_action(
    id="tec-tac.scheduler-test-failure",
    module_id="tec-tac",
    label="Scheduler deliberate failure test",
    description="Framework diagnostic action that always fails permanently.",
    target_types=("none",),
    handler=_test_failure_handler,
)

register_scheduled_action(
    id="tec-tac.scheduler-test-retry",
    module_id="tec-tac",
    label="Scheduler retry test",
    description="Framework diagnostic action that fails once, then succeeds when retry_count is at least 1.",
    target_types=("none",),
    handler=_test_retry_handler,
)


def _zone(value: str) -> ZoneInfo:
    try:
        return ZoneInfo(str(value or "UTC"))
    except ZoneInfoNotFoundError as exc:
        raise SchedulerError(f"Unknown timezone: {value}") from exc


MIN_INTERVAL_SECONDS = 60
MISSED_LATE_TOLERANCE = timedelta(minutes=3)
DEFAULT_RUNNING_STALE_GRACE = timedelta(minutes=5)
MAX_ACTION_TIMEOUT_SECONDS = 604800


def validate_schedule_payload(data: dict, *, partial: bool = False) -> dict:
    if not isinstance(data, dict):
        raise SchedulerError("Schedule payload must be an object.")
    out = dict(data)
    if not partial or "name" in out:
        name = str(out.get("name", "")).strip()
        if not name:
            raise SchedulerError("Schedule name is required.")
        out["name"] = name
    if not partial or "action_id" in out:
        action_id = str(out.get("action_id", "")).strip()
        action = get_scheduled_action(action_id)
        out["action_id"] = action.id
        out["module_id"] = action.module_id
    if "timezone" in out or not partial:
        tz_name = str(out.get("timezone") or "UTC").strip()
        _zone(tz_name)
        out["timezone"] = tz_name
    if "schedule_type" in out or not partial:
        schedule_type = str(out.get("schedule_type") or TecTacSchedule.ScheduleType.ONCE)
        if schedule_type not in TecTacSchedule.ScheduleType.values:
            raise SchedulerError("schedule_type must be once, daily, weekly, monthly, or interval.")
        out["schedule_type"] = schedule_type
    if "target_mode" in out:
        if out["target_mode"] not in TecTacSchedule.TargetMode.values:
            raise SchedulerError("target_mode must be snapshot or dynamic.")
    for key in ("targets", "parameters"):
        if key in out and not isinstance(out[key], dict):
            raise SchedulerError(f"{key} must be an object.")
    if "enabled" in out and not isinstance(out["enabled"], bool):
        raise SchedulerError("enabled must be true or false.")
    if "missed_policy" in out and out["missed_policy"] not in TecTacSchedule.MissedPolicy.values:
        raise SchedulerError("Invalid missed_policy.")
    if "concurrency_policy" in out and out["concurrency_policy"] not in TecTacSchedule.ConcurrencyPolicy.values:
        raise SchedulerError("Invalid concurrency_policy.")
    for key, minimum, maximum in (("missed_grace_minutes", 0, 43200), ("retry_count", 0, 10), ("retry_delay_seconds", 1, 86400)):
        if key in out:
            try:
                value = int(out[key])
            except (TypeError, ValueError) as exc:
                raise SchedulerError(f"{key} must be an integer.") from exc
            if value < minimum or value > maximum:
                raise SchedulerError(f"{key} must be between {minimum} and {maximum}.")
            out[key] = value
    if "interval_seconds" in out and out["interval_seconds"] not in (None, ""):
        value = out["interval_seconds"]
        if isinstance(value, bool):
            raise SchedulerError("interval_seconds must be an integer >= 60.")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise SchedulerError("interval_seconds must be an integer >= 60.") from exc
        if value < MIN_INTERVAL_SECONDS:
            raise SchedulerError(f"interval_seconds must be at least {MIN_INTERVAL_SECONDS}.")
        out["interval_seconds"] = value
    if "weekdays" in out:
        if not isinstance(out["weekdays"], list) or any(not isinstance(v, int) or v < 0 or v > 6 for v in out["weekdays"]):
            raise SchedulerError("weekdays must be an array of integers 0-6.")
        out["weekdays"] = sorted(set(out["weekdays"]))
    if "day_of_month" in out and out["day_of_month"] not in (None, ""):
        try:
            dom = int(out["day_of_month"])
        except (TypeError, ValueError) as exc:
            raise SchedulerError("day_of_month must be an integer 1-31.") from exc
        if dom < 1 or dom > 31:
            raise SchedulerError("day_of_month must be between 1 and 31.")
        out["day_of_month"] = dom
    return out


def _as_utc(value: datetime) -> datetime:
    if timezone.is_naive(value):
        return value.replace(tzinfo=dt_timezone.utc)
    return value.astimezone(dt_timezone.utc)


def _local_occurrence(schedule: TecTacSchedule, day, *, hour: int, minute: int):
    tz = _zone(schedule.timezone)
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz).astimezone(dt_timezone.utc)


def latest_occurrence(schedule: TecTacSchedule, now: datetime) -> datetime | None:
    now = _as_utc(now)
    tz = _zone(schedule.timezone)
    local_now = now.astimezone(tz)
    if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
        return _as_utc(schedule.run_at) if schedule.run_at else None
    if schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL:
        if not schedule.interval_anchor_at or not schedule.interval_seconds:
            return None
        anchor = _as_utc(schedule.interval_anchor_at)
        seconds = int(schedule.interval_seconds)
        if seconds < MIN_INTERVAL_SECONDS or now < anchor:
            return None
        elapsed = (now - anchor).total_seconds()
        steps = int(elapsed // seconds)
        return anchor + timedelta(seconds=steps * seconds)
    if not schedule.run_time:
        return None
    hour, minute = schedule.run_time.hour, schedule.run_time.minute
    if schedule.schedule_type == TecTacSchedule.ScheduleType.DAILY:
        candidate = _local_occurrence(schedule, local_now.date(), hour=hour, minute=minute)
        if candidate > now:
            candidate -= timedelta(days=1)
        return candidate
    if schedule.schedule_type == TecTacSchedule.ScheduleType.WEEKLY:
        weekdays = set(schedule.weekdays or [])
        if not weekdays:
            return None
        for offset in range(0, 8):
            day = local_now.date() - timedelta(days=offset)
            if day.weekday() not in weekdays:
                continue
            candidate = _local_occurrence(schedule, day, hour=hour, minute=minute)
            if candidate <= now:
                return candidate
        return None
    if schedule.schedule_type == TecTacSchedule.ScheduleType.MONTHLY:
        dom = int(schedule.day_of_month or 0)
        if not dom:
            return None
        year, month = local_now.year, local_now.month
        for _ in range(14):
            last = calendar.monthrange(year, month)[1]
            day_num = min(dom, last)
            candidate = _local_occurrence(schedule, datetime(year, month, day_num).date(), hour=hour, minute=minute)
            if candidate <= now:
                return candidate
            month -= 1
            if month == 0:
                month, year = 12, year - 1
    return None


def next_occurrence(schedule: TecTacSchedule, after: datetime | None = None) -> datetime | None:
    now = _as_utc(after or timezone.now())
    tz = _zone(schedule.timezone)
    local_now = now.astimezone(tz)
    if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
        when = _as_utc(schedule.run_at) if schedule.run_at else None
        return when if when and when >= now else None
    if schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL:
        if not schedule.interval_anchor_at or not schedule.interval_seconds:
            return None
        anchor = _as_utc(schedule.interval_anchor_at)
        seconds = int(schedule.interval_seconds)
        if seconds < MIN_INTERVAL_SECONDS:
            return None
        if now <= anchor:
            return anchor
        elapsed = (now - anchor).total_seconds()
        steps = int(elapsed // seconds)
        candidate = anchor + timedelta(seconds=steps * seconds)
        if candidate < now:
            candidate += timedelta(seconds=seconds)
        return candidate
    if not schedule.run_time:
        return None
    hour, minute = schedule.run_time.hour, schedule.run_time.minute
    if schedule.schedule_type == TecTacSchedule.ScheduleType.DAILY:
        for offset in range(0, 2):
            candidate = _local_occurrence(schedule, local_now.date() + timedelta(days=offset), hour=hour, minute=minute)
            if candidate >= now:
                return candidate
    elif schedule.schedule_type == TecTacSchedule.ScheduleType.WEEKLY:
        weekdays = set(schedule.weekdays or [])
        for offset in range(0, 8):
            day = local_now.date() + timedelta(days=offset)
            if day.weekday() in weekdays:
                candidate = _local_occurrence(schedule, day, hour=hour, minute=minute)
                if candidate >= now:
                    return candidate
    elif schedule.schedule_type == TecTacSchedule.ScheduleType.MONTHLY:
        dom = int(schedule.day_of_month or 0)
        if dom:
            year, month = local_now.year, local_now.month
            for _ in range(14):
                last = calendar.monthrange(year, month)[1]
                candidate = _local_occurrence(schedule, datetime(year, month, min(dom, last)).date(), hour=hour, minute=minute)
                if candidate >= now:
                    return candidate
                month += 1
                if month == 13:
                    month, year = 1, year + 1
    return None


def due_key(when: datetime, *, exact: bool = False) -> str:
    value = _as_utc(when)
    if not exact:
        value = value.replace(second=0, microsecond=0)
    return value.isoformat()


def _should_run_occurrence(schedule: TecTacSchedule, occurrence: datetime, now: datetime) -> bool:
    occurrence = _as_utc(occurrence)
    now_utc = _as_utc(now)
    if schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL:
        if occurrence > now_utc:
            return False
        # The scheduler evaluates once per minute. An interval occurrence that
        # happened since the preceding minute tick is current, not missed.
        if (now_utc - occurrence) <= MISSED_LATE_TOLERANCE:
            return True
        if schedule.missed_policy != TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
            return False
        grace = int(schedule.missed_grace_minutes or 0)
        return grace == 0 or (now_utc - occurrence) <= timedelta(minutes=grace)
    occurrence = occurrence.replace(second=0, microsecond=0)
    now_min = now_utc.replace(second=0, microsecond=0)
    if occurrence > now_min:
        return False
    if occurrence == now_min or (now_min - occurrence) <= MISSED_LATE_TOLERANCE:
        return True
    if schedule.missed_policy != TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
        return False
    grace = int(schedule.missed_grace_minutes or 0)
    return grace == 0 or (now_min - occurrence) <= timedelta(minutes=grace)


def _occurrence_predates_schedule_revision(schedule: TecTacSchedule, occurrence: datetime) -> bool:
    """True when an unconsumed occurrence predates the current schedule revision.

    Creating or materially editing a schedule establishes a new baseline; old
    occurrences from before that baseline are not missed executions of the new
    definition.
    """
    if schedule.last_due_key or not getattr(schedule, "updated_at", None):
        return False
    return _as_utc(occurrence) < _as_utc(schedule.updated_at)


def _consume_revision_baseline(schedule: TecTacSchedule, occurrence: datetime, key: str) -> bool:
    """Consume an occurrence that belongs to the schedule's pre-edit baseline."""
    if not _occurrence_predates_schedule_revision(schedule, occurrence):
        return False
    schedule.last_due_key = key
    if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
        schedule.enabled = False
    schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
    return True


def _run_kwargs(schedule: TecTacSchedule, **extra):
    values = {
        "schedule": schedule,
        "schedule_snapshot_id": schedule.id,
        "schedule_name": schedule.name,
        "module_id": schedule.module_id,
        "action_id": schedule.action_id,
        "owner_type": schedule.owner_type,
        "owner_module": schedule.owner_module,
        "owner_key": schedule.owner_key,
        "target_mode_snapshot": schedule.target_mode,
        "parameters_snapshot": schedule.parameters or {},
        "retry_count_snapshot": int(schedule.retry_count or 0),
        "retry_delay_seconds_snapshot": effective_retry_delay_seconds(schedule.retry_delay_seconds),
        "last_queued_at": timezone.now(),
    }
    values.update(extra)
    return values


def recover_stale_runs(now: datetime | None = None) -> dict[str, int]:
    """Fail abandoned queued/running runs so they cannot block a schedule forever."""
    now = _as_utc(now or timezone.now())
    config = TecTacSchedulerConfig.current()
    queued_minutes = max(1, min(int(config.queued_stale_minutes or 10), 1440))
    queued_cutoff = now - timedelta(minutes=queued_minutes)
    recovered_queued = 0
    recovered_running = 0

    with transaction.atomic():
        # Prefilter in SQL before taking row locks. Retry rows may have a later
        # stale deadline, so this is deliberately only a coarse lower bound;
        # queued_stale_deadline() below remains authoritative.
        queued = list(TecTacScheduleRun.objects.select_for_update().filter(
            Q(status=TecTacScheduleRun.Status.QUEUED)
            & (Q(last_queued_at__lt=queued_cutoff) | Q(last_queued_at__isnull=True, created_at__lt=queued_cutoff))
        ))
        for run in queued:
            queued_at = _as_utc(run.last_queued_at or run.created_at)
            # A retrying Celery task is intentionally invisible until its countdown
            # expires. Do not classify that expected wait as stale. Initial queueing
            # has attempt=0 and therefore keeps the normal dispatch stale window.
            stale_after = queued_stale_deadline(
                queued_at=queued_at,
                queued_stale_minutes=queued_minutes,
                attempt=int(run.attempt or 0),
                retry_delay_seconds=effective_retry_delay_seconds(run.retry_delay_seconds_snapshot),
            )
            if now <= stale_after:
                continue
            run.status = TecTacScheduleRun.Status.FAILED
            run.error_type = "Stale"
            run.error = (
                f"Stale queued run exceeded {queued_minutes} minute dispatch window"
                + (f" after {effective_retry_delay_seconds(run.retry_delay_seconds_snapshot)} second retry countdown." if int(run.attempt or 0) > 0 else ".")
            )
            run.finished_at = now
            run.save(update_fields=["status", "error_type", "error", "finished_at"])
            recovered_queued += 1

    # Running timeout is action-specific. Unknown actions use the conservative
    # one-hour default plus a small recovery grace period.
    candidates = list(TecTacScheduleRun.objects.filter(
        status=TecTacScheduleRun.Status.RUNNING,
        started_at__isnull=False,
    ).only("id", "action_id", "started_at"))
    for candidate in candidates:
        action = _ACTIONS.get(candidate.action_id)
        timeout_seconds = int(action.timeout_seconds if action else 3600)
        if now - _as_utc(candidate.started_at) <= timedelta(seconds=timeout_seconds) + DEFAULT_RUNNING_STALE_GRACE:
            continue
        with transaction.atomic():
            run = TecTacScheduleRun.objects.select_for_update().get(pk=candidate.pk)
            if run.status != TecTacScheduleRun.Status.RUNNING:
                continue
            task_id = str(run.celery_task_id or "").strip()
            if task_id:
                try:
                    from tacticalrmm.celery import app as celery_app
                    celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
                except Exception:
                    # Do not release the Scheduler concurrency lock if Core cannot
                    # request termination of the still-running worker task. A later
                    # recovery tick will retry revocation instead of allowing SKIP
                    # schedules to overlap the abandoned execution.
                    continue
            run.status = TecTacScheduleRun.Status.FAILED
            run.error_type = "Stale"
            run.error = f"Stale running run exceeded action timeout of {timeout_seconds} seconds."
            run.finished_at = now
            run.save(update_fields=["status", "error_type", "error", "finished_at"])
            recovered_running += 1
    return {"queued": recovered_queued, "running": recovered_running}


def cleanup_run_history(now: datetime | None = None) -> int:
    now = _as_utc(now or timezone.now())
    config = TecTacSchedulerConfig.current()
    days = max(1, min(int(config.run_retention_days or 90), 3650))
    cutoff = now - timedelta(days=days)
    qs = TecTacScheduleRun.objects.filter(
        created_at__lt=cutoff,
        status__in=[
            TecTacScheduleRun.Status.SUCCEEDED, TecTacScheduleRun.Status.FAILED, TecTacScheduleRun.Status.SKIPPED,
        ],
    )
    deleted, _ = qs.delete()
    return int(deleted)


def cleanup_once_schedules(now: datetime | None = None) -> int:
    now = _as_utc(now or timezone.now())
    config = TecTacSchedulerConfig.current()
    retention = max(1, min(int(config.once_retention_hours or 48), 720))
    cutoff = now - timedelta(hours=retention)
    cleaned = 0
    qs = TecTacSchedule.objects.filter(schedule_type=TecTacSchedule.ScheduleType.ONCE, enabled=False)
    for schedule in qs:
        if schedule.runs.filter(status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]).exists():
            continue
        latest = schedule.runs.order_by("-finished_at", "-created_at").first()
        terminal_at = (latest.finished_at if latest and latest.finished_at else None) or schedule.last_run_at or schedule.run_at or schedule.updated_at
        if terminal_at and _as_utc(terminal_at) <= cutoff:
            schedule.delete()
            cleaned += 1
    return cleaned


def scheduler_health(now: datetime | None = None) -> dict:
    now = _as_utc(now or timezone.now())
    state = TecTacSchedulerState.current()
    last_tick = _as_utc(state.last_tick_completed_at) if state.last_tick_completed_at else None
    tick_age = int((now - last_tick).total_seconds()) if last_tick else None
    tick_health = "healthy" if tick_age is not None and tick_age <= 180 and not state.last_tick_error else ("degraded" if last_tick else "unknown")
    recent_cutoff = now - timedelta(hours=24)
    runs = TecTacScheduleRun.objects.filter(created_at__gte=recent_cutoff)
    authorization_revoked = runs.filter(error_type="AuthorizationRevoked")
    authorization_revoked_health = _authorization_revoked_health(authorization_revoked)
    return {
        "tick_health": tick_health,
        "last_tick_at": state.last_tick_at.isoformat() if state.last_tick_at else None,
        "last_tick_completed_at": state.last_tick_completed_at.isoformat() if state.last_tick_completed_at else None,
        "tick_age_seconds": tick_age,
        "last_tick_error": state.last_tick_error,
        "last_checked": state.last_checked,
        "last_queued": state.last_queued,
        "last_skipped": state.last_skipped,
        "last_cleaned": state.last_cleaned,
        "last_dispatch_at": state.last_dispatch_at.isoformat() if state.last_dispatch_at else None,
        "last_dispatch_error": state.last_dispatch_error,
        "enabled_schedules": TecTacSchedule.objects.filter(enabled=True).count(),
        "queued_runs": TecTacScheduleRun.objects.filter(status=TecTacScheduleRun.Status.QUEUED).count(),
        "running_runs": TecTacScheduleRun.objects.filter(status=TecTacScheduleRun.Status.RUNNING).count(),
        "failed_last_24h": runs.filter(status=TecTacScheduleRun.Status.FAILED).count(),
        **authorization_revoked_health,
    }


def _authorization_revoked_health(authorization_revoked) -> dict:
    """Return Scheduler health fields for runtime authorization revocations."""
    latest = authorization_revoked.order_by("-created_at").first()
    return {
        "authorization_revoked_last_24h": authorization_revoked.count(),
        "last_authorization_revoked": ({
            "schedule_id": (
                str(latest.schedule_snapshot_id or latest.schedule_id)
                if (latest.schedule_snapshot_id or latest.schedule_id)
                else None
            ),
            "schedule_name": str(
                latest.schedule_name
                or (getattr(latest.schedule, "name", "") if latest.schedule else "")
                or "Deleted schedule"
            ),
            "created_at": latest.created_at.isoformat(),
            "error": latest.error,
        } if latest else None),
    }


def _queue_run(run: TecTacScheduleRun):
    from .tasks import execute_schedule_run
    state = TecTacSchedulerState.current()
    try:
        action = _ACTIONS.get(run.action_id)
        timeout_seconds = int(action.timeout_seconds if action else 3600)
        hard_time_limit = min(MAX_ACTION_TIMEOUT_SECONDS, timeout_seconds) + int(DEFAULT_RUNNING_STALE_GRACE.total_seconds())
        async_result = execute_schedule_run.apply_async(args=[str(run.id)], time_limit=hard_time_limit)
        run.celery_task_id = str(async_result.id or "")
        run.save(update_fields=["celery_task_id"])
        state.last_dispatch_at = timezone.now()
        state.last_dispatch_error = ""
        state.save(update_fields=["last_dispatch_at", "last_dispatch_error"])
        return run
    except Exception as exc:
        run.status = TecTacScheduleRun.Status.FAILED
        run.error_type = "DispatchError"
        run.error = f"{exc.__class__.__name__}: {exc}"
        run.finished_at = timezone.now()
        run.save(update_fields=["status", "error_type", "error", "finished_at"])
        state.last_dispatch_at = timezone.now()
        state.last_dispatch_error = run.error
        state.save(update_fields=["last_dispatch_at", "last_dispatch_error"])
        raise


def is_one_off_key(owner_key) -> bool:
    return isinstance(owner_key, str) and owner_key.startswith(ONE_OFF_PREFIX)


def is_one_off_schedule(schedule) -> bool:
    return schedule is not None and schedule.owner_type == TecTacSchedule.OwnerType.MODULE and is_one_off_key(schedule.owner_key)


def _runtime_authorization_error(schedule: TecTacSchedule) -> str | None:
    """Re-check the saved actor, action permission and Tactical target scope.

    Save-time authorization is not durable authority. User-owned schedules run
    only while the original actor remains active and still has permission for
    both the registered action and the saved client/site/endpoint scope.
    Since 1.17.16 a module-owned one-off schedule (owner_key ``one-off:<id>``, AD-13 condition 2) is held to the same
    check against ``created_by``, the user the module started it for.
    """
    one_off = is_one_off_schedule(schedule)
    if schedule.owner_type != TecTacSchedule.OwnerType.USER and not one_off:
        return None
    actor = schedule.created_by
    if actor is None or not bool(getattr(actor, "is_active", False)) or (one_off and bool(getattr(actor, "is_installer_user", False))):
        return "Schedule owner is missing or inactive."
    try:
        action = get_scheduled_action(schedule.action_id)
        # Runtime import avoids a scheduler <-> scheduler_views import cycle.
        from .scheduler_views import _can_use_action, _can_access_target_scope
        if not _can_use_action(actor, action):
            return "Schedule owner no longer has permission to run this action."
        if not _can_access_target_scope(actor, schedule.targets or {}):
            return "Schedule targets are no longer within the owner's Tactical scope."
    except Exception:
        return "Schedule authorization could not be verified at run time."
    return None


def _canonicalize_persisted_endpoint_identity(targets):
    """Canonicalize legacy endpoint PK aliases before a handler can see them."""
    from . import resources_adapter
    from .scheduler_targets import SchedulerTargetShapeError

    canonical = dict(targets or {})
    target_type = str(canonical.get("type") or "none").strip().lower()
    try:
        if target_type in {"endpoint", "endpoints", "agent", "agents"}:
            values = list(canonical.get("ids") or [])
            resolved = resources_adapter.canonical_agent_target_ids(identifiers=values)
            if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
                raise SchedulerTargetShapeError("One or more persisted scheduler endpoints no longer resolve to a Tactical agent.")
            canonical["ids"] = resolved
        elif target_type == "dynamic":
            scope = dict(canonical.get("scope") or {})
            if str(scope.get("type") or "").strip().lower() in {"endpoint", "agent"}:
                values = list(scope.get("ids") or [])
                resolved = resources_adapter.canonical_agent_target_ids(identifiers=values)
                if len(resolved) != len(dict.fromkeys(str(v).strip() for v in values)):
                    raise SchedulerTargetShapeError("One or more persisted scheduler endpoints no longer resolve to a Tactical agent.")
                scope["type"] = "endpoint"
                scope["ids"] = resolved
                canonical["scope"] = scope
    except resources_adapter.TacticalResourceAdapterError as exc:
        raise SchedulerTargetShapeError(str(exc)) from exc
    return canonical


def dispatch_due_schedules(now: datetime | None = None) -> dict:
    now = _as_utc(now or timezone.now())
    state = TecTacSchedulerState.current()
    state.last_tick_at = now
    state.last_tick_error = ""
    state.save(update_fields=["last_tick_at", "last_tick_error"])
    queued, skipped, dispatch_failed = [], [], []
    stale = recover_stale_runs(now)
    schedule_ids = list(TecTacSchedule.objects.filter(enabled=True).values_list("id", flat=True))
    try:
        for schedule_id in schedule_ids:
            try:
                with transaction.atomic():
                    try:
                        schedule = TecTacSchedule.objects.select_for_update().get(pk=schedule_id)
                    except TecTacSchedule.DoesNotExist:
                        continue
                    if not schedule.enabled:
                        continue
                    try:
                        canonical_targets = normalize_scheduler_targets(schedule.targets or {})
                        canonical_targets = _canonicalize_persisted_endpoint_identity(canonical_targets)
                    except SchedulerTargetShapeError as exc:
                        schedule.enabled = False
                        schedule.target_state = "invalid"
                        schedule.target_state_detail = str(exc)[:500]
                        schedule.save(update_fields=["enabled", "target_state", "target_state_detail", "updated_at"])
                        run = TecTacScheduleRun.objects.create(**_run_kwargs(
                            schedule, status=TecTacScheduleRun.Status.SKIPPED, scheduled_for=now,
                            targets_snapshot=schedule.targets or {}, error=str(exc),
                            error_type="InvalidTargetShape", finished_at=now,
                        ))
                        skipped.append(str(run.id))
                        continue
                    if canonical_targets != (schedule.targets or {}):
                        schedule.targets = canonical_targets
                        schedule.target_state = "valid"
                        schedule.target_state_detail = ""
                        schedule.save(update_fields=["targets", "target_state", "target_state_detail", "updated_at"])
                    authorization_error = _runtime_authorization_error(schedule)
                    if authorization_error:
                        occurrence = latest_occurrence(schedule, now)
                        if occurrence:
                            key = due_key(occurrence, exact=(schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL))
                            if schedule.last_due_key != key and not _consume_revision_baseline(schedule, occurrence, key):
                                run = TecTacScheduleRun.objects.create(**_run_kwargs(
                                    schedule, status=TecTacScheduleRun.Status.SKIPPED, scheduled_for=occurrence,
                                    targets_snapshot=schedule.targets or {}, error=authorization_error,
                                    error_type="AuthorizationRevoked", finished_at=now,
                                ))
                                schedule.last_due_key = key
                                schedule.save(update_fields=["last_due_key", "updated_at"])
                                skipped.append(str(run.id))
                        continue
                    occurrence = latest_occurrence(schedule, now)
                    if not occurrence:
                        continue
                    key = due_key(occurrence, exact=(schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL))
                    if schedule.last_due_key == key:
                        continue
                    # A create/edit is a new scheduling baseline. Consume any
                    # occurrence from before that revision before lateness/grace
                    # evaluation so it can neither run nor become a missed row.
                    if _consume_revision_baseline(schedule, occurrence, key):
                        continue
                    if not _should_run_occurrence(schedule, occurrence, now):
                        if schedule.missed_policy == TecTacSchedule.MissedPolicy.EXPIRE:
                            error_type = "MissedExpired"
                            message = "Occurrence expired after the scheduler lateness window."
                        elif schedule.missed_policy == TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
                            error_type = "MissedRecoveryWindowExpired"
                            message = "Occurrence was outside the configured recovery grace window."
                        else:
                            error_type = "MissedSkip"
                            message = "Occurrence was missed and the schedule policy is skip."
                        run = TecTacScheduleRun.objects.create(**_run_kwargs(
                            schedule, status=TecTacScheduleRun.Status.SKIPPED, scheduled_for=occurrence,
                            targets_snapshot=schedule.targets or {}, error=message, error_type=error_type, finished_at=now,
                        ))
                        schedule.last_due_key = key
                        if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
                            schedule.enabled = False
                        schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
                        skipped.append(str(run.id))
                        continue
                    try:
                        get_scheduled_action(schedule.action_id)
                    except SchedulerError as exc:
                        run = TecTacScheduleRun.objects.create(**_run_kwargs(
                            schedule,
                            status=TecTacScheduleRun.Status.SKIPPED, scheduled_for=occurrence,
                            targets_snapshot=schedule.targets or {}, error=str(exc),
                            error_type="ActionUnavailable", finished_at=now,
                        ))
                        schedule.last_due_key = key
                        if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
                            schedule.enabled = False
                        schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
                        skipped.append(str(run.id))
                        continue
                    active = schedule.runs.filter(status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]).exists()
                    if active and schedule.concurrency_policy == TecTacSchedule.ConcurrencyPolicy.SKIP:
                        run = TecTacScheduleRun.objects.create(**_run_kwargs(
                            schedule, status=TecTacScheduleRun.Status.SKIPPED, scheduled_for=occurrence,
                            targets_snapshot=schedule.targets or {},
                            error="Skipped because a previous run is still active.",
                            error_type="ConcurrencySkip", finished_at=now,
                        ))
                        schedule.last_due_key = key
                        schedule.save(update_fields=["last_due_key", "updated_at"])
                        skipped.append(str(run.id))
                        continue
                    run = TecTacScheduleRun.objects.create(**_run_kwargs(
                        schedule, scheduled_for=occurrence, targets_snapshot=schedule.targets or {},
                    ))
                    schedule.last_due_key = key
                    if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
                        schedule.enabled = False
                    schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
                try:
                    _queue_run(run)
                    queued.append(str(run.id))
                except Exception:
                    # _queue_run records the failed dispatch on the run and scheduler
                    # state. A broker outage for one schedule must not abort the tick.
                    dispatch_failed.append(str(run.id))
                    continue
            except Exception as exc:
                # A malformed/deleted schedule or one broken module action must
                # never prevent unrelated schedules from being processed.
                state.last_dispatch_at = timezone.now()
                state.last_dispatch_error = f"schedule {schedule_id}: {exc.__class__.__name__}: {exc}"[:1000]
                state.save(update_fields=["last_dispatch_at", "last_dispatch_error"])
                dispatch_failed.append(f"schedule:{schedule_id}")
                continue
        cleaned_once = cleanup_once_schedules(now)
        cleaned_runs = cleanup_run_history(now)
        cleaned = cleaned_once + cleaned_runs
        state.last_tick_completed_at = timezone.now()
        state.last_checked = len(schedule_ids)
        state.last_queued = len(queued)
        state.last_skipped = len(skipped)
        state.last_cleaned = cleaned
        state.last_tick_error = ""
        state.save(update_fields=["last_tick_completed_at", "last_checked", "last_queued", "last_skipped", "last_cleaned", "last_tick_error"])
        return {
            "queued": queued, "skipped": skipped, "dispatch_failed": dispatch_failed,
            "stale_recovered": stale, "cleaned": cleaned, "cleaned_once": cleaned_once,
            "cleaned_runs": cleaned_runs, "checked": len(schedule_ids), "now": now.isoformat(),
        }
    except Exception as exc:
        state.last_tick_completed_at = timezone.now()
        state.last_tick_error = f"{exc.__class__.__name__}: {exc}"
        state.save(update_fields=["last_tick_completed_at", "last_tick_error"])
        raise


def queue_manual_run(schedule: TecTacSchedule):
    run = TecTacScheduleRun.objects.create(**_run_kwargs(
        schedule, scheduled_for=timezone.now(), manual=True, targets_snapshot=schedule.targets or {},
    ))
    return _queue_run(run)


def _validate_owner(owner_module: str, owner_key: str) -> tuple[str, str]:
    module = str(owner_module or "").strip()
    key = str(owner_key or "").strip()
    if not module:
        raise SchedulerError("owner_module is required.")
    if not key:
        raise SchedulerError("owner_key is required.")
    if len(module) > 100:
        raise SchedulerError("owner_module exceeds 100 characters.")
    if len(key) > 255:
        raise SchedulerError("owner_key exceeds 255 characters.")
    return module, key


def reconcile_schedule(*, owner_module: str, owner_key: str, action_id: str, schedule_type: str,
                       targets: dict | None = None, parameters: dict | None = None, enabled: bool = True,
                       name: str | None = None, timezone_name: str = "UTC", run_at: datetime | None = None,
                       run_time=None, weekdays: list[int] | None = None, day_of_month: int | None = None,
                       interval_seconds: int | None = None, interval_anchor_at: datetime | None = None,
                       target_mode: str = TecTacSchedule.TargetMode.SNAPSHOT,
                       missed_policy: str = TecTacSchedule.MissedPolicy.SKIP, missed_grace_minutes: int = 60,
                       concurrency_policy: str = TecTacSchedule.ConcurrencyPolicy.SKIP, retry_count: int = 0,
                       retry_delay_seconds: int = 60) -> TecTacSchedule | None:
    """Idempotently create/update a backend-module-owned scheduler definition.

    The ownership tuple is the stable identity. ``enabled=False`` disables an
    existing definition and is a no-op when one does not yet exist. Browser
    authentication is intentionally not part of this server-side contract.
    """
    module, key = _validate_owner(owner_module, owner_key)
    action = get_scheduled_action(str(action_id or "").strip())
    if action.module_id != module:
        raise SchedulerError(
            f"Scheduled action {action.id!r} belongs to module {action.module_id!r}, not {module!r}."
        )
    if not isinstance(enabled, bool):
        raise SchedulerError("enabled must be true or false.")

    with transaction.atomic():
        existing = TecTacSchedule.objects.select_for_update().filter(owner_module=module, owner_key=key).first()
        if not enabled and existing is None:
            return None

        anchor = interval_anchor_at
        if schedule_type == TecTacSchedule.ScheduleType.INTERVAL and anchor is None:
            anchor = existing.interval_anchor_at if existing and existing.interval_anchor_at else timezone.now().replace(second=0, microsecond=0)

        data = validate_schedule_payload({
            "name": str(name or (existing.name if existing else f"{action.label} · {key}")),
            "action_id": action.id,
            "schedule_type": schedule_type,
            "timezone": timezone_name,
            "run_at": run_at,
            "run_time": run_time,
            "weekdays": weekdays or [],
            "day_of_month": day_of_month,
            "interval_seconds": interval_seconds,
            "target_mode": target_mode,
            "targets": targets or {"type": action.target_types[0]},
            "parameters": parameters or {},
            "enabled": enabled,
            "missed_policy": missed_policy,
            "missed_grace_minutes": missed_grace_minutes,
            "concurrency_policy": concurrency_policy,
            "retry_count": retry_count,
            "retry_delay_seconds": retry_delay_seconds,
        })
        try:
            data["targets"] = normalize_scheduler_targets(data.get("targets"))
        except SchedulerTargetShapeError as exc:
            raise SchedulerError(str(exc)) from exc

        if data["schedule_type"] == TecTacSchedule.ScheduleType.ONCE and not data.get("run_at"):
            raise SchedulerError("A one-time schedule requires run_at.")
        if data["schedule_type"] in {TecTacSchedule.ScheduleType.DAILY, TecTacSchedule.ScheduleType.WEEKLY, TecTacSchedule.ScheduleType.MONTHLY} and not data.get("run_time"):
            raise SchedulerError("Recurring calendar schedules require run_time.")
        if data["schedule_type"] == TecTacSchedule.ScheduleType.WEEKLY and not data.get("weekdays"):
            raise SchedulerError("Weekly schedules require at least one weekday.")
        if data["schedule_type"] == TecTacSchedule.ScheduleType.MONTHLY and not data.get("day_of_month"):
            raise SchedulerError("Monthly schedules require day_of_month.")
        if data["schedule_type"] == TecTacSchedule.ScheduleType.INTERVAL and not data.get("interval_seconds"):
            raise SchedulerError("Interval schedules require interval_seconds.")
        target_type = str((data.get("targets") or {}).get("type") or "none")
        if target_type not in action.target_types:
            raise SchedulerError(f"Action {action.id} does not support target type {target_type!r}.")

        schedule = existing or TecTacSchedule(owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module, owner_key=key)
        previous_signature = None
        if existing:
            previous_signature = (
                existing.schedule_type, existing.interval_seconds, existing.interval_anchor_at, existing.run_at,
                existing.run_time, tuple(existing.weekdays or []), existing.day_of_month, existing.enabled,
            )
        for field in (
            "name", "module_id", "action_id", "target_mode", "targets", "parameters", "schedule_type",
            "timezone", "run_at", "run_time", "weekdays", "day_of_month", "interval_seconds", "enabled",
            "missed_policy", "missed_grace_minutes", "concurrency_policy", "retry_count", "retry_delay_seconds",
        ):
            if field in data:
                setattr(schedule, field, data[field])
        schedule.owner_type = TecTacSchedule.OwnerType.MODULE
        schedule.owner_module = module
        schedule.owner_key = key
        schedule.interval_anchor_at = _as_utc(anchor) if anchor else None
        if schedule.schedule_type != TecTacSchedule.ScheduleType.INTERVAL:
            schedule.interval_seconds = None
            schedule.interval_anchor_at = None
        schedule.module_id = action.module_id
        schedule.target_state = "valid"
        schedule.target_state_detail = ""
        new_signature = (
            schedule.schedule_type, schedule.interval_seconds, schedule.interval_anchor_at, schedule.run_at,
            schedule.run_time, tuple(schedule.weekdays or []), schedule.day_of_month, schedule.enabled,
        )
        if previous_signature is not None and previous_signature != new_signature:
            schedule.last_due_key = ""
        schedule.save()
        return schedule


def disable_owned_schedule(*, owner_module: str, owner_key: str) -> TecTacSchedule | None:
    module, key = _validate_owner(owner_module, owner_key)
    with transaction.atomic():
        schedule = TecTacSchedule.objects.select_for_update().filter(owner_module=module, owner_key=key).first()
        if schedule is None:
            return None
        if schedule.enabled:
            schedule.enabled = False
            schedule.save(update_fields=["enabled", "updated_at"])
        return schedule


def remove_owned_schedule(*, owner_module: str, owner_key: str) -> bool:
    module, key = _validate_owner(owner_module, owner_key)
    with transaction.atomic():
        schedule = TecTacSchedule.objects.select_for_update().filter(owner_module=module, owner_key=key).first()
        if schedule is None:
            return False
        if schedule.runs.filter(status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]).exists():
            raise SchedulerError("Owned schedule cannot be removed while a run is queued or running.")
        schedule.delete()
        return True


def _one_off_user_refusal(user) -> str | None:
    if user is None or not bool(getattr(user, "is_active", False)) or bool(getattr(user, "is_installer_user", False)):
        return "A one-off run needs an active, interactive user."
    return None


def start_one_off_run(*, user, owner_module: str, action_id: str, targets: dict | None = None,
                      parameters: dict | None = None, name: str | None = None) -> TecTacScheduleRun:
    """Start one run of a registered Scheduler action on behalf of ``user`` and return the queued run (1.17.16).

    A module starts only its own actions (``action.module_id == owner_module``, as ``reconcile_schedule`` requires). The user
    must hold the action now (``scheduler_views._can_use_action``: an action with no permission is startable only by native
    scheduler managers, as in the browser) and the targets' Tactical scope. Core then creates a disabled ONCE module-owned
    schedule with ``owner_key`` ``one-off:<uuid>`` and ``created_by`` the user, so the ticker never dispatches it, the browser
    shows it as managed by the module, and ``cleanup_once_schedules`` removes it after the retention. The run is queued like a
    manual run. Before the handler runs Core re-checks that the user is still active and still holds the action and scope
    (AD-13 condition 2); if not, the run ends ``skipped``. This is the start-and-track call only, not the system-action
    contract. Raises ``SchedulerError`` (``SchedulerNotAllowed`` for a user who may not), ``SchedulerTransientError`` when the
    run could not be queued. Call it outside a database transaction that has not committed: the worker reads the run at once."""
    refusal = _one_off_user_refusal(user)
    if refusal:
        raise SchedulerNotAllowed(refusal)
    module, _ = _validate_owner(owner_module, ONE_OFF_PREFIX)
    action = get_scheduled_action(str(action_id or "").strip())
    if action.module_id != module:
        raise SchedulerError(f"Scheduled action {action.id!r} belongs to module {action.module_id!r}, not {module!r}.")
    if targets is not None and not isinstance(targets, dict):
        raise SchedulerError("targets must be an object.")
    data = validate_schedule_payload({
        "name": str(name or f"{action.label} · one-off").strip()[:255],
        "action_id": action.id,
        "schedule_type": TecTacSchedule.ScheduleType.ONCE,
        "targets": targets or {"type": action.target_types[0]},
        "parameters": parameters if parameters is not None else {},
        "enabled": False,
    })
    try:
        json.dumps(data["parameters"])
    except (TypeError, ValueError) as exc:
        raise SchedulerError("parameters must be JSON data.") from exc
    try:
        canonical = normalize_scheduler_targets(data["targets"])
    except SchedulerTargetShapeError as exc:
        raise SchedulerError(str(exc)) from exc
    target_type = str(canonical.get("type") or "none")
    if target_type not in action.target_types:
        raise SchedulerError(f"Action {action.id} does not support target type {target_type!r}.")
    # Runtime import avoids a scheduler <-> scheduler_views import cycle.
    from .scheduler_views import _can_use_action, _can_access_target_scope, _canonicalize_endpoint_targets_for_user
    try:
        may_run = _can_use_action(user, action)
    except Exception as exc:  # fail closed when the permission lookup itself fails
        raise SchedulerNotAllowed("The user's permission to run this action could not be verified.") from exc
    if not may_run:
        raise SchedulerNotAllowed("The user does not have permission to run this action.")
    try:
        canonical = _canonicalize_endpoint_targets_for_user(user, canonical)
        in_scope = _can_access_target_scope(user, canonical)
    except SchedulerError:
        raise
    except Exception as exc:
        raise SchedulerNotAllowed("The targets are outside the user's Tactical scope.") from exc
    if not in_scope:
        raise SchedulerNotAllowed("The targets are outside the user's Tactical scope.")

    now = timezone.now()
    with transaction.atomic():
        schedule = TecTacSchedule.objects.create(
            name=data["name"], module_id=action.module_id, action_id=action.id,
            target_mode=TecTacSchedule.TargetMode.SNAPSHOT, targets=canonical, target_state="valid", target_state_detail="",
            parameters=data["parameters"], schedule_type=TecTacSchedule.ScheduleType.ONCE, timezone="UTC", run_at=now,
            owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module, owner_key=f"{ONE_OFF_PREFIX}{uuid.uuid4()}",
            enabled=False, created_by=user, updated_by=user,
        )
    try:
        run = queue_manual_run(schedule)
    except Exception as exc:
        # _queue_run left the failed run as history. The schedule has no use without a run, so remove it.
        schedule.delete()
        raise SchedulerTransientError("The run could not be queued. Try again.") from exc
    try:
        from .audit import record as audit_record
        audit_record(
            actor=user, module_id="core", action="add", object_type="scheduler_run", object_id=str(run.id),
            message=f"Module {module} started a one-off run of {action.id}.",
            metadata={"owner_module": module, "action_id": action.id, "requested_by": "scheduler"},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a one-off scheduler run could not be written")
    return run


def get_one_off_run(run_id, *, owner_module: str) -> dict:
    """The state of a run that ``start_one_off_run`` started, as ``serialize_run`` shows it (1.17.16). A module reads only its own.
    Raises ``SchedulerError`` when there is no such one-off run for ``owner_module``."""
    module, _ = _validate_owner(owner_module, ONE_OFF_PREFIX)
    try:
        run = TecTacScheduleRun.objects.filter(pk=run_id, owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module).first()
    except (TypeError, ValueError, ValidationError):  # a malformed id is "not found", never a crash
        run = None
    if run is None or not is_one_off_key(run.owner_key):
        raise SchedulerError("No one-off run with that id was found for this module.")
    return serialize_run(run)


def get_owned_schedule(owner_module: str, owner_key: str) -> dict | None:
    """Read one module-owned schedule without exposing the model (1.17.16): ``{enabled, schedule_type, next_run_at,
    last_run_at, last_run_status, last_run_finished_at}``, or None when no schedule has that ownership tuple. A module reads
    only its own tuple (the same trust as ``reconcile_schedule``)."""
    module, key = _validate_owner(owner_module, owner_key)
    schedule = TecTacSchedule.objects.filter(owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module, owner_key=key).first()
    if schedule is None:
        return None
    latest = schedule.runs.order_by("-created_at").first()
    upcoming = next_occurrence(schedule) if schedule.enabled else None
    return {
        "enabled": bool(schedule.enabled),
        "schedule_type": schedule.schedule_type,
        "next_run_at": upcoming.isoformat() if upcoming else None,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "last_run_status": latest.status if latest else None,
        "last_run_finished_at": latest.finished_at.isoformat() if latest and latest.finished_at else None,
    }


def serialize_action(action: ScheduledAction) -> dict:
    return {
        "id": action.id,
        "module_id": action.module_id,
        "label": action.label,
        "description": action.description,
        "target_types": list(action.target_types),
        "permission": action.permission,
        "dangerous": action.dangerous,
        "timeout_seconds": action.timeout_seconds,
    }


def serialize_run(run: TecTacScheduleRun) -> dict:
    return {
        "id": str(run.id),
        "schedule_id": str(run.schedule_snapshot_id or run.schedule_id) if (run.schedule_snapshot_id or run.schedule_id) else None,
        "schedule_name": run.schedule_name or (run.schedule.name if run.schedule else "Deleted schedule"),
        "module_id": run.module_id or (run.schedule.module_id if run.schedule else ""),
        "action_id": run.action_id or (run.schedule.action_id if run.schedule else ""),
        "owner_type": run.owner_type,
        "owner_module": run.owner_module or None,
        "owner_key": run.owner_key or None,
        "status": run.status,
        "scheduled_for": run.scheduled_for.isoformat(),
        "manual": run.manual,
        "targets_snapshot": run.targets_snapshot,
        "target_mode_snapshot": run.target_mode_snapshot,
        "parameters_snapshot": run.parameters_snapshot,
        "result": run.result,
        "error": run.error,
        "error_type": run.error_type,
        "attempt": run.attempt,
        "celery_task_id": run.celery_task_id,
        "created_at": run.created_at.isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


def serialize_schedule(schedule: TecTacSchedule, *, include_runs: bool = False) -> dict:
    action = _ACTIONS.get(schedule.action_id)
    latest = None if hasattr(schedule, "latest_status") else schedule.runs.first()
    payload = {
        "id": str(schedule.id),
        "name": schedule.name,
        "module_id": schedule.module_id,
        "action_id": schedule.action_id,
        "action_label": action.label if action else schedule.action_id,
        "action_available": bool(action),
        "target_mode": schedule.target_mode,
        "targets": schedule.targets,
        "target_state": getattr(schedule, "target_state", "valid"),
        "target_state_detail": getattr(schedule, "target_state_detail", ""),
        "parameters": schedule.parameters,
        "schedule_type": schedule.schedule_type,
        "timezone": schedule.timezone,
        "run_at": schedule.run_at.isoformat() if schedule.run_at else None,
        "run_time": schedule.run_time.isoformat() if schedule.run_time else None,
        "weekdays": schedule.weekdays,
        "day_of_month": schedule.day_of_month,
        "interval_seconds": schedule.interval_seconds,
        "interval_anchor_at": schedule.interval_anchor_at.isoformat() if schedule.interval_anchor_at else None,
        "owner_type": schedule.owner_type,
        "owner_module": schedule.owner_module or None,
        "owner_key": schedule.owner_key or None,
        "owner_label": (schedule.owner_module if schedule.owner_type == TecTacSchedule.OwnerType.MODULE else (schedule.created_by.username if schedule.created_by else "User")),
        "managed_by_module": schedule.owner_type == TecTacSchedule.OwnerType.MODULE,
        "enabled": schedule.enabled,
        "missed_policy": schedule.missed_policy,
        "missed_grace_minutes": schedule.missed_grace_minutes,
        "concurrency_policy": schedule.concurrency_policy,
        "retry_count": schedule.retry_count,
        "retry_delay_seconds": schedule.retry_delay_seconds,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "next_run_at": (next_occurrence(schedule).isoformat() if schedule.enabled and next_occurrence(schedule) else None),
        "last_status": getattr(schedule, "latest_status", None) if hasattr(schedule, "latest_status") else (latest.status if latest else None),
        "created_by": schedule.created_by.username if schedule.created_by else None,
        "updated_by": schedule.updated_by.username if schedule.updated_by else None,
        "created_at": schedule.created_at.isoformat(),
        "updated_at": schedule.updated_at.isoformat(),
    }
    if include_runs:
        payload["runs"] = [serialize_run(run) for run in schedule.runs.all()[:50]]
    return payload
