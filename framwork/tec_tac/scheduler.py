from __future__ import annotations

import calendar
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import RLock
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.db import transaction
from django.utils import timezone

from .models import TecTacSchedule, TecTacScheduleRun, TecTacSchedulerConfig, TecTacSchedulerState


class SchedulerError(RuntimeError):
    pass


class SchedulerPermanentError(SchedulerError):
    """A failure that retries cannot reasonably correct."""


class SchedulerTransientError(SchedulerError):
    """A failure that may recover and may use the configured retry policy."""


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


_ACTIONS: dict[str, ScheduledAction] = {}
_ACTION_LOCK = RLock()


def register_scheduled_action(*, id: str, module_id: str, label: str, handler, description: str = "", target_types=("none",), permission: str | None = None, dangerous: bool = False):
    action_id = str(id or "").strip()
    module = str(module_id or "").strip()
    if not action_id or "." not in action_id:
        raise SchedulerError("Scheduled action id must be a namespaced value such as module.action.")
    if not module:
        raise SchedulerError("Scheduled action module_id is required.")
    if not callable(handler):
        raise SchedulerError("Scheduled action handler must be callable.")
    targets = tuple(str(v).strip() for v in target_types if str(v).strip()) or ("none",)
    action = ScheduledAction(action_id, module, str(label or action_id), handler, str(description or ""), targets, permission, bool(dangerous))
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
        if (now_utc - occurrence) < timedelta(minutes=1):
            return True
        if schedule.missed_policy != TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
            return False
        grace = int(schedule.missed_grace_minutes or 0)
        return grace == 0 or (now_utc - occurrence) <= timedelta(minutes=grace)
    occurrence = occurrence.replace(second=0, microsecond=0)
    now_min = now_utc.replace(second=0, microsecond=0)
    if occurrence > now_min:
        return False
    if occurrence == now_min:
        return True
    if schedule.missed_policy != TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
        return False
    grace = int(schedule.missed_grace_minutes or 0)
    return grace == 0 or (now_min - occurrence) <= timedelta(minutes=grace)


def _run_kwargs(schedule: TecTacSchedule, **extra):
    values = {
        "schedule": schedule,
        "schedule_snapshot_id": schedule.id,
        "schedule_name": schedule.name,
        "module_id": schedule.module_id,
        "action_id": schedule.action_id,
    }
    values.update(extra)
    return values


def cleanup_once_schedules(now: datetime | None = None) -> int:
    now = _as_utc(now or timezone.now())
    config = TecTacSchedulerConfig.current()
    retention = max(1, min(int(config.once_retention_hours or 48), 720))
    cutoff = now - timedelta(hours=retention)
    cleaned = 0
    qs = TecTacSchedule.objects.filter(schedule_type=TecTacSchedule.ScheduleType.ONCE, enabled=False)
    for schedule in qs.prefetch_related("runs"):
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
    }


def _queue_run(run: TecTacScheduleRun):
    from .tasks import execute_schedule_run
    state = TecTacSchedulerState.current()
    try:
        async_result = execute_schedule_run.delay(str(run.id))
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


def dispatch_due_schedules(now: datetime | None = None) -> dict:
    now = _as_utc(now or timezone.now())
    state = TecTacSchedulerState.current()
    state.last_tick_at = now
    state.last_tick_error = ""
    state.save(update_fields=["last_tick_at", "last_tick_error"])
    queued, skipped = [], []
    schedule_ids = list(TecTacSchedule.objects.filter(enabled=True).values_list("id", flat=True))
    try:
        for schedule_id in schedule_ids:
            with transaction.atomic():
                schedule = TecTacSchedule.objects.select_for_update().get(pk=schedule_id)
                if not schedule.enabled:
                    continue
                occurrence = latest_occurrence(schedule, now)
                if not occurrence:
                    continue
                key = due_key(occurrence, exact=(schedule.schedule_type == TecTacSchedule.ScheduleType.INTERVAL))
                if schedule.last_due_key == key:
                    continue
                if not _should_run_occurrence(schedule, occurrence, now):
                    if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE and occurrence < now.replace(second=0, microsecond=0):
                        schedule.last_due_key = key
                        schedule.enabled = False
                        schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
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
            _queue_run(run)
            queued.append(str(run.id))
        cleaned = cleanup_once_schedules(now)
        state.last_tick_completed_at = timezone.now()
        state.last_checked = len(schedule_ids)
        state.last_queued = len(queued)
        state.last_skipped = len(skipped)
        state.last_cleaned = cleaned
        state.last_tick_error = ""
        state.save(update_fields=["last_tick_completed_at", "last_checked", "last_queued", "last_skipped", "last_cleaned", "last_tick_error"])
        return {"queued": queued, "skipped": skipped, "cleaned": cleaned, "checked": len(schedule_ids), "now": now.isoformat()}
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

        schedule = existing or TecTacSchedule(owner_module=module, owner_key=key)
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
        schedule.owner_module = module
        schedule.owner_key = key
        schedule.interval_anchor_at = _as_utc(anchor) if anchor else None
        if schedule.schedule_type != TecTacSchedule.ScheduleType.INTERVAL:
            schedule.interval_seconds = None
            schedule.interval_anchor_at = None
        schedule.module_id = action.module_id
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


def serialize_action(action: ScheduledAction) -> dict:
    return {
        "id": action.id,
        "module_id": action.module_id,
        "label": action.label,
        "description": action.description,
        "target_types": list(action.target_types),
        "permission": action.permission,
        "dangerous": action.dangerous,
    }


def serialize_run(run: TecTacScheduleRun) -> dict:
    return {
        "id": str(run.id),
        "schedule_id": str(run.schedule_snapshot_id or run.schedule_id) if (run.schedule_snapshot_id or run.schedule_id) else None,
        "schedule_name": run.schedule_name or (run.schedule.name if run.schedule else "Deleted schedule"),
        "module_id": run.module_id or (run.schedule.module_id if run.schedule else ""),
        "action_id": run.action_id or (run.schedule.action_id if run.schedule else ""),
        "status": run.status,
        "scheduled_for": run.scheduled_for.isoformat(),
        "manual": run.manual,
        "targets_snapshot": run.targets_snapshot,
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
    latest = schedule.runs.first()
    payload = {
        "id": str(schedule.id),
        "name": schedule.name,
        "module_id": schedule.module_id,
        "action_id": schedule.action_id,
        "action_label": action.label if action else schedule.action_id,
        "action_available": bool(action),
        "target_mode": schedule.target_mode,
        "targets": schedule.targets,
        "parameters": schedule.parameters,
        "schedule_type": schedule.schedule_type,
        "timezone": schedule.timezone,
        "run_at": schedule.run_at.isoformat() if schedule.run_at else None,
        "run_time": schedule.run_time.isoformat() if schedule.run_time else None,
        "weekdays": schedule.weekdays,
        "day_of_month": schedule.day_of_month,
        "interval_seconds": schedule.interval_seconds,
        "interval_anchor_at": schedule.interval_anchor_at.isoformat() if schedule.interval_anchor_at else None,
        "owner_module": schedule.owner_module or None,
        "owner_key": schedule.owner_key or None,
        "enabled": schedule.enabled,
        "missed_policy": schedule.missed_policy,
        "missed_grace_minutes": schedule.missed_grace_minutes,
        "concurrency_policy": schedule.concurrency_policy,
        "retry_count": schedule.retry_count,
        "retry_delay_seconds": schedule.retry_delay_seconds,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "next_run_at": (next_occurrence(schedule).isoformat() if schedule.enabled and next_occurrence(schedule) else None),
        "last_status": latest.status if latest else None,
        "created_by": schedule.created_by.username if schedule.created_by else None,
        "updated_by": schedule.updated_by.username if schedule.updated_by else None,
        "created_at": schedule.created_at.isoformat(),
        "updated_at": schedule.updated_at.isoformat(),
    }
    if include_runs:
        payload["runs"] = [serialize_run(run) for run in schedule.runs.all()[:50]]
    return payload
