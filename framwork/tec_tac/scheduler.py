from __future__ import annotations

import calendar
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import RLock
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.db import transaction
from django.utils import timezone

from .models import TecTacSchedule, TecTacScheduleRun


class SchedulerError(RuntimeError):
    pass


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


def _zone(value: str) -> ZoneInfo:
    try:
        return ZoneInfo(str(value or "UTC"))
    except ZoneInfoNotFoundError as exc:
        raise SchedulerError(f"Unknown timezone: {value}") from exc


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
            raise SchedulerError("schedule_type must be once, daily, weekly, or monthly.")
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


def due_key(when: datetime) -> str:
    return _as_utc(when).replace(second=0, microsecond=0).isoformat()


def _should_run_occurrence(schedule: TecTacSchedule, occurrence: datetime, now: datetime) -> bool:
    occurrence = _as_utc(occurrence).replace(second=0, microsecond=0)
    now_min = _as_utc(now).replace(second=0, microsecond=0)
    if occurrence > now_min:
        return False
    if occurrence == now_min:
        return True
    if schedule.missed_policy != TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY:
        return False
    grace = int(schedule.missed_grace_minutes or 0)
    return grace == 0 or (now_min - occurrence) <= timedelta(minutes=grace)


def dispatch_due_schedules(now: datetime | None = None) -> dict:
    from .tasks import execute_schedule_run

    now = _as_utc(now or timezone.now())
    queued, skipped = [], []
    schedule_ids = list(TecTacSchedule.objects.filter(enabled=True).values_list("id", flat=True))
    for schedule_id in schedule_ids:
        with transaction.atomic():
            schedule = TecTacSchedule.objects.select_for_update().get(pk=schedule_id)
            if not schedule.enabled:
                continue
            occurrence = latest_occurrence(schedule, now)
            if not occurrence:
                continue
            key = due_key(occurrence)
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
                run = TecTacScheduleRun.objects.create(
                    schedule=schedule,
                    status=TecTacScheduleRun.Status.SKIPPED,
                    scheduled_for=occurrence,
                    targets_snapshot=schedule.targets or {},
                    error=str(exc),
                    error_type="ActionUnavailable",
                    finished_at=now,
                )
                schedule.last_due_key = key
                if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
                    schedule.enabled = False
                schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
                skipped.append(str(run.id))
                continue
            active = schedule.runs.filter(status__in=[TecTacScheduleRun.Status.QUEUED, TecTacScheduleRun.Status.RUNNING]).exists()
            if active and schedule.concurrency_policy == TecTacSchedule.ConcurrencyPolicy.SKIP:
                run = TecTacScheduleRun.objects.create(
                    schedule=schedule,
                    status=TecTacScheduleRun.Status.SKIPPED,
                    scheduled_for=occurrence,
                    targets_snapshot=schedule.targets or {},
                    error="Skipped because a previous run is still active.",
                    error_type="ConcurrencySkip",
                    finished_at=now,
                )
                schedule.last_due_key = key
                schedule.save(update_fields=["last_due_key", "updated_at"])
                skipped.append(str(run.id))
                continue
            run = TecTacScheduleRun.objects.create(
                schedule=schedule,
                scheduled_for=occurrence,
                targets_snapshot=schedule.targets or {},
            )
            schedule.last_due_key = key
            if schedule.schedule_type == TecTacSchedule.ScheduleType.ONCE:
                schedule.enabled = False
            schedule.save(update_fields=["last_due_key", "enabled", "updated_at"])
        async_result = execute_schedule_run.delay(str(run.id))
        TecTacScheduleRun.objects.filter(pk=run.id).update(celery_task_id=str(async_result.id or ""))
        queued.append(str(run.id))
    return {"queued": queued, "skipped": skipped, "checked": len(schedule_ids), "now": now.isoformat()}


def queue_manual_run(schedule: TecTacSchedule):
    from .tasks import execute_schedule_run

    run = TecTacScheduleRun.objects.create(
        schedule=schedule,
        scheduled_for=timezone.now(),
        manual=True,
        targets_snapshot=schedule.targets or {},
    )
    async_result = execute_schedule_run.delay(str(run.id))
    run.celery_task_id = str(async_result.id or "")
    run.save(update_fields=["celery_task_id"])
    return run


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
        "schedule_id": str(run.schedule_id),
        "status": run.status,
        "scheduled_for": run.scheduled_for.isoformat(),
        "manual": run.manual,
        "targets_snapshot": run.targets_snapshot,
        "result": run.result,
        "error": run.error,
        "error_type": run.error_type,
        "attempt": run.attempt,
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
