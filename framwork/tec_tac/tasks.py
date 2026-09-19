from __future__ import annotations

import json

from django.utils import timezone
from tacticalrmm.celery import app

from .models import TecTacScheduleRun
from .capabilities import capability_status, CapabilityDisabled, CapabilityUnavailable, CapabilityVersionMismatch, CapabilityUnhealthy
from .scheduler import SchedulerError, SchedulerPermanentError, SchedulerTransientError, get_scheduled_action


def _json_result(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        try:
            json.dumps(value)
            return value
        except TypeError:
            pass
    return {"value": str(value)}


def _retryable(exc) -> bool:
    if isinstance(exc, (SchedulerTransientError, CapabilityUnhealthy)):
        return True
    if isinstance(exc, (SchedulerError, CapabilityDisabled, CapabilityVersionMismatch, CapabilityUnavailable, ValueError, TypeError)):
        return False
    return True


@app.task(bind=True, name="tec_tac.execute_schedule_run")
def execute_schedule_run(self, run_id: str):
    try:
        run = TecTacScheduleRun.objects.select_related("schedule").get(pk=run_id)
    except TecTacScheduleRun.DoesNotExist:
        return "run missing"
    schedule = run.schedule
    run.status = TecTacScheduleRun.Status.RUNNING
    run.started_at = timezone.now()
    run.attempt = int(getattr(self.request, "retries", 0) or 0) + 1
    run.error = ""
    run.error_type = ""
    run.save(update_fields=["status", "started_at", "attempt", "error", "error_type"])
    try:
        action = get_scheduled_action(schedule.action_id)
        context = {
            "schedule_id": str(schedule.id),
            "run_id": str(run.id),
            "module_id": schedule.module_id,
            "action_id": schedule.action_id,
            "target_mode": schedule.target_mode,
            "targets": run.targets_snapshot,
            "parameters": schedule.parameters or {},
            "scheduled_for": run.scheduled_for,
            "manual": run.manual,
            "attempt": run.attempt,
        }
        result = action.handler(context)
        run.status = TecTacScheduleRun.Status.SUCCEEDED
        run.result = _json_result(result)
        run.finished_at = timezone.now()
        run.save(update_fields=["status", "result", "finished_at"])
        schedule.last_run_at = run.finished_at
        schedule.save(update_fields=["last_run_at", "updated_at"])
        return run.result
    except Exception as exc:
        run.error = str(exc) or exc.__class__.__name__
        run.error_type = exc.__class__.__name__
        run.finished_at = timezone.now()
        retries = int(schedule.retry_count or 0)
        current_retry = int(getattr(self.request, "retries", 0) or 0)
        if _retryable(exc) and current_retry < retries:
            run.status = TecTacScheduleRun.Status.QUEUED
            run.save(update_fields=["status", "error", "error_type", "finished_at"])
            raise self.retry(exc=exc, countdown=int(schedule.retry_delay_seconds or 60), max_retries=retries)
        run.status = TecTacScheduleRun.Status.FAILED
        run.save(update_fields=["status", "error", "error_type", "finished_at"])
        schedule.last_run_at = run.finished_at
        schedule.save(update_fields=["last_run_at", "updated_at"])
        raise


@app.task(name="tec_tac.capability_probe")
def capability_probe(capability_id: str, version: str | None = None):
    """Return capability state from the Celery worker process for diagnostics."""
    return capability_status(capability_id, version=version)
