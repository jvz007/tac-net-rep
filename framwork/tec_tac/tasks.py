from __future__ import annotations

import json

from django.db import transaction
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
    # Claim exactly once. Duplicate broker delivery must not execute an action
    # twice, and a stale-recovery decision must not be overwritten by a late task.
    with transaction.atomic():
        try:
            run = TecTacScheduleRun.objects.select_for_update().select_related("schedule").get(pk=run_id)
        except TecTacScheduleRun.DoesNotExist:
            return "run missing"
        if run.status != TecTacScheduleRun.Status.QUEUED:
            return f"run already {run.status}"
        schedule = run.schedule
        run.status = TecTacScheduleRun.Status.RUNNING
        run.started_at = timezone.now()
        run.finished_at = None
        run.attempt = int(getattr(self.request, "retries", 0) or 0) + 1
        run.error = ""
        run.error_type = ""
        run.save(update_fields=["status", "started_at", "finished_at", "attempt", "error", "error_type"])

    action_id = run.action_id or (schedule.action_id if schedule else "")
    module_id = run.module_id or (schedule.module_id if schedule else "")
    target_mode = run.target_mode_snapshot or (schedule.target_mode if schedule else "snapshot")
    parameters = run.parameters_snapshot if isinstance(run.parameters_snapshot, dict) else {}
    retries = int(run.retry_count_snapshot or 0)
    retry_delay = int(run.retry_delay_seconds_snapshot or 60)

    try:
        action = get_scheduled_action(action_id)
        context = {
            "schedule_id": str(run.schedule_snapshot_id or (schedule.id if schedule else "")),
            "run_id": str(run.id),
            "module_id": module_id,
            "action_id": action_id,
            "target_mode": target_mode,
            "targets": run.targets_snapshot,
            "parameters": parameters,
            "scheduled_for": run.scheduled_for,
            "manual": run.manual,
            "attempt": run.attempt,
        }
        result = action.handler(context)
        with transaction.atomic():
            current = TecTacScheduleRun.objects.select_for_update().get(pk=run.pk)
            if current.status != TecTacScheduleRun.Status.RUNNING:
                return f"run no longer active: {current.status}"
            current.status = TecTacScheduleRun.Status.SUCCEEDED
            current.result = _json_result(result)
            current.finished_at = timezone.now()
            current.save(update_fields=["status", "result", "finished_at"])
            if current.schedule_id:
                current.schedule.last_run_at = current.finished_at
                current.schedule.save(update_fields=["last_run_at", "updated_at"])
        return current.result
    except Exception as exc:
        current_retry = int(getattr(self.request, "retries", 0) or 0)
        retry = _retryable(exc) and current_retry < retries
        with transaction.atomic():
            current = TecTacScheduleRun.objects.select_for_update().get(pk=run.pk)
            if current.status != TecTacScheduleRun.Status.RUNNING:
                return f"run no longer active: {current.status}"
            current.error = str(exc) or exc.__class__.__name__
            current.error_type = exc.__class__.__name__
            current.finished_at = None if retry else timezone.now()
            current.status = TecTacScheduleRun.Status.QUEUED if retry else TecTacScheduleRun.Status.FAILED
            current.save(update_fields=["status", "error", "error_type", "finished_at"])
            if not retry and current.schedule_id:
                current.schedule.last_run_at = current.finished_at
                current.schedule.save(update_fields=["last_run_at", "updated_at"])
        if retry:
            raise self.retry(exc=exc, countdown=retry_delay, max_retries=retries)
        raise


@app.task(name="tec_tac.capability_probe")
def capability_probe(capability_id: str, version: str | None = None):
    """Return capability state from the Celery worker process for diagnostics."""
    return capability_status(capability_id, version=version)
