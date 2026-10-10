from __future__ import annotations

import json
import logging

from django.db import transaction
from django.utils import timezone
from tacticalrmm.celery import app

from .models import TecTacScheduleRun
from .capabilities import capability_status, CapabilityDisabled, CapabilityUnavailable, CapabilityVersionMismatch, CapabilityUnhealthy
from .scheduler import (
    SchedulerError, SchedulerPermanentError, SchedulerTransientError, _runtime_authorization_error, effective_retry_delay_seconds,
    get_scheduled_action, is_one_off_key,
)

logger = logging.getLogger("tec_tac.tasks")


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



def _is_one_off_run(run) -> bool:
    return run.owner_type == "module" and is_one_off_key(run.owner_key)


def _skip_unauthorized_one_off(run, schedule) -> str | None:
    """AD-13 condition 2 (1.17.16): a one-off run is re-checked against the user it was started for just before its handler.

    Returns None when the run may go on. Otherwise the run ends ``skipped`` with the plain reason, one audit row is
    written (best effort) and the reason is returned. It never raises: a check that cannot be made counts as a refusal."""
    if schedule is None:
        reason = "The one-off schedule no longer exists."
    else:
        try:
            reason = _runtime_authorization_error(schedule)
        except Exception:
            logger.exception("The authorization check of a one-off run failed")
            reason = "Schedule authorization could not be verified at run time."
    if not reason:
        return None
    with transaction.atomic():
        current = TecTacScheduleRun.objects.select_for_update().get(pk=run.pk)
        if current.status != TecTacScheduleRun.Status.RUNNING:
            return f"run no longer active: {current.status}"
        current.status = TecTacScheduleRun.Status.SKIPPED
        current.error = reason
        current.error_type = "AuthorizationRevoked"
        current.finished_at = timezone.now()
        current.save(update_fields=["status", "error", "error_type", "finished_at"])
    try:
        from . import audit

        audit.record(
            actor=audit.service_audit_actor(module_id="core", service="scheduler", identity="one-off-run"),
            module_id="core", action="deny", object_type="scheduler_run", object_id=str(run.id),
            message=f"A one-off run of {run.action_id} was skipped: {reason}",
            metadata={"owner_module": run.owner_module, "action_id": run.action_id, "requested_by": "scheduler", "reason": reason},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a skipped one-off run could not be written")
    return f"run skipped: {reason}"


def _handler_owner(run, schedule) -> dict:
    """The additive owner keys of the handler context (1.17.16). The user fields are set only for a one-off run and for a
    user-owned schedule, the two cases where a person's authority backs the run; otherwise they are None."""
    one_off = _is_one_off_run(run)
    user = None
    if schedule is not None and (one_off or run.owner_type == "user"):
        user = schedule.created_by
    return {
        "owner_type": run.owner_type or (schedule.owner_type if schedule else None),
        "owner_module": run.owner_module or None,
        "owner_key": run.owner_key or None,
        "owner_user_id": getattr(user, "pk", None),
        "owner_username": getattr(user, "username", None),
        "one_off": one_off,
    }


def _retryable(exc) -> bool:
    if isinstance(exc, (SchedulerTransientError, CapabilityUnhealthy)):
        return True
    if isinstance(exc, (SchedulerError, CapabilityDisabled, CapabilityVersionMismatch, CapabilityUnavailable, ValueError, TypeError)):
        return False
    return True


@app.task(bind=True, name="tec_tac.execute_schedule_run", time_limit=605100)
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
    retry_delay = effective_retry_delay_seconds(run.retry_delay_seconds_snapshot)

    if _is_one_off_run(run):
        skipped = _skip_unauthorized_one_off(run, schedule)
        if skipped:
            return skipped

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
            **_handler_owner(run, schedule),
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
            if retry:
                current.last_queued_at = timezone.now()
            current.save(update_fields=["status", "error", "error_type", "finished_at", "last_queued_at"] if retry else ["status", "error", "error_type", "finished_at"])
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
