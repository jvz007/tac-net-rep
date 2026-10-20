"""Scheduler runs that finish later: ``PendingCompletion`` and ``complete_pending_run`` (Core 1.17.61, R-21 and R-22).

Until 1.17.61 a Scheduler run ended when its handler returned. A handler that only *started* something (a server-maintenance job, a
long fan-out in its own job) had to wait inside the handler or report success too early. Now a handler may return a
``PendingCompletion`` instead of a result. Core then keeps the run ``running`` (never ``succeeded``) until the real outcome arrives.

What a handler returns
    ``pending_completion(kind, external_job_id, note=None)``. It is an explicit Core class, not a dict with magic keys, so no existing
    handler can park a run by accident. ``kind`` is ``module`` (the module will call ``complete_pending_run`` from its own job) or
    ``server_maintenance_job`` (Core reads the job file and settles the run itself). ``external_job_id`` is 1 to 128 characters of
    letters, digits and ``. _ : -`` (a UUID for a server job). ``note`` is optional plain text up to 200 printable characters.

What Core does
    * The run stays ``running``. ``status`` values do not change, so the concurrency skip, once-cleanup and ``remove_owned_schedule``
      keep protecting it. ``completion_state`` is ``pending`` and ``completion_ref`` holds ``{kind, external_job_id, note}``.
    * ``schedule.last_run_at`` is not set and the run is never retried.
    * A run that waits longer than its action's ``timeout_seconds`` (the wait is bounded by it, 7 days at most) is failed by
      ``recover_stale_runs`` with error type ``CompletionTimeout``.

``complete_pending_run`` (kind ``module``), every rule fails closed
    1. The caller is verified from the call stack (``calling_module_for_core_provider``) and must be the module that owns the run's
       action. Core is never a caller. The function is exported from ``tec_tac.scheduler`` as a plain alias, with no wrapper frame, so
       the identity check sees the module's own frame. A call through a library or Core frame is refused.
    2. Under a row lock the run must still be ``running`` with ``completion_state`` ``pending`` and the ``external_job_id`` must equal
       the stored one.
    3. The same completion twice (same job id, same outcome) is an idempotent no-op: no second audit row, ``finished_at`` unchanged. A
       different second outcome, a completion after stale recovery and a completion by the wrong module are refused, each with at
       most one best-effort audit row ``custom:scheduler-completion-refused`` carrying a reason code only.
    4. ``succeeded`` ends the run ``succeeded``. ``failed``, ``cancelled`` and ``timed_out`` end it ``failed`` with error type
       ``ExternalFailed``, ``ExternalCancelled`` or ``ExternalTimedOut``. A job created, or an acknowledgement, is never success.
    5. ``result`` is JSON of at most 16 KiB and ``error`` is printable text of at most 500 characters.

Server-maintenance jobs (R-22, the Core-owned half)
    A handler that started a ``core.server_maintenance`` job with ``source_module`` and ``source_run_id`` in the operation context
    returns ``pending_completion("server_maintenance_job", job_id)``. When it returns, Core reads the job file and refuses the pending
    state (run ``failed``, error type ``PendingRefused``) unless the job exists and its context names this module and this run. The
    scheduler tick then calls ``settle_server_job_runs`` (guarded, at most 50 runs a tick, no module code runs in the tick) and settles
    the run when the job is terminal. The result carries the job id, status, exit code and failure classification, never output text or
    parameters. Honest limit: the job context is caller-asserted, so the binding stops mistakes and an honest module, not hostile signed
    code (the same limit as docs/caller-identity.md).

Core 1.17.62: a module cannot complete a run parked as ``server_maintenance_job`` (refused as ``wrong_kind``, run unchanged). The
module-callback hook for a finished job (R-22 part 2) lives in ``server_job_hooks.py``.
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db import transaction
from django.utils import timezone

from .models import TecTacScheduleRun

logger = logging.getLogger("tec_tac.scheduler_completion")

KIND_MODULE = "module"
KIND_SERVER_JOB = "server_maintenance_job"
KINDS = (KIND_MODULE, KIND_SERVER_JOB)
STATE_PENDING = "pending"
STATE_COMPLETED = "completed"
STATE_EXPIRED = "expired"
OUTCOMES = ("succeeded", "failed", "cancelled", "timed_out")
ERROR_TYPES = {"failed": "ExternalFailed", "cancelled": "ExternalCancelled", "timed_out": "ExternalTimedOut"}
EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NOTE_MAX = 200
ERROR_MAX = 500
RESULT_MAX_BYTES = 16 * 1024
WARNINGS_MAX = 10
SETTLE_BATCH = 50
MISSING_JOB_GRACE = timedelta(minutes=10)
REFUSAL_WINDOW_SECONDS = 300.0
_REFUSAL_MAX_KEYS = 256

_RUNNING = TecTacScheduleRun.Status.RUNNING
_SUCCEEDED = TecTacScheduleRun.Status.SUCCEEDED
_FAILED = TecTacScheduleRun.Status.FAILED

REFUSAL_TEXT = {
    "caller_unverified": "Core could not tell which module is calling, so the completion was refused.",
    "wrong_module": "Only the module that owns this run's action can complete it.",
    "action_unavailable": "The action of this run is not registered, so the completion was refused.",
    "unknown_run": "No run with that id exists.",
    "not_pending": "This run is not waiting for a result.",
    "wrong_job": "The job id does not match the one this run is waiting for.",
    "conflict": "This run was already completed with a different outcome.",
    "late": "This run was already closed, so the late completion was refused.",
    "wrong_kind": "This run waits for a server-maintenance job, which Core settles itself. A module cannot complete it.",
}

_REFUSALS: dict[tuple[str, str], float] = {}
_clock = time.monotonic  # a test replaces it


def _error(message: str):
    from .scheduler import SchedulerError

    return SchedulerError(message)


def _clean_ref(kind, external_job_id, note) -> dict:
    """Validate the three fields of a pending completion and return the ``completion_ref`` dict. Raises ``SchedulerError``."""
    if not isinstance(kind, str) or kind not in KINDS:
        raise _error(f"A pending completion kind must be one of {', '.join(KINDS)}.")
    if not isinstance(external_job_id, str) or not EXTERNAL_ID_RE.fullmatch(external_job_id):
        raise _error("A pending completion external_job_id must be 1 to 128 characters: letters, digits and . _ : -")
    if kind == KIND_SERVER_JOB:
        try:
            canonical = str(uuid.UUID(external_job_id))
        except (ValueError, AttributeError, TypeError):
            canonical = None
        if canonical != external_job_id:
            raise _error("A server_maintenance_job pending completion needs the job id exactly as Core wrote it (a lowercase UUID).")
    ref = {"kind": kind, "external_job_id": external_job_id}
    if note is not None:
        if not isinstance(note, str) or len(note) > NOTE_MAX or not note.isprintable():
            raise _error(f"A pending completion note must be printable text of at most {NOTE_MAX} characters.")
        ref["note"] = note
    return ref


@dataclass(frozen=True)
class PendingCompletion:
    """What a Scheduler handler returns for "started, finished later". Build it with ``pending_completion``. See the module docstring."""

    kind: str
    external_job_id: str
    note: str | None = None

    def __post_init__(self):
        _clean_ref(self.kind, self.external_job_id, self.note)


def pending_completion(kind, external_job_id, note=None) -> PendingCompletion:
    """Build the return value of a handler that finished starting something and will be completed later (Core 1.17.61)."""
    return PendingCompletion(kind, external_job_id, note)


def is_pending_completion(value) -> bool:
    """True only for an exact ``PendingCompletion`` (a subclass or a dict with the same keys is not one)."""
    return type(value) is PendingCompletion


# ------------------------------------------------------------------------------------------------ audit (best effort)
def _refusal_due(run_id: str, reason: str) -> bool:
    """At most one refusal row per run and reason in a window, so a looping caller cannot fill the audit trail."""
    now = _clock()
    key = (run_id, reason)
    last = _REFUSALS.get(key)
    if last is not None and 0 <= now - last < REFUSAL_WINDOW_SECONDS:
        return False
    if len(_REFUSALS) >= _REFUSAL_MAX_KEYS:
        _REFUSALS.clear()
    _REFUSALS[key] = now
    return True


def _audit(action: str, run, *, message: str, **metadata) -> None:
    """One best-effort Core audit row about a run. Never raises. Never carries a result, an error text or a parameter."""
    try:
        from . import audit

        meta = {"requested_by": "scheduler", "run_id": str(run.id), "action_id": str(run.action_id or ""), "owner_module": str(run.module_id or "")}
        meta.update({k: v for k, v in metadata.items() if v is not None})
        audit.record(
            actor=audit.service_audit_actor(module_id="core", service="scheduler", identity="completion"),
            module_id="core", action=action, object_type="scheduler_run", object_id=str(run.id), message=message, metadata=meta,
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a scheduler completion could not be written")


def _refuse(run, reason: str, caller: str | None = None):
    """Write at most one refusal row (reason code only) and raise ``SchedulerCompletionRefused``."""
    from .scheduler import SchedulerCompletionRefused

    text = REFUSAL_TEXT.get(reason, "The completion was refused.")
    if run is not None and _refusal_due(str(run.id), reason):
        _audit("custom:scheduler-completion-refused", run, message=f"A completion of a pending run was refused: {reason}.", reason=reason, caller_module=caller)
    raise SchedulerCompletionRefused(text, reason=reason)


# ------------------------------------------------------------------------------------------------ payload checks
def _clean_result(result, warnings) -> dict:
    if result is None:
        value = {}
    elif isinstance(result, dict):
        value = result
    else:
        value = {"value": result}
    try:
        raw = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        raise _error("complete_pending_run result must be JSON data.") from None
    if len(raw.encode("utf-8")) > RESULT_MAX_BYTES:
        raise _error(f"complete_pending_run result may be at most {RESULT_MAX_BYTES // 1024} KiB of JSON.")
    value = json.loads(raw)
    if warnings is not None:
        if (not isinstance(warnings, (list, tuple)) or len(warnings) > WARNINGS_MAX
                or not all(isinstance(w, str) and len(w) <= NOTE_MAX and w.isprintable() for w in warnings)):
            raise _error(f"complete_pending_run warnings must be a list of at most {WARNINGS_MAX} printable texts of at most {NOTE_MAX} characters.")
        if warnings:
            value = {**value, "warnings": list(warnings)}
    return value


def _clean_error(error) -> str:
    if error is None:
        return ""
    if not isinstance(error, str) or len(error) > ERROR_MAX or not error.isprintable():
        raise _error(f"complete_pending_run error must be printable text of at most {ERROR_MAX} characters.")
    return error


# ------------------------------------------------------------------------------------------------ applying an outcome
def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=dt_timezone.utc) if value.tzinfo is None else value.astimezone(dt_timezone.utc)


def _apply_outcome(run_pk, *, allowed_kind: str, external_job_id: str, outcome: str, result: dict, error: str, error_type: str | None = None):
    """Settle one pending run under a row lock. Returns ``(code, run)``; ``code`` is ``applied``, ``duplicate`` or a refusal reason.

    ``allowed_kind`` is the pending kind the caller may settle (Core 1.17.62): ``complete_pending_run`` passes ``module`` and the tick
    passes ``server_maintenance_job``. A run parked as the other kind is refused as ``wrong_kind`` and left untouched."""
    now = timezone.now()
    with transaction.atomic():
        try:
            current = TecTacScheduleRun.objects.select_for_update().get(pk=run_pk)
        except TecTacScheduleRun.DoesNotExist:
            return "unknown_run", None
        ref = current.completion_ref if isinstance(current.completion_ref, dict) else {}
        state = current.completion_state or ""
        if ref.get("kind") and ref.get("kind") != allowed_kind:
            return "wrong_kind", current
        if state == STATE_COMPLETED:
            same = ref.get("external_job_id") == external_job_id and ref.get("outcome") == outcome
            return ("duplicate" if same else "conflict"), current
        if state == STATE_EXPIRED:
            return "late", current
        if state != STATE_PENDING:
            return "not_pending", current
        if current.status != _RUNNING:
            return "late", current
        if ref.get("external_job_id") != external_job_id:
            return "wrong_job", current
        new_ref = dict(ref)
        new_ref["outcome"] = outcome
        current.completion_ref = new_ref
        current.completion_state = STATE_COMPLETED
        current.status = _SUCCEEDED if outcome == "succeeded" else _FAILED
        current.result = result
        current.error = error
        current.error_type = "" if outcome == "succeeded" else (error_type or ERROR_TYPES[outcome])
        current.finished_at = now
        current.save(update_fields=["completion_ref", "completion_state", "status", "result", "error", "error_type", "finished_at"])
        if current.schedule_id:
            current.schedule.last_run_at = now
            current.schedule.save(update_fields=["last_run_at", "updated_at"])
        return "applied", current


def _find_run(run_id):
    try:
        key = run_id if isinstance(run_id, uuid.UUID) else uuid.UUID(str(run_id))
    except (ValueError, AttributeError, TypeError):
        return None
    return TecTacScheduleRun.objects.filter(pk=key).first()


def _action_module(run) -> str | None:
    from .scheduler import get_scheduled_action

    try:
        return get_scheduled_action(str(run.action_id or "")).module_id
    except Exception:
        return None


def complete_pending_run(run_id, *, external_job_id, outcome, result=None, error=None, warnings=None):
    """Finish a run whose handler returned ``pending_completion("module", ...)`` (Core 1.17.61). The only way a module completes a run.

    ``outcome`` is ``succeeded``, ``failed``, ``cancelled`` or ``timed_out`` (anything else raises ``SchedulerError``). Only the module
    that owns the run's action may call it, from its own code (Core verifies the caller from the call stack and refuses Core, library and
    generated frames). The run must still be waiting and ``external_job_id`` must equal the one the handler returned. Call it after the
    handler has returned: a call before that finds no pending run and is refused as ``not_pending``, so retry it shortly. Returns
    ``{"run_id", "status", "duplicate"}``. A refusal raises ``SchedulerCompletionRefused`` (a ``SchedulerError``) with a ``reason`` code
    and a plain message, and writes at most one ``custom:scheduler-completion-refused`` audit row (reason code only). A bad ``result``,
    ``error`` or ``warnings`` raises ``SchedulerError``. See the module docstring."""
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise _error(f"complete_pending_run outcome must be one of {', '.join(OUTCOMES)}.")
    if not isinstance(external_job_id, str) or not EXTERNAL_ID_RE.fullmatch(external_job_id):
        raise _error("complete_pending_run external_job_id must be the id the handler returned.")
    from .caller_identity import calling_module_for_core_provider  # imported here so a module that only needs the Scheduler loads without it

    identity = calling_module_for_core_provider(provider_file=__file__)  # frame 1 is this function: a plain alias keeps the walk honest
    run = _find_run(run_id)
    if run is None:
        _refuse(None, "unknown_run")
    if identity is None:
        _refuse(run, "caller_unverified")
    owner = _action_module(run)
    if owner is None:
        _refuse(run, "action_unavailable", identity.module_id)
    if identity.module_id != owner or identity.module_id != str(run.module_id or owner):
        _refuse(run, "wrong_module", identity.module_id)
    clean_result = _clean_result(result, warnings if outcome == "succeeded" else None)
    clean_error = _clean_error(error)
    if outcome != "succeeded" and not clean_error:
        clean_error = {"failed": "The module reported that the work failed.", "cancelled": "The module reported that the work was cancelled.",
                       "timed_out": "The module reported that the work timed out."}[outcome]
    code, current = _apply_outcome(run.pk, allowed_kind=KIND_MODULE, external_job_id=external_job_id, outcome=outcome, result=clean_result, error=clean_error)
    if code == "applied":
        _audit("custom:scheduler-completion", current, message=f"A pending run was completed: {outcome}.", outcome=outcome,
               caller_module=identity.module_id, kind=(current.completion_ref or {}).get("kind"))
    elif code != "duplicate":
        _refuse(current or run, code, identity.module_id)
    return {"run_id": str(current.id), "status": str(current.status), "duplicate": code == "duplicate"}


# ------------------------------------------------------------------------------------------------ parking (called by the worker)
def server_job_binding_error(job_id: str, *, module_id: str, run_id: str) -> str | None:
    """None when the server-maintenance job exists and its context names this module and this run, else a plain reason."""
    from . import server_maintenance as sm

    try:
        job = sm._read_job(job_id)
    except sm.ServerMaintenanceNotFound:
        return "The server job does not exist."
    except Exception:
        logger.warning("The server job of a pending run could not be read.", exc_info=True)
        return "The server job could not be read."
    context = job.get("context")
    if not isinstance(context, dict) or str(context.get("source_module") or "") != module_id or str(context.get("source_run_id") or "") != run_id:
        return "The server job was not started by this module for this run."
    return None


def park_pending_run(run, pending, *, module_id: str) -> str:
    """Keep ``run`` running with a pending completion, or fail it as ``PendingRefused``. Called only by ``execute_schedule_run``."""
    refusal = None
    ref = None
    if not is_pending_completion(pending):
        refusal = "The handler returned something that is not a pending completion."
    else:
        try:
            ref = _clean_ref(pending.kind, pending.external_job_id, pending.note)  # a frozen object can still be changed with object.__setattr__
        except Exception as exc:
            refusal = str(exc) or "The pending completion is not valid."
        if refusal is None and ref["kind"] == KIND_SERVER_JOB:
            refusal = server_job_binding_error(ref["external_job_id"], module_id=module_id, run_id=str(run.id))
    now = timezone.now()
    with transaction.atomic():
        current = TecTacScheduleRun.objects.select_for_update().get(pk=run.pk)
        if current.status != _RUNNING:
            return f"run no longer active: {current.status}"
        if refusal:
            current.status = _FAILED
            current.error = refusal[:ERROR_MAX]
            current.error_type = "PendingRefused"
            current.finished_at = now
            current.save(update_fields=["status", "error", "error_type", "finished_at"])
            if current.schedule_id:
                current.schedule.last_run_at = now
                current.schedule.save(update_fields=["last_run_at", "updated_at"])
            return f"run failed: {refusal}"
        current.completion_state = STATE_PENDING
        current.completion_ref = ref
        current.completion_started_at = now
        current.save(update_fields=["completion_state", "completion_ref", "completion_started_at"])
    return "pending completion"


# ------------------------------------------------------------------------------------------------ the tick step (server jobs)
_JOB_OUTCOME = {"succeeded": "succeeded", "failed": "failed", "dispatch_failed": "failed", "cancelled": "cancelled"}
_CLASSIFICATION_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def _job_result(job: dict, status: str) -> dict:
    exit_result = job.get("exit_result") if isinstance(job.get("exit_result"), dict) else {}
    code = exit_result.get("exit_code")
    result = {"job_id": str(job.get("id") or ""), "status": status, "exit_code": code if isinstance(code, int) and not isinstance(code, bool) else None}
    failure = job.get("failure") if isinstance(job.get("failure"), dict) else {}
    classification = failure.get("classification")
    if isinstance(classification, str) and _CLASSIFICATION_RE.fullmatch(classification):
        result["classification"] = classification
    return result


def _settle_one(run, now: datetime, counts: dict) -> None:
    from . import server_maintenance as sm

    ref = run.completion_ref if isinstance(run.completion_ref, dict) else {}
    job_id = str(ref.get("external_job_id") or "")
    try:
        job = sm._read_job(job_id)
    except sm.ServerMaintenanceNotFound:
        started = run.completion_started_at or run.started_at
        if started is not None and now - _as_utc(started) > MISSING_JOB_GRACE:
            code, current = _apply_outcome(run.pk, allowed_kind=KIND_SERVER_JOB, external_job_id=job_id, outcome="failed", result={"job_id": job_id, "status": "missing"},
                                           error="The server job record is gone.")
            counts["settled" if code == "applied" else "skipped"] += 1
            if code == "applied":
                _audit("custom:scheduler-completion", current, message="A pending run was completed: failed (job record missing).", outcome="failed", caller_module="core", kind=KIND_SERVER_JOB)
        else:
            counts["waiting"] += 1
        return
    except Exception:
        counts["unreadable"] += 1
        logger.warning("A server job of a pending run could not be read; the next tick tries again.", exc_info=True)
        return
    context = job.get("context") if isinstance(job.get("context"), dict) else {}
    if str(context.get("source_module") or "") != str(run.module_id or "") or str(context.get("source_run_id") or "") != str(run.id):
        code, current = _apply_outcome(run.pk, allowed_kind=KIND_SERVER_JOB, external_job_id=job_id, outcome="failed", result={"job_id": job_id},
                                       error="The server job was not started by this module for this run.", error_type="PendingRefused")
    else:
        status = str(job.get("status") or "")
        outcome = _JOB_OUTCOME.get(status)
        if outcome is None:
            counts["waiting"] += 1
            return
        text = "" if outcome == "succeeded" else {"failed": "The server job failed.", "cancelled": "The server job was cancelled."}[outcome]
        code, current = _apply_outcome(run.pk, allowed_kind=KIND_SERVER_JOB, external_job_id=job_id, outcome=outcome, result=_job_result(job, status), error=text)
    if code == "applied":
        counts["settled"] += 1
        _audit("custom:scheduler-completion", current, message=f"A pending run was completed by the server job: {current.completion_ref.get('outcome')}.",
               outcome=current.completion_ref.get("outcome"), caller_module="core", kind=KIND_SERVER_JOB)
    else:
        counts["skipped"] += 1


def settle_server_job_runs(now: datetime | None = None, limit: int = SETTLE_BATCH) -> dict:
    """Settle every pending run that awaits a server-maintenance job whose job has finished. Never raises; at most ``limit`` runs.

    Idempotent: ``_apply_outcome`` settles a run once, under a row lock, so two ticks or two workers cannot settle it twice. Runs no
    module code. Returns counts: ``checked``, ``settled``, ``waiting``, ``skipped``, ``unreadable``, ``errors``."""
    counts = {"checked": 0, "settled": 0, "waiting": 0, "skipped": 0, "unreadable": 0, "errors": 0}
    try:
        moment = _as_utc(now or timezone.now())
        runs = list(TecTacScheduleRun.objects.filter(
            status=_RUNNING, completion_state=STATE_PENDING, completion_ref__kind=KIND_SERVER_JOB,
        ).order_by("completion_started_at")[:max(1, min(int(limit), SETTLE_BATCH))])
    except Exception:
        logger.exception("The pending server-job runs could not be listed")
        counts["errors"] += 1
        return counts
    for run in runs:
        counts["checked"] += 1
        try:
            _settle_one(run, moment, counts)
        except Exception:
            counts["errors"] += 1
            logger.exception("A pending server-job run could not be settled; the next tick tries again.")
    return counts
