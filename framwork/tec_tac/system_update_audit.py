"""The audit row of a finished system update (Core 1.17.67, Q83 part 2).

The root helper that installs a framework or UI update cannot write Django audit. It leaves a job file (and, when the job ends, a history
file). The Scheduler tick calls ``audit_finished_system_updates`` once a minute; it reads those files and writes one row per finished job, so
the Audit page shows what happened a minute or two after the update ended:

    Update installed successfully 1.17.16 -> 1.17.17
    Update failed 1.17.16 -> 1.17.17. 1.17.16 was restored.

The "from" version comes from ``installed_version`` in the job file, which the helper records since 1.17.67. A job that the older helper ran
(including the update to 1.17.67 itself) has none, so its row reads ``Update installed successfully to 1.17.67``.

Rules: only jobs that finished in the last 24 hours, newest first, at most 20 rows per tick, one row per job (found again by its correlation
id, so a second pass writes nothing; a lookup that cannot run writes nothing). Versions pass a strict shape check, else ``unknown``. A
failure row carries no error text and no path. The sweep never raises and is not strict. The downgrade rows that the install route writes
(``system_update_downgrade``) are unchanged.
"""
from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from . import module_job_logs

logger = logging.getLogger("tec_tac.system_update_audit")

WINDOW_SECONDS = 24 * 3600
MAX_ROWS_PER_TICK = 20
FAILED_ACTION = "custom:system-update-failed"
_COMPONENTS = frozenset({"framework", "ui"})
_OPERATION_RE = re.compile(r"^[a-z][a-z-]{0,19}$")
_STATUS_RE = re.compile(r"^[a-z][a-z-]{0,29}$")


def correlation_id_for(result: str, job_id) -> str:
    """``system-update:<installed|failed>:<job id>``. The audit writer keeps the correlation id, so the sweep can always find its own row."""
    return f"system-update:{result}:{job_id or ''}"[:255]


def _version(value) -> str:
    text = str(value).strip() if isinstance(value, str) else ""
    return text if text and module_job_logs._VERSION_RE.fullmatch(text) else "unknown"


def _when(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _word(value, pattern) -> str | None:
    text = str(value).strip().lower() if isinstance(value, str) else ""
    return text if text and pattern.fullmatch(text) else None


def describe(job: dict) -> dict | None:
    """The row for one finished job, or None when the job is not finished or has no usable id. Builds no text from an error or a path."""
    status = job.get("status")
    if status not in ("succeeded", "failed"):
        return None
    job_id = str(job.get("id") or "")
    if not module_job_logs._UUID_RE.fullmatch(job_id):
        return None
    component = str(job.get("component") or "")
    component = component if component in _COMPONENTS else "unknown"
    old, new = _version(job.get("installed_version")), _version(job.get("version"))
    rollback = job.get("rollback") if isinstance(job.get("rollback"), dict) else None
    rollback_status = _word(rollback.get("status"), _STATUS_RE) if rollback else None
    if status == "succeeded":
        result = "installed"
        message = f"Update installed successfully {old} -> {new}" if old != "unknown" else f"Update installed successfully to {new}"
        action = "install"
    else:
        result = "failed"
        message = f"Update failed {old} -> {new}." if old != "unknown" else f"Update failed to {new}."
        if rollback and rollback.get("status") == "failed":
            message += " The rollback did not finish, check the server."
        elif old != "unknown" and rollback and (rollback.get("status") == "succeeded" or rollback.get("performed") is False):
            message += f" {old} was restored."
        action = FAILED_ACTION
    return {
        "action": action, "object_id": component, "message": message, "result": result, "job_id": job_id,
        "correlation_id": correlation_id_for(result, job_id),
        "metadata": {
            "job_id": job_id, "component": component, "from_version": old, "to_version": new, "operation": _word(job.get("operation"), _OPERATION_RE),
            "result": result, "requested_by": str(job.get("requested_by") or "")[:150] or None, "rollback_status": rollback_status,
        },
    }


def _already_written(row: dict) -> bool:
    """True when an audit row with this correlation id (or this job id) is already there. Raises when the lookup cannot run, so the caller
    writes nothing and a broken lookup can never repeat a row every tick."""
    from django.db.models import Q

    from . import audit

    return audit._auditlog_model().objects.filter(
        Q(debug_info__correlation_id=row["correlation_id"]) | Q(debug_info__metadata__job_id=row["job_id"]),
        action=row["action"], debug_info__object_id=row["object_id"],
    ).exists()


def _write(row: dict) -> bool:
    try:
        if _already_written(row):
            return False
    except Exception:
        logger.exception("Could not look up the system update audit row of job %s; not writing it.", row.get("job_id"))
        return False
    try:
        from . import audit

        actor = audit.service_audit_actor(module_id="core", service="system-update", identity="system")
        result = audit.record(
            actor=actor, module_id="core", action=row["action"], object_type="system_update", object_id=row["object_id"], message=row["message"],
            metadata=row["metadata"], strict=False, correlation_id=row["correlation_id"],
        )
    except Exception:
        logger.exception("Could not write the system update audit row of job %s.", row.get("job_id"))
        return False
    return bool(result.get("recorded", True)) if isinstance(result, dict) else True


def _iter_jobs():
    """Every readable job record of the jobs and the history folder, one per job id (the history copy wins)."""
    from . import system_update

    found = {}
    for root in (system_update.JOBS_ROOT, system_update.HISTORY_ROOT):
        for job_id, path in module_job_logs._job_files(Path(root)):
            record = module_job_logs._read_json_file(path)
            if record is not None:
                found[job_id] = record
    return list(found.values())


def audit_finished_system_updates(*, now: datetime | None = None, jobs=None) -> int:
    """Write the audit rows of system update jobs that finished in the last 24 hours. Returns the number of rows written. Never raises."""
    written = 0
    try:
        jobs = _iter_jobs() if jobs is None else jobs
        now = now or datetime.now(UTC)
        horizon = now.timestamp() - WINDOW_SECONDS
        candidates = []
        for job in jobs:
            if not isinstance(job, dict) or job.get("status") not in ("succeeded", "failed"):
                continue
            finished = _when(job.get("finished_at"))
            if finished is not None and finished.timestamp() >= horizon:
                candidates.append((finished, job))
        candidates.sort(key=lambda item: item[0], reverse=True)
        for _finished, job in candidates:
            if written >= MAX_ROWS_PER_TICK:
                break
            try:
                row = describe(job)
                if row is not None and _write(row):
                    written += 1
            except Exception:
                logger.exception("Could not write the system update audit row for job %s.", job.get("id"))
    except Exception:
        logger.exception("The system update audit sweep failed; the next tick retries.")
    return written
