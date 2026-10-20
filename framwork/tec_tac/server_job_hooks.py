"""Server job hooks: Core hands a finished server-maintenance job to the module that owns it (Core 1.17.62, R-22 part 2).

Why. A module that starts a ``core.server_maintenance`` job (a certificate renewal, a Tactical update) often has to record the outcome when
the job ends. Until now it could only do that while a browser page polled ``get_job``. If the tab was closed, nothing recorded the outcome.
Now Core does the waiting. It runs no module code in the one-minute Scheduler tick: it stores one event job for the owning module and the
ordinary ``core.event_jobs`` worker runs the module's handler, with every limit, retry, back-off, expiry and audit that event jobs have.

How a module takes part (``AppConfig.ready()`` only)::

    from tec_tac.event_jobs import register_event_job

    register_event_job(id="<module_id>.server_job_finished", module_id="<module_id>", label="Record a finished server job", handler=on_finished)

The event job id is fixed: ``<module_id>.server_job_finished``. The module's manifest-registered server-maintenance action carries
``owner_module`` (already so since 1.17.17), and Core ties a job to the module through the ``owner_module`` that Core wrote in the job file
when the job started. No new manifest key. A module that registers no such event job is left alone: its jobs are marked ``ignored``.

What the handler receives. ``context["payload"]`` is exactly ``{job_id, action_id, status, exit_code, classification?}``. ``status`` is
``succeeded``, ``failed``, ``cancelled`` or ``dispatch_failed``. ``classification`` is a short code such as ``timeout`` and appears only
when the job file holds one. Never output text and never parameters (rule A8): the handler reads the job through ``core.server_maintenance``
if it needs more. The handler runs as the module with no user and cannot make a Tactical change (AD-13 is unchanged).

Delivery. At most once per Core: the tick inserts a ``TecTacServerJobHook`` row (unique on the job id) BEFORE it stores the event, so two
ticks or two Core processes cannot hand over the same job twice. If the event could not be stored (a rate cap, a full backlog, a store
error) the row waits in ``retry`` and the next tick tries again, three times in all, then it is ``abandoned`` with one audit row. Once the
event is stored, its handler runs under the event job's own limits (attempts, back-off, expiry). A handler may therefore run more than
once, and it can also run for a job that a browser poll of ``JobView`` has already recorded, so it MUST be idempotent.

A module that is disabled, removed or not honoured (a replacement that is not the honoured one right now) when its job finishes gets
its job marked ``skipped`` with one audit row, never retried for ever. A module state Core cannot read leaves the job for the next tick.

Cost per tick. One directory listing of the job folder, one query for the already handled ids, then at most 50 job files are read, oldest
first. Only files changed in the last six hours are looked at, so a job that finished while Core was off for longer is not handed over.
The step never raises, and the tick's own output line is unchanged.

Honest limit: the owner of a job is what the job file says, and a job file is written by Core and the root helper (the same caller-asserted
limit as docs/caller-identity.md). The event job is stored on Core's authority through ``event_jobs.publish_for_core``, not through a
module's own publisher handle.
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from pathlib import Path

logger = logging.getLogger("tec_tac.server_job_hooks")

HOOK_JOB_NAME = "server_job_finished"
# BATCH caps the jobs HANDED OVER (read as finished) in one tick. READ_BUDGET caps the job files read in one tick, so files that are not
# finished yet cannot use up the batch (1.17.63, the held Medium of the 1.17.62 review).
BATCH = 50
READ_BUDGET = 200
CANDIDATE_CAP = 2000
# 1.17.64: a file read as not finished is skipped with no read for this many ticks at most, then read once more, so a rewrite that kept both
# the mtime and the size cannot hide a finished job for ever (the held Low of the 1.17.63 review).
WAITING_TICKS = 5
LOOKUP_CHUNK = 500
RECENT_WINDOW = timedelta(hours=6)
MAX_ATTEMPTS = 3
CLAIM_STALE = timedelta(minutes=15)
RETENTION = timedelta(days=30)
KEY_PREFIX = "server-job:"
TERMINAL = frozenset({"succeeded", "failed", "cancelled", "dispatch_failed"})
# 1.17.63 (CQ183): an owner is read as the job file wrote it, with the module id's own spelling. Never lowercased.
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

ACTION_SKIPPED = "custom:server-job-hook-skipped"
ACTION_ABANDONED = "custom:server-job-hook-abandoned"

STATE_CLAIMING = "claiming"
STATE_RETRY = "retry"
STATE_QUEUED = "queued"
STATE_SKIPPED = "skipped"
STATE_IGNORED = "ignored"
STATE_ABANDONED = "abandoned"
SETTLED_STATES = (STATE_CLAIMING, STATE_QUEUED, STATE_SKIPPED, STATE_IGNORED, STATE_ABANDONED)

REASON_TEXT = {
    "module_unavailable": "the module that owns the job was not installed and enabled when the job finished",
    "not_honoured": "the module that owns the job replaces a core module but is not the honoured replacement right now",
    "store_failed": "Core could not store the event job for the module after three tries",
}


def hook_job_id(module_id: str) -> str:
    """The event job id Core delivers to for ``module_id``: ``<module_id>.server_job_finished``."""
    return f"{module_id}.{HOOK_JOB_NAME}"


# ------------------------------------------------------------------------------------------------ the places this module reads Core
# Each one is small so a test can replace it without Django.

def _sm():
    from . import server_maintenance

    return server_maintenance


def _events():
    from . import event_jobs

    return event_jobs


def _now() -> datetime:
    from django.utils import timezone

    return timezone.now()


def _recent_job_ids(now: datetime) -> list[tuple[tuple[int, int], str]]:
    """``(stamp, job id)`` of the job files changed inside the window, oldest first, at most ``CANDIDATE_CAP``. The stamp is
    ``(st_mtime_ns, st_size)`` from the same stat (1.17.64). A listing and a stat, no file is read."""
    root = Path(_sm()._jobs_root())
    if not root.is_dir():
        return []
    floor = (now - RECENT_WINDOW).timestamp()
    found = []
    with os.scandir(root) as entries:
        for entry in entries:
            name = entry.name
            if not name.endswith(".json") or entry.is_symlink():
                continue
            try:
                canonical = str(uuid.UUID(name[:-5]))
                if canonical != name[:-5]:
                    continue
                info = entry.stat()
            except (ValueError, OSError):
                continue
            if info.st_mtime >= floor:
                found.append((info.st_mtime_ns, info.st_size, canonical))
    found.sort()
    return [((mtime_ns, size), job_id) for mtime_ns, size, job_id in found[:CANDIDATE_CAP]]


def _settled_ids(job_ids: list[str]) -> set[str]:
    """The job ids that already have a hook row in any state but ``retry``."""
    from .models import TecTacServerJobHook

    settled: set[str] = set()
    for start in range(0, len(job_ids), LOOKUP_CHUNK):
        chunk = job_ids[start:start + LOOKUP_CHUNK]
        rows = TecTacServerJobHook.objects.filter(job_id__in=chunk, state__in=SETTLED_STATES).values_list("job_id", flat=True)
        settled.update(str(value) for value in rows)
    return settled


def _claim(job_id: str, *, module_id: str, action_id: str, job_status: str) -> bool:
    """Take the at-most-once claim for ``job_id``. True only for the one caller that got it. A ``retry`` row is taken again, once."""
    from django.db import IntegrityError, transaction
    from django.db.models import F

    from .models import TecTacServerJobHook

    existing = TecTacServerJobHook.objects.filter(job_id=job_id).first()
    if existing is None:
        try:
            with transaction.atomic():
                TecTacServerJobHook.objects.create(
                    job_id=job_id, module_id=module_id, action_id=action_id, job_status=job_status, state=STATE_CLAIMING, attempts=1,
                )
        except IntegrityError:
            return False  # another tick or process claimed it first
        return True
    if existing.state != STATE_RETRY:
        return False
    taken = TecTacServerJobHook.objects.filter(pk=existing.pk, state=STATE_RETRY).update(state=STATE_CLAIMING, attempts=F("attempts") + 1)
    return taken == 1


def _set_state(job_id: str, state: str, *, reason: str = "", module_id: str = "", action_id: str = "", job_status: str = "") -> None:
    """Record the end state of a claim (create the row when there was no claim, as for an ignored job). Never raises."""
    try:
        from django.db import IntegrityError, transaction

        from .models import TecTacServerJobHook

        changed = TecTacServerJobHook.objects.filter(job_id=job_id).update(state=state, reason=reason[:40])
        if not changed:
            try:
                with transaction.atomic():
                    TecTacServerJobHook.objects.create(
                        job_id=job_id, module_id=module_id, action_id=action_id, job_status=job_status, state=state, reason=reason[:40], attempts=0,
                    )
            except IntegrityError:
                TecTacServerJobHook.objects.filter(job_id=job_id).update(state=state, reason=reason[:40])
    except Exception:
        logger.exception("A server job hook row could not be written")


def _attempts(job_id: str) -> int:
    from .models import TecTacServerJobHook

    row = TecTacServerJobHook.objects.filter(job_id=job_id).values_list("attempts", flat=True).first()
    return int(row or 0)


def _expire_stale_claims(now: datetime) -> int:
    """A claim left ``claiming`` for 15 minutes means a tick died between the claim and the store. At most once wins: the row becomes
    ``abandoned`` and the event is NOT stored again."""
    from .models import TecTacServerJobHook

    return TecTacServerJobHook.objects.filter(state=STATE_CLAIMING, updated_at__lt=now - CLAIM_STALE).update(state=STATE_ABANDONED, reason="claim_stale")


def _prune(now: datetime) -> None:
    from .models import TecTacServerJobHook

    TecTacServerJobHook.objects.filter(created_at__lt=now - RETENTION).exclude(state__in=(STATE_CLAIMING, STATE_RETRY)).delete()


def _replacement_blocked(module_id: str) -> bool | None:
    """True when the module replaces a core module and is not the honoured replacement now. None when that cannot be read."""
    try:
        from . import module_replacement, registry

        plugin = next((p for p in registry.discover_plugins() if p.plugin_id == module_id), None)
        replaces = str(getattr(plugin, "replaces", "") or "") if plugin is not None else ""
        if not replaces:
            return False
        return module_replacement.honoured_replacement(module_id) != replaces
    except Exception:
        logger.warning("The replacement state of module %s could not be read.", module_id, exc_info=True)
        return None


def _audit(action: str, *, job_id: str, module_id: str, action_id: str, reason: str) -> None:
    """One best-effort Core audit row about a job Core did not hand over. Never raises. Names ids and a reason code only."""
    try:
        from . import audit

        audit.record(
            actor=audit.service_audit_actor(module_id="core", service="server-maintenance", identity="job-hook"),
            module_id="core", action=action, object_type="server_maintenance_job", object_id=job_id,
            message=f"A finished server job was not handed to its module: {REASON_TEXT.get(reason, reason)}.",
            metadata={"requested_by": "server-job-hook", "job_id": job_id, "action_id": action_id, "owner_module": module_id, "reason": reason},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a server job hook could not be written")


# ------------------------------------------------------------------------------------------------ the payload
def hook_payload(job: dict) -> dict:
    """What the handler is given: ids, status, exit code and a failure code. Never output and never parameters."""
    from .scheduler_completion import _job_result

    status = str(job.get("status") or "")
    result = _job_result(job, status)
    action = str(job.get("action") or "")
    payload = {"job_id": result["job_id"], "action_id": action if ACTION_RE.fullmatch(action) else "", "status": status, "exit_code": result["exit_code"]}
    if "classification" in result:
        payload["classification"] = result["classification"]
    return payload


# ------------------------------------------------------------------------------------------------ the tick step
# Job files read as not finished (or briefly not there): job id -> (the file's stamp when it was read, the tick it was remembered in). While the
# stamp (mtime in nanoseconds and size) is unchanged and the entry is younger than WAITING_TICKS the file is skipped with no read, because a
# status change rewrites the job file and so changes its stamp. An entry that has expired is read once more and remembered again, so a stuck
# job costs one read every few minutes and not one a minute. In memory, per process, and cleared of every job outside the window each tick.
# Never decides anything by itself: a job it skips is simply looked at again once its file changes or the entry expires.
_WAITING: dict[str, tuple[tuple[int, int], int]] = {}
_TICK = [0]  # advances once per deliver_finished_server_jobs call


def _remember(job_id: str, stamp) -> None:
    if stamp is not None:
        _WAITING[job_id] = (stamp, _TICK[0])


def _is_waiting(job_id: str, stamp) -> bool:
    entry = _WAITING.get(job_id)
    return entry is not None and entry[0] == stamp and _TICK[0] - entry[1] < WAITING_TICKS


def _handle_one(job_id: str, counts: dict, stamp: tuple[int, int] | None = None) -> bool:
    """Read one job file and hand it over when it is finished. True only when the job was read as FINISHED (it uses the batch)."""
    sm = _sm()
    try:
        job = sm._read_job(job_id)
    except sm.ServerMaintenanceNotFound:
        counts["waiting"] += 1
        _remember(job_id, stamp)
        return False
    except Exception:
        counts["unreadable"] += 1
        logger.warning("A server job could not be read; the next tick tries again.", exc_info=True)
        return False
    status = str(job.get("status") or "")
    if status not in TERMINAL:
        counts["waiting"] += 1
        _remember(job_id, stamp)
        return False
    _WAITING.pop(job_id, None)
    _hand_over(job_id, job, status, counts)
    return True


def _hand_over(job_id: str, job: dict, status: str, counts: dict) -> None:
    """Hand one job read as finished to the module that owns it (the part of the tick that stores the event)."""
    action_id = str(job.get("action") or "")
    action_id = action_id if ACTION_RE.fullmatch(action_id) else ""
    raw_owner = job.get("owner_module")
    owner = raw_owner if isinstance(raw_owner, str) and OWNER_RE.fullmatch(raw_owner) else ""
    common = {"module_id": owner, "action_id": action_id, "job_status": status}
    events = _events()
    if not owner or not events.has_registered_event_job(hook_job_id(owner), owner):
        _set_state(job_id, STATE_IGNORED, reason="no_hook" if owner else "no_owner", **common)
        counts["ignored"] += 1
        return
    module_state = events.module_status_for_core(owner)
    if module_state == events.UNKNOWN:
        counts["unreadable"] += 1
        return  # no row: the next tick looks again
    blocked = _replacement_blocked(owner) if module_state == events.RUNNABLE else False
    if blocked is None:
        counts["unreadable"] += 1
        return
    if module_state != events.RUNNABLE or blocked:
        reason = "not_honoured" if module_state == events.RUNNABLE else "module_unavailable"
        if _claim(job_id, **common):
            _set_state(job_id, STATE_SKIPPED, reason=reason, **common)
            _audit(ACTION_SKIPPED, job_id=job_id, reason=reason, **{k: common[k] for k in ("module_id", "action_id")})
            counts["skipped"] += 1
        return
    if not _claim(job_id, **common):
        counts["duplicate"] += 1
        return
    outcome = events.publish_for_core(hook_job_id(owner), module_id=owner, key=KEY_PREFIX + job_id, payload=hook_payload(job))
    if outcome.outcome in ("queued", "duplicate"):
        _set_state(job_id, STATE_QUEUED, **common)
        counts["delivered"] += 1
    elif outcome.outcome == "disabled":  # the module was disabled between the check and the store
        _set_state(job_id, STATE_SKIPPED, reason="module_unavailable", **common)
        _audit(ACTION_SKIPPED, job_id=job_id, reason="module_unavailable", module_id=owner, action_id=action_id)
        counts["skipped"] += 1
    elif _attempts(job_id) >= MAX_ATTEMPTS:
        _set_state(job_id, STATE_ABANDONED, reason="store_failed", **common)
        _audit(ACTION_ABANDONED, job_id=job_id, reason="store_failed", module_id=owner, action_id=action_id)
        counts["abandoned"] += 1
    else:
        _set_state(job_id, STATE_RETRY, reason=(outcome.reason or "not_stored")[:40], **common)
        counts["retry"] += 1


def deliver_finished_server_jobs(now: datetime | None = None, limit: int = BATCH) -> dict:
    """Hand every recently finished server-maintenance job to the module that owns it, once. Never raises. At most ``limit`` (and never more
    than ``BATCH``) finished jobs are handed over a tick, and at most ``READ_BUDGET`` job files are read. A file that is not finished is
    skipped with no read while its mtime and size are unchanged and the entry is young (under ``WAITING_TICKS`` ticks), so unfinished files cannot use the batch (1.17.63, 1.17.64).

    Runs no module code: it stores one event job (``event_jobs.publish_for_core``) and a worker runs the handler. Returns counts:
    ``checked``, ``delivered``, ``waiting``, ``skipped``, ``ignored``, ``duplicate``, ``retry``, ``abandoned``, ``unreadable``, ``errors``."""
    counts = {"checked": 0, "delivered": 0, "waiting": 0, "skipped": 0, "ignored": 0, "duplicate": 0, "retry": 0, "abandoned": 0, "unreadable": 0, "errors": 0}
    try:
        moment = now or _now()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt_timezone.utc)
        _TICK[0] += 1
        recent = _recent_job_ids(moment)
        settled = _settled_ids([job_id for _stamp, job_id in recent]) if recent else set()
        in_window = {job_id for _stamp, job_id in recent}
        for stale in [job_id for job_id in _WAITING if job_id not in in_window]:
            _WAITING.pop(stale, None)  # outside the window: forgotten
        todo = [(stamp, job_id) for stamp, job_id in recent if job_id not in settled]
        batch = max(1, min(int(limit), BATCH))
    except Exception:
        logger.exception("The finished server jobs could not be listed")
        counts["errors"] += 1
        return counts
    reads = handed = 0
    for stamp, job_id in todo:
        if _is_waiting(job_id, stamp):
            counts["waiting"] += 1  # read as not finished and not changed since (and still young): no read, no cost
            continue
        if handed >= batch or reads >= READ_BUDGET:
            break
        reads += 1
        counts["checked"] += 1
        try:
            if _handle_one(job_id, counts, stamp):
                handed += 1
        except Exception:
            counts["errors"] += 1
            logger.exception("A finished server job could not be handed over; the next tick tries again.")
    try:
        _expire_stale_claims(moment)
        _prune(moment)
    except Exception:
        logger.warning("The server job hook bookkeeping failed; the next tick retries.", exc_info=True)
    return counts
