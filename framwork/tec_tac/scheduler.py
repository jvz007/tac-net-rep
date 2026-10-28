from __future__ import annotations

import calendar
import functools
import json
import logging
import re
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
from .scheduler_run_context import (  # noqa: F401  (1.17.19: public re-exports of the run-context contract)
    SchedulerRunContext, VerifiedSchedulerRun, is_core_issued_run_context, verify_run_context,
)
from .scheduler_completion import (  # noqa: F401  (1.17.61: public re-exports; complete_pending_run is a plain alias so caller identity works)
    PendingCompletion, complete_pending_run, pending_completion,
)
from .scheduler_timing import queued_stale_deadline
from .scheduler_targets import SchedulerTargetShapeError, normalize_scheduler_targets
from . import scheduler_creation_scope


class SchedulerError(RuntimeError):
    pass


class SchedulerPermanentError(SchedulerError):
    """A failure that retries cannot reasonably correct."""


class SchedulerTransientError(SchedulerError):
    """A failure that may recover and may use the configured retry policy."""


class CreationScopeUnavailable(SchedulerPermanentError):
    """1.17.68: a read that needs the schedule's creation-time scope (``VerifiedSchedulerRun.held_at_creation``, ``resolved_endpoints``) found none,
    because the schedule was made before Core kept it (migration 0037) and nobody has edited it since. Core never invents one. The plain text
    tells the person what to do: edit the schedule or profile and save it once."""

    reason = "creation_scope_unavailable"

    def __init__(self, message="This schedule was made before Core kept its scope. Edit it and save it once."):
        super().__init__(message)


class SchedulerRunContextInvalid(SchedulerError):
    """1.17.19: ``verify_run_context`` was given a context Core did not issue, or for a run or an owner that no longer holds."""


class SchedulerNotAllowed(SchedulerError):
    """1.17.16: the user a module started a one-off run for may not run that action or touch those targets."""


class SchedulerCompletionRefused(SchedulerError):
    """1.17.61: ``complete_pending_run`` refused the completion. ``reason`` is a short code (caller_unverified, wrong_module, not_pending,
    wrong_job, conflict, late, unknown_run, action_unavailable); the message is plain text and names no ids."""

    def __init__(self, message, *, reason="refused"):
        super().__init__(message)
        self.reason = reason


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
    # 1.17.17: more than one accepted entry (any-of). Empty for a single entry or none. Last, so a positional constructor and
    # equality of every earlier action stay as they were. ``permission`` is then the entries joined with PERMISSION_ANY_JOIN.
    permission_any: tuple[str, ...] = ()
    # 1.17.63 (CQ179 b): kept for compatibility. Since 1.17.65 it has no effect (CQ188): every user-owned scheduled run is exempt from the
    # creator re-check, flagged or not. Still last, so equality and every positional constructor of an earlier action stay as they were.
    # Core still accepts True only for a module whose signed manifest lists system_actions.
    unattended: bool = False

    @property
    def permission_entries(self) -> tuple[str, ...]:
        """Every entry the caller may hold, any-of: a Tec-Tac permission code or ``tactical:<flag>``. Empty means managers only."""
        if self.permission_any:
            return self.permission_any
        return (self.permission,) if self.permission else ()


# 1.17.17: a scheduled action's permission may name a Tactical role flag, written ``tactical:can_manage_winupdates``.
TACTICAL_PERMISSION_PREFIX = "tactical:"
PERMISSION_ANY_JOIN = " | "
MAX_PERMISSION_ENTRIES = 8
_TACTICAL_ENTRY_RE = re.compile(r"can_[a-z0-9_]+")


def is_tactical_permission_entry(entry) -> bool:
    return isinstance(entry, str) and entry.startswith(TACTICAL_PERMISSION_PREFIX)


def _normalize_permission(permission) -> tuple[str | None, tuple[str, ...]]:
    """Check the shape of an action's ``permission`` and return ``(permission, permission_any)``.

    ``None`` or a text entry stays as it was (an empty text still means managers only). A list or tuple means any-of: one to
    eight non-empty, distinct text entries, a single entry reading as that entry. Only the shape is checked here. Whether a
    Tec-Tac code or a Tactical flag exists is decided when the action is used and fails closed (see ``_can_use_action``).
    """
    if permission is None or isinstance(permission, str):
        entries = (permission,) if permission else ()
        many = False
    elif isinstance(permission, (list, tuple)):
        entries, many = tuple(permission), True
        if not entries:
            raise SchedulerError("Scheduled action permission list may not be empty.")
        if len(entries) > MAX_PERMISSION_ENTRIES:
            raise SchedulerError(f"Scheduled action permission list has more than {MAX_PERMISSION_ENTRIES} entries.")
    else:
        raise SchedulerError("Scheduled action permission must be text, a list of text entries or None.")
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise SchedulerError("Scheduled action permission entries must be non-empty text.")
        if is_tactical_permission_entry(entry) and not _TACTICAL_ENTRY_RE.fullmatch(entry[len(TACTICAL_PERMISSION_PREFIX):]):
            raise SchedulerError(
                f"Scheduled action permission {entry!r} must be tactical: followed by a Tactical role flag such as can_manage_winupdates."
            )
    if len(set(entries)) != len(entries):
        raise SchedulerError("Scheduled action permission list repeats an entry.")
    if many and len(entries) > 1:
        return PERMISSION_ANY_JOIN.join(entries), entries
    return (entries[0] if entries else None), ()


_ACTIONS: dict[str, ScheduledAction] = {}
_ACTION_LOCK = RLock()


def _manifest_system_actions(module_id: str) -> tuple:
    """The ``system_actions`` ids in the signed manifest of the installed extension ``module_id``, or () (1.17.63). A test replaces it."""
    from . import registry

    for plugin in registry.discover_plugins():
        if plugin.plugin_id == module_id and plugin.plugin_type == "extension" and not getattr(plugin, "legacy", False):
            return tuple(getattr(plugin, "system_actions", ()) or ())
    return ()


_MANIFEST_CACHE: dict = {"signature": None, "actions": {}, "error": ""}
_MANIFEST_CACHE_LOCK = RLock()


def _manifest_signature() -> tuple:
    """A cheap fingerprint of every installed manifest file: (folder, mtime_ns, size). It changes when a module is installed, upgraded or
    removed, so the cache below needs no hook into the module manager (1.17.81)."""
    from . import registry

    parts = []
    for root in (registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT):
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            manifest = child / registry.MANIFEST_NAME
            try:
                info = manifest.stat()
            except OSError:
                continue
            parts.append((str(manifest), info.st_mtime_ns, info.st_size))
    return tuple(parts)


def _manifest_person_actions_table() -> tuple[dict, str]:
    """(module id -> ``scheduler_person_actions`` ids, error reason code). One ``discover_plugins`` scan per change of the manifest files,
    not one per run (1.17.81). A broken manifest gives ({}, 'manifest_unreadable'): fail closed, and the cache keeps the reason."""
    from . import registry

    try:
        signature = _manifest_signature()
    except Exception:  # noqa: BLE001 - an unreadable folder is never cached as good
        return {}, "manifest_unreadable"
    with _MANIFEST_CACHE_LOCK:
        if _MANIFEST_CACHE["signature"] == signature:
            return _MANIFEST_CACHE["actions"], _MANIFEST_CACHE["error"]
        try:
            actions = {
                plugin.plugin_id: tuple(getattr(plugin, "scheduler_person_actions", ()) or ())
                for plugin in registry.discover_plugins()
                if plugin.plugin_type == "extension" and not getattr(plugin, "legacy", False)
            }
            error = ""
        except Exception as exc:  # noqa: BLE001 - fail closed; the reason is logged
            logger.warning("Scheduler manifest read failed (reason=manifest_unreadable): %s", exc)
            actions, error = {}, "manifest_unreadable"
        _MANIFEST_CACHE.update(signature=signature, actions=actions, error=error)
        return actions, error


def _manifest_person_actions(module_id: str) -> tuple:
    """The ``scheduler_person_actions`` ids in the signed manifest of the installed extension ``module_id``, or () (1.17.80). Cached by
    manifest fingerprint since 1.17.81. A test replaces it."""
    return tuple(_manifest_person_actions_table()[0].get(module_id, ()))


def scheduled_person_action(schedule, action_id: str = "") -> bool:
    """1.17.80: does this module-owned schedule's action run as the schedule's stored creator, with every re-check kept?

    True only when ALL hold: the schedule is module-owned and not a one-off, a creator name is stored (so a person confirmed it through
    ``reconcile_schedule(confirmed_by_request=...)``, which checked their permission and scope and wrote the audit row), the action is registered
    with the Scheduler by the module that owns it, and that module's signed, installed manifest lists it under ``scheduler_person_actions``.
    It is not the AD-13 exemption: ``_is_unattended_scheduled_run`` stays False for it, so the creator must be active and must still hold the
    action permission and the scope on every run. Any error answers False."""
    try:
        if schedule is None or schedule.owner_type != TecTacSchedule.OwnerType.MODULE or is_one_off_schedule(schedule):
            return False
        action = get_scheduled_action(str(action_id or schedule.action_id))
        if action.module_id != schedule.owner_module:
            return False
        if action.id not in _manifest_person_actions(action.module_id):
            if _MANIFEST_CACHE.get("error"):
                logger.warning("Schedule %s runs without a person (reason=manifest_unreadable): the module manifest could not be read.", getattr(schedule, "pk", ""))
            return False
        return bool(schedule_creator_names(schedule)[0])
    except Exception:  # noqa: BLE001 - any failure means the creator is not the person
        return False


def manual_person_action(schedule, action_id: str = "") -> bool:
    """1.17.85: is a Run now of this schedule's action done as the person who pressed it, with every re-check kept?

    True when the schedule is module-owned and not a one-off, the action is registered with the Scheduler by the module that owns it, and that
    module's signed, installed manifest lists it under ``scheduler_person_actions``. Unlike ``scheduled_person_action`` no stored creator is needed:
    the person is the one who pressed the button, so Core checks them, not the creator. Any error answers False."""
    try:
        if schedule is None or schedule.owner_type != TecTacSchedule.OwnerType.MODULE or is_one_off_schedule(schedule):
            return False
        action = get_scheduled_action(str(action_id or schedule.action_id))
        return action.module_id == schedule.owner_module and action.id in _manifest_person_actions(action.module_id)
    except Exception:  # noqa: BLE001 - any failure means the clicker is not the person
        return False


# Since 1.17.65: True. Johan signed the amended AD-13 condition 2 (CQ184 b, CQ186, CQ189, chat, 20 October 2026); it is recorded in
# docs/tec-tac-module-standard.md section 1a, docs/review-accepted-decisions.md row 13, development rules 1.7 and checklist A2. A scheduled run
# is not re-checked against its creator at run time, as in Tactical. A person-started run (manual, one-off) still is. The scheduler gate test
# under tests/ fails when this literal is False or the documents lose the amended text.
AD13_CONDITION_2_AMENDED = True


def _action_declared_as_system_action(module_id: str, action_id: str) -> bool:
    """Is ``action_id`` listed in the signed manifest ``system_actions`` of ``module_id`` AND registered with core.system_actions for that
    module? Read at decision time (1.17.63); any error answers False."""
    try:
        from . import system_actions

        if action_id not in _manifest_system_actions(system_actions.declaring_module(module_id, action_id)):
            return False
        return bool(system_actions.is_registered_system_action(module_id, action_id))
    except Exception:  # noqa: BLE001 - any failure to read means the exemption does not apply
        return False


def system_action_state(module_id, action_id) -> str:
    """Is ``action_id`` a declared system action? ``'declared'`` (listed in the signed manifest AND registered with core.system_actions),
    ``'not_declared'`` (a definite no from either fact) or ``'unknown'`` (a read failed and the other fact did not already settle it) (1.17.67).

    The creation gate needs BOTH facts, so a definite False from either one proves an ordinary action. The cheap memory check runs first, so an
    ordinary action never reads the manifest. ``_action_declared_as_system_action`` is not this: it stays the run-time exemption, where a failed
    read means False and every re-check is kept (the safe side there)."""
    if not isinstance(module_id, str) or not isinstance(action_id, str):
        return "not_declared"
    from . import system_actions

    try:
        registered = bool(system_actions.is_registered_system_action(module_id, action_id))
    except Exception:  # noqa: BLE001 - a failed read is not an answer; the manifest may still settle it
        registered = None
    if registered is False:
        return "not_declared"
    try:
        listed = action_id in _manifest_system_actions(system_actions.declaring_module(module_id, action_id))
    except Exception:  # noqa: BLE001
        return "unknown"
    if not listed:
        return "not_declared"
    return "declared" if registered else "unknown"


def register_scheduled_action(*, id: str, module_id: str, label: str, handler, description: str = "", target_types=("none",), permission: str | list | tuple | None = None, dangerous: bool = False, timeout_seconds: int = 3600, unattended: bool = False):
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
    permission_text, permission_any = _normalize_permission(permission)
    if not isinstance(unattended, bool):
        raise SchedulerError("Scheduled action unattended must be true or false.")
    if unattended:
        try:
            from . import system_actions as _sys_actions

            declared = _manifest_system_actions(_sys_actions.declaring_module(module, action_id))
        except Exception as exc:
            raise SchedulerError("Core could not read the module's signed manifest, so the action cannot be marked unattended.") from exc
        if action_id not in declared:
            raise SchedulerError("An unattended scheduled action's id must be listed in its module's signed manifest under system_actions.")
    action = ScheduledAction(action_id, module, str(label or action_id), handler, str(description or ""), targets, permission_text, bool(dangerous), timeout, permission_any, unattended)
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


def _test_pending_handler(context):
    # 1.17.61: parks the run as "pending, finished later". No module can complete it (Core is never a caller), so the run stays Running
    # with a waiting label and recover_stale_runs fails it with CompletionTimeout after the action timeout. For the dev-server check.
    return pending_completion("module", f"scheduler-test:{context.get('run_id')}", note="Diagnostic run: it waits until the action timeout.")


register_scheduled_action(
    id="tec-tac.scheduler-test-pending",
    module_id="tec-tac",
    label="Scheduler pending-completion test",
    description="Framework diagnostic action that waits for a result nobody sends. The run stays Running and fails with CompletionTimeout after the action timeout. Harmless.",
    target_types=("none",),
    handler=_test_pending_handler,
    timeout_seconds=120,
)


def _module_repository_sync_handler(context):
    # 1.17.42 (CQ122): the daily refresh of the enabled module repositories. The logic lives in module_repository.
    from .module_repository import run_scheduled_sync

    return run_scheduled_sync(context)


register_scheduled_action(
    id="tec-tac.module-repository-sync",
    module_id="tec-tac",
    label="Module repository sync (daily)",
    description="Refreshes the enabled module repositories once a day. Only counts are recorded. One failed repository does not fail the run; the run fails only when every enabled repository fails.",
    target_types=("none",),
    permission=None,
    handler=_module_repository_sync_handler,
    timeout_seconds=900,
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
            waiting = str(getattr(run, "completion_state", "") or "") == "pending"
            if task_id and not waiting:  # a pending run's worker task has already returned: there is nothing to revoke
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
            if waiting:
                # 1.17.61: a run that waited for a result longer than its action timeout. The late completion is then refused.
                run.error_type = "CompletionTimeout"
                run.error = f"No result arrived within the action timeout of {timeout_seconds} seconds."
                run.completion_state = "expired"
                run.finished_at = now
                run.save(update_fields=["status", "error_type", "error", "completion_state", "finished_at"])
            else:
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
        "event_jobs": _event_jobs_health(now),  # 1.17.45, additive
    }


def _event_jobs_health(now: datetime) -> dict:
    """The additive ``event_jobs`` block of ``scheduler_health()`` (core.event_jobs 1.0.0). Never raises."""
    try:
        from .event_jobs import event_jobs_health

        return event_jobs_health(now)
    except Exception:
        logger.exception("The event job health could not be read.")
        return {"registered": 0, "pending": 0, "running": 0, "failed_last_24h": 0, "dropped_last_24h": 0, "oldest_pending_age_seconds": None, "error": "unavailable"}


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


def schedule_creator_names(schedule) -> tuple[str, str]:
    """``(creator, confirmed_by)`` as text (1.17.63). The stored names win. A row made before migration 0036 has none, so the creator
    falls back to ``created_by.username``. Either may be an empty string."""
    creator = str(getattr(schedule, "created_by_username", "") or "").strip()
    if not creator:
        creator = str(getattr(getattr(schedule, "created_by", None), "username", "") or "").strip()
    return creator, str(getattr(schedule, "confirmed_by_username", "") or "").strip()


def _is_unattended_scheduled_run(subject) -> bool:
    """The ONE place that decides whether the run-time owner re-check is skipped (1.17.65, AD-13 condition 2 amended, wide rule).

    ``subject`` is a ``TecTacSchedule`` (the tick, before the run exists) or a ``TecTacScheduleRun`` (verify_run_context). True only when
    ``AD13_CONDITION_2_AMENDED`` is True, the run is a scheduled one (a run with ``manual`` set is never), the schedule is not a one-off,
    and a creator name is stored (or readable from ``created_by``); and then: a user-owned schedule is exempt for EVERY registered action;
    a module-owned schedule is exempt only while the action id is still listed in the module's signed manifest ``system_actions`` and is
    registered with core.system_actions. Any error, an unregistered action or an unreadable manifest answers False, so the re-check stays.
    The person's right was checked when they created or edited the schedule. What stays checked on every run is listed in
    docs/system-actions.md. The ``unattended`` field of a registered action has no effect here (CQ188)."""
    if not AD13_CONDITION_2_AMENDED:
        return False  # the signed amendment is switched off: every scheduled run keeps the run-time re-check
    try:
        is_run = hasattr(subject, "manual")
        if is_run and _delegated_run_is_valid(subject):
            return True  # 1.17.68 (S4): the one-off a provider started under a valid delegation grant; its marker is signed and the grant is checked now
        schedule = getattr(subject, "schedule", None) if is_run else subject
        if schedule is None or (is_run and bool(subject.manual)):
            return False
        owner_type = (getattr(subject, "owner_type", "") if is_run else "") or schedule.owner_type
        owner_key = getattr(subject, "owner_key", "") if (is_run and getattr(subject, "owner_type", "")) else schedule.owner_key
        if owner_type not in (TecTacSchedule.OwnerType.USER, TecTacSchedule.OwnerType.MODULE):
            return False
        if owner_type == TecTacSchedule.OwnerType.MODULE and (is_one_off_key(owner_key) or is_one_off_schedule(schedule)):
            return False
        action_id = (getattr(subject, "action_id", "") if is_run else "") or schedule.action_id
        registered = get_scheduled_action(action_id)
        if owner_type == TecTacSchedule.OwnerType.MODULE and not _action_declared_as_system_action(registered.module_id, action_id):
            return False
        return bool(schedule_creator_names(schedule)[0])
    except Exception:
        return False


def _delegated_run_is_valid(run) -> bool:
    """Is this run the one-off that ``delegation.start_delegated_run`` started, with a marker Core signed, while its grant is still enabled and
    unchanged? Any other run, and any error, answers False, so every other one-off keeps all of its re-checks (CQ50)."""
    try:
        from . import delegation

        return bool(delegation.run_is_validly_delegated(run))
    except Exception:  # noqa: BLE001 - any failure means the re-check stays
        return False


def _runtime_authorization_error(schedule: TecTacSchedule, actor=None) -> str | None:
    """Re-check the saved actor, action permission and Tactical target scope.

    Save-time authorization is not durable authority. User-owned schedules run
    only while the original actor remains active and still has permission for
    both the registered action and the saved client/site/endpoint scope.
    Since 1.17.16 a module-owned one-off schedule (owner_key ``one-off:<id>``, AD-13 condition 2) is held to the same
    check against ``created_by``, the user the module started it for. Since 1.17.80 so is a module-owned schedule whose action is declared in the
    module's manifest ``scheduler_person_actions`` (``scheduled_person_action``) and that has a stored creator.
    Since 1.17.85 ``actor`` (optional) is the person who pressed Run now on a declared person action: the same checks run for them and not for the creator.
    """
    one_off = is_one_off_schedule(schedule)
    if actor is None:
        if schedule.owner_type != TecTacSchedule.OwnerType.USER and not one_off and not scheduled_person_action(schedule):
            return None  # 1.17.80: a declared module scheduled action with a stored creator is checked like a user-owned one
        actor = schedule.created_by
    if actor is None or not bool(getattr(actor, "is_active", False)) or (one_off and bool(getattr(actor, "is_installer_user", False))):
        return "Schedule owner is missing or inactive." if actor is schedule.created_by else "The person who started this run is missing or inactive."
    try:
        action = get_scheduled_action(schedule.action_id)
        # Runtime import avoids a scheduler <-> scheduler_views import cycle.
        from .scheduler_views import _can_use_action, _can_access_target_scope
        if not _can_use_action(actor, action):
            return "Schedule owner no longer has permission to run this action."
        decided = _resolver_scope_check(actor, action.module_id, schedule.targets or {})  # 1.17.68: a module-owned type with a resolver
        if decided is None:
            if not _can_access_target_scope(actor, schedule.targets or {}):
                return "Schedule targets are no longer within the owner's Tactical scope."
        elif not decided:
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


def _recover_event_jobs_safely(now: datetime) -> dict:
    """The tick's event job work (core.event_jobs 1.0.0, Core 1.17.45). A fault here is logged and never stops the schedules."""
    try:
        from .event_jobs import recover_event_jobs

        return recover_event_jobs(now)
    except Exception:
        logger.exception("The event job step of the Scheduler tick failed; schedules continue.")
        return {"error": True}


def dispatch_due_schedules(now: datetime | None = None) -> dict:
    now = _as_utc(now or timezone.now())
    state = TecTacSchedulerState.current()
    state.last_tick_at = now
    state.last_tick_error = ""
    state.save(update_fields=["last_tick_at", "last_tick_error"])
    queued, skipped, dispatch_failed = [], [], []
    stale = recover_stale_runs(now)
    event_jobs_result = _recover_event_jobs_safely(now)  # 1.17.45: isolated, so a fault there never stops the schedules below
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
                    # 1.17.65 (AD-13 condition 2 amended): a scheduled run is not re-checked against its creator (the one helper decides)
                    authorization_error = None if _is_unattended_scheduled_run(schedule) else _runtime_authorization_error(schedule)
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
            "cleaned_runs": cleaned_runs, "checked": len(schedule_ids), "now": now.isoformat(), "event_jobs": event_jobs_result,
        }
    except Exception as exc:
        state.last_tick_completed_at = timezone.now()
        state.last_tick_error = f"{exc.__class__.__name__}: {exc}"
        state.save(update_fields=["last_tick_completed_at", "last_tick_error"])
        raise


def queue_manual_run(schedule: TecTacSchedule, *, started_by=None):
    """Queue a Run now. 1.17.85: ``started_by`` (keyword-only, optional) is the signed-in person who pressed the button. Core stores them on the run and
    re-checks them live when a handler of a declared ``scheduler_person_actions`` action verifies its context. Without it a manual run has no person, as before."""
    extra = {}
    if started_by is not None:
        extra = {"started_by": started_by, "started_by_username": str(getattr(started_by, "username", "") or "")[:150]}
    run = TecTacScheduleRun.objects.create(**_run_kwargs(
        schedule, scheduled_for=timezone.now(), manual=True, targets_snapshot=schedule.targets or {}, **extra,
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


def _after_refusal_record_deny_row(function):
    """1.17.66: ``reconcile_schedule`` runs its work in one transaction, which a refusal rolls back. A refused system action schedule writes
    its deny audit row after that, so the row is kept. Any other exception passes through untouched."""
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SchedulerNotAllowed as exc:
            if getattr(exc, "pending", None):
                from . import system_action_confirmation

                system_action_confirmation.record_refusal(exc)
            if getattr(exc, "takeover_row", None):
                _record_takeover_refusal(exc)
            raise

    return wrapper


@_after_refusal_record_deny_row
def reconcile_schedule(*, owner_module: str, owner_key: str, action_id: str, schedule_type: str,
                       targets: dict | None = None, parameters: dict | None = None, enabled: bool = True,
                       name: str | None = None, timezone_name: str = "UTC", run_at: datetime | None = None,
                       run_time=None, weekdays: list[int] | None = None, day_of_month: int | None = None,
                       interval_seconds: int | None = None, interval_anchor_at: datetime | None = None,
                       target_mode: str = TecTacSchedule.TargetMode.SNAPSHOT,
                       missed_policy: str = TecTacSchedule.MissedPolicy.SKIP, missed_grace_minutes: int = 60,
                       concurrency_policy: str = TecTacSchedule.ConcurrencyPolicy.SKIP, retry_count: int = 0,
                       retry_delay_seconds: int = 60, confirmed_by_request=None, confirmation_id: str | None = None) -> TecTacSchedule | None:
    """Idempotently create/update a backend-module-owned scheduler definition.

    The ownership tuple is the stable identity. ``enabled=False`` disables an
    existing definition and is a no-op when one does not yet exist. Browser
    authentication is intentionally not part of this server-side contract.

    1.17.63 (CQ176): ``confirmed_by_request`` (keyword-only, optional) names the person behind the schedule. It must be a real Django
    or DRF request that passed Core's session check (the proof ``run_tactical_operation`` asks for), never a user id or an object
    that merely has a ``user``. Core then checks, for that person, the action's permission and the Tactical scope of the targets, the
    same checks ``start_one_off_run`` makes, stores the creator (the first time) and the confirmer by name, and writes one audit row
    for the creation and one for every change. The module stays the owner and the executor. WITHOUT a request, a schedule that has a
    stored creator can only be disabled or left unchanged: any change to its action, targets, parameters, timing or policies, and
    switching it back on, raises ``SchedulerError``. A schedule with no stored creator behaves exactly as before 1.17.63.

    1.17.66: ``confirmation_id`` (keyword-only, optional) is the id the confirmation route (or ``core.system_actions`` ``describe_confirmation``)
    issued for this person, action, targets, parameters and timing. It is read only when ``confirmed_by_request`` is given, the schedule is
    enabled and the action is a declared system action (in the signed manifest ``system_actions`` and registered with ``core.system_actions``).
    Then Core checks the person's permission, Tactical flags and scope at this creation or edit and refuses without a valid id
    (``SystemActionCreationRefused``, a ``SchedulerNotAllowed``). Any other action behaves exactly as before.
    """
    module, key = _validate_owner(owner_module, owner_key)
    if is_one_off_key(key):
        # 1.17.17: the one-off: prefix is Core's. Only start_one_off_run makes such a key, so a module cannot dress an
        # ordinary schedule as a one-off run (which the browser then refuses to run again and the worker re-checks as its owner).
        raise SchedulerError(f"owner_key may not start with {ONE_OFF_PREFIX!r}: that prefix is reserved to Core.")
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

        stored_creator = bool(existing is not None and schedule_creator_names(existing)[0])
        person = None
        takeover = False
        system_info = None
        if confirmed_by_request is not None:
            person = _verified_person(confirmed_by_request)
            _check_person_may_schedule(person, action, data["targets"])
            # 1.17.68 (Johan, 21 October 2026): a call with a person's request IS an edit, and the person who edits moves the ownership to
            # themselves. Never widens: their own scope must cover every target. Decided before any field of the row is touched.
            takeover = bool(enabled and existing is not None and schedule_creator_names(existing)[0] and _owner_differs(existing, person))
            if takeover and not _person_covers_targets(person, action, data["targets"]):
                refusal = TakeoverRefused(TAKEOVER_REFUSED)
                refusal.takeover_row = (person, existing.pk, action.id, module)
                raise refusal
            if data.get("enabled", True):
                system_info = _system_action_creation(person, action, data, confirmation_id, defer=True)
            data["targets"] = _canonicalize_targets_for_person(person, data["targets"])
        elif stored_creator and not enabled:
            # A module can switch off a person's schedule, never rewire it: only ``enabled`` changes.
            if existing.enabled:
                existing.enabled = False
                existing.save(update_fields=["enabled", "updated_at"])
                _audit_schedule_row(None, existing, "disable", "A module switched off a schedule that a person created.")
            return existing
        schedule = existing or TecTacSchedule(owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module, owner_key=key)
        before_fields = {name: _comparable(name, getattr(existing, name)) for name in _LOCKED_FIELDS} if existing is not None else None
        previous_names = schedule_creator_names(existing) if existing is not None else ("", "")
        # a refused change must leave the row exactly as it was, whatever holds it (a fresh database read, or a cached object)
        restore = ({name: getattr(existing, name) for name in (*_LOCKED_FIELDS, "name", "module_id", "target_state", "target_state_detail", "last_due_key")}
                   if (stored_creator and person is None) else None)
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
        changed = existing is None or any(_comparable(name, getattr(schedule, name)) != value for name, value in before_fields.items())
        if stored_creator and person is None and changed:
            for field_name, value in restore.items():
                setattr(existing, field_name, value)
            raise SchedulerError(
                "This schedule was created by a person. A module can switch it off or leave it as it is, but only that person's own "
                "request can change its action, targets, parameters, timing or switch it back on."
            )
        if stored_creator and person is None:
            return existing  # nothing changed: an identical call is a no-op and writes nothing
        owner_move = None
        if person is not None:
            first_time = existing is None or not schedule_creator_names(existing)[0]
            name_now = str(getattr(person, "username", "") or "")[:150]
            if first_time:
                schedule.created_by = person
                schedule.created_by_username = name_now
            elif takeover:
                owner_move = {"owner_changed_from": previous_names[0], "owner_changed_to": name_now, "previous_confirmed_by": previous_names[1]}
                schedule.created_by = person
                schedule.created_by_username = name_now
            schedule.updated_by = person
            schedule.confirmed_by_username = name_now
            if first_time or takeover or not _owner_differs(existing, person):
                # 1.17.68: what this person could reach when they saved it. Another person who only switches the schedule off changes neither
                # the owner nor the stored scope.
                schedule.creation_scope = scheduler_creation_scope.capture(person)
        schedule.save()
        if person is not None and (changed or owner_move or schedule_creator_names(schedule) != previous_names):
            _audit_schedule_row(
                person, schedule, "add" if existing is None else "modify",
                f"Module {module} {'created' if existing is None else 'changed'} a schedule that a person confirmed."
                + (" The ownership moved to the person who edited it." if owner_move else ""),
                strict=True, extra={**_system_action_audit_extra(system_info), **(owner_move or {})},
            )
        return schedule


# The fields a module may not change on a schedule a person created (1.17.63, CQ176). The name is display text and is left out.
_LOCKED_FIELDS = (
    "action_id", "target_mode", "targets", "parameters", "schedule_type", "timezone", "run_at", "run_time", "weekdays", "day_of_month",
    "interval_seconds", "interval_anchor_at", "enabled", "missed_policy", "missed_grace_minutes", "concurrency_policy", "retry_count",
    "retry_delay_seconds",
)


def _comparable(name: str, value):
    """A value in a form that two spellings of the same time compare equal in (a text time or datetime against the stored one)."""
    if isinstance(value, str) and name in ("run_time", "run_at", "interval_anchor_at"):
        from django.utils.dateparse import parse_datetime, parse_time

        parsed = parse_time(value) if name == "run_time" else parse_datetime(value)
        value = parsed if parsed is not None else value
    if name == "run_time" and hasattr(value, "hour") and not hasattr(value, "year"):
        value = value.replace(second=0, microsecond=0, tzinfo=None)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _verified_person(request):
    """The user behind a real, session-checked request, or ``SchedulerNotAllowed`` (1.17.63, CQ176). A user id, a stand-in object with
    a ``user`` and a request that did not pass Core's session check are all refused. A test replaces this function."""
    from .tactical_operations import _is_real_request

    if not _is_real_request(request) or getattr(request, "tec_tac_session", None) is None:
        raise SchedulerNotAllowed("A schedule a person confirms needs that person's own signed-in request.")
    user = getattr(request, "user", None)
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise SchedulerNotAllowed("A schedule a person confirms needs that person's own signed-in request.")
    refusal = _one_off_user_refusal(user)
    if refusal:
        raise SchedulerNotAllowed("The person must be an active, interactive user.")
    return user


def _check_person_may_schedule(user, action: ScheduledAction, targets: dict) -> None:
    """The permission and scope checks of ``start_one_off_run``, for the person who confirms a module-owned schedule."""
    from .scheduler_views import _can_use_action, _can_access_target_scope

    try:
        may_run = _can_use_action(user, action)
    except Exception as exc:
        raise SchedulerNotAllowed("The person's permission to run this action could not be verified.") from exc
    if not may_run:
        raise SchedulerNotAllowed("The person does not have permission to run this action.")
    try:
        decided = _resolver_scope_check(user, action.module_id, targets, refuse_empty=True)  # 1.17.68: a module-owned type with a resolver is judged by its endpoints
        in_scope = _can_access_target_scope(user, targets) if decided is None else decided
    except Exception as exc:
        raise SchedulerNotAllowed("The targets are outside the person's Tactical scope.") from exc
    if not in_scope:
        if decided is False and _names_no_endpoints(action.module_id, targets):
            raise SchedulerNotAllowed(EMPTY_TARGET_LIST_REFUSED)
        raise SchedulerNotAllowed("The targets are outside the person's Tactical scope.")


TAKEOVER_REFUSED = "You cannot take over this schedule: some of its targets are outside your Tactical scope."


class TakeoverRefused(SchedulerNotAllowed):
    """1.17.68: a person other than the owner tried to edit a schedule whose targets are wider than that person's own Tactical scope. Owner and
    scope stay as they were (CQ205 a: ownership never widens what a schedule runs as). ``reason`` is ``takeover_out_of_scope``."""

    reason = "takeover_out_of_scope"
    takeover_row = None  # (person, schedule id, action id, owner module): the deny row is written after the transaction rolls back


EMPTY_TARGET_LIST_REFUSED = (
    "This target list names no endpoints, so Core cannot check it against your Tactical scope. Add at least one endpoint and try again."
)


def _names_no_endpoints(module_id, targets) -> bool:
    """True when a resolver applies to ``targets`` and names no endpoint (1.17.69). Used only to choose the refusal text."""
    from . import scheduler_target_resolvers as resolvers

    try:
        pks = resolvers.resolve_agent_pks(module_id, targets)
    except Exception:  # noqa: BLE001 - only picks a text
        return False
    return pks is not None and not pks


def _resolver_scope_check(user, module_id, targets, *, strict: bool = False, refuse_empty: bool = False):
    """For a module-owned target type that has a registered resolver (1.17.68): ``True`` when every endpoint it names is inside the person's
    Tactical scope (a native scheduler manager passes unless ``strict``), ``False`` when one is not or the targets cannot be read, and ``None``
    when no resolver applies, so the caller keeps its existing rule. Never raises for a missing resolver; a read fault is ``False``.

    A resolver that names no endpoint (1.17.69, AD-42) cannot be checked against a scope. It is ``False`` when ``strict`` (a takeover) and, with
    ``refuse_empty`` (creation), for a person who is not a native scheduler manager and whose Tactical scope is not unrestricted. Every other path
    keeps ``True`` for it: a run with nothing to do must not fail, and a schedule must not vanish from a scoped person's list."""
    from . import scheduler_target_resolvers as resolvers

    kind = resolvers.target_type_of(targets)
    if kind is None or not module_id or not resolvers.has_resolver(module_id, kind):
        return None
    if not strict:
        from .scheduler_views import _native_scheduler_manager

        if _native_scheduler_manager(user):
            return True
    pks = resolvers.resolve_agent_pks(module_id, targets)
    if pks is None:
        return False
    from . import resources_adapter

    if not pks:
        if strict:
            return False  # nothing to check the person's scope against: a takeover is refused
        if refuse_empty:
            try:
                return bool(resources_adapter.tactical_scope_unrestricted(user=user))
            except Exception:  # noqa: BLE001 - fail closed
                return False
        return True  # a run-time or read check: a resolver that names no endpoint reaches nothing

    return bool(resources_adapter.agent_pks_in_role_scope(user=user, pks=sorted(pks)))


def _person_covers_targets(person, action: ScheduledAction, targets: dict) -> bool:
    """Does the person's own Tactical scope cover every target? No bypass for a scheduler manager: used before ownership moves to them."""
    decided = _resolver_scope_check(person, action.module_id, targets, strict=True)
    if decided is not None:
        return decided
    from .scheduler_views import _can_access_target_scope

    return bool(_can_access_target_scope(person, targets, strict=True))


def _owner_differs(existing, person) -> bool:
    """Is ``person`` someone other than the stored owner of ``existing`` (which has a stored creator name)?"""
    owner = getattr(existing, "created_by", None)
    if owner is not None:
        return getattr(owner, "pk", None) != getattr(person, "pk", None)
    stored = schedule_creator_names(existing)[0].casefold()
    return stored != str(getattr(person, "username", "") or "").casefold()


def _record_takeover_refusal(exc) -> None:
    """One deny row for a refused takeover, written after the transaction that the refusal rolled back. Never raises."""
    row, exc.takeover_row = exc.takeover_row, None
    try:
        from . import audit

        person, schedule_id, action_id, owner_module = row
        audit.record(
            actor=person, module_id="core", action="deny", object_type="scheduler_schedule", object_id=str(schedule_id),
            message=f"A schedule was not taken over: {TAKEOVER_REFUSED}",
            metadata={"reason": TakeoverRefused.reason, "requested_by": "module", "owner_module": str(owner_module)[:100], "action_id": str(action_id)[:160]},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a refused schedule takeover could not be written")


_TIMING_FIELDS = ("schedule_type", "run_at", "run_time", "weekdays", "day_of_month", "interval_seconds", "timezone")


def _system_action_creation(person, action: ScheduledAction, data: dict, confirmation_id, *, defer: bool = False):
    """The creation-time controls for a declared system action (1.17.66, AD-13 as amended). None for any other action: nothing changes for it.
    Raises ``SystemActionCreationRefused`` (a ``SchedulerNotAllowed``) when the person may not, or when the confirmation id does not fit."""
    from . import system_action_confirmation

    when = {name: data.get(name) for name in _TIMING_FIELDS}
    return system_action_confirmation.require_creation(person, action, data.get("targets"), data.get("parameters"), when, confirmation_id, defer=defer)


def _system_action_audit_extra(info) -> dict:
    """Counts for the audit row of a system action schedule (none for any other action)."""
    if not info:
        return {}
    from . import system_action_confirmation

    return system_action_confirmation.audit_extra(info)


def _canonicalize_targets_for_person(user, targets: dict) -> dict:
    from .scheduler_views import _canonicalize_endpoint_targets_for_user

    try:
        return _canonicalize_endpoint_targets_for_user(user, targets)
    except SchedulerError:
        raise
    except Exception as exc:
        raise SchedulerNotAllowed("The targets are outside the person's Tactical scope.") from exc


def _audit_schedule_row(person, schedule, action: str, message: str, *, strict: bool = False, extra: dict | None = None) -> None:
    """One audit row for a module-owned schedule a person created or changed (1.17.63). The actor is the person; with none, a Core service
    actor. The row names the creator and the confirmer. A strict row that cannot be written stops the change (the caller's transaction
    rolls back)."""
    from . import audit

    creator, confirmed = schedule_creator_names(schedule)
    try:
        actor = person if person is not None else audit.service_audit_actor(module_id="core", service="scheduler", identity="module-schedule")
        audit.record(
            actor=actor, module_id="core", action=action, object_type="scheduler_schedule", object_id=str(schedule.pk),
            message=message,
            metadata={
                "owner_module": schedule.owner_module, "owner_key": schedule.owner_key, "action_id": schedule.action_id,
                "requested_by": "module", "creator": creator, "confirmed_by": confirmed, "enabled": bool(schedule.enabled),
                **(extra or {}),
            },
            strict=strict,
        )
    except Exception as exc:
        if strict:
            raise SchedulerError("The audit row of this schedule could not be written, so nothing was changed.") from exc
        logger.exception("Tec-Tac audit row for a module-owned schedule could not be written")


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
                      parameters: dict | None = None, name: str | None = None, retry_count: int = 0,
                      retry_delay_seconds: int = DEFAULT_RETRY_DELAY_SECONDS, confirmation_id: str | None = None) -> TecTacScheduleRun:
    """Start one run of a registered Scheduler action on behalf of ``user`` and return the queued run (1.17.16).

    A module starts only its own actions (``action.module_id == owner_module``, as ``reconcile_schedule`` requires). The user
    must hold the action now (``scheduler_views._can_use_action``: an action with no permission is startable only by native
    scheduler managers, as in the browser) and the targets' Tactical scope. Core then creates a disabled ONCE module-owned
    schedule with ``owner_key`` ``one-off:<uuid>`` and ``created_by`` the user, so the ticker never dispatches it, the browser
    shows it as managed by the module, and ``cleanup_once_schedules`` removes it after the retention. The run is queued like a
    manual run. Before the handler runs Core re-checks that the user is still active and still holds the action and scope
    (AD-13 condition 2); if not, the run ends ``skipped``. This is the start-and-track call only, not the system-action
    contract. Raises ``SchedulerError`` (``SchedulerNotAllowed`` for a user who may not), ``SchedulerTransientError`` when the
    run could not be queued. Call it outside a database transaction that has not committed: the worker reads the run at once.

    1.17.18: ``retry_count`` (0 to 10, default 0) and ``retry_delay_seconds`` (1 to 86400, default 60) are keyword-only retry
    settings, stored on the one-off schedule exactly as ``reconcile_schedule`` stores them and snapshotted onto the run. When
    the handler raises ``SchedulerTransientError`` (or another error the worker treats as retryable) the worker re-queues the
    run with that countdown until the attempts are used up. The owner re-check of a one-off run runs again on every attempt. Anything that is
    not a whole number in range (a bool, a text, a float) raises ``SchedulerError`` before anything is created. The defaults
    equal the behaviour before 1.17.18.

    1.17.66: ``confirmation_id`` (keyword-only, optional). For a declared system action (in the signed manifest ``system_actions`` and registered
    with ``core.system_actions``) Core checks the user's permission, Tactical flags and scope now and refuses without a valid id
    (``SystemActionCreationRefused``, a ``SchedulerNotAllowed``); ask the confirmation route with timing ``{"schedule_type": "once", "run_at": "now"}``.
    For any other action the argument is ignored and nothing changes."""
    refusal = _one_off_user_refusal(user)
    if refusal:
        raise SchedulerNotAllowed(refusal)
    module, _ = _validate_owner(owner_module, ONE_OFF_PREFIX)
    action = get_scheduled_action(str(action_id or "").strip())
    if action.module_id != module:
        raise SchedulerError(f"Scheduled action {action.id!r} belongs to module {action.module_id!r}, not {module!r}.")
    if targets is not None and not isinstance(targets, dict):
        raise SchedulerError("targets must be an object.")
    for label, value in (("retry_count", retry_count), ("retry_delay_seconds", retry_delay_seconds)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchedulerError(f"{label} must be a whole number.")
    data = validate_schedule_payload({
        "name": str(name or f"{action.label} · one-off").strip()[:255],
        "action_id": action.id,
        "schedule_type": TecTacSchedule.ScheduleType.ONCE,
        "targets": targets or {"type": action.target_types[0]},
        "parameters": parameters if parameters is not None else {},
        "enabled": False,
        "retry_count": retry_count,
        "retry_delay_seconds": retry_delay_seconds,
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
    system_info = _system_action_creation(user, action, {"targets": canonical, "parameters": data["parameters"], "schedule_type": "once", "run_at": "now"}, confirmation_id)
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
        decided = _resolver_scope_check(user, action.module_id, canonical, refuse_empty=True)  # 1.17.68: a module-owned type with a resolver
        in_scope = _can_access_target_scope(user, canonical) if decided is None else decided
    except SchedulerError:
        raise
    except Exception as exc:
        raise SchedulerNotAllowed("The targets are outside the user's Tactical scope.") from exc
    if not in_scope:
        if decided is False and _names_no_endpoints(action.module_id, canonical):
            raise SchedulerNotAllowed(EMPTY_TARGET_LIST_REFUSED)
        raise SchedulerNotAllowed("The targets are outside the user's Tactical scope.")

    now = timezone.now()
    with transaction.atomic():
        schedule = TecTacSchedule.objects.create(
            name=data["name"], module_id=action.module_id, action_id=action.id,
            target_mode=TecTacSchedule.TargetMode.SNAPSHOT, targets=canonical, target_state="valid", target_state_detail="",
            parameters=data["parameters"], schedule_type=TecTacSchedule.ScheduleType.ONCE, timezone="UTC", run_at=now,
            owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=module, owner_key=f"{ONE_OFF_PREFIX}{uuid.uuid4()}",
            enabled=False, created_by=user, updated_by=user,
            retry_count=data["retry_count"], retry_delay_seconds=data["retry_delay_seconds"],
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
            metadata={"owner_module": module, "action_id": action.id, "requested_by": "scheduler", **_system_action_audit_extra(system_info)},
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
        "created_by_username": schedule_creator_names(schedule)[0] or None,  # 1.17.63, additive
    }


def serialize_action(action: ScheduledAction) -> dict:
    return {
        "id": action.id,
        "module_id": action.module_id,
        "label": action.label,
        "description": action.description,
        "target_types": list(action.target_types),
        "permission": action.permission,
        "permission_any": list(action.permission_any),
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
        "completion": _serialize_completion(run),  # 1.17.61, additive: null unless the run was parked as pending
    }


def _serialize_completion(run: TecTacScheduleRun) -> dict | None:
    state = str(getattr(run, "completion_state", "") or "")
    if not state:
        return None
    ref = getattr(run, "completion_ref", None)
    since = getattr(run, "completion_started_at", None)
    return {"state": state, "kind": (ref.get("kind") if isinstance(ref, dict) else None), "since": since.isoformat() if since else None}


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
        "created_by_username": schedule_creator_names(schedule)[0] or None,  # 1.17.63, additive: the stored name outlives the user row
        "confirmed_by_username": schedule_creator_names(schedule)[1] or None,
        "created_at": schedule.created_at.isoformat(),
        "updated_at": schedule.updated_at.isoformat(),
    }
    if include_runs:
        payload["runs"] = [serialize_run(run) for run in schedule.runs.all()[:50]]
    return payload
