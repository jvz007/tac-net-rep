"""The handler context of a Scheduler run, issued by Core so a module can tell it from one it built itself (Core 1.17.19).

A Scheduler action handler receives a context dict. Until 1.17.19 any module could build a dict with the same keys, so a
handler that must act for the person who owns a schedule (Script Manager running a script, Global Settings changing a setting)
could not tell a real run from a made-up one.

What this module does:

* ``execute_schedule_run`` (tec_tac/tasks.py, the one place a handler is called) builds the context through
  ``issue_run_context``. The result is a ``SchedulerRunContext``, a ``dict`` subclass. It carries every key it always did, so a
  handler that reads ``context["owner_username"]``, calls ``dict(context)`` or ``json.dumps(context)`` is unchanged.
* Core keeps a private identity registry of the instances it issued, with the run id of each. The dict fields are never trusted.
* ``verify_run_context(context)`` answers with a frozen ``VerifiedSchedulerRun`` or raises ``SchedulerRunContextInvalid``. The owner
  comes from the database (the run row, then the schedule's ``created_by``), never from the dict, and is checked again for
  access at that moment. A mutated ``owner_username`` or ``owner_user_id`` changes nothing.

What it does not do. Modules run in the same Python process as Core, so code that deliberately reaches into Core's private state
is outside what this stops. What it stops is a module naming a run or an owner that Core did not issue. A copy, ``{**context}``,
``copy.copy``, a pickled or Celery-carried context, and a context a module builds are all refused: pass the context object itself.
This is not the AD-13 system-action contract, which stays open.
"""
from __future__ import annotations

import logging
import threading
import weakref
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("tec_tac.scheduler_run_context")

_RUNNING = "running"  # TecTacScheduleRun.Status.RUNNING (a text choice)
_PLAIN = "This is not a scheduler run context that Core issued for a run that is still going."
_NO_OWNER = "This run has no person behind it."
_OWNER_REFUSED = "The person who owns this schedule may no longer run it."
_UNVERIFIED = "The run could not be verified."


class SchedulerRunContext(dict):
    """The handler context Core issues. A plain dict to every reader; Core knows the instances it issued."""


_LOCK = threading.Lock()
_ISSUED: dict[int, tuple[weakref.ref, str]] = {}


def issue_run_context(fields: dict, *, run_id: Any) -> SchedulerRunContext:
    """Build the context of one run and remember it. Called only by ``execute_schedule_run``."""
    context = SchedulerRunContext(fields)
    key = id(context)

    def _forget(_ref, key=key):
        with _LOCK:
            entry = _ISSUED.get(key)
            if entry is not None and entry[0] is _ref:
                del _ISSUED[key]

    with _LOCK:
        _ISSUED[key] = (weakref.ref(context, _forget), str(run_id))
    return context


def _issued_run_id(context: Any) -> str | None:
    """The run id Core issued ``context`` for, or None when this exact object is not one Core issued."""
    if type(context) is not SchedulerRunContext:
        return None
    with _LOCK:
        entry = _ISSUED.get(id(context))
    if entry is None or entry[0]() is not context:
        return None
    return entry[1]


def is_core_issued_run_context(context: Any) -> bool:
    """True when ``context`` is a context Core issued itself. Never raises."""
    try:
        return _issued_run_id(context) is not None
    except Exception:
        return False


def _invalid(message: str):
    from .scheduler import SchedulerRunContextInvalid

    return SchedulerRunContextInvalid(message)


# The few places this module reads Core. Each is one small function so a test can replace it without Django.

def _load_run(run_id: str):
    from .models import TecTacScheduleRun

    return TecTacScheduleRun.objects.select_related("schedule", "schedule__created_by").filter(pk=run_id).first()


def _is_one_off_key(owner_key) -> bool:
    from .scheduler import is_one_off_key

    return is_one_off_key(owner_key)


def _authorization_error(schedule) -> str | None:
    from .scheduler import _runtime_authorization_error

    return _runtime_authorization_error(schedule)


def _reload_user(pk):
    """The owner as the database holds them now, so a role or active flag changed a moment ago is seen."""
    from accounts.models import User

    return User.objects.filter(pk=pk).first()


def _check_flag(flag) -> str:
    from .rbac import _validate_tactical_flag

    return _validate_tactical_flag(flag)


def _user_has_flag(user, flag: str) -> bool:
    from .rbac import has_tactical_permission

    return bool(has_tactical_permission(user, flag))


def _user_resource_context(user):
    from . import resources

    return resources.user_context(user)


@dataclass(frozen=True)
class VerifiedSchedulerRun:
    """What Core confirmed about a run: who started it, for whom, and what it is. Built only by ``verify_run_context``."""

    run_id: str
    schedule_id: str
    module_id: str
    action_id: str
    owner_module: str | None
    owner_key: str | None
    one_off: bool
    user: Any
    owner_user_id: Any
    owner_username: str | None

    def _owner_now(self):
        if self.user is None:
            raise _invalid(_NO_OWNER)
        try:
            owner = _reload_user(self.owner_user_id)
        except Exception:
            logger.warning("Could not reload the owner of scheduler run %s.", self.run_id, exc_info=True)
            raise _invalid(_UNVERIFIED) from None
        if owner is None or not bool(getattr(owner, "is_active", False)):
            raise _invalid(_OWNER_REFUSED)
        return owner

    def has_tactical_permission(self, flag) -> bool:
        """Does the owner hold this Tactical role flag right now? Read fresh on every call. Fails closed.

        ``flag`` must name a boolean ``can_*`` field of Tactical's Role. Any other name, a missing owner and any lookup error
        answer False."""
        try:
            name = _check_flag(flag)
            return _user_has_flag(self._owner_now(), name)
        except Exception:
            return False

    def resource_context(self):
        """The Resource Directory context of the owner, so a scope-bound read runs as the person and not as Core."""
        return _user_resource_context(self._owner_now())


def verify_run_context(context: Any, *, require_owner: bool = True) -> VerifiedSchedulerRun:
    """Confirm that ``context`` is a handler context Core issued for a run that is still going, and read its owner.

    Raises ``SchedulerRunContextInvalid`` (a ``SchedulerError``) with a plain message for anything else: a plain dict or a copy of
    the context, a run that is no longer running or no longer exists, a schedule that is gone, a run with no person behind it
    (when ``require_owner`` is True, the default) and an owner who is inactive, no longer holds the action or no longer holds the
    target scope. With ``require_owner=False`` a module-owned run verifies with ``user`` None."""
    run_id = _issued_run_id(context)
    if run_id is None:
        raise _invalid(_PLAIN)
    try:
        run = _load_run(run_id)
        if run is None or str(getattr(run, "status", "")) != _RUNNING:
            raise _invalid(_PLAIN)
        schedule = getattr(run, "schedule", None)
        if schedule is None:
            raise _invalid(_PLAIN)
        one_off = bool(run.owner_type == "module" and _is_one_off_key(run.owner_key))
        user = schedule.created_by if (one_off or run.owner_type == "user") else None
        if user is None and require_owner:
            raise _invalid(_NO_OWNER)
        if user is not None and _authorization_error(schedule):
            raise _invalid(_OWNER_REFUSED)
        return VerifiedSchedulerRun(
            run_id=str(run.id), schedule_id=str(run.schedule_snapshot_id or schedule.id),
            module_id=str(run.module_id or schedule.module_id), action_id=str(run.action_id or schedule.action_id),
            owner_module=run.owner_module or None, owner_key=run.owner_key or None, one_off=one_off, user=user,
            owner_user_id=getattr(user, "pk", None), owner_username=getattr(user, "username", None),
        )
    except Exception as exc:
        if type(exc).__name__ == "SchedulerRunContextInvalid":
            raise
        logger.warning("Scheduler run context of run %s could not be verified.", run_id, exc_info=True)
        raise _invalid(_UNVERIFIED) from None
