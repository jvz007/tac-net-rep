"""The handler context of a Scheduler run, issued by Core so a module can tell it from one it built itself (Core 1.17.19).

A Scheduler action handler receives a context dict. Until 1.17.19 any module could build a dict with the same keys, so a
handler that must act for the person who owns a schedule (Script Manager running a script, Global Settings changing a setting)
could not tell a real run from a made-up one.

What this module does:

* ``execute_schedule_run`` (tec_tac/tasks.py, the one place a handler is called) builds the context through
  ``issue_run_context``. The result is a ``SchedulerRunContext``, a ``dict`` subclass. It carries every key it always did, so a
  handler that reads ``context["owner_username"]``, calls ``dict(context)`` or ``json.dumps(context)`` is unchanged.
* Core keeps a private identity registry of the instances it issued, with the run id of each. The dict fields are never trusted.
* ``verify_run_context(context, expected_module_id=..., expected_action_id=...)`` answers with a frozen ``VerifiedSchedulerRun`` or
  raises ``SchedulerRunContextInvalid``. The owner comes from the database (the run row, then the schedule's ``created_by``),
  never from the dict, and is checked again for access at that moment. A mutated ``owner_username`` or ``owner_user_id`` changes
  nothing.
* Since 1.17.20 the handler also names its own module id and action id (both required keywords). Core compares them with the module
  and action of the run it loaded, so a context issued for module A's action cannot verify inside module B's handler (a confused
  deputy). A missing, empty or non-string id fails closed. The comparison is exact.

What it does not do. Modules run in the same Python process as Core, so code that deliberately reaches into Core's private state
is outside what this stops. What it stops is a module naming a run or an owner that Core did not issue. A copy, ``{**context}``,
``copy.copy``, a pickled or Celery-carried context, and a context a module builds are all refused: pass the context object itself.
This is not the AD-13 system-action contract, which stays open.
"""
from __future__ import annotations

import copy
import logging
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("tec_tac.scheduler_run_context")

_RUNNING = "running"  # TecTacScheduleRun.Status.RUNNING (a text choice)
_PLAIN = "This is not a scheduler run context that Core issued for a run that is still going."
_NO_OWNER = "This run has no person behind it."
_OWNER_REFUSED = "The person who owns this schedule may no longer run it."
_UNVERIFIED = "The run could not be verified."
_OTHER_RUN = "This run belongs to another module or action."


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


def _is_unattended_scheduled_run(run) -> bool:
    """Is this a scheduled (not manual, not one-off) run, which the owner re-check skips (1.17.65)? The one decision lives in scheduler.py."""
    from .scheduler import _is_unattended_scheduled_run as decide

    return decide(run)


def _scheduled_person_action(schedule, action_id) -> bool:
    from .scheduler import scheduled_person_action

    return scheduled_person_action(schedule, action_id)


def _creator_names(schedule) -> tuple[str, str]:
    from .scheduler import schedule_creator_names

    return schedule_creator_names(schedule)


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


def _creation_scope_of(schedule):
    """The creation-time scope snapshot stored on the schedule (1.17.68), or None for a row that has none."""
    from . import scheduler_creation_scope

    return scheduler_creation_scope.snapshot_of(schedule)


def _max_agents() -> int:
    from .system_actions import MAX_AGENTS

    return MAX_AGENTS


def _read_endpoint_rows(*, targets, module_id, snapshot, user, whole_scope: bool, limit: int) -> list:
    """The endpoints of ``targets`` that lie inside ``snapshot`` (an unattended run) or ``user``'s live scope (a person-started run), as plain rows.
    Raises ``SchedulerPermanentError`` when the targets cannot be read as endpoints or more than ``limit`` are named, ``SchedulerTransientError``
    for a read fault. Nothing is truncated."""
    from . import resources_adapter as adapter
    from .scheduler import SchedulerPermanentError, SchedulerTransientError
    from .scheduler_targets import normalize_scheduler_targets, tactical_scope_ref

    try:
        shaped = normalize_scheduler_targets(targets)
        kind = tactical_scope_ref(shaped)["kind"]
        if kind == "none":
            if not whole_scope:
                return []
            pks = None  # the whole scope of the snapshot (or of the person), bounded by ``limit``
        else:
            resolved = adapter.agent_pks_for_scheduler_targets(targets=shaped, module_id=module_id)
            if resolved is None:
                raise SchedulerPermanentError("Core cannot read this schedule's targets as endpoints.")
            pks = sorted(int(pk) for pk in resolved[0])
            if len(pks) > limit:
                raise SchedulerPermanentError(f"The targets name more than {limit} endpoints, so nothing was read.")
        rows = adapter.agent_rows_in_scope(pks=pks, snapshot=snapshot, user=user, limit=limit)
    except SchedulerPermanentError:
        raise
    except Exception as exc:
        if type(exc).__name__ in ("TacticalResourceAdapterError", "SchedulerTargetShapeError"):
            raise SchedulerPermanentError("Core cannot read this schedule's targets as endpoints.") from None
        logger.warning("The endpoints of a scheduler run could not be read.", exc_info=True)
        raise SchedulerTransientError("Core could not read the endpoints just now. Try again.") from None
    if len(rows) > limit:
        raise SchedulerPermanentError(f"The targets name more than {limit} endpoints, so nothing was read.")
    return rows


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
    # 1.17.63 (CQ179 b), last so a positional constructor stays as it was. ``unattended`` is True for a scheduled run (since 1.17.65 every
    # user-owned one, not only a flagged action): its creator's rights are not read again for this run. The names are the stored ones and survive a deleted user row.
    creator_username: str | None = None
    confirmed_by_username: str | None = None
    unattended: bool = False
    # 1.17.68 (Johan, 21 October 2026, Q-APM12 b), appended and private: the creation-time scope of the schedule and the run's targets. The public
    # reads are ``has_creation_scope``, ``creation_scope_info``, ``held_at_creation`` and ``resolved_endpoints``.
    _creation_scope: Any = field(default=None, repr=False, compare=False)
    _targets: Any = field(default=None, repr=False, compare=False)

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

    # ---- 1.17.68: the scope the schedule was created with. Additive; every method above is unchanged.
    @property
    def has_creation_scope(self) -> bool:
        """True when the schedule carries the scope its person had when they created or last edited it. False for a schedule made before Core 1.17.68
        that nobody has edited since (the new reads then raise ``CreationScopeUnavailable``)."""
        return self._creation_scope is not None

    def creation_scope_info(self) -> dict | None:
        """A copy of the stored scope, ``{v, captured_for, captured_at, scope: {unrestricted, whole_client_ids, site_ids}, flags}``, or None.
        Changing the copy changes nothing."""
        return copy.deepcopy(self._creation_scope) if self._creation_scope is not None else None

    def _creation_scope_or_raise(self) -> dict:
        if self._creation_scope is None:
            from .scheduler import CreationScopeUnavailable

            raise CreationScopeUnavailable()
        return self._creation_scope

    def held_at_creation(self, flag) -> bool:
        """Did the person hold this Tactical role flag when they created or last edited the schedule? Never reads the owner's live row for an unattended
        run, so a disabled or demoted owner changes nothing. For a run a person started it is ``has_tactical_permission(flag)``, as before. A flag that
        is not a boolean ``can_*`` field of Tactical's Role answers False. Raises ``CreationScopeUnavailable`` for an unattended run with no stored scope."""
        try:
            name = _check_flag(flag)
        except Exception:
            return False
        if not self.unattended:
            return self.has_tactical_permission(name)
        return name in self._creation_scope_or_raise()["flags"]

    def resolved_endpoints(self, *, whole_scope: bool = False, limit: int | None = None) -> list:
        """The endpoints this run may reach, as rows ``{pk, agent_id, hostname, platform, client_id, site_id}`` sorted by ``pk``.

        An unattended run reads the stored creation-time scope and never the owner's live row; a run a person started reads that person's live scope,
        as before. Either way the result is the run's targets AND that scope, so it is never wider than what the person could see. Native targets
        (client, site, endpoint, dynamic) resolve as Core always read them; a module-owned type resolves through the module's registered resolver
        (``scheduler_target_resolvers``). ``none`` names no endpoint, so it returns [] unless ``whole_scope=True``, which returns the whole scope.
        ``limit`` (default and ceiling ``system_actions.MAX_AGENTS``): more endpoints than that raise, nothing is truncated. Raises
        ``CreationScopeUnavailable`` (unattended, no stored scope), ``SchedulerPermanentError`` (targets that cannot be read as endpoints, too many)
        or ``SchedulerTransientError`` (a read fault; try again)."""
        ceiling = _max_agents()
        if limit is None:
            limit = ceiling
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= ceiling:
            raise ValueError(f"limit must be a whole number from 1 to {ceiling}.")
        if self.unattended:
            snapshot, user = self._creation_scope_or_raise(), None
        else:
            snapshot, user = None, self._owner_now()
        return _read_endpoint_rows(targets=self._targets or {}, module_id=self.module_id, snapshot=snapshot, user=user, whole_scope=bool(whole_scope), limit=limit)


def _expected_id(value: Any) -> str:
    """An expected id the handler passed. Anything but a non-empty string fails closed: the check is never skipped."""
    if not isinstance(value, str) or not value:
        raise _invalid(_OTHER_RUN)
    return value


def verify_run_context(
    context: Any, *, expected_module_id: str, expected_action_id: str, require_owner: bool = True,
) -> VerifiedSchedulerRun:
    """Confirm that ``context`` is a handler context Core issued for a run that is still going, and read its owner.

    Since 1.17.20 the handler passes its own ``expected_module_id`` and ``expected_action_id`` (both required, keyword-only).
    They must equal the module and action of the run Core loaded, exactly. A context issued for another module's or action's run
    is refused with a plain message that names no ids, and so is an expected id that is missing, empty or not a string.

    Raises ``SchedulerRunContextInvalid`` (a ``SchedulerError``) with a plain message for anything else: a plain dict or a copy of
    the context, a run that is no longer running or no longer exists, a schedule that is gone, a run with no person behind it
    (when ``require_owner`` is True, the default) and an owner who is inactive, no longer holds the action or no longer holds the
    target scope. With ``require_owner=False`` a module-owned run verifies with ``user`` None."""
    want_module = _expected_id(expected_module_id)
    want_action = _expected_id(expected_action_id)
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
        module_id = str(run.module_id or schedule.module_id)
        action_id = str(run.action_id or schedule.action_id)
        if module_id != want_module or action_id != want_action:
            raise _invalid(_OTHER_RUN)
        one_off = bool(run.owner_type == "module" and _is_one_off_key(run.owner_key))
        unattended = _is_unattended_scheduled_run(run)  # the one helper; a manual run and a one-off are never unattended
        person_action = bool(not unattended and not bool(getattr(run, "manual", False)) and _scheduled_person_action(schedule, action_id))  # 1.17.80: declared module action; re-checked below
        user = schedule.created_by if (one_off or run.owner_type == "user" or unattended or person_action) else None
        if user is None and require_owner:
            raise _invalid(_NO_OWNER)
        if user is not None and not unattended and _authorization_error(schedule):
            raise _invalid(_OWNER_REFUSED)
        creator, confirmed = _creator_names(schedule) if (unattended or user is not None) else ("", "")
        return VerifiedSchedulerRun(
            run_id=str(run.id), schedule_id=str(run.schedule_snapshot_id or schedule.id),
            module_id=module_id, action_id=action_id,
            owner_module=run.owner_module or None, owner_key=run.owner_key or None, one_off=one_off, user=user,
            owner_user_id=getattr(user, "pk", None), owner_username=getattr(user, "username", None),
            creator_username=creator or None, confirmed_by_username=confirmed or None, unattended=bool(unattended),
            _creation_scope=_creation_scope_of(schedule), _targets=getattr(run, "targets_snapshot", None) or {},
        )
    except Exception as exc:
        if type(exc).__name__ == "SchedulerRunContextInvalid":
            raise
        logger.warning("Scheduler run context of run %s could not be verified.", run_id, exc_info=True)
        raise _invalid(_UNVERIFIED) from None
