"""System actions: typed Tactical work that Core runs unattended for a named owner (core.system_actions 1.0.0, Core 1.17.61, R-20, AD-13).

A system action is a Tactical function that Core may run when nobody is signed in: a scheduled patch scan, for example. It is not a free
path into Tactical. Core holds a fixed table, ``SYSTEM_FUNCTIONS``, of the few Tactical functions it will reach. A module cannot name a
callable of its own.

The five AD-13 conditions and how each is met (see docs/system-actions.md for the long form)
    1. Typed actions only. ``register_system_action`` takes a key of ``SYSTEM_FUNCTIONS``, never a dotted path. The action id must also be
       listed in the module's signed manifest under ``system_actions``.
    2. Permission and scope are checked where Tactical checks them. At every run Core re-reads the owner (active, not an installer user),
       the Tactical role flags and the role's client and site scope. A native scheduler manager gets no scope bypass for a Tactical
       function. One agent outside the owner's scope refuses the whole call; nothing is narrowed silently.
    3. Run as the owner. The audit row names the owner as the actor with ``requested_by`` scheduler. Tactical's own tasks for the first
       two rows take no username, so only Core's audit row names the owner.
    4. No HTTP and no keys. Core imports the Tactical task named in the table and calls ``.delay()``, the way Tactical's bulk view does.
       No loopback request, no API key, no service account, no model write.
    5. Only the owning core module registers. The table names the owner; the honoured premium replacement (AD-20) may register too.

At-most-once. A mark is committed on the run row before the audit row, and the audit row before the send. A retry that finds a mark never
sends again; a mark stuck at ``claiming`` fails the run as outcome-unknown. The cost is a possibly missed scan, never a double install.

Honest limits: the owner re-check reads Tactical's role through Core's own helpers; modules share the Core process, so code that reaches
into Core's private state is outside what this stops (the same limit as docs/caller-identity.md).
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass
from importlib import import_module
from types import MappingProxyType

from django.db import transaction
from django.utils import timezone

from . import scheduler_run_context as _run_context
from .caller_identity import calling_module_for_core_provider
from .scheduler import SchedulerPermanentError, SchedulerTransientError

logger = logging.getLogger("tec_tac.system_actions")

CAPABILITY_ID = "core.system_actions"
CAPABILITY_VERSION = "1.0.0"
MAX_AGENTS = 2000  # a Core constant: refused above, never truncated
MAX_PERMISSIONS = 8
MAX_MARKS_PER_RUN = 20
LABEL_MAX = 100
SCOPE_KIND_AGENTS = "agents"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\.[a-z0-9][a-z0-9_-]{0,63}$")
_FLAG_RE = re.compile(r"^can_[a-z0-9_]+$")
_PARAM_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
UNMATCHED_WINDOW_SECONDS = 300.0

STATE_CLAIMING = "claiming"
STATE_SENT = "sent"
STATE_ABORTED = "aborted"

_RUNNING = "running"  # TecTacScheduleRun.Status.RUNNING (a text choice)
_SKIPPED = "skipped"
_FAILED = "failed"

QUEUED_TEXT = "Queued in Tactical; the result shows in each endpoint's update list."


class SystemActionRegistrationError(ValueError):
    """``register_system_action`` refused the registration. A module wraps the call, logs and goes on, so Tactical always starts."""


class SystemActionRefused(SchedulerPermanentError):
    """A run was refused. The run ends ``skipped`` with error type SystemActionRefused. ``reason`` is a short code; the message is plain
    text and names no agent and no id."""

    def __init__(self, message, *, reason="refused"):
        super().__init__(message)
        self.reason = reason


class SystemActionOutcomeUnknown(SchedulerPermanentError):
    """A mark shows a send may already have happened (or the send itself failed). Core never sends again; the run fails."""

    reason = "outcome_unknown"


class _NotHonoured(Exception):
    """Internal: the registering module replaces the owner but is not the honoured replacement right now."""


# ------------------------------------------------------------------------------------------------ the fixed function table
@dataclass(frozen=True)
class SystemFunction:
    """One Tactical function Core will run for a system action. A new row is a Core release (additive), like ``ROUTE_OWNERS``."""

    key: str
    module_path: str  # the Tactical module Core imports lazily at run time
    function_name: str  # a Celery task there, called with ``.delay``
    owner_module: str  # the core module that owns this Tactical group (a module id rule, like ROUTE_OWNERS)
    min_flags: tuple  # Tactical role flags the owner and the registration must hold, every one
    accepts: str  # "agent_pks": one positional list of Tactical agent numbers
    takes_username: bool
    reapproves_by_policy: bool  # the task re-approves updates by patch policy (reference agents/models.py approve_updates)
    result_text: str


SYSTEM_FUNCTIONS = MappingProxyType({
    # reference/tacticalrmm v1.5.2: winupdate/tasks.py bulk_check_for_updates_task(pks: list[int]); agents/views.py bulk() mode patch, patchMode scan.
    "winupdate.scan": SystemFunction(
        key="winupdate.scan", module_path="winupdate.tasks", function_name="bulk_check_for_updates_task", owner_module="patching",
        min_flags=("can_manage_winupdates", "can_run_bulk"), accepts="agent_pks", takes_username=False, reapproves_by_policy=False,
        result_text=QUEUED_TEXT,
    ),
    # winupdate/tasks.py bulk_install_updates_task(pks: list[int]) calls agent.approve_updates() first, which re-approves an update an
    # administrator or Advanced Patch Management set to Ignore. Windows Patching only (see CQ173 and R-36).
    "winupdate.install": SystemFunction(
        key="winupdate.install", module_path="winupdate.tasks", function_name="bulk_install_updates_task", owner_module="patching",
        min_flags=("can_manage_winupdates", "can_run_bulk"), accepts="agent_pks", takes_username=False, reapproves_by_policy=True,
        result_text=QUEUED_TEXT,
    ),
})


# ------------------------------------------------------------------------------------------------ the registry (memory only)
@dataclass(frozen=True)
class SystemActionDefinition:
    id: str
    module_id: str
    label: str
    function: str  # a key of SYSTEM_FUNCTIONS
    permissions: tuple
    scope_kind: str
    dangerous: bool
    username_param: str | None
    via_replacement: bool  # registered by the premium module that honourably replaces the owner


_ACTIONS: dict[str, SystemActionDefinition] = {}
_LOCK = threading.RLock()


# The few places this module reads Core. Each is one small function so a test can replace it without Django.
def _plugins() -> tuple:
    from . import registry

    return tuple(registry.discover_plugins())


def _enabled_now(module_id: str) -> bool:
    from . import module_state

    return bool(module_state.is_enabled(module_id))  # read fresh each time, never cached


def _honoured(module_id: str):
    from . import module_replacement

    return module_replacement.honoured_replacement(module_id)


def _effective_category(declared) -> str:
    from . import module_category

    return module_category.effective_category(declared)


def _check_flag(flag) -> str:
    from .rbac import _validate_tactical_flag

    return _validate_tactical_flag(flag)


def _load_run(run_id):
    from .models import TecTacScheduleRun

    return TecTacScheduleRun.objects.filter(pk=run_id).first()


def _locked_run(run_id):
    from .models import TecTacScheduleRun

    return TecTacScheduleRun.objects.select_for_update().get(pk=run_id)


def _agents_in_scope(user, ids) -> bool:
    from . import resources_adapter as adapter

    return bool(adapter.agent_pks_in_role_scope(user=user, pks=ids))


def _import_function(entry: SystemFunction):
    """The Tactical task named by the table row, or None. An ImportError or a missing function fails closed: a Tactical upgrade can never
    make Core call something else."""
    try:
        function = getattr(import_module(entry.module_path), entry.function_name)
    except Exception:
        logger.warning("Tactical function %s.%s is not available.", entry.module_path, entry.function_name, exc_info=True)
        return None
    return function if callable(function) and callable(getattr(function, "delay", None)) else None


def _audit():
    from . import audit

    return audit


# ------------------------------------------------------------------------------------------------ registration
def _clean_permissions(permissions) -> tuple:
    if isinstance(permissions, (str, bytes)) or not isinstance(permissions, (list, tuple, set, frozenset)):
        raise SystemActionRegistrationError("permissions must be a list of Tactical role flags.")
    flags = []
    for flag in permissions:
        if not isinstance(flag, str) or not _FLAG_RE.fullmatch(flag):
            raise SystemActionRegistrationError("every permission must be a Tactical role flag such as can_manage_winupdates.")
        try:
            _check_flag(flag)
        except ValueError as exc:
            raise SystemActionRegistrationError(str(exc)) from None
        flags.append(flag)
    flags = tuple(sorted(set(flags)))
    if len(flags) > MAX_PERMISSIONS:
        raise SystemActionRegistrationError(f"permissions may list at most {MAX_PERMISSIONS} flags.")
    return flags


def _registered_plugin(module_id: str):
    try:
        plugins = _plugins()
    except Exception:
        logger.warning("System action registration: the installed modules could not be read.", exc_info=True)
        raise SystemActionRegistrationError("Core could not read the installed modules to verify the owner.") from None
    plugin = next((p for p in plugins if p.plugin_id == module_id), None)
    if plugin is None or plugin.plugin_type != "extension" or getattr(plugin, "legacy", False):
        raise SystemActionRegistrationError("module_id is not an installed extension module.")
    return plugin


def _build_definition(id, module_id, label, function, permissions, scope_kind, dangerous, username_param) -> SystemActionDefinition:
    action_id = id if isinstance(id, str) else ""  # exact text: nothing is trimmed into a valid id
    module = module_id if isinstance(module_id, str) else ""
    entry = SYSTEM_FUNCTIONS.get(function) if isinstance(function, str) else None
    if entry is None:
        raise SystemActionRegistrationError("function must be one of the keys of Core's fixed table of Tactical functions. A module cannot name a callable of its own.")
    if not module:
        raise SystemActionRegistrationError("module_id is required.")
    if not _ID_RE.fullmatch(action_id) or not action_id.startswith(module + "."):
        raise SystemActionRegistrationError("id must be '<module_id>.<name>' in lowercase letters, digits, - and _.")
    if not isinstance(label, str) or not label.strip() or len(label) > LABEL_MAX or not label.isprintable():
        raise SystemActionRegistrationError(f"label must be printable text of 1 to {LABEL_MAX} characters.")
    if scope_kind != SCOPE_KIND_AGENTS:
        raise SystemActionRegistrationError("scope_kind must be 'agents'.")
    if not isinstance(dangerous, bool):
        raise SystemActionRegistrationError("dangerous must be true or false.")
    if username_param is not None:
        if not isinstance(username_param, str) or not _PARAM_RE.fullmatch(username_param):
            raise SystemActionRegistrationError("username_param must be a parameter name.")
        if not entry.takes_username:
            raise SystemActionRegistrationError("this Tactical function takes no username, so username_param is not allowed.")
    flags = _clean_permissions(permissions)
    missing = [flag for flag in entry.min_flags if flag not in flags]
    if missing:
        raise SystemActionRegistrationError(
            "permissions must include every minimum flag of this Tactical function (" + ", ".join(entry.min_flags) + "). A module may add flags, never remove one."
        )
    plugin = _registered_plugin(module)
    category = _effective_category(getattr(plugin, "category", ""))
    via_replacement = False
    if module != entry.owner_module:
        if _honoured(module) == entry.owner_module:
            via_replacement = True
        elif str(getattr(plugin, "replaces", "") or "") == entry.owner_module:
            raise _NotHonoured(f"module {module!r} replaces {entry.owner_module!r}, but the replacement is not honoured right now")
        else:
            raise SystemActionRegistrationError(f"only module {entry.owner_module!r}, or the module that honourably replaces it, may register {function!r}.")
    elif category != "core":
        raise SystemActionRegistrationError(f"module {module!r} is not a core module (its category is {category}).")
    if action_id not in tuple(getattr(plugin, "system_actions", ()) or ()):
        raise SystemActionRegistrationError("the action id is not listed in the module's signed manifest key 'system_actions'.")
    try:
        enabled = _enabled_now(module)
    except Exception:
        raise SystemActionRegistrationError("Core could not read whether the module is enabled.") from None
    if not enabled:
        raise SystemActionRegistrationError("module_id is not enabled.")
    if via_replacement and entry.reapproves_by_policy:
        raise SystemActionRegistrationError(
            f"{function!r} re-approves updates by patch policy, so it is not allowed for a replacement module while R-36 is open. Windows Patching may register it."
        )
    return SystemActionDefinition(action_id, module, label.strip(), function, flags, SCOPE_KIND_AGENTS, dangerous, username_param, via_replacement)


def register_system_action(id, module_id, label, function, permissions, scope_kind="agents", dangerous=False, username_param=None):
    """Register one system action. Call it from ``AppConfig.ready()``; it touches memory only and never raises out of ``ready()``'s own
    guard for a replacement that is not honoured (that is logged, nothing is registered, and ``None`` comes back).

    ``function`` is a key of Core's table (``winupdate.scan``, ``winupdate.install``); a dotted path, an unknown key or anything else is
    refused. Every other refusal raises ``SystemActionRegistrationError`` (a ValueError): the module wraps the call, logs and goes on.
    Registering the identical definition again returns the same one; a different definition under the same id is refused."""
    try:
        definition = _build_definition(id, module_id, label, function, permissions, scope_kind, dangerous, username_param)
    except _NotHonoured as exc:
        logger.warning("System action %r is not registered: %s.", id, exc)
        return None
    except SystemActionRegistrationError as exc:
        logger.warning("System action %r is refused: %s", id, exc)
        raise
    with _LOCK:
        previous = _ACTIONS.get(definition.id)
        if previous is not None:
            if previous == definition:
                return previous
            raise SystemActionRegistrationError(f"system action {definition.id!r} is already registered with a different definition.")
        _ACTIONS[definition.id] = definition
    return definition


def _describe(definition: SystemActionDefinition) -> dict:
    entry = SYSTEM_FUNCTIONS.get(definition.function)
    return {
        "id": definition.id, "module_id": definition.module_id, "label": definition.label, "function": definition.function,
        "permissions": list(definition.permissions), "scope_kind": definition.scope_kind, "dangerous": definition.dangerous,
        "username_param": definition.username_param, "via_replacement": definition.via_replacement,
        "owner_module": entry.owner_module if entry else None, "min_flags": list(entry.min_flags) if entry else [],
        "reapproves_by_policy": bool(entry.reapproves_by_policy) if entry else None,
    }


def registered_system_actions() -> list[dict]:
    """The actions registered in this process, as plain rows (no callable)."""
    with _LOCK:
        rows = sorted(_ACTIONS.values(), key=lambda d: (d.module_id, d.id))
    return [_describe(d) for d in rows]


def get_system_action(action_id) -> dict | None:
    with _LOCK:
        definition = _ACTIONS.get(action_id) if isinstance(action_id, str) else None
    return _describe(definition) if definition else None


# ------------------------------------------------------------------------------------------------ refusals
REASONS = {
    "context_invalid": "This is not a scheduler run context that Core issued for a run that is still going.",
    "owner_refused": "The person who owns this schedule may no longer run it.",
    "no_owner": "This run has no person behind it. A system action needs a user-owned schedule or a one-off run.",
    "caller_unverified": "Core could not tell which module is calling.",
    "wrong_module": "Only the module that owns this run and this action can run it.",
    "unknown_action": "This system action is not registered.",
    "module_disabled": "The module that owns this action is not enabled.",
    "replacement_not_honoured": "The module that registered this action no longer replaces the core module right now.",
    "function_unavailable": "Core cannot reach the Tactical function this action needs.",
    "owner_inactive": "The person who owns this run is no longer an active, interactive user.",
    "permission_lost": "The person who owns this run no longer holds the Tactical permission this action needs.",
    "bad_parameters": "This system action takes no parameters.",
    "bad_agents": "The endpoint list is not a list of whole endpoint numbers.",
    "agent_count": f"A system action runs on 1 to {MAX_AGENTS} endpoints.",
    "out_of_scope": "At least one endpoint is outside the owner's Tactical scope, so nothing was run.",
    "reapproves_by_policy": "This action would re-approve updates by patch policy, which is not allowed for a replacement module.",
    "mark_limit": "This run has already sent the most system actions it may send.",
}

_UNMATCHED: dict[tuple[str, str], float] = {}
_clock = time.monotonic  # a test replaces it


def _unmatched_due(reason: str, caller: str) -> bool:
    now = _clock()
    key = (reason, caller)
    last = _UNMATCHED.get(key)
    if last is not None and 0 <= now - last < UNMATCHED_WINDOW_SECONDS:
        return False
    if len(_UNMATCHED) >= 128:
        _UNMATCHED.clear()
    _UNMATCHED[key] = now
    return True


def _safe_action_id(value) -> str | None:
    return value if isinstance(value, str) and _ID_RE.fullmatch(value) else None


def _deny_row(reason: str, text: str, *, owner, module_id, run_id, action_id) -> None:
    """ONE deny row: reason code, the owner as actor (a Core service actor when there is none), requested_by scheduler. No agent, no id list."""
    try:
        audit = _audit()
        actor = owner if owner is not None else audit.service_audit_actor(module_id="core", service="scheduler", identity="system-action")
        metadata = {"reason": reason, "requested_by": "scheduler"}
        if module_id:
            metadata["owner_module"] = str(module_id)[:100]
        if run_id:
            metadata["run_id"] = str(run_id)
        audit.record(
            actor=actor, module_id="core", action="deny", object_type="system_action", object_id=_safe_action_id(action_id),
            message=f"A scheduled system action was refused: {text}", metadata=metadata,
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a refused system action could not be written")


def _end_run(run_id, status: str, error_type: str, text: str) -> None:
    """End the run ``skipped`` or ``failed`` under a row lock, only if it is still running. Never raises."""
    try:
        with transaction.atomic():
            current = _locked_run(run_id)
            if str(current.status) != _RUNNING:
                return
            current.status = status
            current.error = text
            current.error_type = error_type
            current.finished_at = timezone.now()
            current.save(update_fields=["status", "error", "error_type", "finished_at"])
    except Exception:
        logger.exception("A refused system action run could not be ended")


# A caller Core cannot place, or one that is not the run's module, gets a refusal and a deny row but does NOT end the run: the context may
# have been handed to code that does not own the run, and such code must not be able to end another module's run. The run's own handler
# fails with the refusal it receives.
_KEEP_RUN_REASONS = frozenset({"caller_unverified", "wrong_module"})


def _refuse(reason: str, *, run_id=None, owner=None, module_id=None, action_id=None, caller: str = ""):
    text = REASONS.get(reason, "The system action was refused.")
    if run_id is not None:
        if reason not in _KEEP_RUN_REASONS:
            _end_run(run_id, _SKIPPED, "SystemActionRefused", text)
        _deny_row(reason, text, owner=owner, module_id=module_id, run_id=run_id, action_id=action_id)
    elif _unmatched_due(reason, caller):
        _deny_row(reason, text, owner=None, module_id=None, run_id=None, action_id=action_id)
    raise SystemActionRefused(text, reason=reason)


# ------------------------------------------------------------------------------------------------ running
def _agent_ids(agent_ids):
    """The distinct, sorted endpoint numbers, or a reason code. The count is judged before anything is looked up."""
    if isinstance(agent_ids, (str, bytes, dict)) or not isinstance(agent_ids, (list, tuple, set, frozenset)):
        return None, "bad_agents"
    if len(agent_ids) == 0 or len(agent_ids) > MAX_AGENTS:
        return None, "agent_count"
    ids = set()
    for value in agent_ids:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**63:
            return None, "bad_agents"
        ids.add(value)
    return sorted(ids), None


def _digest(run_id, action_id: str, ids) -> str:
    raw = f"{run_id}|{action_id}|" + ",".join(str(i) for i in ids)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()[:32]


def _claim_mark(run_id, action_id: str, digest: str, agents: int):
    """Write the at-most-once mark under a row lock and commit. Returns ``(state, mark)``: claimed, sent, unknown, gone or full."""
    with transaction.atomic():
        current = _locked_run(run_id)
        if str(current.status) != _RUNNING:
            return "gone", None
        marks = [dict(m) for m in (current.system_action_marks or []) if isinstance(m, dict)]
        for mark in marks:
            if mark.get("action_id") == action_id and mark.get("targets_digest") == digest:
                if mark.get("state") == STATE_SENT:
                    return "sent", mark
                if mark.get("state") != STATE_ABORTED:
                    return "unknown", mark
                mark["state"] = STATE_CLAIMING  # an earlier attempt aborted before anything was sent: claim again
                current.system_action_marks = marks
                current.save(update_fields=["system_action_marks"])
                return "claimed", mark
        if len(marks) >= MAX_MARKS_PER_RUN:
            return "full", None
        mark = {"action_id": action_id, "targets_digest": digest, "state": STATE_CLAIMING, "agents": agents}
        marks.append(mark)
        current.system_action_marks = marks
        current.save(update_fields=["system_action_marks"])
        return "claimed", mark


def _set_mark(run_id, action_id: str, digest: str, state: str, task_id: str = "") -> bool:
    """Move one mark to ``state`` under a row lock. Returns False when it could not be written. Never raises."""
    try:
        with transaction.atomic():
            current = _locked_run(run_id)
            marks = [dict(m) for m in (current.system_action_marks or []) if isinstance(m, dict)]
            for mark in marks:
                if mark.get("action_id") == action_id and mark.get("targets_digest") == digest:
                    mark["state"] = state
                    if task_id:
                        mark["task_id"] = task_id
                    current.system_action_marks = marks
                    current.save(update_fields=["system_action_marks"])
                    return True
        return False
    except Exception:
        logger.exception("A system action mark could not be updated")
        return False


def _queued_result(entry: SystemFunction, agents: int, **extra) -> dict:
    return {"outcome": "queued", "agents": agents, "message": entry.result_text, **extra}


def _unknown(run_id, owner, definition, action_id: str, module_id: str):
    text = "A system action may already have been sent for this run, so Core did not send it again. Check the endpoints before running it again."
    _end_run(run_id, _FAILED, "OutcomeUnknown", text)
    try:
        _audit().record(
            actor=owner, module_id="core", action="custom:outcome-unknown", object_type="system_action", object_id=_safe_action_id(action_id),
            message=f"A scheduled system action has an unknown outcome: {text}",
            metadata={"requested_by": "scheduler", "run_id": str(run_id), "owner_module": module_id, "reason": "outcome_unknown"},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a system action with an unknown outcome could not be written")
    raise SystemActionOutcomeUnknown(text)


def run_system_action(context, *, action_id, agent_ids, parameters=None) -> dict:
    """Run a registered system action for the owner of the Scheduler run ``context`` belongs to (core.system_actions 1.0.0).

    Call it from the module's own Scheduler handler, passing the context object the handler received. Returns
    ``{"outcome": "queued", "agents": N, "message": ...}``: the work is queued in Tactical, not done. Every refusal ends the run
    ``skipped`` (error type ``SystemActionRefused``), writes one ``deny`` audit row and raises ``SystemActionRefused`` (a
    ``SchedulerPermanentError``, so the worker does not retry). See docs/system-actions.md for the checks and their reason codes."""
    identity = calling_module_for_core_provider(provider_file=__file__)  # the module whose own code called this function, or None
    return _run(context, identity, action_id, agent_ids, parameters)


def _run(context, identity, action_id, agent_ids, parameters) -> dict:
    caller = identity.module_id if identity is not None else ""
    shown_id = action_id if isinstance(action_id, str) else None
    # (1) a context Core issued, a run still going and a person behind it
    run_id = _run_context._issued_run_id(context)
    run = None
    try:
        run = _load_run(run_id) if run_id is not None else None
    except Exception:
        logger.warning("The run of a system action could not be read.", exc_info=True)
    if run is None:
        _refuse("context_invalid", action_id=shown_id, caller=caller)
    module_id = str(run.module_id or "")
    try:
        verified = _run_context.verify_run_context(context, expected_module_id=module_id, expected_action_id=str(run.action_id or ""), require_owner=False)
    except Exception as exc:
        reason = "owner_refused" if str(exc) == _run_context._OWNER_REFUSED else "context_invalid"
        _refuse(reason, run_id=run.id, module_id=module_id, action_id=shown_id, caller=caller)
    # the person behind the schedule (as the schedule row holds them) is the actor of any refusal that follows, even before the fresh read
    common = {"run_id": run.id, "module_id": module_id, "action_id": shown_id, "caller": caller, "owner": verified.user}
    if verified.user is None:
        _refuse("no_owner", **common)
    # (2) the verified caller is the run's module
    if identity is None:
        _refuse("caller_unverified", **common)
    if identity.module_id != verified.module_id:
        _refuse("wrong_module", **common)
    # (3) the action is registered, its owner is enabled now, a replacement is honoured now
    with _LOCK:
        definition = _ACTIONS.get(action_id) if isinstance(action_id, str) else None
    if definition is None:
        _refuse("unknown_action", **common)
    if definition.module_id != identity.module_id:
        _refuse("wrong_module", **common)
    entry = SYSTEM_FUNCTIONS.get(definition.function)
    if entry is None:
        _refuse("function_unavailable", **common)
    try:
        enabled = _enabled_now(definition.module_id)
    except Exception:
        enabled = False
    if not enabled:
        _refuse("module_disabled", **common)
    if definition.via_replacement:
        try:
            honoured = _honoured(definition.module_id) == entry.owner_module
        except Exception:
            honoured = False
        if not honoured:
            _refuse("replacement_not_honoured", **common)
    # (4) the owner, read again from the database
    try:
        owner = verified._owner_now()
    except Exception:
        _refuse("owner_inactive", **common)
    common["owner"] = owner
    if bool(getattr(owner, "is_installer_user", False)):
        _refuse("owner_inactive", **common)
    for flag in sorted(set(entry.min_flags) | set(definition.permissions)):
        if not verified.has_tactical_permission(flag):
            _refuse("permission_lost", **common)
    if parameters not in (None, {}):
        _refuse("bad_parameters", **common)
    # (6) the count, judged before any lookup, then (5) the scope of every endpoint
    ids, reason = _agent_ids(agent_ids)
    if reason:
        _refuse(reason, **common)
    try:
        in_scope = _agents_in_scope(owner, ids)
    except Exception:
        logger.warning("The scope of a system action could not be checked; the run is refused.", exc_info=True)
        in_scope = False
    if not in_scope:  # a native scheduler manager has no bypass here: Tactical's own role scope decides, and one miss refuses all
        _refuse("out_of_scope", **common)
    # (7) an install that re-approves by policy is not run for a replacement
    if entry.reapproves_by_policy and definition.via_replacement:
        _refuse("reapproves_by_policy", **common)
    function = _import_function(entry)
    if function is None:
        _refuse("function_unavailable", **common)

    # at-most-once: the mark, then the strict audit row, then the send
    digest = _digest(run.id, definition.id, ids)
    state, _mark = _claim_mark(run.id, definition.id, digest, len(ids))
    if state == "gone":
        raise SchedulerPermanentError("The run is no longer active, so nothing was sent.")
    if state == "full":
        _refuse("mark_limit", **common)
    if state == "sent":
        return _queued_result(entry, len(ids), duplicate=True)
    if state == "unknown":
        _unknown(run.id, owner, definition, definition.id, module_id)
    try:
        _audit().record(
            actor=owner, module_id="core", action="run", object_type="system_action", object_id=definition.id,
            message=f"A scheduled system action is being sent to Tactical for {len(ids)} endpoint(s).",
            metadata={
                "requested_by": "scheduler", "run_id": str(run.id), "schedule_id": str(verified.schedule_id), "owner_module": definition.module_id,
                "function": definition.function, "agent_count": len(ids), "targets_digest": digest,
            },
            strict=True,
        )
    except Exception:
        logger.exception("The audit row of a system action could not be written; nothing is sent.")
        _set_mark(run.id, definition.id, digest, STATE_ABORTED)
        raise SchedulerTransientError("The audit row could not be written, so nothing was sent.") from None
    try:
        sent = function.delay(list(ids))  # exactly the way Tactical's own bulk view starts the task
    except Exception:
        logger.exception("Tactical's task could not be started; Core never sends again for this run.")
        _unknown(run.id, owner, definition, definition.id, module_id)
    task_id = str(getattr(sent, "id", "") or "")[:80]
    if not _set_mark(run.id, definition.id, digest, STATE_SENT, task_id):
        logger.error("The system action was sent but its mark could not be set to 'sent'; a retry would fail as outcome-unknown.")
    return _queued_result(entry, len(ids))


# ------------------------------------------------------------------------------------------------ the capability
class _SystemActionsProvider:
    """The ``core.system_actions`` 1.0.0 provider: list_actions, get_action, run."""

    def list_actions(self) -> list[dict]:
        return registered_system_actions()

    def get_action(self, action_id):
        return get_system_action(action_id)

    def run(self, context, *, action_id, agent_ids, parameters=None) -> dict:
        return run_system_action(context, action_id=action_id, agent_ids=agent_ids, parameters=parameters)


_PROVIDER = _SystemActionsProvider()


def system_actions_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["list_actions", "get_action", "run"],
        "python": (
            "tec_tac.system_actions.register_system_action(id, module_id, label, function, permissions, scope_kind='agents', dangerous=False, "
            "username_param=None) -> SystemActionDefinition | None; tec_tac.system_actions.run_system_action(context, *, action_id, agent_ids, "
            "parameters=None) -> {outcome: 'queued', agents, message}"
        ),
        "functions": {
            key: {
                "tactical": f"{row.module_path}.{row.function_name}", "owner_module": row.owner_module, "min_flags": list(row.min_flags),
                "takes_username": row.takes_username, "reapproves_by_policy": row.reapproves_by_policy,
            }
            for key, row in SYSTEM_FUNCTIONS.items()
        },
        "manifest_key": "system_actions: list of '<module id>.<name>' ids, at most 20 (extensions only)",
        "max_agents": MAX_AGENTS,
        "refusal_reasons": sorted(REASONS),
        "http": None,
        "delivery": "at most once",
        "audit_actions": ["run (strict, before the send)", "deny (one per refusal)", "custom:outcome-unknown"],
        "requires_framework": ">=1.17.61",
    }


def register_core_system_actions_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Typed Tactical functions that Core runs unattended for a named owner, with the owner and scope checked at every run.",
        operations=("list_actions", "get_action", "run"),
        metadata=system_actions_contract_metadata(),
    )


def _clear_for_tests() -> None:
    with _LOCK:
        _ACTIONS.clear()
    _UNMATCHED.clear()
