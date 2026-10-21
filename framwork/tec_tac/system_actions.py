"""System actions: typed Tactical work that Core runs unattended for a named owner (core.system_actions 1.4.0, Core 1.17.74; first built 1.17.61, R-20, AD-13).

A system action is a Tactical function that Core may run when nobody is signed in: a scheduled patch scan, for example. It is not a free
path into Tactical. Core holds a fixed table, ``SYSTEM_FUNCTIONS``, of the few Tactical functions it will reach. A module cannot name a
callable of its own.

The five AD-13 conditions and how each is met (see docs/system-actions.md for the long form)
    1. Typed actions only. ``register_system_action`` takes a key of ``SYSTEM_FUNCTIONS``, never a dotted path. The action id must also be
       listed in the module's signed manifest under ``system_actions``.
    2. Permission and scope are checked where Tactical checks them. A run a person starts (a manual run or a one-off run) re-reads the
       owner (active, not an installer user), the Tactical role flags and the role's client and site scope at that run. A native
       scheduler manager gets no scope bypass for a Tactical function. One agent outside the owner's scope refuses the whole call;
       nothing is narrowed silently. Johan signed the amended condition 2 on 20 October 2026 (CQ179, CQ184 b, CQ186, CQ189); it is recorded in the authority
       documents and ``scheduler.AD13_CONDITION_2_AMENDED`` is True since Core 1.17.65: a SCHEDULED run of a user-owned schedule skips only that re-read. The person's right was checked when they created or edited
       the schedule, and Core stores and audits who that was. The cost is plain: a person who is demoted or deactivated later keeps
       their schedules running until someone removes or edits them, as in Tactical.
    3. Run as the owner. The audit row names the creator as the actor with ``requested_by`` scheduler (a Core service actor, with the
       stored name in the metadata, when the user row is gone). Tactical's own tasks for the first two rows take no username, so only
       Core's audit row names the person.
    4. No HTTP and no keys. Core imports the Tactical task named in the table and calls ``.delay()``, the way Tactical's bulk view does.
       No loopback request, no API key, no service account, no model write.
    5. Only the owning core module registers. The table names the owner; the honoured premium replacement (AD-20) may register too.

At-most-once. A mark is committed on the run row before the audit row, and the audit row before the send. A retry that finds a mark never
sends again; a mark stuck at ``claiming`` fails the run as outcome-unknown. The cost is a possibly missed scan, never a double install.

Groups (1.17.66, Johan CQ178). More than 2000 endpoints are not refused: they are split. The whole set is judged first (shape, count against
the ceiling, scope, targets, parameters, declared, enabled, honoured); one failure refuses the whole call and nothing is sent. The sorted ids
are cut into groups of at most 2000. Every group has its own mark, its own strict audit row written before its own send, and is sent at most
once. A group that is already sent is skipped on a retry. A group whose mark is stuck or whose send failed ends the run failed as
outcome-unknown, is never sent again, and every later group stays not started.

The plan (1.17.67). The groups are fixed on the first attempt of a call and stored in a plan mark on the run (kind ``plan``: the endpoint
numbers as ranges, and the digest of every group). A retry cuts its groups from that plan, never from the live endpoint list. A call is
identified by its full sorted id set. A retry whose list differs but overlaps a plan, once any group of that plan was claimed, sent or
left unknown, ends the run failed as outcome-unknown and sends nothing: an endpoint is never sent twice, a scan may be missed. When nothing was
sent yet (every group mark of the plan is absent or aborted) the plan is replaced and the call goes on. A second call with no endpoint in
common with a plan is a new call and is planned on its own.

Honest limits: the owner re-check reads Tactical's role through Core's own helpers; modules share the Core process, so code that reaches
into Core's private state is outside what this stops (the same limit as docs/caller-identity.md).

1.17.68 (additive, capability 1.2.0). (1) A module-owned target type that its module registered a resolver for now reads as endpoints
(``scheduler_target_resolvers``), so a run on such a schedule is no longer refused as ``targets_unresolved``. (2) ``register_system_action`` takes
``delegable_to``: the modules that may start this action for someone else under a delegation grant. (3) Five functions let the owner module of
a grant (Maintenance) and the provider (Advanced Patch Management) start a scheduled install without a person present: ``describe_delegation``,
``register_delegation_grant``, ``remove_delegation_grant``, ``issue_delegation_ticket`` and ``start_delegated_run``. They are thin wrappers that
verify the calling module here, in this file, then hand over to ``delegation.py``. ``run_system_action`` keeps its signature and its
``wrong_module`` rule. (4) While Core's patch lockdown is active and its guard is installed in the process, Tactical's own approve is inert, so an
install by the honoured replacement no longer carries the re-approve warning.

1.17.70 (additive, capability 1.3.0, CQ203, AD-45). A row of the table has a ``kind``. Every row until now is a ``task`` (a Tactical Celery task that Core
starts with ``.delay``). The new kind is ``write``: Core itself writes one fixed column of Tactical's own table, in Core's process, through Tactical's own
serializer. The first and only write row is ``winupdate.set_action`` (the approve, ignore or do-nothing decision of one Windows update). It is
``replacement_only``: Windows Patching never registers it (it uses a person's own request); only the premium module that is the HONOURED
replacement of ``patching`` right now may. A module names only the key. ``run_system_write`` runs it with the same checks in the same order as
``run_system_action``, then reads each update's endpoint itself and judges the endpoint set like ``agent_ids``. See ``system_writes.py`` and
docs/system-actions.md.

1.17.74 (additive, capability 1.4.0, Q-APM21 b). ``resolve_delegated_targets`` (delegation.py) tells a provider which endpoints a delegation ticket covers.
There is no command kind: a reboot row waits for Johan's signed decision (CQ213, CQ215). See docs/system-actions.md.
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
CAPABILITY_VERSION = "1.4.0"
MAX_AGENTS_PER_GROUP = 2000  # Johan, CQ178: more than this splits into groups of at most this many
MAX_GROUPS = 20  # the ceiling of one run (assumption CQ195, asked): 20 groups
MAX_AGENTS = MAX_AGENTS_PER_GROUP * MAX_GROUPS  # a Core constant: refused above, never truncated
MAX_PERMISSIONS = 8
MAX_MARKS_PER_RUN = 105  # one mark per group plus one plan mark per call; room for five full calls of 20 groups (1.17.67)
KIND_PLAN = "plan"  # a mark with no ``kind`` is a group mark
KIND_TASK = "task"  # 1.17.70: a row of the table is a Tactical Celery task that Core starts ...
KIND_WRITE = "write"  # ... or one fixed column of a Tactical table that Core writes itself, through Tactical's own serializer
WRITE_ACTIONS = ("approve", "ignore", "nothing")  # what a Windows update decision may be set to ('inherit' has no meaning on one update row; Tactical v1.5.2)
MAX_WRITE_ITEMS = MAX_AGENTS  # one call writes at most this many decisions (2000 per group, 20 groups); refused above, never truncated
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
REAPPROVE_WARNING = "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere."
PARAMETERS_KEY = "system_action_parameters"  # the key of a schedule's (and a run's) parameters that holds what the person confirmed
MAX_LIST_ITEMS = 50
MAX_ITEM_CHARS = 1000
DEFAULT_SCRIPT_TIMEOUT = 90  # Tactical's own default for a script run


def _no_parameters(values) -> dict:
    if values:
        raise ValueError("This system action takes no parameters.")
    return {}


def _agents_only_call(ids, cleaned, username):
    return (list(ids),), {}  # exactly the way Tactical's bulk view starts these tasks: one positional list


def _no_audit_extra(cleaned) -> dict:
    return {}


def _bounded_text_list(values, name):
    if values is None:
        return []
    if isinstance(values, (str, bytes, dict)) or not isinstance(values, (list, tuple)) or len(values) > MAX_LIST_ITEMS:
        raise ValueError(f"{name} must be a list of at most {MAX_LIST_ITEMS} texts.")
    out = []
    for item in values:
        if not isinstance(item, str) or len(item) > MAX_ITEM_CHARS or any(ord(ch) < 32 and ch != "\t" for ch in item):
            raise ValueError(f"every entry of {name} must be text of at most {MAX_ITEM_CHARS} characters.")
        out.append(item)
    return out


def _script_parameters(values) -> dict:
    """What a confirmed script run may carry. Anything else is refused; nothing is repaired or dropped silently."""
    if not isinstance(values, dict):
        raise ValueError("parameters must be an object.")
    allowed = {"script_pk", "args", "env_vars", "timeout", "run_as_user", "collector_all_output", "save_to_agent_note"}
    if set(values) - allowed:
        raise ValueError("a script run takes only script_pk, args, env_vars, timeout, run_as_user, collector_all_output and save_to_agent_note.")
    script_pk = values.get("script_pk")
    if isinstance(script_pk, bool) or not isinstance(script_pk, int) or not 0 < script_pk < 2**63:
        raise ValueError("script_pk must be a whole number.")
    timeout = values.get("timeout", DEFAULT_SCRIPT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 86400:
        raise ValueError("timeout must be a whole number of seconds from 1 to 86400.")
    flags = {}
    for flag in ("run_as_user", "collector_all_output", "save_to_agent_note"):
        flags[flag] = values.get(flag, False)
        if not isinstance(flags[flag], bool):
            raise ValueError(f"{flag} must be true or false.")
    return {
        "script_pk": script_pk, "args": _bounded_text_list(values.get("args"), "args"), "env_vars": _bounded_text_list(values.get("env_vars"), "env_vars"),
        "timeout": timeout, **flags,
    }


def _script_call(ids, cleaned, username):
    # scripts/tasks.py bulk_script_task takes keywords only. custom_field_pk is always None: a scheduled run saves no custom field.
    return (), {
        "script_pk": cleaned["script_pk"], "agent_pks": list(ids), "args": list(cleaned["args"]), "timeout": cleaned["timeout"],
        "username": str(username or "")[:50], "run_as_user": cleaned["run_as_user"], "env_vars": list(cleaned["env_vars"]),
        "custom_field_pk": None, "collector_all_output": cleaned["collector_all_output"], "save_to_agent_note": cleaned["save_to_agent_note"],
    }


def _script_audit_extra(cleaned) -> dict:
    """Counts and the script number only: never an argument or an environment value."""
    return {"script_pk": cleaned["script_pk"], "args_count": len(cleaned["args"]), "env_vars_count": len(cleaned["env_vars"])}


def _winupdate_parameters(values) -> dict:
    """What a confirmed update-decision write may carry: ``allowed_actions`` only, a non-empty subset of approve, ignore and nothing."""
    if not isinstance(values, dict):
        raise ValueError("parameters must be an object.")
    if set(values) - {"allowed_actions"}:
        raise ValueError("an update decision write takes only allowed_actions.")
    allowed = values.get("allowed_actions")
    if isinstance(allowed, (str, bytes, dict)) or not isinstance(allowed, (list, tuple)) or not 1 <= len(allowed) <= len(WRITE_ACTIONS):
        raise ValueError("allowed_actions must be a list of one to three decisions.")
    if not all(isinstance(item, str) and item in WRITE_ACTIONS for item in allowed) or len(set(allowed)) != len(allowed):
        raise ValueError("allowed_actions may list approve, ignore and nothing, each once.")
    return {"allowed_actions": [item for item in WRITE_ACTIONS if item in allowed]}


def _winupdate_audit_extra(cleaned) -> dict:
    return {"allowed_actions": list(cleaned["allowed_actions"])}


_DECISION_WORDS = {"approve": "approve", "ignore": "ignore", "nothing": "do nothing"}


def _winupdate_confirmation_line(cleaned) -> str:
    words = [_DECISION_WORDS[item] for item in cleaned["allowed_actions"]]
    listed = words[0] if len(words) == 1 else ", ".join(words[:-1]) + " or " + words[-1]
    return (f"Each time it runs, the module you named decides which updates of these endpoints to {listed}, and Core writes that decision into Tactical. "
            "Core records the earlier and the new decision of every update in its own audit log. "
            "Tactical keeps the decisions even if the module is later removed. A decision a person changed in Tactical in the meantime is left as it is.")


@dataclass(frozen=True)
class SystemFunction:
    """One Tactical function Core will run for a system action. A new row is a Core release (additive), like ``ROUTE_OWNERS``.

    1.17.66: a row declares its own call shape. ``validate_parameters(values)`` returns the cleaned parameters or raises ``ValueError``;
    ``build_call(ids, cleaned, username)`` returns ``(args, kwargs)`` for ``.delay``; ``audit_extra(cleaned)`` returns counts for the audit
    row. Parameters come only from what the person confirmed (the run's snapshot), never from the caller."""

    key: str
    module_path: str  # the Tactical module Core imports lazily at run time
    function_name: str  # a Celery task there, called with ``.delay``
    owner_module: str  # the core module that owns this Tactical group (a module id rule, like ROUTE_OWNERS)
    min_flags: tuple  # Tactical role flags the owner and the registration must hold, every one
    accepts: str  # "agent_pks": one positional list of Tactical agent numbers
    takes_username: bool
    reapproves_by_policy: bool  # the task re-approves updates by patch policy (reference agents/models.py approve_updates)
    result_text: str
    parameters: tuple = ()  # names of the parameters the row takes (for the contract metadata)
    validate_parameters: object = _no_parameters
    build_call: object = _agents_only_call
    audit_extra: object = _no_audit_extra
    # 1.17.70 (CQ203): the second kind. Defaulted, so every earlier row and every module is untouched.
    kind: str = KIND_TASK  # KIND_TASK: ``module_path.function_name`` is a Celery task called with ``.delay``; KIND_WRITE: Core writes it itself (system_writes.py)
    replacement_only: bool = False  # True: only the HONOURED replacement of ``owner_module`` may register it, never ``owner_module`` itself
    confirmation_line: object = None  # a function of the cleaned parameters that returns one plain line for the Yes or No text, or None


SYSTEM_FUNCTIONS = MappingProxyType({
    # reference/tacticalrmm v1.5.2: winupdate/tasks.py bulk_check_for_updates_task(pks: list[int]); agents/views.py bulk() mode patch, patchMode scan.
    "winupdate.scan": SystemFunction(
        key="winupdate.scan", module_path="winupdate.tasks", function_name="bulk_check_for_updates_task", owner_module="patching",
        min_flags=("can_manage_winupdates", "can_run_bulk"), accepts="agent_pks", takes_username=False, reapproves_by_policy=False,
        result_text=QUEUED_TEXT,
    ),
    # winupdate/tasks.py bulk_install_updates_task(pks: list[int]) calls agent.approve_updates() first, which re-approves an update an
    # administrator or Advanced Patch Management set to Ignore. Since 1.17.66 (CQ173, Johan: yes) the honoured replacement may register it too;
    # Core shows REAPPROVE_WARNING in the confirmation and the audit row. Since 1.17.68 (Johan, 21 October 2026) Core's patch lockdown makes Tactical's own
    # approve inert while the replacement is honoured (patch_lockdown.py); the warning then goes for the replacement's install.
    "winupdate.install": SystemFunction(
        key="winupdate.install", module_path="winupdate.tasks", function_name="bulk_install_updates_task", owner_module="patching",
        min_flags=("can_manage_winupdates", "can_run_bulk"), accepts="agent_pks", takes_username=False, reapproves_by_policy=True,
        result_text=QUEUED_TEXT,
    ),
    # scripts/tasks.py bulk_script_task(*, script_pk, agent_pks, args, timeout, username, run_as_user, env_vars, custom_field_pk,
    # collector_all_output, save_to_agent_note); agents/views.py bulk() mode script. Tactical's bulk route needs only can_run_bulk; Core also
    # asks can_run_scripts (stricter, on purpose). The username is the creator's stored name, never a name from the caller.
    "scripts.run": SystemFunction(
        key="scripts.run", module_path="scripts.tasks", function_name="bulk_script_task", owner_module="scriptexecution",
        min_flags=("can_run_bulk", "can_run_scripts"), accepts="agent_pks", takes_username=True, reapproves_by_policy=False,
        result_text=QUEUED_TEXT,
        parameters=("script_pk", "args", "env_vars", "timeout", "run_as_user", "collector_all_output", "save_to_agent_note"),
        validate_parameters=_script_parameters, build_call=_script_call, audit_extra=_script_audit_extra,
    ),
    # reference/tacticalrmm v1.5.2: winupdate/views.py EditWindowsUpdates.put (PUT winupdate/<pk>/): needs can_manage_winupdates and the person's right on the
    # update's endpoint, then WinUpdateSerializer(update, data, partial=True).save(). WinUpdate.action is one of inherit, approve, ignore, nothing. There is no
    # Celery task for it, so Core writes the one column itself (system_writes.py). Only the honoured replacement of patching (AD-45, CQ203 option a).
    "winupdate.set_action": SystemFunction(
        key="winupdate.set_action", module_path="winupdate.serializers", function_name="WinUpdateSerializer", owner_module="patching",
        min_flags=("can_manage_winupdates",), accepts="update_actions", takes_username=False, reapproves_by_policy=False,
        result_text="Written to Tactical's update decisions; Core's audit log holds the earlier and the new decision of every update.",
        parameters=("allowed_actions",), validate_parameters=_winupdate_parameters, audit_extra=_winupdate_audit_extra,
        kind=KIND_WRITE, replacement_only=True, confirmation_line=_winupdate_confirmation_line,
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
    delegable_to: tuple = ()  # 1.17.68: the modules that may start this action for someone else under a delegation grant (last, so equality of an older definition holds)


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


def _declared_now(module_id: str, action_id: str) -> bool:
    """Is ``action_id`` still listed in the module's signed manifest ``system_actions``? Read at every run (1.17.63); any error answers False."""
    try:
        plugin = next((p for p in _plugins() if p.plugin_id == module_id), None)
        return plugin is not None and action_id in tuple(getattr(plugin, "system_actions", ()) or ())
    except Exception:
        logger.warning("The signed manifest of a module could not be read for a system action run.", exc_info=True)
        return False


def _target_pks(snapshot, module_id=None):
    """``(pks, missing)`` for the run's targets snapshot, or None when it cannot be read as endpoints. ``module_id`` (1.17.68) is the module whose
    registered resolver may read a module-owned target type; without it, or without a resolver, such a type is None as before."""
    from . import resources_adapter as adapter

    if module_id is None:
        return adapter.agent_pks_for_scheduler_targets(targets=snapshot)
    return adapter.agent_pks_for_scheduler_targets(targets=snapshot, module_id=module_id)


def _is_module_target(snapshot) -> bool:
    """Is this a module-owned target type (one only a module's resolver can read)? Anything unreadable counts as yes, the safe side."""
    from .scheduler_targets import SchedulerTargetShapeError, tactical_scope_ref

    try:
        return tactical_scope_ref(snapshot)["kind"] == "module"
    except (SchedulerTargetShapeError, KeyError, TypeError, ValueError):
        return True


def _reapprove_warning_applies(definition, entry) -> bool:
    """Does the fixed re-approve warning belong to this install? Yes, unless the install is the honoured replacement's and Core's patch lockdown has made
    Tactical's own approve inert in this process (1.17.68). Windows Patching's own install, and any case where the lockdown is not active, keep it."""
    if not entry.reapproves_by_policy:
        return False
    if definition is not None and getattr(definition, "via_replacement", False) and entry.owner_module == "patching":
        try:
            from . import patch_lockdown

            return not patch_lockdown.approve_neutralised()
        except Exception:
            return True
    return True


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


_MODULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_DELEGABLE_TO = 5


def _clean_delegable_to(delegable_to, module: str) -> tuple:
    if delegable_to in (None, (), []):
        return ()
    if isinstance(delegable_to, (str, bytes)) or not isinstance(delegable_to, (list, tuple, set, frozenset)):
        raise SystemActionRegistrationError("delegable_to must be a list of module ids.")
    out = []
    for value in delegable_to:
        if not isinstance(value, str) or not _MODULE_ID_RE.fullmatch(value) or value == module:
            raise SystemActionRegistrationError("every delegable_to entry must be the id of another module.")
        out.append(value)
    out = sorted(set(out))
    if len(out) > MAX_DELEGABLE_TO:
        raise SystemActionRegistrationError(f"delegable_to may list at most {MAX_DELEGABLE_TO} modules.")
    return tuple(out)


def _build_definition(id, module_id, label, function, permissions, scope_kind, dangerous, username_param, delegable_to=()) -> SystemActionDefinition:
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
    if entry.kind == KIND_WRITE:  # 1.17.70: the strictest rules, all fixed here and none left to the module
        if not dangerous:
            raise SystemActionRegistrationError("a write to a Tactical table must be registered with dangerous=True.")
        if _clean_delegable_to(delegable_to, module):
            raise SystemActionRegistrationError("a write to a Tactical table cannot be delegated: delegable_to must be empty.")
    if entry.replacement_only and module == entry.owner_module:
        raise SystemActionRegistrationError(f"{function!r} may be registered only by the module that honourably replaces {entry.owner_module!r}, never by {entry.owner_module!r} itself.")
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
    return SystemActionDefinition(action_id, module, label.strip(), function, flags, SCOPE_KIND_AGENTS, dangerous, username_param, via_replacement,
                                  _clean_delegable_to(delegable_to, module))


def register_system_action(id, module_id, label, function, permissions, scope_kind="agents", dangerous=False, username_param=None, delegable_to=()):
    """Register one system action. Call it from ``AppConfig.ready()``; it touches memory only and never raises out of ``ready()``'s own
    guard for a replacement that is not honoured (that is logged, nothing is registered, and ``None`` comes back).

    ``function`` is a key of Core's table (``winupdate.scan``, ``winupdate.install``); a dotted path, an unknown key or anything else is
    refused. Every other refusal raises ``SystemActionRegistrationError`` (a ValueError): the module wraps the call, logs and goes on.
    Registering the identical definition again returns the same one; a different definition under the same id is refused.

    1.17.68: ``delegable_to`` (keyword, optional, default none) lists up to five other module ids that may start this action for someone else under a
    delegation grant (see ``start_delegated_run``). It only names modules; each start is still judged by Core."""
    try:
        definition = _build_definition(id, module_id, label, function, permissions, scope_kind, dangerous, username_param, delegable_to)
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
        "parameters": list(entry.parameters) if entry else [],
        "warning": REAPPROVE_WARNING if (entry and _reapprove_warning_applies(definition, entry)) else None,
        "delegable_to": list(definition.delegable_to),
        "kind": entry.kind if entry else None, "replacement_only": bool(entry.replacement_only) if entry else None,
    }


def registered_system_actions() -> list[dict]:
    """The actions registered in this process, as plain rows (no callable)."""
    with _LOCK:
        rows = sorted(_ACTIONS.values(), key=lambda d: (d.module_id, d.id))
    return [_describe(d) for d in rows]


def is_registered_system_action(module_id, action_id) -> bool:
    """Is ``action_id`` registered here by ``module_id``? Memory only (1.17.63; the scheduler asks it before it trusts an unattended flag)."""
    with _LOCK:
        definition = _ACTIONS.get(action_id) if isinstance(action_id, str) else None
    return definition is not None and definition.module_id == module_id


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
    "action_not_declared": "This action is no longer listed in the module's signed manifest under system_actions.",
    "owner_inactive": "The person who owns this run is no longer an active, interactive user.",
    "permission_lost": "The person who owns this run no longer holds the Tactical permission this action needs.",
    "bad_parameters": "The parameters of this system action are not valid.",
    "parameters_changed": "The parameters passed to the run differ from what the person confirmed, so nothing was run.",
    "bad_agents": "The endpoint list is not a list of whole endpoint numbers.",
    "agent_count": f"A system action runs on 1 to {MAX_AGENTS} endpoints, in groups of at most {MAX_AGENTS_PER_GROUP}.",
    "out_of_scope": "At least one endpoint is outside the owner's Tactical scope, so nothing was run.",
    "reapproves_by_policy": "Not returned since 1.17.66: a replacement module may install, and Core shows a plain warning instead.",
    "mark_limit": "This run has already sent the most system actions it may send.",
    "outside_targets": "At least one endpoint is not one of this schedule's targets, so nothing was run. A run never widens the schedule's set.",
    "targets_unresolved": "Core cannot read this schedule's targets as endpoints, so nothing was run.",
    "creation_scope_unavailable": "Core has no stored scope for this schedule, so nothing was run. Save the schedule again.",
    "not_permitted": "You do not hold the permission this system action needs.",
    "confirmation_required": "This system action needs the Yes or No confirmation, and none came with the request.",
    "declaration_unreadable": "Core could not read the signed manifest or the registry just now, so it did not create or change this schedule. Try again in a minute.",
    "confirmation_invalid": "The confirmation does not match this person, action, endpoints, parameters and timing, or it has expired. Ask again.",
    "wrong_kind": "This action is of the other kind: use run_system_action for a task and run_system_write for a write.",
    "bad_changes": f"The changes are not a list of 1 to {MAX_WRITE_ITEMS} items of exactly update_id and action, each update once.",
    "unknown_update": "At least one update does not exist, so nothing was written.",
    "action_not_allowed": "At least one decision is not one the person confirmed, so nothing was written.",
    "decisions_changed": "This run already tried these updates with other decisions, so Core wrote nothing new. Start a new run if you want the new decisions.",
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


def _provenance(run) -> dict:
    """Who is behind a run, for every audit row (1.17.63): ``run_kind`` (scheduled or person), the creator and the confirmer by stored name."""
    try:
        one_off = bool(getattr(run, "owner_type", "") == "module" and _run_context._is_one_off_key(getattr(run, "owner_key", "")))
        kind = "person" if (bool(getattr(run, "manual", False)) or one_off) else "scheduled"
        creator, confirmed = _run_context._creator_names(getattr(run, "schedule", None))
    except Exception:
        kind, creator, confirmed = "scheduled", "", ""
    return {"run_kind": kind, "creator": creator or None, "confirmed_by": confirmed or None}


def _actor_for(owner):
    """The creator row when it still exists, otherwise a Core service actor (the stored name is in the row's metadata)."""
    if owner is not None:
        return owner
    return _audit().service_audit_actor(module_id="core", service="scheduler", identity="system-action")


def _deny_row(reason: str, text: str, *, owner, module_id, run_id, action_id, provenance=None) -> None:
    """ONE deny row: reason code, the owner as actor (a Core service actor when there is none), requested_by scheduler. No agent, no id list."""
    try:
        audit = _audit()
        actor = owner if owner is not None else audit.service_audit_actor(module_id="core", service="scheduler", identity="system-action")
        metadata = {"reason": reason, "requested_by": "scheduler"}
        if provenance:
            metadata.update(provenance)
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


def _refuse(reason: str, *, run_id=None, owner=None, module_id=None, action_id=None, caller: str = "", detail: str = "", provenance=None):
    text = REASONS.get(reason, "The system action was refused.") + detail
    if run_id is not None:
        if reason not in _KEEP_RUN_REASONS:
            _end_run(run_id, _SKIPPED, "SystemActionRefused", text)
        _deny_row(reason, text, owner=owner, module_id=module_id, run_id=run_id, action_id=action_id, provenance=provenance)
    elif _unmatched_due(reason, caller):
        _deny_row(reason, text, owner=None, module_id=None, run_id=None, action_id=action_id)
    raise SystemActionRefused(text, reason=reason)


# ------------------------------------------------------------------------------------------------ running
def _agent_ids(agent_ids):
    """The distinct, sorted endpoint numbers, or a reason code. The count is judged against the ceiling before anything is looked up."""
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


def _decision_pairs(ids, decisions) -> str:
    """1.17.71: the sorted ``id:action`` pairs of a write, so a digest changes when a decision changes (and not when the input order does)."""
    return ",".join(f"{i}:{decisions[i]}" for i in sorted(ids))


def _digest(run_id, action_id: str, ids, decisions=None) -> str:
    """The at-most-once key of one group. ``decisions`` (a write only) binds the decisions into it; None keeps the formula of every task row."""
    raw = f"{run_id}|{action_id}|" + ",".join(str(i) for i in ids)
    if decisions is not None:
        raw += "|decisions|" + _decision_pairs(ids, decisions)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _plan_digest(run_id, action_id: str, ids, decisions=None) -> str:
    raw = f"{run_id}|{action_id}|plan|" + ",".join(str(i) for i in ids)
    if decisions is not None:
        raw += "|decisions|" + _decision_pairs(ids, decisions)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _ranges_of(ids) -> list:
    """The sorted ids as ``[first, last]`` runs: compact, and enough to tell whether two id sets overlap."""
    out = []
    for value in ids:
        if out and value == out[-1][1] + 1:
            out[-1][1] = value
        else:
            out.append([value, value])
    return out


def _ranges_overlap(a, b) -> bool:
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i][1] < b[j][0]:
            i += 1
        elif b[j][1] < a[i][0]:
            j += 1
        else:
            return True
    return False


def _is_plan(mark) -> bool:
    return isinstance(mark, dict) and mark.get("kind") == KIND_PLAN


def _claim_plan(run_id, action_id: str, ids, group_digests, decisions=None):
    """Fix the group plan of this call under the run's row lock (1.17.67). Returns ``(state, plan)``: ``new`` or ``same`` (go on with
    ``plan``), ``changed`` (an overlapping plan has a group that was claimed, sent or left unknown: send nothing), ``gone`` or ``full``.

    1.17.71: a write binds its decisions into the digest. A stored plan for the same updates with other decisions is never replaced and never
    written again: ``changed_decisions`` when one of its groups was claimed, sent or left unknown, ``decisions_changed`` when none was (nothing
    is written in either case). A plan written by 1.17.70 has no ``ids_key``; its ``targets_digest`` is the ids-only digest."""
    digest = _plan_digest(run_id, action_id, ids, decisions)
    ids_digest = _plan_digest(run_id, action_id, ids) if decisions is not None else None
    ranges = _ranges_of(ids)
    with transaction.atomic():
        current = _locked_run(run_id)
        if str(current.status) != _RUNNING:
            return "gone", None
        marks = [dict(m) for m in (current.system_action_marks or []) if isinstance(m, dict)]
        plans = [m for m in marks if _is_plan(m) and m.get("action_id") == action_id]
        for plan in plans:
            if plan.get("targets_digest") == digest:
                return "same", plan
        if ids_digest is not None:
            for plan in plans:
                if (plan.get("ids_key") or plan.get("targets_digest")) != ids_digest:
                    continue  # the same updates with other decisions: nothing is written
                own = set(plan.get("group_digests") or [])
                for mark in marks:
                    if not _is_plan(mark) and mark.get("action_id") == action_id and mark.get("targets_digest") in own and mark.get("state") != STATE_ABORTED:
                        return "changed_decisions", plan
                return "decisions_changed", plan
        stale = []
        for plan in plans:
            if not _ranges_overlap(ranges, plan.get("ids") or []):
                continue  # a second, disjoint call of the same run is legal
            own = set(plan.get("group_digests") or [])
            for mark in marks:
                if not _is_plan(mark) and mark.get("action_id") == action_id and mark.get("targets_digest") in own and mark.get("state") != STATE_ABORTED:
                    return "changed", plan
            stale.append(plan)
        if stale:  # nothing of the old plan was sent: it is replaced, and its aborted group marks go with it
            gone_digests = {d for plan in stale for d in (plan.get("group_digests") or [])} | {plan.get("targets_digest") for plan in stale}
            marks = [m for m in marks if not (m.get("action_id") == action_id and m.get("targets_digest") in gone_digests)]
        if len(marks) >= MAX_MARKS_PER_RUN:
            return "full", None
        plan = {"action_id": action_id, "kind": KIND_PLAN, "targets_digest": digest, "ids": ranges, "group_digests": list(group_digests),
                "group_size": MAX_AGENTS_PER_GROUP, "state": KIND_PLAN}
        if ids_digest is not None:
            plan["ids_key"] = ids_digest
        marks.append(plan)
        current.system_action_marks = marks
        current.save(update_fields=["system_action_marks"])
        return "new", plan


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


def _groups_of(ids) -> list:
    """The sorted ids cut into groups of at most ``MAX_AGENTS_PER_GROUP`` (no id twice, none lost)."""
    return [list(ids[i:i + MAX_AGENTS_PER_GROUP]) for i in range(0, len(ids), MAX_AGENTS_PER_GROUP)]


def _group_counts(total: int, sent: int, failed: int = 0) -> dict:
    return {"total": total, "sent": sent, "failed": failed, "not_started": max(total - sent - failed, 0)}


def _summary(agents: int, counts: dict, noun: str = "endpoint(s)") -> str:
    """One plain line. Counts only: no endpoint ids."""
    return (f"{agents} {noun} in {counts['total']} group(s): {counts['sent']} sent, {counts['failed']} failed, "
            f"{counts['not_started']} not started.")


def _queued_result(entry: SystemFunction, agents: int, counts: dict | None = None, **extra) -> dict:
    counts = counts or _group_counts(1, 1)
    return {"outcome": "queued", "agents": agents, "message": entry.result_text, "groups": dict(counts), "summary": _summary(agents, counts), **extra}


def _unknown(run_id, owner, definition, action_id: str, module_id: str, provenance=None, summary: str = ""):
    text = "A system action may already have been sent for this run, so Core did not send it again. Check the endpoints before running it again."
    if summary:
        text = f"{text} {summary}"
    _end_run(run_id, _FAILED, "OutcomeUnknown", text)
    try:
        _audit().record(
            actor=_actor_for(owner), module_id="core", action="custom:outcome-unknown", object_type="system_action", object_id=_safe_action_id(action_id),
            message=f"A scheduled system action has an unknown outcome: {text}",
            metadata={"requested_by": "scheduler", "run_id": str(run_id), "owner_module": module_id, "reason": "outcome_unknown", **(provenance or {})},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a system action with an unknown outcome could not be written")
    raise SystemActionOutcomeUnknown(text)


def run_system_action(context, *, action_id, agent_ids, parameters=None) -> dict:
    """Run a registered system action for the owner of the Scheduler run ``context`` belongs to (core.system_actions 1.1.0).

    Call it from the module's own Scheduler handler, passing the context object the handler received. Returns
    ``{"outcome": "queued", "agents": N, "message": ..., "groups": {total, sent, failed, not_started}, "summary": ...}``: the work is
    queued in Tactical, not done. More than 2000 endpoints run in groups of at most 2000 (1.17.66). Every refusal ends the run
    ``skipped`` (error type ``SystemActionRefused``), writes one ``deny`` audit row and raises ``SystemActionRefused`` (a
    ``SchedulerPermanentError``, so the worker does not retry). See docs/system-actions.md for the checks and their reason codes."""
    identity = calling_module_for_core_provider(provider_file=__file__)  # the module whose own code called this function, or None
    return _run(context, identity, action_id, agent_ids, parameters)


def run_system_write(context, *, action_id, changes) -> dict:
    """Run a registered WRITE action for the owner of the Scheduler run ``context`` belongs to (core.system_actions 1.3.0, Core 1.17.70, CQ203).

    ``changes`` is a list of ``{"update_id": int, "action": "approve" | "ignore" | "nothing"}``, exactly those two keys, each update once, at most 40 000.
    Call it from the honoured replacement's own Scheduler handler. Every check of ``run_system_action`` runs in the same order, then Core reads each
    update's endpoint itself and judges that endpoint set like ``agent_ids``; one miss refuses the whole call and nothing is written. A task row
    refuses here as ``wrong_kind``, and a write row refuses in ``run_system_action`` the same way. Returns ``{"outcome": "written", "changes", "written",
    "unchanged", "changed_meanwhile", "groups": {...}, "message", "summary"}``. See docs/system-actions.md, "The second kind: a write"."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    return _run(context, identity, action_id, None, None, writing=True, changes=changes)


def _run(context, identity, action_id, agent_ids, parameters, *, writing=False, changes=None) -> dict:
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
        _refuse(reason, run_id=run.id, module_id=module_id, action_id=shown_id, caller=caller, provenance=_provenance(run))
    # 1.17.65 (AD-13 condition 2 amended): a scheduled run of a user-owned schedule skips only the three re-reads of the person (owner_inactive,
    # permission_lost, out_of_scope). Core decided that in verify_run_context through the one helper; a manual or one-off run never is.
    unattended = bool(getattr(verified, "unattended", False))
    provenance = _provenance(run)
    # the person behind the schedule (as the schedule row holds them) is the actor of any refusal that follows, even before the fresh read
    common = {"run_id": run.id, "module_id": module_id, "action_id": shown_id, "caller": caller, "owner": verified.user, "provenance": provenance}
    if verified.user is None and not (unattended and (getattr(verified, "creator_username", None) or "")):
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
    if not _declared_now(definition.module_id, definition.id):  # 1.17.63: listed in the signed manifest now, not only at registration
        _refuse("action_not_declared", **common)
    entry = SYSTEM_FUNCTIONS.get(definition.function)
    if entry is None:
        _refuse("function_unavailable", **common)
    if entry.kind != (KIND_WRITE if writing else KIND_TASK):  # 1.17.70: a task row is run by run_system_action, a write row by run_system_write
        _refuse("wrong_kind", **common)
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
    # (4) the owner, read again from the database. An unattended scheduled run skips this read (checked when the person made the schedule).
    if unattended:
        owner = verified.user  # None when the creator's row is gone: the audit actor is then a Core service actor
    else:
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
    # (5) the parameters: only what the person confirmed (the run's snapshot). The caller's own argument may only repeat it.
    snapshot = run.parameters_snapshot if isinstance(getattr(run, "parameters_snapshot", None), dict) else {}
    confirmed = snapshot.get(PARAMETERS_KEY)
    caller_params = parameters
    if not entry.parameters:
        if caller_params not in (None, {}) or confirmed not in (None, {}):
            _refuse("bad_parameters", **common)
        cleaned = {}
    else:
        if caller_params not in (None, {}) and caller_params != confirmed:
            _refuse("parameters_changed", **common)
        try:
            cleaned = entry.validate_parameters(confirmed if confirmed is not None else {})
        except ValueError:
            _refuse("bad_parameters", **common)
    username = ""
    if entry.takes_username:
        username = str(provenance.get("creator") or getattr(owner, "username", "") or "")[:50]
        if not username:
            _refuse("no_owner", **common)
    # (6) the count, judged before any lookup, then (5) the scope of every endpoint
    decisions = {}
    if writing:  # 1.17.70: the endpoints are the ones Core reads off the update rows itself; the rest of the checks below judge them like agent_ids
        from . import system_writes as writer

        try:
            decisions, ids = writer.resolve_changes(changes, cleaned)
        except writer.WriteRefused as exc:
            _refuse(exc.reason, detail=exc.detail, **common)
        items = sorted(decisions)
    else:
        ids, reason = _agent_ids(agent_ids)
        if reason:
            _refuse(reason, **common)
        items = ids
    if not unattended:
        try:
            in_scope = _agents_in_scope(owner, ids)
        except Exception:
            logger.warning("The scope of a system action could not be checked; the run is refused.", exc_info=True)
            in_scope = False
        if not in_scope:  # a native scheduler manager has no bypass here: Tactical's own role scope decides, and one miss refuses all
            _refuse("out_of_scope", **common)
    # (6b) a run never widens the schedule's set: every endpoint must be one of the run's snapshotted targets (Core 1.17.62)
    try:
        resolved = _target_pks(run.targets_snapshot or {}, module_id)
    except Exception:
        logger.warning("The targets of a system action run could not be resolved; the run is refused.", exc_info=True)
        resolved = None
    if resolved is None:
        _refuse("targets_unresolved", **common)
    target_pks, vanished = resolved
    if not set(ids) <= set(target_pks):
        note = f" {vanished} target(s) of this schedule no longer exist." if vanished else ""
        _refuse("outside_targets", detail=note, **common)
    # (6c) 1.17.68: an unattended run on a module-owned target type reads its endpoints from a module's resolver. Whatever the resolver names is
    # cut to the scope the person had when they saved the schedule, so module code can never add an endpoint they did not confirm.
    if unattended and _is_module_target(run.targets_snapshot or {}):
        stored = verified.creation_scope_info()
        if stored is None:
            _refuse("creation_scope_unavailable", **common)
        try:
            from . import resources_adapter as adapter

            inside = adapter.agent_rows_in_scope(pks=ids, snapshot=stored, limit=MAX_AGENTS)
            all_inside = {int(row["pk"]) for row in inside} == set(ids)
        except Exception:
            logger.warning("The stored scope of a system action run could not be checked; the run is refused.", exc_info=True)
            all_inside = False
        if not all_inside:
            _refuse("out_of_scope", **common)
    # (7) 1.17.66 (CQ173): an install that re-approves by policy is allowed for the honoured replacement; the warning is in the audit row
    if writing:
        function = None
        if not writer.available():
            _refuse("function_unavailable", **common)
    else:
        function = _import_function(entry)
        if function is None:
            _refuse("function_unavailable", **common)

    # at-most-once, group by group: the mark, then the strict audit row, then the send. The whole set was judged above.
    groups = _groups_of(items)  # a write is grouped by update number; a task by endpoint number
    bound = decisions if writing else None  # 1.17.71: a write's digests cover its decisions; a task's stay as they were
    digests = [_digest(run.id, definition.id, group) if bound is None else _digest(run.id, definition.id, group, bound) for group in groups]
    existing = [m for m in (getattr(run, "system_action_marks", None) or []) if isinstance(m, dict)]
    plan_digest = _plan_digest(run.id, definition.id, items, bound)
    ours = sum(1 for m in existing if m.get("action_id") == definition.id and m.get("targets_digest") in set(digests) | {plan_digest})
    if len(existing) - ours + len(groups) + 1 > MAX_MARKS_PER_RUN:
        _refuse("mark_limit", **common)
    plan_state, plan = _claim_plan(run.id, definition.id, items, digests, bound)
    if plan_state == "gone":
        raise SchedulerPermanentError("The run is no longer active, so nothing was sent.")
    if plan_state == "full":
        _refuse("mark_limit", **common)
    if plan_state == "decisions_changed":
        _refuse("decisions_changed", **common)
    if plan_state == "changed_decisions":
        _unknown(run.id, owner, definition, definition.id, module_id, provenance,
                 "The decisions changed after part of this run was started, so Core did not write again. Check the updates.")
    if plan_state == "changed":
        _unknown(run.id, owner, definition, definition.id, module_id, provenance,
                 "The endpoint list changed after part of this run was sent, so Core did not send again. Check the endpoints.")
    # the groups come from the stored plan, never from the live list again
    size = int(plan.get("group_size") or MAX_AGENTS_PER_GROUP)
    groups = [list(items[i:i + size]) for i in range(0, len(items), size)]
    digests = list(plan.get("group_digests") or digests)
    if len(digests) != len(groups):
        _unknown(run.id, owner, definition, definition.id, module_id, provenance, "The stored plan of this run does not fit the endpoints, so Core did not send again. Check the endpoints.")
    extra = {"vanished_targets": int(vanished)} if vanished else {}  # 1.17.63: targets that no longer exist, while the rest still run
    row_extra = dict(entry.audit_extra(cleaned))
    if _reapprove_warning_applies(definition, entry):
        row_extra["warning"] = REAPPROVE_WARNING
    elif entry.reapproves_by_policy:
        row_extra["patch_lockdown"] = "active"  # 1.17.68: Tactical's own approve was inert for this install
    noun = "update decision(s)" if writing else "endpoint(s)"
    sent_now = 0
    sent_before = 0
    totals = {"written": 0, "unchanged": 0, "changed_meanwhile": 0, "vanished": 0}
    for index, (group, digest) in enumerate(zip(groups, digests), start=1):
        state, _mark = _claim_mark(run.id, definition.id, digest, len(group))
        if state == "gone":
            raise SchedulerPermanentError("The run is no longer active, so nothing was sent.")
        if state == "full":
            _unknown(run.id, owner, definition, definition.id, module_id, provenance,
                     _summary(len(items), _group_counts(len(groups), sent_now + sent_before, 1), noun))
        if state == "sent":
            sent_before += 1
            continue
        if state == "unknown":
            _unknown(run.id, owner, definition, definition.id, module_id, provenance,
                     _summary(len(items), _group_counts(len(groups), sent_now + sent_before, 1), noun))
        if writing:
            outcome = _write_group(
                writer, run=run, definition=definition, owner=owner, verified=verified, provenance=provenance, extra={**extra, **row_extra},
                group=group, decisions=decisions, cleaned=cleaned, digest=digest, index=index, groups_total=len(groups), total=len(items),
            )
            sent_now += 1
            for key in totals:
                totals[key] += outcome.get(key, 0)
            if not _set_mark(run.id, definition.id, digest, STATE_SENT):
                logger.error("The write was made but its mark could not be set to 'sent'; a retry would fail as outcome-unknown.")
            writer.record_closing(
                actor=_actor_for(owner), definition=definition, run=run, schedule_id=verified.schedule_id, provenance=provenance, extra={**extra, **row_extra},
                outcome=outcome, digest=digest, index=index, groups_total=len(groups), total=len(items),
            )
            continue
        try:
            _audit().record(
                actor=_actor_for(owner), module_id="core", action="run", object_type="system_action", object_id=definition.id,
                message=f"A scheduled system action is being sent to Tactical for {len(group)} endpoint(s) (group {index} of {len(groups)}).",
                metadata={
                    "requested_by": "scheduler", "run_id": str(run.id), "schedule_id": str(verified.schedule_id), "owner_module": definition.module_id,
                    "function": definition.function, "agent_count": len(group), "total_agents": len(ids), "group": index, "groups": len(groups),
                    "targets_digest": digest, **provenance, **extra, **row_extra,
                },
                strict=True,
            )
        except Exception:
            logger.exception("The audit row of a system action could not be written; nothing is sent for this group.")
            _set_mark(run.id, definition.id, digest, STATE_ABORTED)
            raise SchedulerTransientError("The audit row could not be written, so nothing was sent for this group.") from None
        try:
            args, kwargs = entry.build_call(group, cleaned, username)
            sent = function.delay(*args, **kwargs)  # exactly the way Tactical's own bulk view starts the task
        except Exception:
            logger.exception("Tactical's task could not be started; Core never sends again for this group.")
            _unknown(run.id, owner, definition, definition.id, module_id, provenance,
                     _summary(len(ids), _group_counts(len(groups), sent_now + sent_before, 1)))
        task_id = str(getattr(sent, "id", "") or "")[:80]
        sent_now += 1
        if not _set_mark(run.id, definition.id, digest, STATE_SENT, task_id):
            logger.error("The system action was sent but its mark could not be set to 'sent'; a retry would fail as outcome-unknown.")
    counts = _group_counts(len(groups), sent_now + sent_before)
    if writing:
        return _written_result(entry, len(items), counts, totals, duplicate=sent_now == 0, **extra)
    if sent_now == 0:
        return _queued_result(entry, len(ids), counts, duplicate=True, **extra)
    return _queued_result(entry, len(ids), counts, **extra)


def _written_result(entry: SystemFunction, changes: int, counts: dict, totals: dict, **extra) -> dict:
    """The result of ``run_system_write``. The totals are for the groups this attempt wrote; a group a retry found already written adds nothing."""
    result = {
        "outcome": "written", "changes": changes, "written": totals["written"], "unchanged": totals["unchanged"],
        "changed_meanwhile": totals["changed_meanwhile"], "groups": dict(counts), "message": entry.result_text,
        "summary": (f"{_summary(changes, counts, 'update decision(s)')} {totals['written']} written, {totals['unchanged']} already as decided, "
                    f"{totals['changed_meanwhile']} left alone because a person changed them meanwhile."),
    }
    result.update(extra)
    if result.pop("duplicate", False):
        result["duplicate"] = True
    return result


def _write_group(writer, *, run, definition, owner, verified, provenance, extra, group, decisions, cleaned, digest, index, groups_total, total) -> dict:
    """One group of a write: read the current decisions, write the strict audit rows, then write. At most once: a failure before the audit rows
    are all written aborts the mark (nothing was written); a failure while writing ends the run as outcome-unknown and is never repeated."""
    module_id = definition.module_id
    try:
        planned = writer.plan_group(group, decisions)
        writer.write_audit_rows(
            actor=_actor_for(owner), definition=definition, run=run, schedule_id=verified.schedule_id, provenance=provenance, extra=extra,
            planned=planned, digest=digest, index=index, groups_total=groups_total, total=total,
        )
    except Exception:
        logger.exception("The decisions of a write group could not be read or audited; nothing is written for this group.")
        _set_mark(run.id, definition.id, digest, STATE_ABORTED)
        raise SchedulerTransientError("The audit row could not be written, so nothing was written for this group.") from None
    try:
        return writer.apply_group(planned)
    except Exception:
        logger.exception("Tactical's update decisions could not be written; Core never writes this group again.")
        _unknown(run.id, owner, definition, definition.id, module_id, provenance, _summary(total, _group_counts(groups_total, index - 1, 1), "update decision(s)"))


# ------------------------------------------------------------------------------------------------ the capability
# ------------------------------------------------------------------------------------------------ delegation (1.17.68)
# The five public functions below are thin: each hands over to ``delegation.py``, which reads the calling module itself (1.17.69: the frame walk skips
# every frame of this file and of delegation.py, so the capability route, these wrappers and a direct import give the same answer). ``run_system_action`` is not one of them and is unchanged.
def describe_delegation(request, *, owner_module, provider_module, action_id, targets, parameters=None) -> dict:
    """The plain Yes or No text and a 600 second confirmation id for a delegation grant, for the person behind a real, session-checked ``request``
    (1.17.68). The caller must be ``owner_module``. See docs/system-actions.md, "Delegation"."""
    from . import delegation

    return delegation.describe(request, owner_module=owner_module, provider_module=provider_module, action_id=action_id,
                               targets=targets, parameters=parameters)


def register_delegation_grant(request, *, owner_module, grant_key, provider_module, action_id, targets, parameters=None, confirmation_id=None) -> dict:
    """Store (or replace) the grant a person confirmed. The caller must be ``owner_module``. A second person who registers the same grant takes it over."""
    from . import delegation

    return delegation.register(request, owner_module=owner_module, grant_key=grant_key, provider_module=provider_module,
                               action_id=action_id, targets=targets, parameters=parameters, confirmation_id=confirmation_id)


def remove_delegation_grant(*, owner_module, grant_key) -> bool:
    """Remove a grant. The caller must be ``owner_module``. Every ticket made for it stops working."""
    from . import delegation

    return delegation.remove(owner_module=owner_module, grant_key=grant_key)


def issue_delegation_ticket(context, *, grant_key) -> str:
    """A signed 24 hour ticket for the owner module's own LIVE Scheduler run, bound to that run and to the grant as it is now."""
    from . import delegation

    return delegation.issue_ticket(context, grant_key=grant_key)


def start_delegated_run(ticket, *, action_id, agent_ids, name=None):
    """Start the provider's own one-off run for the grant behind ``ticket``. The caller must be the grant's provider module. Returns the queued run."""
    from . import delegation

    return delegation.start(ticket, action_id=action_id, agent_ids=agent_ids, name=name)


def resolve_delegated_targets(ticket, *, action_id, endpoint_ids) -> dict:
    """Which of ``endpoint_ids`` (1 to 40 000 endpoint numbers or agent id texts) does ``ticket`` cover? (1.17.74, Q-APM21 b.) The caller must be the grant's
    provider module. Applies the ticket checks ``start_delegated_run`` applies before it makes a run, then returns ``{"agents": [{"agent_id", "pk"}], "covered", "not_covered"}``
    and names no endpoint it refuses. Any ticket problem is one generic refusal (``ticket_invalid``). Creates no run and no schedule."""
    from . import delegation

    return delegation.resolve_targets(ticket, action_id=action_id, endpoint_ids=endpoint_ids)


class _SystemActionsProvider:
    """The ``core.system_actions`` 1.4.0 provider: list_actions, get_action, run, describe_confirmation, (1.17.68) the five delegation operations, (1.17.70) run_write and (1.17.74) resolve_delegated_targets."""

    def list_actions(self) -> list[dict]:
        return registered_system_actions()

    def get_action(self, action_id):
        return get_system_action(action_id)

    def run(self, context, *, action_id, agent_ids, parameters=None) -> dict:
        return run_system_action(context, action_id=action_id, agent_ids=agent_ids, parameters=parameters)

    def run_write(self, context, *, action_id, changes) -> dict:
        """1.17.70: the second kind (a write). The caller is read from the stack, so this route and a direct import give the same answer."""
        return run_system_write(context, action_id=action_id, changes=changes)

    def describe_confirmation(self, request, *, action_id, targets, parameters=None, when=None) -> dict:
        """The plain Yes or No text and a short-lived confirmation id for the person behind a real, session-checked ``request`` (1.17.66)."""
        from . import system_action_confirmation

        return system_action_confirmation.describe_confirmation_for_request(request, action_id=action_id, targets=targets, parameters=parameters, when=when)

    def describe_delegation(self, request, *, owner_module, provider_module, action_id, targets, parameters=None) -> dict:
        return describe_delegation(request, owner_module=owner_module, provider_module=provider_module, action_id=action_id, targets=targets, parameters=parameters)

    def register_delegation_grant(self, request, *, owner_module, grant_key, provider_module, action_id, targets, parameters=None, confirmation_id=None) -> dict:
        return register_delegation_grant(request, owner_module=owner_module, grant_key=grant_key, provider_module=provider_module, action_id=action_id,
                                         targets=targets, parameters=parameters, confirmation_id=confirmation_id)

    def remove_delegation_grant(self, *, owner_module, grant_key) -> bool:
        return remove_delegation_grant(owner_module=owner_module, grant_key=grant_key)

    def issue_delegation_ticket(self, context, *, grant_key) -> str:
        return issue_delegation_ticket(context, grant_key=grant_key)

    def start_delegated_run(self, ticket, *, action_id, agent_ids, name=None):
        return start_delegated_run(ticket, action_id=action_id, agent_ids=agent_ids, name=name)

    def resolve_delegated_targets(self, ticket, *, action_id, endpoint_ids) -> dict:
        """1.17.74: which endpoints a delegation ticket covers. The caller is read from the stack, so this route and a direct import give the same answer."""
        return resolve_delegated_targets(ticket, action_id=action_id, endpoint_ids=endpoint_ids)


_PROVIDER = _SystemActionsProvider()
OPERATIONS = (
    "list_actions", "get_action", "run", "describe_confirmation",
    "describe_delegation", "register_delegation_grant", "remove_delegation_grant", "issue_delegation_ticket", "start_delegated_run",
    "run_write", "resolve_delegated_targets",
)


def system_actions_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": list(OPERATIONS),
        "python": (
            "tec_tac.system_actions.register_system_action(id, module_id, label, function, permissions, scope_kind='agents', dangerous=False, "
            "username_param=None, delegable_to=()) -> SystemActionDefinition | None; tec_tac.system_actions.run_system_action(context, *, action_id, agent_ids, "
            "parameters=None) -> {outcome: 'queued', agents, message, groups: {total, sent, failed, not_started}, summary}; "
            "tec_tac.system_action_confirmation.describe_confirmation(user, action_id, targets, parameters, when) -> {text, confirmation_id, total, groups, expires_in}; "
            "tec_tac.system_actions.describe_delegation(request, *, owner_module, provider_module, action_id, targets, parameters=None) -> {required, text, confirmation_id, total, groups, expires_in}; "
            "tec_tac.system_actions.register_delegation_grant(request, *, owner_module, grant_key, provider_module, action_id, targets, parameters=None, confirmation_id) -> {grant_key, created, owner_changed}; "
            "tec_tac.system_actions.remove_delegation_grant(*, owner_module, grant_key) -> bool; "
            "tec_tac.system_actions.issue_delegation_ticket(context, *, grant_key) -> str; "
            "tec_tac.system_actions.start_delegated_run(ticket, *, action_id, agent_ids, name=None) -> TecTacScheduleRun (queued); "
            "tec_tac.system_actions.run_system_write(context, *, action_id, changes) -> {outcome: 'written', changes, written, unchanged, changed_meanwhile, groups: {total, sent, failed, not_started}, message, summary} "
            "(1.17.70, the second kind, honoured replacement only); "
            "tec_tac.system_actions.resolve_delegated_targets(ticket, *, action_id, endpoint_ids) -> {agents: [{agent_id, pk}], covered, not_covered} "
            "(1.17.74, Q-APM21 b)"
        ),
        "write": {
            "kinds": ["task", "write"], "function": "winupdate.set_action", "changes": "list of {update_id: int, action: 'approve' | 'ignore' | 'nothing'}, exactly those keys, each update once",
            "max_changes": MAX_WRITE_ITEMS, "max_changes_per_group": MAX_AGENTS_PER_GROUP, "audit_chunk": 500,
            "refusal_reasons": ["wrong_kind", "bad_changes", "unknown_update", "action_not_allowed", "decisions_changed"],
            "limit": "Tactical's own audit log does not show Core's in-process write; Core's strict audit rows (before and after of every update) are the record.",
        },
        "delegation": {
            "grants_per_owner_module": 20, "ticket_seconds": 24 * 3600, "confirmation_seconds": 600,
            "callers": {"describe_delegation": "owner module", "register_delegation_grant": "owner module", "remove_delegation_grant": "owner module",
                        "issue_delegation_ticket": "owner module, from its own live Scheduler run", "start_delegated_run": "provider module named by the grant",
                        "resolve_delegated_targets": "provider module named by the grant"},
        },
        "functions": {
            key: {
                "tactical": f"{row.module_path}.{row.function_name}", "owner_module": row.owner_module, "min_flags": list(row.min_flags),
                "takes_username": row.takes_username, "reapproves_by_policy": row.reapproves_by_policy, "parameters": list(row.parameters),
                "kind": row.kind, "replacement_only": row.replacement_only,
            }
            for key, row in SYSTEM_FUNCTIONS.items()
        },
        "manifest_key": "system_actions: list of '<module id>.<name>' ids, at most 20 (extensions only)",
        "max_agents": MAX_AGENTS,
        "max_agents_per_group": MAX_AGENTS_PER_GROUP,
        "max_groups": MAX_GROUPS,
        "parameters_key": PARAMETERS_KEY,
        "refusal_reasons": sorted(REASONS),
        "http": {"confirmation": "POST /api/tfd/scheduler/system-actions/confirmation/"},
        "delivery": "at most once per group",
        "audit_actions": ["run (strict, before each group's send)", "deny (one per refusal)", "custom:outcome-unknown", "add and modify on the schedule (strict)"],
        "requires_framework": ">=1.17.61 (groups, parameters, scripts.run and describe_confirmation need >=1.17.66; delegable_to, the five delegation operations and module-owned target resolvers need >=1.17.68; run_write and the winupdate.set_action row need >=1.17.70; resolve_delegated_targets needs >=1.17.74)",
        "unattended": "A scheduled run of a user-owned schedule skips owner_inactive, permission_lost and out_of_scope (>=1.17.65; the unattended= flag has no effect); every other check stays. A manual or one-off run keeps all of them.",
    }


def register_core_system_actions_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Typed Tactical functions that Core runs unattended for a named owner, in groups of at most 2000 endpoints, with the owner and scope checked at every person-started run and the permission, scope and one Yes or No checked when a person creates or edits the schedule (>=1.17.66); a scheduled run is not re-checked against its creator (>=1.17.65); a module may start another module's action under a delegation grant a person confirmed once (>=1.17.68); the honoured replacement of Windows Patching may write Windows update decisions through run_write, with a strict before and after audit row for every update (>=1.17.70); the provider named in a delegation grant may ask which endpoints a ticket covers through resolve_delegated_targets (>=1.17.74).",
        operations=OPERATIONS,
        metadata=system_actions_contract_metadata(),
    )


def _clear_for_tests() -> None:
    with _LOCK:
        _ACTIONS.clear()
    _UNMATCHED.clear()
