"""Tactical's own patch policy, switched off while Advanced Patch Management is honoured (Core 1.17.68, Johan 21 October 2026; the former R-36).

Johan's words: "the tactical patch policy must be disabled when APM is installed so that this doesn't happen."

What "this" is. Tactical's install call (``winupdate/views.py`` ``InstallWindowsUpdates.post`` and ``winupdate/tasks.py``
``bulk_install_updates_task``) first calls ``agent.approve_updates()``. That flips every not-yet-installed update whose severity the endpoint's own
patch policy approves back to Approve, so an update that Advanced Patch Management set to Ignore is installed anyway. Tactical's own scheduled
tasks (``auto_approve_updates_task`` and ``check_agent_update_schedule_task``) do the same on their own timetable.

When it applies. ``active()`` is True only while a replacement of the core module ``patching`` is honoured right now (``tactical_operations._honoured_pairs``,
the one source AD-20 uses). It is cached for 30 seconds. A read that fails answers False and logs: a fault never switches Tactical's patching off.

What Core does while it is active. Three guards. None writes Tactical data. None blocks a declared operation the replacement registers (scan,
install, set-update-action, reset, add, edit and delete patch policy): those still run through Core's executor as the signed-in person, and the
install still sends what is already approved.

1. At ``AppConfig.ready()`` in every process (web and Celery; enabling or disabling a module reloads uwsgi and restarts Celery, so this is read again),
   Core sets Tactical's own documented switches ``TRMM_DISABLE_APPROVE_UPDATES_TASK`` and ``TRMM_DISABLE_WINUPDATES_INSTALL_TASK`` to True. It never sets
   one to False and never overrides a value the administrator set.
2. ``Agent.approve_updates`` is wrapped (same pattern as ``tactical_account_guard``). While active it returns without approving anything. Otherwise it
   calls Tactical's own method unchanged.
3. The capability ``core.patch_lockdown`` 1.0.0 answers ``status()``: ``{active, honoured_module, tasks_off, approve_guard_installed}``.

When it stops. The moment the replacement is no longer honoured, ``active()`` answers False and Tactical's own approve works again. The two
settings are Python settings read at the start of each process, so they go back with the restart that a module enable or disable already causes.

Fail directions. An unreadable module state: inactive, Tactical keeps patching. A guard that cannot be installed: Tactical keeps working, ``status()``
says ``approve_guard_installed`` False, one log line. Nothing here can stop Tactical from starting.

Not built here: refusing Tactical's own native ``winupdate/`` and ``automation/patchpolicy/`` mutating routes, and any write of WinUpdatePolicy rows
(see docs/patch-lockdown.md). This is a named exception to checklist A2 and rule 1.7 that Johan asked for; it is flagged for human review.
"""
from __future__ import annotations

import logging
import threading
import time
from functools import wraps

logger = logging.getLogger("tec_tac.patch_lockdown")

# Johan signed the lockdown on 21 October 2026 (AD-41, docs/review-accepted-decisions.md). The two guards below touch Tactical (its settings and Agent.approve_updates),
# which checklist A2 and rule 1.7 allow only for authentication, accounts, AD-13 and AD-19. AD-41 is the named exception, with its conditions: fail open, never over an
# administrator's value, only while an honoured replacement of patching is installed. False is the switch that turns ``apply_at_startup`` into a no-op.
# tests/patch-lockdown-held-1.17.68.py pins this value to the documents.
DECISION_RECORDED = True

CAPABILITY_ID = "core.patch_lockdown"
CAPABILITY_VERSION = "1.0.0"
REPLACED_MODULE = "patching"
CACHE_SECONDS = 30.0
SETTING_NAMES = ("TRMM_DISABLE_APPROVE_UPDATES_TASK", "TRMM_DISABLE_WINUPDATES_INSTALL_TASK")
GUARD_MARKER = "_tec_tac_patch_lockdown_guard"
AUDIT_ACTION = "custom:tactical-patch-lockdown"
AUDIT_OBJECT_TYPE = "tactical_patch_lockdown"
AUDIT_OBJECT_ID = "winupdate"

_LOCK = threading.Lock()
_CACHE = {"at": None, "module": None}
_STATE = {"settings": {}, "guard": False, "fault_logged": False}
_clock = time.monotonic  # a test replaces it


# The few places this module reads Core or Tactical. Each is one small function so a test can replace it without Django.
def _honoured_pairs() -> dict:
    from . import tactical_operations

    return tactical_operations._honoured_pairs()


def _django_settings():
    from django.conf import settings

    return settings


def _agent_class():
    from agents.models import Agent

    return Agent


def _last_row_state():
    """``'on'``, ``'held'``, ``'off'`` or None (no row yet) for the newest lockdown audit row. Raises when the lookup cannot run."""
    from . import audit

    row = (
        audit._auditlog_model().objects.filter(action=AUDIT_ACTION, debug_info__object_id=AUDIT_OBJECT_ID).order_by("-entry_time", "-id").first()
    )
    if row is None:
        return None
    info = row.debug_info if isinstance(row.debug_info, dict) else {}
    metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
    state = metadata.get("state")
    return state if state in ("on", "held", "off") else None


def in_effect() -> bool:
    """True only when the lockdown is really in effect in THIS process: the switch is on and the settings are off or the approve guard is
    installed. ``status()['active']`` only says a replacement is honoured; this says Tactical's own patch policy is actually switched off."""
    return bool(DECISION_RECORDED) and (tasks_off() or bool(_STATE["guard"]))


def _write_row(state: str, module_id, previous=None, reason=None, tasks_off_now=None, approve_guard_now=None) -> None:
    from . import audit

    actor = audit.service_audit_actor(module_id="core", service="patch-lockdown", identity="system")
    metadata = {"state": state, "honoured_module": module_id or None}
    if state in ("on", "held"):
        metadata["tasks_off"] = bool(tasks_off_now)
        metadata["approve_guard"] = bool(approve_guard_now)
    if state == "on":
        text = f"Tactical's own patch policy is switched off while {module_id} replaces Windows Patching."
    elif state == "held":
        metadata["reason"] = reason
        text = (
            f"{module_id} replaces Windows Patching, but Tactical's own patch policy is still on: Core's patch lockdown is held "
            + ("because Core has it turned off." if reason == "decision_not_recorded" else "because it could not be applied in this process.")
        )
    elif previous == "held":
        text = "The replacement of Windows Patching is gone. Core's patch lockdown was held, so it had changed nothing in Tactical's own patch policy."
    else:
        text = "Tactical's own patch policy works again: no replacement of Windows Patching is honoured."
    audit.record(
        actor=actor, module_id="core", action=AUDIT_ACTION, object_type=AUDIT_OBJECT_TYPE, object_id=AUDIT_OBJECT_ID, message=text,
        metadata=metadata, strict=False,
    )


def honoured_module():
    """The id of the module that honourably replaces Windows Patching right now, or None. Cached for ``CACHE_SECONDS``. Never raises."""
    now = _clock()
    with _LOCK:
        at = _CACHE["at"]
        if at is not None and 0 <= now - at < CACHE_SECONDS:
            return _CACHE["module"]
    module = None
    try:
        for candidate, replaced in sorted(_honoured_pairs().items()):
            if replaced == REPLACED_MODULE:
                module = candidate
                break
        _STATE["fault_logged"] = False
    except Exception:
        if not _STATE["fault_logged"]:
            _STATE["fault_logged"] = True
            logger.warning("The replacement state could not be read; Tactical's own patch policy stays on.", exc_info=True)
        module = None
    with _LOCK:
        _CACHE["at"] = now
        _CACHE["module"] = module
    return module


def active() -> bool:
    """True only while a replacement of Windows Patching is honoured right now. A read that fails answers False."""
    try:
        return honoured_module() is not None
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        return False


def approve_neutralised() -> bool:
    """True when Tactical's own approve is inert in THIS process: the lockdown is active and the guard is installed here. Core uses it to drop the
    re-approve warning from a confirmation and from the audit row of an install for the honoured replacement."""
    return bool(_STATE["guard"]) and active()


def apply_settings(target=None) -> dict:
    """Set Tactical's two documented switches to True while active. Never sets a switch to False and never changes one that is already set
    (an administrator's value stands). Returns ``{name: value}`` for the switches as they stand afterwards, or {} when inactive."""
    if not active():
        return {}
    target = _django_settings() if target is None else target
    result = {}
    for name in SETTING_NAMES:
        try:
            if hasattr(target, name):
                result[name] = bool(getattr(target, name))
                continue
            setattr(target, name, True)
            result[name] = True
        except Exception:
            logger.warning("Could not set the Tactical switch %s.", name, exc_info=True)
            result[name] = False
    _STATE["settings"] = result
    return dict(result)


def tasks_off() -> bool:
    values = _STATE["settings"]
    return bool(values) and all(values.get(name) is True for name in SETTING_NAMES)


def install_approve_guard() -> bool:
    """Wrap ``Agent.approve_updates`` once. The wrapper returns without approving while ``active()``, otherwise it calls Tactical's own method.
    Idempotent. Returns False, and the guard stays absent, when Tactical's method is not there: that fails open."""
    try:
        agent = _agent_class()
        original = agent.approve_updates
        if getattr(original, GUARD_MARKER, False):
            _STATE["guard"] = True
            return True

        @wraps(original)
        def approve_updates(self, *args, **kwargs):
            try:
                blocked = active()
            except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
                blocked = False
            if blocked:
                return None
            return original(self, *args, **kwargs)

        setattr(approve_updates, GUARD_MARKER, True)
        agent.approve_updates = approve_updates
        _STATE["guard"] = True
        return True
    except Exception:
        _STATE["guard"] = False
        logger.warning("The patch lockdown guard on Agent.approve_updates could not be installed; Tactical keeps working unchanged.", exc_info=True)
        return False


def apply_at_startup() -> dict:
    """Called from ``AppConfig.ready()`` in every process. Each step is guarded on its own; nothing raises, so Tactical always starts."""
    if not DECISION_RECORDED:
        return status()  # switched off in Core: Tactical's settings and Agent.approve_updates stay exactly as Tactical ships them
    try:
        apply_settings()
    except Exception:
        logger.warning("The patch lockdown settings could not be applied.", exc_info=True)
    install_approve_guard()
    return status()


def status() -> dict:
    return {"active": active(), "honoured_module": honoured_module(), "tasks_off": tasks_off(), "approve_guard_installed": bool(_STATE["guard"])}  # decision_recorded stays out: the contract keys are fixed


def audit_transition():
    """One audit row when the state differs from the newest lockdown row. Three states: ``on`` (the lockdown is in effect in this process),
    ``held`` (a replacement is honoured but nothing is switched off: the switch is off in Core, or applying failed in this process) and ``off`` (no replacement
    is honoured). The tick process runs ``AppConfig.ready()``, so ``apply_at_startup`` has filled the state here. Called by the Scheduler tick.
    Never raises, never strict. A lookup that cannot run writes nothing. Returns the state it wrote, or None."""
    try:
        module = honoured_module()
        reason = None
        if module is None:
            now_state = "off"
        elif in_effect():
            now_state = "on"
        else:
            now_state = "held"
            reason = "decision_not_recorded" if not DECISION_RECORDED else "not_applied"
        previous = _last_row_state()
        if previous is None and now_state == "off":
            return None  # never switched on or held: nothing to say
        if previous == now_state:
            return None
        _write_row(now_state, module, previous, reason, tasks_off(), bool(_STATE["guard"]))
        return now_state
    except Exception:
        logger.warning("The patch lockdown audit step failed; the next tick retries.", exc_info=True)
        return None


class _PatchLockdownProvider:
    def status(self) -> dict:
        return status()


_PROVIDER = _PatchLockdownProvider()


def patch_lockdown_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["status"],
        "python": "tec_tac.patch_lockdown.status() -> {active, honoured_module, tasks_off, approve_guard_installed}",
        "active_when": "a replacement of the core module patching (Advanced Patch Management) is honoured right now (AD-20); read at most every 30 seconds; a failed read means inactive",
        "guards": [
            "TRMM_DISABLE_APPROVE_UPDATES_TASK and TRMM_DISABLE_WINUPDATES_INSTALL_TASK set to True at start-up in every process, never set to False and never over an administrator's value",
            "Agent.approve_updates returns without approving while active (an update set to Ignore is no longer flipped back)",
        ],
        "not_blocked": "the declared operations a replacement registers (scan, install, set-update-action, reset, add, edit and delete patch policy) and the system actions",
        "writes_tactical_data": False,
        "fails": "open: an unreadable state or a guard that cannot be installed leaves Tactical's own patching on",
        "audit": "custom:tactical-patch-lockdown (state on, held or off, honoured_module, and for on and held which parts are in effect: tasks_off, approve_guard; held means a replacement is honoured but nothing was switched off, for example because applying failed in that process), object type tactical_patch_lockdown, written by the Scheduler tick when the state changes",
        "requires_framework": ">=1.17.68",
    }


def register_core_patch_lockdown_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Whether Tactical's own patch policy is switched off because a replacement of Windows Patching is honoured (read-only status).",
        operations=("status",),
        metadata=patch_lockdown_contract_metadata(),
    )


def _clear_for_tests() -> None:
    with _LOCK:
        _CACHE.update(at=None, module=None)
    _STATE.update(settings={}, guard=False, fault_logged=False)
