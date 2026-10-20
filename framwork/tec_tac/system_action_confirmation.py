"""System-action confirmation: the one plain Yes or No when a person creates or edits a schedule for a system action (Core 1.17.66, AD-13 as amended).

AD-13 as Johan amended it on 20 October 2026 puts the whole permission and scope check where the person acts: at creation, at edit and at a
person-started run. A scheduled run is not re-checked against its creator. So the checks below are the control, and they run in one place for
every way in (the browser route, ``reconcile_schedule`` with ``confirmed_by_request`` and ``start_one_off_run``).

What a declared system action needs at creation or edit
    1. The owning module's own permission (the action's ``permission`` entries, as the Scheduler page already reads them).
    2. Every Tactical role flag of the table row and of the registered definition. A native scheduler manager has no bypass here.
    3. The Tactical scope of every target endpoint (one miss refuses the whole call, nothing is narrowed).
    4. The targets read as endpoints (a module-owned target type stays ``targets_unresolved``), within the ceiling of 40 000 endpoints.
    5. The parameters, against the row's own schema.
    6. The module enabled now and, for a replacement, honoured now.
    7. A confirmation id that Core issued for this person, action, targets, parameters and timing in the last ten minutes.

The confirmation id proves the text was produced for that exact request. It does not prove the person pressed Yes: Core cannot see the button.
It is signed with the server's secret and never stored. A refusal writes ONE deny row (a reason code, no endpoint ids). An allowed creation or
edit writes one strict audit row naming the creator, the confirmer, the schedule, the total, the groups and the timing.

Any scheduled action that is not both listed in the module's signed manifest ``system_actions`` and registered with ``core.system_actions`` is
untouched by this file.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone as dt_timezone

from . import system_actions as _sa
from .scheduler import SchedulerNotAllowed, get_scheduled_action
from .scheduler_targets import SchedulerTargetShapeError, normalize_scheduler_targets

logger = logging.getLogger("tec_tac.system_actions")

CONFIRMATION_TTL_SECONDS = 600
_PREFIX = b"tec-tac-system-action-confirmation-v1|"
_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_WHEN_KEYS = ("schedule_type", "run_at", "run_time", "weekdays", "day_of_month", "interval_seconds", "timezone")
_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})")

_clock = time.time  # a test replaces it
_STATE = threading.local()  # ``deferred`` is True while a caller that holds a database transaction wants the deny row written after it ends


class SystemActionCreationRefused(SchedulerNotAllowed):
    """A creation, edit or one-off start of a system action schedule was refused. ``reason`` is a code of ``system_actions.REASONS``.

    ``pending`` holds the deny audit row that has not been written yet (only when the check ran with ``defer=True``, inside a transaction that
    the refusal rolls back). ``record_refusal`` writes it once the transaction is over."""

    def __init__(self, message, *, reason, pending=None):
        super().__init__(message)
        self.reason = reason
        self.pending = pending


# The few places this file reads Core. Each is one small function so a test can replace it without Django.
def _secret() -> bytes:
    from django.conf import settings

    return str(settings.SECRET_KEY).encode("utf-8")


def _can_use_action(user, action) -> bool:
    from .scheduler_views import _can_use_action as check

    return bool(check(user, action))


def _has_flag(user, flag) -> bool:
    from .rbac import has_tactical_permission

    return bool(has_tactical_permission(user, flag))


def _canonical_for_user(user, targets):
    from .scheduler_views import _canonicalize_endpoint_targets_for_user

    return _canonicalize_endpoint_targets_for_user(user, targets)


def _person_name(user) -> str:
    return str(getattr(user, "username", "") or "")[:150]


# ------------------------------------------------------------------------------------------------ what a confirmation binds
def _digest(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _norm_time(value) -> str | None:
    if value is None or value == "":
        return None
    if hasattr(value, "hour") and hasattr(value, "minute") and not hasattr(value, "year"):
        return f"{value.hour:02d}:{value.minute:02d}"
    match = _TIME_RE.match(str(value))
    return f"{int(match.group(1)):02d}:{match.group(2)}" if match else str(value)


def _norm_moment(value) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip()
        if text.lower() == "now":
            return "now"
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt_timezone.utc)
    return moment.astimezone(dt_timezone.utc).replace(second=0, microsecond=0).isoformat()


def when_key(when) -> dict:
    """The timing of a schedule in one canonical form, so the text the person saw and the data saved compare equal."""
    source = when if isinstance(when, dict) else {}
    out = {
        "schedule_type": str(source.get("schedule_type") or "").strip().lower() or None,
        "run_at": _norm_moment(source.get("run_at")),
        "run_time": _norm_time(source.get("run_time")),
        "weekdays": sorted({int(v) for v in (source.get("weekdays") or []) if isinstance(v, int) and not isinstance(v, bool)}),
        "day_of_month": source.get("day_of_month") if isinstance(source.get("day_of_month"), int) else None,
        "interval_seconds": source.get("interval_seconds") if isinstance(source.get("interval_seconds"), int) else None,
        "timezone": str(source.get("timezone") or "UTC"),
    }
    return {k: out[k] for k in _WHEN_KEYS}


def when_text(when) -> str:
    key = when_key(when)
    kind, at, zone = key["schedule_type"], key["run_time"], key["timezone"]
    if kind == "once":
        return "once, now" if key["run_at"] in (None, "now") else f"once, at {key['run_at']}"
    if kind == "daily":
        return f"every day at {at} ({zone})"
    if kind == "weekly":
        days = ", ".join(_WEEKDAYS[d] for d in key["weekdays"] if 0 <= d <= 6) or "no day"
        return f"every week on {days} at {at} ({zone})"
    if kind == "monthly":
        return f"on day {key['day_of_month']} of every month at {at} ({zone})"
    if kind == "interval":
        seconds = key["interval_seconds"] or 0
        return f"every {seconds} seconds" if seconds % 60 else f"every {seconds // 60} minutes"
    return "at the time you set"


def _targets_key(targets) -> str:
    try:
        return _digest(normalize_scheduler_targets(targets))
    except SchedulerTargetShapeError as exc:
        raise SystemActionCreationRefused(str(exc), reason="targets_unresolved") from exc


def _parameters_of(parameters):
    """The confirmed part of a schedule's parameters: the value under ``system_action_parameters`` (or None)."""
    if isinstance(parameters, dict) and _sa.PARAMETERS_KEY in parameters:
        return parameters.get(_sa.PARAMETERS_KEY)
    return None


# ------------------------------------------------------------------------------------------------ the id
def _sign(payload: bytes) -> str:
    return hmac.new(_secret(), _PREFIX + payload, hashlib.sha256).hexdigest()


def _issue(user, action_id: str, targets_key: str, params_key: str, when_digest: str) -> str:
    body = {"u": str(getattr(user, "pk", "")), "a": action_id, "t": targets_key, "p": params_key, "w": when_digest, "x": int(_clock()) + CONFIRMATION_TTL_SECONDS}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=") + "." + _sign(payload)


def _valid_id(confirmation_id, user, action_id: str, targets_key: str, params_key: str, when_digest: str) -> bool:
    try:
        if not isinstance(confirmation_id, str) or confirmation_id.count(".") != 1 or len(confirmation_id) > 1024:
            return False
        encoded, signature = confirmation_id.split(".")
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if not hmac.compare_digest(signature, _sign(payload)):
            return False
        body = json.loads(payload.decode("utf-8"))
        wanted = {"u": str(getattr(user, "pk", "")), "a": action_id, "t": targets_key, "p": params_key, "w": when_digest}
        if any(body.get(key) != value for key, value in wanted.items()):
            return False
        return int(body.get("x", 0)) >= int(_clock())
    except Exception:  # noqa: BLE001 - any malformed id is simply not valid
        return False


# ------------------------------------------------------------------------------------------------ the checks
def is_system_action_schedule(module_id, action_id) -> bool:
    """Is this scheduled action a declared system action (in the signed manifest AND registered with core.system_actions)? Read now."""
    from .scheduler import system_action_state

    return system_action_state(module_id, action_id) == "declared"


def _write_deny_row(user, reason: str, text: str, action_id, owner_module: str) -> None:
    try:
        _sa._audit().record(
            actor=user, module_id="core", action="deny", object_type="system_action", object_id=_sa._safe_action_id(action_id),
            message=f"A system action schedule was refused: {text}",
            metadata={"reason": reason, "requested_by": "person", "phase": "creation", "owner_module": owner_module[:100]},
        )
    except Exception:
        logger.exception("Tec-Tac audit row for a refused system action schedule could not be written")


def _deny(user, reason: str, action, detail: str = ""):
    text = _sa.REASONS.get(reason, "The system action was refused.") + detail
    action_id, owner_module = getattr(action, "id", None), str(getattr(action, "module_id", ""))
    if getattr(_STATE, "deferred", False):
        # the caller holds a transaction that this refusal rolls back, so the row would be lost: the caller writes it after the rollback
        raise SystemActionCreationRefused(text, reason=reason, pending=(user, reason, text, action_id, owner_module))
    _write_deny_row(user, reason, text, action_id, owner_module)
    raise SystemActionCreationRefused(text, reason=reason)


def record_refusal(exc) -> None:
    """Write the deny row of a refusal that was raised with ``defer=True``, once. Never raises. Does nothing for any other exception."""
    pending = getattr(exc, "pending", None)
    if pending:
        exc.pending = None
        _write_deny_row(*pending)


def _declaration_state(user, action) -> str:
    """``declared`` or ``not_declared``. When Core could not read the manifest or the registry (``unknown``) it refuses (1.17.67): a schedule that
    might be a system action is never created, changed or started on a guess. One deny row; the caller saves and queues nothing."""
    from .scheduler import system_action_state

    state = system_action_state(action.module_id, action.id)
    if state == "unknown":
        _deny(user, "declaration_unreadable", action)
    return state


def _controls(user, action, targets, parameters) -> dict:
    """Every creation-time check except the confirmation id. Returns what the text and the audit row need, or raises a refusal."""
    sa = _sa
    with sa._LOCK:
        definition = sa._ACTIONS.get(action.id)
    if definition is None or definition.module_id != action.module_id:
        _deny(user, "unknown_action", action)
    entry = sa.SYSTEM_FUNCTIONS.get(definition.function)
    if entry is None:
        _deny(user, "function_unavailable", action)
    if user is None or not bool(getattr(user, "is_active", False)) or bool(getattr(user, "is_installer_user", False)):
        _deny(user, "owner_inactive", action)
    try:
        enabled = sa._enabled_now(definition.module_id)
    except Exception:
        enabled = False
    if not enabled:
        _deny(user, "module_disabled", action)
    if definition.via_replacement:
        try:
            honoured = sa._honoured(definition.module_id) == entry.owner_module
        except Exception:
            honoured = False
        if not honoured:
            _deny(user, "replacement_not_honoured", action)
    try:
        may_use = _can_use_action(user, action)
    except Exception:
        may_use = False
    if not may_use:
        _deny(user, "not_permitted", action)
    for flag in sorted(set(entry.min_flags) | set(definition.permissions)):
        try:
            held = _has_flag(user, flag)
        except Exception:
            held = False
        if not held:  # no bypass for a native scheduler manager: Tactical's own role decides
            _deny(user, "not_permitted", action)
    confirmed = _parameters_of(parameters)
    if not entry.parameters:
        if confirmed not in (None, {}):
            _deny(user, "bad_parameters", action)
        cleaned = {}
    else:
        try:
            cleaned = entry.validate_parameters(confirmed if confirmed is not None else {})
        except ValueError:
            _deny(user, "bad_parameters", action)
    resolved = None
    try:
        shaped = normalize_scheduler_targets(targets)
        canonical = _canonical_for_user(user, shaped)
        resolved = sa._target_pks(canonical)
    except Exception as exc:  # noqa: BLE001 - a target outside the person's scope is a scope refusal; anything else is unresolved
        if type(exc).__name__ == "PermissionDenied":
            _deny(user, "out_of_scope", action)
    if resolved is None:
        _deny(user, "targets_unresolved", action)
    pks, vanished = resolved
    ids = sorted(int(v) for v in pks)
    if not ids or len(ids) > sa.MAX_AGENTS:
        _deny(user, "agent_count", action)
    try:
        in_scope = sa._agents_in_scope(user, ids)
    except Exception:
        in_scope = False
    if not in_scope:
        _deny(user, "out_of_scope", action)
    return {
        "definition": definition, "entry": entry, "cleaned": cleaned, "total": len(ids), "groups": len(sa._groups_of(ids)),
        "vanished": int(vanished or 0),
    }


def _text(info, user, when) -> str:
    definition, entry = info["definition"], info["entry"]
    lines = [
        f"{definition.label}: {info['total']} endpoint(s), sent to Tactical in {info['groups']} group(s) of at most {_sa.MAX_AGENTS_PER_GROUP}, {when_text(when)}.",
        "It runs as a schedule. Core does not check your rights again when it runs, so it keeps running until someone edits or removes it.",
    ]
    if entry.parameters:
        cleaned = info["cleaned"]
        lines.append(f"Script number {cleaned['script_pk']}, {len(cleaned['args'])} argument(s), time limit {cleaned['timeout']} seconds.")
    if entry.reapproves_by_policy:
        lines.append(_sa.REAPPROVE_WARNING)
    if definition.dangerous:
        lines.append("This action can change many endpoints at once.")
    if info["vanished"]:
        lines.append(f"{info['vanished']} target(s) no longer exist and are left out.")
    lines.append(f"Requested by {_person_name(user)}. Do you want to continue?")
    return " ".join(lines)


def describe_confirmation(user, action_id, targets, parameters=None, when=None) -> dict:
    """The plain Yes or No text for a schedule of a system action, and a short-lived confirmation id (1.17.66).

    Runs every creation-time check first: a person who may not create the schedule gets a refusal (and a deny row), never a text. For an action
    that is not a declared system action it answers ``{"required": False}`` and issues nothing. Raises ``SystemActionCreationRefused`` or
    ``SchedulerError`` (an unknown action)."""
    action = get_scheduled_action(str(action_id or "").strip())
    if _declaration_state(user, action) == "not_declared":
        return {"required": False, "text": None, "confirmation_id": None, "total": None, "groups": None, "expires_in": None}
    info = _controls(user, action, targets, parameters)
    params_key = _digest(_parameters_of(parameters))
    confirmation_id = _issue(user, action.id, _targets_key(targets), params_key, _digest(when_key(when)))
    return {
        "required": True, "text": _text(info, user, when), "confirmation_id": confirmation_id, "total": info["total"], "groups": info["groups"],
        "expires_in": CONFIRMATION_TTL_SECONDS,
    }


def describe_confirmation_for_request(request, *, action_id, targets, parameters=None, when=None) -> dict:
    """The capability's operation: the person is the one behind a real, session-checked ``request`` (a module cannot name one)."""
    from .scheduler import _verified_person

    return describe_confirmation(_verified_person(request), action_id, targets, parameters, when)


def require_creation(user, action, targets, parameters, when, confirmation_id, *, defer=False) -> dict | None:
    """The check a creation, an edit or a one-off start of ``action`` must pass. Returns None when the action is not a declared system action
    (nothing changes for it). Otherwise every control and a valid confirmation id are required; a refusal raises ``SystemActionCreationRefused``.
    The result carries ``total``, ``groups`` and ``when`` for the audit row.

    ``defer=True`` is for a caller that holds a database transaction the refusal rolls back (``reconcile_schedule``): the exception then carries
    the deny row in ``pending`` and the caller writes it with ``record_refusal`` after the transaction ends."""
    previous = getattr(_STATE, "deferred", False)
    _STATE.deferred = bool(defer)  # before the state call: a refusal of an unreadable declaration keeps its deny row after a rollback
    try:
        if _declaration_state(user, action) == "not_declared":
            return None
        info = _controls(user, action, targets, parameters)
        if confirmation_id in (None, ""):
            _deny(user, "confirmation_required", action)
        key = _targets_key(targets)
        if not _valid_id(confirmation_id, user, action.id, key, _digest(_parameters_of(parameters)), _digest(when_key(when))):
            _deny(user, "confirmation_invalid", action)
    finally:
        _STATE.deferred = previous
    return {"total": info["total"], "groups": info["groups"], "when": when_text(when), "vanished": info["vanished"]}


def audit_extra(info: dict | None) -> dict:
    """The counts an audit row of a created or edited schedule carries (no endpoint ids)."""
    if not info:
        return {}
    return {"total_agents": info["total"], "groups": info["groups"], "when": info["when"], **({"vanished_targets": info["vanished"]} if info.get("vanished") else {})}
