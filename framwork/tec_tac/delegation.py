"""Delegation: how one module starts another module's scheduled system action for a person who confirmed it once (Core 1.17.68, S4).

The problem. Maintenance runs a patch step later, in its own Celery engine, with nobody signed in and after its Scheduler run has ended.
Advanced Patch Management (APM) owns the install. ``run_system_action`` answers only the module that owns the run (``wrong_module`` stays as it is) and
``describe_confirmation`` needs a person's own request, so neither can serve Maintenance. This module is the supported path. It adds no way to reach
Tactical: the work is still ``run_system_action`` inside a Core one-off run, with its groups, its at-most-once marks and its strict audit rows.

The path, all checked by Core from the call stack, never from an argument:

1. The provider (APM) registers its system action with ``delegable_to=("maintenance",)``. That only names who may ask.
2. When a person saves a Maintenance profile, Maintenance calls ``describe_delegation(request, ...)``. Core runs every creation-time check for that
   person (the action's permission, every Tactical flag with no bypass for a scheduler manager, scope of every resolved endpoint, count, parameters,
   module enabled, replacement honoured) and answers the plain Yes or No text and a 600 second confirmation id with its own signature prefix, so an
   id issued for a schedule cannot be reused here. Maintenance shows the text in the shell's dialog.
3. On Yes, Maintenance calls ``register_delegation_grant(request, ..., confirmation_id=...)``. Core stores a grant: the confirmed action, targets and
   parameters, the person (by row and by stored name) and the person's Tactical scope at that moment. At most 20 grants per owner module. A second
   person who registers the same grant takes it over (scope stored again, one strict audit row), and only if their own scope covers every target.
   ``remove_delegation_grant`` removes it.
4. In its own LIVE Scheduler run, Maintenance calls ``issue_delegation_ticket(context, grant_key=...)``. The ticket is signed, bound to that run, the
   grant and the grant as it is now (a digest that changes with every edit), and valid for 24 hours.
5. The patch step hands the ticket to APM. APM calls ``start_delegated_run(ticket, action_id=..., agent_ids=...)``. Core re-reads the grant (still there,
   enabled, same digest, so any profile edit or removal revokes every ticket), the module and its replacement, the declaration of the action, resolves
   the grant's targets and the stored scope, and refuses any endpoint outside them or above the ceiling. Then it creates APM's own one-off schedule and
   run: ``created_by`` is the person who confirmed, the targets are exactly the endpoints passed, the parameters are exactly what was confirmed plus a
   marker Core signed for that schedule. APM's handler calls the unchanged ``run_system_action``.

Why the run is not re-checked against the person. A scheduled run is not re-checked against its creator (AD-13 condition 2 as amended). A one-off run
a person starts is. This one-off is the continuation of a schedule the person confirmed, so it is treated as unattended, but ONLY while its marker
verifies (HMAC with the server's secret, bound to this schedule) and its grant is still enabled with the same digest. Every other one-off keeps all
of its re-checks (CQ50). A grant is revoked by editing or removing it; nothing else is needed.

Retry. A call with the same ticket and the same endpoints always names the same one-off run, so a retry returns that run and never starts a second install.

Nothing here widens a scope. The endpoints of a run are inside the grant's targets AND the person's stored scope. A person who takes a grant over must
cover every target with their own scope, or nothing changes. Honest limit: modules share Core's process, so code that reaches into Core's private state
is outside what this stops (docs/caller-identity.md).

Every read of Core is one small function so a test can replace it without Django.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
import uuid

from django.db import transaction
from django.utils import timezone

from . import scheduler_creation_scope
from . import scheduler_run_context as _run_context
from . import system_actions as _sa
from .scheduler import (
    SchedulerNotAllowed,
    SchedulerPermanentError,
    SchedulerTransientError,
    get_scheduled_action,
    is_one_off_key,
)

logger = logging.getLogger("tec_tac.system_actions")

TICKET_TTL_SECONDS = 24 * 3600
CONFIRMATION_TTL_SECONDS = 600
MAX_GRANTS_PER_OWNER = 20
MARKER_KEY = "system_action_delegation"
# Johan signed the delegated start on 21 October 2026 (AD-43, CQ204, with AD-42 and AD-44). A delegated one-off skips the run-time owner re-check (CQ50, AD-13 condition 2)
# only when this is True, and then only for a run whose signed marker, grant, grant digest and provider module all still hold. False is the switch that makes a delegated
# one-off an ordinary one-off again: the owner's permission and scope are re-checked at run time and a disabled owner fails closed.
# tests/delegation-ticket-1.17.68.py pins this value to the documents.
DECISION_RECORDED = True
_GRANT_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9:_.-]{0,119}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CONFIRMATION_PREFIX = b"tec-tac-delegation-confirmation-v1|"
_TICKET_PREFIX = b"tec-tac-delegation-ticket-v1|"
_MARKER_PREFIX = b"tec-tac-delegated-run-v1|"

_clock = time.time  # a test replaces it

REASONS = {
    "caller_unverified": "Core could not tell which module is calling.",
    "wrong_module": "Only the module named for this step may make this call.",
    "no_person": "A grant needs the signed-in person's own request.",
    "bad_grant_key": "The grant key must be 1 to 120 lowercase letters, digits and : _ . - characters.",
    "bad_module": "The module ids are not valid.",
    "unknown_action": "This system action is not registered, or it is not a scheduled action of the provider.",
    "not_delegable": "The provider has not allowed this module to start this action for someone else.",
    "action_not_declared": "This action is no longer listed in the module's signed manifest under system_actions.",
    "module_disabled": "A module this grant needs is not enabled.",
    "replacement_not_honoured": "The module that registered this action no longer replaces the core module right now.",
    "grant_limit": f"A module may hold at most {MAX_GRANTS_PER_OWNER} delegation grants.",
    "confirmation_required": "This grant needs the Yes or No confirmation, and none came with the request.",
    "confirmation_invalid": "The confirmation does not match this person, module, action, endpoints and parameters, or it has expired. Ask again.",
    "takeover_out_of_scope": "You cannot take over this grant: some of its targets are outside your Tactical scope.",
    "context_invalid": "This is not a scheduler run context that Core issued for a run that is still going.",
    "grant_missing": "There is no such delegation grant.",
    "grant_disabled": "This delegation grant is switched off.",
    "grant_changed": "This delegation grant was edited or removed after the ticket was issued, so the ticket no longer works.",
    "ticket_invalid": "The ticket is not valid.",
    "ticket_expired": "The ticket has expired.",
    "creation_scope_unavailable": "This grant has no stored scope, so nothing was started.",
    "targets_unresolved": "Core cannot read this grant's targets as endpoints, so nothing was started.",
    "bad_agents": "The endpoint list is not a list of whole endpoint numbers.",
    "agent_count": f"A delegated run takes 1 to {_sa.MAX_AGENTS} endpoints.",
    "ticket_used": "This ticket already started a run for other endpoints. A ticket starts one run, so nothing was started.",
    "outside_grant": "At least one endpoint is outside what this grant covers, so nothing was started.",
    "queue_failed": "The run could not be queued. Try again.",
}


class DelegationRefused(SchedulerNotAllowed, SchedulerPermanentError):
    """A delegation call was refused. ``reason`` is a code of ``REASONS``; the message is plain text and names no endpoint and no id. A
    ``SchedulerNotAllowed`` (a person or module may not) and a ``SchedulerPermanentError`` (never retried)."""

    def __init__(self, message, *, reason="refused"):
        super().__init__(message)
        self.reason = reason


# ------------------------------------------------------------------------------------------------ the places this file reads Core
def _secret() -> bytes:
    from django.conf import settings

    return str(settings.SECRET_KEY).encode("utf-8")


def _grants():
    from .models import TecTacDelegationGrant

    return TecTacDelegationGrant.objects


def _schedules():
    from .models import TecTacSchedule

    return TecTacSchedule


def _runs():
    from .models import TecTacScheduleRun

    return TecTacScheduleRun


def _person(request):
    from .scheduler import _verified_person

    return _verified_person(request)


def _controls(person, action, targets, parameters, owner_module):
    from . import system_action_confirmation as confirmation

    return confirmation._controls(person, action, targets, parameters, resolver_module=owner_module)


def _canonical_targets(person, targets):
    from . import system_action_confirmation as confirmation
    from .scheduler_targets import normalize_scheduler_targets

    return confirmation._canonical_for_user(person, normalize_scheduler_targets(targets))


def _targets_key(targets) -> str:
    from . import system_action_confirmation as confirmation

    return confirmation._targets_key(targets)


def _parameters_of(parameters):
    from . import system_action_confirmation as confirmation

    return confirmation._parameters_of(parameters)


def _person_covers(person, action, targets) -> bool:
    from .scheduler import _person_covers_targets

    return bool(_person_covers_targets(person, action, targets))


def _run_kwargs(schedule, **extra):
    from .scheduler import _run_kwargs as build

    return build(schedule, **extra)


def _queue(run):
    from .scheduler import _queue_run

    return _queue_run(run)


def _agent_rows(*, pks, snapshot, limit):
    from . import resources_adapter

    return resources_adapter.agent_rows_in_scope(pks=pks, snapshot=snapshot, limit=limit)


def _audit():
    from . import audit

    return audit


def _service_actor():
    return _audit().service_audit_actor(module_id="core", service="delegation", identity="system")


# ------------------------------------------------------------------------------------------------ small helpers
def _digest(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _name(person) -> str:
    return str(getattr(person, "username", "") or "")[:150]


def _sign(prefix: bytes, body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(_secret(), prefix + payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=") + "." + signature


def _open(prefix: bytes, token) -> dict | None:
    """The body of a token Core signed with ``prefix``, or None for anything else (wrong shape, wrong signature, wrong kind). Expiry is the caller's."""
    try:
        if not isinstance(token, str) or token.count(".") != 1 or len(token) > 4096:
            return None
        encoded, signature = token.split(".")
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        expected = hmac.new(_secret(), prefix + payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        body = json.loads(payload.decode("utf-8"))
        return body if isinstance(body, dict) else None
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        return None


def grant_digest(grant) -> str:
    """What a ticket is bound to. It changes with every save of the grant (``updated_at``), so editing or re-registering revokes every ticket."""
    updated = getattr(grant, "updated_at", None)
    return _digest({
        "g": str(grant.pk), "o": grant.owner_module, "k": grant.grant_key, "p": grant.provider_module, "a": grant.action_id, "t": grant.targets,
        "q": grant.parameters_digest, "u": str(getattr(getattr(grant, "created_by", None), "pk", "") or ""), "n": grant.created_by_username,
        "e": bool(grant.enabled), "w": updated.isoformat() if hasattr(updated, "isoformat") else str(updated or ""),
    })


def _deny(reason: str, *, caller: str = "", person=None, owner_module="", provider_module="", action_id=None, grant=None, text=None):
    """One deny row (not strict) and the refusal. A caller that Core cannot place is written at most once per five minutes per reason."""
    message = text or REASONS.get(reason, "The delegation was refused.")
    if reason != "caller_unverified" or _sa._unmatched_due(reason, caller):
        try:
            metadata = {"reason": reason, "requested_by": "delegation"}
            if owner_module:
                metadata["owner_module"] = str(owner_module)[:100]
            if provider_module:
                metadata["provider_module"] = str(provider_module)[:100]
            if grant is not None:
                metadata["grant_key"] = str(getattr(grant, "grant_key", ""))[:120]
            _audit().record(
                actor=person if person is not None else _service_actor(), module_id="core", action="deny", object_type="delegation_grant",
                object_id=str(getattr(grant, "pk", "")) or None, message=f"A delegation was refused: {message}", metadata=metadata,
            )
        except Exception:
            logger.exception("Tec-Tac audit row for a refused delegation could not be written")
    raise DelegationRefused(message, reason=reason)


def _need_caller(caller: str, expected: str, **meta) -> None:
    if not caller:
        _deny("caller_unverified", caller="", **meta)
    if caller != expected:
        _deny("wrong_module", caller=caller, **meta)


class _Rollback(Exception):
    """Internal: a refusal found inside a transaction. The transaction rolls back first, then the deny row is written (an audit row written inside
    it would be rolled back with it)."""

    def __init__(self, reason, grant=None):
        super().__init__(reason)
        self.reason, self.grant = reason, grant


def _check_ids(owner_module, provider_module, meta: dict) -> None:
    if not isinstance(owner_module, str) or not _ID_RE.fullmatch(owner_module) or not isinstance(provider_module, str) or not _ID_RE.fullmatch(provider_module):
        _deny("bad_module", **meta)


def _provider_action(owner_module: str, provider_module: str, action_id, **extra):
    """``(scheduled action, definition, function row)`` when the provider's system action may be delegated to ``owner_module``, else a refusal.
    ``extra`` (person, grant, caller) only goes into the deny row."""
    meta = {"owner_module": owner_module, "provider_module": provider_module, "action_id": action_id if isinstance(action_id, str) else None, **extra}
    with _sa._LOCK:
        definition = _sa._ACTIONS.get(action_id) if isinstance(action_id, str) else None
    if definition is None or definition.module_id != provider_module:
        _deny("unknown_action", **meta)
    try:
        action = get_scheduled_action(action_id)
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        action = None
    if action is None or action.module_id != provider_module:
        _deny("unknown_action", **meta)
    if owner_module not in definition.delegable_to:
        _deny("not_delegable", **meta)
    entry = _sa.SYSTEM_FUNCTIONS.get(definition.function)
    if entry is None:
        _deny("unknown_action", **meta)
    if not _sa._declared_now(provider_module, action_id):
        _deny("action_not_declared", **meta)
    for module in (provider_module, owner_module):
        try:
            enabled = _sa._enabled_now(module)
        except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
            enabled = False
        if not enabled:
            _deny("module_disabled", **meta)
    if definition.via_replacement:
        try:
            honoured = _sa._honoured(provider_module) == entry.owner_module
        except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
            honoured = False
        if not honoured:
            _deny("replacement_not_honoured", **meta)
    return action, definition, entry


def _text(info: dict, person, owner_module: str, definition, entry) -> str:
    lines = [
        f"{definition.label}: {info['total']} endpoint(s), sent to Tactical in {info['groups']} group(s) of at most {_sa.MAX_AGENTS_PER_GROUP}.",
        f"{owner_module} will start this for you later, with nobody signed in, each time its own schedule says so.",
        (
            "Each time, Core checks that this confirmation is unchanged, that the modules involved are on, that the replacement is still in place, "
            "and that every endpoint is inside the targets you confirm here and inside what you can reach as of this confirmation."
        ),
        "Core does not look at your account again, so the run goes on even if your account is later disabled. Editing or removing the profile stops it.",
    ]
    if _sa._reapprove_warning_applies(definition, entry):
        lines.append(_sa.REAPPROVE_WARNING)
    if definition.dangerous:
        lines.append("This action can change many endpoints at once.")
    if info["vanished"]:
        lines.append(f"{info['vanished']} target(s) no longer exist and are left out.")
    lines.append(f"Requested by {_name(person)}. Do you want to continue?")
    return " ".join(lines)


def _confirmation_body(person, owner_module, provider_module, action_id, targets, parameters) -> dict:
    return {
        "u": str(getattr(person, "pk", "")), "o": owner_module, "p": provider_module, "a": action_id,
        "t": _targets_key(targets), "q": _digest(_parameters_of(parameters)),
    }


# ------------------------------------------------------------------------------------------------ describe and register (the person's own request)
def describe(caller: str, request, *, owner_module, provider_module, action_id, targets, parameters=None) -> dict:
    """The plain Yes or No text for a delegation grant and a confirmation id. Every creation-time control runs first, so a person who may not
    create the grant gets a refusal and a deny row, never a text."""
    meta = {"owner_module": owner_module, "provider_module": provider_module, "action_id": action_id if isinstance(action_id, str) else None}
    _check_ids(owner_module, provider_module, meta)
    _need_caller(caller, owner_module, **meta)
    try:
        person = _person(request)
    except SchedulerNotAllowed:
        _deny("no_person", caller=caller, **meta)
    action, definition, entry = _provider_action(owner_module, provider_module, action_id, person=person, caller=caller)
    info = _controls(person, action, targets, parameters, owner_module)
    body = _confirmation_body(person, owner_module, provider_module, action_id, targets, parameters)
    token = _sign(_CONFIRMATION_PREFIX, {**body, "x": int(_clock()) + CONFIRMATION_TTL_SECONDS})
    return {
        "required": True, "text": _text(info, person, owner_module, definition, entry), "confirmation_id": token, "total": info["total"],
        "groups": info["groups"], "expires_in": CONFIRMATION_TTL_SECONDS,
    }


def _confirmation_ok(token, person, owner_module, provider_module, action_id, targets, parameters) -> bool:
    body = _open(_CONFIRMATION_PREFIX, token)
    if body is None:
        return False
    wanted = _confirmation_body(person, owner_module, provider_module, action_id, targets, parameters)
    if any(body.get(key) != value for key, value in wanted.items()):
        return False
    try:
        return int(body.get("x", 0)) >= int(_clock())
    except (TypeError, ValueError):
        return False


def _grant_audit(person, grant, verb: str, message: str, extra: dict) -> None:
    """One STRICT audit row for a grant. The change is in the caller's transaction, so a row that cannot be written stops it."""
    creator, confirmed = grant.created_by_username, grant.confirmed_by_username
    try:
        _audit().record(
            actor=person, module_id="core", action=verb, object_type="delegation_grant", object_id=str(grant.pk), message=message,
            metadata={
                "owner_module": grant.owner_module, "grant_key": grant.grant_key, "provider_module": grant.provider_module, "action_id": grant.action_id,
                "requested_by": "person", "creator": creator, "confirmed_by": confirmed, "enabled": bool(grant.enabled), **extra,
            },
            strict=True,
        )
    except Exception as exc:
        raise SchedulerTransientError("The audit row of this delegation could not be written, so nothing was changed.") from exc


def register(caller: str, request, *, owner_module, grant_key, provider_module, action_id, targets, parameters=None, confirmation_id=None) -> dict:
    """Store (or replace) the grant a person confirmed. Returns ``{grant_key, created, owner_changed}``."""
    meta = {"owner_module": owner_module, "provider_module": provider_module, "action_id": action_id if isinstance(action_id, str) else None}
    _check_ids(owner_module, provider_module, meta)
    _need_caller(caller, owner_module, **meta)
    if not isinstance(grant_key, str) or not _GRANT_KEY_RE.fullmatch(grant_key):
        _deny("bad_grant_key", caller=caller, **meta)
    try:
        person = _person(request)
    except SchedulerNotAllowed:
        _deny("no_person", caller=caller, **meta)
    action, _definition, _entry = _provider_action(owner_module, provider_module, action_id, person=person, caller=caller)
    info = _controls(person, action, targets, parameters, owner_module)
    if confirmation_id in (None, ""):
        _deny("confirmation_required", caller=caller, person=person, **meta)
    if not _confirmation_ok(confirmation_id, person, owner_module, provider_module, action_id, targets, parameters):
        _deny("confirmation_invalid", caller=caller, person=person, **meta)
    canonical = _canonical_targets(person, targets)
    name = _name(person)
    try:
        with transaction.atomic():
            existing = _grants().select_for_update().filter(owner_module=owner_module, grant_key=grant_key).first()
            if existing is None and len([g for g in _grants().filter(owner_module=owner_module)]) >= MAX_GRANTS_PER_OWNER:
                raise _Rollback("grant_limit")
            owner_move = None
            if existing is None:
                grant = _grants().model(owner_module=owner_module, grant_key=grant_key, created_by=person, created_by_username=name)
            else:
                grant = existing
                if _owner_differs(grant, person):
                    if not _person_covers(person, action, canonical):  # the person's own scope, no bypass: ownership never widens a grant
                        raise _Rollback("takeover_out_of_scope", grant)
                    owner_move = {"owner_changed_from": grant.created_by_username, "owner_changed_to": name, "previous_confirmed_by": grant.confirmed_by_username}
                    grant.created_by, grant.created_by_username = person, name
            grant.provider_module, grant.action_id = provider_module, action_id
            grant.targets, grant.parameters = canonical, (parameters if isinstance(parameters, dict) else {})
            grant.parameters_digest = _digest(_parameters_of(parameters))
            grant.confirmed_by_username = name
            grant.creation_scope = scheduler_creation_scope.capture(person)
            grant.enabled = True
            grant.save()
            _grant_audit(
                person, grant, "add" if existing is None else "modify",
                "A person confirmed a delegation grant." if existing is None else "A person changed a delegation grant." + (" The ownership moved to them." if owner_move else ""),
                {"total_agents": info["total"], "groups": info["groups"], **(owner_move or {})},
            )
    except _Rollback as refusal:
        _deny(refusal.reason, caller=caller, person=person, grant=refusal.grant, **meta)
    return {"grant_key": grant_key, "created": existing is None, "owner_changed": bool(owner_move)}


def _owner_differs(grant, person) -> bool:
    owner = getattr(grant, "created_by", None)
    if owner is not None:
        return getattr(owner, "pk", None) != getattr(person, "pk", None)
    return str(grant.created_by_username or "").casefold() != _name(person).casefold()


def remove(caller: str, *, owner_module, grant_key) -> bool:
    """Remove a grant. True when there was one. Every ticket made for it stops working."""
    meta = {"owner_module": owner_module if isinstance(owner_module, str) else ""}
    if not isinstance(owner_module, str) or not _ID_RE.fullmatch(owner_module):
        _deny("bad_module", **meta)
    _need_caller(caller, owner_module, **meta)
    if not isinstance(grant_key, str) or not _GRANT_KEY_RE.fullmatch(grant_key):
        _deny("bad_grant_key", caller=caller, **meta)
    with transaction.atomic():
        grant = _grants().select_for_update().filter(owner_module=owner_module, grant_key=grant_key).first()
        if grant is None:
            return False
        try:
            _audit().record(
                actor=_service_actor(), module_id="core", action="delete", object_type="delegation_grant", object_id=str(grant.pk),
                message="A delegation grant was removed.",
                metadata={"owner_module": owner_module, "grant_key": grant_key, "provider_module": grant.provider_module, "action_id": grant.action_id,
                          "requested_by": "module", "creator": grant.created_by_username, "confirmed_by": grant.confirmed_by_username},
                strict=True,
            )
        except Exception as exc:
            raise SchedulerTransientError("The audit row of this delegation could not be written, so nothing was changed.") from exc
        grant.delete()
    return True


# ------------------------------------------------------------------------------------------------ the ticket (the owner module's live run)
def issue_ticket(caller: str, context, *, grant_key) -> str:
    meta = {}
    run_id = _run_context._issued_run_id(context)
    run = None
    try:
        run = _runs().objects.filter(pk=run_id).first() if run_id is not None else None
    except Exception:
        logger.warning("The run behind a delegation ticket request could not be read.", exc_info=True)
    if run is None:
        _deny("context_invalid", caller=caller, **meta)
    module_id = str(run.module_id or "")
    meta = {"owner_module": module_id}
    try:
        _run_context.verify_run_context(context, expected_module_id=module_id, expected_action_id=str(run.action_id or ""), require_owner=False)
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        _deny("context_invalid", caller=caller, **meta)
    _need_caller(caller, module_id, **meta)
    if not isinstance(grant_key, str) or not _GRANT_KEY_RE.fullmatch(grant_key):
        _deny("bad_grant_key", caller=caller, **meta)
    grant = _grants().filter(owner_module=module_id, grant_key=grant_key).first()
    if grant is None:
        _deny("grant_missing", caller=caller, **meta)
    if not grant.enabled:
        _deny("grant_disabled", caller=caller, grant=grant, **meta)
    return _sign(_TICKET_PREFIX, {
        "r": str(run.id), "g": str(grant.pk), "d": grant_digest(grant), "o": module_id, "p": grant.provider_module,
        "x": int(_clock()) + TICKET_TTL_SECONDS,
    })


# ------------------------------------------------------------------------------------------------ the start (the provider module)
def _marker(schedule_id, grant, digest: str) -> str:
    return _sign(_MARKER_PREFIX, {"s": str(schedule_id), "g": str(grant.pk), "d": digest})


def run_is_validly_delegated(run) -> bool:
    """Is ``run`` the one-off ``start`` made, with a marker Core signed for its own schedule, while the grant is still there, enabled and unchanged?
    Never raises: any doubt answers False, and the run keeps every re-check."""
    try:
        if not DECISION_RECORDED:
            return False  # held: no accepted decision yet, so a delegated one-off keeps every re-check
        parameters = getattr(run, "parameters_snapshot", None)
        token = parameters.get(MARKER_KEY) if isinstance(parameters, dict) else None
        body = _open(_MARKER_PREFIX, token)
        if body is None:
            return False
        schedule_id = str(getattr(run, "schedule_snapshot_id", None) or getattr(run, "schedule_id", None) or "")
        if not schedule_id or body.get("s") != schedule_id:
            return False
        if getattr(run, "owner_type", "") != "module" or not is_one_off_key(getattr(run, "owner_key", "")):
            return False
        grant = _grants().filter(pk=body.get("g")).first()
        if grant is None or not grant.enabled or grant.provider_module != getattr(run, "owner_module", None):
            return False
        return grant_digest(grant) == body.get("d")
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        return False


def start(caller: str, ticket, *, action_id, agent_ids, name=None):
    """Create and queue the provider's own one-off run for the grant behind ``ticket``. Returns the queued run."""
    meta = {"action_id": action_id if isinstance(action_id, str) else None}
    if not caller:
        _deny("caller_unverified", caller="", **meta)
    body = _open(_TICKET_PREFIX, ticket)
    if body is None:
        _deny("ticket_invalid", caller=caller, provider_module=caller, **meta)
    meta.update(provider_module=caller, owner_module=str(body.get("o") or ""))
    try:
        if int(body.get("x", 0)) < int(_clock()):
            _deny("ticket_expired", caller=caller, **meta)
    except (TypeError, ValueError):
        _deny("ticket_invalid", caller=caller, **meta)
    grant = _grants().filter(pk=body.get("g")).first()
    if grant is None:
        _deny("grant_missing", caller=caller, **meta)
    if not grant.enabled:
        _deny("grant_disabled", caller=caller, grant=grant, **meta)
    digest = grant_digest(grant)
    if digest != body.get("d") or grant.owner_module != body.get("o") or grant.provider_module != body.get("p"):
        _deny("grant_changed", caller=caller, grant=grant, **meta)
    if grant.provider_module != caller:
        _deny("wrong_module", caller=caller, grant=grant, **meta)
    if grant.action_id != action_id:
        _deny("unknown_action", caller=caller, grant=grant, **meta)
    action, _definition, _entry = _provider_action(grant.owner_module, caller, action_id, grant=grant, caller=caller)
    ids, reason = _sa._agent_ids(agent_ids)
    if reason:
        _deny(reason, caller=caller, grant=grant, **meta)
    snapshot = scheduler_creation_scope.snapshot_of(grant)
    if snapshot is None:
        _deny("creation_scope_unavailable", caller=caller, grant=grant, **meta)
    try:
        resolved = _sa._target_pks(grant.targets or {}, grant.owner_module)
    except Exception:
        logger.warning("The targets of a delegation grant could not be resolved; nothing is started.", exc_info=True)
        resolved = None
    if resolved is None:
        _deny("targets_unresolved", caller=caller, grant=grant, **meta)
    if not set(ids) <= {int(pk) for pk in resolved[0]}:
        _deny("outside_grant", caller=caller, grant=grant, **meta)
    try:
        rows = _agent_rows(pks=ids, snapshot=snapshot, limit=_sa.MAX_AGENTS)
    except Exception:
        logger.warning("The endpoints of a delegated run could not be read.", exc_info=True)
        raise SchedulerTransientError("Core could not read the endpoints just now. Try again.") from None
    if {int(row["pk"]) for row in rows} != set(ids):
        _deny("outside_grant", caller=caller, grant=grant, **meta)  # an endpoint outside the person's stored scope, or one that is gone
    # One ticket names one run: the key holds the ticket, the grant and the action but not the endpoints. The same endpoints again is a
    # retry and answers the earlier run; any other endpoint list on the same ticket is refused, so one ticket never starts several installs.
    call_key = uuid.UUID(_digest({"r": body.get("r"), "g": str(grant.pk), "d": digest, "a": action_id}))
    owner_key = f"one-off:{call_key}"
    schedules = _schedules()
    existing = schedules.objects.filter(owner_module=caller, owner_key=owner_key).first()
    if existing is not None:
        earlier = (existing.targets or {}).get("ids") if isinstance(existing.targets, dict) else None
        if not isinstance(earlier, list) or {str(x) for x in earlier} != {str(row["agent_id"]) for row in rows}:
            _deny("ticket_used", caller=caller, grant=grant, **meta)
        previous = existing.runs.order_by("-created_at").first()
        if previous is not None:
            # Whatever happened to it, the earlier run is the answer: a failed or unknown run is never started again from here, because its marks
            # may show a send. Only a run that was created but never handed to the queue (a crash between the two) is queued now; a worker claims a
            # run exactly once, so a second hand-over is harmless.
            if str(getattr(previous, "status", "")) == "queued" and not getattr(previous, "celery_task_id", ""):
                try:
                    _queue(previous)
                except Exception as exc:
                    raise SchedulerTransientError(REASONS["queue_failed"]) from exc
            return previous
    now = timezone.now()
    targets = {"type": "endpoint", "ids": [row["agent_id"] for row in rows]}
    schedule_id = uuid.uuid4()
    parameters = {**(grant.parameters if isinstance(grant.parameters, dict) else {}), MARKER_KEY: _marker(schedule_id, grant, digest)}
    label = str(name or f"{action.label} · delegated").strip()[:255]
    with transaction.atomic():
        schedule = schedules.objects.create(
            id=schedule_id, name=label, module_id=action.module_id, action_id=action.id, target_mode=schedules.TargetMode.SNAPSHOT, targets=targets,
            target_state="valid", target_state_detail="", parameters=parameters, schedule_type=schedules.ScheduleType.ONCE, timezone="UTC", run_at=now,
            owner_type=schedules.OwnerType.MODULE, owner_module=caller, owner_key=owner_key, enabled=False,
            created_by=grant.created_by, updated_by=grant.created_by, created_by_username=grant.created_by_username,
            confirmed_by_username=grant.confirmed_by_username, creation_scope=grant.creation_scope, retry_count=0, retry_delay_seconds=60,
        )
        run = _runs().objects.create(**_run_kwargs(schedule, scheduled_for=now, manual=True, targets_snapshot=targets))
        try:
            _audit().record(
                actor=grant.created_by if grant.created_by is not None else _service_actor(), module_id="core", action="add", object_type="scheduler_run",
                object_id=str(run.id), message=f"Module {grant.owner_module} started a delegated run of {action.id} through {caller}.",
                metadata={
                    "owner_module": grant.owner_module, "provider_module": caller, "action_id": action.id, "grant_key": grant.grant_key,
                    "requested_by": "delegation", "creator": grant.created_by_username, "confirmed_by": grant.confirmed_by_username,
                    "total_agents": len(ids), "groups": len(_sa._groups_of(ids)), "ticket_run_id": str(body.get("r") or ""),
                },
                strict=True,
            )
        except Exception as exc:
            raise SchedulerTransientError("The audit row of this delegated run could not be written, so nothing was started.") from exc
    try:
        _queue(run)
    except Exception as exc:
        schedule.delete()
        raise SchedulerTransientError(REASONS["queue_failed"]) from exc
    return run
