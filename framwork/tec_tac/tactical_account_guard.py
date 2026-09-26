"""Protect Tactical's native role/user editors from privilege escalation.

Tactical owns the ``/accounts/roles`` and ``/accounts/users`` endpoints, so
Tec-Tac cannot replace those source files. Core installs narrow, idempotent
wrappers around the four native mutation handlers at AppConfig.ready() time.
The wrappers run after DRF authentication and therefore have the real actor.

Only actual privilege transitions are blocked. Full-form saves that resend an
unchanged ``is_superuser`` value or the user's existing role remain valid for
ordinary Tactical role/account managers.
"""
from __future__ import annotations

import logging
from functools import wraps

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.fields import BooleanField

from accounts.models import Role, User

from .rbac import is_effective_superuser

logger = logging.getLogger("tec_tac.tactical_account_guard")
_GUARD_MARKER = "_tec_tac_superuser_guard"


def _payload_has(payload, key: str) -> bool:
    try:
        return key in payload
    except Exception:
        return False


def _payload_get(payload, key: str, default=None):
    try:
        return payload.get(key, default)
    except Exception:
        return default


def _validated_bool(value):
    """Return DRF's boolean interpretation, or None when native validation owns it."""
    try:
        return bool(BooleanField().run_validation(value))
    except (ValidationError, TypeError, ValueError):
        return None


def _role_from_payload(payload, *, for_update: bool = False):
    if not _payload_has(payload, "role"):
        return None
    raw = _payload_get(payload, "role")
    if raw in (None, ""):
        return None
    # Tactical's native user-create handler uses ``isinstance(raw, int)``.
    # In Python ``bool`` is a subclass of ``int``, so True is role pk 1 and
    # False is role pk 0. Mirror that coercion here so the Core guard cannot
    # be bypassed with a boolean role value.
    try:
        role_id = int(raw)
    except (TypeError, ValueError):
        return None
    manager = Role.objects.select_for_update() if for_update else Role.objects
    try:
        return manager.only("id", "is_superuser").get(pk=role_id)
    except (ObjectDoesNotExist, Role.DoesNotExist, ValueError, TypeError):
        return None


def _audit_denied(actor, violation: dict) -> None:
    try:
        from .audit import record
        record(
            actor=actor,
            module_id="core",
            action="deny",
            object_type=violation["object_type"],
            object_id=violation.get("object_id"),
            message="Blocked Tactical account/role privilege escalation attempt.",
            metadata=violation.get("metadata") or {},
            strict=False,
        )
    except Exception:
        logger.exception("Unable to persist Tactical privilege-escalation denial audit")


def _raise_violation(actor, violation: dict) -> None:
    _audit_denied(actor, violation)
    raise PermissionDenied(violation["detail"])


def _role_flag_violation(actor, *, role, requested: bool, operation: str):
    if is_effective_superuser(actor):
        return None
    role_id = getattr(role, "pk", getattr(role, "id", None)) if role is not None else None
    return {
        "object_type": "role_superuser_change",
        "object_id": role_id if role_id is not None else "new",
        "detail": "Only an effective superuser may change Tactical role superuser status.",
        "metadata": {
            "operation": operation,
            "current_is_superuser": None if role is None else bool(getattr(role, "is_superuser", False)),
            "requested_is_superuser": bool(requested),
        },
    }


def _superuser_role_assignment_violation(actor, *, target_user_id, role, operation: str):
    if is_effective_superuser(actor):
        return None
    return {
        "object_type": "superuser_role_assignment",
        "object_id": target_user_id if target_user_id is not None else "new",
        "detail": "Only an effective superuser may assign a Tactical superuser role.",
        "metadata": {
            "operation": operation,
            "role_id": getattr(role, "pk", getattr(role, "id", None)),
        },
    }


def _role_create_violation(actor, payload):
    if not _payload_has(payload, "is_superuser"):
        return None
    requested = _validated_bool(_payload_get(payload, "is_superuser"))
    if requested is not True:
        return None
    return _role_flag_violation(actor, role=None, requested=True, operation="create")


def _role_update_violation(actor, role, payload):
    if role is None or not _payload_has(payload, "is_superuser"):
        return None
    requested = _validated_bool(_payload_get(payload, "is_superuser"))
    if requested is None:
        return None
    current = bool(getattr(role, "is_superuser", False))
    if requested == current:
        return None
    return _role_flag_violation(actor, role=role, requested=requested, operation="update")


def _user_create_violation(actor, payload, *, role=None):
    role = role if role is not None else _role_from_payload(payload)
    if role is None or not bool(getattr(role, "is_superuser", False)):
        return None
    return _superuser_role_assignment_violation(
        actor,
        target_user_id=_payload_get(payload, "username") or "new",
        role=role,
        operation="create",
    )


def _user_update_violation(actor, user, payload, *, role=None):
    if user is None or not _payload_has(payload, "role"):
        return None
    role = role if role is not None else _role_from_payload(payload)
    if role is None or not bool(getattr(role, "is_superuser", False)):
        return None
    current_role_id = getattr(user, "role_id", None)
    requested_role_id = getattr(role, "pk", getattr(role, "id", None))
    if requested_role_id == current_role_id:
        return None
    return _superuser_role_assignment_violation(
        actor,
        target_user_id=getattr(user, "pk", getattr(user, "id", None)),
        role=role,
        operation="update",
    )


# Direct guard helpers are intentionally kept small for focused regression tests.
def _guard_role_create(actor, payload) -> None:
    violation = _role_create_violation(actor, payload)
    if violation:
        _raise_violation(actor, violation)


def _guard_role_update(actor, role, payload) -> None:
    violation = _role_update_violation(actor, role, payload)
    if violation:
        _raise_violation(actor, violation)


def _guard_user_create(actor, payload) -> None:
    violation = _user_create_violation(actor, payload)
    if violation:
        _raise_violation(actor, violation)


def _guard_user_update(actor, user, payload) -> None:
    violation = _user_update_violation(actor, user, payload)
    if violation:
        _raise_violation(actor, violation)


def _mark_guarded(fn):
    setattr(fn, _GUARD_MARKER, True)
    return fn


def _already_guarded(fn) -> bool:
    return bool(getattr(fn, _GUARD_MARKER, False))


def _wrap_role_create(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        violation = _role_create_violation(request.user, request.data)
        if violation:
            _raise_violation(request.user, violation)
        return original(self, request, *args, **kwargs)
    return _mark_guarded(guarded)


def _wrap_role_update(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        violation = None
        with transaction.atomic():
            role = Role.objects.select_for_update().only("id", "is_superuser").filter(pk=pk).first()
            violation = _role_update_violation(request.user, role, request.data)
            if violation is None:
                return original(self, request, pk, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _wrap_user_create(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        violation = None
        if _payload_has(request.data, "role"):
            with transaction.atomic():
                role = _role_from_payload(request.data, for_update=True)
                violation = _user_create_violation(request.user, request.data, role=role)
                if violation is None:
                    return original(self, request, *args, **kwargs)
            _raise_violation(request.user, violation)
        return original(self, request, *args, **kwargs)
    return _mark_guarded(guarded)


def _wrap_user_update(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        violation = None
        with transaction.atomic():
            user = User.objects.select_for_update().only("id", "role_id").filter(pk=pk).first()
            role = _role_from_payload(request.data, for_update=True) if _payload_has(request.data, "role") else None
            violation = _user_update_violation(request.user, user, request.data, role=role)
            if violation is None:
                return original(self, request, pk, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def install_tactical_account_guard() -> None:
    """Install idempotent wrappers around Tactical's native role/user editors."""
    from accounts import views as tactical_views

    if not _already_guarded(tactical_views.GetAddRoles.post):
        tactical_views.GetAddRoles.post = _wrap_role_create(tactical_views.GetAddRoles.post)
    if not _already_guarded(tactical_views.GetUpdateDeleteRole.put):
        tactical_views.GetUpdateDeleteRole.put = _wrap_role_update(tactical_views.GetUpdateDeleteRole.put)
    if not _already_guarded(tactical_views.GetAddUsers.post):
        tactical_views.GetAddUsers.post = _wrap_user_create(tactical_views.GetAddUsers.post)
    if not _already_guarded(tactical_views.GetUpdateDeleteUser.put):
        tactical_views.GetUpdateDeleteUser.put = _wrap_user_update(tactical_views.GetUpdateDeleteUser.put)
