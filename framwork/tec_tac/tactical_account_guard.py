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

from accounts.models import APIKey, Role, User

from .account_security_policy import protection_enabled
from .rbac import is_effective_superuser

logger = logging.getLogger("tec_tac.tactical_account_guard")
_GUARD_MARKER = "_tec_tac_superuser_guard"
_MESH_TASK_PROXY_MARKER = "_tec_tac_commit_aware_mesh_sync"


class _CommitAwareTaskProxy:
    """Defer Tactical's Mesh permission sync until the guard transaction commits."""

    def __init__(self, task):
        self._task = task
        setattr(self, _MESH_TASK_PROXY_MARKER, True)

    def delay(self, *args, **kwargs):
        connection = transaction.get_connection()
        if bool(getattr(connection, "in_atomic_block", False)):
            saved_kwargs = dict(kwargs)
            transaction.on_commit(
                lambda task=self._task, args=tuple(args), kwargs=saved_kwargs: task.delay(*args, **kwargs)
            )
            return None
        return self._task.delay(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._task, name)


def _install_commit_aware_mesh_sync(tactical_views) -> None:
    task = getattr(tactical_views, "sync_mesh_perms_task", None)
    if task is None or bool(getattr(task, _MESH_TASK_PROXY_MARKER, False)):
        return
    tactical_views.sync_mesh_perms_task = _CommitAwareTaskProxy(task)


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


def _is_superuser_account(user) -> bool:
    if user is None:
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    role = getattr(user, "role", None)
    if role is not None:
        return bool(getattr(role, "is_superuser", False))
    role_id = getattr(user, "role_id", None)
    if not role_id:
        return False
    try:
        return bool(Role.objects.only("is_superuser").get(pk=role_id).is_superuser)
    except Exception:
        return False


def _protected_account_violation(actor, target_user, *, operation: str):
    if not protection_enabled():
        return None
    if target_user is None or not _is_superuser_account(target_user):
        return None
    if is_effective_superuser(actor):
        return None
    target_id = getattr(target_user, "pk", getattr(target_user, "id", None))
    return {
        "object_type": "superuser_account_protection",
        "object_id": target_id if target_id is not None else "unknown",
        "detail": "Superuser account protection requires effective superuser authority for this action.",
        "metadata": {"operation": operation},
    }


def _locked_user(user_id):
    try:
        return (
            User.objects.select_for_update(of=("self",))
            .only("id", "is_superuser", "role_id")
            .filter(pk=user_id)
            .first()
        )
    except (TypeError, ValueError):
        return None


def _user_id_from_payload(payload):
    """Resolve Tactical UserActions' request.data["id"] target only."""
    if not _payload_has(payload, "id"):
        return None
    raw = _payload_get(payload, "id")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _api_key_user_id_from_payload(payload):
    """Resolve the APIKeySerializer owner field exactly as Tactical saves it.

    Tactical's APIKeySerializer persists ``user``.  ``id`` is the API-key
    object's read-only identifier and must never influence owner authorization.
    A malformed explicit ``user`` is denied by the guard instead of being
    passed through to a later serializer stage, keeping the D1 boundary closed.
    """
    if not _payload_has(payload, "user"):
        return None, False
    raw = _payload_get(payload, "user")
    try:
        return int(raw), False
    except (TypeError, ValueError):
        return None, True


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
    if role is None:
        return None
    current = bool(getattr(role, "is_superuser", False))
    # Tactical's RoleSerializer handles PUT as a full update.  A missing
    # BooleanField therefore resolves to False rather than preserving the
    # current value.  Mirror that persisted result here so form-encoded PUTs
    # cannot silently demote a superuser role outside the R5 guard.
    if _payload_has(payload, "is_superuser"):
        requested = _validated_bool(_payload_get(payload, "is_superuser"))
        if requested is None:
            return None
    else:
        requested = False
    if requested == current:
        return None
    return _role_flag_violation(actor, role=role, requested=requested, operation="update")


def _role_delete_violation(actor, role):
    if role is None or not bool(getattr(role, "is_superuser", False)):
        return None
    return _role_flag_violation(actor, role=role, requested=False, operation="delete")


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
    protected = _protected_account_violation(actor, user, operation="update_user")
    if protected:
        return protected
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


def _wrap_role_delete(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        violation = None
        with transaction.atomic():
            role = Role.objects.select_for_update().only("id", "is_superuser").filter(pk=pk).first()
            violation = _role_delete_violation(request.user, role)
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
            user = _locked_user(pk)
            role = _role_from_payload(request.data, for_update=True) if _payload_has(request.data, "role") else None
            violation = _user_update_violation(request.user, user, request.data, role=role)
            if violation is None:
                return original(self, request, pk, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _wrap_user_delete(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        with transaction.atomic():
            user = _locked_user(pk)
            violation = _protected_account_violation(request.user, user, operation="delete_user")
            if violation is None:
                return original(self, request, pk, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _wrap_user_action(original, operation: str):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        user_id = _user_id_from_payload(request.data)
        if user_id is None:
            return original(self, request, *args, **kwargs)
        with transaction.atomic():
            user = _locked_user(user_id)
            violation = _protected_account_violation(request.user, user, operation=operation)
            if violation is None:
                return original(self, request, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _wrap_self_user_action(original, operation: str):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        violation = _protected_account_violation(request.user, request.user, operation=operation)
        if violation:
            _raise_violation(request.user, violation)
        return original(self, request, *args, **kwargs)
    return _mark_guarded(guarded)


def _api_key_target(apikey=None, payload=None, *, for_update=False):
    payload = payload or {}
    if _payload_has(payload, "user"):
        user_id, invalid = _api_key_user_id_from_payload(payload)
        if invalid:
            raise PermissionDenied("Invalid API key user target.")
        if user_id is not None:
            return _locked_user(user_id) if for_update else User.objects.select_related("role").filter(pk=user_id).first()
    if apikey is None:
        return None
    try:
        return apikey.user
    except Exception:
        return None


def _wrap_api_key_list(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        response = original(self, request, *args, **kwargs)
        if not protection_enabled() or is_effective_superuser(request.user):
            return response

        data = getattr(response, "data", None)
        if not isinstance(data, list):
            return response

        protected_owner_ids = {}
        for item in data:
            if not isinstance(item, dict) or "user" not in item:
                continue
            raw_user_id = item.get("user")
            try:
                user_id = int(raw_user_id)
            except (TypeError, ValueError):
                continue
            if user_id not in protected_owner_ids:
                user = User.objects.select_related("role").filter(pk=user_id).first()
                protected_owner_ids[user_id] = bool(user and _is_superuser_account(user))
            if protected_owner_ids[user_id] and "key" in item:
                item["key"] = "[REDACTED]"
        return response
    return _mark_guarded(guarded)


def _wrap_api_key_create(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        user_id, invalid = _api_key_user_id_from_payload(request.data)
        if invalid:
            raise PermissionDenied("Invalid API key user target.")
        if user_id is None:
            return original(self, request, *args, **kwargs)
        with transaction.atomic():
            target = _locked_user(user_id)
            violation = _protected_account_violation(request.user, target, operation="create_api_key")
            if violation is None:
                return original(self, request, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _wrap_api_key_mutation(original, operation: str):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        with transaction.atomic():
            apikey = APIKey.objects.select_for_update(of=("self",)).select_related("user").filter(pk=pk).first()
            current_target = _api_key_target(apikey)
            violation = _protected_account_violation(request.user, current_target, operation=operation)
            if violation is None and operation == "update_api_key":
                requested_target = _api_key_target(apikey, request.data, for_update=True)
                violation = _protected_account_violation(request.user, requested_target, operation=operation)
            if violation is None:
                return original(self, request, pk, *args, **kwargs)
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def install_tactical_account_guard() -> None:
    """Install idempotent wrappers around Tactical's native account security mutations."""
    from accounts import views as tactical_views

    _install_commit_aware_mesh_sync(tactical_views)
    wrappers = [
        (tactical_views.GetAddRoles, "post", _wrap_role_create),
        (tactical_views.GetUpdateDeleteRole, "put", _wrap_role_update),
        (tactical_views.GetUpdateDeleteRole, "delete", _wrap_role_delete),
        (tactical_views.GetAddUsers, "post", _wrap_user_create),
        (tactical_views.GetUpdateDeleteUser, "put", _wrap_user_update),
        (tactical_views.GetUpdateDeleteUser, "delete", _wrap_user_delete),
        (tactical_views.UserActions, "post", lambda fn: _wrap_user_action(fn, "reset_password")),
        (tactical_views.UserActions, "put", lambda fn: _wrap_user_action(fn, "reset_totp")),
        (tactical_views.GetAddAPIKeys, "get", _wrap_api_key_list),
        (tactical_views.GetAddAPIKeys, "post", _wrap_api_key_create),
        (tactical_views.GetUpdateDeleteAPIKey, "put", lambda fn: _wrap_api_key_mutation(fn, "update_api_key")),
        (tactical_views.GetUpdateDeleteAPIKey, "delete", lambda fn: _wrap_api_key_mutation(fn, "delete_api_key")),
        (tactical_views.TOTPSetup, "post", lambda fn: _wrap_self_user_action(fn, "setup_totp")),
        (tactical_views.ResetPass, "put", lambda fn: _wrap_self_user_action(fn, "reset_self_password")),
        (tactical_views.Reset2FA, "put", lambda fn: _wrap_self_user_action(fn, "reset_self_totp")),
    ]
    for view_cls, method, wrapper in wrappers:
        original = getattr(view_cls, method)
        if not _already_guarded(original):
            setattr(view_cls, method, wrapper(original))
