"""Protect Tactical's native role/user editors from privilege escalation.

Tactical owns the ``/accounts/roles`` and ``/accounts/users`` endpoints, so
Tec-Tac cannot replace those source files. Core installs narrow, idempotent
wrappers around the four native mutation handlers at AppConfig.ready() time.
The wrappers run after DRF authentication and therefore have the real actor.

Only actual privilege transitions are blocked. Full-form saves that resend an
unchanged ``is_superuser`` value or the user's existing role remain valid for
ordinary Tactical role/account managers.

1.17.26: the three API key writes (create, edit, delete) also write one strict Core audit row each, in the guard's transaction. The
row names the key's id, name and owner. It never carries the key value: the key field is never read for the row.

1.17.28 (CQ84 a, Johan: "enforce the guard, superuser only"): Tactical's SSO provider and settings writes (ee/sso/views.py) are wrapped
the same way. Only an effective superuser may add, edit or delete a provider, save the SSO settings or disconnect an SSO account; anyone
else gets 403 and one Core deny row before the body is read, a holder of can_manage_accounts included. A settings save that would leave
local sign-in blocked with no provider row, and a delete of the last provider while local sign-in is blocked, are refused with 409
sso_lockout_guard and nothing is kept: a delete is checked before Tactical is called, and a settings save is checked on the state Tactical
stored, inside the guard's transaction, and rolled back when it would lock everyone out. The provider list shows the client secret as [REDACTED] to anyone who is not an
effective superuser. Each successful write writes one strict Core audit row in the same transaction. The client id and the secret are
never stored in a row, only the names of the fields an edit changed.
"""
from __future__ import annotations

import importlib
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


ROLE_SCOPE_AUDIT_CAP = 1000


def _relation_ids(role, name: str):
    """The sorted ids a role relation lists, or None when the role object has no such relation (a lightweight test stub)."""
    relation = getattr(role, name, None)
    if relation is None:
        return None
    return sorted({int(value) for value in relation.values_list("pk", flat=True)})


def _role_scope_lists(role_id):
    """``{"clients": [ids], "sites": [ids]}`` for one role, or None when the role is gone or exposes no scope relations.

    Reads ``can_view_clients`` and ``can_view_sites`` only (ids, never names). Both lists empty is Tactical's unrestricted role.
    """
    if role_id is None:
        return None
    role = Role.objects.filter(pk=role_id).first()
    if role is None:
        return None
    clients = _relation_ids(role, "can_view_clients")
    sites = _relation_ids(role, "can_view_sites")
    if clients is None or sites is None:
        return None
    return {"clients": clients, "sites": sites}


def _scope_audit_view(lists: dict | None) -> dict:
    """The audited form of a role's lists: sorted ids capped at ROLE_SCOPE_AUDIT_CAP, with a count and a truncated flag."""
    lists = lists or {"clients": [], "sites": []}
    view = {}
    for key in ("clients", "sites"):
        ids = list(lists.get(key) or [])
        view[key] = {
            "ids": ids[:ROLE_SCOPE_AUDIT_CAP],
            "count": len(ids),
            "truncated": len(ids) > ROLE_SCOPE_AUDIT_CAP,
        }
    return view


def _audit_role_scope_change(actor, *, role_id, action: str, before: dict | None, after: dict | None) -> bool:
    """Write one strict Core audit row when a role's client or site list changed (1.17.22). Returns True when a row was written.

    Tactical's own audit compares a serialisation at save time and the serializer sets many-to-many fields afterwards, so a
    change that only touches these two lists leaves no Tactical audit row. The write is strict: it runs inside the guard's
    transaction, so a failed audit write rolls the role save back. Ids only, never names.
    """
    if after is None:
        return False
    before_lists = before or {"clients": [], "sites": []}
    if before_lists.get("clients") == after.get("clients") and before_lists.get("sites") == after.get("sites"):
        return False
    from .audit import record
    try:
        record(
            actor=actor,
            module_id="core",
            action=action,
            object_type="role_scope",
            object_id=str(role_id),
            message="Tactical role client and site lists changed.",
            before=_scope_audit_view(before_lists),
            after=_scope_audit_view(after),
            metadata={"role_id": int(role_id)},
            strict=True,
        )
    except Exception as exc:
        raise RuntimeError("A role scope change requires a persisted Core audit record.") from exc
    return True


def _succeeded(response) -> bool:
    status = getattr(response, "status_code", 200)
    return isinstance(status, int) and status < 400


def _created_role_id(ids_before: set, name):
    """The id of the one role a successful create added, or a RuntimeError (1.17.23).

    One new id is the created role. When a concurrent create committed in between, the new ids whose name equals the request
    name are kept, and exactly one must remain. Zero new ids, or an ambiguous set, raises: the guard's transaction then rolls
    Tactical's create back, as a failed audit write does."""
    new_ids = set(Role.objects.values_list("pk", flat=True)) - ids_before
    if len(new_ids) > 1:
        new_ids = set(Role.objects.filter(pk__in=new_ids, name=name).values_list("pk", flat=True)) if name else set()
    if len(new_ids) != 1:
        raise RuntimeError("A role create must be matched to exactly one new role.")
    return int(next(iter(new_ids)))


def _wrap_role_create(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        violation = _role_create_violation(request.user, request.data)
        if violation:
            _raise_violation(request.user, violation)
        # Tactical's create answers with text only, so find the new role by comparing the role ids before and after, inside one
        # transaction (1.17.23). The table is small. An empty table works, and a created role is never skipped silently.
        with transaction.atomic():
            ids_before = set(Role.objects.values_list("pk", flat=True))
            response = original(self, request, *args, **kwargs)
            if _succeeded(response):
                created = _created_role_id(ids_before, _payload_get(request.data, "name"))
                _audit_role_scope_change(
                    request.user, role_id=created, action="add",
                    before=None, after=_role_scope_lists(created),
                )
            return response
    return _mark_guarded(guarded)


def _wrap_role_update(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        violation = None
        with transaction.atomic():
            role = Role.objects.select_for_update().only("id", "is_superuser").filter(pk=pk).first()
            violation = _role_update_violation(request.user, role, request.data)
            if violation is None:
                before = _role_scope_lists(role.pk) if role is not None else None
                response = original(self, request, pk, *args, **kwargs)
                if before is not None and _succeeded(response):
                    _audit_role_scope_change(
                        request.user, role_id=role.pk, action="modify",
                        before=before, after=_role_scope_lists(role.pk),
                    )
                return response
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


API_KEY_AUDIT_OBJECT = "api_key"
API_KEY_NAME_AUDIT_MAX = 100


def _api_key_owner(apikey):
    """(owner id, owner username) of a key, or (None, None). Reads the owner row only, never the key value."""
    try:
        owner = apikey.user
        return getattr(owner, "pk", getattr(owner, "id", None)), str(getattr(owner, "username", "") or "") or None
    except Exception:
        return None, None


def _api_key_expiry_text(value):
    if value is None:
        return None
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def _api_key_audit_view(apikey) -> dict:
    """The audited form of a key: id, name, owner and expiry. The key value is NEVER read here."""
    owner_id, owner_name = _api_key_owner(apikey)
    return {
        "id": getattr(apikey, "pk", getattr(apikey, "id", None)),
        "name": str(getattr(apikey, "name", "") or "")[:API_KEY_NAME_AUDIT_MAX],
        "owner": owner_name,
        "owner_id": owner_id,
        "expiration": _api_key_expiry_text(getattr(apikey, "expiration", None)),
    }


def _audit_api_key(actor, *, action: str, view: dict | None, before=None, after=None, metadata: dict | None = None) -> None:
    """One strict Core audit row for a successful API key write (1.17.26). ``view`` names the key; it holds no key value.

    The write is strict: it runs inside the guard's transaction, so a failed audit write rolls the Tactical change back. The row
    carries ids, names and the expiry only."""
    from .audit import record

    view = view or {}
    key_id = view.get("id")
    try:
        record(
            actor=actor,
            module_id="core",
            action=action,
            object_type=API_KEY_AUDIT_OBJECT,
            object_id=None if key_id is None else str(key_id),
            message="Tactical API key " + {"add": "created", "modify": "edited", "delete": "deleted"}[action] + ".",
            before=before,
            after=after,
            metadata={"name": view.get("name"), "owner": view.get("owner"), "owner_id": view.get("owner_id"), **(metadata or {})},
            strict=True,
        )
    except Exception as exc:
        raise RuntimeError("An API key change requires a persisted Core audit record.") from exc


def _created_api_key(name, user_id):
    """The one key a successful create added, found by name and owner, or None. Tactical's key names are unique."""
    if not isinstance(name, str) or not name:
        return None
    try:
        query = APIKey.objects.select_related("user").filter(name=name)
        if user_id is not None:
            query = query.filter(user_id=user_id)
        rows = list(query[:2])
    except Exception:
        logger.exception("Unable to look up the API key a create added")
        return None
    return rows[0] if len(rows) == 1 else None


def _wrap_api_key_create(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        user_id, invalid = _api_key_user_id_from_payload(request.data)
        if invalid:
            raise PermissionDenied("Invalid API key user target.")
        with transaction.atomic():
            violation = None
            if user_id is not None:
                target = _locked_user(user_id)
                violation = _protected_account_violation(request.user, target, operation="create_api_key")
            if violation is None:
                name = _payload_get(request.data, "name")
                response = original(self, request, *args, **kwargs)
                if _succeeded(response):
                    created = _created_api_key(name, user_id)
                    if created is not None:
                        view = _api_key_audit_view(created)
                        _audit_api_key(request.user, action="add", view=view, after={k: view[k] for k in ("name", "owner", "expiration")})
                    else:
                        # Never skipped: the row goes out with no id and a count of what was found.
                        shown = name[:API_KEY_NAME_AUDIT_MAX] if isinstance(name, str) else None
                        _audit_api_key(request.user, action="add", view={"id": None, "name": shown, "owner": None, "owner_id": user_id},
                                       metadata={"matched": 0})
                return response
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
                before = _api_key_audit_view(apikey) if apikey is not None else None
                response = original(self, request, pk, *args, **kwargs)
                if before is not None and _succeeded(response):
                    _audit_api_key_write(request.user, operation, pk, before)
                return response
        _raise_violation(request.user, violation)
    return _mark_guarded(guarded)


def _audit_api_key_write(actor, operation: str, pk, before: dict) -> None:
    """The row of a successful edit or delete. An edit row names the changed fields, with owner and expiry before and after."""
    if operation == "delete_api_key":
        _audit_api_key(actor, action="delete", view=before, before={k: before[k] for k in ("name", "owner", "expiration")})
        return
    current = APIKey.objects.select_related("user").filter(pk=pk).first()
    after = _api_key_audit_view(current) if current is not None else before
    changed = [field for field in ("name", "owner", "expiration") if before.get(field) != after.get(field)]
    _audit_api_key(
        actor, action="modify", view=after,
        before={field: before[field] for field in ("name", "owner", "expiration")},
        after={field: after[field] for field in ("name", "owner", "expiration")},
        metadata={"changed": changed},
    )


# ----------------------------------------------------------------------------------------------- SSO admin (1.17.28, CQ84 a)
SSO_AUDIT_PROVIDER = "sso_provider"
SSO_AUDIT_SETTINGS = "sso_settings"
SSO_AUDIT_ACCOUNT = "sso_account"
SSO_AUDIT_SETTINGS_ID = "sso_settings"
SSO_SUPERUSER_OBJECT = "sso_admin_superuser_required"
SSO_LOCKOUT_OBJECT = "sso_lockout_guard"
SSO_SUPERUSER_DETAIL = "Only a Tec-Tac superuser may change SSO providers or SSO settings."
SSO_LOCKOUT_CODE = "sso_lockout_guard"
SSO_LOCKOUT_TEXT = (
    "Local sign-in cannot be blocked while no SSO provider exists. Add a working SSO provider first, or leave local sign-in open."
)
SSO_REDACTED = "[REDACTED]"
SSO_SECRET_FIELD = "secret"
SSO_CHANGE_FIELDS = ("name", "client_id", "secret", "server_url", "role")  # the names an edit may list as changed
SSO_NAME_AUDIT_MAX = 255


class _SSOLockoutRefused(Exception):
    """Raised inside the guard's transaction so that nothing is kept. It is caught outside the transaction, where the deny row is written."""

    def __init__(self, operation: str, object_id=None):
        super().__init__(operation)
        self.operation = operation
        self.object_id = object_id


def _audit_sso_deny(actor, *, object_type: str, object_id, operation: str, message: str) -> None:
    """One best-effort Core deny row. It names the operation and the object id, and never a value, a secret or a Tactical text."""
    try:
        from .audit import record

        record(
            actor=actor, module_id="core", action="deny", object_type=object_type,
            object_id=None if object_id is None else str(object_id), message=message,
            metadata={"operation": operation}, strict=False,
        )
    except Exception:
        logger.exception("Unable to persist the SSO admin denial audit")


def _deny_sso_not_superuser(request, operation: str, object_id=None):
    _audit_sso_deny(
        request.user, object_type=SSO_SUPERUSER_OBJECT, object_id=object_id, operation=operation,
        message="Blocked an SSO change by someone who is not a Tec-Tac superuser.",
    )
    raise PermissionDenied(SSO_SUPERUSER_DETAIL)


def _refuse_sso_lockout(request, refused: _SSOLockoutRefused):
    """The 409 answer for a lock-out refusal: one deny row, a plain sentence and the code. Nothing was kept."""
    from rest_framework.response import Response

    _audit_sso_deny(
        request.user, object_type=SSO_LOCKOUT_OBJECT, object_id=refused.object_id, operation=refused.operation,
        message="Blocked an SSO change that would lock every local user out.",
    )
    return Response({"detail": SSO_LOCKOUT_TEXT, "code": SSO_LOCKOUT_CODE}, status=409)


def _lock_core_settings():
    """Tactical's CoreSettings row, locked until the transaction ends (None when there is none). Every SSO admin write takes it first,
    so two administrators queue behind each other and cannot both pass the lock-out check."""
    from core.models import CoreSettings

    return CoreSettings.objects.select_for_update().order_by("pk").first()


def _stored_sso_state(row) -> dict:
    """The two Tactical settings Core reads for SSO, as stored."""
    return {
        "sso_enabled": bool(getattr(row, "sso_enabled", False)),
        "block_local_user_logon": bool(getattr(row, "block_local_user_logon", False)),
    }


def _provider_count(exclude_pk=None) -> int:
    from allauth.socialaccount.models import SocialApp

    query = SocialApp.objects.all()
    if exclude_pk is not None:
        query = query.exclude(pk=exclude_pk)
    return query.count()


def _locks_out(state: dict, providers: int) -> bool:
    """True when local sign-in would be blocked with no provider row to sign in through (CQ89 a: a row is what counts)."""
    return bool(state.get("block_local_user_logon")) and providers == 0


def _requested_sso_state(data):
    """The state Tactical stores for a body of two real booleans. Tactical's own failsafe clears the block when SSO is off, so the
    block is kept only with SSO on. None for any other body: then the state Tactical stored is checked after its save instead."""
    if not _payload_has(data, "sso_enabled") or not _payload_has(data, "block_local_user_logon"):
        return None
    sso = _payload_get(data, "sso_enabled")
    block = _payload_get(data, "block_local_user_logon")
    if not isinstance(sso, bool) or not isinstance(block, bool):
        return None
    return {"sso_enabled": sso, "block_local_user_logon": block and sso}


def _audit_sso_settings(actor, before: dict, after: dict) -> None:
    """One strict row per successful settings save, with the stored state before and after (the failsafe is visible)."""
    from .audit import record

    try:
        record(
            actor=actor, module_id="core", action="modify", object_type=SSO_AUDIT_SETTINGS, object_id=SSO_AUDIT_SETTINGS_ID,
            message="Tactical SSO settings changed.", before=dict(before), after=dict(after), strict=True,
        )
    except Exception as exc:
        raise RuntimeError("An SSO settings change requires a persisted Core audit record.") from exc


def _provider_view(app) -> dict:
    """The audited form of a provider: name, provider id, server URL and role. Never the client id or the secret."""
    settings = getattr(app, "settings", None)
    if not isinstance(settings, dict):
        settings = {}
    return {
        "name": str(getattr(app, "name", "") or "")[:SSO_NAME_AUDIT_MAX],
        "provider_id": str(getattr(app, "provider_id", "") or "")[:SSO_NAME_AUDIT_MAX],
        "server_url": settings.get("server_url"),
        "role": settings.get("role"),
    }


def _provider_row(pk):
    from allauth.socialaccount.models import SocialApp

    return SocialApp.objects.filter(pk=pk).first()


def _provider_snapshot(app) -> dict:
    """The audited view plus the two secret fields, kept in memory only to decide which names an edit changed. Never written."""
    settings = getattr(app, "settings", None)
    if not isinstance(settings, dict):
        settings = {}
    return {
        **_provider_view(app),
        "client_id": getattr(app, "client_id", None),
        "secret": getattr(app, "secret", None),
    }


def _audit_sso_provider(actor, *, action: str, object_id, before, after, metadata: dict) -> None:
    """One strict row per successful provider write, in the guard's transaction. ``metadata`` holds the view, or the view plus the
    names of the fields an edit changed. Client ids and secrets are never in it."""
    from .audit import record

    try:
        record(
            actor=actor, module_id="core", action=action, object_type=SSO_AUDIT_PROVIDER,
            object_id=None if object_id is None else str(object_id),
            message="Tactical SSO provider " + {"add": "created", "modify": "edited", "delete": "deleted"}[action] + ".",
            before=before, after=after, metadata=metadata, strict=True,
        )
    except Exception as exc:
        raise RuntimeError("An SSO provider change requires a persisted Core audit record.") from exc


def _created_provider(ids_before: set, name):
    """The one provider a successful create added, found by comparing the ids before and after (1.17.28). When a concurrent create
    committed in between, the new ids with the requested name are kept. None when exactly one cannot be found."""
    from allauth.socialaccount.models import SocialApp

    new_ids = set(SocialApp.objects.values_list("pk", flat=True)) - ids_before
    if len(new_ids) > 1 and isinstance(name, str):
        new_ids = set(SocialApp.objects.filter(pk__in=new_ids, name=name).values_list("pk", flat=True))
    if len(new_ids) != 1:
        return None
    return SocialApp.objects.filter(pk=next(iter(new_ids))).first()


def _sso_account_snapshot(data):
    """The audited parts of the account a disconnect names: the Tactical user id, the provider and the username. None when the body
    names no account. The external uid is read to find the row and is never kept."""
    from allauth.socialaccount.models import SocialAccount

    uid = _payload_get(data, "account")
    provider = _payload_get(data, "provider")
    if not isinstance(uid, (str, int)) or isinstance(uid, bool) or not isinstance(provider, str):
        return None
    account = SocialAccount.objects.select_related("user").filter(uid=uid, provider=provider).first()
    if account is None:
        return None
    return {
        "user_id": account.user_id,
        "provider": str(account.provider or ""),
        "username": str(getattr(account.user, "username", "") or ""),
    }


def _audit_sso_account(actor, snapshot: dict) -> None:
    from .audit import record

    try:
        record(
            actor=actor, module_id="core", action="delete", object_type=SSO_AUDIT_ACCOUNT, object_id=str(snapshot["user_id"]),
            message="Tactical SSO account disconnected.",
            metadata={"provider": snapshot["provider"], "username": snapshot["username"]}, strict=True,
        )
    except Exception as exc:
        raise RuntimeError("An SSO account disconnect requires a persisted Core audit record.") from exc


def _wrap_sso_provider_list(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        response = original(self, request, *args, **kwargs)
        if is_effective_superuser(request.user):
            return response
        data = getattr(response, "data", None)
        if not isinstance(data, list):
            return response
        for item in data:
            if isinstance(item, dict) and SSO_SECRET_FIELD in item:
                item[SSO_SECRET_FIELD] = SSO_REDACTED
        return response
    return _mark_guarded(guarded)


def _wrap_sso_provider_add(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        if not is_effective_superuser(request.user):
            _deny_sso_not_superuser(request, "add_provider")
        with transaction.atomic():
            _lock_core_settings()
            ids_before = set(_provider_ids())
            response = original(self, request, *args, **kwargs)
            if _succeeded(response):
                name = _payload_get(request.data, "name")
                created = _created_provider(ids_before, name)
                if created is not None:
                    view = _provider_view(created)
                    _audit_sso_provider(request.user, action="add", object_id=created.pk, before=None, after=view, metadata=dict(view))
                else:
                    # Never skipped: the row goes out with no id and a count of what was found.
                    shown = str(name)[:SSO_NAME_AUDIT_MAX] if isinstance(name, str) else None
                    _audit_sso_provider(request.user, action="add", object_id=None, before=None, after=None,
                                        metadata={"name": shown, "matched": 0})
            return response
    return _mark_guarded(guarded)


def _provider_ids():
    from allauth.socialaccount.models import SocialApp

    return SocialApp.objects.values_list("pk", flat=True)


def _wrap_sso_provider_edit(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        if not is_effective_superuser(request.user):
            _deny_sso_not_superuser(request, "edit_provider", object_id=pk)
        with transaction.atomic():
            _lock_core_settings()
            app = _provider_row(pk)
            if app is None:
                return original(self, request, pk, *args, **kwargs)  # Tactical answers 404; no row
            before = _provider_snapshot(app)
            response = original(self, request, pk, *args, **kwargs)
            if _succeeded(response):
                now = _provider_snapshot(_provider_row(pk) or app)
                changed = [field for field in SSO_CHANGE_FIELDS if before.get(field) != now.get(field)]
                view_before = {key: before[key] for key in ("name", "provider_id", "server_url", "role")}
                view_after = {key: now[key] for key in ("name", "provider_id", "server_url", "role")}
                _audit_sso_provider(request.user, action="modify", object_id=pk, before=view_before, after=view_after,
                                    metadata={**view_after, "changed": changed})
            return response
    return _mark_guarded(guarded)


def _wrap_sso_provider_delete(original):
    @wraps(original)
    def guarded(self, request, pk, *args, **kwargs):
        if not is_effective_superuser(request.user):
            _deny_sso_not_superuser(request, "delete_provider", object_id=pk)
        try:
            with transaction.atomic():
                settings_row = _lock_core_settings()
                app = _provider_row(pk)
                if app is None:
                    return original(self, request, pk, *args, **kwargs)  # Tactical answers 404; no row
                if bool(_stored_sso_state(settings_row)["block_local_user_logon"]) and _provider_count(exclude_pk=pk) == 0:
                    raise _SSOLockoutRefused("delete_provider", pk)
                view = _provider_view(app)
                response = original(self, request, pk, *args, **kwargs)
                if _succeeded(response):
                    _audit_sso_provider(request.user, action="delete", object_id=pk, before=view, after=None, metadata=dict(view))
                return response
        except _SSOLockoutRefused as refused:
            return _refuse_sso_lockout(request, refused)
    return _mark_guarded(guarded)


def _wrap_sso_settings_save(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        if not is_effective_superuser(request.user):
            _deny_sso_not_superuser(request, "save_settings", object_id=SSO_AUDIT_SETTINGS_ID)
        try:
            with transaction.atomic():
                before = _stored_sso_state(_lock_core_settings())
                requested = _requested_sso_state(request.data)
                if requested is not None and _locks_out(requested, _provider_count()):
                    raise _SSOLockoutRefused("save_settings", SSO_AUDIT_SETTINGS_ID)
                response = original(self, request, *args, **kwargs)
                if not _succeeded(response):
                    return response  # Tactical refused (its licence answer, 423): nothing changed, no row
                # The state Tactical stored, after its own failsafe. This is what the lock-out rule reads when the body was not two booleans.
                after = _stored_sso_state(_lock_core_settings())
                if _locks_out(after, _provider_count()):
                    raise _SSOLockoutRefused("save_settings", SSO_AUDIT_SETTINGS_ID)
                _audit_sso_settings(request.user, before, after)
                return response
        except _SSOLockoutRefused as refused:
            return _refuse_sso_lockout(request, refused)
    return _mark_guarded(guarded)


def _wrap_sso_disconnect(original):
    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        if not is_effective_superuser(request.user):
            _deny_sso_not_superuser(request, "disconnect_account")
        with transaction.atomic():
            _lock_core_settings()
            snapshot = _sso_account_snapshot(request.data)
            response = original(self, request, *args, **kwargs)
            if snapshot is not None and _succeeded(response):
                _audit_sso_account(request.user, snapshot)
            return response
    return _mark_guarded(guarded)


def _install_sso_wrappers() -> None:
    """Wrap Tactical's SSO admin handlers in place (1.17.28, CQ84 a). Sign-in routes (the token, the OIDC callback, the allauth
    routes) are not touched. Without ee.sso, the wrappers are skipped with one log line."""
    try:
        # import_module, not ``from ee.sso import views``: a None entry in sys.modules would make that statement return None silently.
        sso_views = importlib.import_module("ee.sso.views")
    except ImportError:
        logger.info("Tactical's SSO views (ee.sso) are not installed; the SSO admin guard is not installed.")
        return
    wrappers = [
        (sso_views.GetAddSSOProvider, "get", _wrap_sso_provider_list),
        (sso_views.GetAddSSOProvider, "post", _wrap_sso_provider_add),
        (sso_views.GetUpdateDeleteSSOProvider, "put", _wrap_sso_provider_edit),
        (sso_views.GetUpdateDeleteSSOProvider, "delete", _wrap_sso_provider_delete),
        (sso_views.GetUpdateSSOSettings, "post", _wrap_sso_settings_save),
        (sso_views.DisconnectSSOAccount, "delete", _wrap_sso_disconnect),
    ]
    for view_cls, method, wrapper in wrappers:
        original = getattr(view_cls, method)
        if not _already_guarded(original):
            setattr(view_cls, method, wrapper(original))


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
    _install_sso_wrappers()
