"""Core saved views service (Core 1.17.0).

One table for every module's saved views: a named payload (filters and layout only)
under a module id and a view key, owned by the user who created it.

Rules:

* ``readers`` empty means shared with everyone. ``readers`` not empty means private to the
  owner and the listed user ids. A view only the owner can read has ``readers = [owner id]``.
* Only the owner edits or deletes. There is no administrator override.
* A user who cannot read a private view gets "not found", so its existence does not leak.
  A user who can read it but is not the owner gets "permission denied" on change or delete.
* Reader ids are returned to the owner only. Everyone else sees a ``shared`` flag.
* A module with permission groups needs one of its grants. A permissionless module needs a
  signed-in user only. Tactical's own permissions still decide what the user can do in the module.
* Create, change and delete write a Core audit row inside the same transaction. The row never
  holds the payload. A failed audit write rolls the change back.

Removing a module leaves its views in place, like user preferences.
"""
from __future__ import annotations

import json
import re
import uuid
from contextlib import nullcontext
from typing import Any

from .models import TecTacSavedView

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_READERS = 100
MAX_VIEWS_PER_KEY = 100
MAX_NAME_LENGTH = 160
MAX_VIEW_KEY_LENGTH = 64
MAX_LIST_ROWS = 500

_VIEW_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_UNSET = object()


class SavedViewError(Exception):
    """Base class for every saved views failure. ``status_code`` is the HTTP mapping."""

    status_code = 400


class SavedViewValidationError(SavedViewError, ValueError):
    status_code = 400


class SavedViewNotFound(SavedViewError):
    status_code = 404


class SavedViewPermissionDenied(SavedViewError):
    status_code = 403


class SavedViewConflict(SavedViewError):
    status_code = 409


class SavedViewAuditError(SavedViewError):
    status_code = 500


def _atomic():
    try:
        from django.db import transaction
    except ModuleNotFoundError:
        # Lightweight contract tests import this module without Django.
        return nullcontext()
    return transaction.atomic()


def _integrity_error():
    try:
        from django.db import IntegrityError
    except ModuleNotFoundError:
        return ()
    return IntegrityError


def _user_id(user) -> Any:
    if not getattr(user, "is_authenticated", False):
        raise SavedViewPermissionDenied("Sign in to use saved views.")
    return user.pk


# --- validation -------------------------------------------------------------------------------

def _clean_module_id(value: Any) -> str:
    text = str(value or "").strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not text:
        raise SavedViewValidationError("module_id is required.")
    return text


def _clean_view_key(value: Any) -> str:
    if not isinstance(value, str) or not _VIEW_KEY_RE.fullmatch(value):
        raise SavedViewValidationError(
            f"view_key must be a lowercase slug of letters, digits, '-' or '_', up to {MAX_VIEW_KEY_LENGTH} characters."
        )
    return value


def _clean_name(value: Any) -> str:
    if not isinstance(value, str):
        raise SavedViewValidationError("name is required.")
    name = value.strip()
    if not name:
        raise SavedViewValidationError("name is required.")
    if len(name) > MAX_NAME_LENGTH:
        raise SavedViewValidationError(f"name may not exceed {MAX_NAME_LENGTH} characters.")
    if any(ord(ch) < 32 for ch in name):
        raise SavedViewValidationError("name may not contain control characters.")
    return name


def _clean_payload(value: Any) -> dict:
    if not isinstance(value, dict):
        raise SavedViewValidationError("payload must be a JSON object.")
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise SavedViewValidationError("payload must be plain JSON.") from exc
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise SavedViewValidationError(f"payload exceeds the {MAX_PAYLOAD_BYTES // 1024} KiB limit.")
    return json.loads(encoded)


def _clean_readers(value: Any) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SavedViewValidationError("readers must be a list of user ids.")
    ids: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise SavedViewValidationError("readers must contain positive whole user ids.")
        if item not in ids:
            ids.append(item)
    if len(ids) > MAX_READERS:
        raise SavedViewValidationError(f"readers may not list more than {MAX_READERS} users.")
    if ids:
        from django.contrib.auth import get_user_model

        known = set(get_user_model().objects.filter(pk__in=ids, is_active=True).values_list("pk", flat=True))
        if known != set(ids):
            raise SavedViewValidationError("readers contains a user id that does not exist or is not active.")
    return sorted(ids)


def _check_module(user, module_id: str, *, allow_unresolved: bool = False) -> None:
    """Module must be Core, or an installed, enabled extension the user may use."""
    if module_id == "core":
        return
    from . import audit

    try:
        module = audit._resolve_module(module_id)
    except audit.AuditContractError:
        module = None
    if module is None or module.get("legacy"):
        if allow_unresolved:
            return
        raise SavedViewValidationError("module_id must be 'core' or an installed, enabled Tec-Tac module.")
    if not audit._actor_can_use_module(user, module):
        raise SavedViewPermissionDenied(f"You do not have access to Tec-Tac module {module_id!r}.")


# --- access rules -----------------------------------------------------------------------------

def _is_owner(user, view) -> bool:
    return view.owner_id == user.pk


def _can_read(user, view) -> bool:
    readers = view.readers or []
    return _is_owner(user, view) or not readers or user.pk in readers


def _load(user, view_id: Any):
    """Return a view the user can read, or raise not found (also for a private view they cannot read)."""
    _user_id(user)
    try:
        wanted = uuid.UUID(str(view_id))
    except (ValueError, AttributeError, TypeError):
        raise SavedViewNotFound("Saved view not found.") from None
    view = TecTacSavedView.objects.select_related("owner").filter(pk=wanted).first()
    if view is None or not _can_read(user, view):
        raise SavedViewNotFound("Saved view not found.")
    return view


def serialize_view(view, viewer) -> dict[str, Any]:
    readers = list(view.readers or [])
    mine = _is_owner(viewer, view)
    row = {
        "id": str(view.id),
        "module_id": view.module_id,
        "view_key": view.view_key,
        "name": view.name,
        "payload": view.payload if isinstance(view.payload, dict) else {},
        "shared": not readers,
        "mine": mine,
        "can_edit": mine,
        "owner": {"id": view.owner_id, "username": str(getattr(view.owner, "username", "") or "")},
        "created_at": view.created_at,
        "updated_at": view.updated_at,
    }
    if mine:
        row["readers"] = readers
    return row


def _audit(user, action: str, view) -> None:
    """Strict Core audit row. It carries the view's identity, never its payload."""
    readers = list(view.readers or [])
    try:
        from .audit import record

        record(
            actor=user,
            module_id="core",
            action=action,
            object_type="saved_view",
            object_id=str(view.id),
            message=f"Tec-Tac saved view {action}.",
            metadata={
                "module": view.module_id,
                "view_key": view.view_key,
                "name": view.name,
                "shared": not readers,
                "readers_count": len(readers),
            },
            strict=True,
        )
    except Exception as exc:
        raise SavedViewAuditError("A saved view change requires a persisted Core audit record.") from exc


def _name_taken(user, module_id: str, view_key: str, name: str, *, exclude_id: Any = None) -> bool:
    rows = TecTacSavedView.objects.filter(owner_id=user.pk, module_id=module_id, view_key=view_key, name=name)
    return any(str(row.id) != str(exclude_id) for row in rows)


# --- contract ---------------------------------------------------------------------------------

def list_views(user, module_id: Any, view_key: Any = None) -> list[dict[str, Any]]:
    """Views the user can read for one module, optionally narrowed to one view_key."""
    _user_id(user)
    module = _clean_module_id(module_id)
    key = None if view_key in (None, "") else _clean_view_key(view_key)
    _check_module(user, module)
    filters = {"module_id": module}
    if key is not None:
        filters["view_key"] = key
    rows = TecTacSavedView.objects.select_related("owner").filter(**filters).order_by("name", "id")
    out = []
    for view in rows:
        if _can_read(user, view):
            out.append(serialize_view(view, user))
            if len(out) >= MAX_LIST_ROWS:
                break
    return out


def get_view(user, view_id: Any) -> dict[str, Any]:
    view = _load(user, view_id)
    try:
        _check_module(user, view.module_id, allow_unresolved=_is_owner(user, view))
    except SavedViewValidationError:
        # The module was removed or disabled. Only the owner still sees the view.
        raise SavedViewNotFound("Saved view not found.") from None
    return serialize_view(view, user)


def create_view(user, module_id: Any, view_key: Any, name: Any, payload: Any, readers: Any = None) -> dict[str, Any]:
    _user_id(user)
    module = _clean_module_id(module_id)
    key = _clean_view_key(view_key)
    clean_name = _clean_name(name)
    clean_payload = _clean_payload(payload)
    clean_readers = _clean_readers(readers)
    _check_module(user, module)
    try:
        with _atomic():
            existing = TecTacSavedView.objects.filter(owner_id=user.pk, module_id=module, view_key=key)
            if any(row.name == clean_name for row in existing):
                raise SavedViewConflict("You already have a saved view with this name.")
            if existing.count() >= MAX_VIEWS_PER_KEY:
                raise SavedViewValidationError(
                    f"You can keep at most {MAX_VIEWS_PER_KEY} saved views for one module and view_key."
                )
            view = TecTacSavedView.objects.create(
                owner=user, module_id=module, view_key=key, name=clean_name,
                payload=clean_payload, readers=clean_readers,
            )
            _audit(user, "add", view)
    except _integrity_error() as exc:
        raise SavedViewConflict("You already have a saved view with this name.") from exc
    return serialize_view(view, user)


def update_view(user, view_id: Any, *, module_id: Any = _UNSET, view_key: Any = _UNSET,
                name: Any = _UNSET, payload: Any = _UNSET, readers: Any = _UNSET) -> dict[str, Any]:
    """Change name, payload or readers. module_id and view_key never change; repeating them is fine."""
    view = _load(user, view_id)
    _check_module(user, view.module_id)
    if not _is_owner(user, view):
        raise SavedViewPermissionDenied("Only the owner can change this saved view.")
    if module_id is not _UNSET and _clean_module_id(module_id) != view.module_id:
        raise SavedViewValidationError("module_id cannot be changed.")
    if view_key is not _UNSET and view_key != view.view_key:
        raise SavedViewValidationError("view_key cannot be changed.")
    changes: dict[str, Any] = {}
    if name is not _UNSET:
        changes["name"] = _clean_name(name)
    if payload is not _UNSET:
        changes["payload"] = _clean_payload(payload)
    if readers is not _UNSET:
        changes["readers"] = _clean_readers(readers)
    try:
        with _atomic():
            if "name" in changes and _name_taken(user, view.module_id, view.view_key, changes["name"], exclude_id=view.id):
                raise SavedViewConflict("You already have a saved view with this name.")
            for field, value in changes.items():
                setattr(view, field, value)
            view.save(update_fields=[*changes, "updated_at"])
            _audit(user, "modify", view)
    except _integrity_error() as exc:
        raise SavedViewConflict("You already have a saved view with this name.") from exc
    return serialize_view(view, user)


def delete_view(user, view_id: Any) -> None:
    view = _load(user, view_id)
    if not _is_owner(user, view):
        raise SavedViewPermissionDenied("Only the owner can delete this saved view.")
    # The owner may always clean up a view whose module was removed or disabled.
    _check_module(user, view.module_id, allow_unresolved=True)
    with _atomic():
        _audit(user, "delete", view)
        view.delete()
