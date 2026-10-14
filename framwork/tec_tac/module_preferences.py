"""Module user preferences (Core 1.17.35; capability core.module_preferences 1.2.0 from Core 1.17.38).

A module keeps one small per-person choice through Core, such as the collapse control of a window. A preference belongs to one person,
one module id and one name, and holds one JSON value (a scalar, a list or an object) of at most 4 KiB serialised and 5 levels deep.
At most 50 names per person and module. Only the signed-in person can read or write their own rows, through the browser route
/api/tfd/module-preferences/<module_id>/ or through the Python functions below.

Rules (also in docs/module-preferences.md): no secret, token or personal data may be stored; the value is the person's own display
choice. Each real add, modify or delete writes one strict Core audit row in the same transaction as the save (1.17.38, AD-19
condition 5). The row names the person, the module and the name, and holds the size of the value, never the value. Reads are not audited,
and a write that changes nothing writes no row. If the row cannot be written, the change is rolled back and the answer is 503 audit_failed.
A module id must be an installed, enabled extension; core and tec-tac are refused. A person may use a module's preferences only when
they may use that module (403 module_not_allowed, the same rule as saved views); a module with no permission groups is open to every
signed-in person.

Who may call (AD-26, Core 1.17.37). The Python functions verify the calling module: a call may read or write only the preferences of the
module it names in module_id, else it is refused with 403 caller_not_allowed before any name, value or row is looked at. Core is never a
caller, and a call from a Core, library or generated frame, or from a disabled or legacy module, is refused too. The browser route cannot
be verified (the browser names the module id), so the views call the private functions with the path id, as before. The ``user``
argument stays the caller's responsibility: a module could pass any user for its own module id, but it can never reach another module's
rows, and since 1.17.38 it cannot write for a person who may not use that module.

What Core can and cannot prove about the module id (1.17.38). Core can prove who the person is (their session), that the module is
installed and enabled, that the person may use that module, and that a row can only ever belong to that person and that module id pair.
Core cannot prove that a browser request came from that module's page: the browser writes the id in the web address, so any signed-in
person who may use module A can write module A's own preference rows for themselves through the browser, and nothing more. The audit row
records source 'browser' and module_verified false for that path, as a claim, not as a fact.
"""
from __future__ import annotations

import json
import re
from contextlib import nullcontext
from typing import Any

from .caller_identity import calling_module_for_core_provider

CAPABILITY_ID = "core.module_preferences"
CAPABILITY_VERSION = "1.2.0"
MAX_NAMES_PER_MODULE = 50
MAX_VALUE_BYTES = 4 * 1024
MAX_VALUE_DEPTH = 5
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
AUDIT_OBJECT_TYPE = "module_preference"
SOURCE_PYTHON = "module_python"  # the Python functions: Core verified the calling module (AD-26)
SOURCE_BROWSER = "browser"  # the browser route: the browser named the module, so the claim is not verified


class ModulePreferenceError(Exception):
    """A refusal. ``code`` is the machine-readable reason; ``status_code`` is the HTTP mapping.

    Codes: invalid_name (400), invalid_value (400), preference_limit (400), signed_in_required (401), module_not_found (404),
    module_not_allowed (403, the person may not use the module, 1.17.38), caller_not_allowed (403, the Python functions only),
    audit_failed (503, 1.17.38: the change was rolled back because its audit row could not be written).
    """

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


# --- validation -------------------------------------------------------------------------------

def _clean_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ModulePreferenceError(
            "invalid_name",
            "name must be 1 to 64 characters: a lower-case letter or digit, then lower-case letters, digits, '.', '_' or '-'.",
        )
    return name


def _too_deep(value: Any, limit: int, level: int = 1) -> bool:
    """True when a list or an object nests more than ``limit`` levels. The outermost container is level 1."""
    if isinstance(value, dict):
        children = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        return False
    if level > limit:
        return True
    return any(_too_deep(child, limit, level + 1) for child in children)


def _clean_value(value: Any) -> Any:
    """The value as it will be stored: plain JSON, at most 4 KiB and 5 levels deep. Raises before anything is written."""
    if _too_deep(value, MAX_VALUE_DEPTH):
        raise ModulePreferenceError("invalid_value", f"value may nest at most {MAX_VALUE_DEPTH} levels deep.")
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ModulePreferenceError("invalid_value", "value must be plain JSON.") from exc
    if len(encoded.encode("utf-8")) > MAX_VALUE_BYTES:
        raise ModulePreferenceError("invalid_value", "value may not exceed 4 KiB when stored.")
    return json.loads(encoded)


def _canonical_text(value: Any) -> str:
    """The stored value as text, with sorted keys and no spaces. True, 1 and 1.0 give three different texts (1.17.38)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _size_bytes(value: Any) -> int:
    return len(_canonical_text(value).encode("utf-8"))


def _module(module_id: Any) -> str:
    """The module id, checked against the installed, enabled extensions (the same check as notices.publish)."""
    from . import notices

    try:
        return notices.enabled_extension_id(module_id)
    except notices.NoticeError as exc:
        raise ModulePreferenceError("module_not_found", "module_id must be an installed, enabled Tec-Tac module.", 404) from exc


def _may_use(user: Any, module_id: str) -> None:
    """Refuse a person who may not use the module (1.17.38, CQ109 and CQ116). The rule is saved views': a superuser or a role
    superuser may use any module, a module with no permission groups is open to every signed-in person, and otherwise the person
    needs one of the module's permissions. A legacy module is treated as not found."""
    from . import audit

    not_found = "module_id must be an installed, enabled Tec-Tac module."
    try:
        module = audit._resolve_module(module_id)
    except audit.AuditContractError as exc:
        raise ModulePreferenceError("module_not_found", not_found, 404) from exc
    if module.get("legacy"):
        raise ModulePreferenceError("module_not_found", not_found, 404)
    if not audit._actor_can_use_module(user, module):
        raise ModulePreferenceError("module_not_allowed", "You may not use this module's preferences.", 403)


def _person_module(user: Any, module_id: Any) -> str:
    """The checks of a browser or Python call after the caller check, in this order: signed in (401), the module is installed
    and enabled (404), the person may use it (403). Name, value and limit are checked after this, by the caller of this helper."""
    _user_pk(user)
    module = _module(module_id)
    _may_use(user, module)
    return module


def _user_pk(user: Any) -> Any:
    if not getattr(user, "is_authenticated", False):
        raise ModulePreferenceError("signed_in_required", "Sign in to use module preferences.", 401)
    return user.pk


def _atomic():
    try:
        from django.db import transaction
    except ModuleNotFoundError:
        # Lightweight contract tests import this module without Django.
        return nullcontext()
    return transaction.atomic()


def _rows(user: Any, module_id: str):
    from .models import TecTacModulePreference

    return TecTacModulePreference.objects.filter(user_id=_user_pk(user), module_id=module_id)


def _verified_caller(module_id: Any) -> None:
    """Refuse unless the verified calling module is the module named in module_id (AD-26). Fails closed; Core is never a caller."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None or identity.module_id != module_id:
        raise ModulePreferenceError(
            "caller_not_allowed", "Only the module named in module_id may use its own module preferences.", 403,
        )


def _audit(user: Any, action: str, module: str, name: str, *, source: str, size_bytes: int | None = None) -> None:
    """One strict Core audit row for a real change (1.17.38). It names the person, the module and the name, never the value:
    size_bytes is the size of the stored value, and only for add and modify. The row is written under module_id 'core', as
    saved views write theirs, so the person does not need the module's permissions for it. If the row cannot be written for any
    reason, the change is refused with 503 audit_failed, and the caller's transaction rolls the change back."""
    metadata: dict[str, Any] = {
        "module": module,
        "name": name,
        "source": source,
        "module_verified": source == SOURCE_PYTHON,
        "user_id": user.pk,
    }
    if size_bytes is not None:
        metadata["size_bytes"] = size_bytes
    try:
        from .audit import record

        record(
            actor=user,
            module_id="core",
            action=action,
            object_type=AUDIT_OBJECT_TYPE,
            object_id=f"{module}/{name}",
            message=f"Tec-Tac module preference {action}.",
            before=None,
            after=None,
            metadata=metadata,
            strict=True,
        )
    except Exception as exc:
        raise ModulePreferenceError(
            "audit_failed", "The change was not saved because it could not be audited.", 503,
        ) from exc


# --- the public functions (the Python contract): verify the caller, then do the work -----------

def get(user: Any, name: Any, *, module_id: Any, default: Any = None) -> Any:
    """The stored value of one preference, or ``default`` when the person has none. Only this person's row is read."""
    _verified_caller(module_id)
    return _get(user, name, module_id=module_id, default=default)


def set(user: Any, name: Any, value: Any, *, module_id: Any) -> Any:  # the contract name (1.17.35)
    """Store one preference for this person and return the stored value. Refuses a 51st name for the module (preference_limit).
    A real change is audited (1.17.38); a write that changes nothing writes nothing."""
    _verified_caller(module_id)
    return _set(user, name, value, module_id=module_id, source=SOURCE_PYTHON)


def delete(user: Any, name: Any, *, module_id: Any) -> bool:
    """Remove one preference of this person. True when a row was removed. A removal is audited (1.17.38)."""
    _verified_caller(module_id)
    return _delete(user, name, module_id=module_id, source=SOURCE_PYTHON)


def list_for(user: Any, *, module_id: Any) -> dict[str, Any]:
    """Every preference of this person for the module, as {name: value}, sorted by name."""
    _verified_caller(module_id)
    return _list_for(user, module_id=module_id)


# --- the private logic (the browser views call these with the path id; the public functions call them after the caller check) ---

def _get(user: Any, name: Any, *, module_id: Any, default: Any = None) -> Any:
    module = _person_module(user, module_id)
    key = _clean_name(name)
    row = _rows(user, module).filter(name=key).first()
    return default if row is None else row.value


def _set(user: Any, name: Any, value: Any, *, module_id: Any, source: str = SOURCE_BROWSER) -> Any:
    """Store one value. ``source`` is the claim for the audit row: the browser views keep the default, the lower claim, and the
    public set passes SOURCE_PYTHON after the caller check."""
    user_pk = _user_pk(user)
    module = _person_module(user, module_id)
    key = _clean_name(name)
    stored = _clean_value(value)
    from .models import TecTacModulePreference

    with _atomic():
        _lock_user(user_pk)  # one person's writes are serialised, so the 50 names limit holds
        rows = _rows(user, module)
        current = rows.filter(name=key).first()
        if current is None and rows.count() >= MAX_NAMES_PER_MODULE:
            raise ModulePreferenceError(
                "preference_limit", f"A module may keep at most {MAX_NAMES_PER_MODULE} preference names for one person.",
            )
        if current is not None and _canonical_text(current.value) == _canonical_text(stored):
            return current.value  # unchanged: no update and no audit row
        row, _ = TecTacModulePreference.objects.update_or_create(
            user_id=user_pk, module_id=module, name=key, defaults={"value": stored},
        )
        _audit(user, "add" if current is None else "modify", module, key, source=source, size_bytes=_size_bytes(stored))
    return row.value


def _delete(user: Any, name: Any, *, module_id: Any, source: str = SOURCE_BROWSER) -> bool:
    user_pk = _user_pk(user)
    module = _person_module(user, module_id)
    key = _clean_name(name)
    with _atomic():
        _lock_user(user_pk)
        rows = _rows(user, module).filter(name=key)
        if rows.first() is None:
            return False  # nothing to delete: no audit row
        _audit(user, "delete", module, key, source=source)
        deleted, _ = rows.delete()
    return bool(deleted)


def _list_for(user: Any, *, module_id: Any) -> dict[str, Any]:
    module = _person_module(user, module_id)
    return {row.name: row.value for row in _rows(user, module).order_by("name")}


def _lock_user(user_pk: Any) -> None:
    from django.contrib.auth import get_user_model

    get_user_model().objects.select_for_update().get(pk=user_pk)


# --- capability registration ------------------------------------------------------------------

class _CoreModulePreferencesProvider:
    get = staticmethod(get)
    set = staticmethod(set)
    delete = staticmethod(delete)
    list_for = staticmethod(list_for)


_PROVIDER = _CoreModulePreferencesProvider()


def module_preferences_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.module_preferences",
        "operations": ["get", "set", "delete", "list_for"],
        "limits": {"names_per_module": MAX_NAMES_PER_MODULE, "value_bytes": MAX_VALUE_BYTES, "value_depth": MAX_VALUE_DEPTH},
        "caller": (
            "verified (AD-26, since 1.1.0): a call may use only the module named in module_id; any other caller, Core, a library or a "
            "generated frame, a disabled or legacy module, gives 403 caller_not_allowed before any read or write. The browser route "
            "is not verified: the path id is a claim."
        ),
        "access": (
            "since 1.2.0: the signed-in person must be allowed to use the module (403 module_not_allowed, the rule of saved views); "
            "a module with no permission groups is open to every signed-in person."
        ),
        "audit": (
            "since 1.2.0: one strict Core audit row for each real add, modify or delete: action add, modify or delete, object_type "
            "module_preference, object_id <module_id>/<name>, the signed-in person as actor, and metadata module, name, source "
            "(module_python or browser), module_verified, user_id and size_bytes (add and modify only). Never the value. Reads and "
            "unchanged writes write no row. If the row cannot be written, the change is rolled back and the answer is 503 audit_failed."
        ),
        "requires_framework": ">=1.17.38",
    }


def register_core_module_preferences_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="One small per-person choice per module (name and JSON value), read and written by the signed-in person only.",
        operations=("get", "set", "delete", "list_for"),
        metadata=module_preferences_contract_metadata(),
    )
