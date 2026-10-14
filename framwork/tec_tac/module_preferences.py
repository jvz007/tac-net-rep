"""Module user preferences (Core 1.17.35, capability core.module_preferences 1.0.0).

A module keeps one small per-person choice through Core, such as the collapse control of a window. A preference belongs to one person,
one module id and one name, and holds one JSON value (a scalar, a list or an object) of at most 4 KiB serialised and 5 levels deep.
At most 50 names per person and module. Only the signed-in person can read or write their own rows, through the browser route
/api/tfd/module-preferences/<module_id>/ or through the Python functions below.

Rules (also in docs/module-preferences.md): no secret, token or personal data may be stored; the value is the person's own display
choice. Nothing here is audited (same as /api/tfd/ui/preferences/). The module id is a claim: the browser cannot prove which module
calls, so the path id is trusted the way notices.publish trusts its module_id. The damage is limited to one person editing their own
display choice of another module. A module id must be an installed, enabled extension; core and tec-tac are refused.
"""
from __future__ import annotations

import json
import re
from contextlib import nullcontext
from typing import Any

CAPABILITY_ID = "core.module_preferences"
CAPABILITY_VERSION = "1.0.0"
MAX_NAMES_PER_MODULE = 50
MAX_VALUE_BYTES = 4 * 1024
MAX_VALUE_DEPTH = 5
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class ModulePreferenceError(Exception):
    """A refusal. ``code`` is the machine-readable reason; ``status_code`` is the HTTP mapping."""

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


def _module(module_id: Any) -> str:
    """The module id, checked against the installed, enabled extensions (the same check as notices.publish)."""
    from . import notices

    try:
        return notices.enabled_extension_id(module_id)
    except notices.NoticeError as exc:
        raise ModulePreferenceError("module_not_found", "module_id must be an installed, enabled Tec-Tac module.", 404) from exc


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


# --- the public functions (the Python contract) -----------------------------------------------

def get(user: Any, name: Any, *, module_id: Any, default: Any = None) -> Any:
    """The stored value of one preference, or ``default`` when the person has none. Only this person's row is read."""
    module = _module(module_id)
    key = _clean_name(name)
    row = _rows(user, module).filter(name=key).first()
    return default if row is None else row.value


def set(user: Any, name: Any, value: Any, *, module_id: Any) -> Any:  # the contract name (1.17.35)
    """Store one preference for this person and return the stored value. Refuses a 51st name for the module (preference_limit)."""
    module = _module(module_id)
    key = _clean_name(name)
    stored = _clean_value(value)
    user_pk = _user_pk(user)
    from .models import TecTacModulePreference

    with _atomic():
        _lock_user(user_pk)  # one person's writes are serialised, so the 50 names limit holds
        rows = _rows(user, module)
        if not rows.filter(name=key).exists() and rows.count() >= MAX_NAMES_PER_MODULE:
            raise ModulePreferenceError(
                "preference_limit", f"A module may keep at most {MAX_NAMES_PER_MODULE} preference names for one person.",
            )
        row, _ = TecTacModulePreference.objects.update_or_create(
            user_id=user_pk, module_id=module, name=key, defaults={"value": stored},
        )
    return row.value


def delete(user: Any, name: Any, *, module_id: Any) -> bool:
    """Remove one preference of this person. True when a row was removed."""
    module = _module(module_id)
    key = _clean_name(name)
    with _atomic():
        deleted, _ = _rows(user, module).filter(name=key).delete()
    return bool(deleted)


def list_for(user: Any, *, module_id: Any) -> dict[str, Any]:
    """Every preference of this person for the module, as {name: value}, sorted by name."""
    module = _module(module_id)
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
        "requires_framework": ">=1.17.35",
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
