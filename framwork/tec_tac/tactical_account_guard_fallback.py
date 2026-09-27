"""Independent fail-closed Tactical account compatibility guard.

This module intentionally does not import ``tactical_account_guard``.  It is the
last-resort privilege boundary used when the precise guard cannot even import or
when Tactical renamed a native account view.  Keeping the implementation
separate prevents one broken compatibility module from taking out both layers.
"""
from __future__ import annotations

import logging
from functools import wraps

from rest_framework.exceptions import PermissionDenied

logger = logging.getLogger("tec_tac.tactical_account_guard_fallback")
_FAIL_CLOSED_MARKER = "_tec_tac_account_fail_closed_guard"


def _is_effective_superuser(user) -> bool:
    """Resolve Tactical effective-superuser authority without Core guard imports."""
    if not getattr(user, "is_authenticated", False):
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    try:
        role = user.get_and_set_role_cache()
    except Exception:
        role = getattr(user, "role", None)
    return bool(getattr(role, "is_superuser", False)) if role else False


def _fail_closed_account_write_wrapper(original):
    if getattr(original, _FAIL_CLOSED_MARKER, False):
        return original

    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        actor = getattr(request, "user", None)
        try:
            allowed = bool(actor is not None and _is_effective_superuser(actor))
        except Exception:
            logger.exception("Tec-Tac fail-closed account guard could not resolve actor authority")
            allowed = False
        if not allowed:
            raise PermissionDenied(
                "Tec-Tac account protection is in fail-closed compatibility mode; "
                "effective superuser authority is required for role/user mutations."
            )
        return original(self, request, *args, **kwargs)

    setattr(guarded, _FAIL_CLOSED_MARKER, True)
    return guarded


def _fail_closed_api_key_list_wrapper(original):
    """Non-superusers may list API-key metadata but never receive secrets."""
    if getattr(original, _FAIL_CLOSED_MARKER, False):
        return original

    @wraps(original)
    def guarded(self, request, *args, **kwargs):
        response = original(self, request, *args, **kwargs)
        actor = getattr(request, "user", None)
        try:
            allowed = bool(actor is not None and _is_effective_superuser(actor))
        except Exception:
            logger.exception("Tec-Tac fail-closed API-key guard could not resolve actor authority")
            allowed = False
        if allowed:
            return response
        data = getattr(response, "data", None)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "key" in item:
                    item["key"] = "[REDACTED]"
        return response

    setattr(guarded, _FAIL_CLOSED_MARKER, True)
    return guarded


def install_tactical_account_guard_fail_closed() -> bool:
    """Best-effort coarse guard that never imports the precise guard module."""
    try:
        from accounts import views as tactical_views
    except Exception:
        logger.exception("Unable to import Tactical account views for fail-closed guard")
        return False

    targets = (
        ("GetAddRoles", ("post",), _fail_closed_account_write_wrapper),
        ("GetUpdateDeleteRole", ("put", "delete"), _fail_closed_account_write_wrapper),
        ("GetAddUsers", ("post",), _fail_closed_account_write_wrapper),
        ("GetUpdateDeleteUser", ("put", "delete"), _fail_closed_account_write_wrapper),
        ("UserActions", ("post", "put"), _fail_closed_account_write_wrapper),
        ("GetAddAPIKeys", ("get",), _fail_closed_api_key_list_wrapper),
        ("GetAddAPIKeys", ("post",), _fail_closed_account_write_wrapper),
        ("GetUpdateDeleteAPIKey", ("put", "delete"), _fail_closed_account_write_wrapper),
        ("TOTPSetup", ("post",), _fail_closed_account_write_wrapper),
        ("ResetPass", ("put",), _fail_closed_account_write_wrapper),
        ("Reset2FA", ("put",), _fail_closed_account_write_wrapper),
    )
    complete = True
    for class_name, methods, wrapper in targets:
        view_cls = getattr(tactical_views, class_name, None)
        if view_cls is None:
            logger.error("Tactical account fail-closed guard target is missing: %s", class_name)
            complete = False
            continue
        for method in methods:
            original = getattr(view_cls, method, None)
            if original is None:
                logger.error("Tactical account fail-closed guard method is missing: %s.%s", class_name, method)
                complete = False
                continue
            if not getattr(original, _FAIL_CLOSED_MARKER, False):
                setattr(view_cls, method, wrapper(original))
    return complete
