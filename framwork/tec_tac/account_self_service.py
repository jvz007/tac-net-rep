from __future__ import annotations

from typing import Any

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

from .mfa_backup import invalidate_backup_codes
from .session_security import SessionSecurityError, _audit, revoke_user_sessions


class AccountSelfServiceError(SessionSecurityError):
    pass


def _is_sso_user(user) -> bool:
    return bool(getattr(user, "is_sso_user", False))


def _can_run_url_actions(user) -> bool:
    if bool(getattr(user, "is_superuser", False)):
        return True
    role = getattr(user, "role", None)
    return bool(role and (getattr(role, "is_superuser", False) or getattr(role, "can_run_urlactions", False)))


def _client_ip(request) -> str:
    return str(getattr(request, "_client_ip", "") or "")[:64]


def _audit_self(event_type: str, user, *, request=None, reason: str = "", metadata: dict | None = None) -> None:
    _audit(
        event_type,
        username=str(getattr(user, "username", "") or ""),
        requested_by=str(getattr(user, "username", "") or ""),
        reason=str(reason or "")[:255],
        new_ip=_client_ip(request) if request is not None else "",
        metadata=dict(metadata or {}),
        force=True,
    )


def account_summary(user) -> dict[str, Any]:
    return {
        "id": getattr(user, "pk", None),
        "username": str(getattr(user, "username", "") or ""),
        "first_name": str(getattr(user, "first_name", "") or ""),
        "last_name": str(getattr(user, "last_name", "") or ""),
        "email": str(getattr(user, "email", "") or ""),
        "sso_user": _is_sso_user(user),
        "totp_configured": bool(getattr(user, "totp_key", None)),
    }


def change_own_password(user, *, current_password: str, new_password: str, current_session_id=None, request=None) -> dict[str, Any]:
    if _is_sso_user(user):
        raise AccountSelfServiceError("Password changes are managed by SSO for this account.")
    if not current_password or not user.check_password(current_password):
        _audit_self("self_password_change_failed", user, request=request, reason="current-password-rejected")
        raise AccountSelfServiceError("Current password was not accepted.")
    if not new_password:
        raise AccountSelfServiceError("A new password is required.")
    try:
        validate_password(new_password, user=user)
    except ValidationError as exc:
        raise AccountSelfServiceError(" ".join(str(item) for item in exc.messages)) from exc

    User = get_user_model()
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        if not locked.check_password(current_password):
            _audit_self("self_password_change_failed", locked, request=request, reason="current-password-changed")
            raise AccountSelfServiceError("Current password was not accepted.")
        locked.set_password(new_password)
        locked.save(update_fields=["password"])
        _audit_self("self_password_changed", locked, request=request, reason="user-request")

    sessions = revoke_user_sessions(
        str(user.username),
        except_session_id=current_session_id,
        reason="password-changed",
        requested_by=str(user.username),
    )
    return {"changed": True, "other_sessions_revoked": int(sessions.get("revoked") or 0)}


def reset_own_totp(user, *, current_password: str, current_totp: str, request=None) -> dict[str, Any]:
    if _is_sso_user(user):
        raise AccountSelfServiceError("Authenticator settings are managed by SSO for this account.")
    key = str(getattr(user, "totp_key", "") or "")
    if not key:
        raise AccountSelfServiceError("Two-factor authentication is not currently configured.")
    if not current_password or not user.check_password(current_password):
        _audit_self("self_totp_reset_failed", user, request=request, reason="current-password-rejected")
        raise AccountSelfServiceError("Current password or authenticator code was not accepted.")
    token = "".join(ch for ch in str(current_totp or "") if ch.isdigit())
    if not token or not pyotp.TOTP(key).verify(token, valid_window=1):
        _audit_self("self_totp_reset_failed", user, request=request, reason="totp-proof-rejected")
        raise AccountSelfServiceError("Current password or authenticator code was not accepted.")

    User = get_user_model()
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        locked_key = str(getattr(locked, "totp_key", "") or "")
        if not locked.check_password(current_password) or not locked_key:
            raise AccountSelfServiceError("Current password or authenticator code was not accepted.")
        if not pyotp.TOTP(locked_key).verify(token, valid_window=1):
            raise AccountSelfServiceError("Current password or authenticator code was not accepted.")
        locked.totp_key = ""
        locked.save(update_fields=["totp_key"])
        invalidate_backup_codes(locked, requested_by=str(locked.username), reason="self-totp-reset")
        _audit_self("self_totp_reset", locked, request=request, reason="user-request", metadata={"reenrollment_required": True})

    sessions = revoke_user_sessions(
        str(user.username),
        reason="totp-reset",
        requested_by=str(user.username),
    )
    return {
        "reset": True,
        "reauthentication_required": True,
        "sessions_revoked": int(sessions.get("revoked") or 0),
    }


def tactical_ui_context(user) -> dict[str, Any]:
    """Return the lightweight Tactical UI values exposed to module runtime context.

    Keep this hot-path payload intentionally small: modules need the effective
    double-click action and selected URL Action identity, not the full URL Action
    catalogue returned by the My Account editor.
    """
    return {
        "agent_dblclick_action": str(getattr(user, "agent_dblclick_action", "") or ""),
        "url_action_id": getattr(user, "url_action_id", None),
        "can_run_url_actions": _can_run_url_actions(user),
    }


def tactical_ui_preferences(user) -> dict[str, Any]:
    field = user._meta.get_field("agent_dblclick_action")
    choices = [{"value": str(value), "label": str(label)} for value, label in field.choices]
    can_run_url_actions = _can_run_url_actions(user)
    url_field = user._meta.get_field("url_action")
    model = url_field.remote_field.model
    actions = []
    if can_run_url_actions:
        actions = list(model.objects.order_by("name", "pk").values("id", "name"))
    selected = getattr(user, "url_action_id", None)
    return {
        "agent_dblclick_action": str(getattr(user, "agent_dblclick_action", "") or ""),
        "url_action_id": selected,
        "agent_dblclick_choices": choices,
        "url_actions": actions,
        "can_run_url_actions": can_run_url_actions,
    }


def update_tactical_ui_preferences(user, payload: dict[str, Any], *, request=None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AccountSelfServiceError("Preferences must be an object.")
    allowed = {"agent_dblclick_action", "url_action_id"}
    unknown = set(payload) - allowed
    if unknown:
        raise AccountSelfServiceError("Unknown Tactical UI preference field(s): " + ", ".join(sorted(unknown)))

    User = get_user_model()
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        update_fields: list[str] = []
        if "agent_dblclick_action" in payload:
            value = str(payload.get("agent_dblclick_action") or "")
            field = locked._meta.get_field("agent_dblclick_action")
            valid = {str(choice) for choice, _ in field.choices}
            if value not in valid:
                raise AccountSelfServiceError("Unsupported agent double-click action.")
            if value == "urlaction" and not _can_run_url_actions(locked):
                raise AccountSelfServiceError("This account cannot run URL Actions.")
            locked.agent_dblclick_action = value
            update_fields.append("agent_dblclick_action")

        if "url_action_id" in payload:
            raw = payload.get("url_action_id")
            if raw in (None, ""):
                locked.url_action_id = None
            else:
                if not _can_run_url_actions(locked):
                    raise AccountSelfServiceError("This account cannot run URL Actions.")
                try:
                    action_id = int(raw)
                except (TypeError, ValueError) as exc:
                    raise AccountSelfServiceError("Invalid URL Action.") from exc
                model = locked._meta.get_field("url_action").remote_field.model
                if not model.objects.filter(pk=action_id).exists():
                    raise AccountSelfServiceError("URL Action was not found.")
                locked.url_action_id = action_id
            update_fields.append("url_action")

        if update_fields:
            locked.save(update_fields=list(dict.fromkeys(update_fields)))
            _audit_self(
                "self_tactical_ui_preferences_changed",
                locked,
                request=request,
                reason="user-request",
                metadata={"fields": sorted(set(update_fields))},
            )

    return tactical_ui_preferences(locked)
