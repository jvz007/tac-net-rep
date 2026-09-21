"""Core-owned Tec-Tac session security enforcement and public backend contract.

Tactical remains the authentication authority. This module adds an independent
server-side trust decision for Tec-Tac requests: idle/absolute expiry, IP-change
policy and explicit revocation. Raw Tactical tokens are never persisted.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated

from .capabilities import register_capability
from .models import TecTacSessionAudit, TecTacSessionSecurityConfig, TecTacSessionTrust

CAPABILITY_ID = "core.session_security"
CAPABILITY_VERSION = "1.0.0"
TOKEN_NAMESPACE = b"tec-tac-session-security:v1\x00"
DEFAULT_IDLE_TIMEOUT_MINUTES = 30
DEFAULT_ABSOLUTE_LIFETIME_MINUTES = 8 * 60
DEFAULT_ACTIVITY_HEARTBEAT_SECONDS = 60
DEFAULT_IP_CHANGE_POLICY = "reauthenticate"
ALLOWED_IP_CHANGE_POLICIES = {"off", "audit", "reauthenticate", "terminate"}


class SessionSecurityError(RuntimeError):
    pass


class SessionSecurityDenied(APIException):
    status_code = 401
    default_code = "tec_tac_session_reauthentication_required"

    def __init__(self, code: str, detail: str = "Session re-authentication required."):
        self.session_code = str(code or self.default_code)
        super().__init__({"detail": detail, "code": self.session_code})


def _role_for_user(user):
    try:
        return user.get_and_set_role_cache()
    except Exception:
        return getattr(user, "role", None)


def can_manage_session_security(user) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    role = _role_for_user(user)
    return bool(getattr(role, "is_superuser", False) or getattr(role, "can_do_server_maint", False)) if role else False


def _policy_dict(config: TecTacSessionSecurityConfig | None = None) -> dict[str, Any]:
    config = config or TecTacSessionSecurityConfig.current()
    return {
        "idle_timeout_minutes": int(config.idle_timeout_minutes),
        "absolute_lifetime_minutes": int(config.absolute_lifetime_minutes),
        "ip_change_policy": str(config.ip_change_policy),
        "session_audit_enabled": bool(config.session_audit_enabled),
        "activity_heartbeat_seconds": int(config.activity_heartbeat_seconds),
        "trusted_proxies": list(config.trusted_proxies or []),
    }


def get_effective_policy(user=None, request=None) -> dict[str, Any]:
    """Return the Core session policy currently enforced for a user/request.

    The v1 contract is global. The signature intentionally accepts user/request
    so a future Security module can add role/user policy resolution without
    changing consumers.
    """
    return _policy_dict()


def update_global_policy(policy: dict, *, requested_by: str = "") -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise SessionSecurityError("policy must be an object.")
    config = TecTacSessionSecurityConfig.current()
    fields = []
    if "idle_timeout_minutes" in policy:
        value = int(policy["idle_timeout_minutes"])
        if value < 1 or value > 1440:
            raise SessionSecurityError("idle_timeout_minutes must be between 1 and 1440.")
        config.idle_timeout_minutes = value; fields.append("idle_timeout_minutes")
    if "absolute_lifetime_minutes" in policy:
        value = int(policy["absolute_lifetime_minutes"])
        if value < 1 or value > 10080:
            raise SessionSecurityError("absolute_lifetime_minutes must be between 1 and 10080.")
        config.absolute_lifetime_minutes = value; fields.append("absolute_lifetime_minutes")
    if "activity_heartbeat_seconds" in policy:
        value = int(policy["activity_heartbeat_seconds"])
        if value < 30 or value > 3600:
            raise SessionSecurityError("activity_heartbeat_seconds must be between 30 and 3600.")
        config.activity_heartbeat_seconds = value; fields.append("activity_heartbeat_seconds")
    if "ip_change_policy" in policy:
        value = str(policy["ip_change_policy"] or "").strip().lower()
        if value not in ALLOWED_IP_CHANGE_POLICIES:
            raise SessionSecurityError("ip_change_policy must be off, audit, reauthenticate, or terminate.")
        config.ip_change_policy = value; fields.append("ip_change_policy")
    if "session_audit_enabled" in policy:
        config.session_audit_enabled = bool(policy["session_audit_enabled"]); fields.append("session_audit_enabled")
    if "trusted_proxies" in policy:
        raw = policy["trusted_proxies"]
        if not isinstance(raw, list):
            raise SessionSecurityError("trusted_proxies must be a list of IP addresses or CIDR networks.")
        normalized = []
        for item in raw:
            text = str(item or "").strip()
            if not text:
                continue
            try:
                normalized.append(str(ipaddress.ip_network(text, strict=False)))
            except ValueError as exc:
                raise SessionSecurityError(f"Invalid trusted proxy network: {text}") from exc
        config.trusted_proxies = sorted(set(normalized)); fields.append("trusted_proxies")
    if fields:
        config.updated_by_label = str(requested_by or "")[:150]
        fields.extend(["updated_by_label", "updated_at"])
        config.save(update_fields=fields)
    return _policy_dict(config)


def _extract_raw_token(request) -> str:
    header = str(request.META.get("HTTP_AUTHORIZATION") or "").strip()
    if header:
        parts = header.split(None, 1)
        if len(parts) == 2 and parts[1].strip():
            return parts[1].strip()
        return header
    auth = getattr(request, "auth", None)
    if isinstance(auth, str) and auth.strip():
        return auth.strip()
    session = getattr(request, "session", None)
    session_key = getattr(session, "session_key", None) if session is not None else None
    if session_key:
        return f"django-session:{session_key}"
    raise SessionSecurityDenied("session_invalid_state", "Authenticated session state is invalid. Cannot identify the credential.")


def token_fingerprint(request) -> str:
    raw = _extract_raw_token(request).encode("utf-8")
    secret = str(settings.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, TOKEN_NAMESPACE + raw, hashlib.sha256).hexdigest()


def user_agent_hash(request) -> str:
    ua = str(request.META.get("HTTP_USER_AGENT") or "")
    if not ua:
        return ""
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()


def _ip(value: str | None):
    if not value:
        return None
    text = str(value).strip().strip('"')
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1 and "." in text:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _trusted_networks(policy: dict[str, Any]):
    out = []
    for item in policy.get("trusted_proxies") or []:
        try:
            out.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return out


def _is_trusted(address, networks) -> bool:
    return bool(address and any(address in network for network in networks))


def _parse_forwarded_for(header: str) -> list[str]:
    values = []
    for part in str(header or "").split(","):
        for param in part.split(";"):
            key, sep, value = param.strip().partition("=")
            if sep and key.lower() == "for":
                values.append(value.strip().strip('"'))
                break
    return values


def effective_client_ip(request, *, policy: dict[str, Any] | None = None) -> str:
    """Resolve client IP while trusting forwarding headers only from trusted peers."""
    policy = policy or get_effective_policy(getattr(request, "user", None), request)
    peer = _ip(request.META.get("REMOTE_ADDR"))
    if peer is None:
        return ""
    networks = _trusted_networks(policy)
    if not _is_trusted(peer, networks):
        return str(peer)

    xff = [str(x) for x in (_ip(part.strip()) for part in str(request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")) if x]
    forwarded = [str(x) for x in (_ip(item) for item in _parse_forwarded_for(request.META.get("HTTP_FORWARDED") or "")) if x]
    xreal = _ip(request.META.get("HTTP_X_REAL_IP"))
    chain = xff or forwarded or ([str(xreal)] if xreal else [])
    if not chain:
        return str(peer)

    # Walk from the proxy nearest us toward the client. Every forwarding hop
    # must be trusted before accepting the address to its left.
    current = peer
    for raw in reversed(chain):
        if not _is_trusted(current, networks):
            break
        candidate = _ip(raw)
        if candidate is None:
            break
        current = candidate
    return str(current)


def _audit(event_type: str, *, session=None, username: str = "", previous_ip: str = "", new_ip: str = "", reason: str = "", requested_by: str = "", metadata: dict | None = None, policy: dict | None = None):
    policy = policy or _policy_dict()
    if not policy.get("session_audit_enabled", True):
        return None
    return TecTacSessionAudit.objects.create(
        session=session,
        username=str(username or getattr(session, "username", "") or "")[:150],
        event_type=str(event_type)[:64],
        previous_ip=str(previous_ip or "")[:64],
        new_ip=str(new_ip or "")[:64],
        reason=str(reason or "")[:255],
        requested_by=str(requested_by or "")[:150],
        metadata=dict(metadata or {}),
    )


def _refresh_expiry(session: TecTacSessionTrust, policy: dict[str, Any]):
    session.absolute_expires_at = session.created_at + timedelta(minutes=int(policy["absolute_lifetime_minutes"]))
    session.idle_expires_at = session.last_activity_at + timedelta(minutes=int(policy["idle_timeout_minutes"]))


def _serialize_session(session: TecTacSessionTrust, *, current: bool = False) -> dict[str, Any]:
    return {
        "id": str(session.id),
        "username": session.username,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "last_activity_at": session.last_activity_at.isoformat() if session.last_activity_at else None,
        "last_seen_at": session.last_seen_at.isoformat() if session.last_seen_at else None,
        "absolute_expires_at": session.absolute_expires_at.isoformat() if session.absolute_expires_at else None,
        "idle_expires_at": session.idle_expires_at.isoformat() if session.idle_expires_at else None,
        "initial_ip": session.initial_ip,
        "last_ip": session.last_ip,
        "current": bool(current),
        "revoked": bool(session.revoked),
        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
        "revocation_reason": session.revocation_reason,
    }


def _revoke_locked(session: TecTacSessionTrust, *, reason: str, requested_by: str = "", event_type: str = "session_revoked", policy: dict | None = None):
    if not session.revoked:
        session.revoked = True
        session.revoked_at = timezone.now()
        session.revoked_by = str(requested_by or "")[:150]
        session.revocation_reason = str(reason or "revoked")[:255]
        session.save(update_fields=["revoked", "revoked_at", "revoked_by", "revocation_reason", "updated_at"])
        _audit(event_type, session=session, reason=reason, requested_by=requested_by, policy=policy)
    return session


def ensure_request_session(request, *, create: bool = True) -> TecTacSessionTrust:
    user = getattr(request, "user", None)
    if not getattr(user, "is_authenticated", False):
        raise SessionSecurityDenied("session_authentication_required", "Authentication is required.")
    fingerprint = token_fingerprint(request)
    policy = get_effective_policy(user, request)
    client_ip = effective_client_ip(request, policy=policy)
    now = timezone.now()
    username = str(getattr(user, "username", "") or "")

    with transaction.atomic():
        try:
            session = TecTacSessionTrust.objects.select_for_update().get(token_fingerprint=fingerprint)
        except TecTacSessionTrust.DoesNotExist:
            if not create:
                raise SessionSecurityDenied("session_invalid_state")
            absolute = now + timedelta(minutes=int(policy["absolute_lifetime_minutes"]))
            idle = now + timedelta(minutes=int(policy["idle_timeout_minutes"]))
            session, created = TecTacSessionTrust.objects.get_or_create(
                token_fingerprint=fingerprint,
                defaults={
                    "user": user,
                    "username": username,
                    "last_activity_at": now,
                    "last_seen_at": now,
                    "initial_ip": client_ip,
                    "last_ip": client_ip,
                    "user_agent_hash": user_agent_hash(request),
                    "absolute_expires_at": absolute,
                    "idle_expires_at": idle,
                },
            )
            if not created:
                session = TecTacSessionTrust.objects.select_for_update().get(pk=session.pk)
            else:
                _audit("session_created", session=session, new_ip=client_ip, policy=policy)

        if session.revoked:
            raise SessionSecurityDenied("session_revoked")
        if session.user_id != getattr(user, "pk", None) or session.username != username:
            _revoke_locked(session, reason="credential-user-mismatch", event_type="session_revoked", policy=policy)
            raise SessionSecurityDenied("session_invalid_state")

        _refresh_expiry(session, policy)
        if now >= session.absolute_expires_at:
            _revoke_locked(session, reason="absolute-timeout", event_type="session_absolute_timeout", policy=policy)
            raise SessionSecurityDenied("session_absolute_timeout")
        if now >= session.idle_expires_at:
            _revoke_locked(session, reason="idle-timeout", event_type="session_idle_timeout", policy=policy)
            raise SessionSecurityDenied("session_idle_timeout")

        if client_ip and session.last_ip and client_ip != session.last_ip:
            mode = policy["ip_change_policy"]
            if mode != "off":
                _audit("session_ip_changed", session=session, previous_ip=session.last_ip, new_ip=client_ip, reason=mode, policy=policy)
            if mode in {"reauthenticate", "terminate"}:
                reason = "ip-change-reauthenticate" if mode == "reauthenticate" else "ip-change-terminate"
                _revoke_locked(session, reason=reason, event_type="session_reauthentication_required" if mode == "reauthenticate" else "session_revoked", policy=policy)
                raise SessionSecurityDenied("session_ip_change")
            session.last_ip = client_ip

        session.last_seen_at = now
        _refresh_expiry(session, policy)
        session.save(update_fields=["last_seen_at", "last_ip", "absolute_expires_at", "idle_expires_at", "updated_at"])
        return session


def record_activity(request) -> dict[str, Any]:
    session = ensure_request_session(request)
    policy = get_effective_policy(request.user, request)
    now = timezone.now()
    with transaction.atomic():
        session = TecTacSessionTrust.objects.select_for_update().get(pk=session.pk)
        if session.revoked:
            raise SessionSecurityDenied("session_revoked")
        _refresh_expiry(session, policy)
        if now >= session.absolute_expires_at:
            _revoke_locked(session, reason="absolute-timeout", event_type="session_absolute_timeout", policy=policy)
            raise SessionSecurityDenied("session_absolute_timeout")
        if now >= session.idle_expires_at:
            _revoke_locked(session, reason="idle-timeout", event_type="session_idle_timeout", policy=policy)
            raise SessionSecurityDenied("session_idle_timeout")
        session.last_activity_at = now
        session.last_seen_at = now
        _refresh_expiry(session, policy)
        session.save(update_fields=["last_activity_at", "last_seen_at", "absolute_expires_at", "idle_expires_at", "updated_at"])
        return _serialize_session(session, current=True)


def get_current_session(request) -> dict[str, Any]:
    return _serialize_session(ensure_request_session(request), current=True)


def list_sessions(*, username: str | None = None, user=None, include_revoked: bool = True) -> list[dict[str, Any]]:
    qs = TecTacSessionTrust.objects.all().order_by("-last_seen_at", "-created_at")
    if user is not None:
        qs = qs.filter(user=user)
    elif username:
        qs = qs.filter(username=str(username))
    if not include_revoked:
        qs = qs.filter(revoked=False)
    return [_serialize_session(item) for item in qs[:1000]]


def revoke_session(session_id, *, reason: str = "administrator-request", requested_by: str = "") -> dict[str, Any]:
    with transaction.atomic():
        session = TecTacSessionTrust.objects.select_for_update().get(pk=session_id)
        _revoke_locked(session, reason=reason, requested_by=requested_by)
        return _serialize_session(session)


def revoke_user_sessions(username: str, *, except_session_id=None, reason: str = "administrator-request", requested_by: str = "") -> dict[str, Any]:
    username = str(username or "").strip()
    if not username:
        raise SessionSecurityError("username is required.")
    count = 0
    ids = []
    with transaction.atomic():
        qs = TecTacSessionTrust.objects.select_for_update().filter(username=username, revoked=False)
        if except_session_id:
            qs = qs.exclude(pk=except_session_id)
        for session in qs:
            _revoke_locked(session, reason=reason, requested_by=requested_by)
            count += 1; ids.append(str(session.id))
    if count:
        _audit("user_sessions_revoked", username=username, reason=reason, requested_by=requested_by, metadata={"count": count, "session_ids": ids})
    return {"username": username, "revoked": count, "session_ids": ids}


def list_audit_events(*, username: str | None = None, event_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    size = max(1, min(int(limit), 1000))
    qs = TecTacSessionAudit.objects.all().order_by("-created_at")
    if username:
        qs = qs.filter(username=str(username))
    if event_type:
        qs = qs.filter(event_type=str(event_type))
    rows = []
    for item in qs[:size]:
        rows.append({
            "id": str(item.id),
            "session_id": str(item.session_id) if item.session_id else None,
            "username": item.username,
            "event_type": item.event_type,
            "previous_ip": item.previous_ip,
            "new_ip": item.new_ip,
            "reason": item.reason,
            "requested_by": item.requested_by,
            "metadata": dict(item.metadata or {}),
            "created_at": item.created_at.isoformat() if item.created_at else None,
        })
    return rows


def cleanup_session_history(*, retention_days: int = 30) -> dict[str, int]:
    days = int(retention_days)
    if days < 1 or days > 3650:
        raise SessionSecurityError("retention_days must be between 1 and 3650.")
    cutoff = timezone.now() - timedelta(days=days)
    sessions_qs = TecTacSessionTrust.objects.filter(
        Q(revoked=True, revoked_at__lt=cutoff)
        | Q(revoked=False, absolute_expires_at__lt=cutoff)
        | Q(revoked=False, idle_expires_at__lt=cutoff)
    )
    sessions = sessions_qs.count()
    sessions_qs.delete()
    audits_qs = TecTacSessionAudit.objects.filter(created_at__lt=cutoff)
    audits = audits_qs.count()
    audits_qs.delete()
    return {"sessions_deleted": sessions, "audit_events_deleted": audits, "retention_days": days}


def diagnostics() -> dict[str, Any]:
    policy = _policy_dict()
    now = timezone.now()
    return {
        "enabled": True,
        "capability": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "policy": policy,
        "counts": {
            "active": TecTacSessionTrust.objects.filter(revoked=False, absolute_expires_at__gt=now, idle_expires_at__gt=now).count(),
            "revoked": TecTacSessionTrust.objects.filter(revoked=True).count(),
            "expired_unrevoked": TecTacSessionTrust.objects.filter(revoked=False).filter(absolute_expires_at__lte=now).count() + TecTacSessionTrust.objects.filter(revoked=False, idle_expires_at__lte=now, absolute_expires_at__gt=now).count(),
        },
    }


class SessionAuthenticated(IsAuthenticated):
    """DRF permission that requires Tactical auth plus the Core session guard."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        request.tec_tac_session = ensure_request_session(request)
        return True


class SessionSecurityProvider:
    def get_policy(self, *, context: dict | None = None) -> dict[str, Any]:
        return _policy_dict()

    def update_policy(self, *, policy: dict, context: dict) -> dict[str, Any]:
        return update_global_policy(policy, requested_by=str((context or {}).get("requested_by") or (context or {}).get("username") or "module"))

    def list_sessions(self, *, username: str | None = None, include_revoked: bool = True, context: dict | None = None) -> list[dict[str, Any]]:
        return list_sessions(username=username, include_revoked=include_revoked)

    def list_audit_events(self, *, username: str | None = None, event_type: str | None = None, limit: int = 200, context: dict | None = None) -> list[dict[str, Any]]:
        return list_audit_events(username=username, event_type=event_type, limit=limit)

    def revoke_session(self, *, session_id: str, reason: str = "module-request", context: dict) -> dict[str, Any]:
        return revoke_session(session_id, reason=reason, requested_by=str((context or {}).get("requested_by") or (context or {}).get("username") or "module"))

    def revoke_user_sessions(self, *, username: str, except_session_id: str | None = None, reason: str = "module-request", context: dict) -> dict[str, Any]:
        return revoke_user_sessions(username, except_session_id=except_session_id, reason=reason, requested_by=str((context or {}).get("requested_by") or (context or {}).get("username") or "module"))

    def cleanup(self, *, retention_days: int = 30, context: dict | None = None) -> dict[str, int]:
        return cleanup_session_history(retention_days=retention_days)

    def diagnostics(self, *, context: dict | None = None) -> dict[str, Any]:
        return diagnostics()

    def health(self) -> dict[str, Any]:
        try:
            policy = _policy_dict()
            return {"healthy": True, "policy_loaded": True, "ip_change_policy": policy["ip_change_policy"]}
        except Exception as exc:
            return {"healthy": False, "reason": f"{exc.__class__.__name__}: {exc}"}


_PROVIDER = SessionSecurityProvider()


def register_core_session_security_capability():
    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Core-owned Tec-Tac session trust, timeout, IP-change and revocation enforcement.",
        health=_PROVIDER.health,
        operations=(
            "get_policy",
            "update_policy",
            "list_sessions",
            "list_audit_events",
            "revoke_session",
            "revoke_user_sessions",
            "cleanup",
            "diagnostics",
        ),
        metadata={
            "ip_change_policies": sorted(ALLOWED_IP_CHANGE_POLICIES),
            "default_idle_timeout_minutes": DEFAULT_IDLE_TIMEOUT_MINUTES,
            "default_absolute_lifetime_minutes": DEFAULT_ABSOLUTE_LIFETIME_MINUTES,
            "default_activity_heartbeat_seconds": DEFAULT_ACTIVITY_HEARTBEAT_SECONDS,
            "enforcement": "core",
        },
    )


def get_session_security_provider() -> SessionSecurityProvider:
    return _PROVIDER
