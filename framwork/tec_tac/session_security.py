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
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from knox.models import AuthToken
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated

from .capabilities import register_capability
from .models import TecTacSessionAudit, TecTacSessionSecurityConfig, TecTacSessionTrust

CAPABILITY_ID = "core.session_security"
CAPABILITY_VERSION = "2.0.0"
TOKEN_NAMESPACE = b"tec-tac-session-security:v1\x00"
LOGIN_SESSION_NAMESPACE = b"tec-tac-login-session-ref:v1\x00"
DEFAULT_IDLE_TIMEOUT_MINUTES = 30
DEFAULT_ABSOLUTE_LIFETIME_MINUTES = 8 * 60
DEFAULT_ACTIVITY_HEARTBEAT_SECONDS = 60
DEFAULT_HISTORY_RETENTION_DAYS = 30
SESSION_PAGINATION_MAX_PAGE = 10000
DEFAULT_IP_CHANGE_POLICY = "reauthenticate"
SESSION_SWEEP_ACTOR = "tec-tac-scheduler"
SESSION_SWEEP_DEFAULT_LIMIT = 500
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
    return bool(getattr(role, "is_superuser", False)) if role else False


def _is_effective_superuser(user) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    if str(getattr(user, "username", "") or "") == str(getattr(settings, "ROOT_USER", "") or ""):
        return True
    role = _role_for_user(user)
    return bool(getattr(role, "is_superuser", False)) if role else False


def _is_protected_login_account(user) -> bool:
    if user is None:
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    if str(getattr(user, "username", "") or "") == str(getattr(settings, "ROOT_USER", "") or ""):
        return True
    role = _role_for_user(user)
    return bool(getattr(role, "is_superuser", False)) if role else False


def _can_administer_login_target(requester, target_user) -> bool:
    if _is_protected_login_account(target_user) and not _is_effective_superuser(requester):
        return False
    return True


def can_administer_account_security_target(requester, target_user) -> bool:
    """Return whether requester may perform destructive auth actions on target_user."""
    return _can_administer_login_target(requester, target_user)


def can_manage_account_security(user) -> bool:
    """Account administrators may manage session and MFA recovery state."""
    if not getattr(user, "is_authenticated", False):
        return False
    if _is_effective_superuser(user):
        return True
    role = _role_for_user(user)
    return bool(getattr(role, "can_manage_accounts", False)) if role else False


def can_manage_login_sessions(user) -> bool:
    """Backward-compatible account-admin authority for Tactical login sessions."""
    return can_manage_account_security(user)


def _normalized_trusted_proxies(raw, *, strict: bool) -> list[str]:
    if not isinstance(raw, list):
        if strict:
            raise SessionSecurityError("trusted_proxies must be a list of IP addresses or CIDR networks.")
        return []
    normalized = []
    for item in raw:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            if strict:
                raise SessionSecurityError(f"Invalid trusted proxy network: {text}") from exc
            continue
        min_prefix = 8 if network.version == 4 else 32
        if network.prefixlen < min_prefix:
            if strict:
                raise SessionSecurityError(f"trusted_proxies network is too broad: {network}")
            continue
        if not (network.is_private or network.is_loopback or network.is_link_local):
            if strict:
                raise SessionSecurityError(f"trusted_proxies must use private/local address space: {network}")
            continue
        normalized.append(str(network))
    return sorted(set(normalized))


def _policy_dict(config: TecTacSessionSecurityConfig | None = None) -> dict[str, Any]:
    config = config or TecTacSessionSecurityConfig.current()
    return {
        "idle_timeout_minutes": int(config.idle_timeout_minutes),
        "absolute_lifetime_minutes": int(config.absolute_lifetime_minutes),
        "ip_change_policy": str(config.ip_change_policy),
        "session_audit_enabled": bool(config.session_audit_enabled),
        "activity_heartbeat_seconds": int(config.activity_heartbeat_seconds),
        "history_retention_days": int(config.history_retention_days),
        # Stored legacy rows predate the stricter proxy validator. Never trust
        # an unsafe legacy network merely because it was accepted by an older Core.
        "trusted_proxies": _normalized_trusted_proxies(config.trusted_proxies, strict=False),
    }


def get_effective_policy(user=None, request=None) -> dict[str, Any]:
    """Return the Core session policy currently enforced for a user/request.

    The v1 contract is global. The signature intentionally accepts user/request
    so a future Security module can add role/user policy resolution without
    changing consumers.
    """
    return _policy_dict()


def _update_global_policy(policy: dict, *, requested_by: str = "") -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise SessionSecurityError("policy must be an object.")
    config = TecTacSessionSecurityConfig.current()
    before_policy = _policy_dict(config)
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
    if "history_retention_days" in policy:
        value = int(policy["history_retention_days"])
        if value < 1 or value > 3650:
            raise SessionSecurityError("history_retention_days must be between 1 and 3650.")
        config.history_retention_days = value; fields.append("history_retention_days")
    if "ip_change_policy" in policy:
        value = str(policy["ip_change_policy"] or "").strip().lower()
        if value not in ALLOWED_IP_CHANGE_POLICIES:
            raise SessionSecurityError("ip_change_policy must be off, audit, reauthenticate, or terminate.")
        config.ip_change_policy = value; fields.append("ip_change_policy")
    if "session_audit_enabled" in policy:
        config.session_audit_enabled = bool(policy["session_audit_enabled"]); fields.append("session_audit_enabled")
    if "trusted_proxies" in policy:
        config.trusted_proxies = _normalized_trusted_proxies(policy["trusted_proxies"], strict=True)
        fields.append("trusted_proxies")
    if fields:
        config.updated_by_label = str(requested_by or "")[:150]
        fields.extend(["updated_by_label", "updated_at"])
        config.save(update_fields=fields)
        after_policy = _policy_dict(config)
        _audit(
            "session_policy_changed",
            requested_by=requested_by,
            reason="global-session-policy-update",
            metadata={"before": before_policy, "after": after_policy, "fields": sorted(set(fields) - {"updated_by_label", "updated_at"})},
            policy=after_policy,
            force=True,
        )
    return _policy_dict(config)


def _credential_identity(request) -> str:
    """Bind Tec-Tac session trust to the authenticator DRF actually accepted."""
    authenticator = getattr(request, "successful_authenticator", None)
    auth = getattr(request, "auth", None)
    auth_name = authenticator.__class__.__name__ if authenticator is not None else ""
    auth_module = authenticator.__class__.__module__ if authenticator is not None else ""
    authorization = str(request.META.get("HTTP_AUTHORIZATION") or "").strip()
    api_header = str(request.META.get("HTTP_X_API_KEY") or "").strip()

    # Tactical APIAuthentication returns the raw API key as request.auth. Resolve
    # it to the database key id so a credential fingerprint never depends on a
    # caller-supplied unrelated Authorization header.
    if auth_name == "APIAuthentication" or auth_module.endswith("tacticalrmm.auth"):
        if authorization:
            raise SessionSecurityDenied("session_invalid_state", "Conflicting authentication headers were supplied.")
        if not isinstance(auth, str) or not auth or not api_header or not hmac.compare_digest(auth, api_header):
            raise SessionSecurityDenied("session_invalid_state", "Authenticated API key state does not match the request credential.")
        try:
            from accounts.models import APIKey
            row = APIKey.objects.only("id", "key", "user_id").get(key=auth, user_id=getattr(request.user, "pk", None))
        except Exception as exc:
            raise SessionSecurityDenied("session_invalid_state", "Authenticated API key could not be resolved.") from exc
        return f"api-key:{row.pk}"

    digest = str(getattr(auth, "digest", "") or "")
    if digest:
        if api_header:
            raise SessionSecurityDenied("session_invalid_state", "Conflicting authentication headers were supplied.")
        parts = authorization.split(None, 1)
        if len(parts) != 2 or not parts[1].strip():
            raise SessionSecurityDenied("session_invalid_state", "Authenticated Knox token header is missing.")
        try:
            from knox.crypto import hash_token
            header_digest = str(hash_token(parts[1].strip()))
        except Exception as exc:
            raise SessionSecurityDenied("session_invalid_state", "Authenticated Knox token header is invalid.") from exc
        if not hmac.compare_digest(header_digest, digest):
            raise SessionSecurityDenied("session_invalid_state", "Authenticated Knox token does not match the request credential.")
        return f"knox:{digest}"

    # A Django session may be used by bounded authentication/setup flows. Bind to
    # the authenticated session key only when no token/API-key authenticator won.
    session = getattr(request, "session", None)
    session_key = getattr(session, "session_key", None) if session is not None else None
    if authenticator is None and session_key and not authorization and not api_header:
        return f"django-session:{session_key}"

    raise SessionSecurityDenied("session_invalid_state", "Authenticated session state is invalid. Cannot identify the credential used by authentication.")


def token_fingerprint(request) -> str:
    identity = _credential_identity(request).encode("utf-8")
    secret = str(settings.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, TOKEN_NAMESPACE + identity, hashlib.sha256).hexdigest()


def _legacy_knox_fingerprint(request) -> str:
    """Return the pre-S6 Knox fingerprint for an already validated credential.

    Older Core releases fingerprinted the raw bearer token. The current S6
    boundary fingerprints ``knox:<digest>`` instead. We only reproduce the old
    value after ``_credential_identity`` has independently proved that the
    Authorization bearer hashes to ``request.auth.digest``. This keeps the
    compatibility bridge from re-introducing the old arbitrary-header bug.
    """
    digest = request_knox_digest(request)
    if not digest:
        return ""
    identity = _credential_identity(request)
    if identity != f"knox:{digest}":
        return ""
    authorization = str(request.META.get("HTTP_AUTHORIZATION") or "").strip()
    parts = authorization.split(None, 1)
    if len(parts) != 2 or not parts[1].strip():
        return ""
    raw = parts[1].strip().encode("utf-8")
    secret = str(settings.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, TOKEN_NAMESPACE + raw, hashlib.sha256).hexdigest()


def request_knox_digest(request) -> str:
    auth = getattr(request, "auth", None)
    digest = getattr(auth, "digest", None)
    return str(digest or "")[:128]


def _login_session_ref(digest: str) -> str:
    secret = str(settings.SECRET_KEY).encode("utf-8")
    value = str(digest or "").encode("utf-8")
    return hmac.new(secret, LOGIN_SESSION_NAMESPACE + value, hashlib.sha256).hexdigest()


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


def _audit(event_type: str, *, session=None, username: str = "", previous_ip: str = "", new_ip: str = "", reason: str = "", requested_by: str = "", metadata: dict | None = None, policy: dict | None = None, force: bool = False):
    policy = policy or _policy_dict()
    if not force and not policy.get("session_audit_enabled", True):
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



def _session_created_auth_metadata(user) -> dict[str, str]:
    """Return read-only authentication provenance for a newly trusted session.

    Tactical remains the authentication authority.  A linked allauth
    SocialAccount marks the Tactical account as SSO-owned; otherwise the
    session is recorded as password-authenticated.  Tec-Tac does not write to
    Tactical authentication tables here.
    """
    if not bool(getattr(user, "is_sso_user", False)):
        return {"auth_method": "password"}

    # Import lazily so portable Core checks do not need allauth installed. In a
    # Tactical runtime this is the same model behind User.is_sso_user.
    from allauth.socialaccount.models import SocialAccount

    account = (
        SocialAccount.objects
        .filter(user_id=getattr(user, "pk", None))
        .only("provider")
        .order_by("pk")
        .first()
    )
    return {
        "auth_method": "sso",
        "provider": str(getattr(account, "provider", "") or ""),
    }

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
        "tactical_session_linked": bool(session.knox_digest),
        "current": bool(current),
        "revoked": bool(session.revoked),
        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
        "revocation_reason": session.revocation_reason,
    }


def _invalidate_knox_for_session(session: TecTacSessionTrust) -> None:
    """Invalidate the Tactical credential represented by a revoked trust row.

    Current rows carry a stable Knox digest and can revoke exactly one token.
    Legacy rows may predate that binding; for those rows Core cannot safely
    distinguish the credential, so revocation fails closed by invalidating all
    Knox tokens for the recorded username rather than leaving a live Tactical
    credential behind.
    """
    digest = str(getattr(session, "knox_digest", "") or "")
    if digest:
        AuthToken.objects.filter(digest=digest).delete()
        return
    username = str(getattr(session, "username", "") or "").strip()
    if username:
        AuthToken.objects.filter(user__username=username).delete()


def _revoke_locked(
    session: TecTacSessionTrust,
    *,
    reason: str,
    requested_by: str = "",
    event_type: str = "session_revoked",
    policy: dict | None = None,
    invalidate_knox: bool = True,
):
    if not session.revoked:
        session.revoked = True
        session.revoked_at = timezone.now()
        session.revoked_by = str(requested_by or "")[:150]
        session.revocation_reason = str(reason or "revoked")[:255]
        session.save(update_fields=["revoked", "revoked_at", "revoked_by", "revocation_reason", "updated_at"])
        if invalidate_knox:
            _invalidate_knox_for_session(session)
        _audit(event_type, session=session, reason=reason, requested_by=requested_by, policy=policy)
    return session




def _bind_knox_digest(session: TecTacSessionTrust, digest: str) -> bool:
    """Bind a legacy row once; never rebind an already-bound credential row."""
    digest = str(digest or "")
    if not digest:
        return False
    existing = str(getattr(session, "knox_digest", "") or "")
    if existing:
        if not hmac.compare_digest(existing, digest):
            raise SessionSecurityDenied(
                "session_invalid_state",
                "Stored session credential binding does not match the authenticated Knox token.",
            )
        return False
    session.knox_digest = digest
    return True

def _existing_session_for_credential(request, *, current_fingerprint: str):
    """Resolve trust state across current and pre-S6 fingerprint formats.

    Knox digest is the stable non-secret credential identifier. Any revoked row
    for the same digest dominates *even a current-fingerprint active row*, so a
    credential cannot come back merely because the fingerprint representation
    changed. Rows created before the digest field was populated are recovered
    through the old raw-bearer HMAC, but only after S6 has validated that bearer
    against the authenticated Knox digest.
    """
    digest = request_knox_digest(request)
    digest_rows = []
    if digest:
        digest_rows = list(
            TecTacSessionTrust.objects.select_for_update()
            .filter(knox_digest=digest)
            .order_by("-revoked", "-last_seen_at", "-created_at")
        )
        revoked = next((row for row in digest_rows if row.revoked), None)
        if revoked is not None:
            return revoked

    try:
        current = TecTacSessionTrust.objects.select_for_update().get(token_fingerprint=current_fingerprint)
    except TecTacSessionTrust.DoesNotExist:
        current = None
    if current is not None:
        return current

    if digest_rows:
        return digest_rows[0]

    legacy = _legacy_knox_fingerprint(request)
    if legacy and legacy != current_fingerprint:
        try:
            session = TecTacSessionTrust.objects.select_for_update().get(token_fingerprint=legacy)
        except TecTacSessionTrust.DoesNotExist:
            session = None
        if session is not None:
            if _bind_knox_digest(session, digest):
                session.save(update_fields=["knox_digest", "updated_at"])
            return session
    return None


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
        session = _existing_session_for_credential(request, current_fingerprint=fingerprint)
        if session is None:
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
                    "knox_digest": request_knox_digest(request),
                    "absolute_expires_at": absolute,
                    "idle_expires_at": idle,
                },
            )
            if not created:
                session = TecTacSessionTrust.objects.select_for_update().get(pk=session.pk)
            else:
                _audit(
                    "session_created",
                    session=session,
                    new_ip=client_ip,
                    metadata=_session_created_auth_metadata(user),
                    policy=policy,
                )

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
        digest = request_knox_digest(request)
        update_fields = ["last_seen_at", "last_ip", "absolute_expires_at", "idle_expires_at", "updated_at"]
        if _bind_knox_digest(session, digest):
            update_fields.append("knox_digest")
        _refresh_expiry(session, policy)
        session.save(update_fields=update_fields)
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
    preserved_digests: set[str] = set()
    with transaction.atomic():
        base_qs = TecTacSessionTrust.objects.select_for_update().filter(username=username, revoked=False)
        if except_session_id:
            # Revoke-others is a credential-level operation as well as a Tec-Tac
            # trust-row operation. Preserve only the Knox credential linked to
            # the explicitly excluded/current session; every other Tactical Knox
            # token for the user must be invalidated, even if Tec-Tac has never
            # observed it and therefore has no trust row for it.
            current = base_qs.filter(pk=except_session_id).first()
            current_digest = str(getattr(current, "knox_digest", "") or "")
            if current_digest:
                preserved_digests.add(current_digest)
            qs = base_qs.exclude(pk=except_session_id)
        else:
            qs = base_qs
        for session in qs:
            _revoke_locked(session, reason=reason, requested_by=requested_by, invalidate_knox=False)
            count += 1
            ids.append(str(session.id))

        token_qs = AuthToken.objects.filter(user__username=username)
        if preserved_digests:
            token_qs = token_qs.exclude(digest__in=preserved_digests)
        token_qs.delete()
    if count:
        _audit("user_sessions_revoked", username=username, reason=reason, requested_by=requested_by, metadata={"count": count, "session_ids": ids})
    return {"username": username, "revoked": count, "session_ids": ids}


def _active_knox_tokens():
    now = timezone.now()
    return AuthToken.objects.select_related("user").filter(expiry__gt=now).order_by("-created")


def _visible_active_knox_tokens(*, requester=None, search: str | None = None):
    qs = _active_knox_tokens()
    if not _is_effective_superuser(requester):
        protected_users = get_user_model().objects.filter(
            Q(is_superuser=True)
            | Q(username=str(getattr(settings, "ROOT_USER", "") or ""))
            | Q(role__is_superuser=True)
        ).values("pk")
        qs = qs.exclude(user_id__in=protected_users)
    term = str(search or "").strip()
    if term:
        observed_digests = TecTacSessionTrust.objects.filter(last_ip__icontains=term).exclude(knox_digest="").values("knox_digest")
        qs = qs.filter(Q(user__username__icontains=term) | Q(digest__in=observed_digests))
    return qs


def _serialize_active_login_sessions(tokens, *, current_request=None) -> list[dict[str, Any]]:
    tokens = list(tokens)
    digests = [str(item.digest) for item in tokens]
    trust_by_digest = {
        item.knox_digest: item
        for item in TecTacSessionTrust.objects.filter(knox_digest__in=digests).order_by("-last_seen_at")
        if item.knox_digest
    }
    current_digest = request_knox_digest(current_request) if current_request is not None else ""
    rows = []
    for token in tokens:
        digest = str(token.digest)
        trust = trust_by_digest.get(digest)
        rows.append({
            "id": _login_session_ref(digest),
            "user_id": token.user_id,
            "username": str(getattr(token.user, "username", "") or ""),
            "created_at": token.created.isoformat() if token.created else None,
            "expires_at": token.expiry.isoformat() if token.expiry else None,
            "current": bool(current_digest and hmac.compare_digest(digest, current_digest)),
            "tec_tac_observed": trust is not None,
            "last_activity_at": trust.last_activity_at.isoformat() if trust and trust.last_activity_at else None,
            "last_seen_at": trust.last_seen_at.isoformat() if trust and trust.last_seen_at else None,
            "last_ip": trust.last_ip if trust else "",
        })
    return rows


def list_active_login_sessions(*, current_request=None, requester=None) -> list[dict[str, Any]]:
    requester = requester or getattr(current_request, "user", None)
    return _serialize_active_login_sessions(
        _visible_active_knox_tokens(requester=requester)[:2000],
        current_request=current_request,
    )


def page_active_login_sessions(*, current_request=None, requester=None, search: str | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    requester = requester or getattr(current_request, "user", None)
    try:
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 100))
        if page > SESSION_PAGINATION_MAX_PAGE:
            raise SessionSecurityError(f"page may not exceed {SESSION_PAGINATION_MAX_PAGE}.")
    except (TypeError, ValueError) as exc:
        raise SessionSecurityError("page and page_size must be integers.") from exc
    qs = _visible_active_knox_tokens(requester=requester, search=search)
    total = qs.count()
    pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    items = _serialize_active_login_sessions(qs[offset:offset + page_size], current_request=current_request)
    return {
        "items": items,
        "count": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "next_page": page + 1 if page < pages else None,
        "previous_page": page - 1 if page > 1 and pages else None,
    }


def _find_active_knox_token(session_ref: str):
    target = str(session_ref or "").strip().lower()
    if len(target) != 64:
        return None
    for token in _active_knox_tokens():
        if hmac.compare_digest(_login_session_ref(str(token.digest)), target):
            return token
    return None


def revoke_active_login_session(session_ref: str, *, reason: str = "administrator-request", requested_by: str = "", requester=None) -> dict[str, Any]:
    with transaction.atomic():
        token = _find_active_knox_token(session_ref)
        if token is None:
            raise SessionSecurityError("Active login session was not found.")
        if not _can_administer_login_target(requester, token.user):
            raise PermissionError("Superuser or root login sessions require superuser authority.")
        digest = str(token.digest)
        username = str(getattr(token.user, "username", "") or "")
        trust_rows = list(TecTacSessionTrust.objects.select_for_update().filter(knox_digest=digest, revoked=False))
        for trust in trust_rows:
            _revoke_locked(trust, reason=reason, requested_by=requested_by, event_type="session_revoked")
        token.delete()
        _audit(
            "tactical_login_session_revoked",
            username=username,
            reason=reason,
            requested_by=requested_by,
            metadata={"session_ref": str(session_ref), "tec_tac_sessions": len(trust_rows)},
        )
        return {"id": str(session_ref), "username": username, "revoked": True}


def revoke_user_login_sessions(user_id: int, *, reason: str = "administrator-request", requested_by: str = "", requester=None) -> dict[str, Any]:
    with transaction.atomic():
        target_user = get_user_model().objects.select_related("role").filter(pk=user_id).first()
        if target_user is not None and not _can_administer_login_target(requester, target_user):
            raise PermissionError("Superuser or root login sessions require superuser authority.")
        tokens = list(_active_knox_tokens().filter(user_id=user_id))
        if not tokens:
            return {"user_id": int(user_id), "username": "", "revoked": 0}
        username = str(getattr(tokens[0].user, "username", "") or "")
        digests = [str(token.digest) for token in tokens]
        trust_rows = list(TecTacSessionTrust.objects.select_for_update().filter(knox_digest__in=digests, revoked=False))
        for trust in trust_rows:
            _revoke_locked(trust, reason=reason, requested_by=requested_by, event_type="session_revoked")
        count = len(tokens)
        AuthToken.objects.filter(digest__in=digests).delete()
        _audit(
            "tactical_user_sessions_revoked",
            username=username,
            reason=reason,
            requested_by=requested_by,
            metadata={"user_id": int(user_id), "count": count},
        )
        return {"user_id": int(user_id), "username": username, "revoked": count}


def _serialize_audit_event(item: TecTacSessionAudit) -> dict[str, Any]:
    return {
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
    }


def _audit_queryset(*, username: str | None = None, event_type: str | None = None):
    qs = TecTacSessionAudit.objects.all().order_by("-created_at")
    if username:
        qs = qs.filter(username=str(username))
    if event_type:
        qs = qs.filter(event_type=str(event_type))
    return qs


def list_audit_events(*, username: str | None = None, event_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Compatibility bounded-list contract for backend providers."""
    size = max(1, min(int(limit), 1000))
    return [_serialize_audit_event(item) for item in _audit_queryset(username=username, event_type=event_type)[:size]]


def page_audit_events(*, username: str | None = None, event_type: str | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    try:
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 100))
        if page > SESSION_PAGINATION_MAX_PAGE:
            raise SessionSecurityError(f"page may not exceed {SESSION_PAGINATION_MAX_PAGE}.")
    except (TypeError, ValueError) as exc:
        raise SessionSecurityError("page and page_size must be integers.") from exc
    qs = _audit_queryset(username=username, event_type=event_type)
    total = qs.count()
    pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    items = [_serialize_audit_event(item) for item in qs[offset:offset + page_size]]
    return {
        "items": items,
        "count": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "next_page": page + 1 if page < pages else None,
        "previous_page": page - 1 if page > 1 and pages else None,
    }


def _fingerprint_for_identity(identity: str) -> str:
    secret = str(settings.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, TOKEN_NAMESPACE + str(identity).encode("utf-8"), hashlib.sha256).hexdigest()


def _active_non_knox_credential_fingerprints(*, now) -> set[str] | None:
    """Return fingerprints for API keys and unexpired Django sessions.

    These credentials do not have a stable secondary identifier on older
    TecTacSessionTrust rows. Reconstructing the same HMAC identity lets cleanup
    preserve a revoked tombstone only while the credential could still log in.
    """
    fingerprints: set[str] = set()
    try:
        from accounts.models import APIKey
        for key_id in APIKey.objects.values_list("id", flat=True).iterator():
            fingerprints.add(_fingerprint_for_identity(f"api-key:{key_id}"))
    except Exception:
        # Fail closed for retention: if Tactical's API-key model cannot be read,
        # do not infer those tombstones are safe to delete.
        return None
    try:
        from django.contrib.sessions.models import Session
        for session_key in Session.objects.filter(expire_date__gt=now).values_list("session_key", flat=True).iterator():
            fingerprints.add(_fingerprint_for_identity(f"django-session:{session_key}"))
    except Exception:
        # Same retention-safe behavior for Django's session store.
        return None
    return fingerprints


def _revoked_tombstone_is_live(session: TecTacSessionTrust, *, now, active_non_knox: set[str] | None) -> bool:
    if session.knox_digest:
        try:
            return AuthToken.objects.filter(digest=session.knox_digest).filter(Q(expiry__isnull=True) | Q(expiry__gt=now)).exists()
        except Exception:
            return True
    # Legacy rows may have no stable digest. Preserve the tombstone while any
    # Knox token for the recorded user can still authenticate; otherwise an old
    # revoked row could age out while its Tactical-native credential remained live.
    username = str(getattr(session, "username", "") or "").strip()
    if username:
        try:
            if AuthToken.objects.filter(user__username=username).filter(
                Q(expiry__isnull=True) | Q(expiry__gt=now)
            ).exists():
                return True
        except Exception:
            return True
    if active_non_knox is None:
        return True
    return session.token_fingerprint in active_non_knox


def _expiry_verdict(session: TecTacSessionTrust, policy: dict[str, Any], now) -> tuple[str, str] | None:
    """Return (reason, audit event) when the row is past the current policy.

    Same maths as ensure_request_session: expiry is always recomputed from the
    row's created_at and last_activity_at with the policy in force now, so a
    policy that was lengthened never makes the sweep stricter than a live request.
    """
    absolute = session.created_at + timedelta(minutes=int(policy["absolute_lifetime_minutes"]))
    if now >= absolute:
        return "absolute-timeout", "session_absolute_timeout"
    idle = session.last_activity_at + timedelta(minutes=int(policy["idle_timeout_minutes"]))
    if now >= idle:
        return "idle-timeout", "session_idle_timeout"
    return None


def sweep_expired_sessions(*, now=None, limit: int = SESSION_SWEEP_DEFAULT_LIMIT) -> dict[str, int]:
    """Revoke trust rows past the session policy and delete their Knox tokens.

    ensure_request_session only enforces expiry when a request reaches a Core
    view. A closed tab or a module that only calls Tactical routes would leave
    the Tactical token alive (Knox refreshes it on every use). The scheduler
    tick calls this so enforcement does not depend on the browser.

    Each row is handled in its own transaction and locked with skip_locked, so
    the sweep never races a live request on the same row. Rows without a
    knox_digest are skipped and counted: revoking them would delete every token
    of that username and end the user's other live sessions.
    """
    limit = max(1, int(limit))
    now = now or timezone.now()
    policy = _policy_dict()
    absolute_cutoff = now - timedelta(minutes=int(policy["absolute_lifetime_minutes"]))
    idle_cutoff = now - timedelta(minutes=int(policy["idle_timeout_minutes"]))
    expired = Q(created_at__lte=absolute_cutoff) | Q(last_activity_at__lte=idle_cutoff)

    live = TecTacSessionTrust.objects.filter(revoked=False)
    skipped_no_digest = live.filter(knox_digest="").filter(expired).count()
    candidate_ids = list(
        live.exclude(knox_digest="").filter(expired).order_by("created_at").values_list("pk", flat=True)[:limit]
    )

    result = {
        "checked": len(candidate_ids),
        "revoked": 0,
        "absolute_timeout": 0,
        "idle_timeout": 0,
        "skipped_no_digest": skipped_no_digest,
        "skipped_locked": 0,
        "errors": 0,
        "orphan_tokens_deleted": 0,
    }
    for pk in candidate_ids:
        try:
            with transaction.atomic():
                row = TecTacSessionTrust.objects.select_for_update(skip_locked=True).filter(pk=pk, revoked=False).first()
                if row is None:
                    # Locked by a live request, or revoked since the list was read.
                    result["skipped_locked"] += 1
                    continue
                if not row.knox_digest:
                    continue
                verdict = _expiry_verdict(row, policy, now)
                if verdict is None:
                    continue  # activity arrived after the list was read
                reason, event_type = verdict
                _revoke_locked(row, reason=reason, requested_by=SESSION_SWEEP_ACTOR, event_type=event_type, policy=policy)
                result["revoked"] += 1
                result["absolute_timeout" if reason == "absolute-timeout" else "idle_timeout"] += 1
        except Exception:
            # One bad row must not stop the rest; the next tick retries it.
            result["errors"] += 1

    # A revoked row whose token is still live is a leak (a delete that failed or
    # a token reissued path). Exact digests only. The step is bounded by the same
    # limit and counts tokens that still exist, so old tombstones whose tokens are
    # already gone never fill the limit. The rest is deleted on the next tick.
    revoked_digests = (
        TecTacSessionTrust.objects.filter(revoked=True).exclude(knox_digest="").values("knox_digest")
    )
    orphan_digests = list(
        AuthToken.objects.filter(digest__in=revoked_digests).values_list("digest", flat=True)[:limit]
    )
    if orphan_digests:
        deleted = AuthToken.objects.filter(digest__in=orphan_digests).delete()
        result["orphan_tokens_deleted"] = int(deleted[0]) if deleted else 0
    return result


def cleanup_session_history(*, retention_days: int | None = None) -> dict[str, int]:
    config = TecTacSessionSecurityConfig.current()
    days = int(config.history_retention_days if retention_days is None else retention_days)
    if days < 1 or days > 3650:
        raise SessionSecurityError("retention_days must be between 1 and 3650.")
    now = timezone.now()
    cutoff = now - timedelta(days=days)

    stale_unrevoked = TecTacSessionTrust.objects.filter(
        Q(revoked=False, absolute_expires_at__lt=cutoff)
        | Q(revoked=False, idle_expires_at__lt=cutoff)
    )
    # Deleting the trust row must not leave its Tactical credential behind. Only
    # exact digests are removed: a row with no digest is never matched by username,
    # because that would end the same user's other live sessions.
    stale_digests = [d for d in stale_unrevoked.values_list("knox_digest", flat=True) if d]
    if stale_digests:
        AuthToken.objects.filter(digest__in=stale_digests).delete()
    sessions_deleted = stale_unrevoked.count()
    stale_unrevoked.delete()

    # Revoked trust rows are security tombstones only while the underlying
    # credential can still authenticate. Once the credential is gone/expired,
    # retain the tombstone for the configured history window and then remove it.
    active_non_knox: set[str] | None = None
    try:
        active_non_knox = _active_non_knox_credential_fingerprints(now=now)
    except Exception:
        active_non_knox = None
    revoked_deleted = 0
    revoked_qs = TecTacSessionTrust.objects.filter(revoked=True).filter(
        Q(revoked_at__lt=cutoff) | Q(revoked_at__isnull=True, updated_at__lt=cutoff)
    )
    for row in revoked_qs.iterator():
        if _revoked_tombstone_is_live(row, now=now, active_non_knox=active_non_knox):
            continue
        row.delete()
        revoked_deleted += 1

    audits_qs = TecTacSessionAudit.objects.filter(created_at__lt=cutoff)
    audits_deleted = audits_qs.count()
    audits_qs.delete()
    return {
        "sessions_deleted": sessions_deleted + revoked_deleted,
        "expired_sessions_deleted": sessions_deleted,
        "revoked_tombstones_deleted": revoked_deleted,
        "audit_events_deleted": audits_deleted,
        "retention_days": days,
        "revoked_tombstones_preserved": TecTacSessionTrust.objects.filter(revoked=True).count(),
    }


def cleanup_session_history_if_due(*, now=None, interval: timedelta = timedelta(days=1)) -> dict[str, Any]:
    """Run Core-owned session history retention at most once per interval.

    The Tec-Tac scheduler timer invokes this every minute. The persisted marker
    is advanced only after a successful cleanup, so failures are retried by the
    next scheduler tick rather than silently delaying retention for another day.
    """
    current_time = now or timezone.now()
    config = TecTacSessionSecurityConfig.current()
    last_run = getattr(config, "last_history_cleanup_at", None)
    if last_run is not None and last_run > current_time - interval:
        return {
            "ran": False,
            "reason": "not_due",
            "last_history_cleanup_at": last_run,
            "next_due_at": last_run + interval,
        }

    result = cleanup_session_history()
    config.last_history_cleanup_at = current_time
    config.save(update_fields=["last_history_cleanup_at"])
    return {
        "ran": True,
        "last_history_cleanup_at": current_time,
        "next_due_at": current_time + interval,
        **result,
    }


def diagnostics() -> dict[str, Any]:
    policy = _policy_dict()
    now = timezone.now()
    return {
        "enabled": True,
        "capability": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "policy": policy,
        "last_history_cleanup_at": TecTacSessionSecurityConfig.current().last_history_cleanup_at,
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
        # Tactical's credential-check endpoint issues a short-lived Knox token
        # before local TOTP enrollment exists. That token is authentication
        # proof for the enrollment flow only; it must never unlock Tec-Tac's
        # operational APIs. SSO accounts are exempt because their MFA lifecycle
        # is owned by the external identity provider.
        if request_knox_digest(request) and not bool(getattr(request.user, "is_sso_user", False)) and not getattr(request.user, "totp_key", None):
            raise SessionSecurityDenied(
                "mfa_enrollment_required",
                "Complete authenticator enrollment before using Tec-Tac.",
            )
        request.tec_tac_session = ensure_request_session(request)
        return True


class SessionSecurityProvider:
    def get_policy(self, *, context: dict | None = None) -> dict[str, Any]:
        return _policy_dict()

    def list_sessions(self, *, username: str | None = None, include_revoked: bool = True, context: dict | None = None) -> list[dict[str, Any]]:
        return list_sessions(username=username, include_revoked=include_revoked)

    def list_audit_events(self, *, username: str | None = None, event_type: str | None = None, limit: int = 200, context: dict | None = None) -> list[dict[str, Any]]:
        return list_audit_events(username=username, event_type=event_type, limit=limit)

    def page_audit_events(self, *, username: str | None = None, event_type: str | None = None, page: int = 1, page_size: int = 50, context: dict | None = None) -> dict[str, Any]:
        return page_audit_events(username=username, event_type=event_type, page=page, page_size=page_size)

    def revoke_session(self, *, session_id: str, reason: str = "module-request", context: dict) -> dict[str, Any]:
        return revoke_session(session_id, reason=reason, requested_by=str((context or {}).get("requested_by") or (context or {}).get("username") or "module"))

    def revoke_user_sessions(self, *, username: str, except_session_id: str | None = None, reason: str = "module-request", context: dict) -> dict[str, Any]:
        return revoke_user_sessions(username, except_session_id=except_session_id, reason=reason, requested_by=str((context or {}).get("requested_by") or (context or {}).get("username") or "module"))

    def cleanup(self, *, context: dict | None = None) -> dict[str, int]:
        return cleanup_session_history()

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
            "default_history_retention_days": DEFAULT_HISTORY_RETENTION_DAYS,
            "default_activity_heartbeat_seconds": DEFAULT_ACTIVITY_HEARTBEAT_SECONDS,
            "enforcement": "core",
        },
    )


def get_session_security_provider() -> SessionSecurityProvider:
    return _PROVIDER
