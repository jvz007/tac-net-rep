from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

import pyotp
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from .models import TecTacMfaBackupCode
from .session_security import SessionSecurityError, _audit

BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 10
BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TOTP_BINDING_NAMESPACE = b"tec-tac-mfa-backup-totp:v1\x00"


class MfaBackupProofError(SessionSecurityError):
    """Password/TOTP proof failed without disclosing which factor was wrong."""


def _normalize_code(value: str) -> str:
    return "".join(ch for ch in str(value or "").upper() if ch.isalnum())


def _format_code(value: str) -> str:
    raw = _normalize_code(value)
    return f"{raw[:5]}-{raw[5:]}" if len(raw) > 5 else raw


def _totp_fingerprint(user) -> str:
    key = str(getattr(user, "totp_key", "") or "")
    if not key:
        return ""
    secret = str(settings.SECRET_KEY).encode("utf-8")
    return hmac.new(secret, TOTP_BINDING_NAMESPACE + key.encode("utf-8"), hashlib.sha256).hexdigest()


def _security_audit(event_type: str, user, *, requested_by: str = "", reason: str = "", metadata: dict | None = None, client_ip: str = ""):
    return _audit(
        event_type,
        username=str(getattr(user, "username", "") or ""),
        requested_by=str(requested_by or getattr(user, "username", "") or ""),
        reason=str(reason or "")[:255],
        new_ip=str(client_ip or "")[:64],
        metadata=dict(metadata or {}),
        force=True,
    )


def audit_generation_proof_failure(user, *, requested_by: str = "", client_ip: str = "") -> None:
    _security_audit(
        "mfa_backup_generation_proof_failed",
        user,
        requested_by=requested_by,
        reason="password-or-totp-proof-rejected",
        client_ip=client_ip,
    )


def _delete_stale_codes_locked(user, current_fingerprint: str, *, requested_by: str = "") -> int:
    stale = TecTacMfaBackupCode.objects.select_for_update().filter(user=user).exclude(totp_fingerprint=current_fingerprint)
    count = stale.count()
    if count:
        stale.delete()
        _security_audit(
            "mfa_backup_codes_invalidated",
            user,
            requested_by=requested_by,
            reason="totp-key-changed",
            metadata={"count": count},
        )
    return count


def backup_code_status(user) -> dict[str, Any]:
    current_fingerprint = _totp_fingerprint(user)
    with transaction.atomic():
        _delete_stale_codes_locked(user, current_fingerprint, requested_by=str(getattr(user, "username", "") or ""))
        qs = TecTacMfaBackupCode.objects.filter(user=user, totp_fingerprint=current_fingerprint)
        total = qs.count()
        unused = qs.filter(used_at__isnull=True).count()
        latest = qs.order_by("-created_at").values_list("created_at", flat=True).first()
    return {
        "totp_configured": bool(getattr(user, "totp_key", None)),
        "sso_user": bool(getattr(user, "is_sso_user", False)),
        "configured": total > 0,
        "total": total,
        "unused": unused,
        "used": max(0, total - unused),
        "generated_at": latest.isoformat() if latest else None,
    }


def _new_code() -> str:
    return "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_LENGTH))


_DUMMY_CODE_HASH = make_password("TEC-TAC-DUMMY-BACKUP-CODE")


def burn_backup_code_hash_cost(*, checks: int = BACKUP_CODE_COUNT) -> None:
    """Perform fixed backup-code hash work for failed login paths.

    Password authentication already has Django's constant-cost behaviour. This
    closes the second-factor timing gap: a wrong password and a correct password
    paired with a wrong recovery code both pay the same backup-code hash budget.
    """
    dummy = _DUMMY_CODE_HASH
    for _ in range(max(0, int(checks))):
        check_password("TEC-TAC-INVALID-CODE", dummy)


def generate_backup_codes(user, *, requested_by: str = "") -> dict[str, Any]:
    if bool(getattr(user, "is_sso_user", False)):
        raise SessionSecurityError("MFA backup codes are not available for SSO-managed accounts.")
    fingerprint = _totp_fingerprint(user)
    if not fingerprint:
        raise SessionSecurityError("TOTP must be configured before backup codes can be generated.")

    codes = []
    seen = set()
    while len(codes) < BACKUP_CODE_COUNT:
        code = _new_code()
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)

    with transaction.atomic():
        TecTacMfaBackupCode.objects.select_for_update().filter(user=user).delete()
        TecTacMfaBackupCode.objects.bulk_create([
            TecTacMfaBackupCode(user=user, code_hash=make_password(code), totp_fingerprint=fingerprint)
            for code in codes
        ])
        _security_audit(
            "mfa_backup_codes_generated",
            user,
            requested_by=requested_by,
            metadata={"count": len(codes)},
        )

    return {
        "codes": [_format_code(code) for code in codes],
        "count": len(codes),
        "status": backup_code_status(user),
    }


def verify_generation_proof(user, *, password: str, totp_code: str) -> None:
    if bool(getattr(user, "is_sso_user", False)):
        raise SessionSecurityError("MFA backup codes are not available for SSO-managed accounts.")
    if not getattr(user, "totp_key", None):
        raise SessionSecurityError("TOTP is not configured for this account.")
    if not password or not user.check_password(password):
        raise MfaBackupProofError("Current password or authenticator code was not accepted.")
    token = _normalize_code(totp_code)
    if not token or not pyotp.TOTP(user.totp_key).verify(token, valid_window=1):
        raise MfaBackupProofError("Current password or authenticator code was not accepted.")


def consume_backup_code(user, code: str, *, requested_by: str = "") -> bool:
    normalized = _normalize_code(code)
    supplied = normalized if len(normalized) == BACKUP_CODE_LENGTH else "TECINVALID"
    current_fingerprint = _totp_fingerprint(user)
    now = timezone.now()

    with transaction.atomic():
        _delete_stale_codes_locked(user, current_fingerprint, requested_by=requested_by)
        candidates = list(
            TecTacMfaBackupCode.objects.select_for_update()
            .filter(user=user, used_at__isnull=True, totp_fingerprint=current_fingerprint)
            .order_by("created_at", "id")[:BACKUP_CODE_COUNT]
        ) if current_fingerprint else []

        matched = None
        checks = 0
        for item in candidates:
            is_match = check_password(supplied, item.code_hash)
            checks += 1
            if is_match and matched is None and len(normalized) == BACKUP_CODE_LENGTH:
                matched = item

        # Failed login paths always perform exactly BACKUP_CODE_COUNT expensive
        # hash checks regardless of password correctness, malformed code, code
        # position, or remaining-code count.
        if checks < BACKUP_CODE_COUNT:
            burn_backup_code_hash_cost(checks=BACKUP_CODE_COUNT - checks)

        if matched is None:
            return False

        matched.used_at = now
        matched.save(update_fields=["used_at"])
        _security_audit(
            "mfa_backup_code_used",
            user,
            requested_by=requested_by,
            metadata={"backup_code_id": str(matched.id)},
        )
        return True
