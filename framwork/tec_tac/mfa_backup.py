from __future__ import annotations

import secrets
from typing import Any

import pyotp
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from .models import TecTacMfaBackupCode
from .session_security import SessionSecurityError, _audit

BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 10
BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _normalize_code(value: str) -> str:
    return "".join(ch for ch in str(value or "").upper() if ch.isalnum())


def _format_code(value: str) -> str:
    raw = _normalize_code(value)
    return f"{raw[:5]}-{raw[5:]}" if len(raw) > 5 else raw


def backup_code_status(user) -> dict[str, Any]:
    qs = TecTacMfaBackupCode.objects.filter(user=user)
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


def generate_backup_codes(user, *, requested_by: str = "") -> dict[str, Any]:
    if bool(getattr(user, "is_sso_user", False)):
        raise SessionSecurityError("MFA backup codes are not available for SSO-managed accounts.")
    if not getattr(user, "totp_key", None):
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
            TecTacMfaBackupCode(user=user, code_hash=make_password(code)) for code in codes
        ])
        _audit(
            "mfa_backup_codes_generated",
            username=str(getattr(user, "username", "") or ""),
            requested_by=str(requested_by or getattr(user, "username", "") or ""),
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
        raise SessionSecurityError("Current password or authenticator code was not accepted.")
    token = _normalize_code(totp_code)
    if not token or not pyotp.TOTP(user.totp_key).verify(token, valid_window=1):
        raise SessionSecurityError("Current password or authenticator code was not accepted.")


def consume_backup_code(user, code: str, *, requested_by: str = "") -> bool:
    normalized = _normalize_code(code)
    if len(normalized) != BACKUP_CODE_LENGTH:
        return False

    now = timezone.now()
    with transaction.atomic():
        candidates = list(
            TecTacMfaBackupCode.objects.select_for_update()
            .filter(user=user, used_at__isnull=True)
            .order_by("created_at", "id")
        )
        for item in candidates:
            if check_password(normalized, item.code_hash):
                item.used_at = now
                item.save(update_fields=["used_at"])
                _audit(
                    "mfa_backup_code_used",
                    username=str(getattr(user, "username", "") or ""),
                    requested_by=str(requested_by or getattr(user, "username", "") or ""),
                    metadata={"backup_code_id": str(item.id)},
                )
                return True
    return False
