from __future__ import annotations

import hashlib
import math
import time

from django.core.cache import cache
from rest_framework.throttling import SimpleRateThrottle


MFA_BACKUP_FAILURE_LIMIT = 5
MFA_BACKUP_FAILURE_WINDOW_SECONDS = 15 * 60
MFA_BACKUP_SUCCESS_LIMIT = 20
MFA_BACKUP_SUCCESS_WINDOW_SECONDS = 24 * 60 * 60


class _AuthenticatedAttemptThrottle(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        user = getattr(request, "user", None)
        ident = str(getattr(user, "pk", "anon") or "anon")
        remote = str(request.META.get("REMOTE_ADDR") or "")[:64]
        return self.cache_format % {"scope": self.scope, "ident": f"{ident}:{remote}"}


class TotpEnrollmentMinThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_totp_enrollment_min"
    rate = "5/min"


class TotpEnrollmentDayThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_totp_enrollment_day"
    rate = "20/day"


class AuditWriteMinThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_audit_write_min"
    rate = "60/min"


class AuditWriteDayThrottle(_AuthenticatedAttemptThrottle):
    scope = "tec_tac_audit_write_day"
    rate = "1000/day"


def _account_token(value: object) -> str:
    raw = str(value or "").strip().casefold()
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _user_token(user: object) -> str:
    pk = getattr(user, "pk", None)
    if pk is not None:
        return _account_token(f"pk:{pk}")
    return _account_token(f"username:{getattr(user, 'username', '')}")


def _username_token(username: object) -> str:
    return _account_token(f"username:{str(username or '').strip().casefold()}")


def _bucket_keys(kind: str, token: str) -> tuple[str, str]:
    base = f"tec-tac:mfa-backup:{kind}:{token}"
    return f"{base}:count", f"{base}:reset"


def _bucket_retry_after(kind: str, token: str, *, limit: int, window: int) -> int | None:
    count_key, reset_key = _bucket_keys(kind, token)
    try:
        count = int(cache.get(count_key, 0) or 0)
    except (TypeError, ValueError):
        count = 0
    if count < limit:
        return None
    now = time.time()
    try:
        reset_at = float(cache.get(reset_key, 0) or 0)
    except (TypeError, ValueError):
        reset_at = 0
    if reset_at <= now:
        cache.delete_many([count_key, reset_key])
        return None
    return max(1, int(math.ceil(reset_at - now)))


def _bucket_record(kind: str, token: str, *, window: int) -> None:
    count_key, reset_key = _bucket_keys(kind, token)
    now = time.time()
    if cache.add(count_key, 1, timeout=window):
        cache.set(reset_key, now + window, timeout=window)
        return
    try:
        cache.incr(count_key)
    except (ValueError, TypeError):
        cache.set(count_key, 1, timeout=window)
        cache.set(reset_key, now + window, timeout=window)
    if cache.get(reset_key) is None:
        cache.set(reset_key, now + window, timeout=window)


def _bucket_clear(kind: str, token: str) -> None:
    cache.delete_many(list(_bucket_keys(kind, token)))


def mfa_backup_proof_failure_retry_after(user: object) -> int | None:
    return _bucket_retry_after(
        "proof-failure",
        _user_token(user),
        limit=MFA_BACKUP_FAILURE_LIMIT,
        window=MFA_BACKUP_FAILURE_WINDOW_SECONDS,
    )


def record_mfa_backup_proof_failure(user: object) -> None:
    _bucket_record("proof-failure", _user_token(user), window=MFA_BACKUP_FAILURE_WINDOW_SECONDS)


def reset_mfa_backup_proof_failures(user: object) -> None:
    _bucket_clear("proof-failure", _user_token(user))


def mfa_backup_proof_success_retry_after(user: object) -> int | None:
    return _bucket_retry_after(
        "proof-success",
        _user_token(user),
        limit=MFA_BACKUP_SUCCESS_LIMIT,
        window=MFA_BACKUP_SUCCESS_WINDOW_SECONDS,
    )


def record_mfa_backup_proof_success(user: object) -> None:
    _bucket_record("proof-success", _user_token(user), window=MFA_BACKUP_SUCCESS_WINDOW_SECONDS)


def backup_code_login_failure_retry_after(username: object) -> int | None:
    return _bucket_retry_after(
        "login-failure",
        _username_token(username),
        limit=MFA_BACKUP_FAILURE_LIMIT,
        window=MFA_BACKUP_FAILURE_WINDOW_SECONDS,
    )


def record_backup_code_login_failure(username: object) -> None:
    _bucket_record("login-failure", _username_token(username), window=MFA_BACKUP_FAILURE_WINDOW_SECONDS)


def reset_backup_code_login_failures(username: object) -> None:
    _bucket_clear("login-failure", _username_token(username))
