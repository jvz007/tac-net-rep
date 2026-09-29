#!/usr/bin/env python3
"""F2 real Tactical/PostgreSQL TOTP reset -> re-enrolment regression.

Run on a Tactical server with the normal Django settings/database available.
This deliberately uses real pyotp, Tactical's User and Knox AuthToken models,
Tec-Tac backup-code storage, the production reset_own_totp service, and the
production TotpEnrollmentView. The outer transaction is always rolled back.
"""
from __future__ import annotations

import hashlib
import os
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

import django
django.setup()

import pyotp
from django.contrib.auth.hashers import make_password
from django.db import connection, transaction
from django.utils import timezone
from knox.models import AuthToken
from rest_framework.test import APIRequestFactory, force_authenticate

from accounts.models import User
from tec_tac.account_self_service import AccountSelfServiceError, reset_own_totp
from tec_tac.mfa_backup import _totp_fingerprint
from tec_tac.models import TecTacMfaBackupCode
from tec_tac.views import TotpEnrollmentView

if connection.vendor != "postgresql":
    raise SystemExit(
        f"[TEST] PostgreSQL required for F2 integration regression; got {connection.vendor!r}"
    )

PASSWORD = "TecTac-F2-Test-Only!123"
factory = APIRequestFactory()


def token_digest(label: str) -> str:
    return hashlib.sha512(label.encode("utf-8")).hexdigest()


def create_knox_token(user: User, label: str, *, ttl_minutes: int = 60) -> AuthToken:
    now = timezone.now()
    return AuthToken.objects.create(
        user=user,
        digest=token_digest(label),
        token_key=(label.replace("-", "") + "01234567")[:8],
        created=now,
        expiry=now + timedelta(minutes=ttl_minutes),
    )


def definitely_wrong_code(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    current = totp.now()
    for value in range(1000000):
        candidate = f"{value:06d}"
        if candidate != current and not totp.verify(candidate, valid_window=1):
            return candidate
    raise AssertionError("could not construct an invalid TOTP code")


with transaction.atomic():
    suffix = (User.objects.order_by("-id").values_list("id", flat=True).first() or 0) + 1
    user = User.objects.create_user(
        username=f"tectac_f2_pg_{suffix}",
        email=f"tectac-f2-{suffix}@invalid.local",
        password=PASSWORD,
    )

    old_secret = pyotp.random_base32()
    user.totp_key = old_secret
    user.save(update_fields=["totp_key"])
    fingerprint = _totp_fingerprint(user)

    for idx in range(2):
        TecTacMfaBackupCode.objects.create(
            user=user,
            code_hash=make_password(f"f2-recovery-{idx}"),
            totp_fingerprint=fingerprint,
        )

    create_knox_token(user, f"f2-live-a-{suffix}")
    create_knox_token(user, f"f2-live-b-{suffix}")
    assert AuthToken.objects.filter(user=user).count() == 2
    assert TecTacMfaBackupCode.objects.filter(user=user).count() == 2

    # A wrong current authenticator code must be a true no-op: do not clear the
    # seed, recovery codes, or Tactical Knox credentials.
    wrong = definitely_wrong_code(old_secret)
    try:
        reset_own_totp(
            user,
            current_password=PASSWORD,
            current_totp=wrong,
        )
    except AccountSelfServiceError:
        pass
    else:
        raise AssertionError("F2 accepted an invalid current authenticator code")

    user.refresh_from_db()
    assert user.totp_key == old_secret
    assert TecTacMfaBackupCode.objects.filter(user=user).count() == 2
    assert AuthToken.objects.filter(user=user).count() == 2

    # Real pyotp proof drives the production reset. The reset must clear the old
    # seed, invalidate all recovery codes, and remove every Tactical Knox token.
    current = pyotp.TOTP(old_secret).now()
    result = reset_own_totp(
        user,
        current_password=PASSWORD,
        current_totp=current,
    )
    assert result["reset"] is True
    assert result["reauthentication_required"] is True

    user.refresh_from_db()
    assert user.totp_key == ""
    assert not TecTacMfaBackupCode.objects.filter(user=user).exists()
    assert not AuthToken.objects.filter(user=user).exists()

    # Tactical's next-sign-in path supplies a short-lived setup credential.
    # Exercise the production Tec-Tac enrollment view with that credential so
    # this test proves reset -> a genuinely new seed rather than reset alone.
    setup_token = create_knox_token(user, f"f2-setup-{suffix}", ttl_minutes=3)
    request = factory.post(
        "/api/tfd/auth/totp/enrollment/?ui_url=https://tec-tac.invalid/tec-tac/",
        {"password": PASSWORD},
        format="json",
    )
    force_authenticate(request, user=user, token=setup_token)
    response = TotpEnrollmentView.as_view()(request)
    response.render()
    assert response.status_code == 201, response.data

    new_secret = str(response.data.get("totp_key") or "")
    assert new_secret
    assert new_secret != old_secret
    assert response.data.get("one_time") is True
    assert not AuthToken.objects.filter(pk=setup_token.pk).exists(), "setup Knox token was not revoked"

    user.refresh_from_db()
    assert user.totp_key == new_secret
    assert not TecTacMfaBackupCode.objects.filter(user=user).exists()

    # The new authenticator secret is operational and the old seed is no longer
    # the account binding. This is the proof the subsequent Tactical login uses.
    new_code = pyotp.TOTP(new_secret).now()
    assert pyotp.TOTP(new_secret).verify(new_code, valid_window=1)
    assert _totp_fingerprint(user) != fingerprint

    transaction.set_rollback(True)

print("[TEST] PASS F2 real TOTP reset and next-sign-in re-enrolment")
