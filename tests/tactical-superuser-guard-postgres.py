#!/usr/bin/env python3
"""PostgreSQL integration regression for the D1 Tactical account guard.

Run this on a Tactical server with the normal Django settings/database available.
It deliberately uses the real Tactical ORM and DRF views; unlike the focused
stub regression, PostgreSQL executes SELECT ... FOR UPDATE and will therefore
catch nullable-join locking regressions.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

import django
django.setup()

from django.db import connection, transaction
from rest_framework.test import APIRequestFactory, force_authenticate

from accounts.models import APIKey, Role, User
from accounts import views as tactical_views
from tec_tac import tactical_account_guard as guard

if connection.vendor != "postgresql":
    raise SystemExit(
        f"[TEST] PostgreSQL required for this integration regression; got {connection.vendor!r}"
    )

factory = APIRequestFactory()


def request(method: str, path: str, actor: User, data=None):
    maker = getattr(factory, method.lower())
    req = maker(path, data=data or {}, format="json")
    force_authenticate(req, user=actor)
    return req


def call(view_cls, method: str, path: str, actor: User, data=None, **kwargs):
    req = request(method, path, actor, data)
    response = view_cls.as_view()(req, **kwargs)
    response.render()
    assert response.status_code < 500, (method, path, response.status_code, response.data)
    return response


def new_target(*, role=None):
    suffix = User.objects.order_by("-id").values_list("id", flat=True).first() or 0
    suffix += 1
    return User.objects.create_user(
        username=f"tectac_guard_pg_target_{suffix}",
        email=f"tectac-guard-{suffix}@invalid.local",
        password="TecTac-Test-Only!123",
        role=role,
    )


def new_key(user: User):
    suffix = APIKey.objects.order_by("-id").values_list("id", flat=True).first() or 0
    suffix += 1
    return APIKey.objects.create(
        name=(f"ttg{suffix}")[-25:],
        key=(f"TEC_TAC_GUARD_PG_{suffix:032d}")[-48:],
        user=user,
    )


# Install the production wrappers against the real Tactical view classes.
guard.install_tactical_account_guard()

with transaction.atomic():
    # Everything is rolled back at the end; no test account/key survives.
    role = Role.objects.create(name="TecTac Guard PG Integration", is_superuser=False)
    actor = User.objects.create_user(
        username="tectac_guard_pg_superuser",
        email="tectac-guard-super@invalid.local",
        password="TecTac-Test-Only!123",
        is_superuser=True,
        role=None,
    )

    # Avoid queueing Mesh permission work while exercising the native handlers.
    with patch.object(tactical_views.sync_mesh_perms_task, "delay", return_value=None):
        for protection in (False, True):
            with patch.object(guard, "protection_enabled", return_value=protection):
                for target_role in (None, role):
                    # PUT /accounts/<pk>/users/
                    target = new_target(role=target_role)
                    call(
                        tactical_views.GetUpdateDeleteUser,
                        "put",
                        f"/accounts/{target.pk}/users/",
                        actor,
                        {"first_name": "GuardPG"},
                        pk=target.pk,
                    )

                    # DELETE /accounts/<pk>/users/
                    target = new_target(role=target_role)
                    call(
                        tactical_views.GetUpdateDeleteUser,
                        "delete",
                        f"/accounts/{target.pk}/users/",
                        actor,
                        pk=target.pk,
                    )

                    # POST /accounts/users/reset/ (password reset)
                    target = new_target(role=target_role)
                    call(
                        tactical_views.UserActions,
                        "post",
                        "/accounts/users/reset/",
                        actor,
                        {"id": target.pk, "password": "TecTac-New-Test!123"},
                    )

                    # PUT /accounts/users/reset/ (TOTP reset)
                    target = new_target(role=target_role)
                    target.totp_key = "JBSWY3DPEHPK3PXP"
                    target.save(update_fields=["totp_key"])
                    call(
                        tactical_views.UserActions,
                        "put",
                        "/accounts/users/reset/",
                        actor,
                        {"id": target.pk},
                    )

                    # POST /accounts/apikeys/
                    target = new_target(role=target_role)
                    suffix = APIKey.objects.order_by("-id").values_list("id", flat=True).first() or 0
                    call(
                        tactical_views.GetAddAPIKeys,
                        "post",
                        "/accounts/apikeys/",
                        actor,
                        {"name": (f"ttgp{suffix+1}")[-25:], "user": target.pk},
                    )

                    # PUT /accounts/apikeys/<pk>/
                    target = new_target(role=target_role)
                    api_key = new_key(target)
                    call(
                        tactical_views.GetUpdateDeleteAPIKey,
                        "put",
                        f"/accounts/apikeys/{api_key.pk}/",
                        actor,
                        {"name": api_key.name, "user": target.pk},
                        pk=api_key.pk,
                    )

                    # DELETE /accounts/apikeys/<pk>/
                    target = new_target(role=target_role)
                    api_key = new_key(target)
                    call(
                        tactical_views.GetUpdateDeleteAPIKey,
                        "delete",
                        f"/accounts/apikeys/{api_key.pk}/",
                        actor,
                        pk=api_key.pk,
                    )

    transaction.set_rollback(True)

print("[TEST] PASS PostgreSQL Tactical account guard base-row locking")
