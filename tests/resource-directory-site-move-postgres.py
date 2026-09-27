#!/usr/bin/env python3
"""PostgreSQL regression for Resource Directory site moves.

Run on a Tactical server with the normal Django settings/database available.
This intentionally exercises the real Tactical ORM through the Core HTTP view
so PostgreSQL sees the actual SELECT ... FOR UPDATE queries.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

import django
django.setup()

from django.db import connection, transaction
from rest_framework.test import APIRequestFactory, force_authenticate

from accounts.models import User
from clients.models import Client, Site
from tec_tac.resource_views import ResourceMutableDetailView

if connection.vendor != "postgresql":
    raise SystemExit(
        f"[TEST] PostgreSQL required for this integration regression; got {connection.vendor!r}"
    )


class SiteMoveView(ResourceMutableDetailView):
    """Use the production handler while bypassing unrelated session-policy setup."""

    permission_classes = []
    resource_type = "site"


factory = APIRequestFactory()
view = SiteMoveView.as_view()


def patch_site(actor: User, site_id: int, client_id: int):
    request = factory.patch(
        f"/api/tfd/resources/sites/{site_id}/",
        {"client_id": client_id},
        format="json",
    )
    force_authenticate(request, user=actor)
    response = view(request, resource_id=site_id)
    response.render()
    return response


with transaction.atomic():
    suffix = (Client.objects.order_by("-id").values_list("id", flat=True).first() or 0) + 1
    source = Client.objects.create(name=f"TecTac Move Source {suffix}")
    target = Client.objects.create(name=f"TecTac Move Target {suffix}")
    first = Site.objects.create(client=source, name=f"Move A {suffix}")
    second = Site.objects.create(client=source, name=f"Move B {suffix}")
    Site.objects.create(client=target, name=f"Target Existing {suffix}")

    username = f"tectac_site_move_pg_{suffix}"
    actor = User.objects.create_user(username=username, password="TecTac-Test-Only!123", is_superuser=True)

    # Two source sites: moving one is allowed and must return the new client id.
    allowed = patch_site(actor, first.pk, target.pk)
    assert allowed.status_code == 200, (allowed.status_code, allowed.data)
    assert allowed.data["client_id"] == target.pk, allowed.data
    first.refresh_from_db()
    assert first.client_id == target.pk

    # One source site remains: moving it would orphan the source client and is denied.
    denied = patch_site(actor, second.pk, target.pk)
    assert denied.status_code == 400, (denied.status_code, denied.data)
    second.refresh_from_db()
    assert second.client_id == source.pk

    transaction.set_rollback(True)

print("[TEST] PASS PostgreSQL Resource Directory site-move locking")
