#!/usr/bin/env python3
"""PostgreSQL acceptance regression for tracker rows F5 and F6.

Run on a Tactical server with the normal Django settings/database available.
The test exercises Tec-Tac's production Resource Directory deletion functions
against Tactical's real Client/Site/Agent/User/Role models and native AuditLog.
All database changes, including audit rows, are rolled back when the test ends.

F5 done-when coverage:
* a restricted role may delete a visible source site only when the destination
  site is also writable and belongs to the same client;
* a refused destination leaves the source site and every agent unchanged and
  does not emit a Resource Directory delete audit event;
* after the destination grant, every agent is moved, the source site is gone,
  and exactly one delete audit event is persisted.

F6 done-when coverage:
* a client delete refuses a destination site inside the source client;
* it refuses an external destination outside the caller's writable scope;
* both refusal paths leave the client/sites/agents unchanged and emit no delete
  audit event;
* after granting the external destination, agents distributed across multiple
  source sites are all moved, the source client disappears, and exactly one
  delete audit event is persisted.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")

import django

django.setup()

from django.db import connection, transaction

from accounts.models import Role, User
from agents.models import Agent
from clients.models import Client, Site
from logs.models import AuditLog
from tec_tac import resources


if connection.vendor != "postgresql":
    raise SystemExit(
        f"[TEST] PostgreSQL required for F5/F6 Resource Directory regression; got {connection.vendor!r}"
    )


def assert_raises(exc_type, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"expected {exc_type.__name__}")


def make_agent(site: Site, label: str) -> Agent:
    token = uuid.uuid4().hex
    return Agent.objects.create(
        site=site,
        hostname=f"tectac-{label}-{token[:8]}",
        agent_id=f"tectac-{label}-{token}",
    )


def resource_delete_audits(*, object_type: str, object_id: int):
    return AuditLog.objects.filter(
        action="delete",
        object_type=object_type,
        debug_info__source="tec-tac",
        debug_info__module_id="core",
        debug_info__object_id=str(object_id),
    )


def refresh_actor_role(actor: User, role: Role) -> Role:
    # Tactical normally caches Role instances for ten minutes. The test changes
    # M2M scope grants inside one transaction, so always return a fresh Role to
    # make each assertion observe the real current database scope.
    fresh = Role.objects.get(pk=role.pk)
    actor.role = fresh
    return fresh


with transaction.atomic():
    suffix = (Client.objects.order_by("-id").values_list("id", flat=True).first() or 0) + 1
    role = Role.objects.create(
        name=f"TecTac Resource Delete PG {suffix}",
        is_superuser=False,
        can_list_clients=True,
        can_manage_clients=True,
        can_list_sites=True,
        can_manage_sites=True,
        can_list_agents=True,
    )
    actor = User.objects.create_user(
        username=f"tectac_resource_delete_pg_{suffix}",
        email=f"tectac-resource-delete-{suffix}@invalid.local",
        password="TecTac-Test-Only!123",
        role=role,
    )

    # Resource Directory's own extension permissions are orthogonal to this
    # regression. Keep them allowed while exercising the real Tactical scope,
    # ORM, transaction and audit boundaries.
    with patch("tec_tac.rbac.has_extension_permission", return_value=True), patch.object(
        User, "get_and_set_role_cache", lambda self: Role.objects.get(pk=self.role_id)
    ):
        # ------------------------------------------------------------------
        # F5: delete one site and move all of its agents to another site in
        # the same client. Destination scope must be independently writable.
        # ------------------------------------------------------------------
        f5_client = Client.objects.create(name=f"TecTac F5 Client {suffix}")
        f5_source = Site.objects.create(client=f5_client, name=f"F5 Source {suffix}")
        f5_destination = Site.objects.create(client=f5_client, name=f"F5 Destination {suffix}")
        f5_a1 = make_agent(f5_source, "f5-a")
        f5_a2 = make_agent(f5_source, "f5-b")

        role.can_view_sites.add(f5_source)
        refresh_actor_role(actor, role)
        f5_ctx = resources.user_context(actor)

        before_f5_audits = resource_delete_audits(
            object_type="resource_site", object_id=f5_source.pk
        ).count()

        denied = assert_raises(
            resources.ResourceValidationError,
            resources.delete_site,
            f5_source.pk,
            move_to_site_id=f5_destination.pk,
            context=f5_ctx,
        )
        assert "outside" in str(denied).lower(), str(denied)
        assert Site.objects.filter(pk=f5_source.pk).exists(), "F5 denied delete removed source site"
        assert Agent.objects.filter(pk__in=[f5_a1.pk, f5_a2.pk], site_id=f5_source.pk).count() == 2, (
            "F5 denied delete moved agents"
        )
        assert resource_delete_audits(
            object_type="resource_site", object_id=f5_source.pk
        ).count() == before_f5_audits, "F5 denied delete wrote an audit row"

        role.can_view_sites.add(f5_destination)
        refresh_actor_role(actor, role)
        result = resources.delete_site(
            f5_source.pk,
            move_to_site_id=f5_destination.pk,
            context=resources.user_context(actor),
        )
        assert result["moved_agents"] == 2, result
        assert not Site.objects.filter(pk=f5_source.pk).exists(), "F5 source site survived successful delete"
        assert Agent.objects.filter(pk__in=[f5_a1.pk, f5_a2.pk], site_id=f5_destination.pk).count() == 2, (
            "F5 did not move every source agent"
        )
        f5_audits = resource_delete_audits(
            object_type="resource_site", object_id=f5_source.pk
        )
        assert f5_audits.count() == before_f5_audits + 1, "F5 success did not emit exactly one delete audit"
        f5_row = f5_audits.order_by("-id").first()
        assert f5_row.debug_info.get("metadata", {}).get("moved_agents") == 2, f5_row.debug_info
        assert int(f5_row.debug_info["metadata"]["destination_site"]["id"]) == f5_destination.pk, f5_row.debug_info

        # ------------------------------------------------------------------
        # F6: delete a client, moving agents from two different source sites
        # to one writable site under another client.
        # ------------------------------------------------------------------
        f6_source_client = Client.objects.create(name=f"TecTac F6 Source Client {suffix}")
        f6_s1 = Site.objects.create(client=f6_source_client, name=f"F6 Source A {suffix}")
        f6_s2 = Site.objects.create(client=f6_source_client, name=f"F6 Source B {suffix}")
        f6_a1 = make_agent(f6_s1, "f6-a")
        f6_a2 = make_agent(f6_s2, "f6-b")
        f6_a3 = make_agent(f6_s2, "f6-c")

        f6_target_client = Client.objects.create(name=f"TecTac F6 Target Client {suffix}")
        f6_target = Site.objects.create(client=f6_target_client, name=f"F6 Target {suffix}")

        # Explicit client authority permits mutation of the source client and
        # makes its own sites writable, but must not authorize the external
        # destination client/site.
        role.can_view_clients.add(f6_source_client)
        refresh_actor_role(actor, role)
        f6_ctx = resources.user_context(actor)

        before_f6_audits = resource_delete_audits(
            object_type="resource_client", object_id=f6_source_client.pk
        ).count()

        inside = assert_raises(
            resources.ResourceValidationError,
            resources.delete_client,
            f6_source_client.pk,
            move_to_site_id=f6_s1.pk,
            context=f6_ctx,
        )
        assert "different client" in str(inside).lower(), str(inside)
        assert Client.objects.filter(pk=f6_source_client.pk).exists(), "F6 inside-client denial removed source client"
        assert Agent.objects.filter(pk=f6_a1.pk, site_id=f6_s1.pk).exists()
        assert Agent.objects.filter(pk__in=[f6_a2.pk, f6_a3.pk], site_id=f6_s2.pk).count() == 2
        assert resource_delete_audits(
            object_type="resource_client", object_id=f6_source_client.pk
        ).count() == before_f6_audits, "F6 inside-client denial wrote an audit row"

        outside = assert_raises(
            resources.ResourceValidationError,
            resources.delete_client,
            f6_source_client.pk,
            move_to_site_id=f6_target.pk,
            context=f6_ctx,
        )
        assert "outside" in str(outside).lower(), str(outside)
        assert Client.objects.filter(pk=f6_source_client.pk).exists(), "F6 out-of-scope denial removed source client"
        assert Agent.objects.filter(pk=f6_a1.pk, site_id=f6_s1.pk).exists()
        assert Agent.objects.filter(pk__in=[f6_a2.pk, f6_a3.pk], site_id=f6_s2.pk).count() == 2
        assert resource_delete_audits(
            object_type="resource_client", object_id=f6_source_client.pk
        ).count() == before_f6_audits, "F6 out-of-scope denial wrote an audit row"

        role.can_view_sites.add(f6_target)
        refresh_actor_role(actor, role)
        result = resources.delete_client(
            f6_source_client.pk,
            move_to_site_id=f6_target.pk,
            context=resources.user_context(actor),
        )
        assert result["moved_agents"] == 3, result
        assert not Client.objects.filter(pk=f6_source_client.pk).exists(), "F6 source client survived successful delete"
        assert not Site.objects.filter(pk__in=[f6_s1.pk, f6_s2.pk]).exists(), "F6 source sites survived client delete"
        assert Agent.objects.filter(
            pk__in=[f6_a1.pk, f6_a2.pk, f6_a3.pk], site_id=f6_target.pk
        ).count() == 3, "F6 did not move all agents from all source sites"
        f6_audits = resource_delete_audits(
            object_type="resource_client", object_id=f6_source_client.pk
        )
        assert f6_audits.count() == before_f6_audits + 1, "F6 success did not emit exactly one delete audit"
        f6_row = f6_audits.order_by("-id").first()
        assert f6_row.debug_info.get("metadata", {}).get("moved_agents") == 3, f6_row.debug_info
        assert int(f6_row.debug_info["metadata"]["destination_site"]["id"]) == f6_target.pk, f6_row.debug_info

    transaction.set_rollback(True)

print("[TEST] PASS PostgreSQL Resource Directory F5/F6 delete + relocate + audit")
