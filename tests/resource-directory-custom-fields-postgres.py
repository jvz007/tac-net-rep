#!/usr/bin/env python3
"""PostgreSQL acceptance regression for tracker row F7.

Run on a Tactical server with normal Django/PostgreSQL available. The test uses
Tactical's real Client/Site/CustomField value models and Tec-Tac's production
Resource Directory API. All changes are rolled back at the end.

Coverage:
* round-trip all supported custom-field types for both clients and sites;
* out-of-scope writes fail as ResourceNotFound and create no value/audit row;
* hidden fields and unsupported single-select options fail validation and write
  nothing;
* persisted audit metadata contains field ids only and never submitted values.
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

from accounts.models import Role, User
from clients.models import Client, ClientCustomField, Site, SiteCustomField
from core.models import CustomField
from logs.models import AuditLog
from tec_tac import resources

if connection.vendor != "postgresql":
    raise SystemExit(f"[TEST] PostgreSQL required for F7 Resource Directory regression; got {connection.vendor!r}")


def assert_raises(exc_type, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"expected {exc_type.__name__}")


def audit_rows(resource_type: str, resource_id: int):
    return AuditLog.objects.filter(
        action="modify",
        object_type=f"resource_{resource_type}",
        debug_info__source="tec-tac",
        debug_info__module_id="core",
        debug_info__object_id=str(resource_id),
    )


def refresh_actor_role(actor: User, role: Role) -> None:
    actor.role = Role.objects.get(pk=role.pk)


with transaction.atomic():
    suffix = (Client.objects.order_by("-id").values_list("id", flat=True).first() or 0) + 1
    role = Role.objects.create(
        name=f"TecTac Custom Fields PG {suffix}",
        is_superuser=False,
        can_list_clients=True,
        can_manage_clients=True,
        can_list_sites=True,
        can_manage_sites=True,
    )
    actor = User.objects.create_user(
        username=f"tectac_custom_fields_pg_{suffix}",
        email=f"tectac-custom-fields-{suffix}@invalid.local",
        password="TecTac-Test-Only!123",
        role=role,
    )

    client = Client.objects.create(name=f"TecTac F7 Client {suffix}")
    site = Site.objects.create(client=client, name=f"TecTac F7 Site {suffix}")
    outside_client = Client.objects.create(name=f"TecTac F7 Outside {suffix}")
    outside_site = Site.objects.create(client=outside_client, name=f"TecTac F7 Outside Site {suffix}")

    # Explicit grants are used so the test proves the production write-scope
    # boundary instead of relying on an unrestricted role.
    role.can_view_clients.add(client)
    role.can_view_sites.add(site)
    refresh_actor_role(actor, role)

    definitions = {}
    for model in ("client", "site"):
        definitions[model] = {
            "text": CustomField.objects.create(model=model, type="text", name=f"F7 {model} text {suffix}"),
            "number": CustomField.objects.create(model=model, type="number", name=f"F7 {model} number {suffix}"),
            "single": CustomField.objects.create(model=model, type="single", name=f"F7 {model} single {suffix}", options=["A", "B"]),
            "multiple": CustomField.objects.create(model=model, type="multiple", name=f"F7 {model} multiple {suffix}", options=["A", "B", "C"]),
            "checkbox": CustomField.objects.create(model=model, type="checkbox", name=f"F7 {model} checkbox {suffix}"),
            "datetime": CustomField.objects.create(model=model, type="datetime", name=f"F7 {model} datetime {suffix}"),
        }

    values_by_type = {
        "text": "hello",
        "number": "42.5",
        "single": "B",
        "multiple": ["A", "C"],
        "checkbox": True,
        "datetime": "2026-09-29T18:45:00+02:00",
    }

    with patch("tec_tac.rbac.has_extension_permission", return_value=True), patch.object(
        User, "get_and_set_role_cache", lambda self: Role.objects.get(pk=self.role_id)
    ):
        ctx = resources.user_context(actor)

        # Round-trip every supported type for both resource kinds.
        for resource_type, resource_id in (("client", client.pk), ("site", site.pk)):
            submitted = [
                {"field_id": field.pk, "value": values_by_type[field_type]}
                for field_type, field in definitions[resource_type].items()
            ]
            before_audits = audit_rows(resource_type, resource_id).count()
            result = resources.update_custom_fields(resource_type, resource_id, values=submitted, context=ctx)
            returned = {row["field_id"]: row["value"] for row in result["fields"]}
            for field_type, field in definitions[resource_type].items():
                assert returned[field.pk] == values_by_type[field_type], (resource_type, field_type, returned[field.pk])

            rows = audit_rows(resource_type, resource_id)
            assert rows.count() == before_audits + 1, f"{resource_type} update did not emit exactly one audit"
            audit = rows.order_by("-id").first()
            metadata = audit.debug_info.get("metadata", {})
            expected_ids = sorted(field.pk for field in definitions[resource_type].values())
            assert metadata.get("custom_fields_updated") == expected_ids, metadata
            assert metadata.get("values_redacted") is True, metadata
            serialized = repr(audit.debug_info)
            for secret_value in ("hello", "42.5", "2026-09-29T18:45:00+02:00"):
                assert secret_value not in serialized, f"audit leaked custom-field value {secret_value!r}"

        # Verify the ORM storage columns as well as the API round trip.
        client_multiple = ClientCustomField.objects.get(client=client, field=definitions["client"]["multiple"])
        client_checkbox = ClientCustomField.objects.get(client=client, field=definitions["client"]["checkbox"])
        site_multiple = SiteCustomField.objects.get(site=site, field=definitions["site"]["multiple"])
        site_checkbox = SiteCustomField.objects.get(site=site, field=definitions["site"]["checkbox"])
        assert client_multiple.multiple_value == ["A", "C"]
        assert client_checkbox.bool_value is True
        assert site_multiple.multiple_value == ["A", "C"]
        assert site_checkbox.bool_value is True

        # Out-of-scope target must look absent and must not create values/audit.
        outside_field = CustomField.objects.create(model="client", type="text", name=f"F7 outside text {suffix}")
        before_outside_audits = audit_rows("client", outside_client.pk).count()
        denied = assert_raises(
            resources.ResourceNotFound,
            resources.update_custom_fields,
            "client",
            outside_client.pk,
            values=[{"field_id": outside_field.pk, "value": "must-not-write"}],
            context=ctx,
        )
        assert "scope" in str(denied).lower(), str(denied)
        assert not ClientCustomField.objects.filter(client=outside_client, field=outside_field).exists()
        assert audit_rows("client", outside_client.pk).count() == before_outside_audits

        # Hidden field is unavailable; no row may be created.
        hidden = CustomField.objects.create(model="client", type="text", name=f"F7 hidden {suffix}", hide_in_ui=True)
        before_client_audits = audit_rows("client", client.pk).count()
        assert_raises(
            resources.ResourceValidationError,
            resources.update_custom_fields,
            "client",
            client.pk,
            values=[{"field_id": hidden.pk, "value": "hidden-secret"}],
            context=ctx,
        )
        assert not ClientCustomField.objects.filter(client=client, field=hidden).exists()
        assert audit_rows("client", client.pk).count() == before_client_audits

        # Bad single-select option is rejected atomically and not audited.
        single = definitions["client"]["single"]
        existing = ClientCustomField.objects.get(client=client, field=single)
        previous = existing.string_value
        assert_raises(
            resources.ResourceValidationError,
            resources.update_custom_fields,
            "client",
            client.pk,
            values=[{"field_id": single.pk, "value": "NOT-AN-OPTION"}],
            context=ctx,
        )
        existing.refresh_from_db()
        assert existing.string_value == previous
        assert audit_rows("client", client.pk).count() == before_client_audits

    transaction.set_rollback(True)

print("[TEST] PASS PostgreSQL Resource Directory F7 custom-field scope + validation + audit")
