"""Tactical resource-model adapter for the Core Resource Directory.

This module is the intentional compatibility boundary between Tec-Tac's stable
resource contract and Tactical's current ORM implementation.  Feature modules
must never import Tactical Client/Site/Agent models directly.
"""
from __future__ import annotations

from typing import Any

from django.db.models import Q


class TacticalResourceAdapterError(RuntimeError):
    pass


def _models():
    """Load Tactical models lazily so this one adapter owns model imports."""
    from agents.models import Agent  # noqa: PLC0415
    from clients.models import Client, Site  # noqa: PLC0415

    return Client, Site, Agent


def _scope_queryset(queryset, *, user=None, trusted: bool = False):
    if trusted:
        return queryset
    if user is None:
        return queryset.none()
    filter_by_role = getattr(queryset, "filter_by_role", None)
    if not callable(filter_by_role):
        raise TacticalResourceAdapterError("Tactical resource queryset does not expose filter_by_role().")
    return filter_by_role(user)


def _active_filter(queryset, active: bool | None):
    # Tactical currently hard-deletes these resource rows and exposes no
    # soft-disabled field. Existing rows are therefore active in contract v1.
    return queryset.none() if active is False else queryset


def clients_queryset(*, user=None, trusted: bool = False, search: str | None = None, active: bool | None = None):
    Client, _, _ = _models()
    qs = _scope_queryset(Client.objects.all(), user=user, trusted=trusted)
    qs = _active_filter(qs, active)
    if search:
        qs = qs.filter(name__icontains=search)
    return qs.order_by("name", "pk")


def sites_queryset(*, user=None, trusted: bool = False, client_id: int | None = None, search: str | None = None, active: bool | None = None):
    _, Site, _ = _models()
    qs = _scope_queryset(Site.objects.all(), user=user, trusted=trusted)
    qs = _active_filter(qs, active)
    if client_id is not None:
        qs = qs.filter(client_id=client_id)
    if search:
        qs = qs.filter(name__icontains=search)
    return qs.order_by("client_id", "name", "pk")


def agents_queryset(*, user=None, trusted: bool = False, client_id: int | None = None, site_id: int | None = None, search: str | None = None, active: bool | None = None):
    _, _, Agent = _models()
    qs = _scope_queryset(Agent.objects.all(), user=user, trusted=trusted)
    qs = _active_filter(qs, active)
    if client_id is not None:
        qs = qs.filter(site__client_id=client_id)
    if site_id is not None:
        qs = qs.filter(site_id=site_id)
    if search:
        qs = qs.filter(
            Q(hostname__icontains=search)
            | Q(agent_id__icontains=search)
            | Q(operating_system__icontains=search)
        )
    return qs.order_by("site__client_id", "site_id", "hostname", "agent_id")


def client_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "client",
        "id": int(row["pk"]),
        "name": str(row.get("name") or ""),
        "active": True,
    }


def site_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "site",
        "id": int(row["pk"]),
        "name": str(row.get("name") or ""),
        "client_id": int(row["client_id"]),
        "active": True,
    }


def agent_row(row: dict[str, Any]) -> dict[str, Any]:
    last_seen = row.get("last_seen")
    return {
        "type": "agent",
        "id": str(row.get("agent_id") or ""),
        "hostname": str(row.get("hostname") or ""),
        "client_id": int(row["site__client_id"]),
        "site_id": int(row["site_id"]),
        "active": True,
        "platform": str(row.get("plat") or ""),
        "monitoring_type": str(row.get("monitoring_type") or ""),
        "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else (str(last_seen) if last_seen else None),
    }


def page_clients(queryset, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = queryset.count()
    rows = queryset.values("pk", "name")[offset : offset + limit]
    return [client_row(row) for row in rows], total


def page_sites(queryset, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = queryset.count()
    rows = queryset.values("pk", "name", "client_id")[offset : offset + limit]
    return [site_row(row) for row in rows], total


def page_agents(queryset, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = queryset.count()
    rows = queryset.values(
        "agent_id", "hostname", "site_id", "site__client_id", "plat",
        "monitoring_type", "last_seen",
    )[offset : offset + limit]
    return [agent_row(row) for row in rows], total


def get_client_row(queryset, client_id: int) -> dict[str, Any] | None:
    row = queryset.filter(pk=client_id).values("pk", "name").first()
    return client_row(row) if row else None


def get_site_row(queryset, site_id: int) -> dict[str, Any] | None:
    row = queryset.filter(pk=site_id).values("pk", "name", "client_id").first()
    return site_row(row) if row else None


def get_agent_row(queryset, agent_id: str) -> dict[str, Any] | None:
    row = queryset.filter(agent_id=agent_id).values(
        "agent_id", "hostname", "site_id", "site__client_id", "plat",
        "monitoring_type", "last_seen",
    ).first()
    return agent_row(row) if row else None
