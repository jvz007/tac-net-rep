"""Tactical resource-model adapter for the Core Resource Directory.

This module is the intentional compatibility boundary between Tec-Tac's stable
resource contract and Tactical's current ORM implementation.  Feature modules
must never import Tactical Client/Site/Agent models directly.
"""
from __future__ import annotations

from typing import Any

from django.db import IntegrityError, transaction
from django.db.models import Q


class TacticalResourceAdapterError(RuntimeError):
    pass


class TacticalResourceConflictError(TacticalResourceAdapterError):
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




def _role_for_user(user):
    try:
        getter = getattr(user, "get_and_set_role_cache", None)
        if callable(getter):
            return getter()
    except Exception:
        pass
    return getattr(user, "role", None)


def _relation_has_any(relation) -> bool:
    if relation is None:
        return False
    exists = getattr(relation, "exists", None)
    if callable(exists):
        return bool(exists())
    all_rows = getattr(relation, "all", None)
    if callable(all_rows):
        return bool(all_rows())
    return bool(relation)


def _role_scope_unrestricted(*, user, role=None) -> bool:
    """Return Tactical's native unrestricted client/site scope state.

    Tactical treats a role with *both* client and site relations empty as full
    resource scope. A site-only role is therefore restricted even though its
    explicit client relation is empty. Keep that rule centralized here so
    Scheduler target checks and Resource Directory writes cannot diverge.
    """
    role = role if role is not None else _role_for_user(user)
    if bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False):
        return True
    if role is None:
        return False
    return not _relation_has_any(getattr(role, "can_view_clients", None)) and not _relation_has_any(
        getattr(role, "can_view_sites", None)
    )


def explicit_client_target_ids_in_scope(*, user, client_ids) -> set[int]:
    """Return client ids authorized for whole-client targeting.

    A Tactical role with no client *or* site restrictions has full scope. Once
    either relation is populated, whole-client actions require an explicit
    ``can_view_clients`` grant; site visibility alone never expands to
    whole-client authority.
    """
    requested = {int(value) for value in client_ids if int(value) > 0}
    if not requested:
        return set()
    role = _role_for_user(user)
    Client, _, _ = _models()
    if _role_scope_unrestricted(user=user, role=role):
        return set(Client.objects.filter(pk__in=requested).values_list("pk", flat=True))
    relation = getattr(role, "can_view_clients", None) if role is not None else None
    if relation is None or not hasattr(relation, "filter"):
        return set()
    return set(relation.filter(pk__in=requested).values_list("pk", flat=True))


def site_target_ids_in_scope(*, user, site_ids) -> set[int]:
    """Return site ids visible through Tactical's native role scope."""
    requested = {int(value) for value in site_ids if int(value) > 0}
    if not requested:
        return set()
    _, Site, _ = _models()
    return set(
        _scope_queryset(Site.objects.all(), user=user, trusted=False)
        .filter(pk__in=requested)
        .values_list("pk", flat=True)
    )


def agent_target_identifiers_in_scope(*, user, identifiers) -> set[str]:
    """Return both pk and agent_id identifiers for endpoints in user scope."""
    requested_text = {str(value) for value in identifiers}
    if not requested_text:
        return set()
    numeric = {int(value) for value in requested_text if value.isdigit() and int(value) > 0}
    _, _, Agent = _models()
    qs = _scope_queryset(Agent.objects.all(), user=user, trusted=False).filter(
        Q(agent_id__in=requested_text) | Q(pk__in=numeric)
    )
    allowed: set[str] = set()
    for pk, agent_id in qs.values_list("pk", "agent_id"):
        allowed.add(str(pk))
        allowed.add(str(agent_id))
    return allowed


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



def client_write_in_scope(*, user, client_id: int) -> bool:
    """Apply the same Tactical client/site scope rule used by reads and Scheduler.

    Parent-client read visibility derived from a site grant is not client write
    authority. Only a fully-unrestricted role or an explicit client grant may
    mutate a client row.
    """
    Client, _, _ = _models()
    role = _role_for_user(user)
    if role is None and not bool(getattr(user, "is_superuser", False)):
        return False
    if not Client.objects.filter(pk=client_id).exists():
        return False
    if _role_scope_unrestricted(user=user, role=role):
        return True
    relation = getattr(role, "can_view_clients", None) if role is not None else None
    return bool(relation is not None and relation.filter(pk=client_id).exists())


def site_write_in_scope(*, user, site_id: int) -> bool:
    """Apply Tactical's one client/site scope rule to site mutations."""
    _, Site, _ = _models()
    role = _role_for_user(user)
    if role is None and not bool(getattr(user, "is_superuser", False)):
        return False
    site = Site.objects.filter(pk=site_id).values("pk", "client_id").first()
    if site is None:
        return False
    if _role_scope_unrestricted(user=user, role=role):
        return True
    site_relation = getattr(role, "can_view_sites", None) if role is not None else None
    if site_relation is not None and site_relation.filter(pk=site_id).exists():
        return True
    client_relation = getattr(role, "can_view_clients", None) if role is not None else None
    return bool(client_relation is not None and client_relation.filter(pk=site["client_id"]).exists())


def create_client_row(*, name: str) -> dict[str, Any]:
    Client, _, _ = _models()
    try:
        with transaction.atomic():
            obj = Client(name=name)
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save()
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    return client_row({"pk": obj.pk, "name": obj.name})


def update_client_row(*, user, client_id: int, name: str) -> dict[str, Any] | None:
    Client, _, _ = _models()
    try:
        with transaction.atomic():
            if not client_write_in_scope(user=user, client_id=client_id):
                return None
            obj = Client.objects.select_for_update().filter(pk=client_id).first()
            if obj is None:
                return None
            obj.name = name
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save(update_fields=["name"])
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    return client_row({"pk": obj.pk, "name": obj.name})


def create_site_row(*, client_id: int, name: str) -> dict[str, Any]:
    _, Site, _ = _models()
    try:
        with transaction.atomic():
            obj = Site(client_id=client_id, name=name)
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save()
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.") from exc
    return site_row({"pk": obj.pk, "name": obj.name, "client_id": obj.client_id})


def update_site_row(*, user, site_id: int, name: str | None = None, client_id: int | None = None) -> dict[str, Any] | None:
    _, Site, _ = _models()
    try:
        with transaction.atomic():
            if not site_write_in_scope(user=user, site_id=site_id):
                return None
            obj = Site.objects.select_for_update().filter(pk=site_id).first()
            if obj is None:
                return None
            update_fields: list[str] = []
            if name is not None and name != obj.name:
                obj.name = name
                update_fields.append("name")
            if client_id is not None and client_id != obj.client_id:
                obj.client_id = client_id
                update_fields.append("client")
            if update_fields:
                obj.full_clean(exclude=None, validate_unique=False)
                obj.save(update_fields=update_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.") from exc
    return site_row({"pk": obj.pk, "name": obj.name, "client_id": obj.client_id})
