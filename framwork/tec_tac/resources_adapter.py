"""Tactical resource-model adapter for the Core Resource Directory.

This module is the intentional compatibility boundary between Tec-Tac's stable
resource contract and Tactical's current ORM implementation.  Feature modules
must never import Tactical Client/Site/Agent models directly.
"""
from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q


class TacticalResourceAdapterError(RuntimeError):
    pass


class TacticalResourceConflictError(TacticalResourceAdapterError):
    pass


class TacticalResourceValidationError(TacticalResourceAdapterError):
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


def tactical_scope_unrestricted(*, user) -> bool:
    """Public Resource Directory decision for Tactical client/site scope.

    Scheduler and other Core consumers must use this rather than reproducing
    Tactical role-relation semantics locally.
    """
    return _role_scope_unrestricted(user=user)


def report_scope_ids(user) -> dict[str, object]:
    """Client and site ids a person may see in report models (1.17.4, the reporting row-scope hook).

    A light helper: it does not load the agent list the way ``scheduler_scope_snapshot`` does. ``client_ids`` are the
    explicitly granted clients. ``site_ids`` are the sites Tactical's own role scope shows (granted sites plus the
    sites of granted clients). ``unrestricted`` follows ``_role_scope_unrestricted``. No role, or no user, sees none and
    carries ``denied`` true, so even rows with no client or site stay hidden.
    """
    role = _role_for_user(user)
    if _role_scope_unrestricted(user=user, role=role):
        return {"unrestricted": True, "client_ids": frozenset(), "site_ids": frozenset()}
    if role is None:
        return {"unrestricted": False, "client_ids": frozenset(), "site_ids": frozenset(), "denied": True}
    _, Site, _ = _models()
    client_relation = getattr(role, "can_view_clients", None)
    if client_relation is not None and hasattr(client_relation, "values_list"):
        client_ids = frozenset(int(v) for v in client_relation.values_list("pk", flat=True))
    else:
        client_ids = frozenset()
    site_ids = frozenset(
        int(v) for v in _scope_queryset(Site.objects.all(), user=user, trusted=False).values_list("pk", flat=True)
    )
    return {"unrestricted": False, "client_ids": client_ids, "site_ids": site_ids}


def scheduler_scope_snapshot(*, user) -> dict[str, object]:
    """Resolve Scheduler-visible Tactical scope once for a request."""
    role = _role_for_user(user)
    if _role_scope_unrestricted(user=user, role=role):
        return {
            "unrestricted": True,
            "client_ids": frozenset(),
            "site_ids": frozenset(),
            "endpoint_ids": frozenset(),
        }

    _, Site, Agent = _models()
    client_relation = getattr(role, "can_view_clients", None) if role is not None else None
    if client_relation is not None and hasattr(client_relation, "values_list"):
        client_ids = frozenset(int(v) for v in client_relation.values_list("pk", flat=True))
    else:
        client_ids = frozenset()
    site_ids = frozenset(
        int(v)
        for v in _scope_queryset(Site.objects.all(), user=user, trusted=False).values_list("pk", flat=True)
    )
    # Compatibility boundary: scheduler targets saved before Core 1.15.134 may
    # contain Tactical Agent database PKs.  Preserve an alias only when that
    # token resolves to exactly one visible Agent.  A numeric agent_id can
    # otherwise collide with another Agent's PK; treating that token as
    # authorized would make history visibility disagree with the save/edit
    # resolver, which correctly fails closed on ambiguity.
    endpoint_rows = list(
        _scope_queryset(Agent.objects.all(), user=user, trusted=False).values_list("pk", "agent_id")
    )
    token_rows = {}
    for pk, agent_id in endpoint_rows:
        row = (int(pk), str(agent_id))
        for token in {str(pk), str(agent_id)}:
            token_rows.setdefault(token, set()).add(row)
    endpoint_ids = {token for token, rows in token_rows.items() if len(rows) == 1}
    return {
        "unrestricted": False,
        "client_ids": client_ids,
        "site_ids": site_ids,
        "endpoint_ids": frozenset(endpoint_ids),
    }


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


def canonical_agent_target_ids(*, identifiers) -> list[str]:
    """Resolve endpoint PK/agent_id aliases globally to canonical agent_id values.

    This is an identity normalizer, not an authorization decision. It is used
    when repairing persisted schedules immediately before execution; Tactical
    scope is still checked separately for user-owned schedules. Ambiguous
    numeric aliases fail closed.
    """
    requested = [str(value).strip() for value in identifiers]
    if not requested:
        return []
    numeric = {int(value) for value in requested if value.isdigit() and int(value) > 0}
    _, _, Agent = _models()
    rows = list(
        Agent.objects.filter(Q(agent_id__in=set(requested)) | Q(pk__in=numeric))
        .values_list("pk", "agent_id")
    )
    resolved = []
    for token in requested:
        matches = {(int(pk), str(agent_id)) for pk, agent_id in rows if str(agent_id) == token or str(pk) == token}
        if not matches:
            continue
        if len(matches) != 1:
            raise TacticalResourceAdapterError(f"Endpoint identifier {token!r} is ambiguous; use the canonical agent_id.")
        resolved.append(next(iter(matches))[1])
    return list(dict.fromkeys(resolved))


def canonical_agent_target_ids_in_scope(*, user, identifiers) -> list[str]:
    """Resolve endpoint references to the one canonical scheduler identity: agent_id.

    Legacy database PKs are accepted only when they resolve unambiguously to one
    visible Agent. A numeric token that simultaneously names a different
    ``agent_id`` and a PK is rejected rather than guessed.
    """
    requested = [str(value).strip() for value in identifiers]
    if not requested:
        return []
    numeric = {int(value) for value in requested if value.isdigit() and int(value) > 0}
    _, _, Agent = _models()
    rows = list(
        _scope_queryset(Agent.objects.all(), user=user, trusted=False)
        .filter(Q(agent_id__in=set(requested)) | Q(pk__in=numeric))
        .values_list("pk", "agent_id")
    )
    resolved = []
    for token in requested:
        matches = {(int(pk), str(agent_id)) for pk, agent_id in rows if str(agent_id) == token or str(pk) == token}
        if not matches:
            continue
        if len(matches) != 1:
            raise TacticalResourceAdapterError(f"Endpoint identifier {token!r} is ambiguous; use the canonical agent_id.")
        resolved.append(next(iter(matches))[1])
    return list(dict.fromkeys(resolved))


def agent_target_identifiers_in_scope(*, user, identifiers) -> set[str]:
    """Return in-scope endpoint identifiers, including legacy PK aliases.

    Core 1.15.134 made ``agent_id`` the canonical persisted Scheduler identity,
    but older schedules may still contain Tactical Agent database PKs.  This
    read/authorization helper intentionally accepts the original visible alias
    while save/edit paths continue to use ``canonical_agent_target_ids_in_scope``
    and therefore write only canonical ``agent_id`` values.
    """
    requested = [str(value).strip() for value in identifiers]
    if not requested:
        return set()
    numeric = {int(value) for value in requested if value.isdigit() and int(value) > 0}
    _, _, Agent = _models()
    rows = list(
        _scope_queryset(Agent.objects.all(), user=user, trusted=False)
        .filter(Q(agent_id__in=set(requested)) | Q(pk__in=numeric))
        .values_list("pk", "agent_id")
    )
    allowed = set()
    for token in requested:
        matches = {(int(pk), str(agent_id)) for pk, agent_id in rows if str(agent_id) == token or str(pk) == token}
        if not matches:
            continue
        if len(matches) != 1:
            raise TacticalResourceAdapterError(f"Endpoint identifier {token!r} is ambiguous; use the canonical agent_id.")
        allowed.add(token)
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


def create_client_row(*, user, name: str, default_site_name: str = "Default Site") -> dict[str, Any]:
    Client, Site, _ = _models()
    try:
        with transaction.atomic():
            obj = Client(name=name)
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save()

            site = Site(client=obj, name=default_site_name)
            site.full_clean(exclude=None, validate_unique=False)
            site.save()

            role = _role_for_user(user)
            if not _role_scope_unrestricted(user=user, role=role):
                relation = getattr(role, "can_view_clients", None) if role is not None else None
                add = getattr(relation, "add", None)
                if not callable(add):
                    raise TacticalResourceValidationError(
                        "Restricted creator role does not expose a writable client-scope relation."
                    )
                add(obj)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Client or default site failed Tactical validation.") from exc
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
            update_fields = ["name"]
            if hasattr(obj, "modified_by"):
                update_fields.append("modified_by")
            if hasattr(obj, "modified_time"):
                update_fields.append("modified_time")
            obj.save(update_fields=update_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Client failed Tactical validation.") from exc
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
    except ValidationError as exc:
        raise TacticalResourceValidationError("Site failed Tactical validation.") from exc
    return site_row({"pk": obj.pk, "name": obj.name, "client_id": obj.client_id})


def update_site_row(*, user, site_id: int, name: str | None = None, client_id: int | None = None) -> dict[str, Any] | None:
    Client, Site, _ = _models()
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
                source_client_id = obj.client_id
                # Serialize site moves through the source client row, then count
                # sites without SELECT ... FOR UPDATE. PostgreSQL rejects FOR
                # UPDATE on aggregate queries such as COUNT(*).
                Client.objects.select_for_update().filter(pk=source_client_id).first()
                remaining = Site.objects.filter(client_id=source_client_id).count()
                if remaining <= 1:
                    raise TacticalResourceValidationError("A client must retain at least one site.")
                obj.client_id = client_id
                update_fields.append("client")
            if update_fields:
                obj.full_clean(exclude=None, validate_unique=False)
                if hasattr(obj, "modified_by"):
                    update_fields.append("modified_by")
                if hasattr(obj, "modified_time"):
                    update_fields.append("modified_time")
                obj.save(update_fields=update_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Site failed Tactical validation.") from exc
    return site_row({"pk": obj.pk, "name": obj.name, "client_id": obj.client_id})


def delete_site_row(*, user, site_id: int, move_to_site_id: int | None = None) -> dict[str, Any] | None:
    """Delete one Tactical site after atomically relocating its agents.

    Site deletion is intentionally limited to a destination under the same
    client so the operation cannot smuggle a cross-client agent move through a
    site-management permission. Cross-client relocation belongs to client
    deletion, where the caller also holds client-management authority.
    """
    Client, Site, Agent = _models()
    try:
        with transaction.atomic():
            if not site_write_in_scope(user=user, site_id=site_id):
                return None
            source = Site.objects.select_for_update().filter(pk=site_id).first()
            if source is None:
                return None
            Client.objects.select_for_update().filter(pk=source.client_id).first()
            site_count = Site.objects.filter(client_id=source.client_id).count()
            if site_count <= 1:
                raise TacticalResourceValidationError("A client must retain at least one site.")

            agent_count = Agent.objects.filter(site_id=source.pk).count()
            destination = None
            if agent_count:
                if move_to_site_id is None:
                    raise TacticalResourceValidationError("A destination site is required while agents remain on the site.")
                if int(move_to_site_id) == int(source.pk):
                    raise TacticalResourceValidationError("The destination site must differ from the site being deleted.")
                if not site_write_in_scope(user=user, site_id=int(move_to_site_id)):
                    raise TacticalResourceValidationError("Destination site is outside the caller's writable Tactical scope.")
                destination = Site.objects.select_for_update().filter(pk=int(move_to_site_id)).first()
                if destination is None:
                    raise TacticalResourceValidationError("Destination site was not found.")
                if int(destination.client_id) != int(source.client_id):
                    raise TacticalResourceValidationError("Deleting a site may move agents only to another site in the same client.")
                moved_agents = Agent.objects.filter(site_id=source.pk).update(site_id=destination.pk)
            else:
                moved_agents = 0
                if move_to_site_id is not None:
                    if int(move_to_site_id) == int(source.pk):
                        raise TacticalResourceValidationError("The destination site must differ from the site being deleted.")
                    destination = Site.objects.select_for_update().filter(pk=int(move_to_site_id), client_id=source.client_id).first()
                    if destination is None or not site_write_in_scope(user=user, site_id=int(move_to_site_id)):
                        raise TacticalResourceValidationError("Destination site is outside the caller's writable Tactical scope.")

            deleted = site_row({"pk": source.pk, "name": source.name, "client_id": source.client_id})
            destination_row = (
                site_row({"pk": destination.pk, "name": destination.name, "client_id": destination.client_id})
                if destination is not None else None
            )
            source.delete()
            return {"deleted": deleted, "destination": destination_row, "moved_agents": int(moved_agents)}
    except IntegrityError as exc:
        raise TacticalResourceConflictError("Tactical prevented the site from being deleted.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Site deletion failed Tactical validation.") from exc


def delete_client_row(*, user, client_id: int, move_to_site_id: int | None = None) -> dict[str, Any] | None:
    """Delete one Tactical client after atomically relocating all its agents."""
    Client, Site, Agent = _models()
    try:
        with transaction.atomic():
            if not client_write_in_scope(user=user, client_id=client_id):
                return None
            source = Client.objects.select_for_update().filter(pk=client_id).first()
            if source is None:
                return None
            # Serialize the source client sites so no concurrent site move can
            # alter the set being deleted while the agent relocation is built.
            list(Site.objects.select_for_update().filter(client_id=source.pk).values_list("pk", flat=True))
            agent_count = Agent.objects.filter(site__client_id=source.pk).count()
            destination = None
            if agent_count:
                if move_to_site_id is None:
                    raise TacticalResourceValidationError("A destination site is required while agents remain under the client.")
                destination = Site.objects.select_for_update().filter(pk=int(move_to_site_id)).first()
                if destination is None:
                    raise TacticalResourceValidationError("Destination site was not found.")
                if int(destination.client_id) == int(source.pk):
                    raise TacticalResourceValidationError("Destination site must belong to a different client.")
                if not site_write_in_scope(user=user, site_id=destination.pk):
                    raise TacticalResourceValidationError("Destination site is outside the caller's writable Tactical scope.")
                moved_agents = Agent.objects.filter(site__client_id=source.pk).update(site_id=destination.pk)
            else:
                moved_agents = 0
                if move_to_site_id is not None:
                    destination = Site.objects.select_for_update().filter(pk=int(move_to_site_id)).first()
                    if destination is None or int(destination.client_id) == int(source.pk) or not site_write_in_scope(user=user, site_id=destination.pk):
                        raise TacticalResourceValidationError("Destination site is outside the caller's writable Tactical scope.")

            deleted = client_row({"pk": source.pk, "name": source.name})
            destination_row = (
                site_row({"pk": destination.pk, "name": destination.name, "client_id": destination.client_id})
                if destination is not None else None
            )
            source.delete()
            return {"deleted": deleted, "destination": destination_row, "moved_agents": int(moved_agents)}
    except IntegrityError as exc:
        raise TacticalResourceConflictError("Tactical prevented the client from being deleted.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Client deletion failed Tactical validation.") from exc


def _custom_models():
    from core.models import CustomField  # noqa: PLC0415
    from clients.models import ClientCustomField, SiteCustomField  # noqa: PLC0415
    return CustomField, ClientCustomField, SiteCustomField


def _custom_value(record, field):
    if record is None:
        return field.default_value
    if field.type == "multiple":
        return list(record.multiple_value or [])
    if field.type == "checkbox":
        return bool(record.bool_value)
    return record.string_value


def custom_field_rows(*, user, resource_type: str, resource_id: int) -> list[dict[str, Any]] | None:
    if resource_type == "client":
        if not client_write_in_scope(user=user, client_id=resource_id):
            return None
    elif resource_type == "site":
        if not site_write_in_scope(user=user, site_id=resource_id):
            return None
    else:
        raise TacticalResourceValidationError("Unsupported custom-field resource type.")

    CustomField, ClientCustomField, SiteCustomField = _custom_models()
    fields = list(
        CustomField.objects.filter(model=resource_type, hide_in_ui=False)
        .order_by("order", "name", "pk")
    )
    field_ids = [field.pk for field in fields]
    if resource_type == "client":
        values = ClientCustomField.objects.filter(client_id=resource_id, field_id__in=field_ids).select_related("field")
    else:
        values = SiteCustomField.objects.filter(site_id=resource_id, field_id__in=field_ids).select_related("field")
    by_field = {row.field_id: row for row in values}
    return [
        {
            "field_id": int(field.pk),
            "name": str(field.name),
            "type": str(field.type),
            "options": list(field.options or []),
            "required": bool(field.required),
            "value": _custom_value(by_field.get(field.pk), field),
        }
        for field in fields
    ]


def _normalize_custom_value(field, value):
    field_type = str(field.type)
    required = bool(field.required)
    if field_type == "checkbox":
        if not isinstance(value, bool):
            raise TacticalResourceValidationError(f"Custom field {field.name!r} requires a boolean value.")
        return value
    if field_type == "multiple":
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise TacticalResourceValidationError(f"Custom field {field.name!r} requires an array of strings.")
        cleaned = [item.strip() for item in value if item.strip()]
        if required and not cleaned:
            raise TacticalResourceValidationError(f"Custom field {field.name!r} is required.")
        options = set(field.options or [])
        if options and any(item not in options for item in cleaned):
            raise TacticalResourceValidationError(f"Custom field {field.name!r} contains an unsupported option.")
        return list(dict.fromkeys(cleaned))
    if value is None:
        value = ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise TacticalResourceValidationError(f"Custom field {field.name!r} requires a scalar value.")
    cleaned = str(value).strip()
    if required and not cleaned:
        raise TacticalResourceValidationError(f"Custom field {field.name!r} is required.")
    if field_type == "number" and cleaned:
        from decimal import Decimal, InvalidOperation  # noqa: PLC0415
        try:
            Decimal(cleaned)
        except InvalidOperation as exc:
            raise TacticalResourceValidationError(f"Custom field {field.name!r} requires a numeric value.") from exc
    if field_type == "single" and cleaned and field.options and cleaned not in set(field.options):
        raise TacticalResourceValidationError(f"Custom field {field.name!r} contains an unsupported option.")
    return cleaned


def update_custom_field_rows(*, user, resource_type: str, resource_id: int, values: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    if resource_type == "client":
        if not client_write_in_scope(user=user, client_id=resource_id):
            return None
    elif resource_type == "site":
        if not site_write_in_scope(user=user, site_id=resource_id):
            return None
    else:
        raise TacticalResourceValidationError("Unsupported custom-field resource type.")
    if not isinstance(values, list):
        raise TacticalResourceValidationError("values must be an array.")

    CustomField, ClientCustomField, SiteCustomField = _custom_models()
    submitted: dict[int, Any] = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {"field_id", "value"}:
            raise TacticalResourceValidationError("Each custom-field update must contain only field_id and value.")
        try:
            field_id = int(item["field_id"])
        except (TypeError, ValueError) as exc:
            raise TacticalResourceValidationError("field_id must be a positive integer.") from exc
        if field_id < 1 or field_id in submitted:
            raise TacticalResourceValidationError("Custom-field updates must contain unique positive field_id values.")
        submitted[field_id] = item["value"]

    fields = {
        int(field.pk): field
        for field in CustomField.objects.filter(pk__in=submitted, model=resource_type, hide_in_ui=False)
    }
    if set(fields) != set(submitted):
        raise TacticalResourceValidationError("One or more custom fields are unavailable for this resource type.")

    with transaction.atomic():
        for field_id, raw_value in submitted.items():
            field = fields[field_id]
            value = _normalize_custom_value(field, raw_value)
            if resource_type == "client":
                record, _ = ClientCustomField.objects.select_for_update().get_or_create(client_id=resource_id, field_id=field_id)
            else:
                record, _ = SiteCustomField.objects.select_for_update().get_or_create(site_id=resource_id, field_id=field_id)
            if str(field.type) == "checkbox":
                record.bool_value = value
                record.save(update_fields=["bool_value"])
            elif str(field.type) == "multiple":
                record.multiple_value = value
                record.save(update_fields=["multiple_value"])
            else:
                record.string_value = value
                record.save(update_fields=["string_value"])

    return custom_field_rows(user=user, resource_type=resource_type, resource_id=resource_id)
