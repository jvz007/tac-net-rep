"""Tactical resource-model adapter for the Core Resource Directory.

This module is the intentional compatibility boundary between Tec-Tac's stable
resource contract and Tactical's current ORM implementation.  Feature modules
must never import Tactical Client/Site/Agent models directly.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q


class TacticalResourceAdapterError(RuntimeError):
    pass


class TacticalResourceConflictError(TacticalResourceAdapterError):
    """A write that Tactical or the compare-and-set guard refused as a conflict. ``code`` is None for the older name conflicts and
    ``record_changed`` when an expected_* guard no longer matches the locked row (core.resources 1.11.0)."""

    def __init__(self, message: str = "", code: str | None = None):
        super().__init__(message)
        self.code = code


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


def _scope_none() -> dict[str, object]:
    return {"mode": "none", "unrestricted": False, "whole_client_ids": [], "site_ids": [], "whole_client_count": 0, "site_count": 0}


def _relation_pks(relation) -> list[int]:
    """The ids a role relation lists, sorted, without loading anything else. None reads as no rows."""
    if relation is None:
        return []
    values_list = getattr(relation, "values_list", None)
    if callable(values_list):
        return sorted({int(value) for value in values_list("pk", flat=True)})
    rows = getattr(relation, "all", None)
    rows = rows() if callable(rows) else relation
    return sorted({int(getattr(row, "pk", row)) for row in rows})


def role_scope_descriptor(user) -> dict[str, object]:
    """One description of a person's Tactical client and site scope (1.17.17, ``core.resources`` 1.4.0).

    ``{mode, unrestricted, whole_client_ids, site_ids, whole_client_count, site_count}``. It uses the rule of
    ``_role_scope_unrestricted`` and the role's ``can_view_clients`` and ``can_view_sites`` relations, so no module needs to
    read Tactical's Role. ``unrestricted`` is a superuser, a role superuser, or a role with both relations empty (Tactical's own
    rule). ``mode`` is ``unrestricted``, ``clients`` (only whole-client grants), ``sites`` (only explicit site grants), ``mixed``
    (both) or ``none``. ``whole_client_ids`` are the explicit ``can_view_clients`` grants. ``site_ids`` are the explicit
    ``can_view_sites`` grants only, never the sites of a granted client, and a site-only role never counts as holding the whole
    client. No user, no role, a Tactical installer user and any lookup failure give mode ``none`` and ``unrestricted`` False
    (fail closed). Returns new lists on every call.
    """
    try:
        if user is None or not bool(getattr(user, "is_authenticated", False)) or bool(getattr(user, "is_installer_user", False)):
            return _scope_none()
        role = _role_for_user(user)
        if bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False):
            return {**_scope_none(), "mode": "unrestricted", "unrestricted": True}
        if role is None:
            return _scope_none()
        clients = _relation_pks(getattr(role, "can_view_clients", None))
        sites = _relation_pks(getattr(role, "can_view_sites", None))
        if not clients and not sites:
            return {**_scope_none(), "mode": "unrestricted", "unrestricted": True}
        mode = "mixed" if clients and sites else ("clients" if clients else "sites")
        return {
            "mode": mode, "unrestricted": False, "whole_client_ids": clients, "site_ids": sites,
            "whole_client_count": len(clients), "site_count": len(sites),
        }
    except Exception:
        return _scope_none()


def existing_client_ids(client_ids) -> set[int]:
    """The ids among ``client_ids`` that name a Tactical client (no scope decision)."""
    wanted = {int(value) for value in client_ids if int(value) > 0}
    if not wanted:
        return set()
    Client, _, _ = _models()
    return set(Client.objects.filter(pk__in=wanted).values_list("pk", flat=True))


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


def objects_in_role_scope(*, user, resource_type: str, identifiers) -> bool:
    """True when every identifier names an existing object inside the user's Tactical role client/site limits.

    Scope only (1.17.7, tec_tac.tactical_operations). It deliberately does not ask for ``can_list_*``: Tactical's own
    permission class for the operation decides the permission, and Core re-checks that flag separately. A missing
    object, an object outside the limits, a malformed identifier and an ambiguous identifier all read as False, so the
    caller cannot tell them apart. Agents are matched by canonical ``agent_id`` only, never by database PK alias.
    """
    tokens = [str(value).strip() for value in identifiers]
    if not tokens:
        return False
    try:
        if resource_type == "agent":
            allowed = set(canonical_agent_target_ids_in_scope(user=user, identifiers=tokens))
            return all(token in allowed for token in tokens)
        if not all(token.isdigit() and 0 < int(token) < 2**63 for token in tokens):
            return False
        wanted = {int(token) for token in tokens}
        if resource_type == "client":
            return wanted <= set(explicit_client_target_ids_in_scope(user=user, client_ids=wanted))
        if resource_type == "site":
            return wanted <= set(site_target_ids_in_scope(user=user, site_ids=wanted))
    except Exception:
        return False
    return False


def agent_pks_in_role_scope(*, user, pks) -> bool:
    """True when every Tactical agent number (database pk) names an existing agent inside the user's role scope (1.17.18).

    Scope only, like ``objects_in_role_scope``, which deliberately matches canonical ``agent_id`` and refuses pk aliases: this is
    the separate helper for operations whose body names agents by their number (automation's ``excluded_agents``). A missing
    agent, an agent outside the limits and a malformed number all read as False, so the caller cannot tell them apart."""
    try:
        tokens = [str(value).strip() for value in pks]
        if not tokens or not all(token.isdigit() and 0 < int(token) < 2**63 for token in tokens):
            return False
        wanted = {int(token) for token in tokens}
        _, _, Agent = _models()
        found = set(_scope_queryset(Agent.objects.all(), user=user, trusted=False).filter(pk__in=wanted).values_list("pk", flat=True))
        return wanted <= {int(value) for value in found}
    except Exception:
        return False


def agent_pks_for_scheduler_targets(*, targets, module_id=None):
    """The Tactical agent numbers a Scheduler target snapshot names, as ``(pks, missing)``, or None when Core cannot resolve it (1.17.62).

    Used only to bound a system action: the run may touch these endpoints and no others. It is not an authorization decision (the
    owner's role scope is checked separately). A client, site or endpoint target resolves to the endpoints it names; a dynamic target
    resolves to its Tactical scope, an upper bound (the module's filter only narrows it); ``none`` resolves to no endpoint. A
    module-owned target type returns None unless ``module_id`` is given and that module registered a resolver for the type (1.17.68,
    ``scheduler_target_resolvers``): then it resolves to the endpoints the resolver names, or None when the resolver cannot answer cleanly. ``missing`` counts the named clients, sites or endpoints
    that no longer exist. An ambiguous endpoint identifier raises ``TacticalResourceAdapterError``, so the caller fails closed."""
    from .scheduler_targets import tactical_scope_ref

    ref = tactical_scope_ref(targets)
    kind, values = ref["kind"], ref["values"]
    if kind == "module":
        if not module_id:
            return None
        from . import scheduler_target_resolvers

        pks = scheduler_target_resolvers.resolve_agent_pks(module_id, targets)
        return None if pks is None else (pks, 0)
    if kind == "none":
        return set(), 0
    Client, Site, Agent = _models()
    if kind == "client":
        found = set(Client.objects.filter(pk__in=values).values_list("pk", flat=True))
        return {int(pk) for pk in Agent.objects.filter(site__client_id__in=found).values_list("pk", flat=True)}, len(set(values)) - len(found)
    if kind == "site":
        found = set(Site.objects.filter(pk__in=values).values_list("pk", flat=True))
        return {int(pk) for pk in Agent.objects.filter(site_id__in=found).values_list("pk", flat=True)}, len(set(values)) - len(found)
    requested = [str(value).strip() for value in values]
    numeric = {int(value) for value in requested if value.isdigit() and int(value) > 0}
    rows = list(Agent.objects.filter(Q(agent_id__in=set(requested)) | Q(pk__in=numeric)).values_list("pk", "agent_id"))
    pks, missing = set(), 0
    for token in dict.fromkeys(requested):
        matches = {(int(pk), str(agent_id)) for pk, agent_id in rows if str(agent_id) == token or str(pk) == token}
        if not matches:
            missing += 1
            continue
        if len(matches) != 1:
            raise TacticalResourceAdapterError(f"Endpoint identifier {token!r} is ambiguous; use the canonical agent_id.")
        pks.add(next(iter(matches))[0])
    return pks, missing


def _chunks(values, size: int = 5000):
    values = list(values)
    for start in range(0, len(values), size):
        yield values[start:start + size]


def agent_pks_for_identifiers(*, identifiers) -> set[int]:
    """Canonical Tactical agent numbers for a list of endpoint references (1.17.68, the target-resolver contract).

    A whole number is a database number. Text is an agent id, and a numeric text may also be a database number. Every reference must name exactly
    one endpoint: a reference that names none, or a number that is one endpoint's number and another endpoint's agent id, raises
    ``TacticalResourceAdapterError``, so the caller treats the whole answer as unresolved. This is an identity step, not an authorization decision."""
    numbers = {int(value) for value in identifiers if isinstance(value, int) and not isinstance(value, bool)}
    texts = {value.strip() for value in identifiers if isinstance(value, str)}
    _, _, Agent = _models()
    found: dict[int, str] = {}
    for part in _chunks(sorted(numbers)):
        found.update({int(pk): str(agent_id) for pk, agent_id in Agent.objects.filter(pk__in=part).values_list("pk", "agent_id")})
    for part in _chunks(sorted(texts)):
        wanted = {int(value) for value in part if value.isdigit() and int(value) > 0}
        query = Q(agent_id__in=set(part)) | Q(pk__in=wanted)
        rows = [(int(pk), str(agent_id)) for pk, agent_id in Agent.objects.filter(query).values_list("pk", "agent_id")]
        for token in part:
            matches = {(pk, agent_id) for pk, agent_id in rows if agent_id == token or str(pk) == token}
            if len(matches) != 1:
                raise TacticalResourceAdapterError("An endpoint reference names no endpoint or more than one.")
            found[next(iter(matches))[0]] = next(iter(matches))[1]
    if not numbers <= set(found):
        raise TacticalResourceAdapterError("An endpoint number names no endpoint.")
    return set(found)


def agent_rows_in_scope(*, pks, snapshot=None, user=None, limit: int) -> list[dict[str, Any]]:
    """The endpoints among ``pks`` (every endpoint when ``pks`` is None) that lie inside a scope, as plain rows, at most ``limit + 1`` of them (1.17.68).

    The scope is ``snapshot``, a creation-time snapshot (``scheduler_creation_scope``): unrestricted, or the endpoint's client is in
    ``whole_client_ids``, or its site is in ``site_ids``, which is Tactical's own rule for agents. An empty snapshot reaches nothing. Or the scope is
    ``user``'s live Tactical role scope. Exactly one of the two must be given. The caller compares the row count with its limit: more than ``limit``
    rows is a refusal there, so nothing is ever truncated silently. Rows: ``{pk, agent_id, hostname, platform, client_id, site_id}`` by number."""
    if (snapshot is None) == (user is None):
        raise TacticalResourceAdapterError("Give either a stored scope or a person.")
    _, _, Agent = _models()
    base = Agent.objects.all()
    if snapshot is not None:
        scope = snapshot["scope"]
        if not scope["unrestricted"]:
            base = base.filter(Q(site__client_id__in=list(scope["whole_client_ids"])) | Q(site_id__in=list(scope["site_ids"])))
    else:
        base = _scope_queryset(base, user=user, trusted=False)
    fields = ("pk", "agent_id", "hostname", "plat", "site__client_id", "site_id")
    rows: list[dict[str, Any]] = []
    sources = [base] if pks is None else [base.filter(pk__in=part) for part in _chunks(sorted(pks))]
    for source in sources:
        for pk, agent_id, hostname, plat, client_id, site_id in source.order_by("pk").values_list(*fields)[: limit + 1 - len(rows)]:
            rows.append({"pk": int(pk), "agent_id": str(agent_id), "hostname": str(hostname or ""), "platform": str(plat or ""),
                         "client_id": int(client_id), "site_id": int(site_id)})
        if len(rows) > limit:
            break
    rows.sort(key=lambda row: row["pk"])
    return rows


def _active_filter(queryset, active: bool | None):
    # Tactical currently hard-deletes these resource rows and exposes no
    # soft-disabled field. Existing rows are therefore active in contract v1.
    return queryset.none() if active is False else queryset


def _policy_filters(qs, *, alert_template_id: int | None, policy_id: int | None):
    """1.7.0: ``alert_template_id`` matches the record's alert template, ``policy_id`` its workstation or its server policy."""
    if alert_template_id is not None:
        qs = qs.filter(alert_template_id=alert_template_id)
    if policy_id is not None:
        qs = qs.filter(Q(workstation_policy_id=policy_id) | Q(server_policy_id=policy_id))
    return qs


def clients_queryset(*, user=None, trusted: bool = False, search: str | None = None, active: bool | None = None,
                     alert_template_id: int | None = None, policy_id: int | None = None):
    Client, _, _ = _models()
    qs = _scope_queryset(Client.objects.all(), user=user, trusted=trusted)
    qs = _active_filter(qs, active)
    qs = _policy_filters(qs, alert_template_id=alert_template_id, policy_id=policy_id)
    if search:
        qs = qs.filter(name__icontains=search)
    return qs.order_by("name", "pk")


def sites_queryset(*, user=None, trusted: bool = False, client_id: int | None = None, search: str | None = None, active: bool | None = None,
                   alert_template_id: int | None = None, policy_id: int | None = None):
    _, Site, _ = _models()
    qs = _scope_queryset(Site.objects.all(), user=user, trusted=trusted)
    qs = _active_filter(qs, active)
    qs = _policy_filters(qs, alert_template_id=alert_template_id, policy_id=policy_id)
    if client_id is not None:
        qs = qs.filter(client_id=client_id)
    if search:
        qs = qs.filter(name__icontains=search)
    return qs.order_by("client_id", "name", "pk")


# 1.17.58 (core.resources 1.12.0): the columns of the agent list sort and the order every sort ends with, so paging is stable.
AGENT_SORT_COLUMNS = {"hostname": "hostname", "client": "site__client__name", "site": "site__name", "platform": "plat", "last_seen": "last_seen"}
AGENT_TIE_BREAK = ("site__client_id", "site_id", "hostname", "agent_id")


def _agent_order(sort_by: str | None, sort_dir: str | None) -> tuple:
    """The order_by arguments: the order before 1.17.58 without a sort_by, else the chosen column first and the same order after it.
    last_seen puts NULL (never reported) last in both directions. The joins exist only for the client and site columns."""
    if sort_by is None:
        return AGENT_TIE_BREAK
    column = AGENT_SORT_COLUMNS[sort_by]
    descending = sort_dir == "desc"
    if sort_by == "last_seen":
        from django.db.models import F  # noqa: PLC0415 - only this sort needs it

        first = F(column).desc(nulls_last=True) if descending else F(column).asc(nulls_last=True)
    else:
        first = f"-{column}" if descending else column
    return (first, *AGENT_TIE_BREAK)


def agents_queryset(*, user=None, trusted: bool = False, client_id: int | None = None, site_id: int | None = None, search: str | None = None, active: bool | None = None, sort_by: str | None = None, sort_dir: str | None = None):
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
    return qs.order_by(*_agent_order(sort_by, sort_dir))


def _template_id(row: dict[str, Any]) -> int | None:
    value = row.get("alert_template_id")
    return int(value) if value is not None else None


POLICY_KEYS = ("workstation_policy_id", "server_policy_id", "block_policy_inheritance")
# The model fields a policy change saves, one per policy key.
_POLICY_UPDATE_FIELDS = {"workstation_policy_id": "workstation_policy", "server_policy_id": "server_policy", "block_policy_inheritance": "block_policy_inheritance"}


def _policy_id(row: dict[str, Any], key: str) -> int | None:
    value = row.get(key)
    return int(value) if value is not None else None


def _policy_part(row: dict[str, Any]) -> dict[str, Any]:
    """1.7.0: the policy ids and the inheritance flag, appended last. Missing keys read as None, None and False."""
    return {
        "workstation_policy_id": _policy_id(row, "workstation_policy_id"),
        "server_policy_id": _policy_id(row, "server_policy_id"),
        "block_policy_inheritance": bool(row.get("block_policy_inheritance") or False),
    }


def _policy_of(obj) -> dict[str, Any]:
    """The policy keys of a model object, in the shape ``client_row`` and ``site_row`` read."""
    return {key: getattr(obj, key, None) for key in POLICY_KEYS}


def client_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "client",
        "id": int(row["pk"]),
        "name": str(row.get("name") or ""),
        "active": True,
        "alert_template_id": _template_id(row),
        **_policy_part(row),
    }


def site_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "site",
        "id": int(row["pk"]),
        "name": str(row.get("name") or ""),
        "client_id": int(row["client_id"]),
        "active": True,
        "alert_template_id": _template_id(row),
        # 1.5.0: the owning client's name, as Tactical's own /clients/sites/ returns it (client__name, no extra query)
        "client_name": str(row.get("client__name") or ""),
        **_policy_part(row),
    }


# 1.10.0: the live-state keys, appended after the policy keys on every client and site record. ``client_row`` and ``site_row``
# never carry them (the audit rows stay stable); ``live_sites``, ``sites_by_client`` and ``attach_sites`` add them at the public return points.
LIVE_KEYS = ("failing_checks", "agent_count", "maintenance_mode")


def _failing_part(value) -> dict[str, bool]:
    """Tactical's stored ``failing_checks`` JSON as two real booleans. Null, a non-dict or a non-boolean value reads false."""
    stored = value if isinstance(value, dict) else {}
    return {"error": stored.get("error") is True, "warning": stored.get("warning") is True}


def _site_agent_stats(site_ids) -> dict[int, tuple[int, bool]]:
    """site id -> (agent count, any agent in maintenance mode), in one grouped query. A site with no agent is absent."""
    # Count is read lazily, with the Tactical models: some tests stub django.db.models with Q only
    from django.db.models import Count

    wanted = sorted({int(value) for value in site_ids})
    if not wanted:
        return {}
    _, _, Agent = _models()
    rows = (
        Agent.objects.filter(site_id__in=wanted)
        .values("site_id")
        .annotate(agent_count=Count("pk"), in_maintenance=Count("pk", filter=Q(maintenance_mode=True)))
        .order_by()
    )
    return {int(row["site_id"]): (int(row["agent_count"]), int(row["in_maintenance"]) > 0) for row in rows}


def _live_site(row: dict[str, Any], failing, stats: dict[int, tuple[int, bool]]) -> dict[str, Any]:
    count, maintenance = stats.get(int(row["id"]), (0, False))
    out = {key: value for key, value in row.items() if key not in LIVE_KEYS}
    out.update({"failing_checks": _failing_part(failing), "agent_count": count, "maintenance_mode": maintenance})
    return out


def live_sites(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copies of site records with the three live keys appended (1.10.0). Two queries for any number of rows.

    A site is computed from its own agents only. The rows are already inside the caller's scope, so nothing here widens it."""
    if not rows:
        return []
    ids = [int(row["id"]) for row in rows]
    _, Site, _ = _models()
    stored = {int(pk): value for pk, value in Site.objects.filter(pk__in=ids).values_list("pk", "failing_checks")}
    stats = _site_agent_stats(ids)
    return [_live_site(row, stored.get(int(row["id"])), stats) for row in rows]


def sites_by_client(client_ids, *, user=None, trusted: bool = False) -> dict[int, list[dict[str, Any]]]:
    """The site records of each client id inside the caller's scope (1.5.0), in one query, with the live keys (1.10.0).

    It uses the same ``filter_by_role`` rule as the sites read, so a client-limited role gets every site of its clients plus
    granted sites, a site-only role only its granted sites, and a trusted global context or an unrestricted caller every site.
    Records are ordered by name then id and have the same shape as ``list_sites`` records. One more grouped agent query covers all sites.
    """
    wanted = sorted({int(value) for value in client_ids})
    grouped: dict[int, list[dict[str, Any]]] = {value: [] for value in wanted}
    if not wanted:
        return grouped
    _, Site, _ = _models()
    qs = _scope_queryset(Site.objects.all(), user=user, trusted=trusted).filter(client_id__in=wanted)
    rows = list(qs.order_by("name", "pk").values("pk", "name", "client_id", "alert_template_id", "client__name", "failing_checks", *POLICY_KEYS))
    stats = _site_agent_stats([row["pk"] for row in rows])
    for row in rows:
        grouped.setdefault(int(row["client_id"]), []).append(_live_site(site_row(row), row.get("failing_checks"), stats))
    return grouped


def _client_live_parts(rows: list[dict[str, Any]], grouped: dict[int, list[dict[str, Any]]]) -> dict[int, dict[str, Any]]:
    """The live keys of each client, from the sites the caller may see (1.10.0, AD-12).

    ``agent_count`` is the sum over those sites and ``maintenance_mode`` is true when any has one. ``failing_checks`` is Tactical's
    stored client value only when the caller sees every site of the client, otherwise the OR of the visible sites' values, so a
    hidden failing site never shows. A client with no visible site gets 0, false and both false."""
    ids = [int(row["id"]) for row in rows]
    if not ids:
        return {}
    Client, Site, _ = _models()
    stored = {int(pk): value for pk, value in Client.objects.filter(pk__in=ids).values_list("pk", "failing_checks")}
    real_sites = Counter(int(value) for value in Site.objects.filter(client_id__in=ids).values_list("client_id", flat=True))
    parts: dict[int, dict[str, Any]] = {}
    for client_id in ids:
        sites = grouped.get(client_id, [])
        if not sites:
            parts[client_id] = {"failing_checks": _failing_part(None), "agent_count": 0, "maintenance_mode": False}
            continue
        if len(sites) == real_sites.get(client_id, 0):
            failing = _failing_part(stored.get(client_id))
        else:
            failing = {
                "error": any(site["failing_checks"]["error"] for site in sites),
                "warning": any(site["failing_checks"]["warning"] for site in sites),
            }
        parts[client_id] = {
            "failing_checks": failing,
            "agent_count": sum(int(site["agent_count"]) for site in sites),
            "maintenance_mode": any(bool(site["maintenance_mode"]) for site in sites),
        }
    return parts


def attach_sites(rows: list[dict[str, Any]], grouped: dict[int, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Client records with ``sites`` and the live keys added (1.10.0), from site records already read inside the caller's scope.

    ``sites`` keeps its place before the policy keys of 1.7.0, and the live keys come last, so the key order is CLIENT_FIELDS."""
    parts = _client_live_parts(rows, grouped)
    nested = []
    for row in rows:
        client_id = int(row["id"])
        out = {key: value for key, value in row.items() if key not in POLICY_KEYS and key not in LIVE_KEYS and key != "sites"}
        out["sites"] = list(grouped.get(client_id, []))
        out.update(_policy_part(row))
        out.update(parts[client_id])
        nested.append(out)
    return nested


def nest_sites(rows: list[dict[str, Any]], *, user=None, trusted: bool = False) -> list[dict[str, Any]]:
    """Return copies of client records with ``sites`` and the live keys added (1.5.0, 1.10.0). A constant number of queries for the whole list."""
    return attach_sites(rows, sites_by_client([row["id"] for row in rows], user=user, trusted=trusted))


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
    rows = queryset.values("pk", "name", "alert_template_id", *POLICY_KEYS)[offset : offset + limit]
    return [client_row(row) for row in rows], total


def page_sites(queryset, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = queryset.count()
    rows = queryset.values("pk", "name", "client_id", "alert_template_id", "client__name", *POLICY_KEYS)[offset : offset + limit]
    return [site_row(row) for row in rows], total


def page_agents(queryset, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
    total = queryset.count()
    rows = queryset.values(
        "agent_id", "hostname", "site_id", "site__client_id", "plat",
        "monitoring_type", "last_seen",
    )[offset : offset + limit]
    return [agent_row(row) for row in rows], total


def get_client_row(queryset, client_id: int) -> dict[str, Any] | None:
    row = queryset.filter(pk=client_id).values("pk", "name", "alert_template_id", *POLICY_KEYS).first()
    return client_row(row) if row else None


def get_site_row(queryset, site_id: int) -> dict[str, Any] | None:
    row = queryset.filter(pk=site_id).values("pk", "name", "client_id", "alert_template_id", "client__name", *POLICY_KEYS).first()
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


def _extend_role_scope(*, user, relation_name: str, obj) -> str | None:
    """Tactical's rule (clients/views.py): a created client or site joins the creator's role list only when that list is not empty.

    Returns "clients" or "sites" when the object was added, else None. A superuser or unrestricted role changes nothing, and a
    role limited only by sites is not widened to a client (1.17.22).
    """
    role = _role_for_user(user)
    if role is None or _role_scope_unrestricted(user=user, role=role):
        return None
    relation = getattr(role, relation_name, None)
    if not _relation_has_any(relation):
        return None
    add = getattr(relation, "add", None)
    if not callable(add):
        raise TacticalResourceValidationError("Restricted creator role does not expose a writable scope relation.")
    add(obj)
    return "clients" if relation_name == "can_view_clients" else "sites"


def create_client_row(*, user, name: str, default_site_name: str = "Default Site", custom_fields=None) -> dict[str, Any]:
    """Create a client and its first site in one transaction (1.17.22).

    ``custom_fields`` is a list of ``{field_id, value}`` saved in the same transaction, without the write-scope check because the
    creator just made the client. Returns ``{"client", "site", "role_scope_extended"}``: the base client record, the first site
    record and ``"clients"`` when the client joined the creator's ``can_view_clients`` (else None).
    """
    Client, Site, _ = _models()
    try:
        with transaction.atomic():
            obj = Client(name=name)
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save()

            site = Site(client=obj, name=default_site_name)
            site.full_clean(exclude=None, validate_unique=False)
            site.save()

            extended = _extend_role_scope(user=user, relation_name="can_view_clients", obj=obj)
            if custom_fields:
                _save_custom_field_values("client", obj.pk, custom_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Client or first site failed Tactical validation.") from exc
    return {
        "client": client_row({"pk": obj.pk, "name": obj.name, "alert_template_id": getattr(obj, "alert_template_id", None), **_policy_of(obj)}),
        "site": site_row({
            "pk": site.pk, "name": site.name, "client_id": obj.pk,
            "alert_template_id": getattr(site, "alert_template_id", None), "client__name": obj.name, **_policy_of(site),
        }),
        "role_scope_extended": extended,
    }


_NOT_GIVEN = object()


def _validation_message(exc: ValidationError, label: str) -> str:
    """A missing alert template or policy reads plainly; every other failure keeps the one-line text of before 1.17.17."""
    fields = getattr(exc, "message_dict", None) if hasattr(exc, "error_dict") else None
    if isinstance(fields, dict) and "alert_template" in fields:
        return "alert_template_id does not name an existing alert template."
    if isinstance(fields, dict):
        for model_field, key in (("workstation_policy", "workstation_policy_id"), ("server_policy", "server_policy_id")):
            if model_field in fields:
                return f"{key} does not name an existing policy."
    return f"{label} failed Tactical validation."


def _apply_policy_fields(obj, update_fields: list[str], given: dict[str, Any]) -> None:
    """Set the policy fields that were given and differ from the stored value (1.17.24). An unchanged value is not saved."""
    for key, value in given.items():
        if value is _NOT_GIVEN or getattr(obj, key, None) == value:
            continue
        setattr(obj, key, value)
        update_fields.append(_POLICY_UPDATE_FIELDS[key])


def check_expected(obj, expected: dict[str, Any] | None, label: str) -> None:
    """The compare of core.resources 1.11.0's optional guard, run on the LOCKED row, before any change is applied.

    ``expected`` maps ``workstation_policy_id`` or ``server_policy_id`` to a whole number (or None for 'must be unset') and
    ``block_policy_inheritance`` to a bool. A key that is present and differs from the row raises a conflict with the code
    ``record_changed`` and a plain sentence that names the field and never a value. Nothing has been written at that point."""
    for key in POLICY_KEYS:
        if not expected or key not in expected:
            continue
        current = getattr(obj, key, None)
        if key == "block_policy_inheritance":
            current = bool(current)
        elif current is not None:
            try:
                current = int(current)
            except (TypeError, ValueError):
                current = None
        if current != expected[key]:
            raise TacticalResourceConflictError(
                f"The {label}'s {key} changed since it was read, so nothing was saved. Read it again and retry.", code="record_changed",
            )


def update_client_row(*, user, client_id: int, name: str | None = None, alert_template_id: int | None = _NOT_GIVEN,
                      workstation_policy_id: int | None = _NOT_GIVEN, server_policy_id: int | None = _NOT_GIVEN,
                      block_policy_inheritance: bool = _NOT_GIVEN, expected: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Change a client's name and, since 1.17.17, its alert template (an id or None). Core holds only the field:
    Alerts owns the template list. The write goes through ``obj.save`` so Tactical's own model hook
    (``cache_agents_alert_template``) still runs. A template id that does not exist fails ``full_clean`` through the ForeignKey.

    1.17.24: the workstation and server policy ids and ``block_policy_inheritance`` are saved the same way, so Tactical's own
    ``Client.save`` re-caches the alert template and refreshes the policy caches. A policy id that names no policy fails the
    ForeignKey. Core holds only the ids: Automation owns the policy list.

    1.17.51 (core.resources 1.11.0): ``expected`` is the optional compare-and-set guard, see ``check_expected``. It is judged against
    the row this transaction has locked, so there is no gap between the compare and the write."""
    Client, _, _ = _models()
    try:
        with transaction.atomic():
            if not client_write_in_scope(user=user, client_id=client_id):
                return None
            obj = Client.objects.select_for_update().filter(pk=client_id).first()
            if obj is None:
                return None
            check_expected(obj, expected, "client")
            update_fields = []
            if name is not None:
                obj.name = name
                update_fields.append("name")
            if alert_template_id is not _NOT_GIVEN:
                obj.alert_template_id = alert_template_id
                update_fields.append("alert_template")
            _apply_policy_fields(obj, update_fields, {
                "workstation_policy_id": workstation_policy_id, "server_policy_id": server_policy_id,
                "block_policy_inheritance": block_policy_inheritance,
            })
            if update_fields:
                obj.full_clean(exclude=None, validate_unique=False)
                if hasattr(obj, "modified_by"):
                    update_fields.append("modified_by")
                if hasattr(obj, "modified_time"):
                    update_fields.append("modified_time")
                obj.save(update_fields=update_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A client with that name already exists.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError(_validation_message(exc, "Client")) from exc
    return client_row({"pk": obj.pk, "name": obj.name, "alert_template_id": getattr(obj, "alert_template_id", None), **_policy_of(obj)})


def create_site_row(*, client_id: int, name: str, user=None, custom_fields=None) -> dict[str, Any]:
    """Create a site (1.17.22). Returns ``{"site", "role_scope_extended"}``: the site record and ``"sites"`` when the site joined
    the creator's ``can_view_sites`` (Tactical's rule: only when that list is not empty), else None. ``custom_fields`` are saved
    in the same transaction."""
    Client, Site, _ = _models()
    try:
        with transaction.atomic():
            obj = Site(client_id=client_id, name=name)
            obj.full_clean(exclude=None, validate_unique=False)
            obj.save()
            extended = _extend_role_scope(user=user, relation_name="can_view_sites", obj=obj) if user is not None else None
            if custom_fields:
                _save_custom_field_values("site", obj.pk, custom_fields)
            client_name = str(Client.objects.filter(pk=obj.client_id).values_list("name", flat=True).first() or "")
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError("Site failed Tactical validation.") from exc
    return {
        "site": site_row({
            "pk": obj.pk, "name": obj.name, "client_id": obj.client_id,
            "alert_template_id": getattr(obj, "alert_template_id", None), "client__name": client_name, **_policy_of(obj),
        }),
        "role_scope_extended": extended,
    }


def site_agent_count(*, site_id: int) -> int:
    """How many agents sit on a site (1.17.24). Agents follow their site when it moves, so a move audit row can say how many."""
    _, _, Agent = _models()
    return int(Agent.objects.filter(site_id=site_id).count())


def update_site_row(*, user, site_id: int, name: str | None = None, client_id: int | None = None,
                    alert_template_id: int | None = _NOT_GIVEN, workstation_policy_id: int | None = _NOT_GIVEN,
                    server_policy_id: int | None = _NOT_GIVEN, block_policy_inheritance: bool = _NOT_GIVEN,
                    expected: dict[str, Any] | None = None) -> dict[str, Any] | None:
    Client, Site, _ = _models()
    try:
        with transaction.atomic():
            if not site_write_in_scope(user=user, site_id=site_id):
                return None
            obj = Site.objects.select_for_update().filter(pk=site_id).first()
            if obj is None:
                return None
            check_expected(obj, expected, "site")  # core.resources 1.11.0: on the locked row, before a move or any other change
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
            if alert_template_id is not _NOT_GIVEN:
                obj.alert_template_id = alert_template_id
                update_fields.append("alert_template")
            _apply_policy_fields(obj, update_fields, {
                "workstation_policy_id": workstation_policy_id, "server_policy_id": server_policy_id,
                "block_policy_inheritance": block_policy_inheritance,
            })
            if update_fields:
                obj.full_clean(exclude=None, validate_unique=False)
                if hasattr(obj, "modified_by"):
                    update_fields.append("modified_by")
                if hasattr(obj, "modified_time"):
                    update_fields.append("modified_time")
                # Saved through the model so Tactical's own Site.save hooks run (alert template and policy caches). The
                # agents follow the site on a move because they point at the site row.
                obj.save(update_fields=update_fields)
    except IntegrityError as exc:
        raise TacticalResourceConflictError("A site with that name already exists for the selected client.") from exc
    except ValidationError as exc:
        raise TacticalResourceValidationError(_validation_message(exc, "Site")) from exc
    return site_row({
        "pk": obj.pk, "name": obj.name, "client_id": obj.client_id, "alert_template_id": getattr(obj, "alert_template_id", None),
        "client__name": str(Client.objects.filter(pk=obj.client_id).values_list("name", flat=True).first() or ""),
        **_policy_of(obj),
    })


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

            source_client_name = str(Client.objects.filter(pk=source.client_id).values_list("name", flat=True).first() or "")
            deleted = site_row({"pk": source.pk, "name": source.name, "client_id": source.client_id, "client__name": source_client_name})
            destination_row = (
                site_row({"pk": destination.pk, "name": destination.name, "client_id": destination.client_id, "client__name": source_client_name})
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
                site_row({
                    "pk": destination.pk, "name": destination.name, "client_id": destination.client_id,
                    "client__name": str(Client.objects.filter(pk=destination.client_id).values_list("name", flat=True).first() or ""),
                })
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
    return [_custom_field_row(field, by_field.get(field.pk)) for field in fields]


def _custom_field_row(field, record) -> dict[str, Any]:
    """One custom field as the stable row. ``record`` is the stored value, or None for the field's default."""
    return {
        "field_id": int(field.pk),
        "name": str(field.name),
        "type": str(field.type),
        "options": list(field.options or []),
        "required": bool(field.required),
        "value": _custom_value(record, field),
    }


def custom_field_definition_rows(resource_type: str) -> list[dict[str, Any]]:
    """The non-hidden custom-field definitions for clients or sites with each field's default as ``value`` (1.17.23).

    Same order and shape as ``custom_field_rows`` (``hide_in_ui`` False, ordered by order, name, pk). No per-client data is read, so
    there is nothing to scope."""
    if resource_type not in ("client", "site"):
        raise TacticalResourceValidationError("Unsupported custom-field resource type.")
    CustomField, _client_values, _site_values = _custom_models()
    fields = CustomField.objects.filter(model=resource_type, hide_in_ui=False).order_by("order", "name", "pk")
    return [_custom_field_row(field, None) for field in fields]


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


def _save_custom_field_values(resource_type: str, resource_id: int, values: list[dict[str, Any]]) -> list[int]:
    """Validate and save custom-field values for one client or site, with no write-scope check (the caller decided that).

    Used by ``update_custom_field_rows`` after its scope check and by create_client and create_site inside their own
    transaction, where the creator has just made the object. Returns the sorted field ids saved.
    """
    if resource_type not in ("client", "site"):
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
    return sorted(submitted)


def update_custom_field_rows(*, user, resource_type: str, resource_id: int, values: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    if resource_type == "client":
        if not client_write_in_scope(user=user, client_id=resource_id):
            return None
    elif resource_type == "site":
        if not site_write_in_scope(user=user, site_id=resource_id):
            return None
    else:
        raise TacticalResourceValidationError("Unsupported custom-field resource type.")
    _save_custom_field_values(resource_type, resource_id, values)
    return custom_field_rows(user=user, resource_type=resource_type, resource_id=resource_id)
