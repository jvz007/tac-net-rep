"""Stable Core Resource Directory public contract.

Tactical owns the underlying Client/Site/Agent resources.  Core owns the
Tec-Tac representation and authorization boundary.  Feature modules consume
this module and must not depend on Tactical ORM implementation details.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from . import resources_adapter as adapter
from .capabilities import register_capability

CONTRACT_ID = "core.resources"
CONTRACT_VERSION = "1.10.0"
RESOURCE_TYPES = ("client", "site", "agent")
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
MAX_PAGE_NUMBER = 10000
# AD-34 condition 1: the only modules that may build a non-global service context. The actor must name the same module.
SERVICE_CONTEXT_CALLERS = ("userinvite",)
CLIENT_MANAGE_PERMISSION = "core.resources.clients.manage"
SITE_MANAGE_PERMISSION = "core.resources.sites.manage"

# 1.4.0 appended alert_template_id (an integer or null) to the client and site records; the earlier keys keep their place.
# 1.5.0 appended ``sites`` (the client's site records inside the caller's scope) to client records and ``client_name`` to site records.
# 1.6.0 added list_custom_field_definitions (the definitions without a client or site id); no record shape changed.
# 1.7.0 appended workstation_policy_id, server_policy_id and block_policy_inheritance to client and site records (the policy
# ids are Automation's; Core holds only the ids), and the alert_template_id and policy_id list filters.
# 1.8.0 (Core 1.17.25, Johan CQ79) moves a site on Tactical's rule: Edit sites and the site's own scope decide, with no destination
# client grant check, and a same-client update needs the site's write scope too (a read-only scope is refused). No record shape changed.
# 1.9.0 (Core 1.17.30, AD-34 condition 1) lets the module userinvite (only) call trusted_service_context(global_access=False): a
# service context with no resource visibility, for a caller Core verified from the call stack. Additive; global_access=True is unchanged.
# 1.10.0 (Core 1.17.40, Endpoints 0.7.0 request) appended failing_checks, agent_count and maintenance_mode to client and site records,
# read only and computed inside the caller's scope (a role never learns of a site it may not see). Additive.
LIVE_FIELDS = ("failing_checks", "agent_count", "maintenance_mode")
CLIENT_FIELDS = ("type", "id", "name", "active", "alert_template_id", "sites", "workstation_policy_id", "server_policy_id", "block_policy_inheritance") + LIVE_FIELDS
SITE_FIELDS = ("type", "id", "name", "client_id", "active", "alert_template_id", "client_name", "workstation_policy_id", "server_policy_id", "block_policy_inheritance") + LIVE_FIELDS
AGENT_FIELDS = (
    "type", "id", "hostname", "client_id", "site_id", "active",
    "platform", "monitoring_type", "last_seen",
)


class _Unset:
    """The value of a keyword the caller left out, so that None can mean clear (``alert_template_id=None``)."""

    def __repr__(self) -> str:
        return "UNSET"

    def __bool__(self) -> bool:
        return False


UNSET = _Unset()


class ResourceDirectoryError(RuntimeError):
    code = "resource_directory_error"


class ResourceValidationError(ResourceDirectoryError):
    code = "invalid_resource_request"


class ResourcePermissionDenied(ResourceDirectoryError):
    code = "resource_permission_denied"


class ResourceNotFound(ResourceDirectoryError):
    code = "resource_not_found"


class ResourceConflict(ResourceDirectoryError):
    code = "resource_conflict"


@dataclass(frozen=True)
class ResourceAccessContext:
    """Explicit authority context for every Resource Directory operation."""

    user: Any | None = None
    service_actor: str | None = None
    service_purpose: str | None = None
    trusted_global: bool = False

    @property
    def is_service(self) -> bool:
        return bool(self.service_actor)

    @property
    def scope(self) -> dict[str, Any]:
        """The caller's Tactical client and site scope (1.4.0): ``scope_descriptor(context=self)``. Read when asked, never
        cached on this frozen object, so it reflects the role as it is now."""
        return scope_descriptor(context=self)


def user_context(user) -> ResourceAccessContext:
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise ResourcePermissionDenied("An authenticated Tactical user is required.")
    return ResourceAccessContext(user=user)


def trusted_service_context(*, actor: str, purpose: str, global_access: bool = False) -> ResourceAccessContext:
    """Create an explicit audited non-interactive trusted execution context.

    Global resource visibility is deliberately opt-in.  A non-global context (``global_access=False``) is for the module userinvite
    only (AD-34 condition 1): it carries the actor and purpose but no visibility, and writes no audit row.  Granting global access is a
    security-relevant event, so Core writes a strict Tactical audit record
    before returning the context. Browser callers never use this path.
    """
    actor = str(actor or "").strip()
    purpose = str(purpose or "").strip()
    if not actor or not purpose:
        raise ResourceValidationError("Trusted service contexts require actor and purpose.")
    if not global_access:
        # AD-34 condition 1: a verified module caller from the Core-held list, naming itself as the actor. Fail closed otherwise,
        # with no audit row and no hint of the list. The context sees no resources: trusted_global stays False.
        # Imported here: standalone test loaders have no parent package.
        from .caller_identity import calling_module_for_core_provider

        identity = calling_module_for_core_provider(provider_file=__file__)
        caller_id = getattr(identity, "module_id", None)
        if caller_id not in SERVICE_CONTEXT_CALLERS or actor != caller_id:
            raise ResourcePermissionDenied("Trusted service resource access requires explicit global_access=True in contract v1.")
        return ResourceAccessContext(service_actor=actor, service_purpose=purpose[:500], trusted_global=False)

    class _ServiceAuditActor:
        is_authenticated = True
        is_superuser = False
        role = None

        def __init__(self, username: str):
            self.username = username

    try:
        from .audit import AuditContractError, AuditWriteError, record
        record(
            actor=_ServiceAuditActor(actor[:160]),
            module_id="core",
            action="custom:resource-global-context",
            object_type="resource_service_context",
            object_id=actor[:160],
            message="Trusted global Resource Directory service context granted.",
            metadata={"purpose": purpose[:500], "global_access": True},
            strict=True,
        )
    except Exception as exc:
        raise ResourcePermissionDenied("Trusted global resource access requires a persisted Core audit record.") from exc

    return ResourceAccessContext(
        service_actor=actor[:160], service_purpose=purpose[:500], trusted_global=True,
    )


def _role(user):
    try:
        getter = getattr(user, "get_and_set_role_cache", None)
        if callable(getter):
            return getter()
    except Exception:
        pass
    return getattr(user, "role", None)


def _is_superuser(user) -> bool:
    role = _role(user)
    return bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False)


def _authorize(context: ResourceAccessContext, resource_type: str) -> tuple[Any | None, bool]:
    if not isinstance(context, ResourceAccessContext):
        raise ResourcePermissionDenied("A ResourceAccessContext is required.")
    if context.is_service:
        if not context.trusted_global:
            raise ResourcePermissionDenied("Service context is not authorized for global resource access.")
        return None, True
    user = context.user
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise ResourcePermissionDenied("An authenticated Tactical user is required.")
    if _is_superuser(user):
        return user, False
    role = _role(user)
    if role is None:
        raise ResourcePermissionDenied("The Tactical user has no role assigned.")
    permission = {
        "client": "can_list_clients",
        "site": "can_list_sites",
        "agent": "can_list_agents",
    }.get(resource_type)
    if not permission:
        raise ResourceValidationError(f"Unsupported resource type: {resource_type!r}.")
    if not bool(getattr(role, permission, False)):
        raise ResourcePermissionDenied(f"Tactical permission {permission} is required.")
    return user, False



def _authorize_write(context: ResourceAccessContext, resource_type: str) -> Any:
    if not isinstance(context, ResourceAccessContext):
        raise ResourcePermissionDenied("A ResourceAccessContext is required.")
    if context.is_service:
        raise ResourcePermissionDenied("Trusted service contexts are read-only in core.resources 1.x write operations.")
    user = context.user
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise ResourcePermissionDenied("An authenticated Tactical user is required.")
    if _is_superuser(user):
        return user
    role = _role(user)
    if role is None:
        raise ResourcePermissionDenied("The Tactical user has no role assigned.")
    tactical_permission = {
        "client": "can_manage_clients",
        "site": "can_manage_sites",
    }.get(resource_type)
    core_permission = {
        "client": CLIENT_MANAGE_PERMISSION,
        "site": SITE_MANAGE_PERMISSION,
    }.get(resource_type)
    if not tactical_permission or not core_permission:
        raise ResourceValidationError(f"Unsupported writable resource type: {resource_type!r}.")
    if not bool(getattr(role, tactical_permission, False)):
        raise ResourcePermissionDenied(f"Tactical permission {tactical_permission} is required.")
    try:
        from .rbac import has_extension_permission
        allowed = has_extension_permission(user, core_permission)
    except Exception as exc:
        raise ResourcePermissionDenied("Unable to resolve Tec-Tac Resource Directory write permission.") from exc
    if not allowed:
        raise ResourcePermissionDenied(f"Tec-Tac permission {core_permission} is required.")
    return user


def _clean_name(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ResourceValidationError(f"{label} must be a string.")
    value = value.strip()
    if not value:
        raise ResourceValidationError(f"{label} is required.")
    if len(value) > 255:
        raise ResourceValidationError(f"{label} may not exceed 255 characters.")
    return value


def _clean_resource_name(value: Any, kind: str) -> str:
    """A client or site name as Tactical accepts it: a trimmed non-empty string of at most 255 characters with no ``|`` (1.17.22).
    Tactical's ClientSerializer and SiteSerializer refuse ``|``, which it uses to join client and site in agent labels."""
    clean = _clean_name(value, "name")
    if "|" in clean:
        raise ResourceValidationError(f"{kind} name cannot contain the | character")
    return clean


def _clean_custom_field_id(value: Any) -> int:
    """A field id as a positive whole number (1.17.23): a real int of 1 or more, or a string of ASCII digits that is at least 1 (the
    HTTP body may carry it). A boolean, float, None, list, zero, a negative number and text such as ``'1.5'`` or ``' 1'`` are refused.
    The adapter's own ``int()`` would take ``True`` and ``1.5`` as 1, so the id is cleaned here, before anything is created."""
    if isinstance(value, bool):
        raise ResourceValidationError("field_id must be a positive whole number.")
    if isinstance(value, str):
        if not (value.isascii() and value.isdigit()):
            raise ResourceValidationError("field_id must be a positive whole number.")
        value = int(value)
    if not isinstance(value, int) or value < 1 or value >= 2**63:
        raise ResourceValidationError("field_id must be a positive whole number.")
    return value


def _clean_custom_fields(value: Any) -> list[dict[str, Any]] | None:
    """None, or a list of ``{field_id, value}`` for create_client, create_site and update_custom_fields (1.17.22). The ids are
    validated and stored back as whole numbers (1.17.23); adapter rules decide the values and refuse a duplicate id."""
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 200:
        raise ResourceValidationError("custom_fields must be an array of at most 200 items.")
    cleaned = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"field_id", "value"}:
            raise ResourceValidationError("Each custom field must contain only field_id and value.")
        cleaned.append({"field_id": _clean_custom_field_id(item["field_id"]), "value": item["value"]})
    return cleaned


def _custom_field_ids(values: list[dict[str, Any]] | None) -> list[int]:
    return sorted(int(item["field_id"]) for item in (values or []))


def _audit_view(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """The record as audited before 1.5.0: without the nested ``sites`` and ``client_name`` added by the read contract, and
    without the live keys of 1.10.0 (they change on their own, so they never belong in a before and after pair)."""
    if row is None:
        return None
    return {key: value for key, value in row.items() if key not in ("sites", "client_name") and key not in LIVE_FIELDS}


def _adapter_write(callable_obj, **kwargs):
    try:
        return callable_obj(**kwargs)
    except getattr(adapter, "TacticalResourceConflictError", adapter.TacticalResourceAdapterError) as exc:
        raise ResourceConflict(str(exc)) from exc
    except getattr(adapter, "TacticalResourceValidationError", adapter.TacticalResourceAdapterError) as exc:
        raise ResourceValidationError(str(exc)) from exc




def _transaction_atomic():
    try:
        from django.db import transaction
    except ModuleNotFoundError:
        # Lightweight contract tests import this module without Django. Tactical
        # production always provides Django, where the real transaction applies.
        return nullcontext()
    return transaction.atomic()


def _record_resource_change(*, actor, action: str, resource_type: str, resource_id: Any, before=None, after=None, metadata=None) -> None:
    """Persist a transaction-critical Core audit row for Resource Directory writes."""
    try:
        from .audit import record
        record(
            actor=actor,
            module_id="core",
            action=action,
            object_type=f"resource_{resource_type}",
            object_id=str(resource_id),
            message=f"Tec-Tac Resource Directory {action} {resource_type}.",
            before=before,
            after=after,
            metadata=metadata or {},
            strict=True,
        )
    except Exception as exc:
        raise ResourceDirectoryError("Resource change requires a persisted Core audit record.") from exc

def _clean_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ResourceValidationError(f"{label} must be a positive integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ResourceValidationError(f"{label} must be a positive integer.") from exc
    if parsed < 1:
        raise ResourceValidationError(f"{label} must be a positive integer.")
    return parsed


def _clean_nullable_id(value: Any, label: str) -> int | None:
    """None clears the id. Otherwise a positive whole number (a text of digits is accepted). Booleans, zero, negatives,
    fractions and any other text are refused. Whether the id exists is checked by Tactical's own ForeignKey."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ResourceValidationError(f"{label} must be a positive integer or null.")
    if isinstance(value, str):
        text = value.strip()
        if not text.isascii() or not text.isdigit():
            raise ResourceValidationError(f"{label} must be a positive integer or null.")
        value = int(text)
    if not isinstance(value, int) or value < 1 or value >= 2**63:
        raise ResourceValidationError(f"{label} must be a positive integer or null.")
    return value


def _clean_alert_template_id(value: Any) -> int | None:
    return _clean_nullable_id(value, "alert_template_id")


def _clean_block_policy_inheritance(value: Any) -> bool:
    """A real true or false only: 1, 0 and text are refused."""
    if not isinstance(value, bool):
        raise ResourceValidationError("block_policy_inheritance must be true or false.")
    return value


POLICY_FIELDS = ("workstation_policy_id", "server_policy_id", "block_policy_inheritance")


def _policy_changes(*, workstation_policy_id: Any, server_policy_id: Any, block_policy_inheritance: Any) -> dict[str, Any]:
    """The policy fields that were given, cleaned (1.7.0). UNSET leaves a field alone; None clears a policy id."""
    changes: dict[str, Any] = {}
    if workstation_policy_id is not UNSET:
        changes["workstation_policy_id"] = _clean_nullable_id(workstation_policy_id, "workstation_policy_id")
    if server_policy_id is not UNSET:
        changes["server_policy_id"] = _clean_nullable_id(server_policy_id, "server_policy_id")
    if block_policy_inheritance is not UNSET:
        changes["block_policy_inheritance"] = _clean_block_policy_inheritance(block_policy_inheritance)
    return changes


def _template_changed(before: dict | None, after: dict | None) -> bool:
    return (before or {}).get("alert_template_id") != (after or {}).get("alert_template_id")


def _policy_changed(before: dict | None, after: dict | None) -> list[str]:
    """The names of the policy fields whose value differs. Ids only, never a policy name."""
    return [key for key in POLICY_FIELDS if (before or {}).get(key) != (after or {}).get(key)]


def _pagination(page: Any, page_size: Any) -> tuple[int, int, int]:
    page = _clean_positive_int(page, "page")
    page_size = _clean_positive_int(page_size, "page_size")
    if page > MAX_PAGE_NUMBER:
        raise ResourceValidationError(f"page may not exceed {MAX_PAGE_NUMBER}.")
    if page_size > MAX_PAGE_SIZE:
        raise ResourceValidationError(f"page_size may not exceed {MAX_PAGE_SIZE}.")
    return page, page_size, (page - 1) * page_size


def _search(value: Any) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    if len(value) > 255:
        raise ResourceValidationError("search may not exceed 255 characters.")
    return value


def _active(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ResourceValidationError("active must be true or false.")


def _page(items: list[dict], total: int, page: int, page_size: int) -> dict[str, Any]:
    pages = (int(total) + page_size - 1) // page_size if total else 0
    return {
        "items": items,
        "count": int(total),
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "next_page": page + 1 if page < pages else None,
        "previous_page": page - 1 if page > 1 and pages else None,
    }


def _filter_id(value: Any, label: str) -> int | None:
    """A list filter id: empty means no filter, otherwise a positive whole number (text of digits accepted). Strict: a fraction,
    a boolean or other text is refused, so a typo never silently widens or empties a list."""
    if value is None or (isinstance(value, str) and value == ""):
        return None
    try:
        return _clean_nullable_id(value, label)
    except ResourceValidationError as exc:
        raise ResourceValidationError(f"{label} must be a positive integer.") from exc


def list_clients(*, context: ResourceAccessContext, search: str | None = None, active: bool | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE,
                 alert_template_id: Any | None = None, policy_id: Any | None = None) -> dict[str, Any]:
    """``alert_template_id`` and ``policy_id`` (matches the workstation or the server policy) filter the list (1.7.0)."""
    user, trusted = _authorize(context, "client")
    page, page_size, offset = _pagination(page, page_size)
    template_filter = _filter_id(alert_template_id, "alert_template_id")
    policy_filter = _filter_id(policy_id, "policy_id")
    qs = adapter.clients_queryset(user=user, trusted=trusted, search=_search(search), active=_active(active),
                                  alert_template_id=template_filter, policy_id=policy_filter)
    items, total = adapter.page_clients(qs, offset=offset, limit=page_size)
    # 1.5.0: each client carries its sites inside the caller's scope (Tactical's own GET /clients/ does), one query per page.
    return _page(adapter.nest_sites(items, user=user, trusted=trusted), total, page, page_size)


def get_client(client_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    user, trusted = _authorize(context, "client")
    resource_id = _clean_positive_int(client_id, "client_id")
    row = adapter.get_client_row(adapter.clients_queryset(user=user, trusted=trusted), resource_id)
    if row is None:
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    return adapter.nest_sites([row], user=user, trusted=trusted)[0]


def list_sites(*, context: ResourceAccessContext, client_id: Any | None = None, search: str | None = None, active: bool | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE,
               alert_template_id: Any | None = None, policy_id: Any | None = None) -> dict[str, Any]:
    """``alert_template_id`` and ``policy_id`` (matches the workstation or the server policy) filter the list (1.7.0)."""
    user, trusted = _authorize(context, "site")
    page, page_size, offset = _pagination(page, page_size)
    client_id = _clean_positive_int(client_id, "client_id") if client_id not in (None, "") else None
    template_filter = _filter_id(alert_template_id, "alert_template_id")
    policy_filter = _filter_id(policy_id, "policy_id")
    qs = adapter.sites_queryset(user=user, trusted=trusted, client_id=client_id, search=_search(search), active=_active(active),
                                alert_template_id=template_filter, policy_id=policy_filter)
    items, total = adapter.page_sites(qs, offset=offset, limit=page_size)
    return _page(adapter.live_sites(items), total, page, page_size)


def get_site(site_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    user, trusted = _authorize(context, "site")
    resource_id = _clean_positive_int(site_id, "site_id")
    row = adapter.get_site_row(adapter.sites_queryset(user=user, trusted=trusted), resource_id)
    if row is None:
        raise ResourceNotFound("Site was not found in the caller's resource scope.")
    return adapter.live_sites([row])[0]


def list_agents(*, context: ResourceAccessContext, client_id: Any | None = None, site_id: Any | None = None, search: str | None = None, active: bool | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    user, trusted = _authorize(context, "agent")
    page, page_size, offset = _pagination(page, page_size)
    client_id = _clean_positive_int(client_id, "client_id") if client_id not in (None, "") else None
    site_id = _clean_positive_int(site_id, "site_id") if site_id not in (None, "") else None
    qs = adapter.agents_queryset(user=user, trusted=trusted, client_id=client_id, site_id=site_id, search=_search(search), active=_active(active))
    items, total = adapter.page_agents(qs, offset=offset, limit=page_size)
    return _page(items, total, page, page_size)


def get_agent(agent_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    user, trusted = _authorize(context, "agent")
    resource_id = str(agent_id or "").strip()
    if not resource_id or len(resource_id) > 200:
        raise ResourceValidationError("agent_id is invalid.")
    row = adapter.get_agent_row(adapter.agents_queryset(user=user, trusted=trusted), resource_id)
    if row is None:
        raise ResourceNotFound("Agent was not found in the caller's resource scope.")
    return row



def create_client(*, name: str, context: ResourceAccessContext, site_name: str | None = None, custom_fields: Any = None) -> dict[str, Any]:
    """Create a client and its first site in one transaction (Tactical's Add client).

    ``site_name`` is the first site's name; new callers always send it. A call without it still works and the site is named
    "Default Site" (deprecated compatibility path, audit metadata ``default_site_created`` true). ``custom_fields`` is an
    optional list of ``{field_id, value}`` saved in the same transaction. As Tactical does, the client joins the creator's
    ``can_view_clients`` only when that list is not empty. Names may not contain ``|``. The record returned carries
    ``sites`` with the first site.
    """
    user = _authorize_write(context, "client")
    clean_name = _clean_resource_name(name, "Client")
    first_site_name = _clean_resource_name(site_name, "Site") if site_name is not None else "Default Site"
    fields = _clean_custom_fields(custom_fields)
    with _transaction_atomic():
        result = _adapter_write(
            adapter.create_client_row, user=user, name=clean_name,
            default_site_name=first_site_name, custom_fields=fields,
        )
        row, first_site = result["client"], result["site"]
        _record_resource_change(
            actor=user, action="add", resource_type="client", resource_id=row["id"],
            after=row,
            metadata={
                "default_site_created": site_name is None,
                "first_site_id": first_site["id"],
                "role_scope_extended": result.get("role_scope_extended") or "none",
                "custom_field_ids": _custom_field_ids(fields),
            },
        )
        # 1.10.0: the record carries the live keys, like every other read of a client
        return adapter.attach_sites([row], {row["id"]: adapter.live_sites([first_site])})[0]


def update_client(client_id: Any, *, name: str | None = None, alert_template_id: Any = UNSET, context: ResourceAccessContext,
                  workstation_policy_id: Any = UNSET, server_policy_id: Any = UNSET, block_policy_inheritance: Any = UNSET) -> dict[str, Any]:
    """Change a client's name, its alert template id, its policy fields, or any of them (at least one).

    ``alert_template_id`` is a positive integer to set or None to clear (1.4.0). ``workstation_policy_id`` and ``server_policy_id``
    work the same way and ``block_policy_inheritance`` takes a real true or false (1.7.0). UNSET leaves a field alone. Core holds
    only the ids: Alerts owns the template list and Automation the policy list."""
    user = _authorize_write(context, "client")
    resource_id = _clean_positive_int(client_id, "client_id")
    if name is None and alert_template_id is UNSET and all(value is UNSET for value in (workstation_policy_id, server_policy_id, block_policy_inheritance)):
        raise ResourceValidationError("At least one of name, alert_template_id, workstation_policy_id, server_policy_id or block_policy_inheritance is required.")
    changes: dict[str, Any] = {}
    if name is not None:
        changes["name"] = _clean_resource_name(name, "Client")
    if alert_template_id is not UNSET:
        changes["alert_template_id"] = _clean_alert_template_id(alert_template_id)
    changes.update(_policy_changes(workstation_policy_id=workstation_policy_id, server_policy_id=server_policy_id, block_policy_inheritance=block_policy_inheritance))
    before = adapter.get_client_row(adapter.clients_queryset(user=user, trusted=False), resource_id)
    with _transaction_atomic():
        row = _adapter_write(adapter.update_client_row, user=user, client_id=resource_id, **changes)
        if row is None:
            raise ResourceNotFound("Client was not found in the caller's resource scope.")
        if before is not None and before == row:
            # Nothing changed (the same values were sent again): no audit row.
            return adapter.nest_sites([row], user=user, trusted=False)[0]
        metadata = {"alert_template_changed": "alert_template_id" in changes and _template_changed(before, row)}
        if any(key in changes for key in POLICY_FIELDS):
            metadata["policy_changed"] = _policy_changed(before, row)
        _record_resource_change(
            actor=user, action="modify", resource_type="client", resource_id=resource_id,
            before=before, after=row, metadata=metadata,
        )
        return adapter.nest_sites([row], user=user, trusted=False)[0]


def create_site(*, client_id: Any, name: str, context: ResourceAccessContext, custom_fields: Any = None) -> dict[str, Any]:
    """Create a site under a client the caller may write to. ``custom_fields`` is an optional list of ``{field_id, value}`` saved
    in the same transaction. As Tactical does, the site joins the creator's ``can_view_sites`` only when that list is not
    empty. Names may not contain ``|``."""
    user = _authorize_write(context, "site")
    target_client_id = _clean_positive_int(client_id, "client_id")
    clean_name = _clean_resource_name(name, "Site")
    fields = _clean_custom_fields(custom_fields)
    if not adapter.client_write_in_scope(user=user, client_id=target_client_id):
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    with _transaction_atomic():
        result = _adapter_write(
            adapter.create_site_row,
            client_id=target_client_id,
            name=clean_name,
            user=user,
            custom_fields=fields,
        )
        row = result["site"]
        _record_resource_change(
            actor=user, action="add", resource_type="site", resource_id=row["id"],
            after=_audit_view(row),
            metadata={
                "role_scope_extended": result.get("role_scope_extended") or "none",
                "custom_field_ids": _custom_field_ids(fields),
            },
        )
        return adapter.live_sites([row])[0]


def update_site(site_id: Any, *, name: str | None = None, client_id: Any | None = None, alert_template_id: Any = UNSET, context: ResourceAccessContext,
                workstation_policy_id: Any = UNSET, server_policy_id: Any = UNSET, block_policy_inheritance: Any = UNSET) -> dict[str, Any]:
    """Change a site's name, its client, its alert template id (a positive integer, or None to clear; 1.4.0), its policy fields
    (1.7.0, as update_client), or any of them.

    Moving a site (``client_id`` other than the current one) is Tactical's Edit site (1.8.0, CQ79): the agents follow the site, the
    source site needs the write scope, and the destination client needs no grant (Tactical checks only Edit sites on the source).
    The last site of a client cannot leave (400). A missing destination client is a 400. A name already used in the destination
    client is a 409. A ``client_id`` equal to the current one is a no-op, after the same write-scope check as any update.
    """
    user = _authorize_write(context, "site")
    resource_id = _clean_positive_int(site_id, "site_id")
    policy_given = (workstation_policy_id, server_policy_id, block_policy_inheritance)
    if name is None and client_id in (None, "") and alert_template_id is UNSET and all(value is UNSET for value in policy_given):
        raise ResourceValidationError("At least one of name, client_id, alert_template_id, workstation_policy_id, server_policy_id or block_policy_inheritance is required.")
    clean_name = _clean_resource_name(name, "Site") if name is not None else None
    target_client_id = _clean_positive_int(client_id, "client_id") if client_id not in (None, "") else None
    changes: dict[str, Any] = {}
    if alert_template_id is not UNSET:
        changes["alert_template_id"] = _clean_alert_template_id(alert_template_id)
    changes.update(_policy_changes(workstation_policy_id=workstation_policy_id, server_policy_id=server_policy_id, block_policy_inheritance=block_policy_inheritance))
    before = adapter.get_site_row(adapter.sites_queryset(user=user, trusted=False), resource_id)
    if not adapter.site_write_in_scope(user=user, site_id=resource_id):
        # Checked before the same-client return below, so a read-only scope gets the same refusal as every other write (1.17.25).
        raise ResourceNotFound("Site was not found in the caller's resource scope.")
    if target_client_id is not None and before is not None and target_client_id == before["client_id"]:
        # The site is already in that client: not a move, so no client change.
        target_client_id = None
        if clean_name is None and not changes:
            return adapter.live_sites([before])[0] if before is not None else before
    moving = target_client_id is not None and before is not None
    with _transaction_atomic():
        agents_moved = adapter.site_agent_count(site_id=resource_id) if moving else 0
        row = _adapter_write(
            adapter.update_site_row,
            user=user,
            site_id=resource_id,
            name=clean_name,
            client_id=target_client_id,
            **changes,
        )
        if row is None:
            raise ResourceNotFound("Site was not found in the caller's resource scope.")
        if before is not None and _audit_view(before) == _audit_view(row):
            # Nothing changed (the same values were sent again): no audit row.
            return adapter.live_sites([row])[0]
        client_changed = before is not None and before.get("client_id") != row.get("client_id")
        metadata: dict[str, Any] = {
            "alert_template_changed": "alert_template_id" in changes and _template_changed(before, row),
        }
        if client_changed:
            # A move says what moved: ids and a count only, never a name. The keys are absent when the client did not change.
            metadata.update({"client_changed": True, "from_client_id": before["client_id"], "to_client_id": row["client_id"], "agents_moved": int(agents_moved)})
        if any(key in changes for key in POLICY_FIELDS):
            metadata["policy_changed"] = _policy_changed(before, row)
        _record_resource_change(
            actor=user, action="modify", resource_type="site", resource_id=resource_id,
            before=_audit_view(before), after=_audit_view(row), metadata=metadata,
        )
        return adapter.live_sites([row])[0]



def delete_site(site_id: Any, *, move_to_site_id: Any | None = None, context: ResourceAccessContext) -> dict[str, Any]:
    user = _authorize_write(context, "site")
    resource_id = _clean_positive_int(site_id, "site_id")
    destination_id = _clean_positive_int(move_to_site_id, "move_to_site_id") if move_to_site_id not in (None, "") else None
    before = adapter.get_site_row(adapter.sites_queryset(user=user, trusted=False), resource_id)
    if before is None:
        raise ResourceNotFound("Site was not found in the caller's resource scope.")
    with _transaction_atomic():
        result = _adapter_write(
            adapter.delete_site_row,
            user=user,
            site_id=resource_id,
            move_to_site_id=destination_id,
        )
        if result is None:
            raise ResourceNotFound("Site was not found in the caller's resource scope.")
        _record_resource_change(
            actor=user,
            action="delete",
            resource_type="site",
            resource_id=resource_id,
            before=_audit_view(before),
            after=None,
            metadata={
                "moved_agents": int(result.get("moved_agents") or 0),
                "destination_site": _audit_view(result.get("destination")),
            },
        )
        return result


def delete_client(client_id: Any, *, move_to_site_id: Any | None = None, context: ResourceAccessContext) -> dict[str, Any]:
    user = _authorize_write(context, "client")
    resource_id = _clean_positive_int(client_id, "client_id")
    destination_id = _clean_positive_int(move_to_site_id, "move_to_site_id") if move_to_site_id not in (None, "") else None
    before = adapter.get_client_row(adapter.clients_queryset(user=user, trusted=False), resource_id)
    if before is None:
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    with _transaction_atomic():
        result = _adapter_write(
            adapter.delete_client_row,
            user=user,
            client_id=resource_id,
            move_to_site_id=destination_id,
        )
        if result is None:
            raise ResourceNotFound("Client was not found in the caller's resource scope.")
        _record_resource_change(
            actor=user,
            action="delete",
            resource_type="client",
            resource_id=resource_id,
            before=before,
            after=None,
            metadata={
                "moved_agents": int(result.get("moved_agents") or 0),
                "destination_site": _audit_view(result.get("destination")),
            },
        )
        return result


def list_custom_fields(resource_type: str, resource_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    resource_type = str(resource_type or "").strip().lower()
    if resource_type not in ("client", "site"):
        raise ResourceValidationError("Custom fields are supported only for clients and sites.")
    user = _authorize_write(context, resource_type)
    clean_id = _clean_positive_int(resource_id, f"{resource_type}_id")
    rows = _adapter_write(
        adapter.custom_field_rows,
        user=user,
        resource_type=resource_type,
        resource_id=clean_id,
    )
    if rows is None:
        raise ResourceNotFound(f"{resource_type.title()} was not found in the caller's resource scope.")
    return {"resource_type": resource_type, "resource_id": clean_id, "fields": rows}


def list_custom_field_definitions(resource_type: str, *, context: ResourceAccessContext) -> dict[str, Any]:
    """The non-hidden custom-field definitions for a new client or site, with each field's default as ``value`` (1.6.0, Core 1.17.23).

    Returns ``{resource_type, fields: [{field_id, name, type, options, required, value}]}`` in the same order and shape as
    ``list_custom_fields``. It serves the Add client and Add site forms, which need the fields before the object exists. No
    per-client data is read, so there is nothing to scope. Gate: the one the create it serves needs (Tactical can_manage_clients or
    can_manage_sites plus the Core permission; a superuser passes; a service context is refused). ``resource_type`` must be exactly
    ``client`` or ``site``."""
    if not isinstance(resource_type, str) or resource_type not in ("client", "site"):
        raise ResourceValidationError("resource_type must be client or site.")
    _authorize_write(context, resource_type)
    rows = _adapter_write(adapter.custom_field_definition_rows, resource_type=resource_type)
    return {"resource_type": resource_type, "fields": rows}


def update_custom_fields(resource_type: str, resource_id: Any, *, values: list[dict[str, Any]], context: ResourceAccessContext) -> dict[str, Any]:
    resource_type = str(resource_type or "").strip().lower()
    if resource_type not in ("client", "site"):
        raise ResourceValidationError("Custom fields are supported only for clients and sites.")
    user = _authorize_write(context, resource_type)
    clean_id = _clean_positive_int(resource_id, f"{resource_type}_id")
    if values is None:
        raise ResourceValidationError("values must be an array.")
    values = _clean_custom_fields(values)  # 1.17.23: ids are whole numbers before anything is read or saved
    before = _adapter_write(
        adapter.custom_field_rows,
        user=user,
        resource_type=resource_type,
        resource_id=clean_id,
    )
    if before is None:
        raise ResourceNotFound(f"{resource_type.title()} was not found in the caller's resource scope.")
    with _transaction_atomic():
        rows = _adapter_write(
            adapter.update_custom_field_rows,
            user=user,
            resource_type=resource_type,
            resource_id=clean_id,
            values=values,
        )
        if rows is None:
            raise ResourceNotFound(f"{resource_type.title()} was not found in the caller's resource scope.")
        field_ids = _custom_field_ids(values)
        _record_resource_change(
            actor=user,
            action="modify",
            resource_type=resource_type,
            resource_id=clean_id,
            before={"custom_field_ids": field_ids},
            after={"custom_field_ids": field_ids},
            metadata={"custom_fields_updated": field_ids, "values_redacted": True},
        )
        return {"resource_type": resource_type, "resource_id": clean_id, "fields": rows}


def _scope_subject(context: ResourceAccessContext):
    """The user a scope question is about, or None for a trusted global service context. A service context that is not global,
    a missing user and a context of the wrong type are refused, the way every other operation refuses them."""
    if not isinstance(context, ResourceAccessContext):
        raise ResourcePermissionDenied("A ResourceAccessContext is required.")
    if context.is_service:
        if not context.trusted_global:
            raise ResourcePermissionDenied("Service context is not authorized for global resource access.")
        return None
    user = context.user
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise ResourcePermissionDenied("An authenticated Tactical user is required.")
    return user


def scope_descriptor(*, context: ResourceAccessContext) -> dict[str, Any]:
    """The caller's Tactical client and site scope, described once (1.4.0): ``{mode, unrestricted, whole_client_ids, site_ids,
    whole_client_count, site_count}``. ``mode`` is ``unrestricted``, ``clients``, ``sites``, ``mixed`` or ``none``. Modules read
    this instead of Tactical's Role. A scope question only: it needs no ``can_list_*`` flag. A trusted global service context is
    unrestricted. No role, an installer user and any lookup failure give mode ``none`` (fail closed)."""
    user = _scope_subject(context)
    if user is None:
        return {"mode": "unrestricted", "unrestricted": True, "whole_client_ids": [], "site_ids": [], "whole_client_count": 0, "site_count": 0}
    return adapter.role_scope_descriptor(user)


def scope_unrestricted(context: ResourceAccessContext) -> bool:
    """True when the caller sees every client and site (a superuser, a role superuser, a role with no client or site limits, or a
    trusted global service context). Same rule as ``scope_descriptor(context=...)["unrestricted"]``."""
    return bool(scope_descriptor(context=context)["unrestricted"])


def has_whole_client_access(client_id: Any, *, context: ResourceAccessContext) -> bool:
    """True only for an unrestricted caller, or a role that lists this client in ``can_view_clients``, and only when the client
    exists. A site-only role never holds the whole client, not even the client that owns its site. A scope question only (it needs
    no ``can_list_clients``, like Scheduler targets). No role, an installer user and a failed lookup give False. A malformed
    ``client_id`` raises ``ResourceValidationError``. A trusted global service context has whole access to every existing client."""
    user = _scope_subject(context)
    resource_id = _clean_positive_int(client_id, "client_id")
    try:
        if user is None:
            return resource_id in adapter.existing_client_ids([resource_id])
        if bool(getattr(user, "is_installer_user", False)):
            return False
        role = _role(user)
        if role is None and not bool(getattr(user, "is_superuser", False)):
            return False
        return resource_id in adapter.explicit_client_target_ids_in_scope(user=user, client_ids=[resource_id])
    except Exception:
        return False


def resolve_resource(resource_type: str, resource_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    resource_type = str(resource_type or "").strip().lower()
    if resource_type == "client":
        return get_client(resource_id, context=context)
    if resource_type == "site":
        return get_site(resource_id, context=context)
    if resource_type == "agent":
        return get_agent(resource_id, context=context)
    raise ResourceValidationError(f"Unsupported resource type: {resource_type!r}.")


def resource_contract_metadata() -> dict[str, Any]:
    return {
        "id": CONTRACT_ID,
        "version": CONTRACT_VERSION,
        "namespace": "tec_tac.resources",
        "read_only": False,
        "write_support": {
            "client": ["create", "update", "delete", "custom_fields"], "site": ["create", "update", "delete", "custom_fields"], "agent": [],
            # 1.4.0: what update_client and update_site accept (alert_template_id since 1.4.0, an id or null)
            # 1.7.0: the policy fields (ids and the inheritance flag) join both lists
            "update_fields": {
                "client": ["name", "alert_template_id", "workstation_policy_id", "server_policy_id", "block_policy_inheritance"],
                "site": ["name", "client_id", "alert_template_id", "workstation_policy_id", "server_policy_id", "block_policy_inheritance"],
            },
        },
        "resource_types": {
            "client": {"id_type": "integer", "fields": list(CLIENT_FIELDS), "filters": ["search", "active", "alert_template_id", "policy_id", "page", "page_size"]},
            "site": {"id_type": "integer", "fields": list(SITE_FIELDS), "filters": ["client_id", "search", "active", "alert_template_id", "policy_id", "page", "page_size"]},
            "agent": {"id_type": "string", "fields": list(AGENT_FIELDS), "filters": ["client_id", "site_id", "search", "active", "page", "page_size"]},
        },
        "operations": ["list_clients", "get_client", "create_client", "update_client", "delete_client", "list_sites", "get_site", "create_site", "update_site", "delete_site", "list_custom_fields", "update_custom_fields", "list_agents", "get_agent", "resolve_resource", "scope_descriptor", "scope_unrestricted", "has_whole_client_access", "list_custom_field_definitions"],
        "context_properties": ["ResourceAccessContext.scope"],
        "pagination": {
            "default_page_size": DEFAULT_PAGE_SIZE,
            "maximum_page_size": MAX_PAGE_SIZE,
            "maximum_page_number": MAX_PAGE_NUMBER,
        },
        "list_contracts": {
            "clients": {
                "python": "list_clients",
                "http": "GET /api/tfd/resources/clients/",
                "query": {"search": "optional string", "active": "optional boolean", "alert_template_id": "optional positive integer (1.7.0): only clients using that alert template", "policy_id": "optional positive integer (1.7.0): only clients whose workstation or server policy is that policy", "page": f"integer 1..{MAX_PAGE_NUMBER}", "page_size": f"integer 1..{MAX_PAGE_SIZE}"},
                "response": {"items": "array[client]", "count": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
            },
            "sites": {
                "python": "list_sites",
                "http": "GET /api/tfd/resources/sites/",
                "query": {"client_id": "optional positive integer", "search": "optional string", "active": "optional boolean", "alert_template_id": "optional positive integer (1.7.0): only sites using that alert template", "policy_id": "optional positive integer (1.7.0): only sites whose workstation or server policy is that policy", "page": f"integer 1..{MAX_PAGE_NUMBER}", "page_size": f"integer 1..{MAX_PAGE_SIZE}"},
                "response": {"items": "array[site]", "count": "integer", "page": "integer", "page_size": "integer", "pages": "integer", "next_page": "integer|null", "previous_page": "integer|null"},
            },
        },
        "mutation_contracts": {
            "create_client": {
                "python": "create_client(*, name, context, site_name=None, custom_fields=None)",
                "http": "POST /api/tfd/resources/clients/",
                "body": {"name": "required string, no | character", "site_name": "the first site's name; send it from every new form (omitting it names the site 'Default Site', deprecated)", "custom_fields": "optional array[{field_id, value}] saved in the same transaction"},
                "semantics": "Since 1.5.0 (site_name and custom_fields; Tactical's Add client). The client, its first site and the custom fields are created in one transaction with a strict audit row (metadata first_site_id, role_scope_extended 'clients' or 'none', custom_field_ids as ids only, default_site_created). As Tactical does, the new client joins the creator's can_view_clients only when that list is not empty: a role limited only by sites is not widened. The record returned carries sites with the first site, and the live keys of 1.10.0. Names may not contain the | character.",
            },
            "create_site": {
                "python": "create_site(*, client_id, name, context, custom_fields=None)",
                "http": "POST /api/tfd/resources/sites/",
                "body": {"client_id": "required positive integer", "name": "required string, no | character", "custom_fields": "optional array[{field_id, value}] saved in the same transaction"},
                "semantics": "Since 1.5.0 (custom_fields). As Tactical does, the new site joins the creator's can_view_sites only when that list is not empty. Audit metadata role_scope_extended 'sites' or 'none' and custom_field_ids.",
            },
            "update_client": {
                "python": "update_client(client_id, *, name=None, alert_template_id=UNSET, workstation_policy_id=UNSET, server_policy_id=UNSET, block_policy_inheritance=UNSET, context)",
                "http": "PATCH /api/tfd/resources/clients/<id>/",
                "body": {
                    "name": "optional string",
                    "alert_template_id": "optional positive integer to set, or null to clear",
                    "workstation_policy_id": "optional positive integer to set, or null to clear (1.7.0)",
                    "server_policy_id": "optional positive integer to set, or null to clear (1.7.0)",
                    "block_policy_inheritance": "optional boolean, true or false only (1.7.0); 1, 0 and text are refused. At least one field is required",
                },
                "semantics": "Since 1.4.0 (alert_template_id) and 1.7.0 (the three policy fields). Core holds only the ids: Alerts owns the template list and Automation owns the policy list. An id must name an existing template or policy (Tactical's own foreign key decides) or the call fails with invalid_resource_request ('alert_template_id does not name an existing alert template.' or 'workstation_policy_id does not name an existing policy.'). Same write rule as a rename (Tactical can_manage_clients, the Core resources permission and a whole-client grant); can_manage_alerts and can_manage_automation_policies are not required, matching Tactical's own client PUT. The write goes through Tactical's model save, so its agent alert cache refresh and policy cache refresh run. The audit row carries before and after records and metadata alert_template_changed and, when a policy field was sent, policy_changed (the names of the fields whose value changed, ids only). A call that changes nothing writes no row.",
            },
            "update_site": {
                "python": "update_site(site_id, *, name=None, client_id=None, alert_template_id=UNSET, workstation_policy_id=UNSET, server_policy_id=UNSET, block_policy_inheritance=UNSET, context)",
                "http": "PATCH /api/tfd/resources/sites/<id>/",
                "body": {
                    "name": "optional string",
                    "client_id": "optional positive integer: move the site to that client (see Move a site)",
                    "alert_template_id": "optional positive integer to set, or null to clear",
                    "workstation_policy_id": "optional positive integer to set, or null to clear (1.7.0)",
                    "server_policy_id": "optional positive integer to set, or null to clear (1.7.0)",
                    "block_policy_inheritance": "optional boolean, true or false only (1.7.0). At least one field is required",
                },
                "semantics": "Since 1.4.0 (alert_template_id) and 1.7.0 (the three policy fields, as update_client). Same write rule as a rename (can_manage_sites, the Core resources permission, a site grant or a grant of the site's client). Audit metadata alert_template_changed, client_changed and, when a policy field was sent, policy_changed. A call that changes nothing writes no row.",
            },
            "move_site": {
                "python": "update_site(site_id, *, client_id=<destination>, ...)",
                "http": "PATCH /api/tfd/resources/sites/<id>/ with client_id (Tactical's Edit site)",
                "semantics": "Documented and tested in 1.7.0 (the mechanism is older); the destination rule follows Tactical since 1.8.0 (Core 1.17.25, CQ79). The agents follow their site. The source needs the site write grant (a site grant or a grant of its client), and a same-client update is refused the same way when the site is read-only in scope. The destination client needs no grant: Tactical's Edit site checks only the Edit sites permission, and Core does the same, so a limited role may move a site into a client it holds no grant on. A missing destination client is a 400 validation error. The last site of a client cannot move away (400, 'A client must retain at least one site.'). A name already used by a site of the destination client is 409 ('A site with that name already exists for the selected client.'). A client_id equal to the current one is a no-op: nothing is saved and no audit row is written. The write goes through Tactical's model save (update_fields client, modified_by, modified_time), so its Site.save hooks run. The strict audit row carries before and after records (client_id) and metadata client_changed true, from_client_id, to_client_id and agents_moved (ids and a count only, never a name). A move together with a rename or another field is one row.",
            },
            "scope_descriptor": {
                "python": ["scope_descriptor(*, context)", "scope_unrestricted(context)", "has_whole_client_access(client_id, *, context)", "ResourceAccessContext.scope"],
                "http": "GET /api/tfd/ui/context/ carries tactical_scope: {mode, unrestricted, whole_client_count, site_count} (counts, never id lists)",
                "response": {
                    "mode": "unrestricted | clients | sites | mixed | none",
                    "unrestricted": "boolean",
                    "whole_client_ids": "array[integer], the explicit can_view_clients grants (Python only)",
                    "site_ids": "array[integer], the explicit can_view_sites grants only, not the sites of a granted client (Python only)",
                    "whole_client_count": "integer",
                    "site_count": "integer",
                },
                "semantics": "Since 1.4.0. One description of the caller's Tactical client and site scope, so no module reads Tactical's Role. unrestricted is a superuser, a role superuser, or a role with both relations empty. A site-only role is mode sites and never holds a whole client. No role, an installer user and any lookup failure give mode none. A trusted global service context is unrestricted. A scope question only: no can_list_* flag is needed.",
            },
            "delete_client": {
                "python": "delete_client",
                "http": "DELETE /api/tfd/resources/clients/<id>/",
                "body": {"move_to_site_id": "optional positive integer; required when agents exist"},
                "semantics": "Move all agents atomically to a writable site outside the deleted client, then hard-delete the client.",
            },
            "delete_site": {
                "python": "delete_site",
                "http": "DELETE /api/tfd/resources/sites/<id>/",
                "body": {"move_to_site_id": "optional positive integer; required when agents exist"},
                "semantics": "Move all agents atomically to another writable site under the same client, then hard-delete the site; the last site cannot be deleted.",
            },
            "custom_field_definitions": {
                "python": "list_custom_field_definitions(resource_type, *, context)",
                "http": "GET /api/tfd/resources/custom-fields/?resource_type=client|site",
                "response": {"resource_type": "client|site", "fields": "array[{field_id,name,type,options,required,value}] where value is the field's default"},
                "semantics": "Since 1.6.0 (Core 1.17.23). The non-hidden definitions for a new client or site, so Add client and Add site can show the fields before the create. Same order and shape as the id read. No per-client data is read, so nothing is scoped. Gate: the create's own (Tactical can_manage_clients or can_manage_sites plus the Core permission; a superuser passes; a service context is refused). resource_type missing or not exactly client or site is 400, as is any other query name.",
            },
            "client_custom_fields": {
                "python": ["list_custom_fields", "update_custom_fields"],
                "http": "GET|PATCH /api/tfd/resources/clients/<id>/custom-fields/",
                "response": {"resource_type": "client", "resource_id": "integer", "fields": "array[{field_id,name,type,options,required,value}]"},
            },
            "site_custom_fields": {
                "python": ["list_custom_fields", "update_custom_fields"],
                "http": "GET|PATCH /api/tfd/resources/sites/<id>/custom-fields/",
                "response": {"resource_type": "site", "resource_id": "integer", "fields": "array[{field_id,name,type,options,required,value}]"},
            },
        },
        "custom_field_types": ["text", "number", "single", "multiple", "checkbox", "datetime"],
        "errors": {
            ResourceValidationError.code: "Invalid type, identifier, filter or pagination input.",
            ResourcePermissionDenied.code: "Caller lacks Tactical read permission/scope or a trusted service context.",
            ResourceNotFound.code: "Resource does not exist or is outside the caller's visible scope.",
            ResourceConflict.code: "Requested resource name conflicts with an existing Tactical resource.",
        },
        "authorization": {
            "interactive": "Authenticated Tactical user + can_list_<resource> + Tactical filter_by_role scope.",
            "service": "Explicit trusted_service_context(..., global_access=True) for reads only; service contexts cannot mutate resources in contract 1.x. Since 1.9.0 (Core 1.17.30, AD-34 condition 1) trusted_service_context(actor, purpose, global_access=False) is available to the module userinvite only, when the actor names that module and Core verifies the caller from the call stack: the context has no resource visibility (every list, get and write is refused) and writes no audit row. Every other caller is refused.",
            "write": "Authenticated Tactical user + Tactical can_manage_clients/can_manage_sites + Tec-Tac Core resource-manage RBAC permission + Tactical native object write scope (_has_perm_on_client/_has_perm_on_site semantics).",
        },
        "active_semantics": "Tactical hard-deletes client/site rows. Core deletion first relocates agents when required, then deletes atomically. Existing rows are active in contract v1; active=false returns no rows.",
        "rbac": {"client_write": CLIENT_MANAGE_PERMISSION, "site_write": SITE_MANAGE_PERMISSION},
        "client_sites": "Since 1.5.0 client records carry sites: the site records of that client inside the caller's scope (the same Site.filter_by_role rule as the sites read), ordered by name then id, with the shape of list_sites records, loaded with one query per page. It needs only can_list_clients, as Tactical's GET /clients/ does. A client-limited role gets every site of its clients plus granted sites, a site-only role only its granted sites, an unrestricted caller and a trusted global context every site. A client with no site in scope has an empty list. Create and update results carry it too. Audit before and after rows are built without sites, client_name and the 1.10.0 live keys.",
        "site_client_name": "Since 1.5.0 site records carry client_name (the owning client's name, as Tactical's /clients/sites/ returns it), appended after the earlier keys, so a role with only can_list_sites can group sites by client without reading clients.",
        "role_reads": "Clients read: can_list_clients (200 with nested sites; the sites read stays refused without can_list_sites). Sites read: can_list_sites (each site carries client_id and client_name; the clients read stays refused without can_list_clients). A role with neither flag is refused both reads. Writes still need can_manage_clients or can_manage_sites plus the Core codenames.",
        "role_scope_lists": {
            "route": "GET|POST /accounts/roles/ and GET|PUT|DELETE /accounts/roles/<id>/ (Tactical's own role routes; Core adds no route)",
            "fields": "can_view_clients and can_view_sites, each a list of ids",
            "semantics": "Since 1.17.22. An empty pair means unrestricted. A role with only can_view_sites is site mode. PUT replaces both lists, so an editor that cannot see every id (a limited editor sees only its own clients and sites) must send back the ids it loaded and could not show. Pickers read clients with nested sites from this Resource Directory (List clients is enough). Core writes one strict audit row (module core, object_type role_scope, object_id the role id) with before and after as sorted id lists (capped at 1000, with counts and a truncated flag), only when a list changed. Core does not change who may edit role lists.",
        },
        "alert_template_id": "Since 1.4.0 client and site records carry alert_template_id (integer or null), appended after the earlier keys. It is an id only. Anyone who can list clients or sites sees it.",
        "policy_fields": "Since 1.7.0 client and site records carry workstation_policy_id (integer or null), server_policy_id (integer or null) and block_policy_inheritance (boolean, false when unset), appended after the earlier keys (after sites on a client, after client_name on a site; nested sites carry them too). They are ids and a flag only: Automation owns the policy list and Core validates nothing about it. Anyone who can list clients or sites sees them. A record built from a row without the keys reads null, null and false.",
        "failing_checks_agent_count_maintenance_mode": "Since 1.10.0 (Core 1.17.40) client and site records carry three read-only keys, appended last (after block_policy_inheritance; nested sites and the records returned by create_client, update_client, create_site and update_site carry them too; agent records never do). failing_checks is {error: boolean, warning: boolean}: Tactical's stored value on the client or site as its own GET /clients/ returns it (null, a non-object or a non-boolean reads false). agent_count is an integer and maintenance_mode a boolean (true when any agent is in maintenance mode). Anyone who can list clients or sites sees them, as Tactical's GET /clients/ gives them to a role with List clients alone; no List agents flag is needed. Read only: no write field changes them.",
        "live_state": "Scope rule for 1.10.0 (AD-12, a role sees counts only for what it may see). A site record is computed from its own agents only. A client record is computed only from the sites the caller may see (the same Site.filter_by_role rule as the nested sites): agent_count is the sum over those sites, maintenance_mode is true when any of them has an agent in maintenance mode, and failing_checks is Tactical's stored client value only when the caller sees every site of the client (an unrestricted caller and a trusted global context always do), otherwise the OR of the visible sites' stored values, so a role never learns that a hidden site is failing or how many agents it has. A client with no visible site reads 0, false and both false. The values are as of Tactical's last refresh: Tactical updates failing_checks only in its periodic cache task, so treat it as a hint and not a live check. agent_count and maintenance_mode are read at call time. Core runs a constant number of queries per page. The audit before and after rows never carry these keys.",
        "list_filters_1_7": "Since 1.7.0 list_clients and list_sites take alert_template_id and policy_id (the workstation or the server policy), each a positive integer or 400, applied inside the caller's scope and under the list's own permission. Both together mean both must match. Alerts uses alert_template_id to find where a template is used, and Automation uses policy_id to build the policy overview without reading every page.",
        "compatibility": "Additive changes are preferred within 1.x. Tactical ORM changes are adapter-internal unless the public representation changes incompatibly.",
    }


class _CoreResourceProvider:
    list_clients = staticmethod(list_clients)
    get_client = staticmethod(get_client)
    create_client = staticmethod(create_client)
    update_client = staticmethod(update_client)
    delete_client = staticmethod(delete_client)
    list_sites = staticmethod(list_sites)
    get_site = staticmethod(get_site)
    create_site = staticmethod(create_site)
    update_site = staticmethod(update_site)
    delete_site = staticmethod(delete_site)
    list_custom_fields = staticmethod(list_custom_fields)
    list_custom_field_definitions = staticmethod(list_custom_field_definitions)
    update_custom_fields = staticmethod(update_custom_fields)
    list_agents = staticmethod(list_agents)
    get_agent = staticmethod(get_agent)
    resolve_resource = staticmethod(resolve_resource)
    scope_descriptor = staticmethod(scope_descriptor)
    scope_unrestricted = staticmethod(scope_unrestricted)
    has_whole_client_access = staticmethod(has_whole_client_access)
    user_context = staticmethod(user_context)
    trusted_service_context = staticmethod(trusted_service_context)


_RESOURCE_PROVIDER = _CoreResourceProvider()


def register_core_resources_capability():
    return register_capability(
        id=CONTRACT_ID,
        module_id="core",
        version=CONTRACT_VERSION,
        provider=_RESOURCE_PROVIDER,
        description="Stable Core directory for Tactical clients, sites and agents with scoped client/site management.",
        operations=(
            "list_clients", "get_client", "create_client", "update_client", "delete_client",
            "list_sites", "get_site", "create_site", "update_site", "delete_site",
            "list_custom_fields", "update_custom_fields",
            "list_agents", "get_agent", "resolve_resource",
            "scope_descriptor", "scope_unrestricted", "has_whole_client_access",
            "user_context", "trusted_service_context", "list_custom_field_definitions",
        ),
        metadata=resource_contract_metadata(),
    )
