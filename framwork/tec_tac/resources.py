"""Stable Core Resource Directory public contract.

Tactical owns the underlying Client/Site/Agent resources.  Core owns the
Tec-Tac representation and authorization boundary.  Feature modules consume
this module and must not depend on Tactical ORM implementation details.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import resources_adapter as adapter
from .capabilities import register_capability

CONTRACT_ID = "core.resources"
CONTRACT_VERSION = "1.1.0"
RESOURCE_TYPES = ("client", "site", "agent")
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
CLIENT_MANAGE_PERMISSION = "core.resources.clients.manage"
SITE_MANAGE_PERMISSION = "core.resources.sites.manage"

CLIENT_FIELDS = ("type", "id", "name", "active")
SITE_FIELDS = ("type", "id", "name", "client_id", "active")
AGENT_FIELDS = (
    "type", "id", "hostname", "client_id", "site_id", "active",
    "platform", "monitoring_type", "last_seen",
)


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


def user_context(user) -> ResourceAccessContext:
    if user is None or not bool(getattr(user, "is_authenticated", False)):
        raise ResourcePermissionDenied("An authenticated Tactical user is required.")
    return ResourceAccessContext(user=user)


def trusted_service_context(*, actor: str, purpose: str, global_access: bool = False) -> ResourceAccessContext:
    """Create an explicit non-interactive trusted execution context.

    Global resource visibility is deliberately opt-in.  This context is for
    trusted in-process Core/module automation only; browser callers never use it.
    """
    actor = str(actor or "").strip()
    purpose = str(purpose or "").strip()
    if not actor or not purpose:
        raise ResourceValidationError("Trusted service contexts require actor and purpose.")
    if not global_access:
        raise ResourcePermissionDenied("Trusted service resource access requires explicit global_access=True in contract v1.")
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


def _adapter_write(callable_obj, **kwargs):
    try:
        return callable_obj(**kwargs)
    except getattr(adapter, "TacticalResourceConflictError", adapter.TacticalResourceAdapterError) as exc:
        raise ResourceConflict(str(exc)) from exc


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


def _pagination(page: Any, page_size: Any) -> tuple[int, int, int]:
    page = _clean_positive_int(page, "page")
    page_size = _clean_positive_int(page_size, "page_size")
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


def list_clients(*, context: ResourceAccessContext, search: str | None = None, active: bool | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    user, trusted = _authorize(context, "client")
    page, page_size, offset = _pagination(page, page_size)
    qs = adapter.clients_queryset(user=user, trusted=trusted, search=_search(search), active=_active(active))
    items, total = adapter.page_clients(qs, offset=offset, limit=page_size)
    return _page(items, total, page, page_size)


def get_client(client_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    user, trusted = _authorize(context, "client")
    resource_id = _clean_positive_int(client_id, "client_id")
    row = adapter.get_client_row(adapter.clients_queryset(user=user, trusted=trusted), resource_id)
    if row is None:
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    return row


def list_sites(*, context: ResourceAccessContext, client_id: Any | None = None, search: str | None = None, active: bool | None = None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    user, trusted = _authorize(context, "site")
    page, page_size, offset = _pagination(page, page_size)
    client_id = _clean_positive_int(client_id, "client_id") if client_id not in (None, "") else None
    qs = adapter.sites_queryset(user=user, trusted=trusted, client_id=client_id, search=_search(search), active=_active(active))
    items, total = adapter.page_sites(qs, offset=offset, limit=page_size)
    return _page(items, total, page, page_size)


def get_site(site_id: Any, *, context: ResourceAccessContext) -> dict[str, Any]:
    user, trusted = _authorize(context, "site")
    resource_id = _clean_positive_int(site_id, "site_id")
    row = adapter.get_site_row(adapter.sites_queryset(user=user, trusted=trusted), resource_id)
    if row is None:
        raise ResourceNotFound("Site was not found in the caller's resource scope.")
    return row


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



def create_client(*, name: str, context: ResourceAccessContext) -> dict[str, Any]:
    _authorize_write(context, "client")
    return _adapter_write(adapter.create_client_row, name=_clean_name(name, "name"))


def update_client(client_id: Any, *, name: str, context: ResourceAccessContext) -> dict[str, Any]:
    user = _authorize_write(context, "client")
    resource_id = _clean_positive_int(client_id, "client_id")
    row = _adapter_write(
        adapter.update_client_row,
        user=user,
        client_id=resource_id,
        name=_clean_name(name, "name"),
    )
    if row is None:
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    return row


def create_site(*, client_id: Any, name: str, context: ResourceAccessContext) -> dict[str, Any]:
    user = _authorize_write(context, "site")
    target_client_id = _clean_positive_int(client_id, "client_id")
    if not adapter.client_write_in_scope(user=user, client_id=target_client_id):
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    return _adapter_write(
        adapter.create_site_row,
        client_id=target_client_id,
        name=_clean_name(name, "name"),
    )


def update_site(site_id: Any, *, name: str | None = None, client_id: Any | None = None, context: ResourceAccessContext) -> dict[str, Any]:
    user = _authorize_write(context, "site")
    resource_id = _clean_positive_int(site_id, "site_id")
    if name is None and client_id in (None, ""):
        raise ResourceValidationError("At least one of name or client_id is required.")
    clean_name = _clean_name(name, "name") if name is not None else None
    target_client_id = _clean_positive_int(client_id, "client_id") if client_id not in (None, "") else None
    if target_client_id is not None and not adapter.client_write_in_scope(user=user, client_id=target_client_id):
        raise ResourceNotFound("Client was not found in the caller's resource scope.")
    row = _adapter_write(
        adapter.update_site_row,
        user=user,
        site_id=resource_id,
        name=clean_name,
        client_id=target_client_id,
    )
    if row is None:
        raise ResourceNotFound("Site was not found in the caller's resource scope.")
    return row


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
        "write_support": {"client": ["create", "update"], "site": ["create", "update"], "agent": []},
        "resource_types": {
            "client": {"id_type": "integer", "fields": list(CLIENT_FIELDS), "filters": ["search", "active", "page", "page_size"]},
            "site": {"id_type": "integer", "fields": list(SITE_FIELDS), "filters": ["client_id", "search", "active", "page", "page_size"]},
            "agent": {"id_type": "string", "fields": list(AGENT_FIELDS), "filters": ["client_id", "site_id", "search", "active", "page", "page_size"]},
        },
        "operations": ["list_clients", "get_client", "create_client", "update_client", "list_sites", "get_site", "create_site", "update_site", "list_agents", "get_agent", "resolve_resource"],
        "pagination": {"default_page_size": DEFAULT_PAGE_SIZE, "maximum_page_size": MAX_PAGE_SIZE},
        "errors": {
            ResourceValidationError.code: "Invalid type, identifier, filter or pagination input.",
            ResourcePermissionDenied.code: "Caller lacks Tactical read permission/scope or a trusted service context.",
            ResourceNotFound.code: "Resource does not exist or is outside the caller's visible scope.",
            ResourceConflict.code: "Requested resource name conflicts with an existing Tactical resource.",
        },
        "authorization": {
            "interactive": "Authenticated Tactical user + can_list_<resource> + Tactical filter_by_role scope.",
            "service": "Explicit trusted_service_context(..., global_access=True) for reads only; service contexts cannot mutate resources in contract 1.x.",
            "write": "Authenticated Tactical user + Tactical can_manage_clients/can_manage_sites + Tec-Tac Core resource-manage RBAC permission + Tactical native object write scope (_has_perm_on_client/_has_perm_on_site semantics).",
        },
        "active_semantics": "Tactical currently hard-deletes client/site/agent rows; existing rows are active in contract v1. active=false returns no rows.",
        "rbac": {"client_write": CLIENT_MANAGE_PERMISSION, "site_write": SITE_MANAGE_PERMISSION},
        "compatibility": "Additive changes are preferred within 1.x. Tactical ORM changes are adapter-internal unless the public representation changes incompatibly.",
    }


class _CoreResourceProvider:
    list_clients = staticmethod(list_clients)
    get_client = staticmethod(get_client)
    create_client = staticmethod(create_client)
    update_client = staticmethod(update_client)
    list_sites = staticmethod(list_sites)
    get_site = staticmethod(get_site)
    create_site = staticmethod(create_site)
    update_site = staticmethod(update_site)
    list_agents = staticmethod(list_agents)
    get_agent = staticmethod(get_agent)
    resolve_resource = staticmethod(resolve_resource)
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
            "list_clients", "get_client", "create_client", "update_client",
            "list_sites", "get_site", "create_site", "update_site",
            "list_agents", "get_agent", "resolve_resource",
            "user_context", "trusted_service_context",
        ),
        metadata=resource_contract_metadata(),
    )
