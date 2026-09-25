# Core Resource Directory

Contract ID: `core.resources`  
Contract version: `1.1.0`  
Python namespace: `tec_tac.resources`

## Purpose

Tactical owns managed clients, sites and agents. Tec-Tac Core owns the stable public representation and supported mutation boundary for those resources. Feature modules consume the Core contract and must not import Tactical resource models directly.

```text
Tactical Client / Site / Agent ORM
        |
        v
tec_tac.resources_adapter   <- Core compatibility boundary
        |
        v
tec_tac.resources           <- stable public contract
        |
        +-- Governance
        +-- Customers
        +-- Licensing
        +-- Reporting
        +-- Alerts / Automation / other modules
```

Contract 1.1 remains read-oriented for all three resource types and adds narrowly scoped create/update support for clients and sites. Agent mutation and resource deletion are not part of this version.

## Stable resource records

### Client

```json
{
  "type": "client",
  "id": 123,
  "name": "North West Radiology",
  "active": true
}
```

Stable fields: `type`, `id`, `name`, `active`.

### Site

```json
{
  "type": "site",
  "id": 456,
  "name": "Potch Mediclinic",
  "client_id": 123,
  "active": true
}
```

Stable fields: `type`, `id`, `name`, `client_id`, `active`.

### Agent

```json
{
  "type": "agent",
  "id": "agent-stable-id",
  "hostname": "NWR-AL-REP04",
  "client_id": 123,
  "site_id": 456,
  "active": true,
  "platform": "windows",
  "monitoring_type": "workstation",
  "last_seen": "2026-09-25T17:00:00+00:00"
}
```

Stable fields: `type`, `id`, `hostname`, `client_id`, `site_id`, `active`, `platform`, `monitoring_type`, `last_seen`.

The public agent `id` is Tactical's stable `agent_id`, not Tactical's Django primary key.

Tactical currently hard-deletes Client, Site and Agent rows and has no shared soft-disabled state for these objects. Contract `1.x` therefore treats an existing row as `active=true`; `active=false` returns no rows. Online/offline agent state is deliberately not represented by `active`.

## Python operations

Every Python call requires an explicit `ResourceAccessContext`.

Interactive/request-backed code:

```python
from tec_tac.resources import user_context, list_sites

ctx = user_context(request.user)
page = list_sites(context=ctx, client_id=123, page=1, page_size=100)
```

Trusted unattended backend code may declare global read authority:

```python
from tec_tac.resources import trusted_service_context, list_agents

ctx = trusted_service_context(
    actor="governance",
    purpose="scheduled compliance evidence collection",
    global_access=True,
)
page = list_agents(context=ctx, page=1, page_size=100)
```

There is no implicit service/global access when the user is absent. Trusted service contexts are read-only in contract 1.x and cannot call create/update operations.

### Read operations

- `list_clients(context=..., search=None, active=None, page=1, page_size=100)`
- `get_client(client_id, context=...)`
- `list_sites(context=..., client_id=None, search=None, active=None, page=1, page_size=100)`
- `get_site(site_id, context=...)`
- `list_agents(context=..., client_id=None, site_id=None, search=None, active=None, page=1, page_size=100)`
- `get_agent(agent_id, context=...)`
- `resolve_resource(resource_type, resource_id, context=...)`
- `user_context(user)`
- `trusted_service_context(actor=..., purpose=..., global_access=True)`

### Client/site write operations

- `create_client(name=..., context=...)`
- `update_client(client_id, name=..., context=...)`
- `create_site(client_id=..., name=..., context=...)`
- `update_site(site_id, name=None, client_id=None, context=...)`

The write operations return the same stable client/site record shapes as the read contract. Core never returns Tactical ORM instances.

List operations return:

```json
{
  "items": [],
  "count": 0,
  "page": 1,
  "page_size": 100,
  "pages": 0,
  "next_page": null,
  "previous_page": null
}
```

`page_size` is limited to 500.

## Authorization

### Reads

Interactive calls retain the accepted 1.0 authorization model:

1. the corresponding Tactical permission (`can_list_clients`, `can_list_sites`, or `can_list_agents`); and
2. Tactical's native `filter_by_role(user)` queryset scope.

A site-limited user therefore cannot enumerate agents/sites outside that Tactical role scope. Out-of-scope detail lookups return the same `resource_not_found` result as a missing resource so the contract does not become an enumeration oracle.

No new Tec-Tac RBAC grant was added to existing read operations in 1.1, avoiding a breaking authorization change for 1.0 consumers.

### Writes

Client/site mutation requires both Tactical authority and Tec-Tac Core RBAC:

| Operation | Tactical permission | Tec-Tac RBAC |
| --- | --- | --- |
| `create_client`, `update_client` | `can_manage_clients` | `core.resources.clients.manage` |
| `create_site`, `update_site` | `can_manage_sites` | `core.resources.sites.manage` |

Effective superusers retain the normal override behavior.

Updates are write-scope constrained using Tactical's native object-permission semantics, not the broader read-only `filter_by_role()` visibility. Client write targets and site destination clients must pass Tactical's `_has_perm_on_client` semantics; site write targets must pass `_has_perm_on_site` semantics. This distinction is intentional because client read visibility can include the parent client of an explicitly visible site, while Tactical does not grant that transitive relationship as client write authority. This prevents a write permission from becoming a scope bypass.

Creating a new client has no pre-existing resource against which to apply scope; it therefore requires the two manage permissions above and creates a new top-level resource.

Trusted service contexts cannot mutate resources in contract 1.x. A future unattended write mechanism must establish explicit non-self-asserted service authority rather than reusing global read authority.

## Core RBAC groups

Core publishes assignable permissions through the normal Tec-Tac Access/RBAC catalogue:

- **Client resource management** -> `core.resources.clients.manage`
- **Site resource management** -> `core.resources.sites.manage`

The permissions are enforced in the Python contract itself and therefore cannot be bypassed by a backend module calling `tec_tac.resources` directly instead of using HTTP.

## HTTP representation

Authenticated browser/external callers can use:

- `GET/POST /api/tfd/resources/clients/`
- `GET/PATCH /api/tfd/resources/clients/<id>/`
- `GET/POST /api/tfd/resources/sites/`
- `GET/PATCH /api/tfd/resources/sites/<id>/`
- `GET /api/tfd/resources/agents/`
- `GET /api/tfd/resources/agents/<agent_id>/`

Read query parameters mirror the Python filters. HTTP always derives a user context from the authenticated Tactical/Tec-Tac session; it cannot create trusted service contexts.

Create payloads:

```json
{"name": "Client name"}
```

```json
{"client_id": 123, "name": "Site name"}
```

Update payloads accept only writable fields. Unknown fields are rejected. Agent HTTP resources remain read-only.

## Errors

Python errors are typed:

- `ResourceValidationError` / `invalid_resource_request`
- `ResourcePermissionDenied` / `resource_permission_denied`
- `ResourceNotFound` / `resource_not_found`
- `ResourceConflict` / `resource_conflict`

HTTP maps those to 400, 403, 404 and 409 respectively.

## Tactical adapter boundary

`tec_tac.resources_adapter` is the only part of this public subsystem that knows current Tactical model names, field names, relationships and mutation mechanics. Consumers must not import the adapter or Tactical Client/Site/Agent models.

If Tactical later changes model/table/field layout, update the Core adapter while preserving the `core.resources` representation wherever practical.

## Versioning

`core.resources` follows semantic contract versioning.

Contract `1.1.0` is additive over `1.0.0`: it preserves all read operations and resource shapes while adding client/site create/update operations, write authorization metadata and stable conflict errors. A Tactical internal schema change alone is not a reason to change this contract version.
