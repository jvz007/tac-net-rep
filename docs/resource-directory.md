# Core Resource Directory

Contract ID: `core.resources`  
Contract version: `1.0.0`  
Python namespace: `tec_tac.resources`

## Purpose

Tactical owns managed clients, sites and agents. Tec-Tac Core owns the stable public representation of those resources. Feature modules consume the Core contract and must not import Tactical resource models directly.

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

The first contract version is read-only. It intentionally does not create, update or delete Tactical resources.

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

Tactical currently hard-deletes Client, Site and Agent rows and has no shared soft-disabled state for these objects. Contract `1.0.0` therefore treats an existing row as `active=true`; `active=false` returns no rows. Online/offline agent state is deliberately not represented by `active`.

## Python operations

Every Python call requires an explicit `ResourceAccessContext`.

Interactive/request-backed code:

```python
from tec_tac.resources import user_context, list_sites

ctx = user_context(request.user)
page = list_sites(context=ctx, client_id=123, page=1, page_size=100)
```

Trusted unattended backend code must declare that it is using global service authority:

```python
from tec_tac.resources import trusted_service_context, list_agents

ctx = trusted_service_context(
    actor="governance",
    purpose="scheduled compliance evidence collection",
    global_access=True,
)
page = list_agents(context=ctx, page=1, page_size=100)
```

There is no implicit service/global access when the user is absent.

Public operations:

- `list_clients(context=..., search=None, active=None, page=1, page_size=100)`
- `get_client(client_id, context=...)`
- `list_sites(context=..., client_id=None, search=None, active=None, page=1, page_size=100)`
- `get_site(site_id, context=...)`
- `list_agents(context=..., client_id=None, site_id=None, search=None, active=None, page=1, page_size=100)`
- `get_agent(agent_id, context=...)`
- `resolve_resource(resource_type, resource_id, context=...)`
- `user_context(user)`
- `trusted_service_context(actor=..., purpose=..., global_access=True)`

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

Interactive calls enforce both parts of Tactical's existing read authority:

1. the corresponding Tactical permission (`can_list_clients`, `can_list_sites`, or `can_list_agents`); and
2. Tactical's native `filter_by_role(user)` queryset scope.

A site-limited user therefore cannot enumerate agents/sites outside that Tactical role scope. Out-of-scope detail lookups return the same `resource_not_found` result as a missing resource so the contract does not become an enumeration oracle.

Service calls use an explicit `trusted_service_context`. Version 1 requires `global_access=True`; this is deliberately noisy so unattended module code cannot accidentally bypass interactive scope.

## HTTP representation

Authenticated browser/external callers can use:

- `GET /api/tfd/resources/clients/`
- `GET /api/tfd/resources/clients/<id>/`
- `GET /api/tfd/resources/sites/`
- `GET /api/tfd/resources/sites/<id>/`
- `GET /api/tfd/resources/agents/`
- `GET /api/tfd/resources/agents/<agent_id>/`

Supported query parameters mirror the Python filters. HTTP always derives a user context from the authenticated Tactical/Tec-Tac session; it cannot create trusted service contexts.

## Errors

Python errors are typed:

- `ResourceValidationError` / `invalid_resource_request`
- `ResourcePermissionDenied` / `resource_permission_denied`
- `ResourceNotFound` / `resource_not_found`

HTTP maps those to 400, 403 and 404 respectively.

## Tactical adapter boundary

`tec_tac.resources_adapter` is the only part of this public subsystem that knows current Tactical model names, field names and relationships. Consumers must not import the adapter or Tactical Client/Site/Agent models.

If Tactical later changes model/table/field layout, update the Core adapter while preserving the `core.resources` representation wherever practical.

## Versioning

`core.resources` follows semantic contract versioning.

Within major version `1`, prefer additive changes: additional optional fields, filters or resource types may be added without breaking existing callers. A Tactical internal schema change alone is not a reason to change this contract version.
