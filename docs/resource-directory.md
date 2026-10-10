# Core Resource Directory

Contract ID: `core.resources`  
Contract version: `1.4.0`  
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

Contract 1.4 (Core 1.17.17, additive, still major 1) adds `alert_template_id` to client and site records, lets `update_client` and `update_site` set or clear it, and adds the scope descriptor (`scope_descriptor`, `scope_unrestricted`, `has_whole_client_access`, `ResourceAccessContext.scope`, and `tactical_scope` in the runtime context). Existing callers keep working: the new record keys are appended after the old ones and every new keyword is optional.

Contract 1.3 keeps the 1.2 scoped read/create/update boundary and adds audited client/site deletion with atomic agent relocation plus client/site custom-field value editing. Agent mutation remains outside this contract. A new client is still created atomically with a `Default Site`, restricted creators are granted scope to the client they create, and clients retain at least one site.

## Stable resource records

### Client

```json
{
  "type": "client",
  "id": 123,
  "name": "North West Radiology",
  "active": true,
  "alert_template_id": 7
}
```

Stable fields: `type`, `id`, `name`, `active`, `alert_template_id` (since 1.4.0, an integer or `null`; appended after the earlier keys).

### Site

```json
{
  "type": "site",
  "id": 456,
  "name": "Potch Mediclinic",
  "client_id": 123,
  "active": true,
  "alert_template_id": null
}
```

Stable fields: `type`, `id`, `name`, `client_id`, `active`, `alert_template_id` (since 1.4.0, an integer or `null`).

`alert_template_id` is the id of the alert template Tactical assigns to the client or site, or `null` for none. It is an id only. Core does not import Alerts models and does not list templates: the Alerts module owns the template list and the picker. Anyone who can already list clients or sites sees the id.

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

### Scope operations (since 1.4.0, framework >=1.17.17)

Modules ask Core about the caller's Tactical client and site scope. They never read Tactical's Role.

- `scope_descriptor(context=...)` returns `{mode, unrestricted, whole_client_ids, site_ids, whole_client_count, site_count}`.
- `scope_unrestricted(context)` returns `True` when the caller sees every client and site.
- `has_whole_client_access(client_id, context=...)` returns `True` when the caller may act on the whole client.
- `context.scope` is the same descriptor as a read-only property of `ResourceAccessContext`. It is computed when you read it and never cached on the context.

`mode` is one of:

| mode | Meaning |
| --- | --- |
| `unrestricted` | A superuser, a role superuser, or a role whose `can_view_clients` and `can_view_sites` are both empty (Tactical's own rule). |
| `clients` | Only whole-client grants (`can_view_clients`). |
| `sites` | Only explicit site grants (`can_view_sites`). |
| `mixed` | Both. |
| `none` | No role, a Tactical installer user, or a lookup that failed. Core fails closed: `unrestricted` is `false`. |

`whole_client_ids` are the explicit `can_view_clients` grants. `site_ids` are the explicit `can_view_sites` grants only, not the sites of a granted client. A site-only role is mode `sites`, has no whole client, and `has_whole_client_access` is `False` for it even for the client that owns its site. `has_whole_client_access` is `True` only for an unrestricted caller or a role that lists the client in `can_view_clients`, and only when the client exists. A malformed `client_id` raises `ResourceValidationError`.

These are scope questions only. They do not need `can_list_clients` or `can_list_sites`, the same as Scheduler targets. A trusted global service context is unrestricted, with whole access to every existing client. A service context that is not global is refused with `ResourcePermissionDenied`.

Core computes the descriptor once in the adapter, from the same rule that Scheduler targets, report row scope and client writes use, so the answers cannot disagree.

### Client/site write operations

- `create_client(name=..., context=...)`
- `update_client(client_id, name=None, alert_template_id=UNSET, context=...)`
- `delete_client(client_id, move_to_site_id=None, context=...)`
- `create_site(client_id=..., name=..., context=...)`
- `update_site(site_id, name=None, client_id=None, alert_template_id=UNSET, context=...)`
- `delete_site(site_id, move_to_site_id=None, context=...)`
- `list_custom_fields(resource_type, resource_id, context=...)`
- `update_custom_fields(resource_type, resource_id, values=[...], context=...)`

The write operations return the same stable client/site record shapes as the read contract. Core never returns Tactical ORM instances.

#### Alert template (since 1.4.0)

`update_client` and `update_site` accept `alert_template_id`: a positive integer sets the template and `None` clears it. Leave the keyword out to leave the template alone (`UNSET` is the default; do not pass it yourself). `name` is optional on `update_client` now, but at least one field is required. Existing calls such as `update_client(7, name="New", context=ctx)` work as before.

- A boolean, zero, a negative number, a fraction and text that is not a whole number raise `ResourceValidationError`.
- An id that names no template raises `ResourceValidationError`. Tactical's own foreign key decides, so Core imports no Alerts model.
- The write rule is the same as a rename: Tactical `can_manage_clients` or `can_manage_sites`, the Core resources permission, and the same client or site write scope (a whole-client grant for a client; a site grant or a grant of the site's client for a site). A role limited to one site cannot change its client's template. Core does not ask for `can_manage_alerts`, because Tactical's own client and site `PUT` check only the manage-clients and manage-sites flags.
- The write goes through Tactical's model save, so Tactical's own refresh of the agents' cached alert template still runs.
- The audit row carries the before and after records, which include `alert_template_id`, and the metadata flag `alert_template_changed`.
- `create_client` and `create_site` do not take `alert_template_id`. A new resource has no template.

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

`page_size` is limited to 500 and `page` is limited to 10000.

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
| `create_client`, `update_client`, `delete_client`, client custom fields | `can_manage_clients` | `core.resources.clients.manage` |
| `create_site`, `update_site`, `delete_site`, site custom fields | `can_manage_sites` | `core.resources.sites.manage` |

Effective superusers retain the normal override behavior.

Updates use the same centralized Tactical client/site scope rule as Scheduler authorization. A role with both `can_view_clients` and `can_view_sites` empty is unrestricted. Once either relation contains entries, client mutations require an explicit client grant; a site-only grant never becomes parent-client write authority. Site mutations are allowed by an explicit site grant or an explicit grant to that site's client. This preserves Tactical's unrestricted-role behavior without letting broader client read visibility become write authority.

Creating a new client has no pre-existing resource against which to apply scope; it therefore requires the two manage permissions above and creates a new top-level resource.

Creating a trusted global service context writes a strict Core audit event before authority is returned. Trusted service contexts cannot mutate resources in contract 1.x. A future unattended write mechanism must establish explicit non-self-asserted service authority rather than reusing global read authority.

## Core RBAC groups

Core publishes assignable permissions through the normal Tec-Tac Access/RBAC catalogue:

- **Client resource management** -> `core.resources.clients.manage`
- **Site resource management** -> `core.resources.sites.manage`

The permissions are enforced in the Python contract itself and therefore cannot be bypassed by a backend module calling `tec_tac.resources` directly instead of using HTTP.

## HTTP representation

Authenticated browser/external callers can use:

- `GET/POST /api/tfd/resources/clients/`
- `GET/PATCH/DELETE /api/tfd/resources/clients/<id>/`
- `GET/PATCH /api/tfd/resources/clients/<id>/custom-fields/`
- `GET/POST /api/tfd/resources/sites/`
- `GET/PATCH/DELETE /api/tfd/resources/sites/<id>/`
- `GET/PATCH /api/tfd/resources/sites/<id>/custom-fields/`
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

```json
{"alert_template_id": 7}
```

`PATCH /api/tfd/resources/clients/<id>/` accepts `name`, `alert_template_id` or both (at least one). `PATCH /api/tfd/resources/sites/<id>/` accepts `name`, `client_id`, `alert_template_id` or any of them. `alert_template_id: null` clears the template.

### Scope in the runtime context

`GET /api/tfd/ui/context/` carries `tactical_scope` since Core 1.17.17, next to `tactical_permissions`:

```json
{"mode": "mixed", "unrestricted": false, "whole_client_count": 2, "site_count": 5}
```

It is built from the same descriptor and holds the mode and counts only, never id lists, so the startup payload stays small. The ids stay in the Python contract (`scope_descriptor`). An installer user, a user with no role and any failure give `{"mode": "none", "unrestricted": false, "whole_client_count": 0, "site_count": 0}`. It is a hint for the page: Tactical still decides every call. Older UI builds ignore it. The UI release that exposes it in `register(context).context` is separate.

Client and site create/update operations are transaction-audited through Core using the authenticated Tactical actor. The audit write is strict: if Tactical audit persistence fails, the resource mutation is rolled back rather than succeeding without an investigation trail. Update events include before/after resource snapshots when the prior row is visible through the caller's Tactical read scope.


### Deletion semantics

- Site deletion moves agents only to another site under the same client. The last site in a client cannot be deleted.
- Client deletion moves all agents to a writable site under a different client when agents remain.
- Relocation and deletion run inside one transaction and the strict Core audit write is part of that transaction.

### Custom-field values

Core exposes non-hidden Tactical custom-field definitions and values as `{field_id,name,type,options,required,value}`. Supported types are `text`, `number`, `single`, `multiple`, `checkbox`, and `datetime`. PATCH accepts an array of `{field_id,value}` entries, validates required/options/type rules, then writes Tactical's native custom-field value rows. Hidden definitions are not exposed or writable through this surface.

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

Contract `1.4.0` is additive over `1.3.0`: client and site records gain `alert_template_id` (appended last), `update_client` and `update_site` gain an optional `alert_template_id`, and the scope operations are new.

## Core consumers

Core subsystems that need Tactical client, site, or agent scope should use this Resource Directory boundary or its internal adapter rather than importing Tactical resource ORM models directly. Scheduler target authorization follows this rule so Tactical model compatibility and scope behavior remain centralized.
