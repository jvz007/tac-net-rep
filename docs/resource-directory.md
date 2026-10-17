# Core Resource Directory

Contract ID: `core.resources`  
Contract version: `1.11.0`  
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

Contract 1.11 (Core 1.17.51, additive, still major 1) lets `update_client` and `update_site` take an optional compare-and-set guard: `expected_workstation_policy_id`, `expected_server_policy_id` and `expected_block_policy_inheritance`. A call without a guard behaves exactly as before. See "Compare-and-set guard (since 1.11.0)".

Contract 1.10 (Core 1.17.40, additive, still major 1) adds `failing_checks`, `agent_count` and `maintenance_mode` to client and site records, read only and counted inside the caller's scope. Existing keys, keywords, paging and error codes do not change. See "Live state (since 1.10.0)".

Contract 1.8 (Core 1.17.25, still major 1) changes one documented rule: moving a site follows Tactical's Edit site (CQ79, Johan, 13 October 2026). The destination client needs no grant check any more, and a same-client update needs the site's write scope. No record shape or keyword changed, so it is listed as a rule change, not an addition. See "Move a site".

Contract 1.7 (Core 1.17.24, additive, still major 1) adds `workstation_policy_id`, `server_policy_id` and `block_policy_inheritance` to client and site records, lets `update_client` and `update_site` set or clear them, and adds the `alert_template_id` and `policy_id` list filters. It also documents and pins the site move. Existing keys, keywords, paging and error codes do not change. See "Policy fields (since 1.7.0)", "List filters (since 1.7.0)" and "Move a site".

Contract 1.5 (Core 1.17.22, additive, still major 1) adds `sites` to client records (that client's site records inside the caller's scope), `client_name` to site records, `site_name` and `custom_fields` to `create_client`, `custom_fields` to `create_site`, and the role scope list contract below. Existing keys, query parameters, paging and error codes do not change.

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

Stable fields: `type`, `id`, `name`, `active`, `alert_template_id` (since 1.4.0, an integer or `null`; appended after the earlier keys), `sites` (since 1.5.0), `workstation_policy_id`, `server_policy_id`, `block_policy_inheritance` (since 1.7.0), `failing_checks`, `agent_count`, `maintenance_mode` (since 1.10.0, appended last).

`sites` is the list of that client's site records the caller may see, ordered by name then id, each with the shape of a site record below. It uses the same `Site.filter_by_role` rule as the sites read. A client-limited role gets every site of its clients plus granted sites. A site-only role gets only its granted sites under the parent client. An unrestricted caller and a trusted global service context get every site. A client with no site in scope has `"sites": []`. It is loaded with one query per page. It needs only `can_list_clients`, as Tactical's own `GET /clients/` does, so showing nested site names to a role without `can_list_sites` opens no data beyond Tactical (AD-5, AD-25). The sites read itself stays refused without `can_list_sites`. `list_clients`, `get_client`, `create_client` and `update_client` carry it.

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

Stable fields: `type`, `id`, `name`, `client_id`, `active`, `alert_template_id` (since 1.4.0, an integer or `null`), `client_name` (since 1.5.0), `workstation_policy_id`, `server_policy_id`, `block_policy_inheritance` (since 1.7.0), `failing_checks`, `agent_count`, `maintenance_mode` (since 1.10.0, appended last).

`client_name` is the owning client's name, as Tactical's own `/clients/sites/` returns it. It comes from the client join with no extra query per row, so a role with only `can_list_sites` can group sites by client without reading clients.

#### What each role can read (since 1.5.0)

| Role holds | Clients read | Sites read |
| --- | --- | --- |
| List clients only | 200, each client with its nested sites | 403 |
| List sites only | 403 | 200, each site with `client_id` and `client_name` |
| Both | 200 | 200 |
| Neither | 403 | 403 (unchanged; names from endpoint rows are not built) |

The UI shows the Clients and Sites page when the role holds either flag (or is a superuser). It reads clients when it can, otherwise sites grouped by `client_name`, and never calls the other read after a 403. Writes still need `can_manage_clients` or `can_manage_sites` plus the Core codenames.

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

Since 1.9.0 (Core 1.17.30, AD-34 condition 1) the module `userinvite`, and no other module, may build a service context without global access:

```python
ctx = trusted_service_context(actor="userinvite", purpose="send an invitation email", global_access=False)
```

Core verifies the caller from the call stack (a private helper, see `docs/caller-identity.md`). The actor must name the same module. Any other caller, an unverified caller, a disabled module or a different actor is refused with `resource_permission_denied`, and Core says nothing about who is allowed. The context carries the actor and purpose and nothing else: it has no resource visibility, so every list, get and write on it is still refused. It writes no audit row. A module such as Global Settings reads only `is_service`, `service_actor` and `service_purpose` from it. `global_access=True` is unchanged. Any further module that needs this path needs Johan's sign-off first (AD-34 condition 2).

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
- `trusted_service_context(actor=..., purpose=..., global_access=True)` (`global_access=False` for `userinvite` only, since 1.9.0)

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

- `create_client(name=..., context=..., site_name=None, custom_fields=None)`
- `update_client(client_id, name=None, alert_template_id=UNSET, workstation_policy_id=UNSET, server_policy_id=UNSET, block_policy_inheritance=UNSET, expected_workstation_policy_id=UNSET, expected_server_policy_id=UNSET, expected_block_policy_inheritance=UNSET, context=...)`
- `delete_client(client_id, move_to_site_id=None, context=...)`
- `create_site(client_id=..., name=..., context=..., custom_fields=None)`
- `update_site(site_id, name=None, client_id=None, alert_template_id=UNSET, workstation_policy_id=UNSET, server_policy_id=UNSET, block_policy_inheritance=UNSET, expected_workstation_policy_id=UNSET, expected_server_policy_id=UNSET, expected_block_policy_inheritance=UNSET, context=...)`
- `delete_site(site_id, move_to_site_id=None, context=...)`
- `list_custom_fields(resource_type, resource_id, context=...)`
- `update_custom_fields(resource_type, resource_id, values=[...], context=...)`

The write operations return the same stable client/site record shapes as the read contract. Core never returns Tactical ORM instances.

#### Create client and create site (since 1.5.0, Core 1.17.22)

Tactical's Add client creates the client and its first site together, and Add site can carry custom fields. Core does the same.

- `site_name` is the first site's name. Every new caller and form sends it. A call without it still works and names the site `Default Site` (deprecated compatibility path; the audit metadata then says `default_site_created: true`). A blank `site_name` is refused.
- `custom_fields` is an optional list of `{field_id, value}`. They are validated by the same rules as `update_custom_fields` and saved in the same transaction as the client and site, so a bad custom field rolls everything back. The write-scope check is skipped for them because the creator just created the object.
- Names may not contain `|`. Tactical refuses it in client and site names, and Core refuses it in create and rename: `Client name cannot contain the | character`.
- As Tactical does, a new client is added to the creator's `can_view_clients` only when that list is not empty, and a new site to `can_view_sites` only when that list is not empty. A role limited only by sites that adds a client is not widened to whole-client authority (a narrowing of Core 1.17.21, which widened every restricted creator). Superusers and unrestricted roles are unchanged.
- The strict audit row carries `first_site_id`, `role_scope_extended` (`clients`, `sites` or `none`) and `custom_field_ids` (ids only, never values). Audit before and after snapshots are built without `sites` and `client_name`.
- The record `create_client` returns carries `sites` with the first site, even when the creator's scope does not show it afterwards.

#### Alert template (since 1.4.0)

`update_client` and `update_site` accept `alert_template_id`: a positive integer sets the template and `None` clears it. Leave the keyword out to leave the template alone (`UNSET` is the default; do not pass it yourself). `name` is optional on `update_client` now, but at least one field is required. Existing calls such as `update_client(7, name="New", context=ctx)` work as before.

- A boolean, zero, a negative number, a fraction and text that is not a whole number raise `ResourceValidationError`.
- An id that names no template raises `ResourceValidationError`. Tactical's own foreign key decides, so Core imports no Alerts model.
- The write rule is the same as a rename: Tactical `can_manage_clients` or `can_manage_sites`, the Core resources permission, and the same client or site write scope (a whole-client grant for a client; a site grant or a grant of the site's client for a site). A role limited to one site cannot change its client's template. Core does not ask for `can_manage_alerts`, because Tactical's own client and site `PUT` check only the manage-clients and manage-sites flags.
- The write goes through Tactical's model save, so Tactical's own refresh of the agents' cached alert template still runs.
- The audit row carries the before and after records, which include `alert_template_id`, and the metadata flag `alert_template_changed`.
- `create_client` and `create_site` do not take `alert_template_id`. A new resource has no template.

#### Policy fields (since 1.7.0, Core 1.17.24)

A client and a site each carry a workstation policy, a server policy and a "block policy inheritance" flag. Tactical's Edit client and Edit site save them. Core holds only the ids and the flag. The Automation module owns the policy list, the picker and what a policy does.

- Record keys `workstation_policy_id` (integer or `null`), `server_policy_id` (integer or `null`) and `block_policy_inheritance` (`true` or `false`, `false` when unset). A nested site carries them too. A record built from a row without the keys reads `null`, `null` and `false`. Anyone who can list clients or sites sees them, as for `alert_template_id`.
- `update_client` and `update_site` take `workstation_policy_id` and `server_policy_id` (a positive whole number sets, `None` clears, leaving the keyword out leaves it alone) and `block_policy_inheritance` (a real `True` or `False` only: `1`, `0` and text are refused). At least one field is still required.
- A policy id that names no policy fails Tactical's own foreign key and answers `400 invalid_resource_request` with `workstation_policy_id does not name an existing policy.` (or `server_policy_id ...`).
- The write rule is the same as a rename: Tactical `can_manage_clients` or `can_manage_sites`, the Core resources permission, and the client or site write scope. Core does not ask for `can_manage_automation_policies`, because Tactical's own client and site `PUT` check only the manage-clients and manage-sites flags. A policy then pushes its checks, tasks and scripts to every endpoint under the client or site, so the audit row names the ids.
- The write goes through Tactical's model save (`update_fields` include `workstation_policy`, `server_policy`, `block_policy_inheritance`, `modified_by`), so Tactical's own refresh of the agents' alert template and policy caches still runs.
- The strict audit row carries before and after records (the new fields are in them) and the metadata `policy_changed`: the names of the fields whose value changed (ids only, never a policy name). A call that changes nothing writes no row.

#### Compare-and-set guard (since 1.11.0, Core 1.17.51)

A caller that read a client or site and now writes a policy field can ask Core to refuse the write when someone else changed the record in between. This is what Automation's "Remove from policy", "Assign client or site" and "Edit policies" need, so two people editing at once never overwrite each other silently.

- `update_client` and `update_site` take `expected_workstation_policy_id` and `expected_server_policy_id` (a positive whole number, or `None` for "must be unset") and `expected_block_policy_inheritance` (a real `True` or `False`). All default to `UNSET`, which leaves a field out of the compare. A policy id may also arrive as digits in text, as for the policy fields.
- `PATCH /api/tfd/resources/clients/<id>/` and `/sites/<id>/` accept the same three keys in the body.
- The compare runs inside the adapter's write transaction, on the row that transaction has locked (`select_for_update`), before a move or any other change. There is no gap between the read and the write.
- When a guard key is sent and the locked record holds another value: nothing is written, no audit row is written, and the answer is `409` with `code: "record_changed"` and a plain sentence that names the field and never a value. In Python the call raises `ResourceConflict`, and its `code` is `record_changed` (the other conflicts keep `resource_conflict`).
- A guard alone is not a change. With no `name`, `client_id`, `alert_template_id` or policy field the call is still `400`. A bad guard value (a bool for an id, text for the flag, zero, a fraction) is `400`.
- A matching guard with a change that changes nothing writes no audit row, as before. A call with no guard key behaves exactly as before.
- There is no guard for the name or the alert template. Nothing asked for one.
- A site call judges the guard together with a move in the same call: a stale guard moves nothing. A same-client `client_id` is not a shortcut past the compare when a guard is given.
- Needs framework >=1.17.51. Feature-detect with `core.resources >= 1.11.0`. `install.sh` accepts any 1.x from 1.1.0, so it needs no change.

#### Live state (since 1.10.0, Core 1.17.40)

Client and site records carry three read-only keys, appended after `block_policy_inheritance`. Endpoints uses them to show which clients and sites need attention, and to sort the Scope pane.

- `failing_checks`: `{"error": true|false, "warning": true|false}`. It is Tactical's stored value on the client or site, as Tactical's own `GET /clients/` returns it. A null, a non-object or a non-boolean value reads `false`.
- `agent_count`: a whole number, the agents counted.
- `maintenance_mode`: `true` when any counted agent is in maintenance mode.
- A nested site, and the record `create_client`, `update_client`, `create_site` and `update_site` return, carry the keys too, so one shape applies everywhere. Agent records never carry them.
- Scope rule (AD-12, a role sees counts only for what it may see). A site record is computed from its own agents only. A client record is computed only from the sites the caller may see (the same `Site.filter_by_role` rule as `sites`): `agent_count` is the sum over those sites and `maintenance_mode` is `true` when any of them has an agent in maintenance mode. `failing_checks` is Tactical's stored client value only when the caller sees every site of the client (an unrestricted caller and a trusted global context always do). Otherwise it is the OR of the visible sites' stored values. A site-only role therefore never learns that a hidden site is failing or how many agents it has. A client with no visible site reads `0`, `false` and both `false`.
- No `can_list_agents` flag is needed: Tactical's own `GET /clients/` gives a role with List clients alone these three values (AD-5, AD-25).
- Following Tactical's `client_tree_sort` (1.17.41 wording). The person's setting is `tactical_ui.client_tree_sort` in the runtime context: `alphafail` is Tactical's "Move failing clients to the top" and `alpha` is A to Z. Core publishes the setting and the failing state (`failing_checks`) and never sorts. The ordering, and any colour marking of a failing client or site, is the consumer's.
- Stale by design. Tactical refreshes `failing_checks` only in its periodic cache task, so the value is as of that refresh. Treat it as a hint, not a live check. `agent_count` and `maintenance_mode` are read when you call.
- Cost: a constant number of queries per page (one grouped agent query, no query per row), so a 500-row page stays cheap.
- Audit: the before and after rows of `update_client` and `update_site` never carry these keys, and a change in Tactical's `failing_checks` between the read and the save does not write a `modify` row.
- HTTP: `GET /api/tfd/resources/clients/` and `sites/` (and the id reads) pass the records through unchanged, so they carry the keys.

#### List filters (since 1.7.0)

`list_clients` and `list_sites` take `alert_template_id` and `policy_id`. Each is a positive whole number or the call fails with `invalid_resource_request`. `alert_template_id` keeps the records that use that alert template. `policy_id` keeps the records whose workstation policy or server policy is that policy. Both together mean both must match. The filters run inside the caller's scope and under the list's own permission. They let Alerts find where a template is used and Automation build the policy overview without reading every page. HTTP: `GET /api/tfd/resources/clients/?alert_template_id=5&policy_id=31` and the same on `sites/`.

#### Move a site (documented in 1.7.0, Core 1.17.24; rule changed in 1.8.0, Core 1.17.25)

This rule is accepted decision AD-29 (Johan, 13 October 2026, CQ79) in `docs/review-accepted-decisions.md`: the source-site write scope is kept, a missing client is 400, a name clash is 409, one audit row is written, and the consequence below is accepted. Revisit when Johan declares parity reached or asks sooner.

`update_site(site_id, client_id=<destination>, context=...)` (HTTP `PATCH /api/tfd/resources/sites/<id>/` with `client_id`) is Tactical's Edit site with a new client. The mechanism is older. Since 1.7.0 the rules are documented and tested. Since 1.8.0 the destination rule is Tactical's (Johan, CQ79, 13 October 2026: "keep it the same as Tactical"). This loosens Core's 1.17.24 rule on purpose.

- The agents on the site follow it, because they point at the site.
- The source site needs its write scope (a site grant or a grant of its client). A same-client update checks the same scope first, so a read-only caller gets the same `404 resource_not_found` refusal as for any other write.
- The destination client needs no grant. Tactical's Edit site checks only the Edit sites permission and the source site's scope, so Core does the same. A role limited to some clients may move a site into a client it holds no grant on. This is a deliberate loosening of the 1.17.24 rule.
- A destination client that does not exist answers `400` (a validation error from the model's own check), as Tactical does.
- The last site of a client cannot move away: `400`, `A client must retain at least one site.`
- A name already used by a site of the destination client gives `409`, `A site with that name already exists for the selected client.`
- A `client_id` equal to the site's current client is a no-op: nothing is saved and no audit row is written.
- A move together with a rename or another field is one write and one audit row.
- The write goes through Tactical's model save (`update_fields` include `client`, `modified_by`, `modified_time`), so its `Site.save` hooks run.
- The strict audit row carries before and after records (`client_id`) and the metadata `client_changed` (`true`), `from_client_id`, `to_client_id` and `agents_moved` (a count). Ids and a number only, never a name. The keys are absent when the client did not change.

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
- `GET /api/tfd/resources/custom-fields/?resource_type=client|site` (since 1.6.0)
- `GET/PATCH /api/tfd/resources/clients/<id>/custom-fields/`
- `GET/POST /api/tfd/resources/sites/`
- `GET/PATCH/DELETE /api/tfd/resources/sites/<id>/`
- `GET/PATCH /api/tfd/resources/sites/<id>/custom-fields/`
- `GET /api/tfd/resources/agents/`
- `GET /api/tfd/resources/agents/<agent_id>/`

Read query parameters mirror the Python filters. HTTP always derives a user context from the authenticated Tactical/Tec-Tac session; it cannot create trusted service contexts.

Create payloads:

```json
{"name": "Client name", "site_name": "Head office", "custom_fields": [{"field_id": 4, "value": "AC-001"}]}
```

```json
{"client_id": 123, "name": "Site name", "custom_fields": [{"field_id": 5, "value": true}]}
```

`site_name` and `custom_fields` are optional on the wire for compatibility; new forms send `site_name`.

Update payloads accept only writable fields. Unknown fields are rejected. Agent HTTP resources remain read-only.

```json
{"alert_template_id": 7}
```

`PATCH /api/tfd/resources/clients/<id>/` accepts `name`, `alert_template_id`, `workstation_policy_id`, `server_policy_id`, `block_policy_inheritance` or any of them (at least one). `PATCH /api/tfd/resources/sites/<id>/` accepts the same plus `client_id`. `null` clears a template or policy id. `block_policy_inheritance` takes only `true` or `false`. Since 1.11.0 both also accept the guard keys `expected_workstation_policy_id`, `expected_server_policy_id` and `expected_block_policy_inheritance`; a stale one answers `409` with `record_changed` and writes nothing.

### Role client and site lists (since Core 1.17.22)

Core has no roles API of its own for these lists. The routes are Tactical's `GET|POST /accounts/roles/` and `GET|PUT|DELETE /accounts/roles/<id>/`. They already read and save `can_view_clients` and `can_view_sites` as lists of ids.

- An empty pair means unrestricted. A role limited to sites only is site mode.
- `PUT` replaces both lists. A limited editor sees only its own clients and sites in the pickers, so the UI must send back the ids it loaded and could not show.
- The pickers read clients (with nested sites) and sites from this Resource Directory. List clients is enough for the tree.
- Core writes one strict audit row for a changed pair: module `core`, action `add` or `modify`, object type `role_scope`, object id the role id, `before` and `after` as sorted id lists (capped at 1000, with counts and a `truncated` flag), ids only, never names. It is written only when a list changed, inside the same transaction as the role save, so a failed audit write rolls the save back. Tactical's own audit does not record a change that only touches these two lists.
- Core does not change who may edit role lists. Tactical's rule stands (any role with Manage roles); see CQ72 in the questions file.

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

Contract `1.11.0` (Core 1.17.51) is additive over `1.10.0`: `update_client` and `update_site` gain three optional keywords (the compare-and-set guard), `ResourceConflict` gains a `code` argument (`record_changed`), and the two PATCH routes accept the same three keys. No record, route or earlier error changed. Needs framework >=1.17.51.

Contract `1.10.0` (Core 1.17.40) is additive over `1.9.0`: client and site records gain `failing_checks`, `agent_count` and `maintenance_mode` (appended last). No keyword, route or error changed. Needs framework >=1.17.40.

Contract `1.8.0` (Core 1.17.25) changes the move rule only: the destination client needs no grant, and a same-client update needs the site's write scope. Records and keywords are unchanged.

Contract `1.7.0` is additive over `1.6.0`: client and site records gain `workstation_policy_id`, `server_policy_id` and `block_policy_inheritance` (appended last), `update_client` and `update_site` gain three optional keywords, `list_clients` and `list_sites` gain the `alert_template_id` and `policy_id` filters, and the site move rules are documented. An unchanged update (the same values sent again) now writes no audit row.

Contract `1.6.0` is additive over `1.5.0`: one new call, `list_custom_field_definitions(resource_type, *, context)`, with the route `GET /api/tfd/resources/custom-fields/?resource_type=client|site`. No record shape changed. See "Custom-field definitions before the create (since 1.6.0)".

Contract `1.5.0` is additive over `1.4.0`: client records gain `sites`, site records gain `client_name` (both appended last), `create_client` gains `site_name` and `custom_fields`, `create_site` gains `custom_fields`.

Contract `1.4.0` is additive over `1.3.0`: client and site records gain `alert_template_id` (appended last), `update_client` and `update_site` gain an optional `alert_template_id`, and the scope operations are new.

## Core consumers

Core subsystems that need Tactical client, site, or agent scope should use this Resource Directory boundary or its internal adapter rather than importing Tactical resource ORM models directly. Scheduler target authorization follows this rule so Tactical model compatibility and scope behavior remain centralized.

## Custom-field definitions before the create (since 1.6.0, Core 1.17.23)

Add client and Add site show the custom fields before the object exists, so they cannot use the read that needs a client or site id.

```python
from tec_tac.resources import list_custom_field_definitions
list_custom_field_definitions("client", context=context)
# {"resource_type": "client", "fields": [{"field_id": 1, "name": "Account code", "type": "text", "options": [], "required": True, "value": ""}]}
```

- `GET /api/tfd/resources/custom-fields/?resource_type=client|site` gives the same answer over HTTP.
- Each row has the shape and order of the id read (`list_custom_fields`): non-hidden fields only, ordered by `order`, name and id. `value` is the field's default.
- No per-client data is read, so nothing is scoped. A role limited to one client still gets the definitions.
- The gate is the create's own: Tactical `can_manage_clients` (for `client`) or `can_manage_sites` (for `site`) plus the Core permission. A superuser passes. A service context is refused. A role with only List clients is refused, because only a person who can add a client needs the form. This is the same gate as the id read.
- `resource_type` missing, or anything other than exactly `client` or `site` (`agent`, `Client `), is a 400. An unknown query name is a 400.
- Field ids in `custom_fields` of `create_client`, `create_site` and `update_custom_fields` must be positive whole numbers (1.17.23). A boolean, a float, `null`, zero, a negative number, a list or text such as `1.5` is refused with 400 `field_id must be a positive whole number.` before anything is created.
