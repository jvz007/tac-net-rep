# Tec-Tac Audit Write Contract

**Status:** Public Core developer contract  
**Backend:** `tec_tac.audit.record(...)`  
**Browser runtime:** `audit.record(event)`  
**Persistence:** Tactical `logs.models.AuditLog` through Core only

## Architectural boundary

```text
Tec-Tac module
    ↓
Core public audit contract
    ↓
Core audit service
    ↓
Tactical AuditLog
    ↓
Audit module / Tactical audit APIs / retention / export
```

Modules MUST NOT import, instantiate, or write `logs.models.AuditLog` directly. Core is the only supported Tec-Tac writer. Tactical's own audit records are not changed or rewritten.

## Where the row should be written (1.17.7)

A browser-sent audit row can be manipulated. The rows Core can vouch for are written on the server, where the action happens. There are three ways, in order of preference:

1. **A Tactical call that must be audited** is declared once by the owning core module as a Tactical operation (`docs/tactical-operations.md`). Core runs the call server-side for the signed-in user and writes the row from Tactical's real answer. The row carries `operation_context.server_provenance = "tactical-operation"`.
2. **A module's own backend action** (a Core update job, an installer run, a change to the module's own data) calls `tec_tac.audit.record` from the backend route, after the action succeeds. Core's audit covers Tec-Tac's own functions as well as Tactical ones.
3. **A browser-only event with no server action** has no server-side replacement yet. It stays on the declared browser path below until the module drops it.

## Backend contract

Server-side modules should record the audit event immediately after the authoritative business action succeeds:

```python
from tec_tac.audit import record

result = record(
    actor=request.user,
    module_id="advancedpatch",
    action="modify",
    object_type="patch_profile",
    object_id=str(profile.pk),
    message="Updated patch profile Monthly Servers",
    before=before_data,
    after=after_data,
    metadata={"request_id": request_id},
    request=request,
)
```

`actor` must be the authenticated Tactical user. There is deliberately no `username` argument. Core derives `username` from the actor and rejects actor/provenance fields on the browser API.

Three `operation_context` keys are Core-owned: `core_refusal`, `browser_provenance` and, since 1.17.7, `server_provenance`. Only Core's own rows set them. `record()` raises `AuditContractError` when a caller supplies any of them, so a backend module cannot forge the marker of another path. (Before 1.17.6 only `core_refusal` was refused, so `browser_provenance` could be forged through the backend call.) `build_operation_context(...)` never sets them.

Core's own audit writers are Core-internal and a module must not call them: `record_browser_declared`, `record_core_refusal` and `_record_tactical_operation`. Since 1.17.8 the last one is private (`audit.record_tactical_operation` is gone, with no alias), so only Core's executor can write a `server_provenance` row. A module that needs a Tactical call audited declares a Tactical operation (`core.tactical_operations`).

Backend authorization remains authoritative. Audit recording does not grant permission to perform the business action. Modules must authorize the action first, perform it, then record the event.

## Browser runtime

Authenticated UI modules receive a module-scoped `audit` service from `register(context)`:

```js
export async function register({ audit }) {
  const result = await audit.record({
    action: 'modify',
    object_type: 'example',
    object_id: '123',
    message: 'Updated example',
    before: oldValue,
    after: newValue,
  })
}
```

The browser runtime injects the owning module ID. A module does not supply `username`, module version, source, or correlation provenance.

For server-mutating operations, prefer recording from the authorized backend endpoint rather than relying on a second browser request. The browser helper is appropriate for Core/UI actions whose authoritative operation is itself browser-side or where the backend API cannot yet own the event.

## Event fields

| Field | Required | Notes |
| --- | --- | --- |
| `action` | yes | Standard action or controlled `custom:<slug>` fallback. |
| `object_type` | yes | Lowercase slug, maximum 100 characters. |
| `object_id` | no | Stored in Core provenance inside `debug_info`. |
| `message` | no | Tactical applies its existing 255-character safe truncation. |
| `before` | no | Written to Tactical `before_value`. |
| `after` | no | Written to Tactical `after_value`. |
| `metadata` | no | Stored beneath Core provenance in `debug_info.metadata`. |

## Rows for a person who holds none of the module's permissions (Core 1.17.20)

A module's backend `record()` call normally needs a signed-in person who holds at least one of the module's own permissions. Some
modules must also record what happens to a person who holds none of them: a refusal, or the outcome of a change that Tactical's own role
flags allow. From 1.17.20 Core accepts that row when the module is the **declaring owner of the action**.

A module is a declaring owner when it has registered at least one Tactical operation (`core.tactical_operations`). So the module is
enabled, not legacy and not `core`. Core then applies these rules to the signed-in person with no grant of the module:

| Action in `record()` | Accepted when |
|---|---|
| `deny` | the module owns at least one declared operation |
| any other action | it is the `audit.action` of one of the module's declared operations that has **no** `module_permission`, **and** the person holds **every** Tactical flag of that operation |

The second rule rests on the check Core would make anyway (AD-5, AD-12). `rbac.tactical_permission_flags` decides it, so it already
refuses an installer user, a user with no Tactical role and any lookup failure. An operation that declares no Tactical flag never
qualifies, because there is nothing to rest the row on.

Core refuses, with `AuditContractError`, the same as before:

- an installer user, an unauthenticated actor, and Core itself (`module_id` `core`);
- a legacy module, a disabled module, and a module with no declared operation;
- an action that none of the module's operations declares;
- an operation that needs a module permission (the person must hold that grant);
- an outcome row for a person who lacks one of the operation's Tactical flags.

Core marks such a row with `debug_info.actor_authority = "declared-operation-owner"`. Core sets it from the actor information it builds,
so a module cannot supply it (a key of that name in `metadata` stays inside `metadata`). A row written for a person who holds a module
grant carries no `actor_authority`, so an auditor can tell the two apart. Service and device actors (`service_audit_actor`,
`device_audit_actor`) are unchanged.

Limits. This is the backend `record()` only. The browser path (`POST /api/tfd/audit/record/`, `can_record_from_browser`,
`declared_browser_event`) is unchanged: a permissioned module's browser row still needs its grant, because Core cannot prove the
module's code sent the event. A module that needs such a row writes it from a backend route instead. The rule is purely additive: it
accepts more rows and refuses nothing that was accepted before. A module that relies on it needs `requires.framework >=1.17.20`.

### Worked example: an export by a person who holds only List checks (Core 1.17.51)

A role may hold Tactical's `can_list_checks` and nothing of the Checks module's own grants, yet be allowed to export an event log. Core
changes nothing for this case: the rule above already accepts the row. Checks only has to declare the read the right way and write its row
from its backend.

1. Declare the event-log read as a Tactical operation: method `GET`, `permissions: ["can_list_checks"]`, **no** `module_permission`, and
   `audit: {"action": "export", "object_type": "agent"}` (the object type of your choice).
2. In the backend route that serves the export, after the data is built, call
   `audit.record(actor=request.user, module_id="checks", action="export", object_type="agent", object_id=..., message=...)`.
3. Core accepts it because Checks owns an operation with audit action `export`, that operation needs no module_permission, and the person holds every Tactical flag of it (`can_list_checks`). The row carries `debug_info.actor_authority = "declared-operation-owner"`.

Core refuses the same row, with `AuditContractError`, for the same person without `can_list_checks`, for a module that declared no `export`
operation, for an operation that sets `module_permission`, for an installer user and for any other action. Core does not loosen the rule: if
it did, any module could claim a flag it never declared. A module that adopts this needs `requires.framework >=1.17.51` (the rule itself is
older, but 1.17.51 is the release that documents and pins this case).

Since 1.17.20 the action `custom:operation-failed` is Core-only. Core writes it when Tactical refuses a change (see
`docs/tactical-operations.md`), so `record()` refuses it with `AuditContractError`. `custom:outcome-unknown` stays open to a module that
writes its own outcome row.

## Deny rows from a server module (Core 1.17.30, AD-34)

A module whose signed manifest category is `server` (User Invite is the first) can refuse a person who holds none of its permissions and
still leave a trace. `audit.record` accepts that person as the actor when all of these hold:

* the action is exactly `deny` (no other action, no `custom:` action);
* the module is enabled, not legacy and its category is `server` (a `core`, `premium`, `test` or empty category is refused);
* Core verifies from the call stack that the caller is that same module. A missing caller, another module, a Core frame, a library
  frame, a generated frame and a disabled module all fail closed with `AuditContractError`;
* the person is signed in and is not an installer user.

Core marks the row `debug_info.actor_authority = server-module-deny`. A caller cannot supply it. The row names the person (`actor_kind`
human, `actor_identity` the username). A person who does hold a module permission gets the normal row, with no `actor_authority`.
Core's own rows (`record_core_refusal`, `record_browser_declared`, the Tactical operation executor) never take this path. The check
never raises: any error is a refusal. The helper that verifies the caller is Core-private and no module may import it.
This is AD-34 conditions 1 and 2. Any further module needs Johan's sign-off in chat (AD-34 condition 2). Pinned by
`tests/audit-server-module-deny-1.17.30.py`.

## Standard action vocabulary

Use these values wherever they fit:

```text
add
modify
delete
run
approve
deny
enable
disable
install
uninstall
view
export
import
sync
test
acknowledge
resolve
```

When no standard action accurately describes the event, use a controlled fallback:

```text
custom:<slug>
```

Example: `custom:recalculate`.

Do not invent ad-hoc action spellings when a standard action exists.

## Provenance added by Core

Core writes these values into Tactical `debug_info`:

```json
{
  "source": "tec-tac",
  "module_id": "advancedpatch",
  "module_version": "1.2.3",
  "object_id": "123",
  "correlation_id": "...when available...",
  "metadata": {}
}
```

Module version is resolved from the installed registry. Browser callers cannot override it. Core never reads a browser `X-Request-ID` or `X-Correlation-ID` header as provenance. The correlation id is the explicit `correlation_id` a backend passes, or the id Core keeps for the request (next section).

## One correlation id for a request or a job (1.17.16)

Core has no middleware entry of its own (adding one would mean editing Tactical's tracked settings), so the id is made the first time it is needed:

- **Per request.** The first audit row written for a request mints an id and keeps it on the underlying Django request as `tec_tac_request_id`. Every later row of the same request shares it. A DRF `Request` and the `HttpRequest` it wraps agree.
- **`audit.request_correlation_id(request)`** returns that id, minting and keeping it if it is not there yet. A module backend reads it to stamp its own parent row, so the parent row and the Tactical operation rows it triggers share one id:

  ```python
  from tec_tac import audit
  from tec_tac.tactical_operations import run_tactical_operation

  cid = audit.request_correlation_id(request)
  audit.record(actor=request.user, module_id="patching", action="run", object_type="agent", object_id=agent_id,
               message="Bulk patch install started.", request=request, correlation_id=cid)
  run_tactical_operation(request, "patching", "install-updates", params, body)  # same request, same id
  ```

- **Per job.** A backend that works across requests or in a Scheduler run passes its own `correlation_id=` to `audit.record` and to `run_tactical_operation` (1.17.16, see `docs/tactical-operations.md`).
- **An explicit id wins** over the request id and never replaces it.
- **Core sets it, a browser never does.** The attribute name `tec_tac_request_id` is Core's. A browser header is never read, and the audit endpoints refuse a `correlation_id` field.
- Two requests always get two different ids.

## Tactical compatibility and payload limits

Core writes through Tactical's existing `AuditLog.objects.create()` and uses Tactical field names:

- `username`
- `action`
- `object_type`
- `before_value`
- `after_value`
- `message`
- `debug_info`

Tactical's existing `AUDIT_MAX_VALUE_BYTES` handling therefore remains authoritative for `before_value`, `after_value`, and final `debug_info` persistence. Core also pre-checks module `metadata` and replaces oversized metadata with a safe error marker. Since 1.16.0 Core also measures the whole `debug_info`: if it is still over the limit, module `metadata` is replaced first, then `operation_context`. The Core keys (`source`, `module_id`, `module_version`, `correlation_id`, `actor_*`) are never dropped, and the `browser_provenance` marker survives.

Tec-Tac object types and controlled action values may extend Tactical's display choices. Tactical stores these fields as normal character columns and its audit serializer/filter path returns their raw values.

## Failure behavior

Audit persistence is **non-strict by default**. A database/audit writer failure:

1. is logged by Core at error level;
2. returns `recorded: false`;
3. does not normally undo an already-successful business action.

Core-owned workflows may explicitly pass `strict=True` to the backend `record()` function when compliance requirements make audit persistence transaction-critical. Modules should not choose strict mode casually.

Contract validation failures (invalid module ID, unauthenticated actor, invalid action/object type) are programming/authorization errors and are raised/rejected rather than silently ignored.

## Declared browser events for permissionless modules (Core 1.16.0, extended in 1.17.0, deprecated in 1.17.7)

**Deprecated since Core 1.17.7.** The path behaves exactly as in 1.17.6, and no manifest key is removed. Core now adds the response header `Deprecation: true` to every response on this path and logs one warning per module per process when a module posts a declared event. No end date is set. Core removes the path in the first release after every module has switched, and not before. The permissioned-module browser path (`can_record_from_browser`) is not deprecated.

Each declared event has a replacement:

| The declared event is... | Replace it with |
| --- | --- |
| a record of a Tactical call the module's page makes (reboot, Wake-on-LAN, a report change, code signing) | a registered Tactical operation (`docs/tactical-operations.md`). Core runs the call and writes the row. |
| a record of the module's own backend action (a Core update job, an installer run) | `tec_tac.audit.record` from the module's backend route, after the action succeeds. |
| a browser-only event with no server action | nothing yet. It stays declared until the module drops it. |

After a module has moved every event, it removes `audit_events` from its manifest. A module that does so can drop its `requires.framework` of `>=1.16.0` for this key.

Some UI modules have no permission groups, because Tactical's own permissions already decide who may use them. Take Control and Remote Background are examples. Before 1.16.0 they had no way to write an audit trail from the browser. A module like this can now declare the events it posts in `tec_tac.json`:

```json
{
  "id": "take-control",
  "requires": { "framework": ">=1.16.0" },
  "audit_events": [
    { "object_type": "agent", "actions": ["view", "run", "custom:remote-session"] }
  ]
}
```

Rules for the key:

- Each entry has only `object_type` and `actions`.
- `object_type` is a lowercase slug (`^[a-z][a-z0-9_-]{0,99}$`). Since 1.17.0 any such slug may be declared, for example `licence_key`. `client`, `site` and `agent` are the types `core.resources` can scope-check; any other type has **no scope check** (see below).
- Each action is a standard action or `custom:<slug>`.
- Core rejects the manifest for unknown keys, a repeated `object_type`, an empty or repeated `actions` list, more than 20 entries or 20 actions, or a reportset that declares the key.
- A module that declares `permission_groups` and `audit_events` keeps the permissioned path above. Core ignores `audit_events` for it.
- Core older than 1.16.0 rejects the unknown key, so a module that declares `audit_events` must set `requires.framework` to `>=1.16.0`. Core 1.16.x also rejects any `object_type` other than `client`, `site` and `agent`, so a module that declares another type must set `requires.framework` to `>=1.17.0`.

What Core does with a `POST /api/tfd/audit/record/` for such a module:

1. Core runs every existing check first: JSON object, no actor or provenance fields, no unknown fields, and no `module_id` of `core`.
2. If the module has no permissions, Core accepts the request only when the module is installed, enabled, not legacy, and declares that exact `object_type` and `action`. Anything else gets HTTP 403 and writes nothing.
3. For `client`, `site` and `agent`, `object_id` is required (HTTP 400 if missing). Core resolves the object through `core.resources` with the signed-in user's own scope. For any other declared type, `object_id` is optional (at most 255 characters, HTTP 400 otherwise), Core makes no `core.resources` call and records the event under the signed-in user with the marker.
4. An object that is missing, or outside the user's client or site scope, gets HTTP 404. The message is the same for both, so Core does not reveal that the object exists. A role without Tactical's `can_list_*` permission for the type gets HTTP 403. The module's event is not recorded in either case.
5. Core writes one Core-owned `deny` row instead, so the attempt stays in the log. It carries the signed-in user, the module id, the declared `object_type`, the `object_id`, and `metadata` with `refused_action`, `reason` (`not_found` or `permission_denied`) and the HTTP `status`. The message is one of two fixed Core texts, one per reason, with none of the module's text: the object is missing or outside the user's scope, or the user's role lacks Tactical's permission to list that object type. The row also sets `debug_info.operation_context.core_refusal = true`. Only Core sets that key. The payload cannot carry `operation_context` (HTTP 400), and a backend `record()` call that supplies `core_refusal` is a contract error.
6. In scope, Core records the module's event. The actor, module id, version, source and correlation id stay Core-owned. The response is HTTP 201, or 202 if Tactical's AuditLog write failed.

Every row on this path carries `debug_info.operation_context.browser_provenance = "module-declared-event"`. That covers accepted rows, Core `deny` rows and rows whose `metadata` or `operation_context` was too large to store. When Core has to replace an oversized value with a "value too large" marker, it replaces the larger of `metadata` and `operation_context` first, and a replaced `operation_context` keeps `browser_provenance` and `core_refusal`.

**Module-declared `deny` events (1.17.0).** A module may list `deny` in `audit_events`, for example to record a 403 that Tactical itself returned for `can_use_mesh` or `can_manage_winsvcs`. Core records that event like any other declared event: the marker, no `core_refusal`. A reader can therefore tell the module's row (no `core_refusal`) from Core's own refusal row (`core_refusal = true`). An event the module did not declare stays HTTP 403 and writes nothing, because that is a wrong manifest and not a user being denied.

What this path cannot prove: Core cannot tell that the module's code sent the request. A signed-in user could post a declared event about an agent they can already see, or, for a type with no scope check, about any object id. The marker lets the Audit module and reviewers tell these rows from backend-written ones. The event describes an action and never authorizes it.

Johan accepted this path on 30 September 2026 (board Q36) on the conditions in `docs/review-accepted-decisions.md` AD-8: the marker on every row, the scope check for client, site and agent, actor and module id set by Core, and events that describe an action and never authorise it. On 9 October 2026 he chose the server-side path as the end state (AD-19, CQ6 and CQ17): a browser can be manipulated, so Core writes the row where the call happens. That is why this path is deprecated in 1.17.7. It is removed in the first Core release after the last declaring module has switched, with no fixed date (CQ18, option a). Until then it keeps every AD-8 condition.

The path uses the same rate limit as the permissioned path: 60 requests a minute and 1 000 a day for each user and IP. Refused requests and deny rows count.

Modules that do not declare `audit_events` behave exactly as before (HTTP 403).

## HTTP endpoint

The module-scoped browser helper uses:

```text
POST /api/tfd/audit/record/
```

The endpoint requires the normal authenticated Tec-Tac session guard. It derives the actor from `request.user` and rejects client-supplied identity/provenance keys.

## Security rules

- Never accept `username` from a module event.
- Never let a module override `source`, `module_version`, or request/correlation provenance.
- The requested module must exist and be enabled.
- Browser audit writes are allowed only for (a) modules that declare an explicit module permission surface, or (b) permissionless modules for the exact `object_type` and `action` they declare in `audit_events`, on an object inside the signed-in user's scope (client, site and agent; other declared types have no scope check). Core, undeclared events, disabled or unknown modules, and legacy modules are rejected with HTTP 403 because Core cannot prove module provenance for a browser-originated request. Path (b) rows carry a `browser_provenance` marker.
- Users without access to a permission-bearing module cannot use its browser audit writer.
- When an enabled module with no declared permissions and no `audit_events` is exposed to the browser runtime, Core logs a warning once per module per process that `/api/tfd/audit/record/` will return HTTP 403 for that module. The module must declare an explicit permission, or declare its events in `audit_events`, before exposing a browser audit surface.
- The UI may hide a module audit affordance when the user lacks a module grant, but Core remains authoritative: direct `POST /api/tfd/audit/record/` attempts return HTTP 403 for Core, legacy modules, permissionless modules that did not declare the event, or actors without an effective module grant. Declared events also return HTTP 404 or 403 when the object is outside the user's scope. Modules must treat that 403 as an authorization result, not as an audit-service failure.
- Audit records describe an action; they do not authorize that action.
- Never place secrets, passwords, API tokens, private keys, or full credential payloads in `before`, `after`, or `metadata`.


## Non-human audit actors

Scheduled jobs, background workers and device/probe callbacks must not create fake Tactical users. Core exposes two public constructors:

```python
from tec_tac.audit import record, service_audit_actor, device_audit_actor

actor = service_audit_actor(module_id="networkprobe", service="scheduler", identity="networkprobe.scan")
record(actor=actor, module_id="networkprobe", action="run", object_type="network_scan")

probe = device_audit_actor(module_id="networkprobe", device_id="probe-42", identity="branch-probe-42", service="callback")
record(actor=probe, module_id="networkprobe", action="sync", object_type="probe_result")
```

Core stores human/service/device provenance in Tactical AuditLog-compatible rows. Non-human actors are module-bound: their `module_id` must match the event's `module_id`. The readable Tactical `username` is prefixed `service:` or `device:`, while structured provenance is retained in `debug_info`. `build_operation_context(...)` may be passed directly as `operation_context=...`; Core retains source/run/requested-by fields and uses an included `correlation_id` when no explicit correlation ID is supplied.

## Core's own refusal row (1.17.21)

For a Tactical operation that is not `GET`, Core writes one Core-only `custom:operation-failed` row (`failure: core_refused`, metadata `code`) when
it refuses `body_field_not_allowed`, `invalid_body`, `invalid_params`, `scope_field_required`, `invalid_correlation_id` or `invalid_audit_before`
before calling Tactical. A module checks `error.audit`: when it is not `None`, Core has written the row and the module writes none. See `docs/tactical-operations.md`.

## Core's own module preference rows (1.17.38)

`core.module_preferences` (capability 1.2.0) writes its own rows, through `tec_tac.audit.record` with `module_id` `core`, for each real
change of one person's module preference. The object type is `module_preference`, the object id is `<module_id>/<name>`, and the actions are
`add`, `modify` and `delete`. The metadata holds `module`, `name`, `source` (`module_python` or `browser`), `module_verified`, `user_id`
and, for `add` and `modify` only, `size_bytes`. The stored value is never in the row. The rule is AD-19 condition 5; see
`docs/module-preferences.md`.
