# Tactical operations: Core runs the call and writes the audit row

**Status:** Public Core developer contract, added in Core 1.17.7
**Python:** `tec_tac.tactical_operations`
**Capability:** `core.tactical_operations` 1.0.0, owner `core`
**HTTP:** `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/`

## Why this exists

A browser can report an audit row, but a browser can also misreport it. Before 1.17.7 a module's page called Tactical
through Core's browser transport, so no backend saw the call. The audit row had to come from the browser, or from the
module's own backend route after the page said what happened.

With a Tactical operation, Core runs the Tactical call on the server for the signed-in user. Core writes the audit
row where the call happens, from Tactical's real answer. The browser names an operation. It never names a path and it
never reports an outcome.

This is mode (a) of the backend transport: a call made by a person who is signed in. Background runs as the owner of
a schedule (mode b) are a different contract (AD-13) and are not part of this release. This path needs an
authenticated request, so a Celery task cannot call it.

## What a module declares

The owning core module declares each operation once, in code, from `AppConfig.ready()`. It is the same pattern as
registering a capability or a Scheduler action.

```python
from tec_tac.tactical_operations import register_tactical_operation

register_tactical_operation(
    "reboot",                                  # id: lowercase slug, unique for the module
    "agents",                                  # module_id: the owning core module
    "POST",
    "agents/{agent_id:agent}/reboot/",         # a Tactical route template, never a free path
    ["can_reboot_agents"],                     # Tactical Role flags. All are required.
    [{"type": "agent", "source": "path:agent_id"}],
    ["mode", "datetime"],                      # body_fields: the only JSON keys allowed
    {"action": "run", "object_type": "agent", "audit_fields": ["mode"]},
    module_permission=None,
    message=None,
)
```

| Argument | Meaning |
| --- | --- |
| `id` | Lowercase slug, for example `reboot` or `wake-on-lan`. Unique within the module. |
| `module_id` | The owning core module: its manifest says `category: core` and it owns the route in Core's route owner table (see "Who may declare where" below). Core refuses `core`, an unknown, legacy or disabled module, a module that is not a core module, and a core module on a route it does not own. The one named exception is Licensing, which owns `core/codesign/` (AD-16). |
| `method` | `GET`, `POST`, `PUT`, `PATCH` or `DELETE`. |
| `route` | Tactical's route as a template, no leading slash. `{name}` is a text parameter (letters, digits, `_`, `.`, `-`). `{name:int}` is a whole number. `{name:agent}` is an agent id (21 characters or more, as Tactical's `agent` converter needs). A route may not start with a parameter. |
| `permissions` | Tactical Role flags, for example `can_reboot_agents`. Each must be a boolean `can_*` field on Tactical's Role. The caller needs all of them. At least one is required. |
| `scope` | A list of `{type, source}`. `type` is `agent`, `client` or `site`. `source` is `path:<name>` or `body:<field>`. A list in a body field is checked id by id. May be empty for an operation with no object. |
| `body_fields` | The whitelist of JSON body keys. Any other key is refused with 400. A `GET` takes none. |
| `audit` | `{action, object_type, audit_fields}`. `action` is a standard audit action or `custom:<slug>`. `audit_fields` names the body keys copied into the row's `after`. Never secrets: Core refuses names that look like a password, token or key. |
| `module_permission` | Optional. A Tec-Tac permission codename, checked with `has_extension_permission` as well as the Tactical flags (AND). A superuser passes. Use it only where a Tec-Tac permission is a real extra rule, such as AD-16 for Licensing (`licensing.manage` plus Tactical's `can_code_sign`). It is not a copy of a Tactical permission (AD-5). |
| `message` | Optional fixed text for the audit row. One line, 255 bytes at most. |

### Who may declare where

Since 1.17.8 ownership is per route, not per Tactical group. Core holds an ordered table of route prefixes (`ROUTE_OWNERS` in `tec_tac/tactical_operations.py`; Core-internal, not a module contract). A `{}` stands for a parameter segment. Core finds the longest prefix a route starts with and applies only that rule, so a sub-route homed elsewhere cannot be claimed through its group. One rule, `agents/{}/{}/webvnc/`, names a single route and matches only a path of exactly that length, so `agents/<id>/eventlog/webvnc/<days>/` stays the eventlog route. An empty owner means the prefix is Core's own, or no core module owns it yet: every module is refused. The table follows the function map (`reviews/modules/tactical-function-map.json`), AD-11, AD-16 and AD-18.

| Route prefix | Who may declare |
| --- | --- |
| `clients/`, `clients/sites/`, `clients/{}/` | Nobody. Clients and sites are Core's (AD-11). |
| `clients/deployments/`, `clients/{}/deploy/` | `agent-management` |
| `core/codesign/` | `licensing` only (AD-16) |
| `core/settings/`, `customfields/`, `keystore/`, `urlaction/`, `emailtest/`, `smstest/`, `clearcache/`, `servermaintenance/`, `version/`, `webtermperms/` | `globalsettings` |
| `core/schedules/` | `reportmanager` |
| `core/serverscript/` | `scriptmanager` |
| `core/openai/`, `core/dashinfo/`, any other `core/` route | Nobody |
| `agents/` (everything not listed below) | `agents` |
| `agents/{}/cmd/` | `remote-background` (AD-18) |
| `agents/{}/{}/webvnc/` | `take-control` (AD-18) |
| `agents/{}/runscript/` | `scriptexecution` |
| `agents/{}/meshcentral/` (and `recover/`) | `take-control` |
| `agents/{}/processes/`, `registry/`, `eventlog/`, `terminal-defaults/` | `remote-background` |
| `agents/update/`, `agents/versions/`, `agents/bulkrecovery/`, `agents/{}/recover/` | `agent-management` |
| `logs/pendingactions/` | `agents` (AD-18) |
| `logs/audit/` | `audit` |
| `logs/debug/` | `debug` |
| any other `logs/` route | Nobody |
| `automation/patchpolicy/` | `patching` |
| `automation/` (the rest) | `automation` |
| `reporting/` | `reportmanager` |
| `alerts/`, `scripts/`, `checks/`, `software/`, `tasks/` | `alerts`, `scriptmanager`, `checks`, `software`, `tasks` |
| `services/` | `remote-background` |
| `winupdate/` | `patching` |

Endpoints is the technician workspace. It composes what other modules publish, so it owns no route and declares no operation. Core refuses a non-owner when it registers, so a module outside its home cannot take a route first and block the owner on the one-caller rule.

**Parameter kinds decide what a route can reach (1.17.9).** A parameter can hold any value, so Core judges a template by every route it can land on. A parameter of kind `agent` (21 characters or more) or `int` (digits) can never hold a route word such as `registry` or `update`, so it only ever stands for an ordinary value. A plain `{name}` parameter can hold a route word, including one with more route after it: `agents/{agent_id:agent}/{p}/create-key/` can be `agents/<id>/registry/create-key/`, which is Remote Background's, so Agents is refused. Declare an agent id as `{agent_id:agent}`.

**Core re-checks ownership at dispatch (1.17.9).** After the concrete path is built, Core finds the rule that path lands on and answers 404 `tactical_operation_not_found` unless the operation's module is an owner of that rule (or the named Licensing exception). Core reads the owner table and module state again, so an operation that slipped into the registry in this process cannot reach another module's route, and a replacement's operation stops working the moment it is no longer honoured, before any restart.

**A replacement joins the replaced module's rules (AD-20, 1.17.9).** A module that is not a core module may declare `replaces = "<core module id>"` in its manifest. While Core honours that (see `docs/module-replacement.md`), the replacement is an owner of every rule the replaced core module owns, and of no other. For Windows Patching that is `winupdate/` and `automation/patchpolicy/`. Core's own rules, a rule with no owner, and every rule the replaced module does not own stay refused. The moment the replacement is disabled, or the core module is enabled again, the replacement is refused again. A premium module with no declared and honoured `replaces` is still refused. Since 1.17.11 the replaced module may also be a server module, but a server module has no Tactical routes, so an honoured replacement of one joins no rule. Licensing's `core/codesign/` route, a named exception, stays with Licensing.

### What Core refuses at registration

- A module that is not a core module (bar Licensing's named exception and an honoured replacement, AD-20), and a core module declaring a route it does not own (table above). A route the table does not list is refused until a Core release adds it. A route a plain `{name}` parameter could steer onto a route another module owns.
- A route under `accounts/`, `api/tfd/`, `api/v3/`, `api/v4/`, `_allauth/`, `logout`, `logoutall`, `v2/` or `agents/installer`. Those are Core's own or agent-facing. A parameter value can never reach them either.
- `..`, a leading slash, a query string, a percent sign, or anything outside the route grammar.
- A second operation on the same method and route, even with a different parameter name. This enforces "one caller per Tactical route" (AD-6 condition 4) at run time. Registering the identical operation again changes nothing.
- A permission flag that is not a boolean `can_*` field on Tactical's Role.
- A scope source that is not a parameter of the route or one of the `body_fields`, and an `int` requirement for client and site path parameters.
- Audit action `deny` and `custom:outcome-unknown`. Only Core writes them.
- A legacy, unknown or disabled module.

The registry is empty until a module declares an operation. Installing Core 1.17.7 changes nothing for a module that
declares none.

A module needs `requires.framework` of `>=1.17.7` to use any of this.

## How a call runs

`run_tactical_operation(request, module_id, operation_id, params=None, body=None)` and the HTTP route run the same code.

1. The operation exists and its module is enabled. Otherwise 404 `tactical_operation_not_found`.
2. The caller is authenticated. Otherwise 401.
3. Core re-checks every Tactical flag with `rbac.has_tactical_permission`. A superuser or role superuser passes. An installer user, or a user with no role, is denied.
4. If the operation names a `module_permission`, Core checks it.
5. Core checks the body size and shape, then the scope: every declared object must exist inside the role's client and site limits. Core checks the limits only. It does not ask for `can_list_*`, because Tactical's own check for the operation does not, and a second gate would break AD-5. A missing object and an out-of-scope object give the same 404 text.
6. Core whitelists the body keys and the parameters, and caps the body at 256 KiB.
7. Core dispatches in this process to Tactical's own view for that route. It uses a copy of the incoming request with the path, method and body replaced, authenticated as the signed-in user. No Knox token is read or forwarded, no HTTP call is made, and no key or service account exists. Tactical's own permission and scope classes and its validation run again. Tactical's own audit rows stay attributed to the signed-in user. If Tactical renamed the route, Core returns 502 `tactical_route_changed`. It never falls back to another path.
8. Core writes the audit row from Tactical's answer.
9. Core relays Tactical's status and body unchanged.

A refusal in steps 3 to 5 writes a Core `deny` row. The text is fixed Core wording and carries nothing from the module.
Steps 1 and 2, and a bad parameter or body, write no row because no operation was attempted.

### The audit row

Core writes the row with the signed-in user as actor and the declaring module as `module_id`.

| Tactical answers | Core writes |
| --- | --- |
| 2xx | the declared action, `object_id` from the scope object, `after` from `audit_fields`, and metadata with the operation, method, route template and Tactical status |
| 401 or 403 | a Core `deny` row (`core_refusal`, reason `tactical_denied`) |
| 5xx, or an error after dispatch, on a call that is not `GET` | `custom:outcome-unknown`, because the change may have happened |
| any other 4xx | nothing, because nothing changed |

Every row carries `operation_context.server_provenance = "tactical-operation"`, `operation` and `tactical_status`
(null when Core refused before calling Tactical). Only Core sets these keys. The public `tec_tac.audit.record` refuses
them.

Core writes the row after the call. A failed audit write cannot undo Tactical's change, so it is not fatal. Core logs
it at error level and sets the response header `X-Tec-Tac-Audit` to `recorded` or `not-recorded`. The header appears
when a row was due. For a Python caller, `TacticalOperationResult.audit` says the same.

## HTTP

```text
POST /api/tfd/tactical-operations/agents/reboot/
{"params": {"agent_id": "..."}, "body": {"mode": "now"}}
```

The reply is Tactical's own status and body. Core's own refusals are JSON `{"detail", "code"}`. Codes:
`tactical_operation_not_found`, `authentication_required`, `tactical_permission_denied`, `module_permission_denied`,
`object_not_found`, `invalid_params`, `invalid_body`, `body_field_not_allowed`, `scope_field_required`,
`body_too_large`, `tactical_route_changed`, `tactical_call_failed`, `tactical_response_refused`.

A file answer, such as a report export, is relayed with its `Content-Type` and `Content-Disposition`, up to 25 MiB.
A streaming answer is refused. Rate limit: 120 a minute and 5 000 a day for each user and IP.

## Python

```python
from tec_tac.capabilities import get_capability

ops = get_capability("core.tactical_operations", version=">=1,<2")
result = ops.run(request, "agents", "reboot", {"agent_id": agent_id}, {"mode": "now"})
result.status, result.data, result.audit
```

`run` returns `TacticalOperationResult(status, data, content_type, headers, audit, content)`. Core's own refusals raise
`TacticalOperationError` with `status`, `code`, `message` and `audit`. `list_operations(module_id=None)` and
`get_operation(module_id, operation_id)` return plain metadata rows.

## AD-19 conditions

Johan accepted this path on 9 October 2026 (AD-19, `docs/review-accepted-decisions.md`) on five conditions. Each has a test in `tests/tactical-operations-1.17.7.py`.

1. **Only a declared operation runs.** The owning core module declares it. Core refuses a non-owner or a route outside the owner's group at registration (`tests/tactical-operations-1.17.7.py`), and an unknown operation gives 404.
2. **The signed-in user's own identity.** Core resolves the route with Django's resolver and calls Tactical's view in-process, on a copy of the request with forced authentication. The `Authorization` header and cookies are dropped. Core reads no Knox token, makes no HTTP call and holds no key. An installer user and a user with no role are denied. Tactical's own permission, scope and validation still run. If Tactical renamed the route, the answer is 502 `tactical_route_changed`, with no fallback.
3. **A failed audit write is not fatal.** Tactical's change has already happened. Core logs the failure at error level and sets `X-Tec-Tac-Audit: not-recorded`. A Python caller reads `TacticalOperationResult.audit`.
4. **Outcome rows.** 2xx writes the declared action. 401 or 403 writes a Core deny row. A 5xx, or an error after dispatch, on a call that is not GET writes `custom:outcome-unknown`. Other 4xx write nothing. Core's own refusals write a deny row with a fixed Core text.
5. **Tec-Tac's own functions are audited too.** Core and the module's own routes (`module_id` `core`, anything under `api/tfd/`) are not Tactical operations, so the executor refuses them. A module's backend action calls `tec_tac.audit.record` from its route instead. Both paths write the same row: actor, module, action, object, `module_version`, `correlation_id`, `operation_context` and `metadata`. Only the Tactical-operation row carries `server_provenance`, so an auditor can tell the two apart.

## Tactical permission flags in the runtime context

`GET /api/tfd/ui/context/` carries `tactical_permissions` since 1.17.7: every boolean `can_*` field on Tactical's Role, mapped to true or false for the signed-in user. Core computes it with one role lookup (`tec_tac.rbac.tactical_permission_catalog`). A superuser or role superuser has every flag. An installer user, a user with no role and any lookup failure have none. It adds no Tec-Tac permission and reads only the user's own role. It is a hint for the page: Tactical still decides every call.

## Browser helpers

The UI gives modules two helpers for this path. They are documented as browser contract rows, `ui.authenticated.tactical-operation` (`tacticalOperation(moduleId, operationId, options)`) and `ui.authenticated.tactical-permissions` (`hasTacticalPermission(flag)`). The rows state what Core checks and the rule that a module passes its own id. They add no HTTP contract, executor or permission change.

The rule is: a module passes its own id, except for the AD-20 module it replaces. From UI 0.12.88 the shell enforces it for `tacticalOperation`. It reads the replaced id from `descriptor.replaces` or from the module's row in `module_status`, and it fails closed when the row carries no `replaces`. Core sends `replaces` in each `module_status` row of `GET /api/tfd/ui/context/` since 1.17.11 (the declared value, or null; see `docs/module-replacement.md`). From UI 0.12.89 `api`, `apiRaw`, `apiBlob` and `apiText` refuse a tactical-operations path for an id other than the module's own id or the one it replaces. The replaced id is a snapshot taken before any `register()` runs. The guard is a helper-level guard, not a sandbox: a module that calls `fetch` itself is not stopped by it. Core's own checks stay the authority: the operation is declared by the module id in the URL, the user holds the Tactical permission and the role scope, the route is owned, and the replacement is honoured. A path hidden behind tab, CR, LF or other control characters is a finding held for the UI.

## What this does not do

- It does not run a Tactical function itself. The owning core module decides which operations exist. Core only runs them.
- It does not run background work. Mode (b), the Scheduler running as the schedule owner, is the AD-13 system-action contract.
- It does not replace `tec_tac.audit.record` for a module's own backend action. Use `record` from the backend route for that.
