# Tactical operations: Core runs the call and writes the audit row

**Status:** Public Core developer contract, added in Core 1.17.7
**Python:** `tec_tac.tactical_operations`
**Capability:** `core.tactical_operations` 1.12.0 (1.11.0 before Core 1.17.43, 1.10.0 before Core 1.17.41, 1.9.0 before Core 1.17.28, 1.8.0 before Core 1.17.26; major 1, additive since 1.0.0), owner `core`
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
| `route` | Tactical's route as a template, no leading slash. `{name}` is a text parameter (letters, digits, `_`, `.`, `-`). `{name:int}` is a whole number. `{name:agent}` is an agent id (21 characters or more, as Tactical's `agent` converter needs). `{name:service}` is a Windows service name (since 1.17.41, see "Added in 1.17.41"). A route may not start with a parameter. |
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
| `agents/{}/tasks/` | `tasks` (1.17.18) |
| `agents/{}/checks/` | `checks` (1.17.18) |
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

The terminal socket (`docs/tactical-websocket.md`) has the same owner as `agents/{}/terminal-defaults/` (1.17.31): the two come from
the one table. `remote-background` may declare `GET agents/{agent_id:agent}/terminal-defaults/` (flag `can_use_terminal`, scope from
`path:agent_id`, audit `view`). Every other module, including `agents` and `endpoints`, is refused the same route, and so is a premium
module that is not an honoured replacement. Core adds nothing to the executor for it.

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
- Audit action `deny`, `custom:outcome-unknown` and `custom:operation-failed` (1.17.20). Only Core writes them.
- A `server_only` that is not true or false (1.17.19).
- A legacy, unknown or disabled module.

The registry is empty until a module declares an operation. Installing Core 1.17.7 changes nothing for a module that
declares none.

A module needs `requires.framework` of `>=1.17.7` to use any of this.

## How a call runs

`run_tactical_operation(request, module_id, operation_id, params=None, body=None, query=None, upload=None)` and the HTTP route run the same code. The steps below are as of 1.17.13: see "Added in 1.17.13" for the before-read (between steps 6 and 7, for the audit row only since 1.17.14), the query string and the file.

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
Steps 1 and 2 write no row because no operation was attempted. Since 1.17.21 six refusals of the validation step write one Core row
for a call that is not `GET` (see "Added in 1.17.21"). The other validation refusals still write none.

### The audit row

Core writes the row with the signed-in user as actor and the declaring module as `module_id`.

| Tactical answers | Core writes |
| --- | --- |
| 2xx | the declared action, `object_id` from the scope object, `after` from `audit_fields`, and metadata with the operation, method, route template and Tactical status |
| 401 or 403 | a Core `deny` row (`core_refusal`, reason `tactical_denied`) |
| 5xx, or an error after dispatch, on a call that is not `GET` | `custom:outcome-unknown`, because the change may have happened |
| any other 4xx on a call that is not `GET` (1.17.20) | `custom:operation-failed`, with the declared action in `metadata.declared_action`, `result: failed`, a fixed Core text, and no before or after value |
| Core's own refusal before Tactical is called, on a call that is not `GET` (1.17.21): `body_field_not_allowed`, `invalid_body`, `invalid_params`, `scope_field_required`, `invalid_correlation_id`, `invalid_audit_before` | `custom:operation-failed`, with `failure: core_refused` and the refusal `code` in the metadata, a fixed Core text, and no before or after value |
| any 4xx on a `GET` | nothing, because nothing changed |

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
`body_too_large`, `tactical_route_changed`, `tactical_call_failed`, `tactical_response_refused`, and since 1.17.19 `operation_server_only`.

The `tactical_permission_denied` detail names the missing Tactical permission since 1.17.19, for example "It needs the Tactical permission can_reboot_agents." (several are listed when several are missing). The code is unchanged, and so is the text of the deny row.

A file answer, such as a report export, is relayed with its `Content-Type` and `Content-Disposition`, up to 25 MiB.
A streaming answer is refused unless the operation declares `file_response` (since 1.17.41). Rate limit: 120 a minute and 5 000 a day for each user and IP.

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

## Added in 1.17.13

Everything here is optional. An operation declared the 1.17.12 way registers and runs exactly as before. The capability
`core.tactical_operations` is now `1.1.0` (it was `1.0.0`). Every caller asks for `>=1,<2`, so nothing breaks. A module that uses any
key below needs `requires.framework` of `>=1.17.13`.

### Name the audit object: `audit.object_param`

`audit.object_param` names a path parameter of the route. Its value is the audit row's `object_id`, with the declared
`audit.object_type`. It is written on every row: success, deny, outcome-unknown and failed. It is also the object hint on a refusal at steps
3 and 4. It must name a real parameter of the route, or registration is refused. Without it, `object_id` comes from the first scope
object, as before.

```python
audit={"action": "delete", "object_type": "report_template", "audit_fields": [], "object_param": "pk"}
```

### Read the object first: `audit.before`

`audit.before = {"route": ..., "fields": [...]}` gives the row a before value. `route` is a Tactical `GET` route that returns the
object. Its parameters must be among the operation's own parameters, with the same names and kinds, and the same module must own it
(the same owner check as the operation). `fields` is a list of at most 32 top-level names (16 before 1.17.18). None may look like a secret.

Before it dispatches the change, Core runs that `GET` in this process through Tactical's own view, as the signed-in user. It uses the
same helper as the operation, so there is no HTTP call and no token. It copies only the listed fields. A string is cut to 256
characters. A value that is not a string, number, true, false or null is dropped. The result is the row's `before_value`.

A read that fails or does not answer 200 never blocks the change. The row is still written, and its metadata says `before:
unavailable` with the read's `before_status`. A `GET` operation has no before value.

### Scope from the read: removed in 1.17.14 (CQ37)

Core 1.17.13 let a scope entry read its object from the `before` answer: `{"type": "agent", "source": "before:agent_id"}`. Johan asked
for it to go (CQ37, 9 October 2026), so **1.17.14 removes the `before:<field>` source**. Registering one is refused with a plain message.
The check Core ran on that read, and the fixed 404 `object_not_found` it gave when the read did not answer 200, are gone with it.

An operation that has only an object id declares `scope: []` and `audit.object_param`. Tactical's own check then decides, as it does
for `cancel-pending-action`. For `PUT` and `DELETE agents/notes/<pk>/` that is the declaration:

```python
route="agents/notes/{pk:int}/", scope=[], audit={"action": "modify", "object_type": "agent_note", "audit_fields": [], "object_param": "pk"}
```

Tactical's own view then answers 403 for a note on an agent the role cannot see, and 404 for a note that does not exist. Core relays the
answer, and writes a deny row for the 403. The row still names the pk as the object. Core still re-checks the Tactical flag first.

`audit.before` is unchanged. It is an audit value only: it fills the row's before value, and a read that fails or does not answer 200
never blocks the change. A role that may manage notes but not list them can now edit a note, and the row records that no before value
was kept. Nothing in `modules/` declared `before` or a `before:` source when it was removed. Agents declares its note operations on
Core 1.17.14 or later (a request to the Agents module).

### Scope type from the body: `body:<field>`

`{"type": "body:type", "source": "body:id", "type_map": {"Client": "client", "Site": "site"}}` takes the scope type from a body
field. `type_map` maps each allowed value to `client` or `site`, with at most 8 entries. A value outside the map is refused 400
`scope_field_required`. The resolved type is written to the row metadata as `scope_type`. `POST agents/maintenance/bulk/` uses this.

### A query string: `query_params`

`query_params` is a whitelist of up to 16 names. Until 1.17.41 only a `GET` operation could declare it. Any method may since then (Tactical's registry delete reads `request.query_params` on a `DELETE`). It is the new last argument of `register_tactical_operation`. A
name may not look like a secret, because a query string is logged. The caller sends `query` (a flat object):

- Each value is a string or a whole number of at most 512 characters.
- No control characters, and no `..` path segment (also after one level of percent-decoding).
- A name outside the whitelist gives 400 `query_field_not_allowed`. A bad value gives 400 `invalid_query`.

Core builds the query string and sets `GET` on the forwarded request, so Tactical's `request.query_params` sees it. `audit_fields` may
name a body field or a query name. The value is copied into `after`.

### One file: `upload`

`upload = {"field": "file", "max_bytes": 1000000, "extensions": ["png", "jpg"]}` lets a `POST`, `PUT` or `PATCH` operation forward exactly
one file. The ceiling is a system setting, 10 MiB by default (see "The upload ceiling is a setting (1.17.14)" below). Each operation declares its own lower cap. The extension list is lower
case, has no dot and may not be empty. The field name may not be `params`, `body`, `query` or a body field.

`run_tactical_operation(..., upload={"name": ..., "content_type": ..., "content": bytes})` and the HTTP route take it. Core:

1. cleans the file name (no path, at most 255 characters, no control characters) and checks the extension against the list;
2. checks the size against the cap before it reads the file;
3. builds its own `multipart/form-data` payload with a random boundary and the text parts from `body`, with no `django.test`;
4. forwards it, so Tactical's own `MultiPartParser` reads the file and the text fields.

Name the part after the file when Tactical wants that. Tactical's report asset upload (`POST reporting/assets/upload/`) stores each
file under the name of its multipart part, not under the `filename` attribute. For such an operation declare
`"field": "{file_name}"`. Core then names the part after the cleaned file name, and the browser's own part name does not matter. From the
HTTP route, the file name is the part's `filename`, falling back to the part name.

The audit row's `after` records only the file name, size and content type. It never holds the content. Refusals: `upload_not_allowed`
(the operation takes no file, or the part has the wrong name), `upload_too_large` (413), `upload_type_not_allowed`, and `invalid_upload`
(no file, a bad name, content that is not bytes).

### HTTP

The JSON form takes `{"params": ..., "body": ..., "query": ...}`. The multipart form carries the text parts `params`, `body` and
`query` (each a JSON object) and one file part named as the operation declares it. The route checks the declared length before it
parses the request, and the file's size before it reads it. The throttles are unchanged. The browser helper sends `query` and the file
from UI 0.12.91 (a UI request).

### What does not work yet

Nothing here is open for a streamed file answer any more. Since 1.17.41 an operation that declares `file_response=True` relays it (see
"Added in 1.17.41"). An operation that does not declare it still has a streamed answer refused as `tactical_response_refused`, so a module
that declared a download before 1.17.41 keeps its refusal until it adds the keyword.

### AD-21: the category decides

The owner table still says which core module owns a route. Since 1.17.13 the declaring module's **effective category** decides too (a
missing category is `test`; see `docs/module-categories.md`). A `premium`, `server` or `test` module is refused every route, even one the
owner table lists by id. The message names the category. Licensing keeps `core/codesign/` (AD-16). An honoured AD-20 replacement keeps its rights.

## Added in 1.17.14

The capability `core.tactical_operations` is now `1.2.0` (still major 1; callers ask for `>=1,<2`).

### The upload ceiling is a setting (1.17.14)

The largest file one operation may forward is the system setting `tactical_operation_upload_max_mib`: whole MiB, 1 to 25, **default 10**. An
existing install reads 10, the ceiling Core had before. A superuser changes it with `PATCH /api/tfd/system/runtime-settings/` (see
`docs/runtime-settings.md`). The executor and the HTTP route read it on every call, so lowering it takes effect at once with no restart.

- A file is held to the smaller of the operation's own `max_bytes` and the setting. A module's cap of 2 MiB still wins over a setting of 25.
- Registration checks `max_bytes` against a fixed absolute ceiling of 25 MiB (`MAX_UPLOAD_ABSOLUTE_BYTES`), because registration runs in
  `AppConfig.ready()` and must not read the database. A module can never declare more than 25 MiB, whatever the setting says.
- `MAX_UPLOAD_BYTES` is still exported. It is now the 10 MiB default, so no import breaks.
- If the setting cannot be read, Core uses 10 MiB.
- The capability's `limits` report `upload_bytes` (the effective ceiling now), `upload_bytes_default` and `upload_bytes_max`.

A body-size limit in the web server (nginx) or in Tactical still applies in front of Core. Core 1.17.14 does not change either, and it
was not checked from the development PC. If you raise the setting above what the web server accepts, the upload fails before Core sees it.

### The before-read scope source is gone (1.17.14)

See "Scope from the read: removed in 1.17.14" above.

## Added in 1.17.16

The capability is `1.3.0`. It is still major 1, so every caller that asks for `>=1,<2` keeps working. Everything below is optional for a caller, except the request check, which only a caller that passes something other than a real request notices.

### A real request, with Core's session proof

`run_tactical_operation` no longer takes any object that has a `.user`. AD-19 condition 2 says Core never substitutes another user, so the first step now accepts only:

- a Django `HttpRequest`, or a DRF `Request` that wraps one,
- whose user is authenticated,
- and which carries `tec_tac_session`. Core's `SessionAuthenticated` guard sets it, so the session-security check ran for this request.

Anything else is refused with HTTP 401, code `authenticated_request_required` and a fixed Core text. No audit row is written, because there is no trustworthy actor to write.

Real callers are unaffected. Patching and Script Execution call it from views that use `SessionAuthenticated`, and the Core HTTP route is the same. A module's own stub tests that pass a fake request must now pass an object that is an `HttpRequest` and carries `tec_tac_session`. Core's shared test stub (`Request` in `tests/tactical-operations-1.17.7.py`) shows the shape.

### A correlation id from the caller: `correlation_id=`

```python
run_tactical_operation(request, "patching", "set-update-action", params, body, correlation_id="patch-run:42")
```

`correlation_id` is 1 to 128 characters of letters, digits and `. _ : -`. Core writes it on every row of that call: success, deny and outcome-unknown. It is the same value `audit.record(correlation_id=...)` takes, so a module can give its own parent row and each operation row one id. A bad value is refused with HTTP 400, code `invalid_correlation_id`, before anything runs.

For one request, use `tec_tac.audit.request_correlation_id(request)` instead. See `docs/module-audit.md`.

It is Python only. The HTTP view still accepts only `params`, `body` and `query`. A browser can never send a correlation id, and the audit endpoints still refuse one.

### A before value from the caller: `audit_before=`

Some routes have no single-row `GET` to read the old value from (Patching's `set-update-action` and `reset-patch-policy` are examples). For those the caller may assert what the value was:

```python
run_tactical_operation(request, "patching", "set-update-action", params, body, audit_before={"action": "approve", "kb": "KB5031356"})
```

The rules:

- A flat dict of at most 16 fields. Each value is text (up to 256 characters, no control characters), a whole number, `true`/`false` or `null`. Since 1.17.23 a value may also be a list of whole numbers or texts (see "A list in `audit_before`" below). The 16-field limit counts the caller's own fields only.
- Field names follow the operation's field-name rule (a letter or `_`, then letters, digits and `_`, up to 64 characters). A name that looks like a secret (`pass`, `secret`, `token`, `key`, `credential`, `auth`, `cookie`, `signature`) is refused. A nested value (an object, or a list inside a list), a float or an oversize value is refused too. The refusal is HTTP 400, code `invalid_audit_before`.
- Core uses it only when the operation declares no `audit.before` read. When both exist, Tactical's own read wins and the caller's value is ignored.
- It is written on the success row only. A refused or failed call keeps no before value.
- The row metadata says `before: recorded` and `before_source: caller`. A value Core read from Tactical says `before_source: tactical`. A reviewer can tell an asserted value from a read one.
- It is Python only and never available over HTTP.

### What `audit.object_param` already does

The audit object id from a `{pk}` path parameter shipped in 1.17.13 and works with a typed `{pk:int}` since 1.17.14. Core writes the path value as the row's `object_id` on success, deny and outcome-unknown rows. A module only has to declare `object_param`. `tests/tactical-operations-audit-before-1.17.16.py` locks the Report Manager shape (`reporting/templates/{pk:int}/` and the operations below it).

## Added in 1.17.18

Capability `core.tactical_operations` is 1.4.0, still major 1. Every addition is optional. An operation declared the 1.17.17 way
registers and runs exactly as before. A module needs framework 1.17.18 to use any of them. The new refusal codes are
`scope_unrestricted_required` (403) and `body_selector_mismatch` (400).

### Only for a caller with no client or site limits: `caller_scope`

`register_tactical_operation(..., caller_scope="unrestricted")`. Any other value is refused at registration. At run time Core asks
`tec_tac.resources.scope_unrestricted` for the caller, the same answer the UI reads as `tactical_scope.unrestricted`. A caller with
no role, an installer user and a failed lookup count as limited (fail closed).

The check runs after the Tactical flags and the module permission, and before the body is cleaned. It applies to every call of the
operation, including a call whose body names no agent (for example Checks' `add-policy-check`). A limited caller gets 403
`scope_unrestricted_required` with a plain message, and Core writes a deny row (reason `scope_unrestricted_required`). Tactical is
never called. The rule is per operation. The "never applies to a row that belongs to no agent" rule (CQ57: follow Tactical) belongs to a `row_lookup` scope entry, which checks the agent of a loaded row. It is not part of `caller_scope`. The UI hides
the control from `tacticalScope().unrestricted`, so a person normally never sees the refusal (AD-12).

### Scope entries: `optional`, `agent_pk` and `row_lookup`

- `optional: true` (a body source only). Core resolves the entry only when the body field is present and not null. An empty list
  is allowed and checks nothing. When the field is absent the entry is skipped and adds no object id. A client or site entry may
  hold a list of ids (up to 1000). One id out of scope refuses the call with 404 `object_not_found`.
- Type `agent_pk` is for Tactical agent numbers: whole positive integers, one or a list, from a body field or an `int` path
  parameter. Core checks them against the role's client and site limits through `resources_adapter.agent_pks_in_role_scope`.
  `objects_in_role_scope` still matches only the canonical `agent_id` and still refuses pk aliases.
- `row_lookup` is for a route whose path id loads a row, such as a task, a policy check or a patch policy (CQ56 a). The scope entry
  is `{"type": "agent", "source": "path:<int param>", "row_lookup": "<lookup id>"}`. The owning core module registers the lookup:

```python
from tec_tac.tactical_operations import register_tactical_row_lookup

def task_row(pk: str):
    row = AutomatedTask.objects.filter(pk=pk).values("agent__agent_id").first()   # the module's own data
    return None if row is None else {"agent_id": row["agent__agent_id"]}         # None for a policy task

register_tactical_row_lookup("tasks", "task-row", task_row)   # from AppConfig.ready()
```

Rules: the same module and category rules as operations. A module names only its own lookups. The lookup returns `None` when the
row does not exist, or a dict with `agent_id` (a canonical agent id, or `None`). Before dispatch Core calls it in this process:

| Lookup answer | What Core does |
| --- | --- |
| Missing, raises, wrong shape or `None` | 404 `object_not_found`, no detail, deny row. |
| An `agent_id` | Applies the caller's role scope to that agent. Out of scope gives 404 `object_not_found`. |
| `{"agent_id": None}` (policy-level row) | Allowed for anyone who holds the Tactical flag. Tactical decides the rest (CQ57). |

The audit row records the object id from the path id, and the metadata `scope_source: row_lookup` and `agentless: true|false`.
Registration refuses `row_lookup` on a body source, on a non-int path parameter, and together with a second `row_lookup` entry.
Core never reads Tactical models itself (CQ56 b was refused). The lookup runs before dispatch, so a row can change between the
lookup and Tactical's own load. That race is small and accepted. Tactical still decides permission.

### List values and counts in `audit.before`

A declared `audit.before` field whose value is a list of whole numbers or short strings is now recorded as a list. Each string is
cut to 256 characters and loses control characters. Core keeps at most 1000 entries and 64 KiB of text, and writes
`<field>_count` (the full length) next to the list, plus `<field>_truncated: true` when it cut. A list that holds an object, a
float, a boolean, a null or another list is not recorded at all. The secret-name rule on field names stays. A declaration may list
up to 32 fields.

`audit.before.count_fields` names list fields of the same read whose length only is recorded, as `<field>_count`. The contents are
never recorded (for example a software package list).

`audit.before.select = {"param": "<path param>", "field": "id"}` is for a route that has no single-row `GET` (CQ58 a), for example
`agents/deployments/`. Core reads the list `GET` in-process through Tactical's own view as the signed-in user, selects the row whose
`field` equals the path parameter Core already cleaned, and records the whitelisted fields of that row. It never uses a before
value or an id sent by the browser, and a caller can still not supply a before over HTTP. The param must be an `int` or `str` path
parameter of the operation's route. A bare list and a paginated `{"results": [...]}` answer are both read, and Core scans the first
1000 rows only. No match, or an answer that is not a list, records `before: unavailable` and never blocks the call. The list route
must be owned by the same module and use only parameters of the operation, with the same kinds.

The Python-only `audit_before` keyword of `run_tactical_operation` stays flat. Since 1.17.23 a field may hold a list of whole numbers or texts (see "A list in `audit_before`").

### Audit the path parameters: `audit.params`

`audit = {..., "params": ["port"]}` names up to 8 path parameters of the route (plain names, none that looks like a secret, each
present on the route). Core copies their cleaned values (shape-checked, printable, at most 255 characters) into the row's `after`
value, next to the declared body and query fields. The row metadata does not change. A name may not also be an `audit_fields`
name. Take Control can record the port of a Web VNC call, and Remote Background the pid of an end-process call.

### Several operations on one route: `body_selector`

AD-6 allows one caller per Tactical route. Core reads that as one caller per *module* (CQ60). The owning module may declare more
than one operation on one `(method, route)` when Core can prove the bodies are exclusive. Each operation declares
`body_selector`: a list of at most 3 conditions, each `{"field": <name in body_fields>, "present": true|false}` or
`{"field": <name>, "equals": <text, whole number or boolean>}`. All of them must hold.

A second operation on the same route is accepted only when:

1. both operations belong to the same module (a second module stays refused);
2. every operation on that route declares a `body_selector`; and
3. every pair is provably exclusive: one field appears in both selectors with contradicting conditions (`present` true against
   `present` false, two different `equals` values, or `equals` against `present` false).

Core proves this at registration, in either order, and refuses the later declaration with a message that names the first. At run
time Core checks the cleaned body against the operation's own selector. A body that does not hold is refused 400
`body_selector_mismatch`, with a refusal row and no Tactical call, so a call can never run under the wrong operation's scope or
audit verb. `present` means the key is in the body and not null.

A selector field must also be one of the operation's `body_fields`, and registration refuses it otherwise. A selector that says
`present: false` still lists the field in `body_fields`. A body that names that field is refused 400 `body_selector_mismatch`.

```python
# add-policy-check lists "agent" in body_fields so the selector can say it must be absent
{"field": "agent", "present": False}   # a body {"agent": "..."} is refused body_selector_mismatch
```

```python
# Checks: POST checks/ is two operations in one module
{"add-agent-check": {..., "body_selector": [{"field": "agent", "present": True}]},
 "add-policy-check": {..., "body_selector": [{"field": "agent", "present": False}, {"field": "policy", "present": True}]}}
```

Single declarations behave exactly as before, including the refusal text for a different module. `describe()` lists
`caller_scope`, `body_selector`, `audit.params`, the scope `optional` and `row_lookup`, and `audit.before.count_fields` and `select`.

## Added in 1.17.19

Capability `core.tactical_operations` is 1.5.0, still major 1. An operation declared the 1.17.18 way registers and runs as before.
A module needs framework 1.17.19 to use `server_only`. The new refusal code is `operation_server_only` (403).

### Server-only operations: `server_only`

`register_tactical_operation(..., server_only=True)` (a strict true or false; anything else is refused at registration). A server-only
operation is for a change that only module code should make, such as a bulk action that a module's own backend runs after its own checks.

Core's browser route, `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/`, refuses it 403 `operation_server_only`. Core looks
the operation up first and refuses before it parses a body or reads a file. It checks that the request is signed in (401 otherwise), writes
one Core deny row (reason `server_only`, `refused_action` = the declared action) and never calls Tactical. This check comes before the
Tactical flag check, so a caller who also lacks a flag sees `operation_server_only`.

A module backend that calls `run_tactical_operation` (or the capability provider) runs the operation as before, with `audit_before`.

What this is not. It stops the browser path only. It is not a verified caller identity: modules run in the same Python process as Core,
and Core does not check which module called. `run_tactical_operation` has a private keyword, `_via_http_route`, that only Core's view sets.
Module code must never pass it. A call that carries it only makes Core stricter for a server-only operation, so it opens nothing.
`list_operations` and `get_operation` carry `server_only`. Ownership rules are unchanged.

### The 403 names the missing flag

The `tactical_permission_denied` detail ends with the missing flag, such as "It needs the Tactical permission can_reboot_agents." The code
and the deny row text are unchanged.

## Added in 1.17.20

### A failed attempt writes a row: `custom:operation-failed` (1.17.20)

Capability `core.tactical_operations` is 1.6.0, still major 1. A module needs framework 1.17.20 to rely on the row, and can feature-detect
it with the capability version. Nothing about declaring or running an operation changes.

When Tactical answers a call that is not `GET` with a 4xx other than 401 and 403 (400, 404, 409, 422, 429 ...), Core writes exactly one row.
The action is `custom:operation-failed`, never the declared action, so a filter on the declared action never matches a failed attempt (the
same as `deny` and `custom:outcome-unknown`). The row has the declared object type and object id, the correlation id, `tactical_status`, a
fixed Core text ("Tactical refused this change (HTTP 404); nothing was changed.") with no Tactical wording, and metadata `declared_action`,
`result: failed`, `failure: tactical_refused`, `operation`, `method` and `route`. It has no before or after value. The `X-Tec-Tac-Audit`
header and `TacticalOperationResult.audit` say whether it was recorded. Before 1.17.20 `result.audit` was `{}` and the header absent for
these answers; both are now a verdict. A 4xx on a `GET` still writes nothing. A module cannot declare `custom:operation-failed`, and
`tec_tac.audit.record` refuses it with `AuditContractError`. A module that wrote its own failed row for a Tactical 4xx should stop, so one
refused attempt gives one row.

## Added in 1.17.21

Capability `core.tactical_operations` is 1.7.0, still major 1. Everything here is additive. A module needs framework 1.17.21 to rely on it,
and can feature-detect it with the capability version and the keys `declaration_keys_added_in_1_7_0`, `behaviour_added_in_1_7_0` and
`refusal_row_codes` in the capability metadata.

### Core's own refusal writes one row (1.17.21)

When Core refuses a call that is not `GET` before it reaches Tactical, with one of `body_field_not_allowed` (both the "takes no body" and the
whitelist refusal), `invalid_body`, `invalid_params`, `scope_field_required`, `invalid_correlation_id` or `invalid_audit_before`, Core
writes exactly one row. The action is `custom:operation-failed`, the same Core-only action as a Tactical 4xx. The row has `core_refusal`,
the declared object type, the object id the deny rows use, the correlation id, a fixed Core text ("Core refused this change before sending it
to Tactical (invalid_body); nothing was changed."), and metadata `declared_action`, `result: failed`, `failure: core_refused`, `code`, `status`,
`operation`, `method` and `route`. It has no before or after value, no body, query or upload value, and no text from the caller's input.
The object id comes from the path parameter named by `audit.object_param`, or else from the first path-sourced scope entry, and only after the
path parameters were cleaned (since 1.17.22; before that the row took a hint built from the raw call). It never comes from a body field value,
including a body-sourced scope entry, and never from a raw value. So `invalid_params`, `invalid_correlation_id` and `invalid_audit_before`
(which are checked before the parameters are cleaned) and a body-scoped operation write a row with no object id.

`TacticalOperationError.audit` is the verdict `{recorded, id, action}`, and the `X-Tec-Tac-Audit` header says the same over HTTP. A failed
audit write gives `{recorded: false, error: audit_write_failed}` and raises nothing else.

What this changes in the order of a call:

- `correlation_id` and `audit_before` are now cleaned at step 5 (the validation step), after the operation lookup, the signed-in check, the
  permission checks and the caller-scope check. Before 1.17.21 they were cleaned first. Until step 5 an invalid correlation id is held back,
  so no earlier deny row carries it (the row has no correlation id of its own).
- An unknown operation, a disabled module, a request that is not a real signed-in request and a caller who fails the permission checks keep
  their answers. The first three write no row. The permission refusals keep their one `deny` row. So each refused change has exactly one row.
- A refusal on a `GET` writes no row and keeps `audit` at `None`.
- `body_too_large`, `invalid_query`, `query_field_not_allowed`, `invalid_upload`, `upload_not_allowed`, `upload_too_large`,
  `upload_type_not_allowed`, `tactical_route_changed` and `tactical_operation_not_found` from the owner recheck write no row in this release.
  Modules handle them in their own ways.

For a module: when `error.audit` is not `None` for one of these six codes, do not write your own failed row. Write it only when `error.audit`
is `None`. Then one refused attempt gives one row.

### Name the object of a create: `audit.object_field` and `audit.object_body_field` (1.17.21)

A create has no id in the path. Two optional keys in the `audit` declaration give the success row an object id:

- `audit.object_field`: the name of a top-level field of Tactical's success answer, when that answer is a JSON object (for example `id` or `pk`).
- `audit.object_body_field`: the name of a cleaned request body field. It must be one of `body_fields` (for example the script `name`).

Both are for a non-`GET` operation, match the usual field name pattern and must not look like a secret. They apply only when no
`audit.object_param` and no scope object gives an id, so a path id or a scope id always wins. On a 2xx answer Core takes the id from
`object_field` first. The value must be text or a whole number. A bool, a float, a list, an object or null is ignored, and Core then tries
`object_body_field`, then leaves the id empty. Control characters are dropped and the id is cut at 255 characters. The row's
`metadata.object_source` is `answer` or `body`.

Neither key is used on a `deny`, `custom:operation-failed` (from Tactical or from Core) or `custom:outcome-unknown` row. Those rows must not
carry request body values or Tactical's text. `describe()` and the exported operation rows list both keys (`null` when not declared).

The original request asked for one key, `object_field`, naming a body field. Johan's answer (CQ66 b) splits it into `object_field` (Tactical's
answer) and `object_body_field` (the request body).

## AD-19 conditions

Johan accepted this path on 9 October 2026 (AD-19, `docs/review-accepted-decisions.md`) on five conditions. Each has a test in `tests/tactical-operations-1.17.7.py`.

1. **Only a declared operation runs.** The owning core module declares it. Core refuses a non-owner or a route outside the owner's group at registration (`tests/tactical-operations-1.17.7.py`), and an unknown operation gives 404.
2. **The signed-in user's own identity.** Core resolves the route with Django's resolver and calls Tactical's view in-process, on a copy of the request with forced authentication. The `Authorization` header and cookies are dropped. Core reads no Knox token, makes no HTTP call and holds no key. An installer user and a user with no role are denied. Tactical's own permission, scope and validation still run. If Tactical renamed the route, the answer is 502 `tactical_route_changed`, with no fallback.
3. **A failed audit write is not fatal.** Tactical's change has already happened. Core logs the failure at error level and sets `X-Tec-Tac-Audit: not-recorded`. A Python caller reads `TacticalOperationResult.audit`.
4. **Outcome rows.** 2xx writes the declared action. 401 or 403 writes a Core deny row. A 5xx, or an error after dispatch, on a call that is not GET writes `custom:outcome-unknown`. Since 1.17.20 another 4xx on a call that is not GET writes `custom:operation-failed`, and a GET 4xx writes nothing. Core's own refusals write a deny row with a fixed Core text. Since 1.17.21 six validation refusals of a change before Tactical is called write one `custom:operation-failed` row with `failure: core_refused` (see "Added in 1.17.21").
5. **Tec-Tac's own functions are audited too.** Core and the module's own routes (`module_id` `core`, anything under `api/tfd/`) are not Tactical operations, so the executor refuses them. A module's backend action calls `tec_tac.audit.record` from its route instead. Both paths write the same row: actor, module, action, object, `module_version`, `correlation_id`, `operation_context` and `metadata`. Only the Tactical-operation row carries `server_provenance`, so an auditor can tell the two apart.

## Tactical permission flags in the runtime context

`GET /api/tfd/ui/context/` carries `tactical_permissions` since 1.17.7: every boolean `can_*` field on Tactical's Role, mapped to true or false for the signed-in user. Core computes it with one role lookup (`tec_tac.rbac.tactical_permission_catalog`). A superuser or role superuser has every flag. An installer user, a user with no role and any lookup failure have none. It adds no Tec-Tac permission and reads only the user's own role. It is a hint for the page: Tactical still decides every call.

`GET /api/tfd/ui/context/` also carries `tactical_scope` since 1.17.17: `{mode, unrestricted, whole_client_count, site_count}`, the signed-in user's Tactical client and site scope. It holds the mode and the counts only, never id lists. The ids are in the Python contract, `core.resources.scope_descriptor`. It is a hint for the page: Tactical still decides every call. See `docs/resource-directory.md`.

## Browser helpers

The UI gives modules two helpers for this path. They are documented as browser contract rows, `ui.authenticated.tactical-operation` (`tacticalOperation(moduleId, operationId, options)`) and `ui.authenticated.tactical-permissions` (`hasTacticalPermission(flag)`). The rows state what Core checks and the rule that a module passes its own id. They add no HTTP contract, executor or permission change.

The rule is: a module passes its own id, except for the AD-20 module it replaces. From UI 0.12.88 the shell enforces it for `tacticalOperation`. It reads the replaced id from `descriptor.replaces` or from the module's row in `module_status`, and it fails closed when the row carries no `replaces`. Core sends `replaces` in each `module_status` row of `GET /api/tfd/ui/context/` since 1.17.11 (the declared value, or null; see `docs/module-replacement.md`). From UI 0.12.89 `api`, `apiRaw`, `apiBlob` and `apiText` refuse a tactical-operations path for an id other than the module's own id or the one it replaces. The replaced id is a snapshot taken before any `register()` runs. The guard is a helper-level guard, not a sandbox: a module that calls `fetch` itself is not stopped by it. Core's own checks stay the authority: the operation is declared by the module id in the URL, the user holds the Tactical permission and the role scope, the route is owned, and the replacement is honoured. A path hidden behind tab, CR, LF or other control characters is a finding held for the UI.

## What this does not do

- It does not run a Tactical function itself. The owning core module decides which operations exist. Core only runs them.
- It does not run background work. Mode (b), the Scheduler running as the schedule owner, is the AD-13 system-action contract.
- It does not replace `tec_tac.audit.record` for a module's own backend action. Use `record` from the backend route for that.

## Added in 1.17.23

Capability `core.tactical_operations` is 1.8.0, still major 1. Everything here is additive. A module needs framework 1.17.23 to rely on it,
and can feature-detect with `core.tactical_operations >= 1.8.0`. A caller that sends only scalars is unchanged.

### A list in `audit_before` (1.17.23)

A caller that acts on many things at once (Automation's Run now on a set of endpoints) can put the list in `audit_before` so Core's own row carries it:

```python
run_tactical_operation(request, "automation", "run-now", params, body, audit_before={"endpoint_ids": [12, 15, 31]})
```

- A field may hold a list. Each item is a whole number (not `true`/`false`) or a text of at most 256 characters with no control characters.
- Core keeps the first 1000 entries (and at most 65536 characters), exactly as it does for a declared before field. The row carries `<field>_count`, the full length, and, when the list was cut, `<field>_truncated: true`. A list of 1000 or fewer short entries is kept whole and sets no flag. An empty list is recorded with a count of 0.
- A list that holds an object, a float, `true`/`false`, `null` or another list, a text over 256 characters or with a control character, or a tuple, is refused: HTTP 400 `invalid_audit_before`, one `core_refused` row, no Tactical call.
- A caller field named `<list>_count` or `<list>_truncated` next to a list is refused, because Core writes those two itself and the row would hold the name twice. The 16-field limit counts the caller's own fields only, so those two Core-written keys do not use it up.
- The secret-name rule, `before_source: caller`, and the rule that an operation with its own `audit.before` ignores the caller's value, are unchanged. A browser still cannot send `audit_before`.

### Already shipped in 1.17.22, closed here

The `core_refused` row's object id is taken from the cleaned path values only (`_refusal_object_id`), and the compatibility test asserts `server_only` is a boolean. Both are in 1.17.22. Nothing more to build.

## Added in 1.17.26

Capability `core.tactical_operations` is 1.9.0, still major 1. Everything here is additive and opt-in: a declaration that passes neither new keyword
behaves exactly as before, with the same text and the same rows. A module needs framework 1.17.26 to rely on it and can feature-detect with
`core.tactical_operations >= 1.9.0`. Report Manager adopts both in its own release.

### Any-of permissions: `permissions_any`

Tactical's report generation lets a role run a report with either "view reports" or "manage reports" (`GenerateReportPerms`). `permissions` can only say
"all of these", so a declaration could not match. `register_tactical_operation(..., permissions_any=[...])` takes a list of Tactical role flags (`can_...`,
the same name check and the same maximum of 8 as `permissions`). The caller needs at least one of them.

- It combines with `permissions`: the caller needs **every** flag of `permissions` **and at least one** flag of `permissions_any`.
- `permissions` may be empty only when `permissions_any` is given. With neither, registration is refused as before.
- A flag may not be in both lists, and a list may not repeat a flag.
- The check runs at the same step as the all-of check (step 3, through `tactical_permission_flags`). A superuser passes, as before.
- The 403 `tactical_permission_denied` names what is needed: `It needs one of can_view_reports, can_manage_reports.` When an all-of flag is also missing, the text names both: `It needs the Tactical permission can_reboot_agents and one of can_view_reports, can_manage_reports.`
- The deny row keeps its fixed wording and gains `needs_one_of` (the list) in its metadata. An operation declared the old way writes the same row as before, with no such key.
- `list_operations` and `get_operation` show `permissions_any` (an empty list for an old declaration). The exported contract describes the keyword.

### A larger body cap: `body_max_bytes`

The JSON body of a call is held to 256 KiB (`MAX_BODY_BYTES`). Report Manager's template import posts a whole template, which can be larger, and its 0.4.0
browser post had no such cap. `register_tactical_operation(..., body_max_bytes=N)` lets one operation raise its own cap.

- `N` is a whole number of bytes (not a bool, float or text) from the 256 KiB default up to the Core ceiling of 8 MiB (`MAX_BODY_CEILING_BYTES`). The ceiling is a Core constant, never a module's choice. A value below the default or above the ceiling is refused at registration. A value equal to the default is stored as the default.
- The size check at the body step uses the operation's cap. `body_too_large` (HTTP 413) names the cap that applied: `body is larger than 2097152 bytes.`
- `list_operations` and `get_operation` show the effective cap as `body_max_bytes` (262144 for an operation that does not set it). The capability's `limits` carry `body_bytes` (the default) and `body_bytes_max` (the ceiling).
- Body parsing, the JSON depth limit, the secret-name rule and the rule that `body_too_large` writes no audit row (it is not a core-refused row code) are unchanged.
- A web-server body limit (nginx) or a limit in Tactical itself still applies and was not verified. A module that posts a large body should test it on a real server.

Tests: `tests/tactical-operations-permissions-any-1.17.26.py`, `tests/tactical-operations-body-cap-1.17.26.py`.

## Added in 1.17.28

Capability `core.tactical_operations` is 1.10.0, still major 1. One new optional keyword. A declaration without it behaves exactly as
before. A module can feature-detect with `core.tactical_operations >= 1.10.0` and needs framework 1.17.28 to rely on it.

### Lists of objects, recorded in clear: `audit_lists`

Tactical's own audit records a whole task, its actions included, as before and after on every change. Core can now record such a list the
same way. `register_tactical_operation(..., audit_lists=["actions"])` names up to two body or before fields that hold a list of flat objects.

**Recorded in clear.** Script arguments and environment values are written as Tactical stores them. Core does not mask a value whose name looks
like a secret. Anyone who can read the Tec-Tac audit can read them, as anyone who can read Tactical's audit can. This is Johan's answer to CQ85 a
(14 October 2026): "do the same as Tactical". It is signed as **AD-32**, an exception to module standard section 3 (no secrets in audit) for the
opt-in `audit_lists` keyword only. Other fields and routes keep section 3. Only holders of the audit view permission can read these rows, and
Johan may reverse the decision at any time.

- The success row's after value holds the list from the cleaned body. When the operation has a before read, the before value holds Tactical's own GET answer.
- Each list is written with `<name>_count`, the full length. `<name>_truncated: true` appears only when something was cut or dropped.
- Bounds (`limits_added_in_1_10_0` in the contract): 50 objects per list; 24 keys per object, each a plain field name; a text value cut at
  4096 characters, with control characters other than tab and newline removed; numbers, booleans and nulls kept; a list of up to 100 scalars
  kept, anything deeper dropped; 64 KiB of text per list field; two list fields per operation.
- A value that is not a list is recorded as an empty list with count 0. A list with an item that is not an object is recorded as its count
  only. Both are flagged truncated. Nothing raises: the change is still written and still made.
- A failed row (Tactical's 4xx), a denied row and an outcome-unknown row carry no list, as before.
- Registration: a GET cannot declare it. Each name must be a body field, or come from a before read. A name may not repeat a field of
  `audit.before` or `audit.audit_fields`, may not clash with another list's `<name>_count` or `<name>_truncated`, and may not look like a secret.
- `describe()` and `list_operations` show `audit.lists`.

Adoption by the Tasks module (declaring `audit_lists` on edit, create, create-policy-task and delete) is a request in
`reviews/requests/core-modules.md`, not part of this release.

## Added in 1.17.41

Capability `core.tactical_operations` is 1.11.0, still major 1. Three additions, all opt-in. A declaration that uses none of them behaves
exactly as before, with the same text and the same rows. A module needs framework 1.17.41 to rely on them and can feature-detect with
`core.tactical_operations >= 1.11.0`.

### A streamed file answer: `file_response`

Tactical answers some routes with a `FileResponse`: a report PDF, a report asset download. `register_tactical_operation(..., file_response=True)`
(a strict bool; GET or POST only) lets Core relay it.

- Core reads the stream chunk by chunk, up to `limits.response_bytes` (25 MiB, the same cap as any answer), and closes it.
- From there the call is an ordinary one. The same status handling and the same audit rows apply: the success row with the declared action,
  the deny row for 401 and 403, the failed row for another 4xx on a change, the outcome-unknown row for a 5xx.
- `Content-Type` and `Content-Disposition` are relayed with the bytes. `TacticalOperationResult.content` holds the bytes, and `data` stays
  the raw bytes for a type that is not JSON.
- A stream that passes the cap is cut, closed and refused as `tactical_response_refused` (the outcome-unknown row for a change, as the existing
  size check writes). The audit row never carries the file name or the bytes.
- A stream that fails part way (the connection breaks or Tactical's side raises while Core reads it) is closed and refused as
  `tactical_call_failed` with the outcome-unknown row for a change, as for any other failure after dispatch. A `GET` writes no row. Since
  1.17.42 this is a normal JSON refusal, not a bare 500. Before 1.17.42 it was an unhandled error.
- Without `file_response` a streaming answer is refused as before, and the stream is closed.
- `list_operations` and `get_operation` show `file_response`. It is buffered in memory, so a file over 25 MiB is refused.
- `agents/installer/` stays a route Core forbids. It is not declared by this release.

### A query string on any method

`query_params` may now be declared on a `DELETE`, `POST`, `PUT` or `PATCH` operation. The protections are the same: a whitelist of names, flat
values of at most 512 characters, no control characters, no `..` path segment, and a name that looks like a secret is refused at registration.
`audit_fields` may name a query parameter. A `GET` declaration behaves as before.

### A route parameter kind for a Windows service name: `{name:service}`

`services/{agent_id:agent}/{svcname:service}/` is how Tactical addresses one service. The kind `service` takes a name whose first character is a
letter, digit or underscore, followed by letters, digits, space and `$ # ( ) . , _ -`, at most 256 characters in all. It never holds a slash or
`..`. Core builds the path unquoted, and Tactical's own `<str:svcname>` pattern resolves it, so `MSSQL$SQLEXPRESS` and `Print Spooler` work. The
kind `str` still refuses `$` and a space. The owner table is unchanged: `services/` is Remote Background's alone. `audit.params` may name it.

Tests: `tests/tactical-operation-file-response-1.17.41.py`, `tests/tactical-operation-query-service-1.17.41.py`.

## Added in 1.17.43

Capability `core.tactical_operations` is 1.12.0, still major 1. Two changes ship together, both opt-in. A declaration that uses neither
behaves exactly as before, with the same text and the same rows. A module needs framework 1.17.43 to rely on them and can feature-detect
with `core.tactical_operations >= 1.12.0`.

### A change marker for a secret body field: `audit.secret_fields`

A body field can hold a secret (a password, a token, a script's arguments and environment). Core must still show that a change touched it, but
never its value. `audit` may name up to eight body fields in `secret_fields`.

- A success row writes `"<field>": "changed"` on the after side when the body sends the field.
- When the operation also declares `audit.before` and Tactical's read holds the field, Core compares the sent value with the read's value in
  memory. Both are reduced to a SHA-256 of their canonical JSON (sorted keys, no whitespace), and the values are dropped at once. The before side
  writes `"<field>": "present"` and the after side writes `"changed"` or `"unchanged"`.
- When there is no before read, or the read does not hold the field, the after side writes `changed` and the before side is left out. Core never
  invents `unchanged`.
- The marker proves the value was sent or differs. It does not say what the value holds.
- Core never records the value in the row, the metadata or a log, so a field named in `secret_fields` may be secret-named (for example `token`).
  Such a field is declared here and nowhere else in the audit declaration.
- A secret field may not also be in `audit_fields`, `audit_lists`, the fields of `audit.before`, `audit.object_body_field` or a body scope source.
  It must be one of `body_fields`. Registration refuses any other combination with `TacticalOperationRegistrationError`.
- A failed, denied, core_refused or outcome-unknown row carries no marker.
- `register_tactical_operation(audit={..., "secret_fields": [...]})` is the only way to declare it. A declaration without the key writes the
  rows it wrote before.

### A count of the ids a list scope names: `metadata.object_count`

An operation whose scope entry names up to 1000 ids writes the joined ids as the row's object id, cut at 255 characters, so a long selection shows
only its first ids. When the first scope entry names more than one id, the success, tactical_denied deny, scope refusal, failed and
outcome-unknown rows of that call carry `metadata.object_count`: the number of ids. It is a number and never an id. The object id is unchanged.
A row written before the scope is read (a permission, module permission or body refusal) carries no count, as before.

Tests: `tests/tactical-operation-secret-fields-1.17.43.py`, `tests/tactical-operation-object-count-1.17.43.py`.
