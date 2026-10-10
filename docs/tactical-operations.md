# Tactical operations: Core runs the call and writes the audit row

**Status:** Public Core developer contract, added in Core 1.17.7
**Python:** `tec_tac.tactical_operations`
**Capability:** `core.tactical_operations` 1.3.0 (major 1, additive since 1.0.0), owner `core`
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

## Added in 1.17.13

Everything here is optional. An operation declared the 1.17.12 way registers and runs exactly as before. The capability
`core.tactical_operations` is now `1.1.0` (it was `1.0.0`). Every caller asks for `>=1,<2`, so nothing breaks. A module that uses any
key below needs `requires.framework` of `>=1.17.13`.

### Name the audit object: `audit.object_param`

`audit.object_param` names a path parameter of the route. Its value is the audit row's `object_id`, with the declared
`audit.object_type`. It is written on every row: success, deny, and outcome-unknown. It is also the object hint on a refusal at steps
3 and 4. It must name a real parameter of the route, or registration is refused. Without it, `object_id` comes from the first scope
object, as before.

```python
audit={"action": "delete", "object_type": "report_template", "audit_fields": [], "object_param": "pk"}
```

### Read the object first: `audit.before`

`audit.before = {"route": ..., "fields": [...]}` gives the row a before value. `route` is a Tactical `GET` route that returns the
object. Its parameters must be among the operation's own parameters, with the same names and kinds, and the same module must own it
(the same owner check as the operation). `fields` is a list of at most 16 top-level names. None may look like a secret.

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

### A query string for `GET`: `query_params`

`query_params` is a whitelist of up to 16 names for a `GET` operation. It is the new last argument of `register_tactical_operation`. A
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

Tactical answers `GET reporting/assets/download/` with a `FileResponse`, which is a streamed answer. Core refuses a streamed answer
(`tactical_response_refused`), so a declared download operation reaches Tactical's view with its query string but the file is not
relayed. The query string itself works for any operation whose answer is not streamed. Relaying a streamed file answer is a separate
request.

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

- A flat dict of at most 16 fields. Each value is text (up to 256 characters, no control characters), a whole number, `true`/`false` or `null`.
- Field names follow the operation's field-name rule (a letter or `_`, then letters, digits and `_`, up to 64 characters). A name that looks like a secret (`pass`, `secret`, `token`, `key`, `credential`, `auth`, `cookie`, `signature`) is refused. A nested value, a float or an oversize value is refused too. The refusal is HTTP 400, code `invalid_audit_before`.
- Core uses it only when the operation declares no `audit.before` read. When both exist, Tactical's own read wins and the caller's value is ignored.
- It is written on the success row only. A refused or failed call keeps no before value.
- The row metadata says `before: recorded` and `before_source: caller`. A value Core read from Tactical says `before_source: tactical`. A reviewer can tell an asserted value from a read one.
- It is Python only and never available over HTTP.

### What `audit.object_param` already does

The audit object id from a `{pk}` path parameter shipped in 1.17.13 and works with a typed `{pk:int}` since 1.17.14. Core writes the path value as the row's `object_id` on success, deny and outcome-unknown rows. A module only has to declare `object_param`. `tests/tactical-operations-audit-before-1.17.16.py` locks the Report Manager shape (`reporting/templates/{pk:int}/` and the operations below it).

## AD-19 conditions

Johan accepted this path on 9 October 2026 (AD-19, `docs/review-accepted-decisions.md`) on five conditions. Each has a test in `tests/tactical-operations-1.17.7.py`.

1. **Only a declared operation runs.** The owning core module declares it. Core refuses a non-owner or a route outside the owner's group at registration (`tests/tactical-operations-1.17.7.py`), and an unknown operation gives 404.
2. **The signed-in user's own identity.** Core resolves the route with Django's resolver and calls Tactical's view in-process, on a copy of the request with forced authentication. The `Authorization` header and cookies are dropped. Core reads no Knox token, makes no HTTP call and holds no key. An installer user and a user with no role are denied. Tactical's own permission, scope and validation still run. If Tactical renamed the route, the answer is 502 `tactical_route_changed`, with no fallback.
3. **A failed audit write is not fatal.** Tactical's change has already happened. Core logs the failure at error level and sets `X-Tec-Tac-Audit: not-recorded`. A Python caller reads `TacticalOperationResult.audit`.
4. **Outcome rows.** 2xx writes the declared action. 401 or 403 writes a Core deny row. A 5xx, or an error after dispatch, on a call that is not GET writes `custom:outcome-unknown`. Other 4xx write nothing. Core's own refusals write a deny row with a fixed Core text.
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
