# Tec-Tac Framework 1.17.0

This release does two things. Modules get one place to keep saved views. And the audit trail for permissionless modules is more accurate and easier to trust.

Nothing here breaks an existing module. Every change is additive.

## Saved views service

People can now save a named set of filters and layout and come back to it. Core keeps every module's saved views in one table (`TecTacSavedView`). Modules no longer need browser storage, cookies or a table of their own. This closes the Core request "Saved views" and the answers to board Q19 and Q25.

### How it works

- A view has a module, a `view_key` (which screen it belongs to), a name, a `payload` (a JSON object up to 64 KiB) and an owner. Core sets the owner from the signed-in user.
- `readers` is a list of user ids. Empty means shared with everyone. Not empty means private to the owner and the listed users. To keep a view for yourself only, send `readers: [<your own user id>]` (Q43).
- Only the owner changes or deletes a view. There is no administrator override, unlike Dashboards.
- Someone who cannot read a private view gets 404, so nothing leaks. A reader who is not the owner gets 403 when they try to change or delete it. Only the owner sees the `readers` list. Everyone else sees a `shared` flag.
- A module with permission groups needs one of its grants. A permissionless module needs a signed-in user (Q45). Tec-Tac adds no permission of its own.
- Limits: `view_key` is a slug up to 64 characters, `name` is 1 to 160 characters, `readers` holds up to 100 active users, and each person keeps at most 100 views per module and `view_key`. A name is unique for one owner, module and `view_key` (409 if repeated).
- Create, change and delete each write a Core audit row (module `core`, object type `saved_view`, action `add`, `modify` or `delete`). The row never holds the payload. The audit write is strict and in the same transaction, so if it fails the change is rolled back.
- Deleting a user deletes that user's views, shared ones included (Q44). Removing a module leaves its views in place, like preferences.

### Contracts

- HTTP: `GET` and `POST /api/tfd/saved-views/`, and `GET`, `PUT` and `DELETE /api/tfd/saved-views/<uuid>/`. Modules call them through the `api()` transport. The list call needs `?module=`. The plan left it optional, but a list across modules would show views of modules the caller cannot use. `?view_key=` is optional. Writes are limited to 60 a minute and 2 000 a day for each user and IP. Reads are not counted.
- Python: `tec_tac.saved_views` with `list_views`, `get_view`, `create_view`, `update_view` and `delete_view`. Failures are `SavedViewError` subclasses.
- Both are in the public contract catalog (area `saved-views`), with one new rule: no browser storage or cookies for saved views. Swagger has a new group, "Tec-Tac · Saved Views".
- New migration `0021_saved_views`. `docs/saved-views.md` explains what a payload may hold (filters and layout only, never data, secrets or tokens) and how a module moves off browser storage.

## Audit trail for permissionless modules

### Denials reach the audit log (Q34)

When Core refuses a declared browser event, it still writes one Core-owned `deny` row. Two things change.

- The row now says why. A missing or out-of-scope object (404) and a role without Tactical's `can_list_*` permission (403) each get their own fixed Core message. Before, a permission refusal was wrongly labelled "outside the signed-in user's scope". `metadata` keeps `refused_action` and `reason`, and now also the HTTP `status`.
- The row sets `debug_info.operation_context.core_refusal = true`. Only Core sets this key. The request cannot carry `operation_context`, and a backend `record()` call that supplies `core_refusal` is a contract error.

A module can declare `deny` in `audit_events`, for example to record a 403 that Tactical itself returned for `can_use_mesh` or `can_manage_winsvcs`. That row is recorded like any declared event, with the marker and without `core_refusal`. So the Audit module can tell the module's row from Core's own. This closes the 1.16.0 review Low "a module-declared deny looks the same as Core's".

An event the module did not declare stays HTTP 403 and writes nothing. That is a wrong manifest, not a denied user, and logging it would let a faulty module flood the log. Deny rows still count toward the 60 a minute and 1 000 a day limit.

### Any object type (Q35)

`audit_events` now accepts any lowercase slug as `object_type`, such as `licence_key`. Johan's answer to Q35 was to allow other types with no scope check.

- `client`, `site` and `agent` behave as in 1.16.0: `object_id` is required, Core checks the signed-in user's scope, and a refusal writes a deny row.
- Any other declared type has no scope check and no deny row. `object_id` is optional (up to 255 characters). The row is recorded under the signed-in user with the marker.
- Still refused: an undeclared type or action, Core, legacy or disabled modules, a repeated type in one manifest, and more than 20 entries or 20 actions.
- The code now has `SCOPE_CHECKED_OBJECT_TYPES`. `AUDIT_EVENT_OBJECT_TYPES` and `BROWSER_EVENT_OBJECT_TYPES` stay as aliases, so nothing that imports them breaks.

### The marker on every row (Q36)

Johan accepted the browser path on the condition that the marker is on every row. Every row on the declared path now carries `operation_context.browser_provenance = "module-declared-event"`: success rows, Core deny rows, and rows whose `metadata` or `operation_context` was too large to store.

`_fit_debug_info` (1.16.0 review Low) now replaces only keys that are present, the larger of `metadata` and `operation_context` first. A replaced `operation_context` keeps `browser_provenance` and `core_refusal`. It never adds a marker for a key that was not there.

The decision is written up as AD-8 in `reviews/modules/PROPOSED-AD-8.md`. Claude may not write `docs/review-accepted-decisions.md`, so it counts once Johan copies it in. Until then the 1.16.0 review Medium ("no signed-off decision covers it") can come back.

## Module-facing changes

- **Additive.** No route, model or contract was changed or removed. A manifest with only `client`, `site` and `agent` parses and behaves as in 1.16.0. The status codes and response bodies of `/api/tfd/audit/record/` are the same. The deny row's `debug_info.operation_context` has one extra key, and its message text differs by reason.
- **Manifest floor.** A module that declares an `object_type` other than `client`, `site` or `agent` must set `requires.framework` to `>=1.17.0`, because Core 1.16.x rejects the manifest. A module that uses saved views must also require `>=1.17.0`.
- **Validator.** Sol's module validator reads `SUPPORTED_KEYS` only. No key was added or renamed, so it needs no change.
- **Take Control and Remote Background.** No change to what they send. Next module run: post Tactical's 403 refusals as action `deny` (today they use `view` with `metadata.result` `denied`) and declare `deny` in `audit_events`.
- **Audit.** Read `operation_context.browser_provenance` and `core_refusal` to show which rows were browser-declared and which were Core refusals. Move saved views to the new service and drop browser storage.
- **Endpoints and Debug.** Move saved views to the new service (Q19, Q25). Dossier profiles, the Summary widget layout and pane sizes are per-user preferences, not saved views. They need the module user preferences request, which is a separate item.

## For Johan

- Q43 (only me = `readers` holds the owner's id), Q44 (deleting a user deletes their views) and Q45 (any signed-in user who can use the module) are on the board with the assumptions used.
- After 1.17.0 is signed and installed on the dev server, please export a fresh public contract into `docs/contracts`.
- Please copy AD-8 from `reviews/modules/PROPOSED-AD-8.md` into `docs/review-accepted-decisions.md`.
- Checklist item c42 from the 1.16.0 test (a module without `audit_events` still gets 403) is a server test. Try it on the dev server.

## Left out

- Audit and Debug CSV export error. This is not a Core bug. Both modules send `Accept: text/csv` to a DRF view. Tactical allows only the JSON renderer when `DEBUG` is off, so DRF answers 406 before the view runs. Each module should send `Accept: */*` or set a pass-through `content_negotiation_class`. Audit 1.3.0 already moves the export to a browser-built CSV. This is a conclusion from source, not a reproduction on the dev server.
- Exposing `Content-Disposition` in Core's CORS configuration. It needs a change to the Tactical settings bootstrap in `install.sh`, and it does not fix the CSV error.
- A UI helper for saved views and the `module-runtime-api.md` text. That is a UI release. Modules call the HTTP contract through `api()` in 1.17.0.
- The rest of the Core requests backlog. Each item is its own contract.

No UI changes are required.

## Tests

- New: `tests/audit-declared-browser-events-1.17.0.py` and `tests/saved-views-1.17.0.py`. Both run from `tests/review-hygiene-foundation.sh`.
- Updated: `tests/audit-declared-browser-events-1.16.0.py` (new deny metadata and message, any object type, larger piece replaced first) and `tests/audit-browser-provenance-hardening.py` (`_fit_debug_info` cases).
