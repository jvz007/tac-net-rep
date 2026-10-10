# Tec-Tac Framework 1.17.13

A module can now tell Core which object a Tactical call changes, and Core records what that object looked like before. Module categories (AD-21) are accepted, stored, shown in status and enforced. A GET operation can pass a query string, and one operation can forward one file. Two findings held from the 1.17.12 review are fixed.

Closes: in `reviews/requests/core.md`, the audit-object entries (agents 0.3.0 and reportmanager 0.5.0), the "query string for GET operations and file upload" item, the AD-21 module categories entry and the runtime-test-fix entry. Also the stale endpoints wording (Endpoints 0.3.0 no longer waits on the Tactical flags entry). Not closed: the production gate (AD-21 condition 6), see "What this release leaves out".

## What changed

### Tactical operations: the audit object, a before value and scope from the read

All of this is optional. An operation declared the 1.17.12 way registers and runs exactly as before.

- **`audit.object_param`** names a path parameter of the route. Its value is the audit row's `object_id`, on success, deny and outcome-unknown rows, and it is the object hint when Core refuses at steps 3 and 4. It must name a real parameter or registration is refused.
- **`audit.before = {route, fields}`.** `route` is a Tactical GET route of the same module that returns the object. Its parameters must be among the operation's own, with the same names and kinds. Before the change, Core runs that GET in this process through Tactical's own view, as the signed-in user (no HTTP call, no token). It copies at most 16 whitelisted top-level fields: strings cut to 256 characters, anything that is not a scalar dropped. That is the row's `before_value`. A read that fails or does not answer 200 never blocks the change. The row is still written, and its metadata says `before: unavailable` with `before_status`.
- **Scope from the read.** A scope entry may use `source: before:<field>`. Core resolves the agent of a note from Tactical's own `agents/notes/<pk>/` answer (`agent_id`) and runs the usual role-limit check on it. The read happens after the Tactical flag and module-permission checks. If it does not answer 200, Core refuses with the fixed 404 `object_not_found` text and a deny row. It fails closed.
- **Scope type from the body.** `{type: "body:type", source: "body:id", type_map: {"Client": "client", "Site": "site"}}` takes the type from a body field. A value outside the map is refused 400 `scope_field_required`. The resolved type is written to the row metadata as `scope_type`.
- **Pending actions.** Tactical has no detail GET for a pending action, and Core does not read Tactical's PendingAction model. `cancel-pending-action` declares `object_param: "pk"` and no scope entry. Tactical's own DELETE view enforces `_has_perm_on_agent`. Core still re-checks the Tactical flag and writes the row with the pk as the object.

`_write_row` gains a `before` argument. `audit._record_tactical_operation` already took one.

### Tactical operations: a query string for GET and one multipart file

- **`query_params`** (new optional last argument of `register_tactical_operation`) whitelists up to 16 names for a GET operation. `run_tactical_operation(..., query=None)` takes a flat object. Each value is a string or a whole number of at most 512 characters, with no control characters and no `..` path segment (also after one level of percent-decoding). Core builds `QUERY_STRING` and sets `GET` on the forwarded request, so DRF's `query_params` sees it. A name outside the whitelist gives 400 `query_field_not_allowed`. `audit_fields` may name a body field or a query name.
- **`upload = {field, max_bytes, extensions}`** (POST, PUT or PATCH) lets an operation forward exactly one file. The hard ceiling is `MAX_UPLOAD_BYTES`, 10 MiB. Each operation declares its own lower cap and a non-empty extension list. Core cleans the file name (no path, at most 255 characters, no control characters), checks the extension, checks the size before it reads the file, writes its own multipart payload with a random boundary (no `django.test`) and forwards it, so Tactical's own parser reads the file and the text parts. The audit row records the file name, size and content type, never the content. New refusal codes: `query_field_not_allowed`, `invalid_query`, `upload_not_allowed`, `upload_too_large`, `upload_type_not_allowed`, `invalid_upload`.
- **The HTTP route** takes `query` in the JSON form, and a `multipart/form-data` form with the text parts `params`, `body` and `query` (each a JSON object) and one file part. It checks the declared length before parsing and the file size before reading. The throttles are unchanged.
- **The part can be named after the file.** The plan said a fixed part name. Tactical's report asset upload does not work that way: `UploadAssets` stores each file under the name of its multipart part (`for filename in request.FILES`), not under the `filename` attribute. So `upload.field` may also be the value `"{file_name}"`, and Core then names the part after the cleaned file name. Report Manager needs this.

### AD-21 module categories

- **Accepted.** Manifest `category` takes `core`, `server`, `premium` or `test`. Anything else is refused. A `test` module may not declare `replaces`. The capability prefix rule stays for `core` and `server` only.
- **A missing category counts as `test`.** The new `tec_tac.module_category` holds the one set of rules: `effective_category`, `is_development_server()` (the root-owned `TEC_TAC_ENVIRONMENT`, read through `trust_policy`, failing closed) and `describe()`.
- **Shown.** Every `module_status` row of `GET /api/tfd/ui/context/` and every extension row of the modules/v2 installed catalogue carries `category`, `effective_category`, `category_missing`, `category_refused` and `category_warning`. The catalogue also has `category_state` and `category_mismatch`. The warning for a missing category says the module does not state its category, Core treats it as Test, and on a server that is not a development server Core refuses to install or enable it, so the next release needs one. On a development server it says the module still runs.
- **Stored.** The root job helper writes the manifest category into the module's state entry, in the existing single state write at install. Status reads the manifest first and flags a mismatch.
- **Enforced.**
  - Install plan, enable validation and the root helper's own re-check (from root-owned manifests and the root config) refuse an effective `test` module off a development server (`category_refused`). Modules that are already installed keep loading.
  - The Tactical operations executor uses the effective category at registration and lookup. A `premium`, `server` or `test` module is refused every route, even where the owner table lists its id, with a message that names the category. Licensing keeps `core/codesign/`. An honoured AD-20 replacement keeps its rights.
  - AD-20: a replacement must be `premium`, or have no category on a development server (reason code `replacement-category`).
- **Requirement.** A manifest that writes `premium` or `test` must require `requires.framework` `>=1.17.13`, because an older Core rejects the value. It is in the notes and in `docs/module-categories.md`.

### Held finding (Medium): the switch-failed row no longer claims a restore that did not run

The root helper now records what happened. `rolled_back` is set to true only after `restore_enabled_flags` returns. `rollback_error` is set when it raises, and no second sync runs then. Neither is set when nothing was changed. `_outcome_rows` builds the sentence from those fields and not from the stage name. Rolled back: "The flags were put back as they were." A rollback error: Core could not put the flags back, check the Modules page. A failure at `runtime-sync` or `rollback` with neither field (including every job file written by 1.17.12): the outcome is not confirmed, with the stage named. A failure before any change: "Nothing was changed." The row metadata carries `rolled_back` (true, false or null).

### Held finding (Low): the duplicate check no longer depends on the metadata

The switch-failed metadata cuts `error` to 300 printable characters and `planned` to 10 ids. Every queued and outcome row carries the correlation id `module-replacement:<action>:<job id>`. The audit writer's size fitting never drops it, so `_audit_already_written` matches on action, object id and `debug_info.correlation_id`, and still matches the old `metadata.job_id` for rows written by 1.17.12. A broken lookup still writes nothing.

### The dev-server runtime scripts, corrected

`tests/module-replacement-reconcile-runtime-1.17.11.py` and `tests/module-replacement-handback-runtime-1.17.12.py` declared `patching.windows` on a probe core module, which Core refuses. Most of their steps failed with `RegistryError` before testing anything. They are renamed to `...-1.17.13.py` with the capability `tectac-probe-replaced.windows` on both probe manifests and `category: premium` on the replacement. They now reach the reconcile sweep, the queue-time and outcome rows, the sweep not duplicating them and the sudo dispatch failure path. New steps cover a test module off a development server, the category fields read from the real root config, the long-error row written once, and a failed switch with no rollback record. Johan reruns them on the dev server. A pass is not a condition of this release (Johan, 9 October 2026).

## Module-facing changes

Every change is additive. The capability `core.tactical_operations` goes from `1.0.0` to `1.1.0`, and every caller asks for `>=1,<2`.

- `register_tactical_operation(..., message=None, query_params=None, upload=None)`: two new optional arguments. `audit` takes `object_param` and `before`. A scope entry takes `before:<field>` sources, `body:<field>` types and `type_map`.
- `run_tactical_operation(request, module_id, operation_id, params=None, body=None, query=None, upload=None)`: two new optional keyword arguments.
- `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/`: `query` in the JSON form and a multipart form. New codes listed above. 413 `upload_too_large`.
- `get_operation` and `list_operations` rows gain `audit.object_param`, `audit.before`, `query_params`, `upload` and `type_map` (null or empty when not declared).
- `module_status[]` and the modules/v2 catalogue gain the five category fields. The catalogue also gains `category_state` and `category_mismatch`. Problem type `category_refused` for an install plan or an enable.
- `module_replacement` gains the reason code `replacement-category`, and `correlation_id_for()`.
- Audit rows for module switches carry a correlation id. The switch-failed row's metadata gains `rolled_back`.
- A module that uses any of this needs `requires.framework` `>=1.17.13`.
- New: `docs/module-categories.md`. Changed: `docs/tactical-operations.md`, `docs/module-replacement.md`, the contract rows in `contracts.py`.

Modules affected: Agents (restores `note-edit`, `note-delete`, `cancel-pending-action`, `bulk-maintenance`), Report Manager (16 `{pk}` operations, asset upload), Checks, Licensing, Script Execution and Alerts (may adopt the same keys), and every module in the catalogue (each writes its category at its next release; 25 of the 43 modules in `modules/` have none today).

## What this release leaves out

- **Report asset download does not work yet.** Tactical answers `GET reporting/assets/download/` with a `FileResponse`, a streamed answer, and Core refuses a streamed answer (`tactical_response_refused`). The query string works (shown by `GET reporting/assets/?path=`, which answers JSON). The download needs the separate "relay a streamed file answer" request, which Johan did not list for this release. It also blocks every PDF run. It is the next most valuable operations change.
- **The production gate** (AD-21 condition 6). Johan said not to build it and has not named the release.
- Report Manager's `permissions_any`, nested scope source, larger body cap for template import, and two audit actions on one route. They wait for a later release, to keep this one reviewable.
- A refusal at load time of an already-installed module without a category (CQ38).

## Questions for Johan

Written to `reviews/questions/core.md` as CQ37 to CQ40. The assumption I went on with is in each.

- CQ37: a role that may manage notes but not list them cannot edit a note through Core (Tactical's own read needs List). Assumed fail closed.
- CQ38: what "refused" means for a module with no category off a development server. Assumed install and enable only.
- CQ39: a replacement must carry `premium`, or have no category on a development server.
- CQ40: the hard upload ceiling is 10 MiB.

## What was not exercised here

Django and Tactical are not installed on the development PC. These ran only against stubs:

- Tactical's real dispatch of the before-read, DRF's `query_params`, and Tactical's own multipart parser;
- the real `AuditLog` fields (`object_id`, `before_value`, `debug_info.correlation_id`) and the JSON lookup that finds a row;
- the root helper as root, the sudo dispatch and a real reload;
- the real root config read.

`tests/tactical-operations-runtime-1.17.13.py` and the two corrected scripts are the dev-server proof. Run them with `manage.py shell`. Each prints PASS or FAIL per step, rolls back or deletes what it creates, and touches no real module, job or state file. The first script creates a throwaway client, site, agent and note in a transaction that is rolled back, and uploads one small report asset that it deletes again.

## Tests

- New stub tests: `tests/module-category-install-route-1.17.13.py`, `tests/tactical-operations-audit-object-1.17.13.py`, `tests/tactical-operations-query-upload-1.17.13.py`, `tests/module-category-1.17.13.py`, `tests/module-category-helper-1.17.13.py` (also the rollback record), `tests/module-replacement-audit-1.17.13.py`, `tests/module-replacement-runtime-probe-1.17.13.py`.
- New dev-server script: `tests/tactical-operations-runtime-1.17.13.py`.
- Renamed and corrected: the two runtime scripts above.
- Changed by design, because a replacement must now be `premium` (a development server for one with no category), or because the capability and the view gained fields: `tests/module-replacement-1.17.9.py`, `module-replacement-capabilities-1.17.9.py`, `module-replacement-owner-1.17.9.py`, `module-replacement-registration-1.17.10.py`, `module-replacement-conflict-1.17.11.py`, `module-replacement-dependency-1.17.11.py`, `module-replacement-enable-1.17.11.py`, `module-replacement-held-lows-1.17.11.py`, `module-replacement-helper-1.17.11.py` (with a new category drift guard), `module-replacement-install-1.17.11.py`, `module-replacement-server-1.17.11.py`, `module-replacement-server-owner-1.17.11.py`, `module-status-replaces-1.17.11.py`, `module-replacement-handback-1.17.12.py`, `module-replacement-helper-handback-1.17.12.py`, `module-replacement-audit-1.17.12.py` (a failed row now needs `rolled_back` to say the flags were put back), `f11-openapi-final-1.15.178.py` (`premium` is a valid category now) and `tactical-operations-1.17.7.py` (capability 1.1.0, the `query` field).
- `tests/release-integrity.sh` passes. `ruff check` adds no new finding to the files it touches beyond the style the repo already carries.

## Fixed in the precheck round

The first install route had a gap. `POST /api/tfd/modules/packages/<id>/install/` and the offline single-package path (`queue_v2_install` hands it to the v1 worker) did not check the category. A module with no category, or category `test`, could install on a server that is not a development server.

- `module_manager.inspect_archive` now sets `installable: false` for that module, with the plain reason `module_category.REFUSED_MESSAGE`. `queue_install` and `queue_v2_install` refuse it before any job is written.
- The v1 root worker `scripts/module-job-helper.py` now reads the category from its own root-private copy of the package, refuses before the install script runs, and fails closed when the manifest is missing, mismatched or names an unknown category. After a successful install it writes the category into the module's state entry, as the v2 worker does.
- Test: `tests/module-category-install-route-1.17.13.py`. It covers the direct v1 route and `queue_v2_install` on a local package, for a missing and a test category, on and off a development server, plus the worker's package reader and state write.
- Module-facing: the package preview of a Test module now returns `installable: false` and `install_block_reason` off a development server. Both fields already existed.
- Not run here: the worker as root and the sudo dispatch.

## Fixed after review

- A multipart upload through `POST /api/tfd/tactical-operations/<module>/<op>/` was refused with 400 "Unknown field(s)", because DRF puts the file part into `request.data`. The view now leaves the file keys out of the unknown-field check. The exactly-one-file and declared-name checks are unchanged. Tests: the stub `DRFRequest` in `tests/tactical-operations-query-upload-1.17.13.py` now carries the file key in `data` as DRF does, and `tests/tactical-operations-runtime-1.17.13.py` has a new step 8b that posts a real multipart request to the view with `APIRequestFactory`. Step 8b did not run here (Django is not installed).
