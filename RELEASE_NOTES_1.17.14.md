# Tec-Tac Framework 1.17.14

Two refusals became warnings, so you can still switch a replacement off when its replaced module cannot come back. A failed module job now tells the people who can act on it. A note edit no longer needs Core to read the note first. A module you already installed can be enabled again, whatever its category. The upload limit is a setting. Johan decided all of this on 9 October 2026 (CQ34 to CQ38 and CQ40).

Closes: in `reviews/requests/core.md`, the entry "Johan's answers to CQ34 to CQ40" (CQ34, CQ35, CQ36, CQ37, CQ38 and CQ40) and the two entries "from ui 0.12.91" (the `ui.authenticated.tactical-operation` row and the modules/v2 fields in the export). Also the Low held from the 1.17.13-1 review (a category-refused v1 install left files behind). CQ39 was answered (a) and shipped in 1.17.13. Not closed: the production gate (AD-21 condition 6). See "What this release leaves out".

## What changed

### Disabling a replacement whose replaced module cannot come back now warns (CQ34)

Until now Core refused. It said "Nothing was changed" and left you stuck. Now Core works out which replaced modules can come back and which cannot.

- `modules[].will_enable` lists only the modules that can come back.
- `modules[].hand_back_unavailable` lists the others: `[{module, reasons[], required_modules[]}]`. The reasons are plain English: a missing or disabled dependency, a version that does not fit, a runtime requirement, or a module that cannot be managed from the UI. `required_modules` names the module behind the dependency, so the UI can say which one is needed.
- `modules[].hand_back_confirmation_required` is true when that list is not empty.
- The first disable is answered with HTTP 400, `code: replacement_hand_back_confirmation_required`, and nothing is queued. The answer carries `detail`, `module`, `will_enable` and `hand_back_unavailable`.
- Send the request again with `confirm_without_hand_back: true` to go ahead. Only exactly `true` confirms. `false` is the same as missing. Any other type is a plain 400, as for `confirm_replacement_switch`.
- The job then disables the replacement and hands back only what can come back. `enable_modules` holds that filtered list, so the root helper is unchanged and still re-checks every rule. The job records `hand_back_skipped`. The queue-time audit row names what was skipped. The outcome row says the replaced module stayed off.
- `_hand_back_problems` stays, and returns warnings now. `hand_back_blocked` is no longer a refusal.

An old caller that sends no flag sees a refusal and nothing changes. Core does not offer to install a missing module. The catalogue is not online yet, so the warning only names the module that is needed.

### Enabling a replaced module no longer refuses when the replacement has dependants (CQ35)

`replacement_has_dependants` is gone. The catalogue row of the replaced module carries `replacement_dependants`: `[{replacement, modules[]}]`, the enabled modules that name the replacement directly in `dependencies`. Modules that depend on the replaced module are not listed. That module is the one coming back, and the replacement's contract parity (AD-20 condition 3) keeps the others satisfied. The `replacement_second_confirmation_required` answer gains `dependants` with the same list, so the warning appears in the confirmation you already show. Nothing cascades. The job and the root helper are unchanged.

### A deliberate disable always hands back, and a failed job tells people (CQ36, CQ41)

- Hand-back stays with a deliberate disable only. It never happens on a rollback, a failed job, a reconcile job or a fault.
- One gap is closed. A replacement disabled as part of a deliberate cascade (it depends on the module being disabled) now hands back its replaced module too. Core builds the list over every module in the cascade. No extra confirmation. The root helper already accepted a replacement anywhere in the job.
- New `tec_tac.notices.publish_system_notice(...)` stores one notice per recipient: source `core`, level `error`, `client_id` `module-job-failed:<job id>`, and an action that opens `/modules`. It stores a notice once. A notice the person has already read is not reset by the next tick.
- New `module_failure_notices.sweep_failed_jobs`, called by the scheduler tick next to the replacement audit sweep, raises one notice for each failed module job: enable, disable, install, bundle install and batch install. A failed switch says whether the flags were put back, from `rolled_back` and `rollback_error`. The text is plain English and printable ASCII, cut short, with no paths. It looks only at jobs finished in the last 7 days, at most 200 a tick, newest first. It never raises.
- Recipients, on my assumption (CQ41 below): every active superuser, plus the user who started the job when that user is active. Installer and agent accounts never receive one.
- The browser toast for a new server-created notice is a UI change. Until it ships, the notice shows in the notice history.

### Tactical operations: the before-read scope check is removed (CQ37)

You said a note edit is not a Tactical function Core should guard by reading. So the scope source `before:<field>` is gone, and so is the fixed 404 `object_not_found` that came from a before-read that did not answer 200. Registering a `before:` source is refused with a plain message.

An operation that has only an object id (an Agents note edit or delete: route `agents/notes/{pk:int}/`, `audit.object_param` `pk`, `scope` empty) registers and runs with Tactical's own check deciding. That is how `cancel-pending-action` already worked. I read Tactical's `GetEditDeleteNote`: its `put` and `delete` check `_has_perm_on_agent` and answer 403, and a missing note gives 404. Core relays both and writes a deny row for the 403. The audit row still names the pk.

`audit.before` stays. It only fills the row's before value. It never refuses a call (my assumption, CQ42 below). A role that may manage notes but not list them can now edit a note, and the row records that no before value was kept. The capability `core.tactical_operations` is `1.2.0`, still major 1.

### A module that is already installed can be enabled, whatever its category (CQ38)

The AD-21 refusal for a module with no category now applies at install only.

- The web side no longer puts `category_refused` into `_enable_problems`. That also stops it blocking a hand-back.
- The root helper `scripts/module-v2-job-helper.py` no longer checks the category at the top of `apply_enable_job`. The install checks stay: `verify_install_categories` and the v1 helper's package check. An upgrade is an install, so it is still checked.
- `category_refused` stays as a status field. It now means "an install is refused". The warning text, `REFUSED_MESSAGE`, the docs and the contract text all say install only.
- The replacement rule (CQ39) and the Tactical operation owner checks are not touched.

### The upload limit is a setting (CQ40)

- New runtime setting `tactical_operation_upload_max_mib`: whole MiB, 1 to 25, **default 10**. It lives on `TecTacRuntimeConfig` (migration `0026_runtime_upload_limit`). An existing row reads as 10.
- `GET /api/tfd/system/runtime-settings/` returns it as `{value, minimum, maximum, default, bytes}`. `PATCH` accepts the module register timeout, the new key, or both. A body with only the old key behaves as before. An empty body or an unknown key is a 400. Values are validated like the timeout: a boolean, float or string is refused.
- Only a superuser changes the upload limit (my assumption, CQ44, the same rule as the update source). The timeout keeps `core.runtime_settings.manage`. Each changed setting writes its own strict audit row with `object_id` the setting name, in the same transaction.
- The executor and the HTTP view use the smaller of the operation's own `max_bytes` and the setting, read on every call. Lowering the setting takes effect at once, with no restart.
- Registration runs in `AppConfig.ready()` and must not read the database. So it checks a fixed absolute ceiling of 25 MiB (`MAX_UPLOAD_ABSOLUTE_BYTES`). `MAX_UPLOAD_BYTES` stays exported as the 10 MiB default, so no import breaks.
- The capability's `limits` report `upload_bytes` (effective), `upload_bytes_default` and `upload_bytes_max`.
- **Not verified:** a body-size limit in nginx or in Tactical sits in front of Core. This release changes neither, and I could not check either from this PC. If you raise the setting above what the web server accepts, the upload fails before Core sees it.

### The exported contract (UI 0.12.91 export items 1 and 2)

- The `ui.authenticated.tactical-operation` row now lists the five options (`params`, `body`, `query`, `file`, `signal`), the 16-name and 512-character query limits, the multipart part names, that there is no auth or audit option, that a file named `params`, `body` or `query` is refused in the browser, that the row needs Core 1.17.13 and UI 0.12.91, and that Core's refusal codes pass through as `error.code`. It no longer says "options accepts only params, body and signal". The size sentence says the ceiling is 10 MiB by default and a setting since 1.17.14, and notes the `{file_name}` limitation.
- A new development rule names the modules/v2 fields, request fields, refusal codes and job fields, says which ones are new in 1.17.14, and says `replacement_has_dependants` and the `hand_back_blocked` refusal were removed. The route entries carry the same fields. This closes the reviewer's "newest contract does not list the fields the UI uses" finding (UI 0.12.90 review, Low).
- A second rule describes the notices Core now creates itself.
- Python contract list: `tec_tac.runtime_settings.get_tactical_upload_max_bytes`.

### Held Low from the 1.17.13-1 review: a refused v1 install now cleans up

`scripts/module-job-helper.py` `run_job` returned early when the AD-21 check refused an install. That left `RUNNING_ROOT/<job id>` (the root-private package copy) on disk and the log without its `0o640` mode. It no longer returns. It sets the failed status and `CategoryRefused`, then runs the shared tail: chmod the log, remove the running request, remove `RUNNING_ROOT/<job id>`. The refusal itself is unchanged. The diff looks larger than the change, because the lifecycle block moved one indent level under `if command is not None:`.

## Module-facing changes

- **`core.tactical_operations` is `1.2.0` (still major 1; callers ask for `>=1,<2`).** The scope source `before:<field>` is **removed**. It was added one release ago in 1.17.13. I searched `modules/` (every `operations.py` and `apps.py`): no module declares `before` or a `before:` source, so nothing breaks. Registering one now raises `TacticalOperationRegistrationError`. The capability metadata lists it under `declaration_keys_removed_in_1_2_0`.
- `register_tactical_operation`: an upload `max_bytes` may be at most 25 MiB (it was 10 MiB). A file is held to the smaller of that and the system setting. `MAX_UPLOAD_BYTES` is still the 10 MiB default. New constant `MAX_UPLOAD_ABSOLUTE_BYTES`, new helper `upload_ceiling_bytes()`.
- Capability `limits`: `upload_bytes` is now the effective ceiling. New `upload_bytes_default` and `upload_bytes_max`.
- `POST /api/tfd/modules/v2/<id>/state/`: new optional request field `confirm_without_hand_back`; new refusal code `replacement_hand_back_confirmation_required`; `replacement_second_confirmation_required` gains `dependants`. The old callers' shape is unchanged.
- `GET /api/tfd/modules/v2/`: new row fields `hand_back_unavailable`, `hand_back_confirmation_required` and `replacement_dependants`. `will_enable` now lists only what can come back.
- Jobs (`GET /api/tfd/modules/v2/jobs/`): new `hand_back_skipped`.
- The problem types `replacement_has_dependants` and `hand_back_blocked` are removed. A disable or an enable that 1.17.12 refused for those reasons now warns and asks for the confirmation.
- `category_refused` keeps its meaning for an install plan and is no longer an enable problem.
- `GET`/`PATCH /api/tfd/system/runtime-settings/`: the new key. A new refusal for a non-superuser who sends it.
- Notices: Core now creates notices itself (source `core`, `client_id` `module-job-failed:<job id>`).
- Modules affected by the Tactical operations changes: Agents (can now declare `note-edit` and `note-delete` with empty scope), Alerts, Checks, Licensing, Report Manager and Script Execution (all register operations; none uses the removed source or the old 10 MiB cap as a hard limit). Nothing in `modules/` declares `replaces` today, so the replacement changes affect no installed module.
- A module that uses any of this needs `requires.framework` `>=1.17.14`.

## What this release leaves out

- **The production gate** (AD-21 condition 6). Johan said not to build it. It waits until he names the release.
- **Offering to install a missing core module** when a hand-back is blocked. The catalogue is not online yet.
- **Hand-back on uninstall.** An enabled replacement that is removed (not just disabled) does not enable the replaced module. Johan answered for a disable only. See CQ43.
- **A public Core contract for modules to push their own server-side notices.** The new `publish_system_notice` is Core-internal and only the module-failure sweep uses it. Alerts keeps waiting for the public one. It needs its own design.
- **Other Tactical operations features** that stay in `reviews/requests/core.md`: permissions any-of, a nested scope source, a streamed file answer (it blocks the report PDF run and the asset download), a larger body cap for template import, and two audit actions on one route. Each is a separate executor feature, and adding them would make this release hard to review.

## For the main session

- `docs/review-accepted-decisions.md`: AD-21 condition 4 still says a test module is refused outside a development server without saying "install only" (CQ38). AD-20 condition 4 should record that disabling a replacement whose replaced module cannot be enabled warns and asks, and that a deliberate cascade hands back (CQ34, CQ36). Only Johan's recorded answers; no new decision.
- Export a fresh public contract into `docs/contracts/` after Core 1.17.14 signs and the dev server runs the new dev-server scripts.
- Requests: the Core entries this release closes are removed from `reviews/requests/core.md`. New requests went to `ui.md` (the Modules page) and `core-modules.md` (Agents). The Agents entry replaces the `note-edit` and `note-delete` wording of "agents: restore four held operations", which still names `before:agent_id`.

## Questions for Johan

Written to `reviews/questions/core.md` as CQ41 to CQ44, with one reading of CQ36. Each has the assumption I went on with.

- CQ41: who receives a module-failure notice? I went with every active superuser plus the user who started the job.
- CQ42: remove only the scope-from-read, or also the optional `audit.before` value? I kept `audit.before`.
- CQ43: should uninstalling an enabled replacement enable the replaced module? I left it out.
- CQ44: who may change the upload limit, and how high? Superusers, 1 to 25 MiB, default 10.
- CQ36 reading: a replacement disabled in a deliberate cascade hands back too.

## What was not exercised here

Django and Tactical are not installed on the development PC. These ran only against stubs, or not at all:

- migration `0026_runtime_upload_limit` and the real `TecTacRuntimeConfig` column;
- real `TecTacUserNotice` rows, the recipient query on Tactical's `User` model and the scheduler tick;
- the real PATCH through DRF (permission and throttle classes), and the real audit rows for each changed setting;
- Tactical's own note views answering a `PUT` or `DELETE` for an agent outside the role (read from source, not run);
- the root helpers as root, and a real module job.

The dev-server scripts are the proof. Run each with `manage.py shell < file`. Each prints PASS or FAIL per step, works inside a transaction that is rolled back, and exits 1 on a failure:

- `tests/module-failure-notices-runtime-1.17.14.py`
- `tests/runtime-settings-upload-runtime-1.17.14.py`
- `tests/tactical-operations-runtime-1.17.13.py` (edited: the note steps now expect Tactical's own 403, 200 and 404)

## Tests

- New stub tests: `tests/module-replacement-warnings-1.17.14.py`, `tests/module-failure-notices-1.17.14.py`, `tests/tactical-operations-before-scope-1.17.14.py`, `tests/module-category-enable-1.17.14.py`, `tests/module-job-helper-category-cleanup-1.17.14.py`, `tests/tactical-operations-upload-setting-1.17.14.py`, `tests/runtime-settings-upload-1.17.14.py` and `tests/contract-export-1.17.14.py`.
- Edited because the behaviour changed by design: `tests/module-replacement-handback-1.17.12.py` (the refusals became warnings), `tests/module-category-1.17.13.py`, `tests/module-category-helper-1.17.13.py` and `tests/module-replacement-reconcile-runtime-1.17.13.py` (an enable is not refused for the category), `tests/tactical-operations-audit-object-1.17.13.py` and `tests/tactical-operations-runtime-1.17.13.py` (no scope from the read), `tests/tactical-operations-query-upload-1.17.13.py` and `tests/tactical-operations-1.17.7.py` (the 25 MiB absolute ceiling and capability 1.2.0), `tests/module-replacement-handback-runtime-1.17.13.py` (the new row fields).
- `tests/release-integrity.sh`, `python -m py_compile` on every changed file and `ruff check` ran on this PC. See the final report for the results.
