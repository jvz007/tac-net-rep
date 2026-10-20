# Tec-Tac Framework 1.17.58

Licensing now runs in log-only mode, as Johan decided on 19 October 2026: nothing is enforced, and Core records what enforcement would have blocked. A health check that calls another capability can no longer hold a web worker for 300 seconds. The agent list can be sorted on the server. A masked list in an audit row now says whether it changed.

Date: 20 October 2026. Every earlier operation, argument, route and response field stays. Contract changes are additive: `core.resources` 1.11.0 to 1.12.0, `core.tactical_operations` 1.15.0 to 1.16.0, and a new capability state, a new runtime setting, a new read route and an optional request field for the licence gate.

## Johan's licensing rules (binding)

These come from Johan's answers of 19 October 2026 ("okay lets stick to log-only", Q13 and the Welcome audit). The code, the docs and the tests state each one.

- **The default is log-only. Nothing is enforced.** A module that needs a licence is staged or installed even when its licence check fails. Core writes one audit row, `custom:licence-would-block`, so the owner can see what enforcement would do.
- **Licensing never blocks sign-in, Tactical operations, module rollback or security updates, in any mode.** The licence gate is called only from module stage and install code. `tests/licensing-enforcement-mode-1.17.58.py` reads the source and fails if sign-in, the UI context, the Tactical operations executor, rollback or the system-update helper ever reaches it.
- **A revoked licence will disable new installs only when enforcement is on.** That is not built. Nothing can detect a revoked licence yet: it needs the 24-hour refresh of the licensed catalogue. Nothing is enforced now, so nothing is disabled.
- **Flipping the default to enforce before public beta is one constant.** `DEFAULT_LICENSING_MODE` in `framwork/tec_tac/module_licensing.py`. The stored mode is blank until someone chooses, so the flip needs no data migration, and a mode someone chose stays. The request is filed in `reviews/requests/core.md` and waits for Johan to name the release.

**For human review (commercial).** This release loosens today's refusal: a module whose licence check fails, or whose licensing capability is missing, now goes through by default. The optional override (below) is a bypass of a licensing gate. Questions CQ166 to CQ168 in `reviews/questions/core.md` ask Johan to confirm both.

## What is new

### Capability health checks cannot loop (request from Johan's dev02 test, 17 October 2026)

On dev02, `GET /api/tfd/reportmanager/data-sources/providers/` held a uWSGI worker for 300 seconds and nginx answered 504, with a `RecursionError` in capability health checks. The loop is not in the source tree, so Core now stops any loop of this kind.

- Core keeps, per thread, the ids whose health callback is running. A nested `capability_status` for an id already running, or nested more than 8 deep, answers at once with state `health-reentrant`, `available: false` and the reason `Capability health check re-entered: A -> B -> A`. The reason names capability ids only, never provider text.
- The stack is always popped, even when a callback raises, so a healthy capability is never marked unhealthy by a stale id. It is per thread, so another thread is unaffected.
- `get_capability` raises `CapabilityUnhealthy` for it, and that class keeps `state == "unhealthy"`. Backups matches on that, so it needs no change.
- `check_health=False` never runs a callback and is unchanged.
- This does not fix Licensing's own recursion (`reviews/requests/core-modules.md`, "licensing: `licensing.entitlements` health check logs a RecursionError"). It stops the loop from holding a worker, and the reason text names the loop if it happens again.

### Sort the agent list (`core.resources` 1.12.0, agent-management 0.15.0)

`list_agents` and `GET /api/tfd/resources/agents/` take `sort_by` (`hostname`, `client`, `site`, `platform`, `last_seen`) and `sort_dir` (`asc`, the default, or `desc`).

- Strict: lowercase and case-sensitive. An unknown key, an unknown direction, an empty value that is present and a value that is not text give 400 `invalid_resource_request`.
- A valid `sort_dir` without `sort_by` is accepted and ignored (the default order has no direction). An invalid `sort_dir` is refused either way.
- The order is applied inside the caller's scope and before the page is cut. A person limited to one site never sees or counts another site's agents. Every sort ends with the old order (client, site, host name, agent id), so paging is stable. `last_seen` puts an agent that never reported last in both directions.
- Without `sort_by` the order is exactly the old one, and the call still costs one count query and one page query.

### A changed or unchanged marker for a masked list (`core.tactical_operations` 1.16.0, tasks 0.10.2)

A masked list records names and `***`, so a change to one argument's value or to a command's text looked like no change. For each list named in `audit_list_masks`, the success row now carries `<list>_changed` on the after side (for example `actions_changed`): `true` or `false`, a bool and never a value.

- Core compares a digest of the raw list in Tactical's before read with a digest of the body's raw list. The digests live in memory for the comparison and are never stored, logged or returned (rule A8).
- It is left out when the before read did not return the list, when the caller gave its own `audit_before`, or when the body sent no list. Core never claims "unchanged" without evidence. It never appears on a failed, denied or outcome-unknown row.
- An operation without `audit_list_masks` writes exactly the rows it wrote before. Tasks can remove its "shows unchanged" help text in its own release.

### The object count follows the object (held Low of 1.17.52)

`metadata.object_count` was counted from the first scope entry even when that entry was marked `names_object: false` and did not name the row's object. The success, failed, Tactical-denied and outcome-unknown rows now count the first entry that names the object, so `object` and `object_count` describe one thing. The scope's own refusal rows keep the full count. An operation with no `names_object: false` entry writes the same rows as before. The plan named the success and outcome-unknown rows. The failed and Tactical-denied rows also name the filtered object, so they follow the same rule.

### Does a replacement register under its own id? (patchmanagement 0.11.0)

Yes, and now a test says so. `tests/module-replacement-registration-1.17.58.py` pins that a premium module with `replaces = "patching"` registers `scan`, `install`, `set-update-action` and `reset-patch-policy` on the `winupdate/` and `automation/patchpolicy/` routes while Core honours the replacement, and that each registration is refused with `TacticalOperationRegistrationError` (a `ValueError`, never another exception, nothing left registered) while Windows Patching is enabled. No registration behaviour changed.

`docs/module-replacement.md` has a new section that answers the second question from the code:

- Core decides at the moment `register_tactical_operation` is called, from the owner table and the live module state. A refused registration is not remembered and not retried.
- The enable job writes the new module state first, then reloads. It sends a graceful `SIGHUP` to the Tactical uWSGI master (the web workers that serve Tactical operations start again and run `ready()`), then restarts the `celery` service. It does not restart `celery-beat` or Tactical's socket service, and it skips the uWSGI step if `reload-rmm-uwsgi.sh` is not on the server.
- So no extra restart is needed after a finished enable job. The Help article can say: "If an operation is missing afterwards, restart the `rmm` service." This comes from reading the helper. It has not run on a server.

### The licensing mode, the status read and the audited override

- **The mode.** A new runtime setting `licensing_enforcement_mode`: `off`, `log-only` (the default) or `enforce`. Migration `0033_runtime_licensing_mode` adds a blank text column to the runtime configuration row. Blank means "use Core's default". Only an effective superuser changes it (checked before the value; a refusal writes one deny row; a mixed body is refused whole). `null` resets it. Each change writes one strict audit row with the effective mode before and after and whether each came from a choice or from the default. The getter `get_licensing_enforcement_mode()` never raises: a read error or an invalid stored value reads as `log-only`. The new text setting also fixes the change check in `RuntimeSettingsView.patch`, which read every stored value as a number.
- **The gate.** `_enforce_candidate_licensing` follows the mode. `enforce` refuses exactly as in 1.17.57. `log-only` runs the check, lets the module through, writes one best-effort audit row and sets `licensing_status` to a summary with `would_block: true`. `off` skips the check and sets `state: "not-checked"`. A module with no licence need and a licensed module read the same in every mode. A failure of the check itself is a would-block outside enforce and still an error in enforce.
- **No provider text in the row or the status.** The row and the log-only status carry the manifest's own names, Core's state code and a fixed sentence per state. A provider's reason, `details` dict, health dict and exception message are never copied (a marker secret in each place never shows up in a row, a status or a log line). The enforce-mode 403 payload is unchanged and still carries the provider's own result, as before.
- **The status read.** `GET /api/tfd/system/licensing/` for an effective superuser or a holder of `core.runtime_settings.manage` (403 for anyone else; no audit row; no network call). It shows the mode, the licence state (`licensing_unavailable` while the Licensing module is missing, disabled, unhealthy or provisional, so nothing shows as licensed while module licensing is provisional), the installed modules that would be blocked (at most 50 listed, with the true count), the grace window (7 days, `days_left: null` until a signed refresh time exists), the things licensing never blocks and the revoked-licence rule in plain words. The UI context answer is not changed.
- **The override.** For an emergency, an effective superuser may send `licence_override_reason` (1 to 500 characters) on the v2 inspect, v2 install and repository stage routes. It matters only when the mode is `enforce` and the check refused: Core writes one strict audit row first (`custom:licence-override`, with the reason) and the stage or install continues. If the row cannot be written, the refusal stands. It skips the licence refusal and nothing else: signature, trust, compatibility, dependency and replacement checks run as before, and a test pins that the override is used inside the one gate function. It does not carry from stage to install. The v1 module package routes take none. Anyone else who sends the field gets 403 and one deny row before any package work.

### Held Lows closed

- **Decimal on an integer column (1.17.52 review).** Documentation and a pinning test, no code change. Core cannot know a column's type, so the reviewer's fix ("equals on a non-whole value matches nothing") would break real decimal and float columns. A number field whose lookup is an integer column or a `Count` annotation must declare `integer: true`. Then a decimal rule value is refused when the set is saved or evaluated (2.5 is refused, 2.0 is stored as 2), so `build_q` and `matches` cannot disagree. The rule is in `docs/filter-sets.md` and in the field declaration text.
- **The 1.17.57 decision-record test.** It compared the version exactly, so a `-N` rebuild or this bump would break it. It now strips a `-N` suffix, requires at least 1.17.57 and looks for its notes at the root or in `docs/releases/`. `RELEASE_NOTES_1.17.57.md` moved to `docs/releases/`.

## Module-facing change

Everything below is additive. A module that ignores it keeps working.

- **`capability_status` state `health-reentrant` (capabilities).** A status dict can now carry `state: "health-reentrant"` with `available: false`. Callers of `get_capability` see `CapabilityUnhealthy` with `state == "unhealthy"`, as for any unhealthy provider. A caller that compares the status dict's `state` against an exact list should treat any state other than `available` as not available. A scan of `modules/` found no module that breaks on it. Two compare the status dict's `state` with exactly `unhealthy`, and neither fails: Alerts (`endpoint_names.py`) would read a re-entrant Agents status as "not supported" instead of "unavailable", and Checks (`scheduled_actions.py`, `TRANSIENT_STATES`) treats it as permanent instead of transient, so a re-entrant answer is not retried (it is not transient: a loop will loop again). Backups matches on the exception's `state`, which stays `unhealthy`. The scan found no other exact match against the status dict's `state`.
- **`core.resources` 1.12.0.** `list_agents(sort_by=None, sort_dir=None)` and the two query parameters on `GET /api/tfd/resources/agents/`. Needs framework >=1.17.58 and is feature-detected with `core.resources >= 1.12.0`. A caller that does not sort gets the old order. The parameters go to the adapter only when `sort_by` is given, so an adapter or a test stub that predates 1.12.0 keeps working. Agent Management 0.15.0 can mark its columns sortable.
- **`core.tactical_operations` 1.16.0.** `<list>_changed` on the after side of a success row for each list in `audit_list_masks`, and the object-count rule above. No new declaration key. Feature-detect with `core.tactical_operations >= 1.16.0`. Tasks reads the new key with `.get`.
- **Licence gate request field `licence_override_reason`.** Optional, on `POST modules/v2/packages/inspect/` (a form field), `POST modules/v2/packages/<upload_id>/install/` and `POST modules/catalog/online/stage/` (JSON). Errors: 403 `licence_override_superuser_required`, 400 `invalid_licence_override_reason`.
- **Licence gate answers.** The 403 `licensing_requirement_failed` payload gains `licensing.enforcement_mode` (always `enforce`: only enforce refuses). A candidate's `licensing_status` gains `enforcement_mode`, `would_block`, `audited` (log-only) and `overridden` (an audited override). **Behaviour change:** in the default log-only mode a failing licence check no longer gives 403. Report Manager is the one module in `modules/` that declares `licensing.required`. Its stage and install now go through by default, with a would-block row.
- **Runtime settings.** `GET` and `PATCH /api/tfd/system/runtime-settings/` gain `licensing_enforcement_mode` (`{value, source, choices, default}` on GET). Superuser only to change.
- **New route.** `GET /api/tfd/system/licensing/` (OpenAPI group "Tec-Tac · Licensing").
- **Audit.** New actions: `custom:licence-would-block` (best effort, actor the service `core/licensing/gate`) and `custom:licence-override` (strict, actor the superuser). Nothing in `modules/` reads either.
- **Contract export.** The newest export is `1.17.57-0.12.117`. Johan generates a fresh one on the dev server after the install (checklist step 8). It shows `core.resources` 1.12.0 and `core.tactical_operations` 1.16.0.
- **Requests for other areas.** The UI request (mode selector, status panel, override control; UI 0.12.118 requires Core >=1.17.58) is in `reviews/requests/ui.md`. The Licensing request (keep the health keys Core reads stable) is in `reviews/requests/core-modules.md`.

## What does not change

- Sign-in, the UI context answer, Tactical operations, module rollback and system updates never touch licensing.
- A module with `licensing.required: false` and the manifest rules for `licensing` are unchanged. `check_licensing_requirement` is still a pure check that raises exactly as before.
- A licensed module stages and installs as before in every mode. The enforce-mode refusal payload keeps its old fields.
- The default order of the agent list, the rows of every Tactical operation that does not declare `audit_list_masks` or `names_object: false`, and every earlier capability state.

## Requests closed or answered

- Closed (removed from `reviews/requests/core.md`): "core: capability health must be re-entrancy-safe" (Johan's test, shipped 1.17.58); "core.resources: sort_by and sort_dir on the agent list" (agent-management 0.15.0, shipped 1.17.58); "a per-list changed or unchanged marker next to `audit_list_masks`" (tasks 0.10.2, shipped 1.17.58); "confirm that a replacement's Tactical operations register under the replacement's own module id" (patchmanagement 0.11.0, answered in `docs/module-replacement.md`, shipped 1.17.58).
- Opened: "flip `licensing_enforcement_mode` to enforce before public beta" (Johan, 19 October 2026). It ends when Johan names the release.

## Left out on purpose

- **R-02a: text rule values shown to people who do not own a shared filter set.** Hiding them changes what every Agents user sees in a shared set. It is Johan's call (CQ165). Assumption: unchanged. It stays a held Low.
- **The 7-day grace window computed from a signed timestamp (R-34).** No input exists until the licensed catalogue and the Licensing capability exist, and Core has no agreed place for the issuer's public key. The status read shows `window_days: 7` and `days_left: null`.
- **A revoked licence disabling new installs (Q13).** Only when enforcement is on, and nothing can detect revocation yet (R-31). Not built.
- **The licensed catalogue route and refresh button (R-31), the licence key sent on download (R-32), automatic recovery, licensed limits, expiry warnings, the licence-changed notice and key replacement (R-33).** They wait on the signed AD-26 exception (Q4), the Licensing module's catalogue capability, the secret store and the Licensing Server endpoints.
- **The secret store `core.secrets` (R-30) and the AD-26 provider.** They wait on Johan's seven secret-store decisions and the Licensing module.
- **Flipping the default to enforce.** A request, not a change here.
- **The Licensing UI** (mode selector, status panel, override control): UI 0.12.118, request filed.
- **Release B items** (the system-action contract, Scheduler async completion, the job-finished hook, hand-registered maintenance actions; installer route, policy task naming, conditional scope for `reset-patch-policy`, the accounts inviter check): the Scheduler hot path gets its own release, and the rest has no urgency.
- **R-36 and R-37 to R-47** (disable Tactical's native patching while a replacement is honoured, CQ130, CQ131, CQ151, the software after-value, deny in `action_by_body`, category enforcement, `conflicts_with`, CQ93, the test-run outcome, two audit actions on one route, the dev-server confirmations): they wait on Johan's answers or decisions.
- **The R-12 permission alias hook and R-13 saved-views permission gate:** not in Johan's list for this run. Each waits on his plan questions (Q-05, Q-06). The numbering R-10 to R-12 in this release follows Johan's licensing list (mode, status, override), not the plan's R-12 alias.
- **`docs/module-audit.md`.** The plan named it for the `object_count` wording. That file never described `object_count`, so the wording is in `docs/tactical-operations.md` ("A count of the ids a list scope names").

## Tests

New, all named after this version:

- `tests/capability-health-reentrancy-1.17.58.py`: a two-capability loop and a chain of 10 both return in well under a second with `health-reentrant`, no `RecursionError`; the stack is empty after a raising callback and after a refusal; another thread is unaffected; a healthy capability stays available; `get_capability` raises `CapabilityUnhealthy`; `check_health=False` is unchanged.
- `tests/tactical-operation-object-count-1.17.58.py`, `tests/tactical-operation-list-marker-1.17.58.py` (a marker secret never appears in a row, a digest, a log line or the result), `tests/filter-sets-integer-number-1.17.58.py`, `tests/module-replacement-registration-1.17.58.py`, `tests/resources-agent-sort-1.17.58.py` (every key both ways, 400s, scope before paging, query count).
- `tests/licensing-enforcement-mode-1.17.58.py`, `tests/licensing-status-1.17.58.py`, `tests/licensing-override-1.17.58.py`, with the shared stubs in `tests/licensing_harness_1_17_58.py`. They run the real gate, the real views and the real settings code against stubs for Django, DRF, the configuration row and the audit writer.
- `tests/licensing-mode-runtime-1.17.58.py`: the dev-server script (migration applied, the setting round trip, one refusal in enforce, one pass plus one audit row in log-only, the override row, the status read). It did not run here.

Changed:

- Version and migration pins moved to the new values (`core.resources` 1.12.0, `core.tactical_operations` 1.16.0, migration 0033) in the tests that pin them.
- `tests/decision-record-ad40-winupdatepolicy-1.17.57.py` is version-tolerant (see above).
- `tests/module-repository-skipped-1.17.39.py` allows the override's words in the repository stage code (it still forbids any entitlement, revocation or downgrade check there).
- `tests/tactical-operations-modules-compat-1.17.18.py` set up a premium replacement badly, so it failed as soon as `modules/` sat beside the repository (it had only passed by skipping). It now sets the replacement state the way `tests/module-replacement-owner-1.17.9.py` does, and passes against all 14 modules that declare operations.
- The tests that expected a refusal through `_enforce_candidate_licensing` replace the gate with a stub or call `check_licensing_requirement` directly, so the default mode does not touch them.

## What ran here, and what could not

- Django is not installed on this PC. The model field, migration 0033, the real views, the route, the OpenAPI grouping and the real audit table could not run. They are covered by the stub tests and by `tests/licensing-mode-runtime-1.17.58.py` on the dev server. Migration 0033 is written by hand: run `manage.py makemigrations --check --dry-run` on the dev server to confirm it matches the model.
- The statement about what the enable job restarts comes from reading `scripts/module-v2-job-helper.py` and `scripts/reload-rmm-uwsgi.sh`. It has not run on a server.
- Every new test above and every test I changed passes on this PC (Windows, Python 3.12.10). I ran all 463 `tests/*.py` here and all 54 `tests/*.sh` in WSL Ubuntu, each also on a clean copy of 1.17.57, and compared. Nothing that passed before fails now. About 120 Python tests and 16 shell tests fail on both, because they need Django, PostgreSQL, root paths or Linux-only files. `tests/licensing-mode-runtime-1.17.58.py` is dev-server only and fails here for the same reason.
- `bash tests/release-integrity.sh` (WSL): PASS. `python -m py_compile` equivalent (`compile()` of all 64 changed or new Python files): clean. `ruff check` with the pipeline's gate rules (`--select E9,F63,F7,F82`, py312) on the whole tree: clean. The repository has no ruff config of its own.
- `tests/tactical-operations-modules-compat-1.17.18.py` passes with `modules/` beside the repository; before this release it only passed where `modules/` was missing, because it skipped.

## Dev-server checklist (Johan)

Install the signed 1.17.58 build first (it runs migration 0033). Then:

1. **Version and migration.** Check the version in the Core UI or `cat /opt/tec-tac/VERSION`, then `manage.py showmigrations tec_tac`. Expected: version 1.17.58 and `[X] 0033_runtime_licensing_mode`. FAIL: another version, or 0033 not applied. Send back the `showmigrations` output and the install log tail.
2. **Nothing else moved.** Sign in, open the Modules page and open two of Tactical's own pages (Agents, Clients). Expected: all three work as before. FAIL: a sign-in problem, an error banner or an empty Modules page. Send back a screenshot and the time.
3. **The providers route (the R-01 regression).** Open `/api/tfd/reportmanager/data-sources/providers/` signed in. Expected: 200 within a few seconds. FAIL: it waits more than 10 seconds, 504, or an error. Send back the status, how long it took, and the last 50 lines of the uWSGI log (`journalctl -u rmm -n 50`).
4. **The setting reads log-only.** Open `/api/tfd/system/runtime-settings/` signed in. Expected: `licensing_enforcement_mode` shows `value: "log-only"` and `source: "default"`. FAIL: the key is missing, or another value. Send back the whole answer.
5. **The runtime script.** `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/licensing-mode-runtime-1.17.58.py`. Expected: lines for default, enforce refused, log-only passed with one would-block row, override with one audit row, the status read, and `PASS` at the end (it rolls everything back, so the mode is log-only afterwards). FAIL: any `FAIL:` line or no `PASS`. Send back the whole output.
6. **The status read.** Open `/api/tfd/system/licensing/` signed in as a superuser. Expected: `mode` log-only, `licence.state` `licensing_unavailable` while Licensing is provisional, `grace.days_left` `null`, a `never_blocked` list, and no key, token or fingerprint text anywhere. FAIL: 404, a state of `licensed` while Licensing is provisional, a number in `days_left`, or any key, token or fingerprint text. Send back the whole answer with anything private blanked. A person with no runtime-settings right should get 403.
7. **Sorting.** Open `/api/tfd/resources/agents/?sort_by=hostname&sort_dir=desc`, then `/api/tfd/resources/agents/?sort_by=bogus`. Expected: the first lists the agents with host names in descending order; the second answers 400 with `invalid_resource_request`. FAIL: the order is unchanged, or the second answers 200. Send back the first three items and the second answer.
8. **Export the public contract.** Generate a fresh public contract export into `docs/contracts`. Expected: the file lists `core.resources` 1.12.0, `core.tactical_operations` 1.16.0, the route `/api/tfd/system/licensing/` and the capability state `health-reentrant`. FAIL: an older version in the export or an export error. Send back the error and the export file name.
