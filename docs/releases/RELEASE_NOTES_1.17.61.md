# Tec-Tac Framework 1.17.61

A scheduled job can now say "I started the work, the result comes later", and Core keeps the run open until the real result arrives. Core can also run a scheduled Windows update scan for a named person when nobody is signed in, and it checks that person again every time.

Date: 20 October 2026. Every earlier route, field and contract stays. Everything here is additive. A handler that returns a dict, or nothing, behaves exactly as before.

## What changed and why

Advanced Patch Management 0.11.0 wrote down three things it could not do: finish a scheduled run honestly, run a scan with no person at the keyboard, and let Maintenance start a patch install. This release builds the Core side of the first two. It also builds the Core half of "a server job finished" (R-22). The rest of that request waits for 1.17.62.

This closes the Core requests R-21 (async completion) and the scan part of R-20 (the system-action contract), and the Core-owned half of R-22. It names no earlier signed request that is now closed in full; the remaining parts stay in `reviews/requests/core.md`.

Release B is split (CQ172, assumed). The Scheduler run path, a migration and a new contract are already a full review. R-22's module-callback hook and R-23's root-helper fix go to 1.17.62.

### 1. A run that finishes later (R-21)

A handler returns `pending_completion(kind, external_job_id, note=None)` instead of a result. Core keeps the run `running` and stores the reference. The run is not `succeeded`, `schedule.last_run_at` is not set, and the run is never retried.

- **A Core class, not a dict.** `PendingCompletion` is a frozen class. A dict with the same keys is an ordinary result, so no existing handler can park a run by accident.
- **Two kinds.** `module` (the module completes the run) and `server_maintenance_job` (Core reads the job file). The id is 1 to 128 characters of letters, digits and `. _ : -`. For a server job it is the job's lowercase UUID. The note is optional printable text of 200 characters at most.
- **`complete_pending_run(run_id, *, external_job_id, outcome, result=None, error=None, warnings=None)`** is the only way a module completes a run. `outcome` is `succeeded`, `failed`, `cancelled` or `timed_out`.
  - Core verifies the caller from the call stack. It must be the enabled module that owns the run's action, called from that module's own code. Core, library, generated, disabled and legacy frames are refused. The function is a plain re-export from `tec_tac.scheduler`, with no wrapper frame, so the check sees the module's own frame.
  - Under a row lock the run must still be `running` with completion state `pending`, and the job id must equal the stored one.
  - The same completion twice is an idempotent no-op: no second audit row, `finished_at` unchanged.
  - A different second outcome (`conflict`), a completion after stale recovery (`late`), a wrong job id (`wrong_job`) and a completion by the wrong module are refused with `SchedulerCompletionRefused` (a `SchedulerError` with `.reason`). Each writes at most one best-effort audit row, `custom:scheduler-completion-refused`, with the reason code only. Rows are limited to one per run and reason per five minutes.
  - `succeeded` ends the run `succeeded` (warnings kept under `result["warnings"]`). `failed`, `cancelled` and `timed_out` end it `failed` with error type `ExternalFailed`, `ExternalCancelled` or `ExternalTimedOut`. A job created, or an acknowledgement, is never success.
  - `result` is JSON up to 16 KiB. `error` is printable text up to 500 characters. A bad payload raises `SchedulerError` and changes nothing.
  - Call it after the handler has returned. An earlier call finds no pending run and is refused as `not_pending`. The module retries shortly.
- **A run cannot wait for ever.** `recover_stale_runs` fails a waiting run that outlives its action's `timeout_seconds` (7 days at most) with error type `CompletionTimeout`, under its existing lock and re-check. It does not try to revoke a worker task, because the worker task has already returned.
- **`serialize_run` gains one key, `completion`:** `null`, or `{state, kind, since}`. `status` values do not change, so the concurrency skip, once-cleanup and `remove_owned_schedule` keep protecting a waiting run.
- **Migration 0034** adds four columns to `TecTacScheduleRun`: `completion_state`, `completion_ref`, `completion_started_at` and `system_action_marks` (used by section 3). All are blank by default. It is hand-written because Django is not installed on the development PC. A test compares it with the model.
- **A diagnostic action,** `tec-tac.scheduler-test-pending` (managers only, harmless, timeout 120 seconds). It parks a run that no module can complete. It stays Running, then fails with `CompletionTimeout` about seven minutes after it starts (120 seconds, plus the five minute recovery grace, plus up to one tick).

### 2. A run that waits for a server job (R-22, the Core-owned half)

A handler that starts a `core.server_maintenance` job with `source_module` and `source_run_id` in the operation context returns `pending_completion("server_maintenance_job", job_id)`.

- When the handler returns, Core reads the job file. It fails the run with `PendingRefused` unless the job exists and its context names this module and this run.
- The scheduler tick has one new guarded step, `settle_server_job_runs()`. It has its own try/except, looks at 50 runs a tick at most, runs no module code and never raises. When the job is terminal it settles the run once: `succeeded` ends it `succeeded`; `failed` and `dispatch_failed` end it `failed` (`ExternalFailed`); `cancelled` ends it `failed` (`ExternalCancelled`). A job record that stays missing for more than 10 minutes fails the run. A queued or running job leaves it waiting. An unreadable job leaves it waiting for the next tick.
- The result carries the job id, status, exit code and failure classification only. Never output text and never parameters (rule A8).
- The tick's own output line is unchanged. A test pins it.
- **Honest limit.** The job context is caller-asserted. The binding stops mistakes and an honest module, not hostile signed code. This is the same limit as `docs/caller-identity.md`.

### 3. System actions: `core.system_actions` 1.0.0 (R-20, AD-13)

A system action lets Core run a fixed piece of Tactical work for a named owner when nobody is signed in. The full description is in `docs/system-actions.md`. Core calling Tactical's own task functions is the AD-13 clause (rules 1.7, standard section 1a). It reaches only what Core's table lists.

- **The table is Core's.** `SYSTEM_FUNCTIONS` holds two rows, verified against Tactical v1.5.2 (`winupdate/tasks.py`, `agents/views.py`):
  - `winupdate.scan` runs `bulk_check_for_updates_task(pks)`. Owner: Windows Patching, or the premium module that honourably replaces it.
  - `winupdate.install` runs `bulk_install_updates_task(pks)`. Owner: Windows Patching only. Tactical's install task calls `approve_updates()` first, which re-approves an update that Advanced Patch Management set to Ignore. So the table refuses it for a replacement while R-36 is open (CQ173), and allows it for Windows Patching, where it equals Tactical's own behaviour.
  - Both need `can_manage_winupdates` AND `can_run_bulk`. That is stricter than either Tactical route alone.
  - Nothing else is reachable: no scripts or commands, no reboot, no uninstall, no model write, no route call, no loopback HTTP, no API key. A new row is a Core release.
- **Registering.** `register_system_action(id, module_id, label, function, permissions, scope_kind="agents", dangerous=False, username_param=None)` from `AppConfig.ready()`. It touches memory only. `function` is a table key, never a dotted path. Only the table's owner, or the honoured premium replacement, may register. The id must be listed in the module's signed manifest under the new optional key `system_actions` (at most 20 ids, extensions only). The permissions must include both minimum flags. Identical re-registration is idempotent. A replacement that is not honoured is logged and nothing is registered (no exception).
- **Running.** `run_system_action(context, *, action_id, agent_ids, parameters=None)` from the module's own Scheduler handler. At every run Core checks, in order: a Core-issued context with a person behind it, the verified caller, the registered action, the module enabled now, a replacement still honoured now, the owner re-read from the database (active, not an installer user), every Tactical flag held now, a count of 1 to 2000 (refused above, never truncated), every endpoint inside the owner's Tactical role scope (one outside refuses the whole call; a scheduler manager gets no bypass), and the Tactical function importable. Each refusal ends the run `skipped` (error type `SystemActionRefused`), writes one `deny` audit row and is never retried.
- **At most once, audited, then sent.** Core commits a mark on the run, writes one strict audit row (action `run`, actor the owner, `requested_by` scheduler, no endpoint ids or hostnames), and only then calls Tactical's task with `.delay()`, as Tactical's bulk view does. If the audit row cannot be written, nothing is sent. A retry that finds a `sent` mark sends nothing again. A mark stuck at `claiming`, or a send that raised, fails the run as `OutcomeUnknown` and is never sent again. A scan may be missed. An install is never done twice.
- **The result is honest.** `{"outcome": "queued", "agents": N, "message": "Queued in Tactical; the result shows in each endpoint's update list."}`. Never "done".
- **The five AD-13 conditions** and how each is met are in `docs/system-actions.md`. Tactical's own tasks for these two rows take no username, so only Core's audit row names the owner. The docs say so.
- The capability `core.system_actions` 1.0.0 (`list_actions`, `get_action`, `run`) is registered at start-up, guarded like the others. There is no HTTP route and no global off switch (CQ178). Disable the owning module or its schedule to stop a run.

## Module-facing

Everything is additive. Needs `requires.framework >=1.17.61` for any module that uses it.

- **Scheduler.** New: `PendingCompletion`, `pending_completion`, `complete_pending_run`, `SchedulerCompletionRefused`, the `completion` key of `serialize_run`, the diagnostic action, the new run error types (`CompletionTimeout`, `ExternalFailed`, `ExternalCancelled`, `ExternalTimedOut`, `PendingRefused`, `SystemActionRefused`, `OutcomeUnknown`). Unchanged: `register_scheduled_action`, `reconcile_schedule`, `start_one_off_run`, `get_one_off_run`, `get_owned_schedule`, `verify_run_context`, the run `status` values and the handler context keys.
- **System actions.** New: `tec_tac.system_actions` (`register_system_action`, `run_system_action`, `SystemActionRefused`, `SystemActionRegistrationError`) and the capability `core.system_actions` 1.0.0.
- **Manifest.** New optional key `system_actions`. A Core older than 1.17.61 refuses a manifest with an unknown key, so a module that declares it must require 1.17.61. The root job helpers keep no allow-list of manifest keys (a test pins it), so they ignore it.
- **Server maintenance.** `start()`, `cancel()` and the job file are unchanged. A module that wants a run to wait for its job puts `source_module` and `source_run_id` in the operation context.
- **Contract catalog.** Eight new rows (`PendingCompletion`, `pending_completion`, `complete_pending_run`, `SchedulerCompletionRefused`, `serialize_run`, `register_system_action`, `run_system_action`, `SystemActionRefused`) and one rule for the manifest key. The public export file is generated on the dev server, so `docs/contracts` is not edited here.

### What I checked in `modules/`

A search of `modules/` (1,485 files read) found:

- 24 modules register Scheduler actions (`alerts`, `backups`, `certificatemanagement`, `checks`, `communicator`, `cybercns`, `cyberhoot`, `governance-compliance`, `halopsa`, `huntress`, `licensing`, `maintenance`, `networkprobe`, `notifications`, `patching`, `patchmanagement`, `reportmanager`, `scoutdns`, `scriptexecution`, `sentinelone`, `softwarerepository`, `tacticalupdater`, `userinvite`, `wau`). Sixteen use `reconcile_schedule`. `backups`, `checks`, `patching` and `patchmanagement` use `start_one_off_run`. `backups` and `patchmanagement` read `get_one_off_run`.
- No module uses `system_actions`, `run_system_action`, `register_system_action`, `PendingCompletion`, `pending_completion` or `complete_pending_run`. No module reads a `completion`, `completion_state`, `completion_ref`, `system_action_marks` or `scheduler_state` key.
- So no module has to change. `tests/system-actions-compat-1.17.61.py` pins this: the signatures modules call, the `ScheduledAction` fields, the run statuses, the worker's old success and failure path, and the module search.

## What was left out, and what ends each wait

- **The module-callback hook** (R-22 part 2: Core runs a module's handler when any server job finishes, certificatemanagement's closed-tab case) and **R-23** (hand-registered server-maintenance actions lose their executable on uninstall): 1.17.62. The hook runs module code from Core and needs a durable "handled" record and a Celery task with limits, retries and expiry. R-23 is root code and cannot run on the development PC. Both stay open in `reviews/requests/core.md`.
- **Scheduled install for Advanced Patch Management.** Refused by the table while R-36 is open (CQ173). Ends when Johan decides R-36.
- **Pushing rule decisions to Tactical on a schedule.** Tactical has no task function for it (CQ174). Not built.
- **R-36** (disabling Tactical's native patching paths while a replacement is honoured): a design question, left out as instructed.
- **Reboot, uninstall, scripts and commands.** Wait for the owning module's request and Johan's sign-off (CQ175).
- **Module-owned recurring schedules with a named acting person** (`acting_user`): not built (CQ176). Today a system action needs a user-owned schedule or a one-off run.
- **Polling a module's capability for a final state** from the tick: not built (CQ177).
- **Licensing decision entry, licensed catalogue (R-31), licence-key download, secret store (R-30), R-12, R-13, R-24 to R-27:** not the same code, not in this release.
- **The contract export file** in `docs/contracts`: generated on a running server after you install the signed build.

## Where the plan changed once I was in the code

- `run_system_action` and `register_system_action` are imported from `tec_tac.system_actions`, not re-exported from `tec_tac.scheduler`. `system_actions` imports the Scheduler, so a re-export would be a circular import. `complete_pending_run` is a plain alias in `tec_tac.scheduler`, as planned.
- The plan asked for a new helper `agent_pks_in_role_scope_for_ids`. Core already has `agent_pks_in_role_scope(user=, pks=)`, which does exactly this (`filter_by_role`, every number must exist and be in scope, a missing agent reads as outside). I reuse it. One helper, one meaning.
- The count and the shape of `agent_ids` are judged before the scope lookup, so a list of 5000 numbers never reaches the database. The refusal reasons are the same.
- `caller_unverified` and `wrong_module` write the deny row and raise, but do not end the run `skipped`. A context handed to code that does not own the run must not be able to end another module's run. The run's own handler fails with the refusal. Every other refusal ends the run `skipped`, as planned (CQ178 lists this).
- A refusal row names the owner as the actor from the moment the schedule's person is known. When there is no person (`no_owner`, `context_invalid`), a Core service actor is the actor.
- A completion writes one best-effort audit row (`custom:scheduler-completion`), so that "no second audit row" for a duplicate has a first row to refer to. The row carries the outcome and the calling module, never the result.
- `scheduler_completion` imports the caller helper inside `complete_pending_run`, so a module or test that loads the Scheduler without the caller helper still works.
- Five older tests pinned "0033 is the newest migration". They now say 0034, as earlier releases did.
- The plan's first step, writing the plan to `reviews/core/CORE-RELEASE-B-PLAN-20-10-2026.md`, was not done. That folder is the release manager's.

## Questions for Johan (assumption used; no wait)

CQ172 to CQ178 are in `reviews/questions/core.md`: the release shape, scheduled install for Advanced Patch Management (flagged for human review), pushing rule decisions, which Tactical functions the table may reach, module-owned schedules with an acting person, how a pending run is completed, and the limits on a system action run. A note asks you to confirm CQ50, which system actions rely on. A second note asks the release manager to add AD-13 to checklist line A2 (it is not Core's file).

## Requests written for other areas

- `reviews/requests/premium-modules.md`: patchmanagement (switch the scan on; keep install, rule push and reboot off) and maintenance (a person as owner; show the reason).
- `reviews/requests/core-modules.md`: patching (declare and register `patching.scan` and `patching.install`).
- `reviews/requests/ui.md`: Core UI Scheduler page ("Waiting for the result", plain error texts). Core works without a UI release.
- `reviews/requests/core.md`: the shipped line for 1.17.61, the AD-13 entry rewritten to what is still open, the async-completion entry removed, the R-22 hook and R-23 entries kept for 1.17.62.

## What could not run on this PC

Django, Celery, Postgres and Tactical are not installed here. Not run: the model, migration 0034 on a real database, the tick command, the Celery task, the JSON key lookup the tick step uses, real Tactical imports and the real audit store. The tests use the stub harness `tests/scheduler-completion-harness-1.17.61.py` (the real Scheduler, caller identity, completion, system-action and worker code against in-memory models) and a pinned excerpt of Tactical v1.5.2 (checked against `reference/tacticalrmm` where it is present). Two dev-server scripts cover the rest: `tests/scheduler-completion-runtime-1.17.61.py` and `tests/system-actions-runtime-1.17.61.py`. Neither has been run.

The AI review has held a Medium on most recent builds. Plan for 1.17.61-1.

## Dev-server checklist (PASS or FAIL for each step)

Do this after the signed build is installed. Do not test while an install is running. Core and the Celery workers must be restarted after the update, the way you did after 1.17.60.

**Step 0. Update and migrate.**
1. Update Core from the dev branch and restart as for 1.17.60.
2. Run: `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac`
3. Expect: `Applying tec_tac.0034_scheduler_run_completion... OK`.
4. Run: `../env/bin/python manage.py makemigrations --check --dry-run`
5. Expect: `No changes detected`.
- **FAIL** if the migration errors, or if `makemigrations` wants to write a file. Send back the full output of both commands.

**Step 1. The completion probe (the real table, locks and JSON lookup).**
1. Run: `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/scheduler-completion-runtime-1.17.61.py`
2. Expect five `PASS` lines and `5 of 5 steps passed`.
- **FAIL** if any line says `FAIL`. Send back the whole output. The last step needs to write one temporary file under the server-maintenance jobs folder; if it says it cannot, send the message and say whether the folder exists.

**Step 2. The test action stays Running, then times out.**
1. In the Scheduler page, create a schedule for the action "Scheduler pending-completion test" (managers only), then press Run now.
2. Expect the run to show Running and stay Running. (The page shows a waiting label only after the UI release.)
3. Wait about eight minutes.
4. Expect the run to show Failed with the text "No result arrived within the action timeout of 120 seconds."
- **FAIL** if the run shows Succeeded, shows Failed at once, or is still Running after ten minutes. Send back the run's row from `GET /api/tfd/scheduler/runs/` and the output of `../env/bin/python manage.py tec_tac_scheduler_tick`.

**Step 3. A shell cannot complete a run.**
1. Run the Step 2 action again. While it is Running, open `../env/bin/python manage.py shell` and run:
   `from tec_tac.scheduler import complete_pending_run`
   `complete_pending_run("<the run id>", external_job_id="x", outcome="succeeded")`
2. Expect an error: `SchedulerCompletionRefused`. The message says Core could not tell which module is calling.
3. Expect the run to be still Running.
4. In Tactical's Audit Manager, expect one row with action `custom:scheduler-completion-refused`. It names a reason (`caller_unverified`) and holds no result text.
- **FAIL** if the call returns without an error, the run changes, or no audit row appears. Send back the error text and the run row.

**Step 4. A server job settles a waiting run.** Step 1's last step does this with a synthetic job file. No installed module returns a server-job completion yet, so there is no real job to wait for until certificatemanagement adopts it.
- **FAIL** if Step 1 failed on that step. Send back its line.

**Step 5. A scheduled scan is queued, as the user.**
1. Pick one test endpoint on dev02 and a Tactical user whose role holds `can_manage_winupdates` and `can_run_bulk` and covers it.
2. Run: `cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=<username> TECTAC_PROBE_AGENT=<agent number> ../env/bin/python manage.py shell < /path/to/tests/system-actions-runtime-1.17.61.py`
3. Expect: `run status: succeeded`, a result that says `queued` and `agents` 1, one mark in state `sent`, an audit row `run` for that username, and `PASS expected queued`.
4. In Tactical, the endpoint's Windows update list refreshes after the scan (a minute or two).
5. In Audit Manager, expect one row: action `run`, object type `system_action`, username the user, no hostname and no endpoint number in the text.
- **FAIL** if the status is not `succeeded`, no scan appears, or the audit row names no user. Send back the whole script output and the audit row.

**Step 6. A lost flag stops the next run.**
1. Run Step 5 again with `TECTAC_PROBE_PHASE=prepare` added. Note the run id it prints.
2. In Tactical, remove `can_run_bulk` from that user's role.
3. Run: `cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=<username> TECTAC_PROBE_AGENT=<agent number> TECTAC_PROBE_PHASE=execute TECTAC_PROBE_RUN=<run id> TECTAC_PROBE_EXPECT=refused ../env/bin/python manage.py shell < /path/to/tests/system-actions-runtime-1.17.61.py`
4. Expect: `run status: skipped`, error type `SystemActionRefused`, no mark, a `deny` audit row for that username, and `PASS expected refused`. No new scan appears on the endpoint.
5. Put the flag back.
- **FAIL** if a scan is queued, or the run is not skipped. Send back the script output and the audit row.

**Step 7. Existing schedules keep running.**
1. Press Run now on an existing schedule, or on the built-in "Scheduler test event".
2. Expect Succeeded, as before.
3. Run: `../env/bin/python manage.py tec_tac_scheduler_tick`
4. Expect one line that starts `TEC-TAC scheduler tick: checked=` with the same fields as before, and no error lines.
- **FAIL** if a run that used to succeed fails, or the tick prints an error or a changed line. Send back the line and the run row.
