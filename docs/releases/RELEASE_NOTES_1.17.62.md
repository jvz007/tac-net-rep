# Tec-Tac Framework 1.17.62

A module can now be told when its server job finishes, even if nobody has the page open. Core also stops a removed module's hand-registered server action from running again by accident, and two held review points from 1.17.61 are closed.

Date: 20 October 2026. Every earlier route, field and contract stays. Everything here is additive for modules, with one visible change for administrators (section 2).

## What changed and why

1.17.61 let a Scheduler run wait for a server-maintenance job. It left two things for this release (CQ172): the module callback for any finished job (R-22 part 2) and the root-helper fix for hand registrations after an uninstall (R-23). The same review held two Lows. This release builds all four.

It closes these requests: "A completion path for a finished server job" (certificatemanagement 0.3.0), "Hand registrations survive uninstall, but their executable is deleted" (held Medium of the 1.17.18 review), and the two Lows held from the 1.17.61 review. The modules adopt the hook in their own releases (see Requests written).

### 1. Core tells the module when its server job finishes (R-22 part 2)

Before, a certificate renewal or a scan recorded its outcome only while a browser page polled the job. A person who started one and closed the tab lost the record. Now the scheduler tick does the waiting.

- **How a module opts in.** From `AppConfig.ready()` it registers one event job with `core.event_jobs`: `<module id>.server_job_finished` (`tec_tac.server_job_hooks.hook_job_id(module_id)`). That is all. Core ties a job to a module through the `owner_module` Core already writes in the job file from the action manifest (since 1.17.17). There is no new manifest key.
- **What Core does.** A new guarded tick step, `deliver_finished_server_jobs()`, runs after the settle step from 1.17.61. It has its own try/except, never raises and runs no module code. It lists the job folder, asks the database which jobs it already handled, and reads at most 50 job files a tick, oldest first. It reads only files changed in the last six hours. For each finished job whose owner registered the hook, it stores one event job through Core's own publish path (`event_jobs.publish_for_core`). That path checks everything a normal publish checks except the caller frame: the event job is registered by that module, the module is runnable right now (read fresh), the key and payload are valid, and the rate and backlog caps apply. Only `server_job_hooks.py` may call it.
- **At most once per Core.** A new table, `TecTacServerJobHook` (migration 0035, unique on the job id), holds a row for each job Core handled. The row is written before the event is stored, so two ticks or two processes cannot hand over the same job twice. A store that fails (rate cap, full backlog, error) waits in `retry` and is tried again on the next ticks, three tries in all, then it is `abandoned` with one audit row. A claim a tick left half-done for 15 minutes is abandoned and never sent again: at most once wins over exactly once.
- **What the handler receives.** `context["payload"]` is `{job_id, action_id, status, exit_code, classification?}`. `status` is `succeeded`, `failed`, `cancelled` or `dispatch_failed`. `classification` is a short code and appears only when the job file holds one. Never output text and never parameters (rule A8). A test puts a marker in a job's parameters and output and checks it never reaches the event or the audit trail.
- **The handler runs as the module, with no user.** It cannot make a Tactical change (AD-13 is unchanged). The event job's own attempts, back-off and expiry apply after that.
- **The handler must be idempotent.** The event job can retry, and a browser poll of `JobView` can record the same job. Key your record on the job id. The docs say so in three places.
- **A disabled, removed or not-honoured module** gets its job marked `skipped` with one audit row (`custom:server-job-hook-skipped`). It is not retried for ever, and enabling the module later does not replay it. A module state Core cannot read leaves the job for the next tick with no row.
- **A module with no hook** is left alone: its jobs are marked `ignored` once. A job with no owner (written before 1.17.17) is ignored too.
- **The tick's own output line is unchanged,** byte for byte. A test pins it, as in 1.17.61.
- **Start, get_job, cancel, list_jobs and the job file are unchanged.** A test pins every signature.
- **Honest limits.** The owner in the job file is caller-asserted (the same limit as `docs/caller-identity.md`). A job that finished while Core was off for more than six hours is not handed over. Event job ids are lowercase only, so `securityWAF` (capital letters in its module id) cannot register one yet (CQ183).

Docs: `docs/scheduler.md` ("Server job finished hook"), `docs/server-maintenance-capability.md` ("Being told when a job finishes") and `docs/event-jobs.md` ("Events Core itself publishes").

### 2. A removed module's hand registration no longer runs by accident (R-23)

An administrator can register a server action by hand, and Tactical Updater's two protected actions work that way. A hand registration carries no hash. When its module was uninstalled, Core deleted the module's own files but left the registration listed and runnable. A later package under the same module id could put a file at that path, and the registration would run it, without the administrator opting in again.

- **What happens now.** `--unregister-module` keeps the registration file (it is the administrator's record) and marks it `enabled: false` with `disabled_reason: module removed`, plus the module and a time. It applies to a hand registration whose `owner_module` is the module, or whose executable lies below the module's own action folder. Nothing else about the file changes. Manifest-registered actions are removed as before. The install path and every normal action are unchanged.
- **What an administrator sees.** Starting it fails with the action_disabled classification and the sentence "its module was removed. An administrator has to register it again." The action list shows `enabled: false` and `disabled_reason: "module removed"`. Dispatch and run in the root helper refuse it with the same reason. It is runnable again only when the administrator registers it again knowingly: `--register <manifest.json>`, or for Tactical Updater `sudo bash register-protected-actions.sh`.
- **Why it is safe.** The disabled check runs before the helper looks at the executable, so it works even though the file is gone. The SHA-256 recheck at dispatch and run stays. The helper deletes nothing here, never follows a symlinked registry file, leaves an administrator's own disabled registration as it is, and flags each file once.
- **A side effect you should know.** The module job helpers also run `--unregister-module` when an install or upgrade of a module declares no server actions. A hand registration owned by such a module is disabled then too. Registering it again is the same step. This is recorded as CQ180.
- **No allow-list of manifest keys was added** (a test pins it). `scripts/module-v2-job-helper.py` and `module-job-helper.py` are unchanged.

### 3. A module cannot complete a run that waits for a server job (held Low)

`_apply_outcome` now takes the pending kind the caller may settle. `complete_pending_run` passes `module`. The tick passes `server_maintenance_job`. A module that calls `complete_pending_run` for a run waiting on a server job gets a new refusal reason, `wrong_kind`; the run stays running and pending. One reason-code audit row is written, under the existing rate limit. A module-kind run behaves exactly as in 1.17.61. The reason is in the contract catalog and `docs/scheduler.md`.

### 4. A system-action run never widens the schedule's set (held Low)

`run_system_action` now resolves the run's snapshotted targets to endpoint numbers and refuses any endpoint outside them (`outside_targets`: one deny row, no send, the run ends skipped). It runs after the count and shape checks and after the owner's scope check, which are unchanged. A target that no longer exists is counted in the refusal text and never dropped silently. Core reads client, site and endpoint targets, and the Tactical scope of a dynamic target (an upper bound; the module's own filter only narrows it). `none` and an empty snapshot refuse as `outside_targets`. A module-owned target type cannot be read, so it refuses as `targets_unresolved` and nothing is guessed. The missing contract (a way for the owning module to publish how its type resolves to endpoints) is a request to Core in `reviews/requests/core.md`. This holds under the signed run-time re-check and under a Tactical-style model alike.

## Module-facing

Needs `requires.framework >=1.17.62` for a module that adopts the hook.

- **New.** `tec_tac.server_job_hooks` (`hook_job_id`; `deliver_finished_server_jobs` is Core's own step), the event job `<module id>.server_job_finished`, the audit actions `custom:server-job-hook-skipped` and `custom:server-job-hook-abandoned`, the refusal reasons `wrong_kind`, `outside_targets` and `targets_unresolved`, and the `list_actions()` key `disabled_reason` (additive: null, or `module removed`).
- **Root helper.** Behaviour change for a hand registration that survives an uninstall (section 2). It affects the three modules that register server-maintenance actions: `tacticalupdater`, `certificatemanagement` and `securityWAF`. None needs a code change. `tacticalupdater`'s Help should say the protected actions need registering again after an uninstall.
- **Capabilities.** Unchanged: `core.server_maintenance` stays 1.1.0, `core.event_jobs` 1.1.0, `core.system_actions` 1.0.0 (its refusal reasons list grows).
- **Contract catalog.** Two new rows (`hook_job_id`, `deliver_finished_server_jobs`), and the rows for `SchedulerCompletionRefused`, `run_system_action` and `SystemActionRefused` name the new reasons.

### What I checked in `modules/`

`tests/server-job-hook-compat-1.17.62.py` reads every module as source. Four modules mention server maintenance (certificatemanagement, globalsettings, securityWAF, tacticalupdater). Every call they make to the provider uses keywords that still exist. No module defines `<id>.server_job_finished`, calls the new internal names, reads `disabled_reason`, or uses system actions. So no module has to change for this release to work. Adopting the hook is each module's own release.

## What changed in existing tests, and why

- Seven tests that pinned "the newest migration is 0034" now say 0035: `event-jobs-refusal-audit-1.17.48`, `event-jobs-refusal-bound-1.17.49`, `migration-model-id-agreement-1.17.36` (it also pins "no 0036"), `runtime-settings-upload-1.17.14`, `session-theme-1.17.24`, `update-source-1.17.2` and `scheduler-migration-0034-1.17.61`. That is two more than the five the plan listed; I found them by running the tests.
- `scheduler-server-job-await-1.17.61.py`: two direct calls of the private `_apply_outcome` now pass `allowed_kind="server_maintenance_job"`. I made the argument required on purpose (a default would let a future caller forget it). The test's assertions are unchanged. The plan asked for it to pass unchanged; it passes with those two call lines changed.
- `scheduler-completion-harness-1.17.61.py`: additive only. A stub for the new target resolver, an `AUTO_TARGETS` hook and a `targets=` argument on `make_run`. Nothing existing changed.
- `system-actions-run-1.17.61.py` and `system-actions-audit-1.17.61.py`: one line each sets `AUTO_TARGETS` so each run snapshots exactly the endpoints its handler sends (a run now has to target what it sends). In the run test, one assertion that checks no endpoint id appears in the run's record now skips the `targets_snapshot` field, which legitimately holds them. No other assertion changed.
- `contract-catalog-1.17.61.py` and `module-job-contract-rows-1.17.60.py`: they pinned "VERSION is 1.17.61" and "1.17.60 or 1.17.61", and the first read the 1.17.61 notes at the root. They now accept 1.17.62 and find the notes in `docs/releases/`.
- `system-actions-runtime-1.17.61.py` (a dev-server probe): its one-off run now carries an endpoint target, because a system action must target what it sends. Without that change the probe would be refused as `outside_targets`.
- `server-maintenance-hand-registered-1.17.18.py`: its four assertions that a hand registration "survives unchanged" now say "survives, disabled and flagged", because that is R-23. The deletion rule is unchanged: nothing a hand registration points at is deleted.

## What was left out, and what ends each wait

- **The AD-13 condition 2 amendment** (check only when a schedule is created, edited or started by a person, never at scheduled runs) and everything built on it. The run was told this was your signed decision. The only message from you here is the question "how does Tactical do their scheduling", which asks and does not decide, and no signed line for it exists. This weakens a control on unattended work on endpoints, so it is flagged for human review (CQ179). I answered your question in `reviews/questions/core.md`. Nothing is weakened. Ends when you type your choice in chat.
- **Widening the table to reboot, uninstall, scripts, commands, checks, tasks and reports.** Your CQ175 answer is (a): a row only when the owning module asks and you sign that row off. No sign-off is on file. Ends when you sign off each row, and the owning module asks.
- **Scheduled install for Advanced Patch Management (CQ173)** and **groups above 2000 endpoints (CQ178):** no answer on file. Both stay as built.
- **Module-owned recurring schedules (CQ176):** your answer is recorded. Not built here, because it depends on the rights-model answer (CQ179) and is too large to add to this review. It is the first item after you answer CQ179.
- **Pushing rule decisions on a schedule (CQ174):** you asked for a recommendation. It is in the question file. Not built.
- **Module requests for scheduled install, KB uninstall, reboot and rule push:** not written, because each depends on CQ179 or a table row that is not signed off. A request naming the wrong rule would mislead those areas.
- **R-36, licensing entry, licensed catalogue, secret store, R-12, R-13, R-24 to R-27:** different code, not in this release.
- **Authority documents.** I did not edit the standard, the AD index, the rules or the review checklist. Line A2 of the checklist should name AD-13 beside the other Tactical exceptions (already noted in the 1.17.61 note; not Core's file).

## Where the plan changed once I was in the code

- **securityWAF is a server module, not premium,** in `modules/catalog.toml`. Its request is in `reviews/requests/core-modules.md`. Its module id has capital letters, so event job registration is refused until the owner decides (CQ183).
- **The Tactical task row does keep a `created_by` name** (it is an audit field), which I first described as "no creator". Nothing reads it at run time, so your suspicion about Tactical stands. The correction is in CQ179.
- **`none` and an empty snapshot refuse as `outside_targets`,** not as `targets_unresolved`. They name no endpoint, so the subset test fails; only a module-owned type is unreadable.
- **A third state, `retry`,** exists in the hook table (the plan had three). A store that fails must be tried again without breaking at-most-once.
- **Event job ids are lowercase only** (policy), which the plan did not mention.
- **Earlier release notes move to `docs/releases/`** (`tests/release-integrity.sh` wants exactly one note at the root). `RELEASE_NOTES_1.17.61.md` moved there.

## Questions for Johan (assumption used; no wait)

CQ179 to CQ183 are in `reviews/questions/core.md`. CQ50 and CQ175 are marked answered (a). CQ176 has your words and the reason it is not built. CQ177 has a plain answer (Tactical never polls; its agent pushes the result with its own token, so we keep option (a)). CQ174 has a recommendation. CQ173 and CQ178 stay open with the assumption in force.

## Requests written for other areas

- `reviews/requests/core-modules.md` ("From Core 1.17.62"): certificatemanagement (adopt the hook), tacticalupdater (note the R-23 change in Help), securityWAF (the same, plus the lowercase-id limit).
- `reviews/requests/core.md`: the shipped line for 1.17.62, the two shipped entries removed, and a new request for a target resolver for module-owned target types.
- No request for `ui` (the Scheduler page's "Waiting for the result" request from 1.17.61 is still there).

## What could not run on this PC

Django, Celery, Postgres and Tactical are not installed here, and the root helper's real ownership checks need Linux and root. Not run: the model and migration 0035 on a real database, the tick command, the database claim (unique row, `retry` rows, the stale-claim and prune queries), the Celery worker side of the event job, real Tactical imports, and the root helper as root. The tests use the stub harness, source reads (ast) and temporary folders with a fake ownership layer. `tests/server-job-finished-runtime-1.17.62.py` and `tests/server-maintenance-uninstall-runtime-1.17.62.sh` cover those parts on the dev server.

Checks that ran: `bash tests/release-integrity.sh`, `python -m py_compile` on every changed file, `ruff check` (the repo has no Core ruff config, so the checks used the default rule set; the new files are clean and no changed file gained a finding that is not the file's own existing pattern), the new tests and every test I changed. The AI review has held a Medium on most recent builds. Plan for 1.17.62-1.

## Dev-server checklist (PASS or FAIL for each step)

Run on the dev server after the signed build is installed. Never run it during an install or a Core update.

1. **Core is 1.17.62.** Open the About or update page. Expected: 1.17.62. FAIL: anything else. Send back: a screenshot.
2. **Migrate.** `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac`. Expected: a line "Applying tec_tac.0035_server_job_hook... OK". FAIL: any error. Send back: the full output.
3. **Model and migration agree.** `../env/bin/python manage.py makemigrations --check --dry-run`. Expected: "No changes detected". FAIL: it lists a change for `TecTacServerJobHook`. Send back: the output.
4. **Restart.** Restart Core and the Celery workers the way you did for 1.17.61. Expected: both come back, the sign-in page loads. FAIL: either does not start. Send back: the last 50 lines of each service log.
5. **The hook table and the tick.** `../env/bin/python manage.py shell < /path/to/tests/server-job-finished-runtime-1.17.62.py`. Expected: PASS for steps 1 to 5, step 6 either PASS or SKIP, and the line "N passed, 0 failed". SKIP for step 6 is expected until certificatemanagement adopts the hook. FAIL: any FAIL line. Send back: the whole output.
6. **R-23 on the real helper.** As root: `sudo bash /path/to/tests/server-maintenance-uninstall-runtime-1.17.62.sh`. Expected: PASS lines for every step and "ALL PASS". FAIL: any FAIL line. Send back: the whole output, `ls -l /etc/tec-tac/server-maintenance/actions.d` and the last 30 lines of the helper's audit log.
7. **The tick log is quiet.** `journalctl -u <the Core service> --since "15 minutes ago" | grep -i "server job hook\|server_job_hooks"`. Expected: no line saying "failed". FAIL: a "The server job hook step failed" line. Send back: those lines.
8. **Existing server maintenance still works.** In Server Maintenance, start a harmless existing action and open its job. Expected: it runs and finishes as before. FAIL: it does not start or never finishes. Send back: the job id and the page's text.
9. **Tactical Updater's protected actions (only if you registered them).** Do not uninstall the module on the dev server for this. Expected: nothing changes for an installed module. FAIL: a protected action shows as disabled while its module is installed. Send back: the action list.
10. **Export the public contract** into `docs/contracts`. Expected: the new rows `hook_job_id` and `deliver_finished_server_jobs` are in it, and `core.server_maintenance` is still 1.1.0. FAIL: either is missing. Send back: the export file.
