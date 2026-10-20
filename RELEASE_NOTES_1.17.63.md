# Tec-Tac Framework 1.17.63

Scheduled system work now follows Tactical: Core checks who may schedule it when the schedule is made, not again at every run. Core also records who made each schedule, lets a person create a schedule that a module owns and runs, and fixes the two limits found in 1.17.62: module ids with capital letters, and unfinished job files crowding out finished ones.

Date: 20 October 2026. Every earlier route, field and contract stays. Everything here is additive and opt-in. No module has to change for this release to work, and no module changes behaviour until it adopts a new keyword.

## What changed and why

Johan answered two questions in chat on 20 October 2026: CQ179 ("yes follow tactical's implementation") and CQ183 ("now fix it pls"). This release builds those two answers. It also builds CQ176, which waited on CQ179, and the one Medium held from the 1.17.62 review.

It closes: the "yes" half of the 1.17.62 waits on CQ179 and CQ176; CQ183 (securityWAF cannot register the job-finished hook); and the held Medium of the 1.17.62 review ("unfinished job files can use the whole 50-per-tick batch").

### 1. Scheduled unattended runs follow Tactical (CQ179 b)

**How Tactical does it** (v1.5.2 source). A person needs `can_manage_autotasks` to create or edit a task, and `can_run_autotasks` to run one now (`autotasks/views.py`, `AutoTaskPerms` and `RunAutoTaskPerms`). When the task is made, Tactical sends it to the agent over NATS (`autotasks/models.py`, `create_task_on_agent`). The agent's own Windows scheduler runs it and reports back with its own token (`apiv3/views.py`, `TaskRunner.patch`). Tactical never checks the person again at run time.

**What Core does now.** A module registers a Scheduler action with a new keyword, `unattended=True`. A scheduled run of that action is no longer re-checked against its creator.

- **Opt-in, per action.** `register_scheduled_action(..., unattended=False)` is the new last keyword. `ScheduledAction` gains the last field `unattended`. Core accepts `True` only for a module whose signed manifest lists at least one `system_actions` id. Anything else raises `SchedulerError`. An existing action is equal to what it was.
- **One place decides.** `scheduler._is_unattended_scheduled_run` answers yes only when the action is flagged, the run was started by the schedule (never `manual`, never a one-off), and a creator name is stored. The tick, `verify_run_context` and the system-action code reach the exemption only through it. A test reads the source to prove it.
- **What a scheduled unattended run skips.** In the tick, a demoted, deactivated or deleted creator no longer causes `AuthorizationRevoked`. In `run_system_action`, exactly three refusals are skipped: `owner_inactive`, `permission_lost` and `out_of_scope`. The person's right was checked when they made the schedule.
- **What stays, for every run.** The signed context and the caller check, the module enabled and honoured right now, the action still listed in the signed manifest, the parameters, the endpoint numbers, the 2000 cap (refused above, never truncated), `outside_targets` (a run never widens the saved targets), `targets_unresolved`, `reapproves_by_policy`, the at-most-once mark and the strict audit row before the send. `has_tactical_permission` and `resource_context` stay fresh reads.
- **What a person-started run keeps.** A manual run and a one-off run keep every re-check, exactly as before (CQ50 a). An action that is not flagged `unattended` is re-checked at every scheduled run, as before.
- **A new refusal, `action_not_declared`.** Core now checks at every run that the action id is still listed in the module's signed manifest. Before, it checked only at registration.
- **Who is on the record.** Migration 0036 adds `created_by_username` and `confirmed_by_username` to the schedule. Creating a schedule stores the signed-in person as both. An edit sets the editor as the confirmer, after the permission and scope checks that were already there. A row made before 0036 reads its creator from `created_by`; there is no data migration. Every `run`, `deny` and `custom:outcome-unknown` audit row of a system action now carries `run_kind` (`scheduled` or `person`), `creator` and `confirmed_by`. The actor is the creator's user row when it still exists, otherwise a Core service actor with the stored name in the metadata.
- **Vanished targets.** When some saved targets no longer exist but every endpoint you name is still a target, the run goes ahead. The result gains `vanished_targets` (a count) and the run's audit row carries it. A refusal keeps its wording.

**The cost, in plain words.** A person who is demoted or deactivated later keeps their unattended schedules running until someone removes or edits them. That is how Tactical works too. An administrator can find those schedules by creator (section 2) and remove or disable them.

**Why I read "yes" narrowly.** Option (b) in CQ179 said "check at creation, edit and person-started run only". Applying that to every scheduled action would change Script Execution, Script Manager, Global Settings and every module that schedules, all at once. No module uses system actions yet, so the narrow reading changes nothing that exists. If Johan wants it wide, it is a change in one helper plus a review of every scheduling module. This is CQ184 in `reviews/questions/core.md` (assumption: narrow; flagged for human review).

**Decision wording for the authority documents** (they are not Core's files; the coordinator pastes them). AD-13 condition 2 reads, with this answer: "Permission and scope are checked where Tactical checks them: when a person creates or edits the schedule, and again for a run a person starts (a manual run or a one-off run). A scheduled run of an action the module flagged unattended is not re-checked against its creator, as in Tactical. Core stores and audits who created and who confirmed the schedule. Still checked at every run: the caller, the module enabled and honoured, the action declared in the signed manifest, the snapshotted targets, the 2000 cap, at-most-once and the audit row." The places: `docs/tec-tac-module-standard.md` section 1a, `docs/review-accepted-decisions.md` row 13, `docs/tec-tac-development-rules.md` rule 1.7, and `docs/review-checklist.md` A2 (which should name AD-13).

Docs: `docs/system-actions.md` ("Unattended scheduled runs"), `docs/scheduler.md`, `docs/module-scheduling.md`.

### 2. An administrator can list schedules by creator (CQ179 b)

`GET /api/tfd/scheduler/schedules/` accepts `created_by=<user name>` and `confirmed_by=<user name>`. The match is exact and not case-sensitive, on the stored name (a row from before 0036 matches its creator row's user name). An unknown name returns an empty list. It adds no right: the filter only removes rows, and it runs before the permission and scope test that was already there, which is unchanged. A test proves that no permission code or role helper was added. Each schedule gains the additive keys `created_by_username` and `confirmed_by_username`. The Scheduler page change is a request for `ui`.

### 3. A schedule a person creates and a module owns (CQ176)

`reconcile_schedule` takes one more keyword-only, optional argument: `confirmed_by_request=None`.

- **With a request.** It must be a real Django or DRF request that passed Core's session check, the same proof `run_tactical_operation` asks for. A user id, a stand-in object with a `user`, or a request without the session proof raises `SchedulerNotAllowed`. Core then checks, for that person, the action's permission and the Tactical scope of the targets (the same checks `start_one_off_run` makes), stores the creator the first time and the confirmer every time, and writes one audit row for the creation (`add`) and one for every change (`modify`), naming the person. If the audit row cannot be written, nothing changes. The module stays the owner and the executor.
- **Without a request.** A schedule that has a stored creator can only be switched off or left unchanged. A change to its action, targets, parameters, timing or policies, or switching it back on, raises `SchedulerError` and leaves the row as it was. An identical call is a no-op that writes nothing. So a module can never widen or rewire a person's schedule.
- **No creator, no keyword.** A module-owned schedule with no stored creator behaves exactly as in 1.17.62. A system action on it is still refused as `no_owner`.
- `get_owned_schedule` gains the additive key `created_by_username`. `start_one_off_run`, `disable_owned_schedule` and `remove_owned_schedule` are unchanged.

### 4. A module id with capital letters can use event jobs and the hook (CQ183)

Module ids are case-sensitive and case-preserving (`docs/module-identifiers.md`), so Core does not rewrite them. The module part of an event job id, and the owner in a job file, now keep the module id's own spelling. The job part after the dot stays lowercase.

- `securityWAF.server_job_finished` registers for module `securityWAF`. `securitywaf.x`, `SecurityWAF.x` and `securityWAF.X` do not.
- A job file whose owner is spelled differently from a registered module is ignored. Core never folds one module's job onto another.
- Every id that registered before still registers with the same parts. A test compares the old and new patterns over 19 608 small strings. The only new matches have a capital letter in the module part.
- **A small fix found while testing.** The id pattern ended with `$`, which also accepts one trailing newline. It now uses a full match. No real id is affected.
- Docs: the "lowercase only" limit sentences are gone from `docs/scheduler.md`, `docs/event-jobs.md` and `docs/server-maintenance-capability.md`. They state the rule.

### 5. Unfinished job files no longer crowd out finished ones (held Medium)

In 1.17.62 the tick read the 50 oldest job files that had no hook row. A file that is not finished never gets a row, so 50 stuck files were read again every minute and a finished job behind them was never reached.

- `BATCH` (50) now caps only the finished jobs handed over in one tick. A new `READ_BUDGET` (200) caps the files read in one tick.
- A file read as not finished (or briefly not there) is remembered in memory with its modification time. It is skipped with no read until the file changes, because a status change rewrites the file. The memory is per process and holds only files inside the six-hour window. A file that cannot be read is not remembered: it is tried every tick, so a passing fault never hides a job.
- Settled ids still come from the database. The tick's output line and the counts keys are byte for byte as in 1.17.62. The claim is still written before the event is stored, so a job is still handed over at most once.
- The bound, stated plainly: with 250 stuck files in front of a finished job, the first tick reads 200 and the second reaches it. With 60 or 120, it is reached in the first tick.

## Module-facing

Needs `requires.framework >=1.17.63` for a module that adopts anything below. Nothing is required.

- **New, all optional.** `register_scheduled_action(..., unattended=False)`; `ScheduledAction.unattended`; `reconcile_schedule(..., confirmed_by_request=None)`; `VerifiedSchedulerRun.creator_username`, `confirmed_by_username` and `unattended` (last, with defaults); `get_owned_schedule()["created_by_username"]`; the refusal reason `action_not_declared`; the result key `vanished_targets`; the audit metadata `run_kind`, `creator`, `confirmed_by`; the schedule keys `created_by_username` and `confirmed_by_username`; the list filters `created_by` and `confirmed_by`.
- **Changed for module ids with capital letters.** `<module id>.<job>` event ids and `<module id>.server_job_finished` accept the module id's own spelling.
- **Capabilities.** Unchanged: `core.system_actions` stays 1.0.0 (its refusal reasons list grows), `core.event_jobs` 1.1.0, `core.server_maintenance` 1.1.0.
- **Contract catalog.** The rows for `register_scheduled_action`, `reconcile_schedule`, `get_owned_schedule`, `verify_run_context`, `VerifiedSchedulerRun`, `run_system_action`, `SystemActionRefused`, `register_event_job`, `hook_job_id` and `deliver_finished_server_jobs` say what changed.

### What I checked in `modules/`

`tests/scheduler-compat-1.17.63.py` reads every module as source. It found 83 calls of the Scheduler, run-context and system-action functions, and every one binds to the 1.17.63 signatures. Of them, 24 modules make the 25 `reconcile_schedule` calls, 6 `start_one_off_run` calls, 2 `verify_run_context` calls (patchmanagement) and 1 `get_owned_schedule` call. The new parameters are optional and keyword-only, the new dataclass fields are last with defaults, and no module passes `unattended` or `confirmed_by_request`. No module calls `run_system_action` or `register_system_action`, no module manifest lists `system_actions` yet, and no module defines a mixed-case `server_job_finished`. So the behaviour change reaches no module until patching or patchmanagement adopts it in its own release.

## What changed in existing tests, and why

- **Newest migration is now 0036** (and "no 0037" where it was "no 0036"): `event-jobs-refusal-audit-1.17.48`, `event-jobs-refusal-bound-1.17.49`, `migration-model-id-agreement-1.17.36`, `runtime-settings-upload-1.17.14`, `session-theme-1.17.24`, `update-source-1.17.2`, `scheduler-migration-0034-1.17.61` and `server-job-hook-migration-0035-1.17.62`. Each pins the newest migration.
- **Version pins:** `contract-catalog-1.17.61` and `module-job-contract-rows-1.17.60` now accept 1.17.63.
- **Stubs that compile the real tick or the run context and now need the one new helper** (the plan did not list these; running the tests found them): `scheduler-closure-1.15.149` and `scheduler-filter-value-compat-1.15.134-2` add `_is_unattended_scheduled_run` to their namespaces (an ordinary schedule is never unattended). `scheduler-run-context-1.17.19` adds two stubs (`_is_unattended_scheduled_run`, `_creator_names`); `scheduler-run-context-bind-1.17.20` runs on the same stubs.
- **Pins of shapes that grew on purpose:** `scheduler-one-off-run-1.17.16` (the key set of `get_owned_schedule` gains `created_by_username`); `system-actions-audit-1.17.61`, `system-actions-run-1.17.61` and `system-actions-targets-1.17.62` (the audit metadata gains `run_kind`, `creator`, `confirmed_by`); `system-actions-compat-1.17.61` (the `register_scheduled_action` signature and the `ScheduledAction` fields gain `unattended` at the end).
- **Harness:** `scheduler-completion-harness-1.17.61.py` gains a `values_list` on its query stub and the two name fields on its schedule model. Nothing existing changed.
- No assertion about behaviour was weakened. Every test that passed before 1.17.63 and does not need Django still passes.

New tests: `scheduler-unattended-owner-1.17.63`, `system-actions-unattended-1.17.63`, `scheduler-creator-filter-1.17.63`, `scheduler-module-owned-creator-1.17.63`, `event-jobs-mixed-case-id-1.17.63`, `server-job-hook-starvation-1.17.63`, `scheduler-compat-1.17.63`, and the dev-server probe `scheduler-unattended-runtime-1.17.63`.

## What was left out, and what ends each wait

- **CQ175 rows (reboot, uninstall, scripts, commands, checks, tasks, reports).** The task for this release said you signed these off. The only words of yours in this release are the two answers above, and no per-row sign-off is on file. These rows run code on endpoints with no one signed in, so I did not build them. They stay (a): a row only when the owning module asks and you sign that row off.
- **CQ173 (scheduled install for Advanced Patch Management).** Not signed off here. `winupdate.install` stays refused for a replacement (`reapproves_by_policy`), because Advanced Patch Management may have set some updates to Ignore and Tactical's bulk install re-approves them.
- **CQ178 (groups above 2000 endpoints).** Not signed off here. The cap stays: refused above 2000, never truncated. The design is ready (groups of at most 2000, the whole set checked first, at-most-once per group, an audit row before each send, a plain summary).
- **CQ174 (rule push) and CQ177 (polling).** Nothing built. CQ174 keeps its recommendation. CQ177 stays "the module pushes the result", which is how Tactical works too.
- **Wide reading of CQ179.** See CQ184.
- **Mixed-case ids for system action ids and the manifest `system_actions` pattern.** No module needs them. Same fix shape when one asks.
- **A way to read a module-owned target type as endpoints.** Still its own design (request in `reviews/requests/core.md`). CQ179 and CQ176 are no longer what it waits for.
- **R-36, licensing entry, licensed catalogue, secret store, R-12, R-13, R-24 to R-27:** different code, not in this release.
- **Authority documents.** I did not edit the standard, the AD index, the rules or the checklist. They are not Core's files. The wording to paste is in section 1.

## Where the plan changed once I was in the code

- **The creator filter runs in Python over the rows the list already loads,** not as a database filter. Same result, and it can only remove rows, so it is easy to prove it adds no right.
- **`tasks.py` needed no change.** The one-off re-check is unchanged and the worker holds no exemption. The tick and `verify_run_context` do the deciding, through the one helper.
- **Two more fields on `VerifiedSchedulerRun` than the plan named:** `unattended` (so the system-action code never decides it again) beside the two names.
- **A refused no-request change restores the row,** whatever object holds it, so a refused call can never leave a half-changed schedule.
- **The trailing-newline fix in the event job id pattern** was not in the plan.

## Questions for Johan (assumption used; no wait)

In `reviews/questions/core.md`: CQ179 is marked answered (b) with the Tactical evidence and the plain cost; CQ183 is marked fixed; CQ176 is marked built. New: CQ184 (how wide "yes follow tactical" reaches; assumption narrow) and CQ185 (the shape of a module-owned schedule that names a person). A note says which earlier answers I did not act on and why. A note says the authority documents need the coordinator.

## Requests written for other areas

- `reviews/requests/ui.md` ("From Core 1.17.63"): show the creator and confirmer on the Scheduler page and offer the filter.
- `reviews/requests/premium-modules.md` ("From Core 1.17.63"): patchmanagement adopts `unattended=True` and `confirmed_by_request`, with the plain cost in its Help.
- `reviews/requests/core-modules.md`: patching may adopt `unattended=True` ("From Core 1.17.63"); securityWAF's hook note is replaced (the lowercase limit is gone, needs framework >=1.17.63).
- `reviews/requests/core.md`: the shipped line for 1.17.63 and updated notes on the two waits it closes.

## What could not run on this PC

Django, Celery, Postgres and Tactical are not installed here. Not run: the model and migration 0036 on a real database, `makemigrations --check`, the real tick against Postgres, the Celery worker, the DRF views (the create, edit and list wiring is read as source and the filter functions are compiled out of the real file), real Tactical imports, and the real job folder. The tests use the stub harness, source reads and temporary folders. `tests/scheduler-unattended-runtime-1.17.63.py` covers the database and process parts on the dev server.

Checks that ran: `bash tests/release-integrity.sh` (PASS; it needs `python3`, so I ran it with a small `python3` shim on the path); `python -m py_compile` on every changed file (clean); the seven new tests that run here (all PASS; the eighth is the dev-server probe); and a full run of all test files before and after, which gave the same result for every existing test (about 130 tests need Django, Celery or Postgres and fail on this PC before and after). `ruff check`: the repo has no Core ruff config, so I used the modules' config (`E`, `F`, `W`, `B`, `I`, line length 160). The changed source files gain no new finding (the same 11 older ones remain), and the new tests are clean. With ruff's wider default rule set the changed source files gain three `BLE001` (a blind `except Exception`) in the same pattern the files already use for best-effort audit and lookups.

## Dev-server checklist (PASS or FAIL for each step)

Run on the dev server after the signed build is installed. Never run it during an install or a Core update.

1. **Core is 1.17.63.** Open the About or update page. Expected: 1.17.63. FAIL: anything else. Send back: a screenshot.
2. **Migrate.** `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac`. Expected: "Applying tec_tac.0036_schedule_creator_name... OK". FAIL: any error. Send back: the full output.
3. **Model and migration agree.** `../env/bin/python manage.py makemigrations --check --dry-run`. Expected: "No changes detected". FAIL: it lists a change for `TecTacSchedule`. Send back: the output.
4. **Restart.** Restart Core and the Celery workers the way you did for 1.17.62. Expected: both come back, the sign-in page loads. FAIL: either does not start. Send back: the last 50 lines of each service log.
5. **Hook probe (CQ183 and the read budget).** `TECTAC_PROBE_PART=hook ../env/bin/python manage.py shell < /path/to/tests/scheduler-unattended-runtime-1.17.63.py`. Expected: PASS lines for the migration, `securityWAF.server_job_finished` accepted, the three bad ids refused, tick 1 delivering the finished job behind 60 unfinished files (61 reads), tick 2 reading none of the 60, and the last line "PASS scheduler unattended runtime 1.17.63". FAIL: any FAIL line. Send back: the whole output.
6. **A demoted creator's scheduled run still runs (CQ179 b).** Use one test endpoint. `TECTAC_PROBE_PART=unattended TECTAC_PROBE_USER=<user> TECTAC_PROBE_AGENT=<id> TECTAC_PROBE_PHASE=prepare ...` and note the run id. In Tactical, remove `can_run_bulk` and `can_manage_winupdates` from that user's role (or deactivate the user). Then `TECTAC_PROBE_PHASE=execute TECTAC_PROBE_RUN=<id> TECTAC_PROBE_EXPECT=queued ...`. Expected: "run status: succeeded", an audit row "run" whose username is that user, and "PASS expected queued for a scheduled run". FAIL: the run is skipped or refused. Send back: the whole output. Restore the user's role afterwards.
7. **A person-started run is still refused.** Repeat step 6 with `TECTAC_PROBE_KIND=manual` and `TECTAC_PROBE_EXPECT=refused` while the user is still demoted. Expected: "run status: skipped", error type `SystemActionRefused`, and "PASS expected refused for a manual run". FAIL: the manual run was queued. Send back: the whole output.
8. **The audit row names the creator.** In the audit log, open the `run` row from step 6. Expected: the metadata shows `run_kind: scheduled`, `creator` and `confirmed_by` with the user's name. FAIL: a missing key. Send back: a screenshot of the row.
9. **The creator filter.** In a browser session signed in as an administrator, open `/api/tfd/scheduler/schedules/?created_by=<that user's name>` (and again with the name in capitals). Expected: only schedules that user created, each with `created_by_username` and `confirmed_by_username`; an unknown name returns `"count": 0`. FAIL: other people's schedules appear, or a 500. Send back: the response text.
10. **Create and edit store the names.** In the Scheduler page, create a schedule for any existing action and then edit it. Expected: it saves as before. Read it back at `/api/tfd/scheduler/schedules/<id>/`: `created_by_username` is your name, and after an edit `confirmed_by_username` is the editor's name. FAIL: a 500, or the names stay empty. Send back: the response text.
11. **Existing schedules still run.** Watch the Scheduler page for ten minutes. Expected: existing recurring schedules still run on time and no new `AuthorizationRevoked` rows appear for people who still hold their roles. FAIL: schedules skipped that ran before. Send back: the run list.
12. **The tick log is quiet.** `journalctl -u <the Core service> --since "15 minutes ago" | grep -i "server job hook\|server_job_hooks\|scheduler"`. Expected: no line saying "failed". FAIL: a "step failed" line. Send back: those lines.
13. **Export the public contract** into `docs/contracts`. Expected: the rows for `register_scheduled_action`, `reconcile_schedule`, `run_system_action` and `hook_job_id` mention 1.17.63, and `core.system_actions` is still 1.0.0. FAIL: either is missing. Send back: the export file.

## Fixed after review (1.17.63 blocked, round 1)

Two findings blocked 1.17.63. Both are fixed here. The creator names, the creator filter, `confirmed_by_request` (CQ176), the mixed-case event job ids (CQ183) and the job hook budget are unchanged.

1. **High: the run-time owner re-check was removed before the decision was recorded.** Johan's chat answer to CQ179 ("yes follow tactical's implementation") is real, but the amended AD-13 condition 2 is not yet in `docs/review-accepted-decisions.md` or `docs/tec-tac-module-standard.md` section 1a, and those are not Core's files. So Core now keeps the re-check for every scheduled run.
   - New switch `scheduler.AD13_CONDITION_2_AMENDED`, shipped as `False`. While it is `False`, `_is_unattended_scheduled_run` answers `False` for every run. The tick, `verify_run_context` and `run_system_action` then re-check the owner (`owner_inactive`, `permission_lost`, `out_of_scope`) exactly as in 1.17.62. A demoted, deactivated or deleted creator's schedule is refused.
   - The unattended code path stays in place and is tested with the switch on. The release that records the decision in the two documents sets the switch to `True` and nothing else.
   - `tests/scheduler-unattended-gate-1.17.63-1.py` reads the two documents when it runs in the workspace. It fails when the switch and the documents disagree (amended text present and switch `False`, or the reverse). It also proves the refusal for a demoted, deactivated and deleted creator while the switch is `False`.
   - The docstrings, `docs/scheduler.md`, `docs/system-actions.md` and the contract rows no longer say "Amended by Johan". They say the answer was given in chat and is not yet recorded.
2. **Medium: the `unattended` flag was not tied to a system action and was checked only at registration.**
   - `register_scheduled_action(unattended=True)` now needs the action's own id in the module's signed manifest `system_actions`. Before, any listed id was enough.
   - At every decision the helper asks again: the id is still in the signed manifest, and the module has registered a system action with that id (`system_actions.is_registered_system_action`). If either is missing or unreadable, the run is re-checked as an ordinary one.
   - I did not require the system action at registration. Modules register both from `AppConfig.ready()` and Core does not fix the order. The check at decision time cannot be bypassed by ordering.

### Module-facing change
- A module that passes `unattended=True` must name the scheduled action with the same id as its system action (for example `patching.scan` for both). No module in `modules/` does this today (grep of `modules/` found none), so nothing breaks. Nothing changes for a module that does not pass `unattended`.
- Until the switch is `True`, `unattended=True` has no effect on checks. The keyword, the `unattended` field and the `VerifiedSchedulerRun` fields stay, so a module can adopt them now.

### Tests changed
- `tests/scheduler-unattended-owner-1.17.63.py`, `tests/scheduler-module-owned-creator-1.17.63.py` and `tests/system-actions-unattended-1.17.63.py` set the switch to `True` in-process. They prove the post-amendment behaviour. They also list and register a system action under each unattended action id.
- `tests/scheduler-unattended-runtime-1.17.63.py` (dev server) sets the switch and the manifest list in the shell for its probe only. Run its steps as written in the 1.17.63 checklist. The probe proves the path that applies once the decision is recorded. It does not change the shipped value.

### What stays open
- Johan or the release manager records the amended AD-13 condition 2 (the suggested wording is in the CQ179 entry of `reviews/questions/core.md`) in `docs/review-accepted-decisions.md` and `docs/tec-tac-module-standard.md` section 1a. Then the next Core release sets `AD13_CONDITION_2_AMENDED = True`. The gate test ends the wait: it fails until both documents contain the text "flagged unattended is not re-checked".
- Dev-server checklist: the 1.17.63 steps for `hook` still apply. For the `unattended` part, the shipped Core refuses a demoted creator's scheduled run until the switch is `True`.

## Fixed after review (1.17.63-1 stopped at signing)
The 1.17.63-1 pack passed the 12 gates and the AI review with no findings. It stopped at signing only because the text "1.17.63-1" appeared in `contracts.py`, `scheduler.py` and `system_actions.py`. Promotion refuses a rebuild suffix in source files.

We reworded those lines to say "1.17.63" or to carry no version. No behaviour changed. `AD13_CONDITION_2_AMENDED` stays `False`, so every scheduled run keeps the run-time re-check. CQ184 and CQ186 stay open for Johan.

### Module-facing change
None. Only the wording of contract text changed. No capability, signature or endpoint moved.
