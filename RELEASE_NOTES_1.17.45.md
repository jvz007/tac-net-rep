# Tec-Tac Framework 1.17.45

This patch release adds `core.event_jobs` 1.0.0, a new Core contract for small background jobs that start from an event, such as a Tactical alert
being saved. It also gives Tactical operations three opt-in additions, and says in the docs which path a module should use to register a report
model. Everything is additive. Migration 0032 adds two empty tables. No existing contract, task, table, route or capability changes.

Why: Alerts hears a Tactical alert change through a signal and must not work inside Tactical's request. Until now it ran its own Celery task and its own
retry timetable. Johan asked for the permanent fix first and the Alerts change second, so Core now owns the job, its limits and its retries.

## Module-facing: `core.event_jobs` 1.0.0 (needs framework 1.17.45 or later)

A module registers an event job once, from `AppConfig.ready()`, and publishes to it from a signal. Core stores the job, sends it to a worker, runs the
module's handler, retries it, limits it and audits it. The full contract is `docs/event-jobs.md`.

- **Register:** `tec_tac.event_jobs.register_event_job(id, module_id, label, handler, ...)` returns the one handle that can publish this job.
  It touches memory only. The id is `"<module_id>.<job>"`. A refusal raises `EventJobRegistrationError` (a `ValueError`); wrap the call, log it and carry
  on, so Tactical always starts. Feature-detect with `has_capability("core.event_jobs")` and set `requires.framework` to `>=1.17.45`.
- **Limits, all Core's:** soft time limit 5 to 600 seconds (default 30; the hard limit is 15 seconds more), 1 to 10 attempts (3), back-off 5 to 3600
  seconds (60, doubling, capped at 3600, plus up to 20 percent jitter), expiry 60 to 86400 seconds (1800), backlog 1 to 5000 pending jobs per job
  (500), `dedupe_seconds` 0 to 3600 (0), payload 2 KiB, key 128 characters, 600 publishes a minute per job per process. A module can ask for less and
  never for more.
- **Publish:** `publisher.publish(key, payload)` never raises and answers `queued`, `duplicate`, `dropped`, `disabled` or `error`. It decides from memory
  first (registry, a 5 second module-enabled cache, a 3 second duplicate check, the rate cap, a backlog gauge) and drops without a database query when
  any says no. Otherwise, after the caller's transaction commits (at once when none is open), it stores one row and sends one Celery message with a
  2 second broker timeout, no retry and a 30 second circuit breaker. If the broker is down or a worker process was recycled, the row stays pending and the
  Scheduler tick (every minute) sends it. Nothing stored is lost.
- **Run:** the new Celery task `tec_tac.execute_event_job` claims the row under a lock, so a duplicate delivery runs nothing twice. It checks again, with
  no cache, that the module is still installed and enabled, that the handler is registered in this worker and that the job has not expired. The handler
  gets an `EventJobContext` with `job_id`, `module_id`, `key`, `payload`, `attempt`, `max_attempts`, `final_attempt`, `enqueued_at` and `run_id`, and no
  user fields. `verify_event_job_context(context, expected_module_id=..., expected_job_id=...)` confirms the context is Core's.
- **Failures:** `SchedulerPermanentError`, `ValueError` and `TypeError` give up at once. `SchedulerTransientError`, Celery's `SoftTimeLimitExceeded` and
  anything else retry with Core's back-off until the attempts are used up, then the row ends `failed` with one Core audit row.
- **Audit:** Core writes a row for a give-up, a skip by the module or handler check, an expiry and a drop (one row per job per tick, with a count), as the
  service actor `event-jobs`. A success writes a row only when the job registered `audit_success=True`. Retries stay on the job row and in the counters.
  Never the payload, never a secret.
- **Read:** `publisher.status()` (counts, backlog, oldest pending age, last failure; own job only), an additive `event_jobs` block in
  `scheduler_health()`, and `GET /api/tfd/scheduler/event-jobs/` (server-maintenance authority, the same as `scheduler/health/`; counts only, never a
  payload, key or row id).
- **What it does not do:** the job runs as the module, not as a person. A handler cannot call `run_tactical_operation`, so an event job cannot make a
  Tactical change. That is the AD-13 system-action contract, which is still open. Scriptexecution, maintenance, licensing, remote-background, patching,
  communicator and checks keep waiting for it.
- **Delivery is at least once.** A handler can run twice and must be safe to repeat. Alerts keeps `NativeAlertState` for that.
- **No module in `modules/` uses it yet,** so no installed module is affected. Alerts adopts it in a later release (`reviews/requests/core-modules.md`).

### Security review points

1. A module cannot publish for another module. Only the handle `register_event_job` returned can publish, and registration binds the job to the module's
   own registry entry and folder (a real-path check, as `caller_identity` does).
2. A module that imports another module's private code is the usual hostile-import case (rule 3.4, signed-module review). Core adds no verified-caller stack
   check on each publish: it would cost a stack walk on every Tactical alert save and make event jobs a fourth caller-verified Core provider. This is
   Johan's call (`reviews/questions/core.md`, CQ134).
3. The handler is at least once and must be safe to run twice.
4. The payload is data: JSON only, 2 KiB at most, never logged, audited, listed or returned.
5. Exception text may reach the audit row, cut to one line of 200 characters. A handler keeps secrets out of exception messages.
6. A disabled or uninstalled module's jobs never run, and the tick expires its pending rows.
7. Core caps the backlog, rate, expiry, attempts, time limits and payload, so a signal storm cannot grow without limit.
8. Registration and the capability registration are guarded, so Tactical always starts (checklist A9).
9. The worker re-checks the module state, the registration and the expiry itself and never trusts the publish-time check.

### What changed in Core for it

- `framwork/tec_tac/event_jobs_policy.py` (new, no Django): the key and payload checks, the limits, the back-off, the expiry, stale and overdue decisions,
  the rate window, the duplicate memory and the circuit breaker.
- `framwork/tec_tac/event_jobs.py` (new): the registry, the publisher, the worker, the tick step, status, health and the capability.
- `models.py` and migration `0032_event_jobs`: `TecTacEventJob` and `TecTacEventJobStat`, with a partial unique constraint so one (module, job, key) is
  pending or running only once.
- `tasks.py`: `tec_tac.execute_event_job`. `scheduler.py`: the tick calls `recover_event_jobs` after `recover_stale_runs` in its own `try` block (a fault
  there never stops a schedule), and `scheduler_health()` gains the `event_jobs` block. `scheduler_views.py` and `urls.py`: the read route. `apps.py`: the
  guarded capability registration. `contracts.py`: the three Python contract rows and the HTTP row.

## Module-facing: `core.tactical_operations` 1.14.0 (needs framework 1.17.45 or later; feature-detect with `>= 1.14.0`)

Three opt-in changes. A declaration that uses none of them behaves exactly as before, with the same rows.

- **`audit.action_by_body = {field, map}`.** The success row's audit action is chosen from the cleaned value of one body field, for example
  `{"field": "action", "map": {"approve": "approve", "ignore": "modify"}}`. A missing, non-text or unmatched value keeps `audit.action`. Registration
  refuses a field outside `body_fields` (or a secret field), more than 8 entries, a key that is not text or is over 40 characters, an action outside the
  audit vocabulary, and `deny`, `custom:outcome-unknown` and `custom:operation-failed`, because Core writes those rows only. Deny and other Core-only rows
  keep their own action. The failed row and the outcome-unknown row carry the chosen action in `metadata.declared_action` (the outcome-unknown row only for
  an operation that declares the key). `describe()`, `get_operation` and `list_operations` show it as `audit.action_by_body`. Closes the 'per-call audit
  action' entry of 'from patching 0.3.0'.
  - **Correction to the request's example.** The request mapped 'ignore' to `deny`. Core refuses that, so Patching maps 'ignore' to another action in the
    vocabulary (`modify` or a `custom:<slug>`). This is written to `reviews/requests/core-modules.md`.
- **A nested body scope source, `body:<field>.<key>`**, one level deep (for example `body:dependencies.client`). `<field>` is one of `body_fields` and
  its value must be an object; a present non-object is 400 `scope_field_required`. Optional entries, list values and the 1000 id cap behave as for a
  top-level source. It is refused with `row_lookup`, `audit.object_body_field` and `audit.secret_fields` (the id would carry the value). Core checks the
  scope before Tactical runs and forwards the body it checked. Closes the 'nested scope source' entry of 'from reportmanager 0.5.0'.
- **The held Low of the 1.17.44 review.** A `core_refused` row for `invalid_correlation_id`, `invalid_audit_before` or `invalid_params` now carries the
  declared `audit.object_id`, as the 1.17.44 text promised for every row. It is declared text, never caller input. The only module that declares
  `audit.object_id` today is `scriptmanager`; nothing in `modules/` reads these rows by a missing id.
- **Compatibility.** The `audit` block of `describe()` gains one key, `action_by_body` (null when not declared). A grep of `modules/` found no reader that
  compares the whole block. Capability pins in tests moved from 1.13.0 to 1.14.0; no behaviour assertion changed.

## Documentation

- `tec_tac.reporting.register_reporting_model` (the shim) stays the supported path for any module whose `AppConfig.ready()` can run before Report Manager's.
  The shim holds the registration pending and replays pending registrations in id order after every `ready()` has run, so no ordering between `ready()`
  calls is needed. It is removed only after the last module switches, with no date (Johan's CQ13 to CQ16 answers of 9 October 2026, confirmed as built).
  This closes the 'Reporting: replay path for direct registry callers' entries of alerts 0.6.0, checks 0.11.0 and cyberhoot 0.8.0. No code changed.
  See `docs/module-reporting.md` and `docs/developer-contracts.md`.
- `docs/event-jobs.md` (new), with pointers from `docs/scheduler.md`, `docs/module-scheduling.md`, `docs/capabilities.md` and
  `docs/developer-contracts.md`. `docs/tactical-operations.md` has an 'Added in 1.17.45' section.

## Requests closed

- 'from alerts 0.10.0': an event-started, time-limited system job a module can publish from a signal (`core.event_jobs` 1.0.0).
- 'from reportmanager 0.5.0': the nested scope source.
- 'from patching 0.3.0': the per-call audit action.
- 'from alerts 0.6.0', 'from checks 0.11.0' and 'from cyberhoot 0.8.0': the reporting replay path (documentation).
- The held Low of the 1.17.44 review.

## Left out, and why

- Module standard section 8 and rule 1.7 are not changed here. They are documents of authority, so the clause that allows event jobs waits on Johan's
  sign-off (CQ133) and the release-manager writes it.
- CQ130 and CQ131 stay open (unanswered). The AD-13 system-action contract, the first-run Welcome contracts, the production gate, `conflicts_with`, general
  secret storage and the other items in `reviews/requests/core.md` are unchanged.

## For Johan

- Update the dev server to Core 1.17.45 once it is signed. The update runs migration 0032 (two empty tables). Nothing changes for anyone until Alerts
  adopts the contract.
- Run `tests/event-jobs-runtime-1.17.45.py` with `manage.py shell`, and `manage.py makemigrations --check --dry-run`, because the migration is written by hand.
  Export a fresh public contract into `docs/contracts`. It must list `core.event_jobs` 1.0.0 and `core.tactical_operations` 1.14.0.
- Questions CQ133 to CQ137 are in `reviews/questions/core.md`, each with the assumption Core went on with. Nothing waits on them.

## Tests

`tests/event-jobs-policy-1.17.45.py`, `tests/event-jobs-1.17.45.py`, `tests/event-jobs-contract-1.17.45.py`, `tests/event-jobs-runtime-1.17.45.py` (dev server),
`tests/tactical-operation-action-by-body-1.17.45.py`, `tests/tactical-operation-nested-scope-1.17.45.py`,
`tests/tactical-operation-object-id-core-refused-1.17.45.py`, `tests/reporting-supported-path-1.17.45.py`. Existing tests were updated for capability 1.14.0,
for migration 0032 as the newest migration, and (two tests that run `dispatch_due_schedules` in a bare namespace) for the tick's new step.

Django, PostgreSQL and Celery are not installed on the development PC. Migration 0032, the partial unique constraint, the row locks, the commit hook, the
statement timeout and the Celery task could not run here. The decisions are tested without Django, the rest against stubs, and the probe above covers the
real services on the dev server.
