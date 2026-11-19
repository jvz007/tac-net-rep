# Tec-Tac Framework 1.18.20

Date: 19 November 2026. Core can now install the licensed modules you ticked in one server-side run, show its progress and stop it. It also closes the two held Mediums of the 1.18.19 review and repairs two tests that already failed on dev.

## What changed and why

### 1. One install run for several licensed modules (requests R1b to R1d)

Welcome's module picker shows what to install. These three routes do the installing, so a browser tab never has to stay open and Core, not the browser, decides the order. All three need `core.privileged_operations`, checked first, and fail closed.

- `POST /api/tfd/modules/catalog/online/install/`. Body `{"modules": ["id", ...]}`, 1 to 50 ids. Core plans again on the server (`module_install_plan.plan_online_install`) and ignores any order or version from the client. A `licence_override_reason` or `disable_replaced` field is refused with 400. Another run still going: 409 `run_in_progress` with its `run_id` (checked before planning and again under a start lock). Plan state not `ok`: the plan body with the same status map as `GET allowed/`, and no run. Nothing installable: 400 `nothing_to_install`. Otherwise Core writes one strict start audit row, then the run file, then queues the first tick, and answers 202 with the progress body. No row, no run (503 `audit_not_saved`).
- `GET /api/tfd/modules/catalog/online/install/<run_id>/`. Progress: `run_id`, `status`, `started_by`, `started_at`, `finished_at`, `stop_requested`, `counts`, and per module `id`, `name`, `version`, `action`, `state`, `reason` (code and sentence), `job_id`, `job_status`, `job_stage`, `started_at`, `ended_at`. No log tail, hash, URL, publisher or key id. An unknown or malformed id is 404. It never stages or starts a module.
- `POST /api/tfd/modules/catalog/online/install/<run_id>/stop/`. The module being installed finishes. Nothing else starts. The rest end `skipped` with `stopped`. A finished run answers 409 `already_finished`. A job in flight is never touched.

How a run works:

- Run states: `running`, `stopping`, `completed`, `stopped`, `interrupted`. Module states: `pending`, `downloading`, `installing`, `succeeded`, `failed`, `skipped`.
- Each module goes through the two calls the single online install already uses: `stage_repository_package` (strict start audit row, licence grant, SHA-256, publisher signature with Core's trusted keys, identity check) and `queue_v2_install` (trust, licence, `resolve_install_plan` on the signed manifest, disabled-install, compatibility and replacement rules, then the helper job). `module_install_run.py` repeats none of those rules and never calls remove, uninstall, enable, disable, download or hash code.
- Modules the plan blocked are recorded `skipped` with the plan's code and sentence and are never downloaded. Deselected premium modules are never in the order, so they are never installed. Nothing in the run uninstalls anything.
- Before each module Core reads the allowed list again. A module that is no longer ticked, has no release or has another version than planned is skipped (`not_selected`, `no_release`, `version_changed`) and never staged. If the list cannot be read, the module is skipped `allowed_unavailable`.
- A failed module is reported with its own sentence (a job error is cut to 400 characters). Only the modules in this run that need it are skipped (`dependency_failed`, naming the module). A module whose manifest would disable a replaced module, or whose licence check needs an override, fails with its sentence. Install it on its own through the single route.
- The run is one JSON file in `/var/lib/tec-tac/module-manager/install-runs/<run_id>.json` with a lock per run. The last 20 are kept.
- The module helper restarts Tactical's Celery and reloads uwsgi during an install, so the driver is a short Celery task, `tec_tac.advance_module_install_run`, that does one idempotent step and queues itself again after 3 seconds. A tick that finds a module still `downloading` with a free lock knows the earlier tick died and marks it failed ("The download was interrupted. Install it again."). A progress request queues a tick if none ran for 30 seconds. A run with no step for 15 minutes and no active job ends `interrupted`, so a lost worker cannot block new runs. A job that is still running is always waited for.
- Audit (existing actions only): the start row (`run`, `module_install_run`, the person), one row per module outcome (service actor `core/module-install-run`), one end row with counts and who started it, and `modify` "Stop requested" for a stop. State words and Core sentences only, never a token, path or URL.

New file `framwork/tec_tac/module_install_run.py`. The views are in the new `module_install_run_views.py` (not in `module_allowed_views.py`, whose audit calls and plan view older tests read as a whole), the routes in `urls.py`, the task in `tasks.py`. The new views are grouped under Module Repository in `openapi.py`. The routes are in `contracts.py` and `docs/module-repositories.md`.

### 2. Held Mediums of the 1.18.19 review (`module_install_plan.py`)

The run plans again before every start, so a 500 here would block every start.

- The allowed release's version must equal the matched catalogue entry's version when the entry has one. Otherwise the module is blocked `not_in_catalogue_cache`.
- The resolver call in `build_plan` is wrapped. A `ModuleManagerV2Error`, `ModuleStateError`, `ValueError`, `KeyError` or `TypeError` now returns the `plan_conflict` body with the error sentence in `conflicts[]` instead of a 500.

### 3. Two tests that already failed on dev

- `tests/online-catalog-availability-1.17.41.py` builds a fake namespace from named source pieces. It was missing `_development_for`, `_unavailable_licensed` and `MAX_UNAVAILABLE_ROWS` (added in 1.17.108 and 1.17.109) and the stubs they read. Test only; the source was right.
- `docs/troubleshooting-diagnostics.md` had 13 LF lines (the "Install checks (1.18.9)" section appended in 1.18.9 and 1.18.10) in a CRLF file. They are CRLF again, so `tests/licensing-repository-1.17.103.py` passes. Nothing else in the file changed.

Moved: `RELEASE_NOTES_1.18.19.md` to `docs/releases/`, `tests/version-1.18.19.py` to `tests/legacy/`.

### Fixed in precheck

The run folder `install-runs` was not in the permission specs, so the Tactical user could not create it and every install run answered 500. `scripts/recovery/lib.sh` now creates it as `root:<tactical group>` mode 2770 and checks it in the recovery runtime-write check. `install.sh` verifies the Tactical user can write it. A source-level assertion in `tests/online-install-run-1.18.20.py` guards the spec.

## Fixed after review

Round 1 blocked 1.18.20 on one High finding: tick chains multiplied on Tactical's Celery while a download held the run lock.

- Cause: `advance_run` holds the per-run lock for the whole download and signature check. A tick that found the lock busy returned "not final", so `advance_and_requeue` queued it again. Each progress poll after 30 seconds also queued a tick, and each of those started its own self-requeuing chain.
- Fix in `framwork/tec_tac/module_install_run.py`: a tick on a busy lock now ends without queuing, because the lock holder queues the next tick itself. `progress()` no longer queues a tick while the lock is held. If the holder dies, its lock is released and the next poll starts one new tick. `advance_run` keeps its True/False result.
- Test: `tests/online-install-run-1.18.20.py` holds the lock, polls ten times past the stale limit, and asserts nothing is queued. It also asserts that a busy tick queues nothing and that outstanding ticks stay at one or fewer after the lock is free.
- Siblings checked: `close_if_stale` and `request_stop` take the lock without queuing from a busy path. `request_stop` queues one tick per stop request, which is bounded by user action.

## Module-facing change

- Three new routes, all additive: `POST /api/tfd/modules/catalog/online/install/`, `GET .../install/<run_id>/` and `POST .../install/<run_id>/stop/`. One new Core-internal Celery task, `tec_tac.advance_module_install_run`. Modules do not call the task.
- No existing route, contract or capability changed. Nothing in `modules/` calls the install routes yet. The first reader will be Welcome 1.2.16.
- The plan route (1.18.19) now returns `plan_conflict` instead of a 500 in one case, and blocks a release whose catalogue entry has another version. Both are stricter, neither changes a field.

## Assumptions

- The run works through a short Celery tick that re-queues itself, with the state in a file (option a). A long task or a request thread would be killed by the helper's restarts, and a loop inside the root helper would widen it.
- A batch never overrides a licence and never confirms a replacement disable. Those are per-person confirmations of the single route. The body fields are refused.
- The run installs everything that is still installable. Blocked and failed modules are reported, and only their dependants are skipped.
- Core re-checks the ticked state and the planned version before each module.
- A run with no step for 15 minutes and no active job ends `interrupted`.
- If a worker dies in the instant between `queue_v2_install` returning and the run file being saved, the next tick marks that module failed while its job may still install. That is the safe direction: nothing extra is installed, and its dependants are skipped.

## What could not be run

Django is not installed on this PC and the module state code needs `fcntl`. The views, the Celery task, `FileStore` locking and the real stage and queue path (`stage_repository_package`, `queue_v2_install`, the helper job) run only on dev02. `tests/online-install-run-1.18.20.py` ran the run logic with injected collaborators and an in-memory store. The routes, task, contract and docs are checked at source level.

Other tests that read the same files (`licensing-availability-1.17.108`, `licensing-unclassified-test-1.17.109`, `repository-retired-1.17.99`, `secret-store-1.17.100`) already failed before this release for their own reasons (the same `_development_for` namespace gap, and a missing `RELEASE_NOTES_1.17.109.md`). They are not changed here.

## What is not in this release

- The held Low of the 1.18.19 review (the plan route repeats installed-catalogue reads and has no throttle). It stays in the backlog.
- R2 (modules whose UI is not reported) and R3 (first-install intake for Licensing and Welcome).
- Licence override, confirmed replacement disable, and index (default or custom) repositories in the batch run.
- The install button and progress screen: Welcome 1.2.16.

## Johan dev02 checklist

Update dev02 to Core 1.18.20 first. Licensing must be 0.10.7 or later.

a. Install two licensed modules where one needs the other, both ticked: POST install with both ids. Expected: the needed module first, one job each in Module Manager job history, one `run_id`, the progress shows both `succeeded`, one start and one end audit row. FAIL: wrong order, more than one run id, a module installed that was not ticked, or any module removed.
b. Stop mid-run: start a run of three modules and POST stop while the first is installing. Expected: the first finishes, the other two end `skipped` with `stopped`, the status is `stopped`, nothing starts afterwards. FAIL: a job is killed mid-install or a later module still installs. Also POST a second start while a run is going. Expected: 409 `run_in_progress` with the first run id.
c. Blocked modules: include one that is unticked, one whose dependency is unticked and one already installed. Expected: each is `skipped` with its plan code and sentence and was never downloaded (no "started downloading" audit row for them). Then make one module's job fail and include a module that needs it and an unrelated one. Expected: the dependant is `skipped` with `dependency_failed` and the unrelated module still installs. FAIL: a dependant installs after its dependency failed.
d. Celery restart safety: the run must finish although the helper restarts Celery between modules. FAIL: the run stays `running` with no progress for more than a minute, or never ends (it must end `interrupted` within 15 minutes at worst).
e. The two repaired tests pass on dev: `python -I tests/online-catalog-availability-1.17.41.py` and `python -I tests/licensing-repository-1.17.103.py`. FAIL: either prints a traceback.
