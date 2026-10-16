# Tec-Tac Framework 1.17.47

Every `core.event_jobs` publish now checks who is calling. Only the module that owns a job can publish it. The check is cheap, because Core reads the
module list and states once every five seconds, not on every Tactical alert save.

## What changed and why

### The caller of every publish is verified (CQ134 b, AD-36)

Johan signed option b on 16 October 2026. Before this release, only the handle that `register_event_job` returns could publish a job, and signed-module
review was the only defence if a module got hold of another module's handle. Now `EventJobPublisher.publish` also asks Core who is calling.

- The first frame above `publish` must be the code of the enabled, non-legacy module that owns the job. Core uses its private
  `calling_module_for_core_provider` helper, the same one `core.accounts`, `core.resources`, `core.audit` and `core.module_preferences` use. This makes
  `core.event_jobs` the fifth Core provider that verifies its caller (AD-31 condition 2, AD-34 condition 2, AD-36).
- Another module, a test or library frame, a generated frame, a Core frame (the Scheduler, a `functools.partial` that Core runs), a disabled or legacy
  module and any error in reading the registry or module state give `PublishResult("error", "the caller is not the module that owns this job")`.
  Nothing is stored, nothing is counted, nothing is raised, and the in-process duplicate memory and the rate cap are untouched.
- The check runs in `publish` itself, after the existing module-enabled gate and before everything else. A disabled owner still answers `disabled`, with
  no stack walk. It never runs in the commit hook (that runs in a Core frame and would always be refused).
- Core logs one warning per job and refused caller a minute at most, so a storm cannot flood the log. The warning names no key and no payload.
- No audit row and no counter column record a refusal, so there is no migration. Whether to add one is CQ138 in `reviews/questions/core.md`. I went on with
  the log only.
- `core.event_jobs` moves from 1.0.0 to 1.1.0 with `requires_framework >=1.17.47` and a `caller` note in the contract metadata (CQ139, the same step
  `module_preferences` took in 1.17.37). The contract rows for `register_event_job`, `EventJobPublisher` and `verify_event_job_context` say the same.

Residual case, stated plainly: a module that makes another module's own code frame call `publish` (a hook list or a signal that runs callables for other
modules) is seen as that other module. This is the callback-surface limit already listed in `docs/caller-identity.md`. Signed-module review covers it.

### The module list and states are read through a five second snapshot, and the cost is measured

Reading the registry means scanning every module folder, and the module state is a file. That is too much for a path that runs on every Tactical alert save.

- `calling_module_for_core_provider` gets an opt-in, keyword-only `cache_seconds` (default 0). At 0 it behaves exactly as before, so `accounts`, `audit`,
  `resources`, `module_preferences` and `tactical_websocket` stay uncached. The public `core.caller_identity.calling_module` is never cached (AD-26: its
  enabled state is read on every call). Only `event_jobs` passes a value (5 seconds, `policy.ENABLED_CACHE_SECONDS`).
- With a value above 0, the plugin list, each module's enabled flag and the real path of each file name come from a process-local snapshot kept that long.
  A failed read is kept for the same window and the caller fails closed. The frame walk itself is never cached.
- Known effects, also in `docs/event-jobs.md`: after a module is disabled it can still be recognised as a caller for up to 5 seconds. The publish already
  tolerated 5 seconds through the module-enabled cache, and the worker re-checks the module uncached before any handler runs, so nothing runs for a disabled
  module. A module installed in the last 5 seconds is refused until the snapshot expires. That fails closed.

Measured cost, on this PC with stub reads (Windows, Python 3.12, 2000 publishes; the numbers move a little from run to run):

| | per publish |
|---|---|
| no caller check | about 6 to 11 microseconds |
| check, warm snapshot | about 24 to 35 microseconds |
| check, cold read every time | about 1.9 to 2.8 milliseconds (dominated by `realpath` calls on this PC, and one plugin scan and one state read per publish) |

The first version of the snapshot cached only the module list and states. It cost about 2.9 milliseconds per publish even when warm, because the frame walk
called `realpath` for every frame and every module folder. Keeping the real paths in the snapshot brought the warm cost down by about a factor of one hundred.

These are stub numbers. The real `discover_plugins()` scan, the real `load_state()` and the real helper cost need the dev server, because Django,
PostgreSQL and the real module folders do not run on this PC. `tests/event-jobs-caller-runtime-1.17.47.py` takes them there (see the Note for Johan in
`reviews/questions/core.md`).

### A deferred event job is retried after one to two minutes, as the docs now say (held Low from the 1.17.46 review)

When a worker cannot read the module state it keeps the row it holds and answers `job deferred`. The row was given `next_attempt_at = now + 60`, but the
tick only resends a row whose next attempt and last enqueue are both more than 60 seconds old, so the real wait was about two minutes plus the next tick.

A deferred row has no message in flight, so it is now due at once: `next_attempt_at = now`, `last_enqueued_at = now`. The first Scheduler tick more than 60
seconds later resends it. With a one-minute tick that is 60 to 120 seconds of wall time. The separate `UNREAD_RETRY_SECONDS` constant is gone, so the retry
and the tick use one number, `policy.OVERDUE_SECONDS`. `RELEASE_NOTES_1.17.46.md` (kept as it is in `docs/releases/`) said "60 seconds"; `docs/event-jobs.md`
now says "after one to two minutes". Retries after a failed attempt are unchanged: they carry their own countdown, and a lost message is resent 60 seconds
after it was due.

## Closes

- The request "Core 1.17.47: verified caller on every event job publish" in `reviews/requests/core.md`.
- The held Low of the Core 1.17.46 review (deferred retry about 120 seconds against 60 seconds documented).

## Module-facing: core.event_jobs 1.1.0, publish verifies its caller

- A module that publishes from its own code (a signal receiver, a view, a method of its own) is unaffected. A module that publishes through another
  module's code, or through a Core callback, now gets `error` and nothing is stored.
- Alerts 0.10.0 (`modules/alerts`, signed) registers `alerts.deliver` in `AppConfig.ready()` and calls `publisher.publish(...)` directly from
  `_publish_native` in its own code (`tec_tac_alerts/signals.py`). Its first non-Core frame is its own file, so it keeps working with no change. It checks
  `has_capability("core.event_jobs")` only and does not pin the version.
- To be sure the check exists, a module sets `requires.framework` to `>=1.17.47`.
- Request for the Alerts owner, written to `reviews/requests/core-modules.md`: the Alerts 0.10.0 release notes say Core adds no verified-caller check on
  each publish. That is wrong against AD-36 once this release ships.
- No import, endpoint or table changes. The Python signatures of `register_event_job`, `publish` and `verify_event_job_context` are the same.

## Docs and tests

- `docs/event-jobs.md`: header (capability 1.1.0, `>=1.17.47`), Publish, Security review points 2 and 6, Compatibility and Tests. `docs/caller-identity.md`:
  core.event_jobs is the fifth Core provider and the only one with the opt-in snapshot. `docs/capabilities.md`, `docs/developer-contracts.md` and
  `docs/scheduler.md` carry the new capability version.
- New `tests/event-jobs-caller-1.17.47.py` (real compiled frames under a stub module folder: the owner publishes; another module, a library, a generated
  frame, a Core frame, a partial run by Core, a disabled and a legacy module, a registry fault and a state fault are refused; a disabled owner answers
  `disabled`; the check is not repeated in the commit hook; the log is throttled; the snapshot counts reads with a fake clock; `cache_seconds=0` re-reads;
  the cost is printed). New `tests/event-jobs-deferred-1.17.47.py` (a deferred row is resent by the tick at +61 seconds and not at +59). New
  `tests/event-jobs-caller-runtime-1.17.47.py`, the dev-server probe.
- `tests/event-jobs-1.17.45.py` and `tests/event-jobs-module-gate-1.17.46.py` got a stub `tec_tac.caller_identity` seam, because a test file is not a
  module's code. `tests/event-jobs-policy-1.17.45.py`, `tests/event-jobs-contract-1.17.45.py` and `tests/event-jobs-1.17.45.py` pin 1.1.0 and
  `>=1.17.47`.

## Not run here

Django, PostgreSQL, Celery and the real module folders are not available on this PC. The event job tests run against stubs. Not run: the migration check
(there is no migration in this release), `tests/accounts-runtime-1.17.27.py` and `tests/event-jobs-runtime-1.17.45.py` (dev-server scripts), and the new
`tests/event-jobs-caller-runtime-1.17.47.py`. The real-disk cost numbers are taken on the dev server. A fresh contract export into `docs/contracts` must
list `core.event_jobs` 1.1.0 with `requires_framework >=1.17.47` and the caller note.
