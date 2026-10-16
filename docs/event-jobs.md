# Event jobs: small background work that starts from an event

**Status:** Public Core developer contract, added in Core 1.17.45
**Python:** `tec_tac.event_jobs`
**Capability:** `core.event_jobs` 1.1.0 (major 1, additive; 1.0.0 until Core 1.17.47), owner `core`
**HTTP:** `GET /api/tfd/scheduler/event-jobs/` (read only, server-maintenance authority)
**Needs:** framework `>=1.17.45` (`requires.framework`), migration `0032_event_jobs`; framework `>=1.17.47` for the caller check on every publish

## What this is for

Sometimes a module has to do a small piece of work because something happened: Tactical saved an alert, a webhook arrived. The module
must not do that work inside the request. It also must not start its own thread, timer or private Celery task for it.

An event job is the one sanctioned way. The module says "this happened" and Core does the rest: it stores the job, sends it to a worker, runs
the module's handler, retries it when it fails, gives up after a fixed number of tries, drops it when there is too much waiting, and writes
the audit row. Core owns every limit. A module can ask for less and never for more.

An event job is not a schedule. The Scheduler runs a registered action at a time. An event job runs a registered handler because of an
event, as soon as a worker is free.

## How a module uses it

Register once, from `AppConfig.ready()`. Registration touches memory only. It writes nothing to the database.

```python
import logging

logger = logging.getLogger(__name__)


def ready(self):
    try:
        from tec_tac.capabilities import has_capability
        from tec_tac.event_jobs import register_event_job

        if has_capability("core.event_jobs"):
            self.deliver = register_event_job(
                id="alerts.deliver",            # "<module_id>.<job>"
                module_id="alerts",
                label="Send an alert notice",
                handler=deliver_alert,          # a plain function defined in this module's own code
                max_attempts=3,
                audit_success=False,
            )
    except Exception:
        logger.exception("Event job registration failed")   # Tactical must still start
```

Publish from the place the event happens, for example a `post_save` receiver:

```python
result = self.deliver.publish(key=f"alert:{alert.pk}:{state}", payload={"alert_id": alert.pk, "state": state})
# result.outcome is one of: queued, duplicate, dropped, disabled, error. It never raises.
```

The handler gets a context and does the work:

```python
from tec_tac.event_jobs import verify_event_job_context
from tec_tac.scheduler import SchedulerPermanentError, SchedulerTransientError


def deliver_alert(context):
    verify_event_job_context(context, expected_module_id="alerts", expected_job_id="alerts.deliver")
    alert_id = context["payload"]["alert_id"]
    ...                                          # do the work; it may run twice, so it must be safe to repeat
    return {"sent": True}                        # None, or a small JSON-safe dict (kept up to 2 KiB)
```

- Raise `SchedulerPermanentError` (or let a `ValueError` or `TypeError` happen) when trying again cannot help. Core gives up at once.
- Raise `SchedulerTransientError`, or let anything else happen, when trying again may help. Core retries with its own back-off.
- Keep secrets out of exception messages. The first 200 characters of one line may reach the audit row.

### Registration arguments

| Argument | Meaning | Core's limit (default) |
|---|---|---|
| `id` | `"<module_id>.<job>"`; the prefix must be the module's own id | lowercase letters, digits, `-` `_` and `.` in the job part |
| `module_id` | the module that owns the job | an installed, enabled extension |
| `label` | one plain line for the Scheduler page | 120 characters |
| `handler` | `handler(context)`, a function or method in the module's own folder | not a partial, a built-in or generated code |
| `soft_time_limit_seconds` | the handler is told to stop after this long | 5 to 600 (30). The hard limit is 15 seconds more. |
| `max_attempts` | tries before Core gives up | 1 to 10 (3) |
| `backoff_seconds` | wait after the first failure; doubles each time | 5 to 3600 (60) |
| `max_backoff_seconds` | the most one wait can be (plus up to 20 percent jitter) | at least `backoff_seconds`, up to 3600 (3600) |
| `expires_seconds` | a job not started by then ends `expired` | 60 to 86400 (1800) |
| `max_backlog` | pending jobs of this job Core keeps | 1 to 5000 (500) |
| `dedupe_seconds` | a run that succeeded with the same key inside this window makes a new publish a duplicate | 0 to 3600 (0) |
| `audit_success` | write a Core audit row for each success | `False` |

Registering the identical definition again returns the same handle. A different definition under the same id is refused. A refusal raises
`EventJobRegistrationError`, a `ValueError`. The module catches it, logs it and carries on.

### Key and payload

- `key` is supplied by the caller: 1 to 128 characters of letters, digits and `. _ : @ / -`. It makes the publish idempotent: one key can be
  pending or running once per job, and a second publish of it is `duplicate`.
- `payload` is a JSON object of at most 2 KiB with text, numbers, true, false, null, lists and objects only (4 levels deep). Send ids, not
  text bodies, and never a secret. It is checked before anything is stored.

## What Core does

### Publish (in the request)

The publish never raises and makes no network call except one bounded broker publish. It decides from memory first, with no database query:
the registry, a module-enabled state kept for 5 seconds, then the caller (from Core 1.17.47: the first frame above `publish` must be the
code of the enabled module that owns the job, read from a 5 second snapshot of the module list and states, else the result is `error`), an in-process memory of the same `(job, key)` for 3 seconds, a cap of 600 publishes a
minute per job per process, and a backlog gauge. A job at its backlog is dropped without a query. An absent or old gauge counts as open.

Otherwise, after the caller's transaction commits (at once when none is open), Core stores one row and sends one Celery message:

- the row is stored with a statement timeout of 1000 ms on PostgreSQL;
- the message uses a 2 second connect and socket timeout, no retry, the job's own soft and hard time limits, and an expiry;
- after one broker failure Core skips the broker for 30 seconds (a circuit breaker);
- a failed broker publish is logged. The row stays `pending`, and the Scheduler tick (every minute) sends it.

So a broker outage, or a uWSGI worker that was recycled before the commit hook ran, loses nothing that was stored.

Results: `queued` (accepted), `duplicate`, `dropped` (over the rate or backlog), `disabled` (the module is disabled, or its state could not be
read by the publish's own five second module-enabled check), `error` (the handle is not a registered publisher, the caller is not the module that owns the job, the caller could not be verified (the module list or state could not be read while the caller was checked), the key or payload was refused, or something failed; the reason never holds a payload
value).

Inside an open transaction the answer is `queued` before the row exists, because the row is stored when the transaction commits. A duplicate
found at that point is counted in the statistics and is not reported to the caller. Outside a transaction the answer is exact.

### Run (in the worker)

`tec_tac.execute_event_job` receives the row id. It claims the row under a lock (`pending` to `running`, attempt plus one), so a duplicate
delivery or a redelivery after a worker loss runs nothing twice. Before it calls the handler it checks again, with no cache:

1. the job has not expired, otherwise the row ends `expired`;
2. the module is still installed and enabled, otherwise it ends `skipped`;
3. the handler is registered in this worker process, otherwise it ends `skipped`.

Each of those writes an audit row, and the handler is never called.

The handler receives an `EventJobContext`: a dict with `job_id`, `module_id`, `key`, `payload` (a copy), `attempt`, `max_attempts`,
`final_attempt`, `enqueued_at` and `run_id`. It has no user fields. `verify_event_job_context(context, expected_module_id=..., expected_job_id=...)`
returns a `VerifiedEventJob` for a context Core issued for this module and job while it runs, and raises `EventJobContextInvalid` for a plain
dict, a copy, another module's or job's context, or a job that has finished. It is the same shape as the Scheduler's `verify_run_context`.

After a failure Core retries: the row returns to `pending` with `next_attempt_at` set to now plus the back-off (plus up to 20 percent jitter),
and Core sends the message with that countdown. After the last attempt, or at once for a permanent error, the row ends `failed`.

### The Scheduler tick

Every minute `dispatch_due_schedules` calls `recover_event_jobs(now)` after `recover_stale_runs`, in its own `try` block, so a fault there never
stops a schedule. The work is bounded to 200 rows a step:

- pending rows past their expiry, and those of a module the tick has confirmed disabled or uninstalled, end `expired` (one audit row per job, with the count); if the module state or the module list cannot be read, the rows stay pending, `module_state_unread` counts the module, and the next tick tries again;
- a running row older than its hard time limit plus 5 minutes is a failed attempt (retry or give up);
- a pending row never sent, or whose `next_attempt_at` passed more than 60 seconds ago, is sent again;
- a backlog over `max_backlog` is trimmed, oldest first, and counted as dropped;
- the backlog gauges are refreshed, this process's counters and any buffered refusal counts are flushed, and one audit row is written per job that dropped, and one per job and clock hour for publishes refused because the caller was not the owner (`custom:event-job-refused`, written after the hour ends);
- finished rows older than the Scheduler's `run_retention_days` are removed, with a hard cap of 20000 finished rows.

## Audit

Core writes the rows, as the service actor `service_audit_actor(module_id="core", service="event-jobs", identity="<job id>")`, with object type
`event_job`, and metadata `owner_module`, `job_id`, `key`, `attempt`, `error_type`, `error` (one line, 200 characters) and
`requested_by: "event-job"`. Never the payload. Never a secret.

| When | Action |
|---|---|
| gave up after the last attempt, or a permanent error | `custom:event-job-failed` |
| skipped by the module or handler check | `custom:event-job-skipped` |
| expired before it started | `custom:event-job-expired` |
| publishes dropped at the gate, or rows trimmed (one row per job per tick, with a count) | `custom:event-job-dropped` |
| publishes refused because the caller was not the module that owns the job (1.17.48: one row per module and job per clock hour, after the hour ends, with the count) | `custom:event-job-refused` |
| a success, only when the job registered `audit_success=True` | `run` |

A retry is recorded on the job row and in the counters, not as an audit row.

The refused row holds `owner_module`, `job_id`, `count`, `window_seconds` (3600) and `hour_start` (ISO time), and never a key or a payload. It
appears once, in the tick after the hour ends (a tick that missed an hour reports it the next time, up to two hours back), so the immediate
signal stays the warning in the log. Where the count is held (1.17.49): the publish only adds one to a small buffer in the web process's memory
(at most 256 keys, never a key or a payload) and makes no Redis, database or network call for it. At most once a minute per process, the buffer goes
to Core's own Celery worker in one bounded broker message (2 second timeout, the publish's circuit breaker, at most 64 entries of module id, job id,
hour and count), also from the Scheduler tick's counter flush, so counts do not wait for the next refusal. If the broker is down the entries stay in
the buffer and the next minute tries again. The worker task `tec_tac.note_event_job_refusals` checks every entry (known job, an hour in the last 3
hours, an integer count clamped to 1..100000) and adds it to Django's shared cache (Redis on a Tactical server). It is Core-internal, not a module
contract. There is no database column and no migration. The limits, stated plainly: a cache flush, a restart or a cache fault loses that hour's
count (a count is a count, not proof); a process that stops publishing can hold up to one minute of counts unsent; a failed audit write is
retried on the next tick within the two hour look-back. The tick reads only the shared cache and the in-memory buffer is never read, so with a
per-process cache (local development) the tick only sees its own process's tally. A caller that could not be verified (the module list or state could
not be read) is not a refusal and writes no row.

## Reading the state

- `publisher.status()` returns the job's own counts, backlog, oldest pending age and last failure. Never a key or a payload.
- `scheduler_health()` (and `GET /api/tfd/scheduler/health/`) gains an additive `event_jobs` block: `registered`, `pending`, `running`,
  `failed_last_24h`, `dropped_last_24h`, `oldest_pending_age_seconds`. `dropped_last_24h` counts the drops in the current 24 hour window.
- `GET /api/tfd/scheduler/event-jobs/` lists every known job with its counts and last error, and Core's limits. It needs the same authority as
  `scheduler/health/` (server maintenance) and never returns a payload, a key or a row id.

## What an event job cannot do

The job runs as the module, not as a person. The context has no user, and a handler cannot call `run_tactical_operation`, because that needs a
signed-in person's request. So an event job cannot make a Tactical change. That stays the job of the AD-13 system-action contract, which is
still open. Nothing runs at a person's authority and no permission check passes through a person.

## Security review points

1. **One module cannot publish for another.** Only the handle that `register_event_job` returned can publish, and the handle cannot be built,
   copied or pickled. Registration binds the job to its module: `module_id` must be an installed, enabled extension read from the registry, the
   id must start with that module's id, and the handler's code file must lie inside that module's folder (a real-path check, as
   `caller_identity` does). A module cannot register under another module's id or point an id at code that is not its own.
2. **The usual hostile import.** A module that imports another module's private code can reach that module's handler or handle. That is the
   case rule 3.4 (signed-module review) already covers for every contract. Since Core 1.17.47 (AD-36) every publish also verifies its caller with
   `calling_module_for_core_provider`: the first frame above `publish` must be the code of the enabled, non-legacy module that owns the job.
   Another module, a Core frame (the Scheduler, a `functools.partial`), a library or generated frame, a disabled or legacy module and any
   error give `error` ('the caller is not the module that owns this job'): nothing is stored or counted, and nothing is raised. The check
   runs in `publish` itself, never in the commit hook. Core logs one warning per job and refused caller a minute at most, and (1.17.48, CQ138) counts each refusal of a foreign caller in memory for the hourly `custom:event-job-refused` audit row (see Audit). The count reaches the worker in bulk, at most one bounded broker message a minute per process; the publish makes no Redis call. A check that fails because the module list or the module state cannot be read is not a refusal: the publish answers `error` 'the caller could not be verified', stores nothing, writes no row and is lost (nothing is stored to retry); that fault is kept for 1 second, so the next publish after about 1 second is checked again. The residual case: a module that makes another module's own code frame call `publish` (a hook
   list or signal that other modules can make it run), the callback-surface limit already listed in `docs/caller-identity.md`.
   *Cost.* The module list and each enabled flag are read through a snapshot kept for 5 seconds (the same window as the module-enabled
   cache), so a Tactical alert save does a stack walk and no disk read (the real path of each file name is kept in the snapshot too, because `realpath` is a system call per path part). On the development PC with stub reads the check adds about 20 microseconds per publish on a warm snapshot; the real-disk cost is read on the dev server with `tests/event-jobs-caller-runtime-1.17.47.py`. A module disabled in the last 5 seconds is still recognised as a caller
   for up to 5 seconds (the publish already tolerates this through the module-enabled cache, and the worker re-checks the module uncached
   before any handler runs, so nothing runs for a disabled module). A module installed in the last 5 seconds is refused until the snapshot
   expires, which fails closed. A failed read of the module list or of a module's state (a corrupt state counts as a failed read) is kept for 1 second only, not the window, and refuses meanwhile ('the caller could not be verified'). A good read keeps the 5 second window.
3. **At least once.** A handler can run twice (a redelivery after a worker loss, a retry after a timeout) and must be safe to repeat.
4. **The payload is data.** Size-capped (2 KiB), JSON only, ids and not text bodies. It is never logged, audited, listed or returned by a status route.
5. **Exception text may reach the audit row**, cut to one line of 200 characters. A handler keeps secrets out of its exception messages.
6. **A disabled or uninstalled module's jobs never run.** The worker checks the module itself, with no cache, and the tick expires its pending rows once it has confirmed the module is disabled or uninstalled (an unreadable state leaves them pending until they expire on their own, and a worker that cannot read the state keeps the row it holds: it answers `job deferred`, runs no handler, uses no attempt and is tried again by the first Scheduler tick more than 60 seconds later, so after one to two minutes; Core 1.17.46 said 60 seconds).
7. **Bounded cost.** Core caps the backlog, the rate, the expiry, the attempts, the time limits and the payload, so a signal storm cannot grow without limit.
8. **Tactical always starts.** Registration and the capability registration are guarded. A refusal is an exception the module catches.
9. **The worker trusts nothing from publish time.** It re-reads the module state, the registration and the expiry itself.

## Limits Core keeps

Soft time limit 5 to 600 seconds (hard 15 more), 1 to 10 attempts, back-off 5 to 3600 seconds up to 3600, expiry 60 to 86400 seconds, backlog 1
to 5000 pending rows per job, payload 2 KiB, key 128 characters, 600 publishes a minute per job per process, 200 rows per tick step, finished
rows kept for the Scheduler's `run_retention_days` with a hard cap of 20000.

## Compatibility

A pure addition. No existing contract, task, table, route or capability changes. From Core 1.17.47 (capability 1.1.0) every publish verifies its caller: a module that publishes from its own code (a signal receiver, a view) is unaffected, and one that makes another module's handle publish gets `error`. Alerts 0.10.0 publishes from its own code and needs no change. Set `requires.framework` to `>=1.17.47` to be sure the check exists. The tick change is additive and isolated; scheduled actions,
one-off runs and notices are untouched. A module that adopts this sets `requires.framework` to `>=1.17.45` and feature-detects with
`has_capability("core.event_jobs")`.

## Tests

`tests/event-jobs-caller-1.17.47.py` (the caller check with real compiled frames, the snapshot with a fake clock, the deferred retry timing, the measured cost), `tests/event-jobs-policy-1.17.45.py` (the decisions, no Django), `tests/event-jobs-1.17.45.py` (the registry, publish, worker, tick, health and route
against stubs), `tests/event-jobs-contract-1.17.45.py` (the contract rows, the migration against the models, the source pins).

`tests/event-jobs-runtime-1.17.45.py` is a script for the dev server (`manage.py shell`): a real publish, a real worker run, a kill and recover,
and a recycled worker. Django, PostgreSQL and Celery do not run on the development PC, so the migration, the partial unique constraint, the row
locks, the commit hook, the statement timeout and the Celery task are checked there. `tests/event-jobs-caller-runtime-1.17.47.py` is the matching probe: it times the real module scan and state read and publishes once from a real module frame.
