# Tec-Tac Framework 1.17.49

One change, in two parts. A refused event-job publish no longer calls Redis while it answers a request. The hourly refusal report now survives a failed audit
write. Both close the two held findings of the 1.17.48 review (`core-1.17.48-20261016-202439`).

## Module-facing changes

These touch `core.event_jobs`, which only Alerts uses. Nothing a module calls changes.

- **No capability bump.** `core.event_jobs` stays 1.1.0 and `requires_framework` stays `>=1.17.47`.
- `publish` answers, reasons and outcomes are unchanged. The outcomes list is unchanged. A publish refused for a foreign caller still answers `error` with
  'the caller is not the module that owns this job' and stores nothing.
- The contract row text for `EventJobPublisher` and the capability's `caller` text changed. They now say where a refusal is counted. This is wording only.
- **Alerts needs no change.** Alerts 0.10.x reads only the outcome (checked in `modules/alerts`).
- The new Celery task `tec_tac.note_event_job_refusals` is Core-internal. It is not a module contract, and no module may call it.

## What changed and why

### A refused publish makes no Redis call (held Medium, Johan CQ143, assumption a)

In 1.17.48 a refused publish called `cache.add` and `cache.incr` on Django's shared cache. Tactical's Redis settings have no timeout, so a slow Redis could
hold a web request for as long as it liked. The wording 'no network call except one bounded broker publish' was no longer true.

The publish now only adds one to a small buffer in the web process's memory.

- The buffer is locked and holds at most 256 keys. A key is an owner module id, a job id and a clock hour. It never holds a publish key or a payload. When it
  is full, it is cleared. Adding to it makes no cache, database or network call, and never raises.
- At most once a minute per process (`REFUSAL_FLUSH_SECONDS = 60`), the buffer goes to Core's own worker in **one bounded broker message**. It uses the same
  mechanics as the publish's own message: 2 second connect and socket timeouts, no retry, the shared circuit breaker, no result. A message holds at most 64
  entries of `[module id, job id, hour, count]`. Scalars only.
- The flush runs from the refusal path when the minute has passed. It also runs from `flush_counters` (the Scheduler tick's counter flush), never inside an open
  transaction. So a count does not wait for the next refusal.
- If the breaker is open or the send fails, the entries go back into the buffer (still bounded) and the next minute tries again.
- The new task `tec_tac.note_event_job_refusals` runs in the Celery worker. It checks every entry: the job must be known, the hour must be within the last 3
  hours, and the count must be an integer, clamped to 1..100000. A list longer than 64 entries is ignored whole. It then does `cache.add` and
  `cache.incr(count)` on the shared cache. A cache fault is logged and that count is lost. The task never raises.

### The hourly report no longer reads a local fallback, and a failed write is retried (held Low)

- The process-local fallback is gone (`_local_refusals`, `_local_reported`). It only ever helped one process and never reached the Celery tick, so it made the
  1.17.48 test pass for a case production cannot reach. The tick now reads the shared cache only. The in-memory buffer is a send buffer and the tick never reads it.
- The tick still takes the atomic claim first (`cache.add`), so two ticks never write the same row. `_audit` now answers `True` only when `audit.record`
  returned without raising. When the write fails, the tick releases the claim (best effort), and the next tick writes the row. The loop already reads the two hours
  before the current one, and the cache entry lives 3 hours.
- A failed claim read (the cache raises) skips the hour and logs. It never falls back to a local claim.

## Limits, in plain words

- A cache flush, a Redis restart or a cache fault loses a count. A count is a count, not proof (CQ141).
- A process that stops publishing can hold up to one minute of counts unsent. Its last send happened up to a minute earlier, so a few counts at the very end can be missing.
- A failed audit write is retried on the next tick, within the two hour look-back. After that the hour is out of reach.
- With a per-process cache (local development) the tick sees only its own process's tally. A production Tactical server uses the shared Redis cache.
- The new internal task needs the Celery worker to restart. The update already restarts it. Until it has restarted, a message for the new task goes unhandled and that count is lost.
- No migration, no new table, no new column (CQ141 option b is not taken).

## Requests closed

- The two held findings of the 1.17.48 review: 'a refused event-job publish makes unbounded Redis calls on the request path' and 'the local fallback tally never
  reaches the Celery tick; the claim is taken before the audit write'. The release manager removes both lines from `reviews/core/BACKLOG-new-findings.md` and adds the 1.17.49 line to `reviews/requests/core.md` after signing.

## Tests

- `tests/event-jobs-refusal-bound-1.17.49.py` (new): with a cache that fails loudly if touched, 50 refused publishes make 0 cache calls and finish in well under
  half a second; refusals inside one window cause one send with the summed count, a refusal after the window a second send, two jobs two entries in one message; a
  failed send or open breaker keeps the entries and the next window re-sends them; the worker task applies valid entries and ignores bad ones, and a raising cache
  is swallowed; `flush_counters` sends a pending buffer, once a minute, never inside a transaction; unverifiable callers and the owner add nothing; a failed
  audit write releases the claim and the next tick writes exactly one row; a failing release, back-to-back ticks and a raising cache in the tick behave.
- `tests/event-jobs-refusal-audit-1.17.48.py` (adapted): counts now reach the cache through the buffer, one send and the worker function; the 'raising cache
  falls back to the local tally' step is replaced by 'a raising cache never breaks the publish and that hour's count is lost'.
- Re-run and passing: `tests/event-jobs-caller-1.17.47.py`, `event-jobs-deferred-1.17.47.py`, `event-jobs-contract-1.17.45.py`, `event-jobs-module-gate-1.17.46.py`.

What could not run on this PC: Django, Redis, Celery and PostgreSQL are not installed. The new task, the real shared cache and the real broker ran only through stubs.

Johan: after the update, restart the Celery worker (the update does this), then repeat the 1.17.48 check on the dev server. Refuse a few publishes from the Django shell, wait for the
next clock hour and one Scheduler tick, and expect one `custom:event-job-refused` row with the count. Export a fresh public contract into `docs/contracts`.

Earlier notes are in `docs/releases/`.
