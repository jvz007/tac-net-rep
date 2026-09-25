# Tec-Tac Framework 1.15.48

## Scheduler durability and recovery

- Recovers stale queued runs after the configured dispatch window and stale running runs after the registered action timeout plus recovery grace.
- Scheduled actions may declare `timeout_seconds` (default 3600 seconds).
- Celery execution claims a run under a row lock and only executes `QUEUED` runs, making duplicate delivery idempotent.
- Run execution uses durable schedule snapshots for target mode, parameters and retry policy, so a deleted schedule cannot crash an already queued task.
- Broker dispatch failure is isolated to the affected run and no longer aborts the entire scheduler tick.
- Scheduler lateness has a three-minute tolerance. Missed occurrences are retained as `SKIPPED` history rows with explicit reasons (`MissedSkip`, `MissedExpired`, or `MissedRecoveryWindowExpired`).
- `MissedPolicy.EXPIRE` now has explicit runtime/history semantics.
- User schedule deletion uses row locking. A `force=true` delete marks active runs `FAILED / ForceDeleted` before deleting the definition.
- Scheduler run history now has configurable terminal-run retention (default 90 days), preventing unbounded history growth.
- Schedule list serialization uses a latest-status subquery instead of one run query per schedule.
- Added owner-or-manager enforcement for modifying, deleting or manually running user-owned schedules.

## Database

Migration `0013_scheduler_durability` adds durable run snapshots plus scheduler retention/stale-dispatch configuration. Existing runs with a live schedule are backfilled.
