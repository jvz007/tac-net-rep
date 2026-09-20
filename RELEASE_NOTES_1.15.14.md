# Tec-Tac Framework 1.15.14

## Core Scheduler interval policy and reconciliation

- Added `interval` as a Core-owned schedule type with a minimum supported interval of 60 seconds.
- Added `interval_seconds` and stable `interval_anchor_at`; due/next occurrences are calculated as `anchor + N * interval_seconds` and do not drift with handler completion time.
- Interval schedules use the existing once-per-minute scheduler tick, concurrency policy, retry policy, missed-run handling, diagnostics, durable run history and duplicate-occurrence protection.
- Added module-owned schedule identity through `owner_module` + `owner_key` with a database uniqueness constraint.
- Added public backend APIs `reconcile_schedule()`, `disable_owned_schedule()` and `remove_owned_schedule()` so modules do not need direct `TecTacSchedule` imports or localhost HTTP calls.
- Reconciliation is idempotent, keeps the original interval anchor unless explicitly replaced, and rejects attempts to reconcile an action owned by a different module.
- Updated scheduler developer documentation and the live public contract catalog for interval/reconciliation usage, including the Checks policy use case.
