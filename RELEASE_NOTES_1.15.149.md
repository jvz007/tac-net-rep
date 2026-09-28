# Tec-Tac Core 1.15.149

## Scheduler target and revision closure

- Added behavioral dispatch coverage proving that an occurrence from before the current schedule revision is consumed before missed/grace evaluation. It is neither queued nor recorded as a synthetic missed run.
- Updated migration 0015 so fresh installations resolve endpoint database PK aliases to the canonical Tactical `agent_id` identity while canonicalising saved Scheduler targets.
- Added migration 0019 for already-upgraded installations. Existing static and dynamic endpoint schedules are rewritten to canonical `agent_id` values; ambiguous or unknown endpoint references fail closed by disabling the affected schedule for administrator review.
- Scheduler run-history snapshots remain immutable and are not rewritten by either migration.
- Added `tests/scheduler-closure-1.15.149.py` and wired it into the normal Scheduler foundation.

## Review items

Closes L19, L24, and L25 from the Core/UI review tracker.
