# Tec-Tac Core 1.15.110

## Fixed

- **M12 — Scheduler run-now target canonicalisation**
  - manual Scheduler runs now canonicalise saved targets before scope authorization and queueing;
  - canonical targets are persisted before a run snapshot is created;
  - invalid saved target shapes disable the schedule, mark target state invalid and return HTTP 400 without queueing a run;
  - already-canonical targets are not rewritten unnecessarily.

## Regression coverage

- Added `tests/scheduler-run-now-canonicalization.py` covering legacy dynamic aliases, canonical no-op behavior and invalid-target quarantine.
- Existing Scheduler durability, interval, scope, pagination, stale Celery revocation/time-limit and Session-retention regressions remain green.
