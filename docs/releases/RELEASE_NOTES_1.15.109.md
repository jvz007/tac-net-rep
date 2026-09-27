# Tec-Tac Core 1.15.109

## Fixed

- **M11 — Scheduler stale-run overlap protection**
  - stale RUNNING Scheduler executions now request termination of their stored Celery task before Core releases the run from RUNNING state;
  - a failed revoke request leaves the run RUNNING so `SKIP` concurrency cannot immediately launch an overlapping replacement;
  - Scheduler dispatch now sends an action-specific Celery hard `time_limit` equal to the declared action timeout plus the existing five-minute stale grace;
  - the Scheduler Celery task keeps a framework-wide maximum hard time limit as a second backstop.

## Regression coverage

- Added `tests/scheduler-stale-revocation.py` for stale task revocation, failed-revoke concurrency preservation, and hard time-limit dispatch behavior.
- Existing Scheduler durability/foundation, interval, target, scope, pagination and Session-retention Scheduler regressions remain green.
