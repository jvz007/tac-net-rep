# FIXING.md — Core 1.15.109

## Review scope

This release is intentionally scoped to **M11** from Claude's Core tracker.

### M11 — stop stale RUNNING Celery tasks before releasing Scheduler concurrency

Problem being fixed:
- a Scheduler run could be marked stale/FAILED in Core while the underlying Celery task continued executing;
- a `SKIP` schedule could then see no RUNNING row and dispatch a replacement, causing overlapping execution.

Expected behavior in this release:
1. A stale RUNNING row with a Celery task id requests `app.control.revoke(task_id, terminate=True, signal="SIGTERM")` before Core marks the run FAILED.
2. If the revoke request itself fails, the row remains RUNNING so `SKIP` continues to block a replacement and a later recovery tick retries.
3. Scheduler dispatch uses an action-specific hard Celery `time_limit` equal to the declared action timeout plus the existing five-minute stale grace.
4. `execute_schedule_run` also has a framework-level hard ceiling of 605100 seconds as a second worker-side backstop.
5. Existing retry, stale-queue, interval, target-scope and Session-retention behavior must remain unchanged.

## Behavioral regression

`tests/scheduler-stale-revocation.py` exercises the real `recover_stale_runs()` and `_queue_run()` function bodies and verifies:
- exact Celery task id is revoked with termination;
- failed revoke keeps the run RUNNING;
- successful revoke permits stale transition to FAILED;
- dispatch passes the expected action-specific hard time limit;
- the task declaration retains the framework maximum ceiling.

## Explicitly out of scope

No other Medium or Low tracker item is intentionally changed in this release. In particular, M12+ remain open.
