# Tec-Tac Scheduler

Framework 1.8.0 adds a framework-owned scheduling service for Tec-Tac modules.

## Design principle

Modules define **what** can run. The Tec-Tac framework owns **when** it runs, how it is queued, retry/concurrency policy, and execution history.

The scheduler is server-side. A user is required to create, edit, delete, enable/disable, or manually run a schedule, but a saved schedule does **not** depend on an interactive Tec-Tac login or an open browser. Once saved, scheduled execution is performed by the Tec-Tac system scheduler and Tactical's Celery worker.

```text
Tec-Tac UI / API
      |
      | create or modify schedule
      v
TecTacSchedule database record
      |
      | unattended evaluation
      v
tec-tac-scheduler.timer
      |
      v
tec_tac_scheduler_tick
      |
      v
Tactical Celery
      |
      v
registered module action
      |
      v
TecTacScheduleRun history
```

The unattended path was validated on Framework 1.8.0 using the built-in `tec-tac.scheduler-test` action: both **Run now** and a true scheduled-time execution produced run-history entries successfully.

## Runtime

`tec-tac-scheduler.timer` evaluates due schedules every minute. Due runs are dispatched into Tactical's existing Celery worker through `tec_tac.execute_schedule_run`. Tec-Tac does not modify Tactical tracked source files to provide scheduling.

The framework installer creates/enables the timer and verifies that the Celery task is registered.

## Schedule types

The current framework supports:

- Once
- Daily
- Weekly
- Monthly
- Interval

Each schedule stores an IANA timezone such as `Africa/Johannesburg`.

One-time schedules use `run_at`. Calendar-recurring schedules use `run_time`; weekly schedules also use `weekdays` (`0` = Monday through `6` = Sunday), and monthly schedules use `day_of_month`. Interval schedules use `interval_seconds` plus a stable `interval_anchor_at`.

## Targets

Each schedule has a `target_mode` and a JSON `targets` object.

`target_mode` can be:

- `snapshot` — the schedule stores the concrete target selection that should be used.
- `dynamic` — the module may treat the target definition as a query/scope definition that is resolved by the module handler at execution time.

The framework validates the top-level target type against the action's declared `target_types`. The module handler remains responsible for resolving and validating module-specific target details.

Example:

```json
{
  "type": "site",
  "ids": ["site-123"]
}
```

## Parameters

Action-specific input is stored in the schedule's JSON `parameters` object. The framework carries this object to the action handler unchanged. The module owns validation and interpretation of its own parameters.

Example:

```json
{
  "message": "Maintenance begins at 20:00",
  "severity": "information"
}
```

## Missed-run policy

The scheduler owns missed-run behaviour.

- `skip` — do not execute an occurrence that was missed.
- `run_on_recovery` — execute a missed occurrence when the scheduler next evaluates it, subject to `missed_grace_minutes`.

A grace value of `0` means no grace limit for `run_on_recovery`.

## Concurrency

Framework 1.8.0 supports the scheduler's concurrency policy on schedule records. The current production path uses `skip` to prevent a new due occurrence from starting while an earlier run for the same schedule is still queued/running.

When skipped for concurrency, a durable `TecTacScheduleRun` row is written with a `ConcurrencySkip` reason.

## Retries

A schedule can define:

- `retry_count` — maximum Celery retries after the initial attempt.
- `retry_delay_seconds` — delay before each retry.

The same run record is updated across retry attempts and records the current attempt number and final result/error.

## Execution history

Every execution is represented by `TecTacScheduleRun` and records, where applicable:

- schedule ID
- scheduled time
- manual vs scheduled execution
- target snapshot
- status (`queued`, `running`, `succeeded`, `failed`, `skipped`)
- attempt number
- Celery task ID
- result JSON
- error and error type
- created/start/finish timestamps

This history is durable and independent of the browser session that originally created the schedule.

## Authentication and RBAC

Scheduler API endpoints require an authenticated Tactical session.

A user may manage an action when either:

- the user/effective Tactical role has server-maintenance/superuser scheduler management authority; or
- the action declares an extension permission and the user's effective Tec-Tac extension permissions include it.

The framework checks this when schedules are listed/created/edited/deleted or manually executed.

Scheduled execution itself is a **system execution**. It does not replay the creator's browser token and does not require the creator to be logged in at execution time. Creator/updater identity remains stored on the schedule for audit.

## Built-in validation action

Framework 1.8.0 registers:

```text
tec-tac.scheduler-test
```

It is a harmless action intended only to validate the framework scheduler, Celery dispatch, and history path before modules register production actions.

Example parameters:

```json
{
  "message": "Scheduler is working"
}
```

## API

- `GET /api/tfd/scheduler/actions/`
- `GET|POST /api/tfd/scheduler/schedules/`
- `GET|PATCH|DELETE /api/tfd/scheduler/schedules/<id>/`
- `POST /api/tfd/scheduler/schedules/<id>/run/`
- `GET /api/tfd/scheduler/runs/`

## Module developers

Do not build a second scheduler inside an extension. Register the module's schedulable actions with the framework and let Tec-Tac own schedule definitions and execution lifecycle.

See [`module-scheduling.md`](module-scheduling.md) for the module integration contract and examples for Communicator and Patch Management.


## Scheduler hardening in Framework 1.11.0

- Completed or expired one-off schedule definitions are cleaned automatically after the configured retention period. The default is 48 hours and operators may configure 1-720 hours from the Scheduler configuration surface. Run history is preserved independently of the schedule definition.
- Scheduler diagnostics expose tick freshness, queue/dispatch state, enabled schedule count, queued/running runs and recent failures.
- Framework self-tests cover immediate dispatch, true scheduled execution, deliberate permanent failure and retry/recovery.
- Permanent failures must not be blindly retried. Module handlers may raise `SchedulerPermanentError` or `SchedulerTransientError`; capability unavailable/version mismatch/disabled and validation-style failures are treated as permanent.
- A handler must only report success after its owned downstream operation has completed successfully. Transport acknowledgement alone is not business-operation success.

## Interval schedules and backend reconciliation (Framework 1.15.14)

Framework 1.15.14 adds the `interval` schedule type for recurring module policy work such as Checks.

An interval schedule stores:

- `interval_seconds` — integer interval, minimum `60` seconds;
- `interval_anchor_at` — stable UTC-capable anchor used to derive every occurrence.

The system timer still evaluates schedules once per minute. Sub-60-second intervals are rejected. Interval timing is deterministic and does not drift with handler duration:

```text
occurrence(N) = interval_anchor_at + N * interval_seconds
```

`latest_occurrence()` selects the latest occurrence at or before the current scheduler tick. `next_occurrence()` returns the first occurrence at or after the requested point. The normal `last_due_key`, concurrency, missed-run, retry, diagnostics, Celery dispatch and `TecTacScheduleRun` history paths are reused unchanged.

### Module-owned reconciliation

Backend modules that own generated schedules must not import `TecTacSchedule`, write scheduler tables directly, or call the local HTTP API. Use the public Python contract from `tec_tac.scheduler`:

```python
from tec_tac.scheduler import reconcile_schedule

schedule = reconcile_schedule(
    owner_module="checks",
    owner_key=f"provider-check:{check.uuid}",
    name=f"Check · {check.name}",
    action_id="checks.provider-run",
    schedule_type="interval",
    interval_seconds=300,
    targets={"type": "none"},
    parameters={"check_id": str(check.uuid)},
    enabled=True,
)
```

`(owner_module, owner_key)` is unique for non-empty owner keys. Repeating the same reconciliation updates the existing schedule. Changing `interval_seconds` retains the existing interval anchor unless the caller explicitly supplies a new `interval_anchor_at`, preventing timing drift and duplicate schedule creation.

When a generated schedule should be disabled, modules may either reconcile the same definition with `enabled=False`, or use:

```python
from tec_tac.scheduler import disable_owned_schedule

disable_owned_schedule(
    owner_module="checks",
    owner_key=f"provider-check:{check.uuid}",
)
```

To remove an owned schedule definition entirely when no run is queued/running:

```python
from tec_tac.scheduler import remove_owned_schedule

remove_owned_schedule(
    owner_module="checks",
    owner_key=f"provider-check:{check.uuid}",
)
```

The owning module must match the registered action's `module_id`; a module cannot reconcile another module's scheduled action. These APIs are server-side framework APIs and intentionally do not depend on browser authentication.
