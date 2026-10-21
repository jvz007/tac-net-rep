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

`tec-tac-scheduler.timer` evaluates due schedules every minute. Due runs are dispatched into Tactical's existing Celery worker through `tec_tac.execute_schedule_run`. The same tick also invokes Core-owned periodic maintenance that is due, including Session Security history retention. Session retention itself is limited to one successful run per 24 hours using a persisted Core timestamp; a failed cleanup is retried on the next tick. Tec-Tac does not modify Tactical tracked source files to provide scheduling.

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
- the action declares a permission and the user holds it. Since 1.17.17 the permission is a Tec-Tac extension permission, a Tactical role flag, or a list of those (any-of).

An action's `permission` takes these forms:

| Form | Meaning |
|---|---|
| `"patching.run"` | A Tec-Tac extension permission (the form before 1.17.17). |
| `"tactical:can_manage_winupdates"` | A Tactical role flag. The user holds it the way Tactical's own `_has_perm` reads it: a Django superuser or role superuser has every flag, a Tactical installer user and a user with no role have none. |
| `["patching.run", "tactical:can_manage_winupdates"]` (or a tuple) | **any-of**: the user needs one entry. Tec-Tac codes and `tactical:` flags may be mixed. One to 8 entries, no duplicates, each a non-empty string. A list of one entry reads as that entry. |
| `None` | Native scheduler managers only. |

Registration checks the shape only (`tactical:` must be followed by `can_` and lowercase letters, digits or underscore) and raises `SchedulerError` for a bad shape. A flag or code that does not exist is caught when the action is used: nobody but a scheduler manager passes, and Core logs it (fail closed). An error on one entry never blocks the next. `GET /api/tfd/scheduler/actions/` shows `permission` (the single entry, or the entries joined with ` | `) and `permission_any` (the list, empty for a single entry). Requires framework >=1.17.17. This adds no Tec-Tac permission.

The framework checks this when schedules are listed/created/edited/deleted or manually executed. Deleting a schedule re-checks the action permission at deletion time; ownership alone is not sufficient.

Targets that do not carry a Tactical client/site/endpoint scope (`none` and module-defined target types) require unrestricted Tactical client/site scope unless the caller has native Scheduler manager authority. Core cannot prove a narrower Tactical scope for those target shapes, so restricted operators must use explicitly scoped target types.

A forced delete that fails active queued/running rows is transaction-audited before the schedule is removed. If the strict Core audit write fails, the force-delete transaction fails rather than leaving unaudited run mutations.

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

## Built-in repository sync (Core 1.17.42)

Core registers `tec-tac.module-repository-sync` (module `tec-tac`, no target, timeout 900 seconds, no per-user permission). Core creates one daily schedule for it, owner `tec-tac` / `module-repository-sync`, at 03:00 in the server's own time zone (Django `TIME_ZONE`, UTC on stock Tactical, so 05:00 in South Africa; the zone is shown on the row), with run-on-recovery within 360 minutes and concurrency skip. The schedule appears on this page like any other, with its run history. It is not edited here: change the repositories instead, see `module-repositories.md` ("Daily sync (1.17.42)").

## API

- `GET /api/tfd/scheduler/actions/`
- `GET|POST /api/tfd/scheduler/schedules/`
- `GET|PATCH|DELETE /api/tfd/scheduler/schedules/<id>/`
- `POST /api/tfd/scheduler/schedules/<id>/run/`
- `POST /api/tfd/scheduler/system-actions/confirmation/` (Core 1.17.66): the plain Yes or No text and a confirmation id for a schedule of a system action (see "System actions" below). For an action that is not a system action it answers `required: false`.
- `GET /api/tfd/scheduler/runs/`
  - paged callers may use `page`, `page_size` (max 100), `owner_type`, `schedule_id`, `status`, and `search`;
  - paged responses include `total`, `page`, `page_size`, `pages`, `next_page`, and `previous_page`;
  - scoped users are counted only after action and Tactical target-scope authorization;
  - the legacy unpaged response remains bounded for compatibility with older consumers.
- `GET /api/tfd/scheduler/schedules/` also takes `created_by=<user name>` and `confirmed_by=<user name>` (Core 1.17.63). The match is exact and not case-sensitive, on the stored creator or confirmer name (a row made before migration 0036 matches its creator row's user name). An unknown name returns an empty list. It needs no new right: it only narrows the list the caller may already see, and the scope and permission filtering is unchanged. Each schedule gains `created_by_username` and `confirmed_by_username`.

## Module developers

Do not build a second scheduler inside an extension. Register the module's schedulable actions with the framework and let Tec-Tac own schedule definitions and execution lifecycle.

See [`module-scheduling.md`](module-scheduling.md) for the module integration contract and examples for Communicator and Patch Management.


## Scheduler hardening in Framework 1.11.0

- Completed or expired one-off schedule definitions are cleaned automatically after the configured retention period. The default is 48 hours and operators may configure 1-720 hours from the Scheduler configuration surface. Run history is preserved independently of the schedule definition.
- Scheduler diagnostics expose tick freshness, queue/dispatch state, enabled schedule count, queued/running runs, recent failures, and `AuthorizationRevoked` skips from the last 24 hours.
  Deleted schedule definitions keep their immutable run snapshot id/name in health output, so retained `AuthorizationRevoked` history remains identifiable after cleanup or deletion.
- Tactical scope follows one rule everywhere: roles with both client and site restrictions empty have full scope; once either relation is populated, saved Scheduler targets are constrained to those explicit grants.
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

#### A schedule a person creates and the module owns (Core 1.17.63, CQ176)

`reconcile_schedule` takes one more keyword-only, optional argument: `confirmed_by_request=None`. Pass the signed-in person's **real request** (a Django or DRF request that went through Core's session check, the same proof `run_tactical_operation` asks for) when that person creates or changes the schedule from your own view. A user id or an object that merely has a `user` is refused (`SchedulerNotAllowed`).

```python
reconcile_schedule(owner_module="patchmanagement", owner_key="nightly-scan", action_id="patchmanagement.scan",
                   schedule_type="daily", run_time=time(2, 0), targets={"type": "client", "ids": [7]},
                   confirmed_by_request=request)
```

With a request, Core checks for that person the action's permission and the Tactical scope of the targets (the same checks as `start_one_off_run`), stores the creator the first time and the confirmer each time, and writes an audit row for the creation (`add`) and for every change (`modify`) naming the person. The module stays the owner and the executor. If the action is flagged `unattended`, a run of this schedule is an unattended scheduled run with that creator.

**Without** a request, a schedule that has a stored creator can only be switched off (`enabled=False`) or left as it is. Any change to its action, targets, parameters, timing or policies, and switching it back on, raises `SchedulerError` and changes nothing. An identical call is a no-op. So a module can never widen or rewire a person's schedule, and it can name only the person who created or confirmed it. A module-owned schedule with no stored creator, and any call without the new keyword on one, behaves exactly as before 1.17.63. `get_owned_schedule` gains the additive key `created_by_username`.


#### The scope a schedule keeps, and ownership (Core 1.17.68, framework >=1.17.68)

A call to `reconcile_schedule(confirmed_by_request=request)` **is an edit by that person**. Core now also stores that person's Tactical client and site scope and role flags on the schedule at that moment (`creation_scope`), so an unattended run reads what the person could reach when they saved it and never their live row (see "Verify a run context", below). If the person is not the stored owner, ownership moves to them after the unchanged checks, with one strict `modify` audit row naming `owner_changed_from`, `owner_changed_to` and `previous_confirmed_by`. Their own scope must cover every target (no shortcut for a scheduler manager), or the call raises `TakeoverRefused` ("You cannot take over this schedule: some of its targets are outside your Tactical scope.") and nothing changes. A call that only switches the schedule off moves nothing. The browser create and edit follow the same rules. A module-owned target type that the module registered a resolver for (`tec_tac.scheduler_target_resolvers.register_target_resolver`) is judged by the endpoints it names. The signature of `reconcile_schedule` is unchanged. Details: `docs/system-actions.md`, "Creation-time scope and ownership".

## Start a one-off run for a user (Core 1.17.16)

A module that needs to run one of its own registered actions once, on behalf of the person who clicked, calls `start_one_off_run`. It is for a manual sync, a bulk scan or an install that should not wait for the ticker.

```python
from tec_tac.scheduler import start_one_off_run, get_one_off_run, SchedulerNotAllowed

run = start_one_off_run(
    user=request.user,
    owner_module="cyberhoot",
    action_id="cyberhoot.sync",
    targets={"type": "client", "ids": [12]},
    parameters={"full": True},
    name="Manual CyberHoot sync",
)
status = get_one_off_run(run.id, owner_module="cyberhoot")  # the serialize_run shape
```

What Core checks, in order:

1. The user is active and not an installer user.
2. The action is registered and `action.module_id == owner_module`. A module starts only its own actions.
3. The targets pass the usual target checks and the action's `target_types`.
4. The user holds the action now (any entry of an any-of permission, a `tactical:` flag included). An action with no permission is startable only by native scheduler managers, the same rule as the browser.
5. The user holds the targets' Tactical scope now.

A failure at 1, 4 or 5 raises `SchedulerNotAllowed`. The others raise `SchedulerError`. If the run cannot be queued, Core removes the schedule it made and raises `SchedulerTransientError`.

What Core creates: one schedule owned by the module with `owner_key` `one-off:<uuid>`, type `once`, `run_at` now, **disabled**, and `created_by` the user. The ticker never dispatches a disabled schedule, so only the queued manual run executes. The Scheduler page shows the schedule as managed by the module and refuses edits. The existing once-retention cleanup removes it (48 hours by default). The run stays in the history. Core then writes one best-effort audit row (`add`, object type `scheduler_run`).

Call it outside a database transaction that has not committed: the worker reads the run as soon as it is queued.

Since 1.17.17 a one-off schedule cannot be run again from the browser. `POST /api/tfd/scheduler/schedules/<id>/run/` refuses it with 403 ("This one-off run is managed by module X and cannot be run again.") before any other check, for every caller including a scheduler manager. The run belongs to the user it was started for, so a second user can never queue a run under that user's identity, and one run cannot be repeated. The `owner_key` prefix `one-off:` is reserved to Core: `reconcile_schedule` raises `SchedulerError` for a key that starts with it, so only `start_one_off_run` can make a one-off schedule. `disable_owned_schedule` and `remove_owned_schedule` are unchanged.

### Retry settings on a one-off run (Core 1.17.18)

`start_one_off_run` takes two keyword-only settings, `retry_count` (a whole number from 0 to 10, default 0) and `retry_delay_seconds` (a whole number from 1 to 86400, default 60). Core stores them on the one-off schedule and copies them onto the run. When your handler raises `SchedulerTransientError`, the worker puts the run back in the queue and waits `retry_delay_seconds` before the next attempt, until `retry_count` retries are used up. Your handler does not need to wait inside the run.

The owner check runs again on every attempt. If the user loses the action, the scope or their account between attempts, the run ends `skipped` and the handler does not run again. A bool, a text, a float or a number out of range raises `SchedulerError` before Core creates anything. A call without the keywords behaves exactly as before 1.17.18. The keywords need framework 1.17.18 or later.

### The owner is re-checked for a run a person starts (AD-13 condition 2)

A run a person starts (a manual run or a one-off run) has that person's authority, and it does not outlive their access. Just before the handler runs, Core checks again that the user is still active, still holds the action (a `tactical:` flag is read from the role again), and still holds the targets' scope. If not, the run ends `skipped` with a plain reason (`error_type` `AuthorizationRevoked`) and an audit row, and the handler never runs. A check that cannot be made counts as a refusal. It never raises into Celery.

**A scheduled run is not re-checked (Core 1.17.65).** Johan signed the amended condition 2 on 20 October 2026. A run the schedule starts on its own is not re-checked against its creator, for every registered action: the right was checked when the person created or edited the schedule, as in Tactical, and Core stores and audits who that was. A module-owned schedule with a stored creator name is exempt only for an action still listed in its module's signed manifest `system_actions` and registered with `core.system_actions`. A manual run and a one-off run are always re-checked. The `unattended=True` keyword of `register_scheduled_action` is still accepted and now has no effect. The plain cost: a person who is demoted or deactivated later keeps their schedules running until someone removes or edits them. Administrators can list schedules by creator (`created_by`). See `docs/system-actions.md` ("Scheduled runs are not re-checked") for what still applies.

### More in the handler context

The context dict gains these keys. Existing handlers that ignore them are unaffected.

| Key | Value |
|---|---|
| `owner_type` | `user` or `module` |
| `owner_module` | the owning module id, or `None` |
| `owner_key` | the ownership key, or `None` |
| `owner_user_id`, `owner_username` | the user the run is for. Set only for a one-off run and for a user-owned schedule. `None` otherwise. |
| `one_off` | `True` for a run from `start_one_off_run` |

A handler that must act inside the owner's scope (Patching reads update rows "under the owner's scope") uses `owner_user_id`.

This is the start-and-track call only. It is not the AD-13 system-action contract (registered Tactical actions running in-process as the owner), which is still open.

## Verify a run context (Core 1.17.19)

Since 1.17.20 the handler also names its own module id and action id (see below).

A Scheduler handler that must act for the person who owns a schedule (Script Manager running a script, Global Settings changing a
setting) needs to know the run is real. Before 1.17.19 any module could build a dict with the same keys. From 1.17.19 Core issues the
handler context itself, and a handler can ask Core to verify it.

```python
from tec_tac.scheduler import SchedulerPermanentError, SchedulerRunContextInvalid, verify_run_context

def handler(context):
    try:
        run = verify_run_context(                    # pass the context object itself, and your own ids
            context, expected_module_id="scriptmanager", expected_action_id="run-script",
        )
    except SchedulerRunContextInvalid as exc:
        raise SchedulerPermanentError(str(exc))
    if not run.has_tactical_permission("can_list_scripts"):   # Script Manager; Global Settings checks its own flag
        raise SchedulerPermanentError("The schedule owner may not do this.")
    rows = read_scripts(run.resource_context())      # a scope-bound read runs as the person
```

`verify_run_context(context, *, expected_module_id, expected_action_id, require_owner=True)` returns a frozen `VerifiedSchedulerRun` (`run_id`, `schedule_id`, `module_id`,
`action_id`, `owner_module`, `owner_key`, `one_off`, `user`, `owner_user_id`, `owner_username`) or raises `SchedulerRunContextInvalid`
(a `SchedulerError`) with a plain message. Core reads the run row again: it must exist and be running. The owner comes from the database
(the schedule's `created_by` for a one-off or user-owned run), never from the dict, so changing `owner_username` in the dict changes
nothing. Core also checks that the owner is active, still holds the action and still holds the target scope.

It fails closed for a plain dict, a copy (`{**context}`, `dict(context)`, `copy.copy`), a JSON, pickle or Celery round-trip, a context a
module builds (including `SchedulerRunContext(...)` called directly), a run that has finished or was deleted, and any lookup error. A run
that belongs to a module with no person behind it is refused unless you pass `require_owner=False`; it then verifies with `user` None.

Since 1.17.20 the handler must also name its own module id and action id. Both keywords are required, so a handler cannot forget them.
Core compares them, exactly, with the module and action of the run it loaded. Why: a context Core issued for module A's action is a real
context. Without this check, module A could hand it to module B's handler, and B would act for A's schedule owner (a confused deputy).
With the ids, that context is refused in B's handler with "This run belongs to another module or action." The message names no ids.
An id that is missing, empty or not a string is refused too; the check is never skipped. A call written the 1.17.19 way, without the ids,
raises `TypeError`. Nothing in `modules/` called it yet. A module that adopts it needs `requires.framework >=1.17.20`.

`run.has_tactical_permission(flag)` reads the owner again on every call (active, then the role flag) and answers False on any error,
a deleted owner or a name that is not a `can_*` flag. `run.resource_context()` gives the owner's Resource Directory context.

Each retry attempt issues a new context for the same run row, and the owner is checked again on every attempt. The context is still a
`dict` with every key it had, so a handler that ignores verification is unchanged.

Since 1.17.68 (framework >=1.17.68) `VerifiedSchedulerRun` also carries the scope the schedule was created with, through four additive reads. For an **unattended** run they use only that stored record, so a disabled or demoted owner changes nothing:

```python
if not run.has_creation_scope:                      # a schedule made before 1.17.68 and not edited since
    raise SchedulerPermanentError("Edit the schedule and save it once.")
if not run.held_at_creation("can_manage_winupdates"):  # the flag the person held when they saved it
    raise SchedulerPermanentError("The person who set this up did not hold the permission.")
endpoints = run.resolved_endpoints()                # [{pk, agent_id, hostname, platform, client_id, site_id}, ...], inside the targets AND the stored scope
```

`resolved_endpoints(*, whole_scope=False, limit=40000)` returns `[]` for a `none` target unless `whole_scope=True`, raises when more than `limit` endpoints are named (nothing is truncated), and raises `SchedulerTransientError` for a read fault. Without a stored record, `held_at_creation` and `resolved_endpoints` raise `CreationScopeUnavailable` (a `SchedulerPermanentError`) for an unattended run. For a run a person started they use that person's live scope, as before. `has_tactical_permission` and `resource_context` are unchanged and still read the owner fresh.

What this does not do. Modules run in the same Python process as Core. This stops a module naming a run or an owner that Core did not issue.
It cannot stop deliberately hostile signed module code; the review of signed modules stays the defence. There is no per-run signed token
(CQ64 a). This is not the AD-13 system-action contract, which is still open.

## Read a module-owned schedule (Core 1.17.16)

```python
from tec_tac.scheduler import get_owned_schedule

info = get_owned_schedule("cyberhoot", "sync")
# {"enabled": True, "schedule_type": "interval", "next_run_at": "...", "last_run_at": "...",
#  "last_run_status": "succeeded", "last_run_finished_at": "..."}  or None
```

`get_owned_schedule` returns `None` when no schedule has that `(owner_module, owner_key)`. `next_run_at` is `None` for a disabled schedule. It takes no user: a module reads only its own tuple, the same trust as `reconcile_schedule`. It does not expose the model.

## Event jobs (Core 1.17.45)

A job a module starts because of an event (a Tactical alert was saved) is not a schedule. It runs through `core.event_jobs` 1.1.0, which the
same tick keeps healthy: `dispatch_due_schedules` calls `recover_event_jobs` after `recover_stale_runs`, in its own `try` block, so a fault there
never stops a schedule. `scheduler_health()` gains an additive `event_jobs` block, and `GET /api/tfd/scheduler/event-jobs/` lists the jobs for
people with server-maintenance authority. See `docs/event-jobs.md`.

## A run that finishes later: pending completion (Core 1.17.61)

A handler that only *starts* something (a server-maintenance job, work in its own job) used to have to wait inside the handler or report success too early. Now it can return a `PendingCompletion`. Core keeps the run `running` until the real result arrives. Nothing changes for a handler that returns a dict or nothing.

```python
from tec_tac.scheduler import pending_completion

def renew_handler(context):
    job_id = start_my_job(context)            # your own job, or a core.server_maintenance job
    return pending_completion("module", job_id, note="Waiting for the renewal job.")
```

- `pending_completion(kind, external_job_id, note=None)` returns a frozen `PendingCompletion`. It is a Core class, not a dict with magic keys, so no existing handler can park a run by accident. A dict with the same keys is an ordinary result. A bad value raises `SchedulerError` when you build it.
- `kind` is `module` (your code completes the run) or `server_maintenance_job` (Core settles the run from the job file). `external_job_id` is 1 to 128 characters of letters, digits and `. _ : -`. For a server job it is the job's lowercase UUID. `note` is optional printable text of 200 characters at most.
- The run stays `running`. The `status` values do not change, so the concurrency skip, once-cleanup and `remove_owned_schedule` keep protecting it. `schedule.last_run_at` is not set and the run is never retried.
- `serialize_run` gains one additive key, `completion`: `null` for a run that never parked, otherwise `{state, kind, since}`. `state` is `pending`, `completed` or `expired`. The Scheduler page can show a pending run as "Waiting for the result".
- A run that waits longer than its action's `timeout_seconds` (7 days at most) fails with error type `CompletionTimeout`. `recover_stale_runs` does this under its normal lock-and-recheck. A completion that arrives later is refused.

### Completing a run (kind `module`)

```python
from tec_tac.scheduler import complete_pending_run

complete_pending_run(run_id, external_job_id=job_id, outcome="succeeded", result={"renewed": 4})
```

`outcome` is `succeeded`, `failed`, `cancelled` or `timed_out`. `failed`, `cancelled` and `timed_out` end the run `failed` with error type `ExternalFailed`, `ExternalCancelled` or `ExternalTimedOut`. A job created, or an acknowledgement, is never success.

Every rule fails closed:

1. **The caller is verified from the call stack** (`docs/caller-identity.md`). It must be the enabled module that owns the run's action, called from that module's own code. Core, library, generated, disabled and legacy frames are refused. `complete_pending_run` is a plain re-export, with no wrapper frame, so do not wrap it in a decorator or call it through a library.
2. **Under a row lock** the run must still be `running` with completion state `pending`, and `external_job_id` must equal the one the handler returned. Call it after the handler has returned. A call before that finds no pending run and is refused as `not_pending`: try again shortly.
3. **Duplicates and conflicts.** The same completion twice is an idempotent no-op: no second audit row, `finished_at` unchanged. A different second outcome (`conflict`), a completion after stale recovery (`late`), a wrong job id (`wrong_job`) and a completion by the wrong module (`wrong_module`, `caller_unverified`) raise `SchedulerCompletionRefused` (a `SchedulerError` with `.reason`). Since 1.17.62 a run that waits for a server-maintenance job is not the module's to complete: the module's call is refused as `wrong_kind` and the run is left as it was (Core settles that run from the job file). Each writes at most one best-effort audit row, `custom:scheduler-completion-refused`, with the reason code only. Rows are limited to one per run and reason per five minutes.
4. **The payload.** `result` is JSON up to 16 KiB (a value that is not an object is wrapped as `{"value": ...}`). `error` is printable text up to 500 characters. `warnings` (for `succeeded` only) are up to 10 printable texts of 200 characters, kept in `result["warnings"]`. A bad payload raises `SchedulerError` and changes nothing.

A completion writes one best-effort audit row, `custom:scheduler-completion`. It carries the outcome and the calling module, never the result text.

### Waiting for a server-maintenance job (kind `server_maintenance_job`)

Start the job with `source_module` and `source_run_id` (the handler context's `run_id`) in the operation context, then return `pending_completion("server_maintenance_job", job["id"])`.

- When the handler returns, Core reads the job file. It fails the run with `PendingRefused` unless the job exists and its context names this module and this run.
- The scheduler tick then runs one guarded step, `settle_server_job_runs()`. It looks at 50 runs a tick at most, runs no module code and never raises. When the job is terminal it settles the run once, under the same row lock: `succeeded` ends the run `succeeded`; `failed` and `dispatch_failed` end it `failed` (`ExternalFailed`); `cancelled` ends it `failed` (`ExternalCancelled`). A job record that stays missing for more than 10 minutes fails the run.
- The run result carries the job id, the status, the exit code and the failure classification. Never output text and never parameters.
- Honest limit: the job context is caller-asserted. The binding stops mistakes and an honest module, not hostile signed code. This is the same limit as `docs/caller-identity.md`.

### What this release does not do

- Before 1.17.62 Core did not run a module's handler when a server job finished. See "Server job finished hook" below.
- The tick does not poll a module for a final state. Completion is pushed by the module, or read from a server job file (CQ177).

### Server job finished hook (Core 1.17.62, R-22 part 2)

A module that starts a server-maintenance job often has to record the outcome when the job ends, even if nobody has a page open. From 1.17.62 the scheduler tick does the waiting for it. The module registers one event job, and Core stores one event for it when its job finishes. No module code runs inside the tick.

```python
# AppConfig.ready()
from tec_tac.event_jobs import register_event_job
from tec_tac.server_job_hooks import hook_job_id

register_event_job(id=hook_job_id("certificatemanagement"), module_id="certificatemanagement", label="Record a finished server job", handler=on_finished)
```

The id is fixed: `<module id>.server_job_finished`, with the module id spelled exactly as the module spells it (`securityWAF.server_job_finished`). Core ties a job to a module through the `owner_module` it wrote in the job file when the job started (the action's `owner_module`, since 1.17.17). There is no new manifest key.

- **One guarded step.** `deliver_finished_server_jobs()` runs after `settle_server_job_runs()`. It has its own try/except, never raises and writes nothing to the tick's output line. It looks at a directory listing, one query for the jobs it already handled, and hands over at most 50 finished jobs a tick, oldest first, reading at most 200 job files to find them (1.17.63; 1.17.62 read at most 50). It reads only job files changed in the last six hours.
- **What the handler gets.** `context["payload"]` is `{job_id, action_id, status, exit_code, classification?}`. `status` is `succeeded`, `failed`, `cancelled` or `dispatch_failed`. Never output text and never parameters.
- **At most once per Core.** Core inserts a row in `TecTacServerJobHook` (unique on the job id) before it stores the event. An event that could not be stored waits in `retry` and the next tick tries again, three tries in all, then it is `abandoned` with one audit row (`custom:server-job-hook-abandoned`). After the event is stored, `core.event_jobs` owns it: its attempts, back-off and expiry apply, so a handler may run more than once.
- **The handler must be idempotent.** A browser poll of `JobView` can record the same job, and the event job can retry. Write the outcome with a key on the job id.
- **A disabled, removed or not-honoured module** gets its job marked `skipped` with one audit row (`custom:server-job-hook-skipped`). Core does not retry it for ever, and enabling the module later does not replay it. A module state Core cannot read leaves the job for the next tick.
- **A module with no hook** is left alone: its jobs are marked `ignored` once.
- **The handler runs as the module, with no user.** It cannot make a Tactical change (AD-13 is unchanged).
- **Honest limits.** The job context and `owner_module` are caller-asserted, the same limit as `docs/caller-identity.md`. A job that finished while Core was off for more than six hours is not handed over. A claim that a tick left half-done for 15 minutes is abandoned and never sent again (at most once wins over exactly once). The module part of an event job id keeps the module id's own spelling (1.17.63, CQ183): a module such as `securityWAF` registers `securityWAF.server_job_finished`. The job part after the dot stays lowercase. Core never folds the case of a module id (`docs/module-identifiers.md`), so `securitywaf.x` and `SecurityWAF.x` do not register for `securityWAF`, and a job file whose owner is spelled differently is not handed to it.
- **Migration.** `0035_server_job_hook` adds one table. Run `manage.py migrate tec_tac` on update.
- **Reads per tick (1.17.63).** At most 50 *finished* jobs are handed over a tick, and at most 200 job files are read (`READ_BUDGET`). A file read as not finished is remembered in memory with its modification time and is not read again until the file changes (a status change rewrites the file), so jobs that are stuck cannot use up the batch and starve a finished job behind them. The memory is per process, holds only files inside the six-hour window and is dropped with them. A file that cannot be read is tried again every tick.

### Diagnostic action

`tec-tac.scheduler-test-pending` (managers only, harmless, timeout 120 seconds) parks a run that no module can complete. The run stays Running, then fails with `CompletionTimeout`. Use it on the dev server.

## System actions (Core 1.17.61)

A module can ask Core to run a fixed piece of Tactical work for a named owner when nobody is signed in, such as a scheduled patch scan. See `docs/system-actions.md`.

**Groups and the summary (Core 1.17.66).** A run of more than 2000 endpoints is split into groups of at most 2000 (up to 20 groups). The run result of a system action gains `groups` (`{total, sent, failed, not_started}`) and a plain `summary` line, such as "4500 endpoint(s) in 3 group(s): 3 sent, 0 failed, 0 not started." A run that fails part way carries the same counts in its error text. Counts only, no endpoint ids.

**Creating or editing (Core 1.17.66).** For a declared system action, `POST` and `PATCH` on `/api/tfd/scheduler/schedules/` need a `confirmation_id` in the body, and Core checks the person's permission, Tactical flags and scope at that moment. Ask `POST /api/tfd/scheduler/system-actions/confirmation/` with `action_id`, `targets`, `parameters` and `when` first, show the returned `text` in the plain Yes/No dialog, and send the id back. A refusal is a 403 with a `reason`. Any other action is unchanged. Details: `docs/system-actions.md` ("Creating or editing a schedule").
