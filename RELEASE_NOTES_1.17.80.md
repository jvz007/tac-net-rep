# Tec-Tac Framework 1.17.80

Date: 27 October 2026. **Security-relevant: please review.** Closes the request "From patchmanagement 0.14.9" (reviews/requests/core.md). No migration, no new route, no new setting.

## What changed and why

A module's own Scheduler action that is not a Tactical function (Advanced Patch Management's `patchmanagement.notice` and `patchmanagement.reboot`) ran with "This run has no person behind it." and sent nothing. Core gave a module-owned schedule its creator only for a declared system action, and these actions have no row in Core's table of Tactical functions.

Now a module can name such an action in its signed manifest under **`scheduler_person_actions`**. For a declared action, a scheduled run verifies with the schedule's stored creator as the person (`user`), with every re-check kept.

## Module-facing change

Additive. Needs framework >=1.17.80.

- Manifest key `scheduler_person_actions`: a JSON list of `<module id>.<name>`, at most 20, extensions only. A manifest with it needs `requires.framework` >=1.17.80.
- The module registers the action with `register_scheduled_action` and creates the schedule with `reconcile_schedule(..., confirmed_by_request=request)`. Nothing else changes in those calls.
- The handler calls `verify_run_context(context, expected_module_id=..., expected_action_id=..., require_owner=True)` as before. It now gets `user` = the creator and `unattended` False.
- Who uses it: Advanced Patch Management lists `patchmanagement.notice` and `patchmanagement.reboot`. Communicator lists the action Core runs for its background worker if that action is its own Scheduler action. A Core system action (`agent.command`) is unchanged and still uses `system_actions`.
- Users checked in `modules/`: Maintenance, Communicator, Remote Background and APM call `verify_run_context` or `reconcile_schedule` with the same arguments as before. None declares the new key, so none changes behaviour.

## Security notes (for Johan)

Core honours an action only when ALL hold:

1. The schedule is module-owned and not a one-off, and the run is a scheduled run (a manual run never gets the creator).
2. The module that registered the action with the Scheduler is the schedule owner, and its signed, installed manifest lists the action.
3. A creator name is stored, so a person confirmed the schedule through `reconcile_schedule(confirmed_by_request=...)`. That call already checks their permission and scope and writes one strict audit row.
4. On every run the creator is still active and still holds the action permission and the scope. The tick skips the run (`AuthorizationRevoked`) and `verify_run_context` raises (`owner_refused`) if not.

What does not change: the AD-13 exemption (`_is_unattended_scheduled_run`) is **not** used and stays False for these actions, so this is stricter than a user-owned schedule. `verify_run_context` still compares the expected module and action ids exactly. An action not declared, a schedule with no creator, a manual run and one-off runs behave as before. Any error reading the manifest means no person.
Audit: unchanged, plus one row per run that uses the creator (`run`, `run_as` creator, run id, owner and creator names; best effort, a failed row is logged and the run goes on).

Residual risk: Low. A signed module that lists an action gets its creator as the person for scheduled runs of its own action. The module is reviewed and signed, and Core runs the same permission and scope checks as it does for a user-owned schedule at every run.

## Tests

`tests/scheduler-person-actions-1.17.80.py` (real scheduler, run context and tasks on the stub harness): a declared notice and reboot schedule made through `reconcile_schedule` verifies with the creator and writes one audit row; an undeclared action, a delisted action, a manual run, a schedule with no creator and another module's action get no person; a deactivated creator, a lost permission and a lost scope are skipped by the tick and refused by verify; a handler naming another action id is refused; the manifest key parser.

## Test checklist (dev02)

Needs Core 1.17.80 and an APM build that lists `patchmanagement.notice` and `patchmanagement.reboot` under `scheduler_person_actions` (and requires framework 1.17.80).

1. Save an APM profile with a patch notice a few minutes ahead. **Expected:** at the due time the run succeeds, Communicator sends the notice, and Core's audit shows one `run` row with `run_as` creator. **FAIL:** the run shows "This run has no person behind it.", or no audit row. Send back: the Scheduler run entry, the audit row and the Core log.
2. Same for the restart prompt (`patchmanagement.reboot`). Same expected and FAIL.
3. Deactivate the engineer who saved the profile, then wait for the next run. **Expected:** the run is skipped with "Schedule owner is missing or inactive." and nothing is sent. **FAIL:** a message goes out. Send back: the run entry and the Communicator log.
4. Press Run now on the schedule in the browser. **Expected:** the person is not the creator (no_owner) and nothing is sent. **FAIL:** it sends. Send back: the run entry.
5. A schedule of any other module (for example Maintenance). **Expected:** behaves exactly as before. **FAIL:** any new refusal. Send back: the run entry.

## Not run here

Django is not installed on this PC. The new test runs on the stub harness; `ruff` and the integration of the real database layer were not run unless listed in the report.
