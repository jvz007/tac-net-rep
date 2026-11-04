# Tec-Tac Framework 1.17.111

Date: 4 November 2026. A module's own scheduled action can now be started later, with nobody signed in, for a person who confirmed it once. Today Core allows exactly one such action: Maintenance starting WAPM's profile install. Nothing else changes for you.

Closes: `reviews/requests/core.md`, "From wapm 0.7.0" (delegation for a module's `scheduler_person_actions` action) and "From automation 0.11.1" (document the keys `capability_status` returns).

## What changed and why

1. **A person action can be named in a delegation grant.**
   * Why: WAPM's `wapm.profile-install` is a Scheduler action of WAPM, not a Tactical function. Until now only a Tactical function could be delegated, so Workflows (module id `maintenance`) could not start it for a person who confirmed it at save time. AD-43 signs exactly this for Maintenance's unattended install.
   * Now: `register_scheduled_action` takes a last, optional keyword `delegable_to` (up to five other module ids). The five delegation functions (`describe_delegation`, `register_delegation_grant`, `remove_delegation_grant`, `issue_delegation_ticket`, `start_delegated_run`) and `resolve_delegated_targets` accept such an action. The grant, the 24 hour ticket, one ticket one run, the stored scope, the takeover rule, the strict audit rows and the revocation by an edit or a removal are the same code as for a system action.
   * **Fixed allow-list.** Core refuses a non-empty `delegable_to` unless the action id is in the module's signed manifest under `scheduler_person_actions` (an unreadable manifest refuses), the id is not also a system action, and every module named is in `delegation.PERSON_ACTION_DELEGATION`. That list is `{"maintenance": ("wapm.profile-install",)}` and nothing else. The reboot, the removal and the download of a WAPM profile, and any other module, are refused until Johan signs them.
   * **What Core checks when the person confirms** (a person action has no row in the table of Tactical functions, so these replace the flag list): the person is active and not the installer user; the person holds the action's own permission, with **no bypass for a scheduler manager** (an action with no permission entry refuses); the parameters are `None`, `{}` or a flat dict of at most 10 keys named `[a-z][a-z0-9_]{0,39}` with `bool`, `int` or text of at most 200 characters, never the marker key; the targets read as 1 to 40 000 endpoints through the owner module's resolver and every one is inside the person's live Tactical scope. One deny row per refusal.
   * **The plain Yes or No text** says what will start, that Maintenance starts it later with nobody signed in, what Core still checks each time, that Core does not look at the account again (the run goes on if the account is later disabled) and that editing or removing the profile stops it. `describe_delegation` gains the key `kind` (`person_action` or `system_action`); `groups` is `None` for a person action.
   * **Parameters are fixed at the confirmation.** Core stores only the confirmed record under `system_action_parameters`. The run's parameters are that record plus the signed marker. `start_delegated_run` still takes no parameters.
   * **When the delegated run is unattended.** Only while the marker, the grant, the run's action id, `delegable_to` on the registered action, the allow-list, the manifest entry and both modules all still hold. Any doubt makes it an ordinary one-off with every re-check, so it is skipped if the person has lost the permission, the scope or the account.
   * Code: `scheduler.py` (`ScheduledAction.delegable_to`, `register_scheduled_action`), `delegation.py` (`PERSON_ACTION_DELEGATION`, `_person_action_reason`, `_person_controls`, the person-action text, `run_is_validly_delegated`), `system_action_confirmation.py` (the target step is now one shared helper, `_checked_target_ids`, with the same checks and the same denials), `system_actions.py` (capability 1.6.0, metadata `delegation.person_actions`).
2. **`capability_status` keys are documented.**
   * Why: Automation Manager reads `module_id` for its "Managed by WAPM" message, and the contract row said only that the function returns "the structured state".
   * Now: the contract row and `docs/capabilities.md` list every key: `id`, `module_id` (the module that provides the capability), `available`, `state`, `required_version`, `installed_version`, `capability_version`, `description`, `operations`, `metadata`, `reason`, `health`, `health_checked`, `replaces`. All of them existed earlier. No behaviour changed. A test fails if a key is added without a line in both places.

## Module-facing changes: delegation for a person action

* `core.system_actions` goes 1.5.0 to **1.6.0**, additive. The operations are the same twelve in the same order. Framework >=1.17.111 is needed to use a person action in a grant. Metadata gains `delegation.person_actions`.
* `register_scheduled_action(..., delegable_to=())` is a new last keyword with a default; `ScheduledAction` gains the last field `delegable_to` (default `()`), so every earlier action compares equal. A grep of `modules/` found 27 modules that call `register_scheduled_action`; none passes the keyword, so none changes.
* The five delegation functions and `resolve_delegated_targets` keep their signatures. `patchmanagement` (`install`, through Maintenance) still uses the system-action path, unchanged: the same text, grant, ticket, run and marker. A write row and a command row are still not delegable. `communicator` requires `core.system_actions` >=1.5.0,<2.0.0, which 1.6.0 satisfies.
* `wapm` (`maintenance.py` answers `delegation_unavailable` today) can switch `start_install` on in a later patch. `maintenance` has not called these functions yet. Both are recorded in `reviews/requests/premium-modules.md`.
* The new reason text of `action_not_declared` now says "system_actions or scheduler_person_actions". The reason code is unchanged.

## What did not run here

Django is not installed on this PC. The new tests run on the stub harness (no database, no Celery): they prove the code paths and the checks, not a real Postgres transaction. The runtime tests that need Django (`delegation-runtime-1.17.68.py`, `scheduler-*-runtime-*`) and a dev-server check of a real grant, ticket and run need the dev server. Several older tests already failed on this PC before this release for reasons outside it (no Django, no `accounts` app, and the module-source checks in `system-actions-compat-1.17.61.py`, `scheduler-compat-1.17.68.py` and `contract-catalog-1.17.61` to `68`).

## Tests

* New: `tests/delegation-person-action-1.17.111.py` (registration, describe, register), `tests/delegation-person-action-run-1.17.111.py` (ticket, start, resolve, the unattended answer and its revocation), `tests/delegation-person-action-compat-1.17.111.py` (the system-action path, signatures, capability 1.6.0, contract rows and documents), `tests/capability-status-docs-1.17.111.py`; shared harness `tests/delegation-person-action-harness-1.17.111.py`.
* Pins that read the field list or the capability version were updated: `scheduler-compat-1.17.63.py`, `scheduler-compat-1.17.68.py`, `scheduler-unattended-owner-1.17.63.py`, `scheduler-wide-recheck-1.17.65.py`, `scheduler-target-resolver-1.17.68.py`, `system-actions-compat-1.17.61.py`, `system-command-1.17.75.py`.
