# Tec-Tac Framework 1.17.46

This patch release fixes one thing in the Scheduler tick for event jobs. The tick no longer ends a module's waiting jobs when Core cannot read the
module list or the module state for a moment. It ends them only when it has confirmed that the module is disabled or uninstalled.

## What changed and why

The review of 1.17.45 held one Medium finding. Each minute the tick checks every module that has pending event jobs. If the check failed, for example
because `module-state.json` was briefly unreadable, Core treated that the same as "disabled" and ended the module's whole backlog as `ModuleUnavailable`.
A short fault could therefore throw away jobs that were fine.

Now Core tells the two cases apart:

- **Confirmed unavailable:** a read that succeeded shows the module is missing, a legacy module, not an extension or disabled. The tick ends its pending
  rows as `ModuleUnavailable`, with one `custom:event-job-skipped` audit row per job, exactly as in 1.17.45.
- **Could not read:** the module list or the module state raised an error, or the state file is flagged corrupt. The tick leaves every pending row of that
  module alone, writes no audit row, does not use up the tick's row budget and logs one warning for the module. The tick result gains an additive key,
  `module_state_unread`, with the number of modules it could not read. The rows are tried again on the next tick, and their own expiry time still ends
  them if the fault lasts. Nothing stored is lost to a short fault.

The worker now follows the same rule. When it cannot read the module state, it keeps the row it holds: the row stays `pending`, no handler runs, no attempt
is used, no audit row is written, and the row is tried again after 60 seconds (the worker answers `job deferred`). Only a read that succeeded and shows the
module is unavailable ends the row as `ModuleUnavailable`. Before this fix a worker that held a row during the fault still ended it as skipped.

The other strict checks are unchanged. A worker never runs a handler on a state it cannot read, publish still answers `disabled` on a state fault, and
registration is still refused on a corrupt state.

Known limit: "confirmed" means a module discovery that finished without an error. A module folder that is briefly missing from a finished scan, for
example in the middle of an upgrade, still counts as uninstalled for that tick.

## Closes

The held Medium finding of the Core 1.17.45 review (the tick expires a module's whole backlog when a read fails for a moment). No entry in
`reviews/requests/core.md` is closed by this release.

## Module-facing

None. `core.event_jobs` stays at 1.0.0. No contract, capability version, endpoint or import changes, and Alerts 0.10.0 (source in `modules/alerts`) uses
`core.event_jobs`. No signature or contract changed for it, and it does not read the additive `module_state_unread` key. A job of Alerts that a worker holds
during a state fault now stays pending instead of ending as skipped. No module reads the tick result.
The only visible change is the additive `module_state_unread` key in the `event_jobs` block of the tick result.

## Docs and tests

- `docs/event-jobs.md` now says the tick ends rows of a module it has confirmed disabled or uninstalled, and leaves them pending when the state cannot
  be read.
- New `tests/event-jobs-module-gate-1.17.46.py`. `tests/event-jobs-1.17.45.py` only gained `load_state` and a `state` argument in its module-state stub.

## Not run here

Django is not installed on this PC. The event job tests run against stubs. `tests/event-jobs-runtime-1.17.45.py` (needs Django, the broker and a worker)
stays Johan's dev-server probe. No migration in this release.
