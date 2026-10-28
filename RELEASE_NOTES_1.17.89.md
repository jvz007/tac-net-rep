# Tec-Tac Framework 1.17.89

Date: 28 October 2026. Clears the held Low findings of the 1.17.87 and 1.17.88 reviews. No migration, no contract, route or capability change. No module-facing change.

## What changed and why

1. **A schedule that is no longer monthly keeps no monthly fields (1.17.88 review, Low).** On `PATCH`, when the merged schedule is not monthly, `switch_monthly_mode` now clears `day_of_month`, `month_week` and `month_weekday`. Before, an old second-Tuesday pair stayed on a schedule changed to weekly and came back when it was made monthly again. A monthly schedule made from a weekly one now needs a fresh choice (`day_of_month`, or the pair).
2. **The confirmation key follows the type (same finding).** `when_key` adds `month_week` and `month_weekday` only when `schedule_type` is monthly. A stale pair can no longer change the key of a weekly timing. The key of every timing that held no pair is unchanged, so a confirmation id issued before this release still matches.
3. **The real POST and PATCH paths are tested (1.17.88 review, Low).** `tests/scheduler-views-monthly-1.17.89.py` runs `SchedulerListView.post` and `SchedulerDetailView.patch` on the shared view harness. It covers the new fields accepted and returned, both modes together, neither, half a pair, out of range and booleans (400, nothing saved), the mode switch both ways, a refused PATCH changing nothing, and monthly to weekly. It fails when fix 1 or 2 is reverted.
4. **Ownership-moving callers are an allow-list again (1.17.87 review, Low).** `tests/scheduler-compat-1.17.68.py` fails when a module other than `patchmanagement` or `communicator` passes `confirmed_by_request`. Add a module there on purpose, after review.
5. **Groups' operator check reads the code (1.17.87 review, Low).** `tests/filter-sets-1.17.50.py` parses Groups' `evaluator.py` with `ast` and compares the operator ids it branches on (comparisons, membership tests, dispatch keys) with Core's six. An id in a comment or an error message no longer counts.
6. **Already shipped: the manifest scan cache (1.17.80 review, Medium).** Core 1.17.81 added `_manifest_person_actions_table`, one `discover_plugins` scan per change of the manifest files. Nothing to change here.

## Module-facing change

None. No contract, signature or route changed. A module that PATCHes nothing is unaffected. `reconcile_schedule` already cleared the unused monthly fields.

## Docs

`docs/module-scheduling.md`: one clause on the `PATCH` clearing.

## Tests

New: `tests/scheduler-views-monthly-1.17.89.py`. Changed: `tests/scheduler-compat-1.17.68.py`, `tests/filter-sets-1.17.50.py`.

## Not run here

Django is not installed on this PC. The view test runs the real `scheduler_views.py` on stubs, not on a database. `makemigrations --check` was not run (no model change in this release).
