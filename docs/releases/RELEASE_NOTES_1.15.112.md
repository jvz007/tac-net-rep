# Tec-Tac Core 1.15.112

## Review rebuild

This is a narrow rebuild of Core 1.15.112. No new backlog work is included.

## Fixed

- **Blocking M14 review defect:** `_permitted_action_ids()` now reads `ScheduledAction.id` instead of the non-existent `ScheduledAction.action_id`.
- Restricted Scheduler run-history no longer raises `AttributeError` when a permitted action is present.
- Both paged and legacy unpaged non-manager run-history paths retain the M14 request-scope filtering behavior and return normally.

## Tests

- Added `tests/scheduler-permitted-action-ids.py`.
- The regression constructs two real `ScheduledAction` objects, permits one, and asserts `_permitted_action_ids()` returns exactly that action's `id`.
- The same regression exercises restricted paged and unpaged Scheduler run-history GET paths and asserts HTTP 200.
