# Tec-Tac Framework 1.6.0

## Module navigation visibility

- Adds persistent `visible` state alongside module `enabled` state.
- Existing modules default to visible when no visibility record exists.
- Adds `POST /api/tfd/modules/v2/<plugin-id>/visibility/` with `{ "visible": true|false }`.
- Module catalog now reports `visible` independently from `enabled`.
- Visibility changes run through the privileged Module Management v2 worker.
- Hidden modules remain enabled and continue to satisfy dependencies.
- Visibility changes trigger UI module synchronization so the generated UI manifest carries the current navigation state.
- Disabling/re-enabling a hidden module preserves its hidden preference.

This release does not alter feature-module functionality.
