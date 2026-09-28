# Fixing — Core 1.15.150

This release closes the remaining Trust Policy review items L26, L27, and L28.

## In scope

- L26 — behaviorally prove that signed-in trust-policy PUTs use dedicated authenticated throttles with non-empty per-user cache keys.
- L27 — behaviorally prove a failed install-time `check-revert` remains non-fatal after the persistent timer is enabled.
- L28 — behaviorally prove `set_level()` and `check_revert_due()` serialize through the same cross-process policy lock.
- Repair the stale 1.15.51 regression so it asserts the current non-fatal trust-policy check and shared Scheduler retry-delay helper.

## Out of scope

- Backup/archive-history closure items.
- Remaining UI closure items.
- D2/D3 restore decision cleanup.
- Unrelated Core behavior changes.
