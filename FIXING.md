# FIXING.md — Core 1.15.106

## Review scope

This release is intentionally scoped to **M8** from the 27 September 2026 Claude tracker.

### M8 — legacy zero-value housekeeping policies

Older saved housekeeping policies may contain `0` in their active `days` or `keep` field. Core 1.15.105 passes those values through to the privileged helper, while the current helper rejects values below 1. That makes housekeeping status/dry-run/purge fail immediately after upgrade for affected installations.

Review that this release:

1. Repairs only an exact legacy zero on config read, replacing it with that category's current built-in default.
2. Applies the same repair in the privileged helper for an already-queued request created by an older Core.
3. Does **not** re-enable destructive-zero semantics (`allow_zero_destructive` remains false).
4. Keeps new/updated policy writes strict: values must remain between 1 and 3650.
5. Does not silently repair negative, malformed, or unsupported values.
6. Includes an executable behavioral regression covering the Core config path and the privileged helper's actual request-processing path.

## Primary files changed

- `framwork/tec_tac/housekeeping.py`
- `scripts/housekeeping-helper.py`
- `tests/housekeeping-legacy-zero-compat.py`
- `docs/housekeeping.md`

## Explicitly out of scope

No other Medium or Low tracker item is intended to be closed by this release.

## Test-environment / legacy-suite note

`tests/review-followup-1.15.79.py` is not used as an M8 acceptance gate because its C16 assertion still greps for the pre-1.15.104 System Update rollback extraction expression. M6 intentionally replaced that implementation with validated sibling staging and atomic swap. This release does not modify that unrelated stale review test.
