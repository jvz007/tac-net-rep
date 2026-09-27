# Tec-Tac Framework 1.15.105

## M7 - backward-compatible backup retention policies

- Restored compatibility for retention policies saved before `keep_unclassified` was introduced.
- A missing `keep_unclassified` now normalizes to `10000` rather than rejecting the policy or risking deletion of unclassified/legacy backups.
- The privileged backup helper enforces the same safe compatibility behavior independently.
- Explicit `keep_unclassified` values continue to be honored exactly.
- Added behavioral regression coverage for both legacy omission and explicit retention behavior.

See `FIXING.md` for the review scope.
