# Tec-Tac Core 1.15.164

## Scheduler compatibility rebuild

This rebuild fixes the blocking review regression introduced by 1.15.164 target normalization.

- Preserves the submitted native Scheduler target type for persistence and module handlers (`endpoints`, `agents`, `clients`, `sites`, etc.).
- Continues to use singular Tactical kinds only inside Core scope/authorization logic.
- Migration 0015 and the 0020 parity repair preserve stored native target types while still canonicalizing identifiers and dynamic Tactical scope.
- Adds behavioral coverage proving plural endpoint target types remain accepted for module actions and survive migration/dispatch snapshots with every selected id.

No public API endpoint changes are introduced. This rebuild restores backwards compatibility with existing scheduled-action module contracts.
