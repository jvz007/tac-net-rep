# FIXING.md — Core 1.15.104

## Review scope

This release is intentionally scoped to **M6** from Claude's Tec-Tac Medium/Low tracker.

### M6 — validate System Update rollback source before swapping the live tree

Review that `scripts/system-update-helper.py::restore_backup()` now:

- refuses missing/non-regular rollback archives before touching the installed component tree;
- validates every tar member before publication and rejects unexpected top-level paths, links, and special files;
- fully extracts the rollback archive into a sibling staging directory before the live tree is renamed or removed;
- keeps the current live component tree in a same-filesystem quarantine until the staged rollback tree is successfully published;
- preserves the live checkout's `.git` metadata because system-update backups intentionally exclude `.git`;
- restores the quarantined live tree if the final staged-tree publication fails;
- removes staging/quarantine artifacts after a successful restore.

Behavioral regression: `tests/system-update-rollback-backup-safety.py`.

The test proves that missing, malformed and truncated/corrupt rollback archives leave the live component tree and `.git` metadata untouched, while a valid archive is staged and then swapped successfully.

## Test-environment note

`tests/tactical-update-survival.sh` reaches its environment prerequisite check and cannot determine the real Tactical service user in the packaging container. The M6-specific regression and System Update extraction/signed-tree/foundation suites pass independently; do not treat the missing service-account environment as an M6 behavior failure.

## Out of scope

No M7+ Mediums or unrelated Low items are intentionally addressed in this release.
