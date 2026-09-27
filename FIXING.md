# FIXING — Core 1.15.101

Review scope for this release: **M3 only**.

## Tracker item

- **M3** — restore rollback must not move `/rmm` across filesystems with `os.replace()`, because a cross-device rename can fail with `EXDEV` before the original Tactical tree is restored.

## Behavioural change

- The failed restored Tactical tree is quarantined to a unique sibling of `TACTICAL_ROOT` instead of the pre-restore snapshot directory.
- Both rollback renames therefore remain on the same filesystem as `TACTICAL_ROOT`.
- The failed restored tree is removed only after the original Tactical tree, host state, databases and runtime verification have succeeded.

## Behavioural regression

- `tests/server-backup-host-rollback.py` now emulates `EXDEV` for every rename whose source and destination parents differ.
- The test runs the real `rollback_failed_restore()` coordinator and proves the original Tactical tree is restored, no cross-filesystem rename is attempted, the preserved tree is consumed, and the failed-tree quarantine is cleaned after success.

## Not in scope

No M4+ Mediums, UI changes, or unrelated Low items are included.
