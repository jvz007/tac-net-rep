# Tec-Tac Framework 1.15.101

## M3 — restore rollback keeps Tactical tree swaps on one filesystem

- Failed restored `/rmm` trees are now quarantined beside `TACTICAL_ROOT` rather than under the pre-restore snapshot root.
- This prevents rollback from depending on a cross-filesystem `os.replace()` that can fail with `EXDEV`.
- The original preserved Tactical tree is restored with a same-filesystem rename, and the failed restored-tree quarantine is deleted only after rollback succeeds.
- Added a behavioural regression that forces any cross-parent rename to fail as `EXDEV` and proves rollback still restores the original Tactical tree.

UI is unchanged.
