# Tec-Tac Core 1.15.174

Closes the production gaps identified in tracker rows **L10** and **D2**. This release intentionally limits scope to backup publication atomicity and older-Core restore correctness.

## L10 — archive/sidecar publication atomicity
- SCP now re-checks both final names immediately before publication and uses `mv -T -n` so a directory or concurrent writer cannot absorb/clobber a final archive or sidecar name.
- SCP publishes the sidecar first and removes it if the archive move fails.
- rclone now reconciles a failed/timed-out archive `moveto`: if the archive actually landed, the sidecar is retained and the publication is treated as complete.
- rclone only removes a published sidecar when the final archive is confirmed absent, and a failed sidecar rollback is surfaced instead of silently ignored.
- Regression coverage executes the real SCP publication shell fragment for directory-target failure and success paths, plus the rclone timeout-after-remote-success case.

## D2 — restoring an older Core version
- Tec-Tac runtime/source/UI restore roots are cleared before extracting the backup payload, preventing newer-only files or migrations from surviving a downgrade restore.
- Restore-root clearing rejects symlinked, relative, `/`, or Tactical-tree-overlapping roots before destructive removal.
- Publisher trust is merged by publisher/key. Revoked state wins. On a replacement server, restored-only source publishers are retained; on the same installation, target-side publisher deletions remain authoritative.
- Post-restore version verification now reads the deployed Core runtime tree rather than the restored source tree, so a source `VERSION` file cannot self-prove a successful install.
- The destructive restore path passes the source installation identity into the security-state merge so same-server and replacement-server semantics are deterministic.

## Regression coverage
- `tests/l10-publication-final-1.15.173.py`
- `tests/server-backup-d2-d3.py`
- `tests/server-backup-d2-version-transition.py`
- `tests/server-backup-decision-closure-1.15.166.py`
- `tests/d2-d3-restore-orchestration-1.15.173.py`
- inherited L10/D2 final acceptance suites


## Rebuild 1 — D2 same-server publisher trust correction
- Same-installation restores once again treat the current target publisher directory as authoritative and replace the restored copy wholesale. Keys and public-key files deleted after the backup therefore stay deleted.
- Replacement-server publisher merging now normalises legacy `key_id`/`key_status` policies into `keys[]` before merging. Current target key state wins for known keys and restored-only keys are added only when absent; revoked state remains fail-closed.
- Added regressions proving a deleted `k1` and `k1.pub` are not resurrected on same-server restore, and proving a legacy revoked key remains `key_revoked` when the backup contains an active `keys[]` record.


## Rebuild 2 — replacement-server publisher filename collision
- Replacement-server publisher merge now compares restored-only key files against current target files before current files are copied over the restored publisher directory.
- If a restored-only key references a public-key filename that already exists on the target with different bytes, the restored-only key record is dropped fail-closed instead of being allowed to resolve to the target key's bytes.
- The collision check applies after normalising both `keys[]` and legacy top-level `key_id` / `key_status` publisher formats.
- Added regressions for both formats proving `kA` cannot resolve to current revoked `kB` bytes and that a package signed by `kB` while claiming `key_id=kA` is rejected.
