# Tec-Tac Core 1.15.70-1

## Security: immutable module artifact claims (R3)

Core now snapshots every Tactical-writable module v1/v2 staged artifact into a newly-created root-private inode before privileged signature verification or installation.

- Source artifacts are opened with `O_NOFOLLOW` and must be regular files.
- The privileged destination is created exclusively in a root-owned `0700` claim directory with mode `0600` and ownership `root:root`.
- Bytes are copied through file descriptors and `fsync`ed before the snapshot is accepted.
- The original staged pathname is unlinked after a successful snapshot.
- A writable file descriptor opened by the Tactical account before claim can therefore mutate only the old, unlinked inode; it cannot alter the root-private artifact that Core verifies and installs.
- V1 package, signature and release-metadata claims use this boundary.
- V2 package/bundle, signature and release-metadata claims use this boundary.
- Staged final-component symlinks are rejected rather than followed.

No `core.*` public capability or endpoint contract changes are introduced by this release.

## Rebuild 1.15.70-1: staged-path deletion boundary

The original 1.15.70 R3 snapshot implementation is hardened so Tactical-writable metadata cannot route the root helper through a symlinked intermediate directory.

- v1 accepts only a single plain filename directly below `STAGED_ROOT`.
- v2 accepts only a single plain filename directly below `STAGED_ROOT` or the managed `STAGED_ROOT/bundles` directory.
- The staging directory is opened with `O_DIRECTORY|O_NOFOLLOW`; bundle staging is opened relative to that fd.
- Source files are opened with `O_NOFOLLOW|O_NONBLOCK` relative to the directory fd.
- Cleanup uses `os.unlink(..., dir_fd=...)`, never a path that can traverse an intermediate symlink.
- Before unlinking, Core verifies the directory entry still has the same `st_dev`/`st_ino` as the file descriptor that was copied. If it changed, root skips deletion.
- Regression coverage proves a symlinked staging subdirectory cannot cause deletion of an external victim file.

No public capability or endpoint contract changes are introduced.
