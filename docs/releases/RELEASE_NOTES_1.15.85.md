# Tec-Tac Framework 1.15.85

## Privileged job-file symlink boundary (H1)

- Replaced fixed `<job>.json.tmp` writes in the system-update and server-backup root helpers with `mkstemp`-backed atomic publication.
- Job/request JSON ownership and mode are now applied to the open temporary inode with `fchown`/`fchmod` before `os.replace`; privileged helpers no longer chown/chmod Tactical-writable job names after publication.
- System-update, server-backup, module v1 and module v2 privileged job/request reads now reject symlinks with `O_NOFOLLOW` and require regular bounded JSON files.
- System-update history is written from the validated in-memory job document rather than copying the mutable jobs-path file.
- Server-maintenance and housekeeping were reviewed against the same boundary; their existing random-temp/fd-based publication patterns remain in place.
- Added `tests/root-job-file-symlink-boundary.py`, which places canary symlinks at both the legacy temp name and final job name and verifies privileged writers cannot modify the symlink targets.
