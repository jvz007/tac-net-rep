# Tec-Tac Framework 1.15.47

## Backup / restore reliability hardening

- Added pre-restore PostgreSQL snapshots and automatic Tactical tree/database rollback after destructive restore failure.
- Silent helper hangs now obey wall-clock timeouts and terminate their process groups.
- SCP listing now discovers both native Tactical archives and Tec-Tac recovery bundles.
- FTP, SCP and rclone destinations upload to `.partial` objects and publish only after verification.
- Relative remote paths are preserved rather than forced to absolute paths.
- Retention now protects backups when sidecar metadata is unreadable and requires an explicit `keep_unclassified` value.
- Verified remote backups no longer leave unnecessary staging bundles in `/rmmbackups`.
- Recovery payloads now include a strict durable-state allow-list for module state and repository configuration; publisher trust remains covered by `/etc/tec-tac`.
- TAR extraction uses Python's data filter and rejects members nested beneath symlinks.
- Backup worker final status handling now also records `SystemExit`/other `BaseException` failures.

## Review tracking

This closes the targeted backup/restore findings B1, B2, B3, B6 and related C1, C2, C3, C15, C16 and C17 from the independent Core 1.15.42 review. Scheduler P1 findings and the remaining helper/housekeeping hardening stay open for the next release.
