# Tec-Tac Framework 1.15.189

## D3 / AD-3 closure hardening

- `core.server_backup` stays on the backwards-compatible 1.x line and advances to **1.9.0**. Existing Backups modules pinned to `>=1.6.0,<2.0.0` continue to resolve the Core provider while receiving the additive AD-3 archive-verification/source-identity fields.
- The installer verifies the same compatible `>=1.6.0,<2.0.0` server-backup capability range used by the installed Backups module.
- Host-rollback discovery treats `/usr/local/sbin/tec-tac-recovery-key` as an explicit legacy removal-only installer target; it is not part of the current rollback inventory because the helper no longer exists.
- Backup capability documentation now matches AD-3 inventory fields: `installation_id`, `server_name`, `created_at`, `core_version`, and `hash_file`.
- Obsolete recovery-key / recovery-trust tests for the removed AD-3 design are removed from the active source tree.
- D3 destructive-restore regression now proves that a missing adjacent hash is recorded as `restore_archive_not_verified`, and that a malformed or mismatched hash stops `operation_restore_backup` before destructive restore work begins.

No UI changes are required for this release.

## Rebuild fix

- Adds an explicit compatibility regression proving `get_capability("core.server_backup", version=">=1.6.0,<2.0.0")` resolves the registered Core provider.
