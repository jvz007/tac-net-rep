# Tec-Tac Framework 1.15.3

## Non-destructive restore readiness

- Bumps `core.server_backup` public capability to 1.3.0.
- Adds `validate_restore(backup_ref, destination, restore_mode, context)`.
- Validation downloads/stages recovery objects and performs mode-aware structural, checksum and component validation without mutating Tactical/Tec-Tac or system state.
- Reports artifact validity separately from current-host target readiness.
- Strengthens the common Tactical pre-destructive validator for backup.sh v34 / restore.sh v67 material, including PostgreSQL gzip integrity, MeshCentral payload/database material, nginx/systemd/config members and nested tar/gzip readability.
- Strengthens Tec-Tac component validation and transient backup-state exclusion checks.
- Keeps tactical-only validation independent from an unused/corrupt Tec-Tac component.
- Records validation in normal Core job history and removes job-owned staging after completion.
