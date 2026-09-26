# Tec-Tac Core 1.15.72-1

## Server Backup: complete host rollback transaction (B1 remainder)

Core Server Backup now snapshots and restores the fixed host paths that Tactical restore and Tec-Tac post-restore can overwrite, in addition to the existing `/rmm` tree and PostgreSQL rollback.

Before the first destructive action, Tactical/full restore captures a root-only host snapshot covering fixed Tactical restore targets including nginx configuration, Let's Encrypt state, Tactical systemd units, `/meshcentral`, `/opt/tactical`, frontend state, `/etc/conf.d`, Tactical host/config files and fixed runtime binaries. Full restore additionally snapshots Tec-Tac runtime/source/UI paths from the root-owned Core configuration, `/etc/tec-tac`, the Tec-Tac nginx snippet and the two durable Module Manager state files.

Tec-Tac-only restore now has its own host rollback transaction. It does not move `/rmm` or snapshot/restore Tactical databases, but a failed Tec-Tac reintegration restores the original Core/Tec-Tac host state before services are restarted.

Snapshot targets are fixed by Core or derived from the root-owned Tec-Tac configuration. Recovery-manifest path metadata is not used as rollback authority. Snapshot/restore refuses symlinked intermediate directories; legitimate final-path symlinks such as nginx `sites-enabled` entries are preserved. Files/directories absent before restore are recorded and removed again on rollback if the failed restore created them.

Rollback results now expose `rollback_host_paths_restored` alongside the existing tree/database markers.

No public `core.server_backup` contract change is required.

## Validation

- `tests/server-backup-host-rollback.py`
- `tests/server-backup-review-hardening.sh`
- `tests/server-backup-foundation.sh`
- `tests/server-backup-root-layout.py`
- `tests/server-backup-transport-security.py`
- `tests/contracts-foundation.sh`
- `tests/release-integrity.sh`


## Rebuild 1.15.72-1

- Extends failed-restore host snapshots to every Core-owned privileged install target written or removed by `install.sh` under `/usr/local/lib`, `/usr/local/sbin`, and `/etc/sudoers.d`.
- Protects the installed module, system-update, server-backup, server-maintenance, housekeeping and trust-policy helpers/libraries plus the legacy repair/diagnostics entry points.
- Restores Tec-Tac sudoers rules from the pre-restore snapshot and requires `visudo -c` to pass before rollback can report success.
- Adds regression coverage keeping the installer privileged-target inventory aligned with the rollback snapshot boundary.
