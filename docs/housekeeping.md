# Core Storage Housekeeping

Tec-Tac Core owns cleanup of disposable operational data below `/var/lib/tec-tac`. Clients submit only named category IDs and retention values; filesystem paths are never accepted from the UI/API.

Default retention:

- `local_settings_backups`: keep 10 newest
- `module_staging`: 7 days
- `module_history`: 30 days
- `system_update_staging`: 7 days
- `system_update_backups`: keep 3 newest
- `system_update_history`: 30 days
- `server_backup_staging`: 7 days
- `server_backup_history`: 30 days
- `server_backup_pre_restore`: 14 days

Protected data includes deployed UI, Module Manager state/repositories, server-backup secrets, configured backup destinations, `/opt/tec-tac`, and `/opt/tec-tac-src`.

API:

- `GET /api/tfd/system/storage/` scans and returns dry-run candidates.
- `PUT /api/tfd/system/storage/` saves retention policies.
- `POST /api/tfd/system/storage/purge/` accepts `dry_run` and optional category IDs.
