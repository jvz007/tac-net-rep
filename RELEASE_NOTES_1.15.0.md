# Tec-Tac Framework 1.15.0

## Core privileged server backup capability

Framework 1.15.0 adds the framework-owned `core.server_backup` capability
(version `1.0.0`) for Tactical-compatible server backup, restore, remote
transfer, retention and backup credential handling.

The capability follows the existing opaque privileged-job pattern. Tactical's
Django/Celery process may dispatch only:

```text
/usr/local/sbin/tec-tac-server-backup --dispatch <UUID>
```

The root-owned helper validates the UUID, job ownership/mode, fixed operation
allow-list and typed fields before an independent systemd worker executes the
operation. No public contract accepts an arbitrary command or executable path.

Public provider operations:

- `create_backup(...)`
- `list_backups(...)`
- `restore_backup(...)`
- `apply_retention(...)`
- `store_secret(...)`
- `delete_secret(...)`

`create_backup()` runs Tactical's current `backup.sh` as the configured Tactical
installation owner using the normal non-`--auto`, non-`--schedule` path. The
new Tactical archive may be extended with a checksummed `tec-tac/` payload and
then fanned out to local, SFTP, FTP, SCP, WebDAV and S3/S3-compatible
destinations. Requested destination failures fail the overall operation and
remain visible in the structured result.

`restore_backup()` stages remote archives locally, validates archive member
safety and the required Tactical backup structure, verifies the optional
Tec-Tac manifest, records the restore job before destructive work, runs
Tactical's official restore script as the installation owner, restores Tec-Tac
state/source/configuration when requested, reruns Tec-Tac reintegration and
verifies nginx/services before reporting success.

Backup class is persisted in `.tectac.json` metadata sidecars; retention is
independent per destination and never infers daily/weekly/monthly class solely
from age. Legacy Tactical archives without sidecars are listed as
`unclassified`.

Backup credential material is stored only in root-owned `0600` files beneath
`/var/lib/tec-tac/server-backup/secrets/`; modules retain opaque UUID
`secret_ref` values.

See `docs/server-backup-capability.md`.
