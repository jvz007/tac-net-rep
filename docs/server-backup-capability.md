# Core privileged server backup capability

**Framework baseline:** 1.15.0+

Tec-Tac Core exposes one narrow privileged server-backup contract:

```text
core.server_backup
capability version 1.0.0
```

It exists so modules such as Backups can request Tactical-compatible backup,
restore, remote transfer and retention operations without receiving arbitrary
`sudo`, shell, executable-path or filesystem privileges.

Resolve it through the normal capability registry:

```python
from tec_tac.capabilities import get_capability

backup = get_capability(
    "core.server_backup",
    version=">=1.0.0,<2.0.0",
)
```

## Security boundary

The Django/Celery process writes a validated opaque job under:

```text
/var/lib/tec-tac/server-backup/jobs/
```

and may sudo only:

```text
/usr/local/sbin/tec-tac-server-backup --dispatch <UUID>
```

The root-owned helper validates job ownership/mode, action allow-list and typed
arguments, then starts an independent systemd transient worker. No public
operation accepts a command, shell fragment or executable path.

Backup mutation/restore operations use a Core lock so destructive restore and
archive mutation cannot overlap.

## Operations

### `create_backup(...)`

```python
result = backup.create_backup(
    backup_class="daily",            # daily|weekly|monthly|manual
    destinations=[...],
    include_tec_tac=True,
    context={...},
)
```

Core runs Tactical's current `/rmm/backup.sh` as the configured Tactical user
with neither `--auto` nor `--schedule`, detects the newly-created
`/rmmbackups/rmm-backup-*.tar`, optionally appends a `tec-tac/` payload, hashes
it, writes a `.tectac.json` sidecar, fans the same archive out to every selected
destination, and verifies each copy. A requested destination failure makes the
overall operation fail while retaining structured per-destination results.

### `list_backups(...)`

```python
rows = backup.list_backups(destinations=[...], context={...})
```

Restore points contain an opaque `backup_ref`, destination metadata, size,
modified time, persisted backup class and SHA-256 when sidecar metadata exists.
Legacy Tactical archives without a sidecar are exposed as `unclassified`.

### `restore_backup(...)`

```python
result = backup.restore_backup(
    backup_ref="destination:3:rmm-backup-2026_09_20__07_30_00.tar",
    destination=destination,
    restore_tec_tac=True,
    context={...},
)
```

Restore is a dangerous Core operation. Remote archives are downloaded into a
protected local staging directory first. Before any destructive work Core
validates:

- regular `.tar` archive and configured size limit;
- safe member paths/types;
- Tactical PostgreSQL dump;
- Tactical `local_settings.py`, systemd, MeshCentral and conf.d members;
- optional Tec-Tac manifest and member checksums.

The helper preserves the existing `/rmm` tree outside `/rmm`, runs Tactical's
official `restore.sh` as the configured Tactical installation owner, then (when
requested) restores the Tec-Tac payload, runs the framework/UI reintegration
installers, checks nginx and verifies Tactical/Tec-Tac runtime services.

A restore job is persisted before dispatch and final success is written only
after the restore and post-restore verification finish.

## Tec-Tac payload

When `include_tec_tac=True`, the Tactical archive receives:

```text
tec-tac/
├── manifest.json
├── backend.tar.gz
├── ui-source.tar.gz
├── state.tar.gz
├── etc.tar.gz
└── nginx/
    └── tec-tac.conf
```

Core resolves source/runtime paths from `/opt/tec-tac/etc/tec-tac.conf`; it does
not assume the framework checkout lives at one fixed path. `manifest.json`
records format/framework/UI versions, source paths, creation time and SHA-256 +
size for every Tec-Tac payload member.

Tec-Tac does **not** create another PostgreSQL dump. Tec-Tac models already live
inside Tactical's `tacticalrmm` database and Tactical `backup.sh` owns that dump.

## Destinations

Supported typed destination types:

```text
local
sftp
ftp
scp
webdav
s3
```

Local copies use filesystem operations and are restricted to Core's configured local destination allow-list (`TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS`, defaulting to `/rmmbackups,/mnt,/media,/srv,/backup,/backups`). SFTP, FTP, WebDAV and S3/S3-compatible
storage use Core-generated temporary `rclone` configuration. SCP uses dedicated
`scp`/`ssh` operations and requires a private key secret. Remote path values are
normalized and are never interpolated into a local shell command.

Remote adapters require the relevant server tools (`rclone` for its adapters;
`ssh`/`scp` for SCP). Missing tooling fails the requested destination rather
than silently falling back to another transport.

## Secrets

Modules persist only opaque `secret_ref` values. Core additionally exposes:

```python
secret_ref = backup.store_secret(secret={...}, context={...})
backup.delete_secret(secret_ref=secret_ref, context={...})
```

Secret files live below:

```text
/var/lib/tec-tac/server-backup/secrets/
```

and are root-owned mode `0600`. Raw credentials are moved out of the transient
job before detached execution, are never returned by list/backup operations and
must never be written to module/browser logs.

Common fields include `password`, `private_key`, `access_key` and `secret_key`.

## Retention

```python
backup.apply_retention(
    policies=[{
        "destination": destination,
        "keep_daily": 14,
        "keep_weekly": 8,
        "keep_monthly": 12,
        "keep_unclassified": 3,
    }],
    context={...},
)
```

Classification comes from the `.tectac.json` sidecar and is not inferred from
age. Retention is evaluated independently per destination. Removing a local
copy does not implicitly remove a remote copy.

## Scheduling

Core does not create cron entries for Backups. The Backups module registers
`backups.create` and `backups.retention` with the shared Tec-Tac Scheduler. The
server-backup capability performs exactly one requested operation.

## Audit context

Every privileged job stores only the standard source context:

```text
source_module
source_action
source_run_id
requested_by
```

This lets module/Scheduler history correlate an operation without exposing
provider-private objects or credentials.
