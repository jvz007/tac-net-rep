# Core privileged server backup capability

**Framework baseline:** 1.15.2+

Tec-Tac Core exposes one narrow privileged recovery contract:

```text
core.server_backup
capability version 1.2.0
```

Modules request typed backup, inventory, restore, retention, destination-validation and secret-store operations. They never receive arbitrary `sudo`, shell, executable-path or unrestricted filesystem access.

```python
from tec_tac.capabilities import get_capability

backup = get_capability(
    "core.server_backup",
    version=">=1.2.0,<2.0.0",
)
```

## Security boundary

Django/Celery writes a validated opaque job below `/var/lib/tec-tac/server-backup/jobs/` and may sudo only:

```text
/usr/local/sbin/tec-tac-server-backup --dispatch <UUID>
```

The root-owned helper validates job ownership/mode, operation allow-list and typed arguments, then runs the worker independently through systemd. No public operation accepts a browser/module supplied command or executable path. Backup/restore mutation uses a Core lock. Remote restores are fully downloaded and validated before destructive work begins.

## Recovery bundle format

Core 1.2 no longer modifies Tactical's native backup archive. The portable artifact is:

```text
tec-tac-backup-YYYY_MM_DD__HH_MM_SS.tgz
├── manifest.json
├── checksums.sha256
├── tactical/
│   └── rmm-backup-YYYY_MM_DD__HH_MM_SS.tar
└── tec-tac/
    └── tec-tac-backup.tar.gz
```

The Tactical member is byte-for-byte the exact archive created by `/rmm/backup.sh`. Core hashes it before bundling and verifies the copied inner member against that same SHA-256. It is never appended to, unpacked/repacked, or otherwise changed.

The Tec-Tac component contains resolved framework runtime/source, UI source, persistent state, `/etc/tec-tac`, installed module/runtime state and Tec-Tac nginx configuration. Active backup jobs/logs/staging/locks are excluded. No second PostgreSQL dump is created because Tec-Tac Django tables already live in Tactical's `tacticalrmm` database dump.

`manifest.json` is format version `2` and records selected components, hashes/sizes, framework/UI versions, resolved Tec-Tac paths, backup class, creation time and supported recovery modes. `checksums.sha256` records the component hashes.

## `create_backup(...)`

```python
result = backup.create_backup(
    backup_class="daily",            # daily|weekly|monthly|manual
    destinations=[...],
    include_tactical=True,
    include_tec_tac=True,
    context={...},
)
```

Both include flags are booleans and at least one must be true. Tactical backup creation always uses the current `/rmm/backup.sh` as the Tactical installation owner, without `--auto` or `--schedule`. Core does not reimplement Tactical backup logic.

The completed outer `.tgz` is hashed once and the same artifact is copied to every selected destination. Each destination also receives the small `.tectac.json` inventory/retention sidecar. Any requested destination failure fails the overall operation while preserving per-destination results.

## `list_backups(...)`

```python
rows = backup.list_backups(destinations=[...], context={...})
```

Version-2 inventory rows expose:

```text
format_version
components
tactical/tec_tac included flags
recovery_modes
backup_class
sha256
size/timestamps/destination metadata
```

Legacy native `rmm-backup-*.tar` files may remain visible but are explicitly marked `legacy: true`, `format_version: 1`, and advertise `recovery_modes: ["tactical"]`. Core never silently treats them as version-2 full bundles.

## `restore_backup(...)`

```python
result = backup.restore_backup(
    backup_ref="destination:3:tec-tac-backup-2026_09_20__09_15_00.tgz",
    destination=destination,
    restore_mode="full",             # full|tactical|tec_tac
    context={...},
)
```

Before restore Core validates the outer archive, safe member paths/types, root manifest/checksum records, requested component hash/size and the selected inner archive format. Components not required by an emergency restore mode are not extracted or hashed, but their manifest/checksum declaration must still be structurally valid.

### `full`

Requires Tactical + Tec-Tac. Core extracts the exact native Tactical `.tar`, preserves the existing Tactical tree, runs Tactical's official `restore.sh` against that exact file, restores the independent Tec-Tac component, runs framework/UI reintegration, validates nginx and verifies runtime health.

### `tactical`

Requires Tactical only. Core runs Tactical's official restore and verifies the standard Tactical frontend/services. It does **not** restore Tec-Tac files or run Tec-Tac reintegration. A corrupt unused Tec-Tac component cannot block this emergency Tactical-only path.

Legacy native Tactical archives can only use this mode.

### `tec_tac`

Requires Tec-Tac only. Core does not run Tactical `restore.sh`, does not replace the Tactical PostgreSQL database, restores Tec-Tac code/config/state and reruns framework/UI integration against the existing Tactical installation. If Tec-Tac database tables themselves need recovery, use `full`/`tactical` because those tables live in Tactical's database dump.

For compatibility with 1.0/1.1 callers, the provider still accepts `restore_tec_tac=True|False` and maps it to `full|tactical`; new modules must use `restore_mode`.

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

Local paths remain restricted by `TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS`.

- SFTP, WebDAV and S3/S3-compatible use Core-generated temporary `rclone` configuration.
- SCP uses dedicated `ssh`/`scp`, private-key secrets and host-key policy/fingerprint checks.
- FTP/FTPS uses Python's standard-library `ftplib` and does not require rclone.

FTP TLS modes currently accepted:

```text
none
explicit
starttls
tls        # compatibility alias for explicit FTPS
```

Implicit FTPS is intentionally not advertised until Core provides a dedicated correct implicit-TLS connection path.

The native FTP adapter implements path preparation, upload, listing/stat, download, deletion and the validation round trip. Remote paths are normalized and are not interpolated into a local shell command.

## Secrets

Modules persist only opaque `secret_ref` values:

```python
secret_ref = backup.store_secret(secret={...}, context={...})
backup.delete_secret(secret_ref=secret_ref, context={...})
```

Secret files live below `/var/lib/tec-tac/server-backup/secrets/`, are root-owned mode `0600`, and raw credential material is never returned in normal backup/inventory/validation results or logs.

## Destination validation

```python
result = backup.validate_destination(destination=destination, context={...})
```

Validation creates a job-unique `.tectac-validation-<uuid>.bin`, performs a real write/read/SHA-256/delete round trip and reports:

```text
configuration
connection
authentication
path_access
write
read
integrity
delete
```

A delete/cleanup failure makes validation fail because normal retention requires delete permission. `ServerBackupError.result` preserves the structured partial result. FTP validation uses the same native ftplib adapter as real FTP backup operations; SFTP/WebDAV/S3 and SCP use their normal adapters.

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

Retention operates on the **outer recovery bundle as one object**. Deleting a recovery bundle also deletes its `.tectac.json` sidecar. Inner Tactical/Tec-Tac members are never independently deleted. Classification remains sidecar-driven and independent per destination.

## Scheduling and audit

Core creates no backup cron entries. The Backups module registers its actions with the shared Tec-Tac Scheduler. Every privileged job retains the standard source context:

```text
source_module
source_action
source_run_id
requested_by
```


## Non-destructive restore validation (1.3.0)

`validate_restore()` runs the same artifact validation used before destructive restore without crossing the mutation boundary:

```python
report = backup.validate_restore(
    backup_ref="destination:3:tec-tac-backup-2026_09_20__08_24_22.tgz",
    destination=destination,
    restore_mode="full",   # full | tactical | tec_tac
    context=context,
)
```

The operation may download/copy the selected recovery object to Core-owned staging, read/verify archives, probe read-only host metadata and delete only its own staging directory. It must not stop/restart services, invoke Tactical `restore.sh`, mutate databases, move live Tactical/Tec-Tac trees, run package installation, migrations or integration installers, or change nginx/systemd/network state.

The report separates `artifact_valid` from `target_ready`. `ok` is true only when both are true. This deliberately allows a dev/live server to prove that a bundle is structurally and cryptographically valid even when the current host is not a suitable restore target.

For `tactical` mode only the Tactical component is hashed/validated; an unused corrupt Tec-Tac component does not fail the artifact result. `tec_tac` behaves symmetrically. Legacy native `rmm-backup-*.tar` files are valid only for `tactical` mode.

Current Tactical compatibility reporting tracks the inspected upstream baseline of backup script v34 and restore script v67. Target preflight is read-only and covers OS/architecture, memory, staging disk space, required executables, Tactical identity/current installation requirements, DNS needed by the current Tactical restore path, and whether another Core backup/restore mutation is active.
