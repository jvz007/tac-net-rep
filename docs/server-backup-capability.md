# Core privileged server backup capability

**Framework baseline:** 1.15.5+

Tec-Tac Core exposes one narrow privileged recovery contract:

```text
core.server_backup
capability version 1.6.0
```

Modules request typed backup, inventory, restore, retention, destination-validation and secret-store operations. They never receive arbitrary `sudo`, shell, executable-path or unrestricted filesystem access.

```python
from tec_tac.capabilities import get_capability

backup = get_capability(
    "core.server_backup",
    version=">=1.4.0,<2.0.0",
)
```

## Security boundary

Django/Celery writes a validated opaque job below `/var/lib/tec-tac/server-backup/jobs/` and may sudo only:

```text
/usr/local/sbin/tec-tac-server-backup --dispatch <UUID>
```

The root-owned helper validates job ownership/mode, operation allow-list and typed arguments, then runs the worker independently through systemd. No public operation accepts a browser/module supplied command or executable path. Backup/restore mutation uses a Core lock. Remote restores are fully downloaded and validated before destructive work begins.

The privileged helper ignores process-environment attempts to redirect its config or state roots. Layout is read only from the fixed `/opt/tec-tac/etc/tec-tac.conf`; when present that file must be a regular root-owned non-writable file.

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

The Tec-Tac component contains resolved framework runtime/source, UI source, `/etc/tec-tac` and Tec-Tac nginx configuration. `/var/lib/tec-tac` remains a **default-deny recovery boundary**: Core retains only the two fixed durable Module Manager files `/var/lib/tec-tac/module-manager/module-state.json` and `/var/lib/tec-tac/module-manager/repositories/repositories.json`. Staged installers, update rollback trees, lifecycle history/logs, caches, validation staging, server-backup data and all other mutable state remain excluded so they cannot be recursively captured into later backups.

Scheduler schedules/configuration, dashboards and user preferences live in Tactical's `tacticalrmm` PostgreSQL database and are therefore protected by Tactical's native backup. The deployed UI below `/var/lib/tec-tac/ui/tec-tac` is rebuilt from the backed-up UI source during Tec-Tac reintegration. The retained Module Manager files reconstruct module enablement and repository configuration; installed module code remains in `/opt/tec-tac/extensions`.

No second PostgreSQL dump is created because Tec-Tac Django tables already live in Tactical's `tacticalrmm` database dump.

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

Requires Tec-Tac only. Core does not run Tactical `restore.sh`, does not replace the Tactical PostgreSQL database, restores Tec-Tac code/configuration and reruns framework/UI integration against the existing Tactical installation. Only the fixed durable Module Manager state files in the Tec-Tac component are eligible for restoration; all other `/var/lib/tec-tac` mutable runtime state is rebuilt. If Tec-Tac database tables themselves need recovery, use `full`/`tactical` because those tables live in Tactical's database dump.

For compatibility with 1.0/1.1 callers, the provider still accepts `restore_tec_tac=True|False` and maps it to `full|tactical`; new modules must use `restore_mode`.

## Mutable state allow-list

The Tec-Tac component records an explicit state policy in its manifest:

```json
{
  "state_policy": {
    "state_root": "/var/lib/tec-tac",
    "included": "allow-list",
    "included_paths": [
      "/var/lib/tec-tac/module-manager/module-state.json",
      "/var/lib/tec-tac/module-manager/repositories/repositories.json"
    ]
  }
}
```

The manifest list is descriptive, not authoritative. Restore validation uses Core's own fixed durable-state allow-list and always protects the canonical `/var/lib/tec-tac` boundary even if manifest metadata claims another state root. Only the two durable Module Manager files are accepted beneath that boundary; directories, caches, history, staging, system-update rollback data, server-backup data and any future mutable state remain rejected by default.

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
explicit   # default
starttls
tls        # compatibility alias for explicit FTPS
none       # only with allow_insecure_transport: true
```

FTPS uses normal CA and hostname verification. Plaintext FTP is never selected by omission; it requires the destination to explicitly set `allow_insecure_transport: true`. Implicit FTPS is intentionally not advertised until Core provides a dedicated correct implicit-TLS connection path.

WebDAV should use `https://`. Plain `http://` WebDAV is rejected unless the destination explicitly sets `allow_insecure_transport: true`. This override is intended for deliberate legacy/lab use and should not be used where credentials cross an untrusted network.

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

## Restore overrides and native-backup trust boundary (1.4.0)

`core.server_backup` 1.4.0 adds auditable per-check target overrides and tightens creation of Tactical-native backup components.

### Target-check overrides

Only checks explicitly advertised by Core are overrideable. The initial allow-list contains only `target.os`. Artifact-integrity checks are never overrideable.

A module first performs normal validation. Each check now reports `overrideable` and `overridden` metadata. To accept a failed OS check, repeat validation with the requested check id and an authenticated `context.requested_by`:

```python
report = backup.validate_restore(
    backup_ref=backup_ref,
    destination=destination,
    restore_mode="full",
    overrides=["target.os"],
    context={
        "source_module": "backups",
        "source_action": "restore.validate",
        "requested_by": username,
    },
)

audit_id = report["accepted_overrides"]["target.os"]
```

Core persists the accepted decision beneath its protected server-backup state. The audit record includes the accepting user, UTC timestamp, backup reference, restore mode, failed check id, original failure status/detail, source context and a fingerprint binding the decision to that exact validation condition.

The destructive restore must send the returned audit token:

```python
result = backup.restore_backup(
    backup_ref=backup_ref,
    destination=destination,
    restore_mode="full",
    overrides={"target.os": audit_id},
    context={
        "source_module": "backups",
        "source_action": "restore.execute",
        "requested_by": username,
    },
)
```

`restore_backup()` reruns target preflight before destructive mutation. An override is honoured only when the persisted audit record still matches the same backup reference, restore mode, check id and original failed detail. Stale/mismatched tokens are rejected. A restore with any remaining non-overridden target failure is blocked before Tactical services are stopped or the live tree is moved.

### Tactical native archive creation

Core now validates the exact `rmm-backup-*.tar` emitted by Tactical `backup.sh` immediately after creation and before SHA-256 calculation, recovery-bundle finalisation or destination upload. A failed native validation fails the backup job and the invalid native TAR is removed.

Tactical `backup.sh` v34 still uses `sudo` for a small fixed set of root-owned backup sources but does not fail closed when those commands fail. Core therefore supplies a narrow compatibility shim only while the Tactical backup is running. The shim can request only fixed collection operations for nginx configuration, Tactical systemd units, `/etc/conf.d`, optional `/etc/letsencrypt` and optional `/opt/tactical`. The privileged helper independently binds every request to the active opaque `create_backup` job and its job-owned Tactical temporary workspace. No caller-provided shell command, executable, arbitrary source path or arbitrary destination path is accepted.

## 1.15.7 restore-script OS override execution

When `target.os` has a valid persisted override audit ID, Core prepares a staged Tactical `restore.sh` before any destructive action. The patch is bound to the inspected Tactical restore baseline (`SCRIPT_VERSION=67`) and requires the exact known OS-support rejection block to occur once. Only that rejection block is removed; real `lsb_release` OS identity, release and codename variables remain unchanged and continue to drive repository/package logic.

If the restore-script version or expected OS-check block differs, Core aborts before stopping services or moving `/rmm`. Without an authorized `target.os` override, Core copies Tactical `restore.sh` byte-for-byte unchanged.


## Privileged Tactical collection ownership (1.4.1)

The narrow privileged bridge writes nginx, systemd, conf.d, certificate and `/opt/tactical` backup material as root, then atomically hands each completed workspace file to the configured Tactical service UID/GID with mode `0600`. Before returning success the helper verifies the exact owner/group and mode and confirms that no group/other permission bits are present. This is required because upstream Tactical `backup.sh` creates the native TAR as the Tactical account.

`validate_tactical_native_archive()` remains the authoritative post-collection trust boundary and is intentionally unchanged.


## Privileged nginx symlink handling (1.4.2)

Tactical nginx `sites-enabled` entries are commonly symlinks. Core permits symlink resolution only for the fixed allow-listed `rmm.conf`, `frontend.conf`, and `meshcentral.conf` collection operations. Each source is resolved with `strict=True`; the final target must be a regular file beneath `/etc/nginx/sites-available`. The workspace member keeps the original filename and the existing Tactical account ownership with mode `0600`. No general privileged source may bypass `ensure_regular()` or traverse arbitrary symlinks.


## Read-only job status (1.5.0)

Core exposes `get_job_status(job_id=..., source_run_id=..., context=...)` so modules never need direct access to `/var/lib/tec-tac/server-backup`. At least one lookup key is required; if both are supplied they must identify the same Core job. `source_run_id` is read from the normalized job context and is intended for module-owned run identifiers.

The response is intentionally small and sanitized: `job_id`, `source_run_id`, `status`, `action`, `stage`, `stage_label`, `started_at`, `finished_at`, `error`, `progress.current`, `progress.total`, and a bounded `log_tail`. Core strips common credential/token forms, URI passwords, authorization values, and private-key material before returning log or error text. Raw job requests, destination secrets, helper environment, and filesystem paths are not exposed.

`create_backup` now publishes durable progress stages through its Core job document: `prepare`, `tactical.backup`, `tactical.validate`, `tec_tac.backup`, `bundle.create`, `bundle.validate`, `destination.upload`, `destination.verify`, and `complete`. The privileged Tactical collector may temporarily publish narrower sub-stages such as `tactical.collect.nginx`, `tactical.collect.systemd`, `tactical.collect.confd`, `tactical.collect.letsencrypt`, and `tactical.collect.opt_tactical`. These are observational only and do not change the backup trust boundaries.


## Archive-namespace TAR link safety (1.5.1)

Tactical and Tec-Tac recovery TAR validation permits symbolic and hard links only when the member path and resolved link target remain inside the archive extraction namespace. Relative symlink targets are resolved from the link member's parent; hardlink targets are resolved from the archive root and must name an archive member. Absolute targets, namespace escapes, duplicate normalized paths, device/FIFO/socket entries and other special members remain rejected. This shared validation applies to Tactical native/nested archive validation and Tec-Tac recovery payload extraction.


## Canonical payload roots (1.6.0)

Tec-Tac recovery payload creation canonicalizes requested source roots before archiving. If a requested path is already recursively covered by an included ancestor directory, the child request is discarded. This prevents callers from emitting duplicate normalized TAR members while retaining duplicate-member validation as the final archive integrity check.

`create_tec_tac_component()` no longer explicitly includes `/opt/tec-tac/etc` because `/opt/tec-tac` already contains it recursively.


## 1.6.0 hardening

- Destructive Tactical/full restores take root-only PostgreSQL and fixed host-path snapshots before services are stopped. The host snapshot covers the Tactical nginx configuration, Let's Encrypt state, Tactical systemd units, MeshCentral, `/opt/tactical`, frontend state and other fixed restore targets. Full restore additionally snapshots Core-configured Tec-Tac runtime/source/UI state, `/etc/tec-tac`, the Tec-Tac nginx snippet and the fixed durable Module Manager state files. A restore or post-restore verification failure restores host paths, the original `/rmm` tree and databases before services are restarted. Tec-Tac-only restore uses the same host transaction without touching Tactical databases or moving `/rmm`. Snapshot targets are Core-fixed/root-config-derived; recovery-manifest paths are not used as rollback authority.
- Remote FTP/SCP/rclone uploads publish through `.partial` names and are renamed only after verification.
- Retention distinguishes missing metadata from unreadable metadata. Unreadable sidecars are protected fail-safe and reported rather than deleted. `keep_unclassified` must be explicit.
- SCP listing discovers both legacy `rmm-backup-*.tar` and Tec-Tac `tec-tac-backup-*.tgz` archives.
- Relative rclone remote paths remain relative.
- Command timeouts are wall-clock enforced even when a child process is silent; timeout kills the child process group.
- Tec-Tac recovery components retain an allow-list of durable state: module state, repository configuration and publisher trust. Cache/history/staging data remains excluded.

## Recovery-bundle authenticity and fixed restore destinations (Core 1.15.80)

Version-2 recovery bundles now carry a mandatory `recovery-signature.json` envelope. Core signs the exact `manifest.json` and `checksums.sha256` bytes with a server-specific Ed25519 recovery key stored at `/etc/tec-tac/recovery-signing/private.pem` (`root:root 0600`). The installer preserves an existing key across upgrades and creates one only when no recovery identity exists.

The signature envelope records the source installation key ID, public-key fingerprint and candidate public key. The candidate key is provided only for disaster-recovery portability; **it is never trusted automatically**. Restore verification loads the authoritative public key from the target server's root-owned `/etc/tec-tac/recovery-trust/<key-id>.pub`. A bundle from an unknown key is rejected until an administrator explicitly provisions the source public key into that trust store.

The source server trusts its own recovery public key automatically at installation, so locally created backups validate without an extra step. For replacement-server recovery, preserve or export `/etc/tec-tac/recovery-signing/public.pem` (public material only) and install it as `/etc/tec-tac/recovery-trust/<source-installation-id>.pub` on the recovery target after verifying its fingerprint out of band. The private recovery key is never required on the target.

Recovery signing and recovery trust are target-local security state. `/etc/tec-tac/recovery-signing` and `/etc/tec-tac/recovery-trust` are explicitly excluded from Tec-Tac recovery payloads and may not be restored from a bundle.

Before any Tec-Tac payload extraction, Core also enforces a fixed destination allow-list derived only from the target's root-owned Tec-Tac configuration plus fixed Core paths. Signed payload members such as `/etc/cron.d/*`, `/root/.ssh/*`, arbitrary systemd units, or recovery-trust/signing files are rejected. Manifest `paths` remain descriptive metadata only; post-restore framework and UI installers are selected exclusively from the target's root-owned local configuration.

This intentionally makes older unsigned version-2 Tec-Tac recovery bundles fail authenticity validation. Legacy native Tactical `rmm-backup-*.tar` remains supported only for `tactical` restore mode and does not gain Tec-Tac payload privileges.
