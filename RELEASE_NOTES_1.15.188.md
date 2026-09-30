# Core 1.15.188

## AD-3 seamless backup restore

- Replaces the recovery signing/trust design with an adjacent `<archive>.sha256` integrity companion.
- New backups are not signed and Core no longer exposes a recovery-signer trust workflow or recovery-key export/import path.
- Local, FTP, SCP and rclone-backed destinations publish `<archive>.sha256` next to every recovery archive and `.tectac.json` sidecar.
- Restore validation and destructive restore verify the companion when present; malformed or mismatched hashes stop the operation.
- Older backups without a companion remain restorable and are reported as `not_verified`; destructive restore records that state in the recovery audit.
- Older signed format-2 bundles remain readable and their embedded signature is verified without a replacement-server trust step.
- Backup inventory exposes source installation ID, server name, creation date and Core version.

Unsigned source delivery.

## Rebuild fix

- Fixes SHA-256 companion reads for SFTP, WebDAV and S3 restore sources by routing those destination types through the same rclone adapter used by backup storage, download and deletion.
- Keeps native SCP handling exclusive to `type == "scp"`.
- Adds regressions covering missing and present hash companions for SFTP/WebDAV/S3, plus validate-restore against an S3 destination with no companion.
