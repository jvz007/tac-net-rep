# Tec-Tac Framework 1.15.1

## Remote backup destination validation

Framework 1.15.1 extends `core.server_backup` from capability contract 1.0.0 to
1.1.0 and adds the additive `validate_destination(...)` operation. Existing 1.x
operations are unchanged.

Validation uses the existing Core-owned destination, secret and transport
adapters and performs a job-unique write/read/SHA-256/delete round trip. It
returns structured stage status for configuration, connection, authentication,
path access, write, read, integrity and delete. Failures preserve the partial
result through `ServerBackupError.result`.

The root helper accepts only the typed `validate_destination` request and never
accepts a browser/module supplied command or executable. Validation objects are
`.tectac-validation-<job-uuid>.bin`, cleanup is attempted after intermediate
failures, and inability to delete/confirm cleanup makes validation fail.

Local destinations keep the existing Core allow-list. SFTP, FTP, WebDAV and S3
reuse the existing rclone adapter; SCP reuses the existing SSH/SCP private-key
and host-key verification path. Secret material is not included in results or
logs.
