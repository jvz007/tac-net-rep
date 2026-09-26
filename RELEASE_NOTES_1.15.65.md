# Tec-Tac Framework 1.15.65

## Server-backup privileged transport hardening

- Removed caller-environment control of the privileged server-backup config path; the root helper now reads layout only from the fixed root-owned `/opt/tec-tac/etc/tec-tac.conf`.
- The root config, when present, must be a regular non-symlink file owned by root and not group/world writable.
- Privileged filesystem roots loaded from config must be absolute paths.
- FTP destinations now default to explicit FTPS instead of plaintext FTP.
- FTPS uses a normal CA/hostname-verifying TLS context (`ssl.create_default_context()`).
- Plaintext FTP (`tls_mode=none`) is rejected unless the destination explicitly sets `allow_insecure_transport: true`.
- WebDAV over `http://` is rejected unless the destination explicitly sets `allow_insecure_transport: true`; HTTPS remains the normal path.
- Existing SFTP/SCP strict host-key defaults and S3 behavior are unchanged.

No public `core.server_backup` method signature changed.
