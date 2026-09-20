# Tec-Tac Framework 1.15.10

- Fixes Core server-backup privileged nginx collection when Tactical nginx `sites-enabled` entries are symlinks.
- Only the fixed `rmm.conf`, `frontend.conf`, and `meshcentral.conf` sources may use this resolver.
- The symlink is resolved strictly and the final target must be a regular file beneath `/etc/nginx/sites-available`; all other privileged sources retain the existing no-symlink policy.
- The copied workspace member keeps the original Tactical filename and the existing Tactical UID/GID + `0600` ownership/readability guarantees.
- `validate_tactical_native_archive()` remains unchanged as the final native-archive trust boundary.
- `core.server_backup` capability version is 1.4.2.
