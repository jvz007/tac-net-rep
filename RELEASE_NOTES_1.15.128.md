# Tec-Tac Core 1.15.128

## Review batch: M19 + L09–L13

### M19 — backup cleanup and repository error disclosure

- Native Tactical `rmm-backup-*.tar` output is now cleaned in the create-backup transaction `finally` path, so a later Tec-Tac component, bundle, validation or destination failure cannot leave the native staging archive behind in `/rmmbackups`.
- Non-module-managers no longer receive raw module-repository `sync.error` text. Repository status and online-catalog responses retain the error state but replace internal transport/parser details with a bounded generic message.

### L09 — keep local staging when remote verification is weak

- Core deletes its local recovery bundle only when every requested destination reports both size verification and SHA-256 verification.
- A provider that can verify only remote size may still complete the copy, but Core keeps the local bundle and records `local_staging_retained_reason` instead of deleting the only strongly verified copy.

### L10 — publish metadata before archives

- Local, FTP, SCP and rclone-backed destinations now publish the `.tectac.json` sidecar before making the final archive visible.
- rclone/FTP/SCP failure paths remove a newly published sidecar when final archive publication fails.
- This prevents a newly published recovery archive from appearing without its required sidecar.

### L11 — preserve numeric ownership during safe extraction

- Tec-Tac recovery extraction still uses Python's `tarfile.data_filter` safety policy, but now restores the accepted member's numeric uid/gid metadata afterward so `numeric_owner=True` remains effective.

### L12 — FTP transport mode must be explicit

- FTP destinations without `tls_mode` are now rejected as ambiguous instead of silently switching legacy FTP records to explicit FTPS.
- Operators must choose `explicit`/`starttls`/`tls`, or choose `none` together with `allow_insecure_transport=true`.

### L13 — invalid helper config no longer crashes import

- Server backup and server maintenance helpers defer invalid root-owned configuration failures until the privileged operation calls `load_config()`.
- Imports and diagnostics remain available, while privileged work still fails closed and never falls back to attacker-controlled environment paths.

## Regression coverage

- Added `tests/review-batch-1.15.128.py` covering M19 and L09–L13.
- Updated the FTP transport regression to require an explicit TLS mode.
- Updated backup hardening coverage for the ownership-preserving safe tar filter.
