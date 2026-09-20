# Tec-Tac Framework 1.15.2

## Recovery bundles and independent restore modes

Framework 1.15.2 advances `core.server_backup` to capability contract `1.2.0`.
The capability now creates an independent Tec-Tac recovery bundle instead of
appending Tec-Tac files into Tactical's native archive.

The portable artifact is:

```text
tec-tac-backup-YYYY_MM_DD__HH_MM_SS.tgz
├── manifest.json
├── checksums.sha256
├── tactical/rmm-backup-YYYY_MM_DD__HH_MM_SS.tar
└── tec-tac/tec-tac-backup.tar.gz
```

The Tactical archive inside the bundle is the exact byte sequence produced by
`/rmm/backup.sh`; Core does not append to it, unpack/repack it, or recompress it.
The root manifest and checksum file record the component hashes and sizes.

`create_backup(...)` now accepts `include_tactical` and `include_tec_tac`.
`restore_backup(...)` accepts `restore_mode="full"|"tactical"|"tec_tac"`.
A compatibility bridge still maps the old `restore_tec_tac=True/False` argument
to `full`/`tactical`, but new modules should use `restore_mode`.

- `full` runs Tactical's official restore against the native inner `.tar`, then
  restores/reintegrates the independent Tec-Tac component.
- `tactical` restores and verifies Tactical only and does not require a healthy
  Tec-Tac component.
- `tec_tac` restores Tec-Tac code/config/state and reintegrates it against the
  existing Tactical installation without replacing Tactical's PostgreSQL DB.

Inventory rows expose format version, component flags and supported recovery
modes. Legacy native `rmm-backup-*.tar` files remain explicitly marked legacy
and advertise Tactical-only recovery.

Retention applies to the outer recovery bundle and its `.tectac.json` sidecar.

## Native FTP/FTPS adapter

FTP no longer depends on rclone. Core uses Python `ftplib` for plain FTP and
explicit FTPS (`explicit`, `starttls`, and existing `tls` alias), including
path preparation, upload, listing, download, deletion and validation round
trips. Implicit FTPS is not advertised until a dedicated correct implicit-TLS
connection path is implemented.

SFTP, WebDAV and S3 keep the existing rclone-backed transport; SCP keeps the
existing SSH/SCP adapter.
