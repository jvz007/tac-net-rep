# Tec-Tac 1.3.0

## System update lifecycle

Tec-Tac 1.3.0 adds a privileged self-update subsystem for the framework and standalone UI.

### Update sources

- Offline repository archives: `.zip`, `.tar.gz`, `.tgz`.
- Latest GitHub release for the configured framework/UI repositories.
- Explicit GitHub branch builds. Branches are resolved to a commit SHA before download so the staged package is deterministic even if the branch moves later.

Normal GitHub "Download ZIP" / source archives are accepted. A single GitHub wrapper directory is detected automatically; users do not need to repackage the repository.

### Safety model

- The Tactical web process performs only discovery, download, inspection, staging, and job creation.
- Privileged replacement is performed by `/usr/local/sbin/tec-tac-system-update`.
- The update worker is launched as an independent transient systemd service so framework installation may restart Tactical without killing the updater.
- Only one system update may run at a time through `/var/lib/tec-tac/system-updates/update.lock`.
- Every update backs up the current component before replacement.
- Failed installs automatically restore the previous code/UI backup and rerun the previous installer.
- Installed extension/reportset directories are preserved during framework updates unless the directory is framework-owned (`example`, legacy `reporting`, reference reportset).
- Downgrades require explicit confirmation.

Database migrations performed by an installer are not automatically reversed by the code rollback mechanism. A rollback restores the component repository and reruns its installer; administrators should retain normal Tactical/database backups for updates that introduce schema changes.

### API

- `GET /api/tfd/system/updates/`
- `POST /api/tfd/system/updates/packages/inspect/`
- `DELETE /api/tfd/system/updates/packages/<upload-id>/`
- `POST /api/tfd/system/updates/packages/<upload-id>/install/`
- `GET /api/tfd/system/updates/jobs/<job-id>/`
- `GET /api/tfd/system/updates/online/?component=framework|ui`
- `GET /api/tfd/system/updates/branches/?component=framework|ui`
- `POST /api/tfd/system/updates/online/stage/`

System update operations require Tactical `can_do_server_maint` or effective superuser access.

### Repository configuration

`install.sh` creates `/etc/tec-tac/system-update.conf` with defaults:

- framework: `jvz007/tac-net-rep`
- UI: `jvz007/tec-tac-ui`

Public repositories require no credential. Private repositories can use a root-only token stored in `/etc/tec-tac/github-token`; the token is read server-side and is never exposed to the browser.

### Package metadata

Repository archives remain valid without extra packaging. Tec-Tac 1.3.0 also recognises optional `tec_tac_package.json` metadata for component identity, version and compatibility requirements.
