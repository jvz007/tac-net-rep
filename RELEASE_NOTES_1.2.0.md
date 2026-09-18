# Tec-Tac backend/framework 1.2.0

## Module discovery

Adds an authenticated installed-module catalog that reports first-class extension/ReportSet pairs, optional runtime UI metadata, permission groups, protected framework entries, and the legacy compatibility plugin.

## Package inspection and staging

The module API accepts `.zip`, `.tar.gz`, and `.tgz` uploads for pre-install inspection. Validation includes:

- 100 MiB upload limit
- 512 MiB expanded-content limit
- archive member-count limit
- path traversal rejection
- symbolic/hard link rejection
- special tar-file rejection
- exactly one matching extension + ReportSet pair
- Tec-Tac registry validation
- aligned extension/ReportSet versions for UI-driven installation
- optional `tec_tac_ui.json` entry/path validation
- UI permission references must be declared by the extension

## Privileged lifecycle worker

`install.sh` installs `/usr/local/sbin/tec-tac-module-job` as root and creates a narrow sudoers dispatch rule for the Tactical service account. The Django API writes a UUID job and never receives arbitrary root command execution. The helper claims staged packages, runs the existing install/remove lifecycle scripts in a detached root process, records job state/logs, and survives Tactical restarts.

Lifecycle scripts are required to be root-owned and not group/world writable before the helper executes them.

## Authorization

- module catalog: authenticated Tactical user
- install/replace/remove/job operations: Tactical `can_do_server_maint` or effective superuser

The UI-driven remove operation preserves database data. Purge remains manual.

## UI synchronization

After a successful install/remove job, the worker runs `/opt/tec-tac-ui/scripts/sync-modules.sh` when present so the deployed runtime module manifest follows the installed backend tree.

## No Tactical tracked-source edits

The framework continues to register routes through the ignored bootstrap/local settings mechanism.
