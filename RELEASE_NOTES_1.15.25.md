# Tec-Tac Framework 1.15.25

## Managed module hotfix lifecycle

Framework 1.15.25 adds a Core-owned module hotfix system for urgent, bounded fixes that must be deployed before the next normal module release.

### Hotfix package contract

A hotfix ZIP contains exactly one `tec_tac_hotfix.json` and complete replacement files under `payload/extension/` or `payload/reportset/`.

Core requires:

- exact `module_id` and exact `base_version`;
- SHA-256 before/after values for every replaced file;
- targets to remain inside the owning module's extension/reportset roots;
- existing regular-file targets only;
- no symlinks, path traversal, migrations, lifecycle hooks or module-manifest replacement;
- no package-provided apply/revert scripts or arbitrary privileged commands.

### Lifecycle

Core now provides authenticated Module Manager endpoints to:

- inspect/stage a hotfix;
- discard a staged hotfix;
- apply a staged hotfix;
- inspect job status;
- list applied hotfixes for a module;
- roll back the latest hotfix for a module.

Apply and rollback execute through the new root-owned `/usr/local/sbin/tec-tac-module-hotfix` worker. The Tactical web process may only dispatch opaque job IDs through the installed sudoers rule.

Hotfix jobs share the global Tec-Tac lifecycle lock with normal module/system lifecycle operations.

### Safety and recovery

Before changing a file, the worker revalidates module version and `sha256_before`, creates a backup, performs atomic replacement, verifies `sha256_after`, and runs type-appropriate validation.

Python changes force Python compilation, `manage.py check`, and a graceful Django/uWSGI reload. UI payload changes force module UI synchronization. Failed application after mutation restores the original files and refreshes the runtime before the job is marked failed.

Rollback is reverse-order only and fails closed if current target files no longer match the applied-hotfix hashes.

### Normal module releases

A successful normal module install/replacement or removal supersedes active hotfix records for that module into hotfix history. Old hotfixes are never automatically replayed onto a new module version.

### Module catalogue

Module Management v2 catalogue rows now include a lightweight `hotfixes` summary (`count`, `ids`, `latest`) so support/UI tooling can identify a hotfixed runtime state without scanning files.

### Developer documentation

See `docs/module-hotfixes.md` for the complete package format, API contract, lifecycle, security model and module-agent rules.
