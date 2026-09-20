# Tec-Tac Framework 1.15.5

## Tec-Tac recovery payload state-root exclusion

- Tec-Tac recovery bundles no longer archive `/var/lib/tec-tac` at all.
- This prevents historical installers, update rollback trees, job logs, staging files and prior backup artifacts from being recursively captured into subsequent backups.
- The Tec-Tac component continues to include framework/runtime code, framework/UI source, Tec-Tac configuration and nginx integration required to rebuild the runtime after restore.
- Scheduler configuration, schedules, dashboards and user preferences remain protected by Tactical's native PostgreSQL backup because those records live in the Tactical database.
- The deployed Tec-Tac UI under `/var/lib/tec-tac/ui/tec-tac` is rebuilt from the backed-up UI source during restore rather than copied as mutable state.
- Module Manager state stored under `/var/lib/tec-tac/module-manager` is intentionally not restored; installed module code remains in `/opt/tec-tac/extensions`, and runtime state is rebuilt/defaulted by the framework installer.
- `core.server_backup` capability version is now `1.4.0` and recovery metadata records the excluded state-root policy.
- Restore validation now rejects a Tec-Tac component if it contains the excluded mutable state root.
