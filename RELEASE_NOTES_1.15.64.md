# Tec-Tac Framework 1.15.64

## Privileged server-maintenance trust-root hardening

- Removed process-environment control of the privileged server-maintenance helper's state root, action registry root, action executable root and Tec-Tac config path.
- The helper now reads optional layout overrides only from the fixed `/opt/tec-tac/etc/tec-tac.conf` root-owned configuration file.
- When present, that configuration must be a regular, non-symlink file owned by root and not group/world writable before any privileged path is accepted.
- Server-maintenance roots supplied by the root-owned config must be absolute paths.
- Existing registered-action validation, root-private job claiming, typed parameter validation, global locking, audit and detached execution behaviour are unchanged.
- Added regressions proving `TEC_TAC_SERVER_MAINTENANCE_*` and `TEC_TAC_CONFIG_FILE` environment variables cannot redirect privileged helper trust roots.

This release contains no public capability/API contract change.
