# Tec-Tac Framework 1.4.0

Module Management v2 foundation release.

## Added

- Installed module enable/disable state persisted outside the Tactical source tree.
- Hard module dependencies with version constraints.
- Optional dependencies and runtime compatibility requirements.
- Multi-package and bundle inspection with dependency ordering.
- Batch/bundle lifecycle jobs with code/state rollback on failure.
- Dependency-aware enable, disable, remove checks, and dependant visibility.
- Module Management v2 API endpoints under `/api/tfd/modules/v2/`.
- Privileged v2 lifecycle worker for enable/disable and bundle orchestration.

## Compatibility

- Existing installed modules default to enabled when no explicit module-state record exists.
- Database migrations applied by a module are deliberately not automatically reversed during bundle rollback.
- Tec-Tac UI 0.4.0 is the matching Module Management v2 user interface.

## Known issue corrected in 1.4.1

The initial 1.4.0 packaging used restrictive permissions for `/var/lib/tec-tac/module-manager/module-state.json`. Tactical processes running under service identities other than the primary Tactical user could fail during Django/ASGI startup with `PermissionError`. Upgrade to Framework 1.4.1.
