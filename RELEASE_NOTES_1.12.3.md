# Tec-Tac Framework 1.12.3

Corrective release for the offline System Updates path.

## Fixed

- Removed the stale hardcoded framework-version assertion from `install.sh`. Developer-contract verification now derives the expected framework version from the package `VERSION` file.
- Added a regression guard so future releases fail packaging tests if a fixed `1.x.y` contract-version assertion is introduced again.
- Added a bounded installer timeout to System Updates so a hung framework/UI installer cannot leave a job running indefinitely.
- Strengthened post-install verification before an offline update can be marked successful:
  - deployed `VERSION` matches the inspected package version;
  - deployed `tec_tac_package.json` matches the same version;
  - Django system checks pass;
  - Tec-Tac framework migrations are fully applied;
  - the System Updates route resolves;
  - the public contract catalog reports the installed framework version;
  - recovery scripts remain executable.
- Strengthened UI post-install verification for future UI updates by validating the deployed `VERSION` file and non-empty `index.html`, not merely the existence of the source checkout.
- Existing backup/rollback behavior remains authoritative: any installer or post-install verification failure marks the update failed and restores the previous component backup.

## Operational note

Warnings from migrations belonging to separately installed extension apps (for example migration drift in `tec_tac_alerts`) are not treated as framework migration failures. Extension migrations remain owned by their module packages.
