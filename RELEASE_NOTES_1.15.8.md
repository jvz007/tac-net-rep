# Tec-Tac Framework 1.15.8

## Mixed multi-artifact module installation
- Multi-file Module Manager intake now accepts any mixture of standalone module packages and Tec-Tac bundle ZIPs.
- Bundle child packages are flattened into the same global dependency plan as standalone packages.
- Dependencies may cross artifact boundaries: a package in one bundle can satisfy a package in another bundle or a standalone upload.
- Duplicate module IDs across bundles/standalone packages are rejected before installation.
- Requested install order still applies to the flattened module list and Core continues to enforce hard dependency ordering.
- The privileged v2 worker expands each bundle into an isolated running directory and installs all resolved child packages through the existing sequential lifecycle/rollback path.
- Successful mixed batches clean both standalone staging records and bundle staging records.
- Batches staged by 1.15.7 and older remain supported.

## Cumulative 1.15.7 changes
- Retains Core Storage & Housekeeping inspection, dry-run/purge and protected-path retention controls.
- Retains Tactical restore `target.os` override execution with restore.sh v67 baseline pinning and fail-closed patching.
