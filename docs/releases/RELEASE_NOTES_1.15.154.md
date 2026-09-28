# Tec-Tac Core 1.15.154

## Trust-policy state publication hardening

- Replaced fixed `update-trust-policy.json.tmp` and `pending-trust-policy-revert.json.tmp` paths in the root trust-policy CLI with unique same-directory `mkstemp` files.
- Atomic trust-policy and pending-revert writes now set the final mode on the open descriptor, fsync file data, atomically replace the destination, and fsync the containing directory.
- Replaced the installer trust-policy migration writer's PID-derived temporary filename with a unique same-directory `mkstemp` file so a pre-planted predictable path cannot block policy migration.
- Added executable regression coverage that plants the historical temporary paths as symlinks and verifies the protected target is not touched.

No public Core contract changes are introduced in this release.
