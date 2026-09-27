# Tec-Tac Core 1.15.136

## Module install hardening

- **L55:** Module v2 bundle extraction now rejects aliased ZIP member paths such as `./x.zip`, duplicate canonical paths, and symlink entries before extraction, so an alias cannot overwrite a root-verified child artifact.
- **L56:** Root-private Module v2 running requests and `.claimed` bridge directories are cleaned even when immutable artifact snapshotting or root trust verification fails before lifecycle execution starts.
- **L57:** System Update validates staged preview component identity before copying/consuming the staged package or detached sidecars. A component mismatch leaves the staged bytes intact.
- **L58:** The privileged publisher verifier now resolves `TEC_TAC_FRAMEWORK_ROOT` from the root-owned Core config and validates the actual configured ancestor chain instead of assuming `/opt/tec-tac`.
- **L59:** Tactical account/role mutations wrapped by Core now defer Tactical's `sync_mesh_perms_task` through `transaction.on_commit`, so Mesh permission synchronization is not queued before the enclosing Core guard transaction commits.

## Regression coverage

- Added `tests/module-install-hardening-1.15.136.py` and wired it into `tests/module-management-foundation.sh`.
- Extended `tests/tactical-superuser-guard.py` with commit-aware Mesh permission task coverage.
- Existing Module v2 signed-bundle/verified-byte, System Update staged-claim, privileged-helper environment, and Access Security regressions remain green.

No unrelated tracker findings are included in this release.
