# Tec-Tac Core 1.15.140

## Backup, recovery, and System Update hardening

- L17: Server backup creation, restore allow-listing, and pre-restore host rollback now honor `TEC_TAC_MODULE_STATE_ROOT` for `module-state.json` and repository configuration instead of assuming `<TEC_TAC_STATE_ROOT>/module-manager`.
- L76: `tec-tac-recovery-key` now starts with isolated `/usr/bin/python3 -I`, resolves recovery signing/trust paths from the root-owned Tec-Tac config, and reads local installation identity/public-key material through bounded no-follow descriptors with root ownership and mode validation.
- L77: `/usr/local/sbin/tec-tac-recovery-key` is now part of the Tec-Tac privileged host rollback inventory. The rollback regression no longer carries a recovery-key exception.
- L78: System Update captures the Tactical result-file group before mutation and reuses it during finalization; the `finally` path no longer re-reads configuration or account identity after an update failure.

## Regression coverage

- Added `tests/backup-recovery-system-update-1.15.140.py` and wired it into the recovery foundation.
- The regression exercises custom module-state layouts, isolated/config-derived recovery-key trust, symlink/writable identity rejection, recovery-key rollback coverage, and a forced System Update failure where config becomes unreadable after startup but the terminal failed state is still persisted.

No database migration is required.
