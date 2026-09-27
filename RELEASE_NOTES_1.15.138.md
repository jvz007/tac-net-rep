# Tec-Tac Core 1.15.138

## Housekeeping and backup preflight/test hardening

- **L40:** Housekeeping request opens now use `O_NOFOLLOW|O_NONBLOCK`, so FIFO substitutions are rejected as non-regular files without blocking the privileged helper.
- **L41:** The housekeeping claim-security regression is now pytest-discoverable through `tests/test_housekeeping_claim_security.py` while retaining the existing standalone behavioral test.
- **L14:** The installer persists its selected `TEC_TAC_CONFIG_FILE` path in `/etc/tec-tac/config-path`. Server-backup and server-maintenance helpers resolve that root-owned, non-writable pointer instead of assuming `/opt/tec-tac/etc/tec-tac.conf` or trusting a sudo environment variable.
- **L15:** Restore target disk preflight now includes the estimated bytes required for the host-path rollback snapshot in addition to staged/extracted bundle space.
- **L16:** The rollback regression now discovers privileged Tec-Tac installer literals from `install.sh`, so newly introduced `/usr/local/{lib,sbin}/tec-tac*` or `/etc/sudoers.d/tec-tac*` targets fail until rollback coverage is reviewed. The already-tracked L77 recovery-key gap remains an explicit exception and is not changed in this release.

## Regression coverage

- Added `tests/housekeeping-backup-hardening-1.15.138.py`.
- Added pytest discovery for the existing housekeeping claim-security test.
- Extended `tests/server-backup-host-rollback.py` so new installer targets cannot silently escape rollback coverage.
- Existing server-backup, server-maintenance, housekeeping, transport-security and layout regressions remain green.

No unrelated tracker findings are included in this release.

## Rebuild 1

- Removed generated `.pytest_cache` release junk so the packaged source tree matches the signable Git tree.
- No production logic changes from 1.15.138.
