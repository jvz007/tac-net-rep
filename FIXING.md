# FIXING.md — Core 1.15.138

## Review scope

This release is intentionally limited to **L40, L41, L14, L15 and L16** from the current Core tracker.

### L40 — FIFO-safe housekeeping request open
Housekeeping request files are opened with `O_NOFOLLOW|O_NONBLOCK` and must pass an `fstat()` regular-file check before any read.

### L41 — pytest-discoverable claim regression
`tests/test_housekeeping_claim_security.py` exposes the existing behavioral claim-security test to normal pytest discovery.

### L14 — custom installer config path
The installer records the selected config location in the fixed root-owned `/etc/tec-tac/config-path` pointer. Privileged backup/maintenance helpers validate that pointer and use the selected config without trusting caller-controlled environment variables.

### L15 — host snapshot in disk preflight
Restore disk preflight adds an estimate of the existing host paths that will be copied into the pre-restore rollback snapshot.

### L16 — detect newly added installer rollback targets
The rollback regression discovers privileged Tec-Tac install literals from `install.sh` and requires rollback coverage for every newly introduced target. The existing L77 `/usr/local/sbin/tec-tac-recovery-key` gap remains an explicit known exception for its own tracker pass.

No other tracker findings are intentionally changed.
