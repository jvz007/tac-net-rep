# Tec-Tac Core 1.15.183

## D3 / L10 tracker closure

This release adds explicit acceptance coverage for the two remaining backup/restore tracker rows without changing their already-reviewed production behavior.

- D3: the recovery signer regression is required to pass as an ordinary non-root CI user while retaining real signature/fingerprint verification, exact confirmation binding, trust-store mutation, downgrade continuity and recovery-security merge behavior.
- L10: the behavioral publication regression is promoted into the current acceptance runner and proves local, FTP, rclone and SCP publish the sidecar first, roll it back if archive publication fails, never leave a final archive without its sidecar, and leave both files on success.

The companion UI 0.12.74 moves recovery-signer confirmation/trust/revalidation into a directly testable workflow used by the real Backup & Restore view.
