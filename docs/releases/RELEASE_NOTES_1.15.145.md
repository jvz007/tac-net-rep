# Tec-Tac Core 1.15.145

## Backup and restore closure

This release closes the remaining review-evidence gaps for M19, L10, L14, L15 and L76 without changing already-correct production behavior.

- M19: executable regression verifies native Tactical staging tar cleanup after a later backup failure and verifies non-manager repository synchronization errors remain redacted while managers retain diagnostic detail.
- L10: failure-injection coverage verifies archive publication cannot complete before its metadata sidecar and that FTP rolls back a newly published sidecar if final archive publication fails.
- L14: executable coverage verifies backup, maintenance and recovery-key helpers resolve the installer-selected custom configuration through the fixed root-owned config pointer and reject a symlinked pointer.
- L15: executable restore-preflight coverage proves rollback host-snapshot bytes materially affect the free-space decision.
- L76: executable coverage verifies isolated Python, config-derived recovery trust roots, and no-follow/root-owned recovery identity reads.

The closure regression is `tests/backup-closure-1.15.145.py` and is wired into the normal server-backup foundation.
