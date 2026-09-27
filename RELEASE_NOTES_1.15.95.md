# Tec-Tac Core 1.15.95

## Review scope

- **D2 / M25:** Restoring an older backup can no longer disable D1 superuser-account protection that was enabled later on the target. The restore merge uses stricter-wins semantics (`on` wins), fails closed for malformed policy data, and records the merge in both root-owned account-policy and recovery audit logs.
- **D2 / L75:** The current target publisher set is authoritative during restore. Publisher/key state on the target overwrites restored copies, and publishers removed from the target after the backup are removed from the restored trust set instead of being resurrected.

## Regression coverage

- Extended `tests/server-backup-d2-d3.py` with behavioural restore-security coverage for revoked keys, deleted publishers, stricter trust floors, D1 account-protection merge, and restore audit records.
- Recovery signer trust remains separate and target-local.
