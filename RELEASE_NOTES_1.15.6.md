# Tec-Tac Framework 1.15.6

## Server backup safety

- Bumps `core.server_backup` to capability version 1.4.0.
- Validates the exact Tactical-native `rmm-backup-*.tar` immediately after `backup.sh` completes and before hashing, recovery-bundle finalisation, or destination upload.
- Deletes a newly-created Tactical native archive when mandatory validation fails, and fails the complete backup operation.
- Adds a narrowly allow-listed Tactical backup privilege bridge for the root-owned nginx/systemd/conf.d and optional certificate/`/opt/tactical` material required by current Tactical `backup.sh`, without granting generic passwordless shell/cp/tar access.

## Restore override policy

- Adds per-check restore override support, initially only for `target.os`.
- Validation check results advertise whether a check is overrideable.
- Accepted overrides are persisted as protected audit records containing accepting user, timestamp, backup reference, restore mode, check id, original failure detail, source context, and a binding fingerprint.
- `validate_restore(..., overrides=["target.os"])` returns the persisted audit token in `accepted_overrides`.
- `restore_backup(..., overrides={"target.os": audit_id})` reruns target preflight and honours only a matching persisted token.
- Destructive restore now blocks on target-preflight failures before stopping services or moving the live Tactical tree.
- Artifact integrity failures are never overrideable.
