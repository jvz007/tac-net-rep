# Tec-Tac Framework 1.15.60

## Administrative MFA recovery lifecycle

- Added an account-admin endpoint for MFA recovery status at `GET /api/tfd/access/users/<user_id>/mfa/`.
- Added `DELETE /api/tfd/access/users/<user_id>/mfa/` to invalidate all Tec-Tac backup codes for a selected Tactical user.
- The administrator endpoint never exposes backup-code plaintext or hashes; generation and rotation remain self-service and require the user's current password + TOTP proof.
- Protected/root/superuser accounts require effective superuser authority for destructive recovery-code invalidation.
- Added a reusable account-security authorization helper while retaining the existing login-session authorization contract.
- Explicit invalidation is audited, including zero-row invalidation attempts, without recording recovery-code material.
- Existing TOTP fingerprint binding remains authoritative: resetting/changing TOTP makes codes bound to the old key unusable.
