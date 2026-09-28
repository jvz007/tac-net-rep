# FIXING.md — Core 1.15.147

## Scope

Review closure release for **L47 + L48 + L49 + L88 + L89** from the Core/UI tracker.

The review-passed 1.15.146 production MFA behavior already implements the intended security boundaries. This release deliberately avoids unrelated production changes and adds executable closure coverage against the real MFA admin/login functions.

- L47: protected-account authorization is behaviorally proven to run before any administrator status read.
- L48: administrator GET status is behaviorally proven read-only: no stale-code deletion and no mutation audit.
- L49: automatic TOTP-change invalidation and explicit administrator invalidation are behaviorally proven to emit distinct audit events.
- L88: the tight per-username backup-code attempt slot is behaviorally proven to be reserved before recovery-code verification, so the sixth concurrent-like attempt is rejected before verification.
- L89: wrong-password failures are behaviorally proven to use only the separate looser password-failure bucket, while correct-password/wrong-code attempts consume only the tight recovery-code bucket.

## Validation intent

- execute the real AdminUserMfaRecoveryView GET method with narrow Django/DRF test doubles;
- execute the real backup_code_status, automatic stale-code invalidation, and explicit invalidation functions;
- execute the real BackupCodeLoginView.post method across wrong-password, wrong-code, and rate-limited paths;
- keep the closure regression in the normal Access/MFA foundation.
