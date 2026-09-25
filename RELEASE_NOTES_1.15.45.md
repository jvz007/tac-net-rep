# Tec-Tac Framework 1.15.45

## Access security hardening

- Throttles MFA backup-code regeneration with Tactical login throttles and force-audits failed password/TOTP generation proofs.
- Binds backup-code sets to an HMAC fingerprint of the Tactical TOTP secret; changing/resetting TOTP invalidates the old recovery set. Existing pre-binding recovery codes are invalidated by migration 0012 and must be regenerated.
- Makes backup-code login failure paths pay a fixed backup-code hash-check budget so password correctness is not exposed by the second-factor timing difference.
- Prevents non-superuser account administrators from listing or revoking root, Tactical-superuser, or role-superuser login sessions.
- Adds POST support to individual admin login-session revocation while retaining DELETE compatibility.
- Requires the Core session guard on the TOTP QR endpoint and uses a colon-free Tec-Tac UI-derived authenticator issuer.

The broader privileged-helper/signing P0 review remains a separate hardening track; this release is intentionally limited to Access/MFA/session findings.
