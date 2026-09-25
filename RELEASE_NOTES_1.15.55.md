# Tec-Tac Framework 1.15.55

## MFA enrollment hardening

- Replaces reusable TOTP QR retrieval with a one-time Core enrollment endpoint.
- Requires Tactical's short-lived Knox setup token plus a fresh current-password proof before a local TOTP seed is issued.
- Generates the TOTP secret and QR provisioning material once, commits the secret atomically, and revokes the setup Knox token before returning the enrollment response.
- Prevents local Knox sessions without configured TOTP from using Tec-Tac operational APIs; SSO-managed identities remain governed by their external identity provider.
- Retires the legacy QR endpoint so an authenticated operational session can no longer re-export the account's active TOTP seed.
- Records forced Core audit events for rejected enrollment proofs and successful one-time seed issuance.
- Keeps final MFA verification under Tactical's normal `/v2/login/` flow; Tec-Tac does not grant operational access from seed issuance alone.
