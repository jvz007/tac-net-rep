# Tec-Tac Framework 1.15.43

## Access security controls

- Adds Core-owned one-time MFA backup codes for Tactical local/TOTP accounts.
- Backup codes are stored only as Django password hashes; plaintext values are returned once at generation time.
- Generating/regenerating codes requires the authenticated user's current password and a current TOTP code and invalidates all older codes.
- Adds a recovery-login endpoint that revalidates Tactical username/password, applies Tactical login throttles and local-login restrictions, atomically consumes one recovery code, and issues the normal Tactical Knox token.
- Adds administrative active-session inventory across Tactical Knox login tokens.
- Session list exposes HMAC-derived opaque references rather than bearer tokens or raw Knox digests.
- Individual and per-user revocation delete the underlying Tactical Knox token and revoke correlated Tec-Tac session-trust records.
- Tec-Tac session trust now records the non-secret Knox digest internally so active sessions can be enriched with Tec-Tac last-activity and IP metadata.
- Administrative session controls require Tactical `can_manage_accounts`, role superuser, or Tactical superuser authority.
- Adds migration `0011_access_security` and regression coverage for recovery-code and Knox-session security boundaries.
