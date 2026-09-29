# Core 1.15.181

## F2 acceptance closure

- Keeps the existing Tactical-native two-factor reset design: My Account proves the current password and current TOTP, clears the old TOTP binding, invalidates Tec-Tac recovery codes, revokes all active sessions/tokens, and requires a fresh sign-in.
- Adds a real Tactical/PostgreSQL integration regression using real `pyotp` that proves an invalid current code changes nothing, a valid reset clears the old TOTP/recovery/token state, and Tactical's short-lived next-sign-in setup credential drives the production `TotpEnrollmentView` to issue a different one-time secret.
- The integration test rolls its complete database transaction back and is intended to run on a Tactical server with PostgreSQL.

This release is unsigned.
