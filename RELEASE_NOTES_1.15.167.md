# Tec-Tac Core 1.15.167

## My Account — F1 to F4

Adds a Core-owned self-service account boundary for the currently authenticated Tactical user.

- **F1:** `PUT /api/tfd/account/password/` changes the current local user's password only after current-password proof and Django password validation. Other sessions are revoked while the current session is preserved.
- **F2:** `POST /api/tfd/account/totp/reset/` requires the current password and current TOTP code, invalidates Tec-Tac MFA backup codes, clears Tactical's TOTP secret and revokes all sessions so the existing login flow performs a fresh enrollment.
- **F3:** My Account uses the existing credential-level `POST /api/tfd/session/revoke-others/` boundary to sign out every other Tactical/Tec-Tac session.
- **F4:** `GET/PUT /api/tfd/account/tactical-ui/` reads and writes Tactical's native `agent_dblclick_action` and `url_action` fields. Valid choices come from the installed Tactical model metadata; URL Actions follow Tactical role permission.

Also adds `GET /api/tfd/account/`, public-contract descriptions, `docs/my-account.md`, sensitive-operation throttling and behavioral regression coverage in `tests/my-account-features-1.15.167.py`.
