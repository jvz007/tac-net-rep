# My Account

Tec-Tac exposes self-service account controls under `/api/tfd/account/`. These endpoints always operate on the authenticated Tactical user and never accept another user id.

## Password change

`PUT /api/tfd/account/password/` requires the user's current local password and a new password that passes Django/Tactical password validation. SSO-managed accounts are rejected. After the password changes, Core revokes every other Tactical Knox credential and Tec-Tac trust session while preserving the current session. The mutation is strictly audited.

## Two-factor reset and re-enrollment

`POST /api/tfd/account/totp/reset/` requires both the current password and current TOTP code. Core then clears the Tactical user's TOTP secret, invalidates all Tec-Tac MFA backup codes, audits the reset and revokes every active session including the current one. The user signs in again through the normal Tec-Tac/Tactical flow; because Tactical now reports no TOTP secret, the existing one-time enrollment path is used to issue a new authenticator seed.

SSO-managed accounts cannot use local password or TOTP self-service.

## Other sessions

My Account uses the existing `POST /api/tfd/session/revoke-others/` contract. It preserves the current Tec-Tac/Knox credential and revokes every other credential for the same username, including Knox tokens Tec-Tac has not previously observed.

## Tactical UI preferences

`GET/PUT /api/tfd/account/tactical-ui/` reads and writes Tactical's own `accounts.User.agent_dblclick_action` and `url_action` fields. Tec-Tac does not duplicate these values in its preference JSON. Valid double-click values are derived from Tactical model metadata at runtime, so Core follows the installed Tactical version. URL Actions are only listed or assignable when the effective Tactical role can run URL Actions.
