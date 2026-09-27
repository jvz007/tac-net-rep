# FIXING — Core 1.15.100

Review scope for this release: **M2 only**.

## Tracker item

- **M2** — revoking a Tec-Tac session must invalidate the linked Tactical Knox token so the same bearer credential cannot continue authenticating against Tactical-native endpoints.

## Behavioural changes

- `revoke_session()` now deletes the linked Knox `AuthToken` inside the same database transaction as the Tec-Tac trust-row revocation.
- `revoke_user_sessions()` now deletes the Knox credentials linked to every revoked trust row.
- The explicitly excluded/current session credential is preserved when another still-active trust row references that digest.
- Legacy Tec-Tac trust rows with no Knox digest still revoke without deleting unrelated credentials.

## Behavioural regression

- `tests/session-knox-revocation.py` executes the real public revocation functions with in-memory trust/token managers and proves:
  - single-session revoke removes the linked Knox token;
  - revoke-other-sessions removes only the revoked sessions' tokens;
  - the excluded current token survives;
  - a legacy digest-less trust row does not trigger token deletion.

## Not in scope

No M3+ Mediums, UI changes, or unrelated Low items are included.
