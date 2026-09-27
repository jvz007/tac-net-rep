# Tec-Tac Framework 1.15.100

## M2 — Tec-Tac revocation now invalidates Tactical Knox credentials

- `revoke_session()` now removes the Knox token linked to the revoked Tec-Tac trust row inside the same transaction.
- `revoke_user_sessions()` now removes Knox tokens associated with the revoked user sessions while preserving a credential still referenced by an explicitly excluded/current active session.
- Legacy trust rows without a Knox digest continue to revoke safely without touching unrelated Tactical credentials.
- Added `tests/session-knox-revocation.py` as a behavioural regression for single-session, revoke-others and legacy-row cases.

UI is unchanged.
