# Tec-Tac Core 1.15.130

## Session/MFA contract and security batch

- M30: Corrected `core.session_security` to capability version 2.0.0 because removing module-callable policy mutation and the cleanup retention override was a breaking public-contract change. Installer and documentation now require `>=2.0.0,<3.0.0`.
- L47: Non-superuser account administrators can no longer read MFA recovery status for protected superuser/root-role accounts.
- L48: Administrative MFA GET/status is read-only; status reads no longer delete stale recovery codes or emit mutation audit events.
- L49: Automatic invalidation after a TOTP-key change now uses a distinct audit event from explicit administrator invalidation.
- L52: Existing Knox digest bindings are immutable. Legacy/current session rows may populate a missing digest once, but a different existing digest causes session-invalid-state instead of being overwritten.
- L53: Stored legacy trusted-proxy networks are revalidated on every policy read, so public, over-broad, malformed, or otherwise unsafe entries are ignored even if accepted by an older Core release.

## Regression coverage

- `tests/session-security-contract-version.py`
- `tests/mfa-admin-readonly-review.py`
- `tests/session-fingerprint-upgrade.py`
- `tests/session-retention-policy.py`
- Existing session-security and MFA administrative recovery foundations remain required.
