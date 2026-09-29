# Core 1.15.177

Tracker closure batch: **F1 + F7 only**.

## F1 — My Account password change acceptance

- Added explicit behavioral coverage proving a password rejected by Django/Tactical password validation is returned as a bounded `AccountSelfServiceError`.
- The regression proves the rejected password is not persisted and no session revocation occurs.
- Production password-change behavior is unchanged.

## F7 — Client & Site custom-field acceptance

- Added `tests/resource-directory-custom-fields-postgres.py`, a rollback-only PostgreSQL/Tactical acceptance test using the real Client, Site, CustomField, ClientCustomField, SiteCustomField, Role, User and AuditLog models.
- Covers every supported field type for both client and site resources: text, number, single, multiple, checkbox and datetime.
- Proves out-of-scope resources remain non-writable, hidden fields and invalid options write nothing, and audit records contain field IDs only with values redacted.
- Production custom-field behavior is unchanged.

## Validation

Portable Core regressions and release-integrity checks pass. The new F7 PostgreSQL acceptance test requires a real Tactical PostgreSQL runtime and is intentionally rollback-only.

This release is unsigned.
