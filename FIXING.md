# FIXING.md — Core 1.15.130

## Review scope

This release is intentionally limited to one Medium plus five Low tracker items in the session/MFA subsystem:

- M30 — `core.session_security` breaking API change was versioned as 1.1.0 instead of a new major.
- L47 — non-superuser administrators can read protected accounts' MFA status.
- L48 — administrator MFA GET/status mutates data and attributes that mutation to the reader.
- L49 — explicit invalidation and TOTP-change invalidation share an audit event name.
- L52 — legacy session relinking can overwrite an existing Knox digest.
- L53 — stricter trusted-proxy validation applies only to new saves, not legacy stored policy.

## Expected outcome

Review should verify the new 2.0.0 session-security contract boundary, protected/read-only MFA administration, immutable credential binding, distinct MFA invalidation audit provenance, and fail-closed handling of unsafe legacy proxy configuration. No unrelated subsystem changes are intended.
