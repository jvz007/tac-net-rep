# Tec-Tac Core 1.15.90

## D4: Core-owned session and audit retention

- Adds `history_retention_days` to the Core session-security policy (default 30, range 1-3650 days).
- Policy mutation remains effective-superuser-only through the Core HTTP boundary and is force-audited.
- Removes module-callable session-policy mutation from `core.session_security`; capability version is now 1.1.0.
- Session cleanup always uses the configured Core retention policy.
- Revoked trust tombstones are preserved beyond retention only while their credential could still authenticate: a live Knox token, present Tactical API key, or unexpired Django session.
- Once the credential is gone or expired, its revoked trust row ages out on the configured retention schedule.
- Tactical-owned authentication tables remain under Tactical retention policy.

## Low-risk cleanup

- Session audit and active-login pagination endpoints now return a stable `Invalid pagination parameters.` response instead of leaking raw integer-conversion errors.
