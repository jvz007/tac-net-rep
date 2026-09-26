# Tec-Tac Core 1.15.75

## Session fingerprint upgrade compatibility

This release fixes the remaining session-security upgrade regression where an
existing revoked or expired trust row could be missed after the credential
fingerprint representation changed.

- Core now resolves existing Knox trust state by the stable Tactical Knox digest
  before creating a new fingerprint row.
- Any revoked trust row for the same Knox digest is authoritative, including
  when another row already exists under the current fingerprint.
- Active/expired legacy rows are reused so their original creation/activity
  timestamps remain authoritative for timeout enforcement.
- Rows created before `knox_digest` was populated are lazily linked through the
  pre-S6 raw-bearer HMAC only after the current S6 credential check proves that
  the request bearer matches the authenticated Knox digest.
- Conflicting or unrelated Authorization headers cannot use the compatibility
  path to select legacy trust state.

No public `core.session_security` contract change is required.
