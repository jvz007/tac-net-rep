# Tec-Tac Framework 1.15.16

## Core Session Security foundation

This release adds the Core-owned API and public contract required by the planned
Security module without changing Tactical authentication source.

### New capability

`core.session_security` v1.0.0 exposes:

- policy read/update;
- safe session enumeration;
- sanitized session-security audit events;
- single-session revocation;
- user-session revocation with an optional preserved session;
- retention cleanup;
- diagnostics.

### Persistent Core state

Migration `0007_session_security.py` adds:

- `TecTacSessionSecurityConfig`;
- `TecTacSessionTrust`;
- `TecTacSessionAudit`.

Core stores only a server-keyed HMAC fingerprint of the presented authentication
credential. Raw Tactical tokens are not persisted or returned.

### Session policy foundation

Built-in defaults are:

- 30-minute idle timeout;
- 8-hour absolute lifetime;
- IP-change policy `reauthenticate`;
- 60-second activity heartbeat interval;
- session-security auditing enabled;
- only loopback proxy networks trusted by default.

Forwarding headers are ignored unless the immediate peer is a configured trusted
proxy.

### HTTP API

New `/api/tfd/session/` endpoints provide current session, explicit activity,
session listing/revocation, policy administration, audit retrieval and
diagnostics.

### Rollout boundary

`SessionAuthenticated` is now a supported Core permission contract. Existing
Tec-Tac endpoints retain their existing Tactical `IsAuthenticated` permission in
this foundation release so installing 1.15.16 cannot cause active users to time
out before the Core UI activity heartbeat is deployed. The enforcement primitive
is available to new endpoints and the subsequent session-security rollout.

### Documentation/tests

Added `docs/session-security.md`, public-contract catalog entries and
`tests/session-security-foundation.sh`.
