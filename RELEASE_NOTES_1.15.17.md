# Tec-Tac Framework 1.15.17

## Core session-security rollout

- Enables `SessionAuthenticated` across Core-owned authenticated `/api/tfd/` browser endpoints.
- Keeps the TOTP enrollment QR endpoint on Tactical-only authentication for pre-operational setup.
- Preserves public and non-interactive authentication boundaries.
- Standardizes browser-facing failure codes including `session_ip_change` and `session_invalid_state`.
- Updates session-security documentation for the Core shell heartbeat and global enforcement rollout.

Capability `core.session_security` remains v1.0.0 and its public 1.x contract is unchanged.
