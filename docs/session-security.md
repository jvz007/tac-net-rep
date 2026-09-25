# Core Session Security

Framework contract: `core.session_security` v1.0.0

## Scope

Tactical remains the authentication authority. Core Session Security adds a
separate Tec-Tac trust record keyed by a one-way HMAC fingerprint of the
presented Tactical credential. Raw Tactical tokens are never stored, returned
or written to audit records.

Core-owned authenticated `/api/tfd/` browser endpoints now use the
`SessionAuthenticated` permission so Tactical token validity alone is not enough
for Tec-Tac interactive trust. The TOTP enrollment QR endpoint remains on native
Tactical authentication because it is intentionally used during pre-operational
TOTP setup. Public endpoints remain public. Backend/module endpoints should opt
into `SessionAuthenticated` when they represent interactive browser trust;
service/API-key contracts must keep their non-interactive authentication path.

## Built-in policy

The Core policy model defaults to:

```text
idle_timeout_minutes        30
absolute_lifetime_minutes   480
ip_change_policy            reauthenticate
session_audit_enabled       true
activity_heartbeat_seconds  60
trusted_proxies             127.0.0.1/32, ::1/128
```

Supported IP policies:

```text
off
audit
reauthenticate
terminate
```

Forwarding headers are ignored unless the immediate peer belongs to a configured
trusted proxy network. Loopback is trusted by default because Tactical/Tec-Tac
is normally reached through the local nginx reverse proxy.

## Server-side Python contract

Backend modules should resolve the versioned capability instead of importing
models:

```python
from tec_tac.capabilities import get_capability

provider = get_capability("core.session_security", version=">=1.0.0,<2.0.0")
```

Supported provider operations:

```text
get_policy
update_policy
list_sessions
list_audit_events
revoke_session
revoke_user_sessions
cleanup
diagnostics
```

Directly supported framework helpers are catalogued under `tec_tac.session_security`:

```python
get_effective_policy(...)
update_global_policy(...)
list_sessions(...)
list_audit_events(...)
revoke_session(...)
revoke_user_sessions(...)
SessionAuthenticated
```

A Security module must not import `TecTacSessionTrust`,
`TecTacSessionSecurityConfig` or `TecTacSessionAudit` directly.

## Browser/Core HTTP API

All endpoints are under `/api/tfd/`:

```text
GET  session/current/
POST session/activity/
GET  session/sessions/
POST session/sessions/<session_id>/revoke/
POST session/revoke-others/
GET  session/policy/
PUT  session/policy/
GET  session/audit/
GET  session/diagnostics/
```

`session/policy/`, `session/audit/` and `session/diagnostics/` require Core
session-security administration rights (Tactical superuser, superuser role, or
`can_do_server_maint`).

`session/sessions/` returns the current user's sessions by default. An
administrator may supply `?username=<name>`.

## Activity semantics

The activity endpoint is explicit by design. Normal background API polling does
not update `last_activity_at`.

The Core UI should send `POST /api/tfd/session/activity/` at most once per policy
heartbeat period and only when real browser interaction has occurred since the
previous heartbeat.

`last_seen_at` is request observation. It is not user activity and must never be
used to extend idle expiry.

Absolute expiry remains anchored to Core session creation time. Handler
completion time and activity heartbeat time cannot move the absolute deadline.

## Revocation semantics

A revoked credential fingerprint is not silently recreated. Continued use of
the same Tactical credential remains rejected by `SessionAuthenticated`.
A genuinely new Tactical credential produces a new fingerprint and may create a
new Core trust record.

Revocation can target one session or all sessions for a username, optionally
preserving the current session.

## Trusted client IP resolution

Core starts from `REMOTE_ADDR`.

- If the peer is not trusted, forwarded headers are ignored.
- If the peer is trusted, Core evaluates `X-Forwarded-For`, then RFC-style
  `Forwarded`, then `X-Real-IP`.
- The forwarding chain is walked from the nearest proxy toward the client and
  stops when the current hop is not trusted.

This prevents an external client from choosing its own effective IP by simply
sending `X-Forwarded-For`.

## Audit events

Core records security transitions such as:

```text
session_created
session_idle_timeout
session_absolute_timeout
session_ip_changed
session_reauthentication_required
session_revoked
user_sessions_revoked
```

The activity heartbeat intentionally does not create a high-volume audit row.

Audit rows never contain the raw Tactical token or the stored token fingerprint.

## Cleanup

The capability exposes `cleanup(retention_days=30)` for expired/revoked session
and audit history retention. This is the backend cleanup contract for the
Security module and future Core housekeeping integration.

## Security module boundary

Core owns:

```text
credential fingerprinting
session trust records
policy validation/storage
client-IP resolution
idle/absolute expiry calculations
IP-change enforcement primitive
revocation
session/audit APIs
backend capability
```

The Security module may own:

```text
policy UI
active-session UI
per-role policy design
security dashboards
alerting
reporting
risk analytics
geo/ASN intelligence
```

The module must consume Core contracts; it must not become the enforcement
boundary.

## Interactive shell rollout

The Core UI shell reads `activity_heartbeat_seconds` from `GET session/current/`
and reports explicit activity to `POST session/activity/`. Only meaningful human
interaction marks the browser active (`keydown`, `pointerdown`, `touchstart`,
and `scroll`). Background polling never counts as activity.

The authenticated UI API client recognizes these stable failure codes:

```text
session_idle_timeout
session_absolute_timeout
session_ip_change
session_revoked
session_invalid_state
```

A matching 401 retires the browser Tactical credential and returns the shell to
the normal sign-in flow. This handling is Core-owned and does not depend on the
optional `coreusersecurity` module.

## MFA backup codes

Tec-Tac adds one-time MFA backup codes without changing Tactical's user model or TOTP secret. Backup codes are stored in `TecTacMfaBackupCode` using Django password hashes; plaintext codes are returned only once when a user generates a new set. Generating a set requires the user's current password and a current TOTP code and invalidates every previous unused code.

Recovery sign-in uses `POST /api/tfd/auth/login/backup-code/`. The endpoint revalidates the Tactical username/password, applies Tactical's local-login restrictions and login throttles, atomically consumes one backup code, and then issues the normal Tactical Knox token. It does not create a parallel Tec-Tac session credential.

## Administrative login-session management

`GET /api/tfd/access/sessions/` lists active Tactical Knox tokens for account administrators. Tec-Tac adds last activity/IP metadata when a token has been observed by the Core session guard. Session identifiers exposed to the browser are HMAC-derived opaque references; raw bearer tokens and Knox digests are not returned.

Revoking a login session deletes the underlying Tactical Knox token and revokes the correlated Tec-Tac trust record. `POST /api/tfd/access/users/<user_id>/sessions/revoke/` revokes every active Tactical token for the selected user. These controls require Tactical account-management permission (or superuser authority).


## 1.15.45 access hardening

MFA recovery-code sets are cryptographically bound to the Tactical TOTP secret present at generation time. A reset or replacement of the TOTP secret invalidates the previous recovery set. Recovery-code regeneration is throttled and failed password/TOTP proofs are always security-audited.

Non-superuser account administrators cannot enumerate or revoke root/effective-superuser Knox sessions. Individual admin revocation accepts both POST and legacy DELETE. The TOTP enrollment QR requires `SessionAuthenticated`, and its issuer is derived from the Tec-Tac UI host/path without colon characters.
