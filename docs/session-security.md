# Core Session Security

Framework contract: `core.session_security` v1.1.0

## Scope

Tactical remains the authentication authority. Core Session Security adds a
separate Tec-Tac trust record keyed by a one-way HMAC fingerprint of the
presented Tactical credential. Raw Tactical tokens are never stored, returned
or written to audit records.

Core-owned authenticated `/api/tfd/` browser endpoints use the
`SessionAuthenticated` permission so Tactical token validity alone is not enough
for Tec-Tac interactive trust. Local Knox sessions without configured TOTP are
rejected with `mfa_enrollment_required`. The sole pre-operational exception is
`POST auth/totp/enrollment/`, which accepts Tactical's short-lived setup token,
requires a fresh password proof, returns the TOTP seed once, and destroys the
setup token before responding. Public endpoints remain public. Backend/module
endpoints should opt into `SessionAuthenticated` when they represent interactive
browser trust; service/API-key contracts must keep their non-interactive
authentication path.

## Built-in policy

The Core policy model defaults to:

```text
idle_timeout_minutes        30
absolute_lifetime_minutes   480
ip_change_policy            reauthenticate
session_audit_enabled       true
activity_heartbeat_seconds  60
history_retention_days      30
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

provider = get_capability("core.session_security", version=">=1.1.0,<2.0.0")
```

Supported provider operations:

```text
get_policy
list_sessions
list_audit_events
page_audit_events
revoke_session
revoke_user_sessions
cleanup
diagnostics
```

Directly supported read/enforcement helpers are catalogued under `tec_tac.session_security`. Policy mutation is intentionally HTTP-only behind `SessionAuthenticated` plus effective-superuser authorization:

```python
get_effective_policy(...)
list_sessions(...)
list_audit_events(...)
page_audit_events(...)
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

`session/audit/` supports bounded pagination with `?page=1&page_size=50`;
`page_size` is capped at 100. The response includes `total`, `pages`,
`next_page` and `previous_page`. The legacy `limit` query remains accepted as a
first-page compatibility alias. Backend providers that need pagination should
use `page_audit_events(...)`; `list_audit_events(...)` remains available for
existing bounded-list consumers.

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

Session/audit history retention is owned by Tec-Tac because both tables are
Tec-Tac-owned. `history_retention_days` is part of the global Core session
policy (default 30 days, range 1–3650) and may only be changed through the
superuser-only policy boundary; every change is audited.

The capability exposes `cleanup()` and always uses that configured policy. Core
also runs this retention automatically from the existing `tec-tac-scheduler.timer`
path. The scheduler tick checks `last_history_cleanup_at` every minute and runs
cleanup only when 24 hours have elapsed. The timestamp advances only after a
successful cleanup, so a failure is retried on the next scheduler tick.

A revoked trust row is preserved beyond the history window only while its
underlying credential could still authenticate: an unexpired Knox token, a
present Tactical API key, or an unexpired Django session. After that credential
is gone/expired, the tombstone is deleted once the configured history window
has elapsed. Tactical-owned authentication tables keep Tactical's own retention.

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
mfa_enrollment_required
```

A matching 401 retires the browser Tactical credential and returns the shell to
the normal sign-in flow. This handling is Core-owned and does not depend on the
optional `coreusersecurity` module.

## One-time TOTP enrollment

First-time local authenticator enrollment uses Tactical's existing
`POST /v2/checkcreds/` credential check to obtain the upstream 180-second Knox
setup token. Tec-Tac never treats that token as an operational session.

The UI then requires the operator to enter the current password again and sends
that proof to:

```text
POST /api/tfd/auth/totp/enrollment/
```

Core accepts only a short-lived Knox credential, confirms the account is local
and has no active TOTP secret, revalidates the password under a database row
lock, generates the TOTP secret and provisioning QR, stores the Tactical
`totp_key`, and deletes the setup Knox token in the same transaction. The
secret, provisioning URI and QR SVG are returned once with `Cache-Control:
no-store`. They cannot be retrieved again from Core.

The legacy `GET /api/tfd/auth/totp/qr/` route is retained only as a compatibility
endpoint and returns `410 totp_qr_retired`; it never exports the account's active
secret.

Seed issuance does not log the user into Tec-Tac. The operator must prove a code
from the newly enrolled authenticator through Tactical's normal `/v2/login/`
endpoint, which issues the operational Knox token. If enrollment is abandoned
after seed issuance, the setup token is already invalid and the account must
complete TOTP login or have 2FA reset by an administrator.

Core force-audits rejected setup/password proofs as
`mfa_enrollment_proof_failed` and successful one-time issuance as
`mfa_enrollment_seed_issued`. Audit records never contain the TOTP seed.

## Administrator MFA recovery endpoint

Account administrators can inspect and invalidate a Tactical user's Tec-Tac MFA backup-code state through the Core account-security boundary:

```text
GET    /api/tfd/access/users/<user_id>/mfa/
DELETE /api/tfd/access/users/<user_id>/mfa/
```

`GET` returns the target user, backup-code status, and whether the requester may invalidate the protected account's recovery codes. `DELETE` invalidates the target user's current backup-code set and accepts an optional `reason`. Both operations require account-management permission; protected superuser/root targets additionally require effective-superuser authority. Responses are marked `no-store` so MFA recovery state is not cached by the browser or intermediaries.

## MFA backup codes

Tec-Tac adds one-time MFA backup codes without changing Tactical's user model or TOTP secret. Backup codes are stored in `TecTacMfaBackupCode` using Django password hashes; plaintext codes are returned only once when a user generates a new set. Generating a set requires the user's current password and a current TOTP code and invalidates every previous unused code.

`GET /api/tfd/auth/mfa/backup-codes/` returns backup-code status for the signed-in account. `POST /api/tfd/auth/mfa/backup-codes/` verifies the current password and TOTP before rotating the set. Failed proof attempts are keyed only to the account: five failures are allowed in a 15-minute window, after which Core returns HTTP 429 with `Retry-After`. A successful proof clears the failure budget. Successful rotations use a separate account-only budget of 20 per day, so failed proofs never consume the success allowance.

Recovery sign-in uses `POST /api/tfd/auth/login/backup-code/`. The endpoint revalidates the Tactical username/password, applies Tactical's local-login restrictions and Tactical's normal login throttles, and additionally applies a Tec-Tac failure budget keyed to the normalized username only. Five failed recovery logins in 15 minutes block subsequent recovery attempts with HTTP 429 and `Retry-After`; a successful recovery clears that username failure budget. Core then atomically consumes one backup code and issues the normal Tactical Knox token. It does not create a parallel Tec-Tac session credential.

`GET /api/tfd/access/users/<user_id>/mfa/` exposes only recovery-code status to an authorized account administrator. `DELETE /api/tfd/access/users/<user_id>/mfa/` invalidates the target user's recovery codes subject to the protected-account guard; neither administrative endpoint exposes plaintext codes or password hashes.

## Administrative login-session management

`GET /api/tfd/access/sessions/` lists active Tactical Knox tokens for account administrators. The paged contract accepts `page`, `page_size` (maximum 100), and optional `search`; search covers Tactical username and Core-observed last IP. Tec-Tac adds last activity/IP metadata when a token has been observed by the Core session guard. Protected root/effective-superuser accounts are excluded before count and pagination for non-superuser administrators. A request with no paging/search parameters retains the legacy bounded-list response for compatibility. Session identifiers exposed to the browser are HMAC-derived opaque references; raw bearer tokens and Knox digests are not returned.

Revoking a login session deletes the underlying Tactical Knox token and revokes the correlated Tec-Tac trust record. `POST /api/tfd/access/users/<user_id>/sessions/revoke/` revokes every active Tactical token for the selected user. These controls require Tactical account-management permission (or superuser authority).


## 1.15.45 access hardening

MFA recovery-code sets are cryptographically bound to the Tactical TOTP secret present at generation time. A reset or replacement of the TOTP secret invalidates the previous recovery set. Recovery-code regeneration is throttled and failed password/TOTP proofs are always security-audited.

Non-superuser account administrators cannot enumerate or revoke root/effective-superuser Knox sessions. Individual admin revocation accepts both POST and legacy DELETE. The legacy TOTP QR endpoint no longer exposes an active seed; first-time seed issuance uses the one-time enrollment flow described above.

## Credential fingerprint upgrade compatibility (1.15.75)

Core session trust is now correlated by the stable Tactical Knox digest before a
new fingerprint row is created. This preserves explicit revocations and timeout
state across the pre-S6 raw-bearer fingerprint format and the current
`knox:<digest>` fingerprint format. A revoked row for the same Knox digest is
authoritative even if a second active row exists. Older rows whose `knox_digest`
was never populated are lazily linked by reproducing the legacy bearer HMAC only
after the current S6 credential binding has proved that the bearer hashes to the
authenticated Knox digest. Arbitrary or conflicting Authorization headers are
therefore not accepted by the compatibility path.

