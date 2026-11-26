# Engineer Console certificates (Core 1.18.52 and 1.18.53)

Core 1.18.52 added the first half of the Engineer Console certificate plan (signed 25 November 2026): Core issues a certificate to each engineer's Console PC. Core 1.18.53 adds the second half: Core checks it. From 1.18.53 a Console without a valid certificate cannot open a tunnel, and a revoked certificate or a replaced CA ends the tunnels that use it within seconds.

## What it is

A **certificate authority (CA)** is a key pair that Core owns. Its private half signs. Its public half lets anyone check the signature.

A **certificate** is a small signed file. It says "this public key belongs to this engineer on this server". Core signs it with the CA's private key.

Each engineer's Console makes its own key pair on the engineer's PC. The private half never leaves that PC. The Console sends Core only the public half and a proof that it holds the private half. Core signs the public half and sends the certificate back.

On every tunnel connect the Console proves again that it holds the private half, and Core proves to the Console that it is the server the Console enrolled with. That is the whole point: Core knows which Console is opening a tunnel, and the Console knows it is talking to the right Core.

This is Core-internal. No module reads, stores or asks for a certificate, a code or a key. There is no capability of its own. The one module-facing effect is a new refusal from `issue_tunnel_ticket` (`core.probe_transport` 1.3.0; see `docs/probe-transport.md`).

## The format

| Part | Value |
|---|---|
| Keys | ECDSA P-256, signatures with SHA-256 |
| CA certificate | self-signed, valid 10 years, `CN=Tec-Tac Engineer Console CA`, basicConstraints `CA:true` with path length 0 (critical), keyUsage `keyCertSign` (critical) |
| `server_id` | the first 16 bytes of the SHA-256 of the CA public key (SPKI DER), as 32 hex characters |
| Console certificate | X.509 v3 in DER, subject `CN=<username>` (cut to 64 characters; the full name is kept in Core's table), issuer = the CA subject |
| Serial | 16 random bytes with the top bit cleared, as 32 hex characters |
| Subject alternative names | `URI:tectac:server:<server_id>` and `URI:tectac:engineer:<user id>` |
| Key usage | `digitalSignature` (critical), extended key usage `clientAuth`, `CA:false` (critical) |
| Validity | from 5 minutes ago (clock skew) to now plus the validity setting, but never past the CA's end minus one day |

There is no revocation list and no OCSP. Core's table is the authority: a revoked row is revoked. The CA signature is the second lock.

## The CA private key

The CA key is encrypted with AES-256-GCM under the same master key as the module secret store (`docs/secret-store.md`) and stored only in the table `core_console_ca`. Core decrypts it in memory for one signature and drops it. It never reaches a file, a log line, an audit row, an error text or an answer. No route returns it.

Since 1.18.53 it signs two things: certificates, and the server proof of each tunnel connect.

If the master key is missing, unsafe, or cannot decrypt the CA row, Core answers `master_key_unavailable` (503) on every route that issues, makes a code or enrols. A tunnel connect that reaches the server proof step closes `1013` with the close text `master_key_unavailable`, and its ticket is gone. The reason (for example `ca_key_unreadable`) is in the log only.

Who can read the key? Anyone who can read the master key file and the database: root, and any process in the `tactical` group, as for every module secret. A database dump on its own is useless, because the key inside it is encrypted.

## Enrolment, step by step

1. An administrator allows an engineer to enrol (`POST issue/`). The first time ever, Core also creates the CA. The administrator never sees a code. The permission lasts 7 days. Allowing again cancels the earlier one.
2. The engineer asks for a one-time code (`POST mine/enrolment-code/`). The code lives 10 minutes. Core stores only its SHA-256. A new code voids the old one.
3. The Console makes a key pair, signs a proof and calls `POST enrol/` with the code.
4. Core checks the code, the proof and the account, signs the key and answers with the bundle.

An engineer may hold at most 3 active certificates. Enrolling again from the same PC (same PC label, any capitals) replaces the older certificate for that PC, which Core revokes with the reason `replaced`. A replacement does not count against the 3. Since 1.18.53 a tunnel that uses the replaced certificate ends at once.

The code works once. Any refusal after Core took the code burns it, but the 7-day permission stays open. The engineer presses "Enrol this PC" again for a new code.

## The enrol route, exactly (for the Console developer)

`POST /api/tfd/console-certificates/enrol/`. No sign-in and no cookie. https only (Core refuses a request that the proxy reports as http).

Header: `Authorization: Enrol <code>`. The code is 43 characters from `A-Z a-z 0-9 _ -`.

Body: JSON of at most 4 KiB with exactly these keys, and nothing else:

```json
{"v": 1, "public_key": "<base64url>", "pc_label": "Work PC", "proof": "<base64url>"}
```

All binary values are **base64url without padding**.

- `public_key`: the P-256 public key as SubjectPublicKeyInfo DER, in the uncompressed form. Core re-encodes the key and refuses it if the bytes differ (trailing data, compressed point, other parameters).
- `pc_label`: 1 to 64 characters, Unicode NFC, trimmed, with no control or format characters.
- `proof`: 64 bytes, `r` then `s`, each 32 bytes big-endian (IEEE P1363), an ECDSA P-256 / SHA-256 signature over exactly these bytes:

```
tectac-console-enrol-v1\nhost=<host>\ncode=<sha256(code) hex>\nkey=<sha256(SPKI DER) hex>
```

`\n` is one line feed. There is no trailing newline. `<host>` is Core's host in lower case, without a port (`:443` removed). It must be the host the Console connects to. `<sha256(code) hex>` and `<sha256(SPKI DER) hex>` are lower-case hex. The hash of the code is taken over the 43 ASCII characters.

Core's own host is `request.get_host()`, lower-cased, with `:443` removed. It must be a plain host name (the same rule as the tunnel launch link). Any other port or an odd host answers `host_unusable`. A Core reached by an alias that differs from its own request host fails the proof. That is on purpose.

Answer, 201, `Cache-Control: no-store`:

```json
{"v": 1, "host": "...", "server_id": "...", "ca_public_key": "...", "ca_cert": "...", "cert": "...", "serial": "...", "not_after": "...",
 "engineer": {"id": 5, "username": "..."}}
```

`ca_public_key`, `ca_cert` and `cert` are base64url DER. The Console pins `server_id` and `ca_public_key` for this host.

Errors. A bad header, an unknown, used, expired or cancelled code all answer the same `401 code_invalid` body, so nobody can tell them apart. After the code was taken the answers are specific: `400 key_invalid`, `400 proof_invalid`, `400 host_unusable`, `403 account_inactive` (inactive, blocked from the dashboard, or an installer account), `409 certificate_limit`, `503 ca_unavailable`, `503 ca_expired`, `503 master_key_unavailable`, `503 audit_failed`. Also `400 invalid_request`, `413 body_too_large`, `403 tls_required`, and `429 rate_limited` with `Retry-After: 60` after 10 failures a minute from one address (an IPv6 address counts by its /64). The answer text never contains the code, the key or the proof.

## The tunnel connect, exactly (for the Console developer)

The Console opens `wss://<host>/ws/tfd/probe-tunnel/` with the one-time ticket from the launch link (`docs/probe-transport.md`). Since Core 1.18.53 it also sends its certificate and a proof, and it checks Core's answer before it opens its local port. This section is the whole wire format.

Conventions, the same as the enrol route: every binary value is **base64url without padding**, in ASCII. Hex is lower case. Lines are joined by one LF and there is no trailing LF. Every signature is ECDSA P-256 / SHA-256, written as 64 bytes `r` then `s` (IEEE P1363).

### 1. The request headers

Each header appears exactly once.

| Header | Value |
|---|---|
| `Authorization` | `Ticket <43 characters>` (unchanged) |
| `X-Tectac-Console-Cert` | the leaf certificate DER, base64url. It is the `cert` value of the enrol bundle. At most 2048 characters. |
| `X-Tectac-Console-Proof` | `v1.<time>.<nonce>.<sig>`. At most 400 bytes. `time` is the Unix time in seconds (UTC), digits only, 1 to 12 of them. `nonce` is base64url of 16 random bytes (exactly 22 characters). `sig` is base64url of 64 bytes (exactly 86 characters). |

### 2. The bytes the Console signs

Sign with the certificate's private key, over exactly these bytes:

```
tectac-console-connect-v1
host=<host>
server=<server_id>
ticket=<sha256 of the 43 ASCII ticket characters, lower-case hex>
serial=<32 hex>
time=<time, as in the header>
nonce=<nonce, as in the header>
```

The first line is the fixed prefix. Each line ends with one LF, except the last. There are six LFs in all.

- `<host>` is the host the Console connects to, lower case, no port. Core compares it with the websocket `Host` header (lower-cased, `:443` removed). It must be a plain host name, the same rule as the launch link. Any other port is unsupported: it answers `proof_invalid`, like `host_unusable` on enrol.
- `<server_id>` is the pinned server id from the bundle.
- `serial` is the certificate serial, 32 hex characters.

A worked example of the bytes (the ticket is 43 times `T`, so its hash is `8a652abf7512959a7ecf7abe32a2bb4634c0b03fc93008b0365ed67933bff00c`):

```
tectac-console-connect-v1
host=tec.example.com
server=11111111111111111111111111111111
ticket=8a652abf7512959a7ecf7abe32a2bb4634c0b03fc93008b0365ed67933bff00c
serial=22222222222222222222222222222222
time=1764000000
nonce=AAAAAAAAAAAAAAAAAAAAAA
```

### 3. Core's answer

On success the websocket accept carries one more header:

```
X-Tectac-Server-Proof: v1.<sig>
```

`sig` is base64url of 64 bytes, signed by the CA key over:

```
tectac-core-connect-v1
host=<host>
server=<server_id>
ticket=<the same hex>
serial=<serial>
nonce=<the Console's nonce>
```

Five LFs, no trailing LF. The Console verifies it with the pinned `ca_public_key` **before** it opens its local port. A missing or wrong server proof means: open nothing and close the connection.

### 4. What Core checks, in this order

Every check fails closed. A refusal is an accepted websocket that Core then closes with code `4401` and the reason as the close text.

1. The gate (address limits, owner, plain text). Unchanged.
2. The ticket header. Unchanged: `malformed_header`, `wrong_scheme`.
3. The two certificate headers, present once each and well shaped. Either missing: `certificate_required`. A malformed certificate header: `certificate_invalid`. A malformed proof header: `proof_invalid`. **The ticket is not burnt yet**, so a Console can fix its headers and try again.
4. Core redeems the ticket (`ticket_invalid`). From here the ticket is burnt, even if a later check fails.
5. The time: the Console's `time` and Core's clock differ by at most 120 seconds (`proof_stale`).
6. The certificate parses, was issued by the active CA and carries a valid CA signature (`certificate_invalid`). After a CA replacement an old-CA certificate therefore answers `certificate_invalid`, not `certificate_revoked`.
7. Core's table has a row for the serial, its stored certificate equals the presented bytes, its key fingerprint matches and its CA is the active CA (`certificate_invalid`). A revoked row: `certificate_revoked`. A row past its end: `certificate_expired`. A row that has not started: `certificate_invalid`.
8. The row belongs to the engineer the ticket was issued to (`certificate_engineer_mismatch`).
9. The proof signature, over the bytes Core builds itself from its own `Host` header, the server id of the active CA, the ticket, the serial and the header's time and nonce (`proof_invalid`).
10. The existing checks: the account, the permission, the module, the session record, the person's scope.
11. Core signs the server proof. If the master key cannot be used, it closes `1013` with `master_key_unavailable`. The ticket is burnt.
12. Core marks the session attached and accepts, with the server proof in the header.

### 5. The refusal reasons, and what to do about each

| Reason | Meaning | What the engineer or administrator does |
|---|---|---|
| `certificate_required` | A certificate header or the proof header was missing. | Update the Console. A current Console always sends both. |
| `certificate_invalid` | The certificate is malformed, is not from this server's current CA, is not in Core's table, or does not match it. | Enrol this PC again from My Account. After a CA replacement every engineer enrols again. |
| `certificate_expired` | The certificate's end has passed. | Enrol this PC again. The My Account card warns 30 days ahead. |
| `certificate_revoked` | An administrator or the engineer revoked it. | Enrol again if the PC is still the engineer's. |
| `certificate_engineer_mismatch` | The certificate belongs to another engineer than the one who started this tunnel. | Sign in to Tec-Tac as the engineer who owns this Console PC. |
| `proof_invalid` | The proof signature is wrong, or its host or server id differs from Core's, or the `Host` header is not a plain host name. | Open the Console with the launch link from the same address you use for Tec-Tac. An alias or a non-standard port fails on purpose. |
| `proof_stale` | The PC's clock and Core's differ by more than 120 seconds. | Fix the PC's clock (turn on automatic time). See "Clock skew". |

Any of these writes one `custom:console-cert-refused` row and counts as a failed attempt for the address. It writes no `custom:probe-tunnel-refused` row.

## After the connect

- **Re-check, every 5 minutes.** Core re-reads the certificate row first. A row that is no longer active, or whose CA is no longer the active CA, ends the session (`ended_by_core`, detail `certificate_revoked`). A row past its end ends it with detail `certificate_expired`. A database fault ends it with detail `check_failed`; a busy or slow check keeps the existing grace.
- **Expiry watcher.** The session ends at the certificate's end, even in the middle of a long copy (detail `certificate_expired`).
- **Revoke and CA replacement end sessions at once.** After the change is saved, Core ends every live session that used the certificate (revoke) or every live session (CA replacement), and writes a marker in the shared cache. Each Console socket reads the marker every 5 seconds, so a session whose connect raced the revoke still ends within seconds. The database row is the authority: the immediate end is best effort, and if the cache or the broker is down the 5-minute re-check ends the session instead.
- **`last_used_at`.** The certificate row records the last tunnel connect that used it, written at most once an hour.

The end row's `detail` carries `certificate_revoked`, `certificate_expired` or `ca_replaced`. The close reason stays `ended_by_core`.

## The management routes

All under `/api/tfd/console-certificates/` and all need a signed-in session, except `enrol/`. Three routes need more than that: an **interactive signed-in session**, not an API key. They are `POST mine/enrolment-code/`, `POST issue/` and `POST ca/replace/`. A Tactical API key (an `X-API-KEY` header), and any request without a Knox sign-in token, gets `403 interactive_session_required` and one `deny` row (reason `api_key_refused`). No code is stored and nothing changes. Revoking and reading are not restricted this way: revoking with a key is the safe direction.

| Route | Who | What |
|---|---|---|
| `GET mine/` | anyone signed in | own certificates, own open enrolment, `host`, `server_id`, `validity_days` |
| `POST mine/enrolment-code/` | anyone with their own open enrolment, signed in interactively | the one-time code (no-store, 5 a minute and 20 a day) |
| `GET /` | anyone: own rows; `view` or `manage`: every row | `?engineer=<id>&state=active\|expired\|revoked&page=&page_size=` (50 a page, at most 100), plus the open `enrolments` (at most 200) |
| `POST issue/` `{user_id}` | `manage`, signed in interactively | allow an engineer to enrol |
| `POST enrolments/<id>/cancel/` | `manage` | cancel an open enrolment |
| `POST <serial>/revoke/` `{reason}` | `manage` on any; the owner on their own | `reason` is `lost`, `left`, `admin` or `other`. Ends the live sessions of that certificate. |
| `GET ca/` | `view` or `manage` | exists, `server_id`, dates, `expires_in_days`, `expiring` (365 days or less), counts, `master_key_available` |
| `POST ca/replace/` `{"confirm": true}` | effective superuser only, signed in interactively | see below |

A certificate row is `{serial, short_serial, pc_label, username, engineer_id, issued_at, not_after, state, expiring, revoked_at, revoked_reason, last_used_at}`. `state` is `active`, `expired` or `revoked`. `expiring` is true for an active certificate with 30 days or less left. `last_used_at` is the last time the certificate opened a tunnel (from 1.18.53; empty until its first use).

A refused permission is hidden and refused (AD-12): Core writes one `deny` audit row and answers 403. A body with an unknown key is a 400. A serial must be 32 lower-case hex characters. Write routes are limited to 30 a minute and 500 a day per person and address.

## Permissions

A new group, **Console certificates**:

- `core.console_certificates.view`: see every certificate and the CA status.
- `core.console_certificates.manage`: allow an engineer to enrol, cancel an enrolment, revoke any certificate. Manage includes view.

An effective superuser holds both. Replacing the CA is for effective superusers only.

## The validity setting

`console_certificate_validity_days` in `GET/PATCH /api/tfd/system/runtime-settings/`: a whole number from 1 to 730, default 365. Only an effective superuser changes it. It affects new certificates only. See `docs/runtime-settings.md`.

## Replacing the CA

`POST ca/replace/` retires the active CA (it is kept, marked retired), makes a new one, revokes every active certificate of the old CA with the reason `ca_replaced`, cancels every open enrolment (their codes stop working) and writes one audit row with the counts. After the change is saved, every live tunnel session ends (detail `ca_replaced`). After a replace the server id changes, so every engineer is allowed again by an administrator and enrols again.

Use it when the CA key may be exposed, when the CA is close to its end (the CA page shows `expiring` from 365 days), or after the master key was lost.

## If the master key is lost

The CA key can no longer be decrypted. Core answers `master_key_unavailable` for issuing, codes and enrolling, and a tunnel connect closes `1013`. Fix the master key file if it was only moved or its permissions changed (see `docs/secret-store.md`). If the key is truly gone, an effective superuser replaces the CA. Engineers then enrol again.

## Clock skew

A certificate starts 5 minutes before it was made, so a Console clock a few minutes slow still accepts it. A clock that is wrong by more than that will see a new certificate as "not yet valid". Fix the PC's clock.

The tunnel proof is stricter. It carries the PC's time, and Core accepts it only within 120 seconds of its own clock, in either direction. A PC that is more than two minutes out gets `proof_stale` on every connect, with a certificate that is otherwise fine. The fix is always the PC's clock: turn on automatic time and sync it. Do not change the server's clock to suit one PC.

## Audit rows

Every row is module `core` with `operation_context.server_provenance = console-certificates`, except the tunnel rows named below. Rows marked strict are written in the same database transaction as the change: if the row cannot be written, the change is not made (503 `audit_failed`).

| Action | Strict | Actor | When |
|---|---|---|---|
| `custom:console-ca-created` | yes | the administrator who caused it; `service:core.console-certificates` when no person is known | the first issue creates the CA |
| `custom:console-ca-replaced` | yes | the administrator | the CA was replaced (counts of revoked certificates and cancelled enrolments) |
| `custom:console-cert-issue-authorised` | yes | the administrator | an administrator allowed an engineer |
| `custom:console-cert-enrolment-cancelled` | yes | the administrator | an administrator cancelled an enrolment |
| `custom:console-cert-issued` | yes | the engineer who owns the matched enrolment (`service:core.console-certificates` only when the engineer has no usable username) | a certificate was signed (`via` = `enrolment_code`, and the address) |
| `custom:console-cert-revoked` | yes | the person who revoked it (the engineer for their own certificate, the administrator otherwise); for `replaced`, the engineer who enrolled | a certificate was revoked (also for `replaced`, with `replaced_by_serial`, `via` and the address) |
| `custom:console-cert-enrol-code` | no | the engineer | an engineer asked for a code (never the code) |
| `custom:console-cert-enrol-refused` | no | the engineer, once the code was matched; `service:core.console-certificates` when no person is known (unknown or burnt code, bad header or body) | an enrolment was refused (reason and address, and after a match also `via`, `engineer_id` and `username`; at most one a minute per address and per kind) |
| `custom:console-cert-refused` | no | `service:core.console-certificates` | a tunnel connect was refused for one of the seven certificate reasons (reason, address, session id, engineer id, and the serial only when it parsed to 32 hex; at most one a minute per address and per kind) |
| `deny` | no | the person refused | a permission refusal, or an API key on one of the three routes (reason `api_key_refused`) |

Since 1.18.55 the enrolment rows sit under the engineer, because the code comes only from their own signed-in My Account page and is bound to their enrolment. The administrator who allowed the enrolment is already named in the `custom:console-cert-issue-authorised` row. A refusal limiter has one key per address and per kind: a refused enrolment and a refused tunnel connect from one address in the same minute each write their one row.

### Finding every row of one certificate

Search the audit log by the certificate's serial (the object id), or by the action names `custom:console-cert-issued`, `custom:console-cert-revoked` and `custom:console-cert-refused`. The revoke row for a person's own certificate is under that person. The administrator's revoke is under the administrator. The issue row is under the engineer who enrolled.

The tunnel's own rows (`custom:probe-tunnel-connect` and `custom:probe-tunnel-end`, provenance `probe-transport`) carry `cert_serial` from 1.18.53.

A row may hold a serial, a key fingerprint (`spki_sha256`), a PC label, a date, ids, a reason, counts and an address. It never holds a code, a ticket, a certificate, a key, a signature, a proof, a header value or the CA private key.

## What is not built

- The Console itself (the pinning, the proof on connect, the check of the server proof) ships separately as Engineer Console 0.1.0. Core 1.18.53 and that Console must reach a server together, because a Console that does not send the proof cannot connect.
- The Core UI pages (My Account card, certificate list) ship separately. Until then use the routes above.
- Accepting the server proof on Tactical 1.5.2 (Daphne) is checked on a 1.6.1 server first. A Console fails closed when the header does not arrive.

## Signing in with the certificate (Core 1.18.56)

Since 1.18.56 the certificate is also how an Engineer Console signs in to Tec-Tac: the browser hands the Console a one-time code, and the Console swaps it for a session by proving it holds this certificate's private key (`docs/console-sessions.md`). Every later request carries a signature made with the same key. A revoked or expired certificate, and a replaced CA, end the Console sessions on that PC (reasons `certificate_revoked`, `certificate_expired`, `ca_replaced`) in the same transaction as the revoke, and the tunnels opened from them end within seconds. The enrolment rows and routes on this page did not change.
