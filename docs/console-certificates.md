# Engineer Console certificates (Core 1.18.52)

Core 1.18.52 adds the first half of the Engineer Console certificate plan (signed 25 November 2026): Core can now issue a certificate to each engineer's Console PC. It does not yet check one. Read "Not enforced yet" before you rely on any of this.

## What it is

A **certificate authority (CA)** is a key pair that Core owns. Its private half signs. Its public half lets anyone check the signature.

A **certificate** is a small signed file. It says "this public key belongs to this engineer on this server". Core signs it with the CA's private key.

Each engineer's Console makes its own key pair on the engineer's PC. The private half never leaves that PC. The Console sends Core only the public half and a proof that it holds the private half. Core signs the public half and sends the certificate back.

The certificate lets a later release (Core 1.18.53) tell which Console is opening a tunnel, and lets the Console check it is talking to the right Core.

This is Core-internal. No module reads, stores or asks for a certificate, a code or a key. There is no Python contract and no capability.

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

If the master key is missing, unsafe, or cannot decrypt the CA row, Core answers `master_key_unavailable` (503) on every route that issues, makes a code or enrols. The reason (for example `ca_key_unreadable`) is in the log only.

Who can read the key? Anyone who can read the master key file and the database: root, and any process in the `tactical` group, as for every module secret. A database dump on its own is useless, because the key inside it is encrypted.

## Enrolment, step by step

1. An administrator allows an engineer to enrol (`POST issue/`). The first time ever, Core also creates the CA. The administrator never sees a code. The permission lasts 7 days. Allowing again cancels the earlier one.
2. The engineer asks for a one-time code (`POST mine/enrolment-code/`). The code lives 10 minutes. Core stores only its SHA-256. A new code voids the old one.
3. The Console makes a key pair, signs a proof and calls `POST enrol/` with the code.
4. Core checks the code, the proof and the account, signs the key and answers with the bundle.

An engineer may hold at most 3 active certificates. Enrolling again from the same PC (same PC label, any capitals) replaces the older certificate for that PC, which Core revokes with the reason `replaced`. A replacement does not count against the 3.

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

## The management routes

All under `/api/tfd/console-certificates/` and all need a signed-in session, except `enrol/`.

| Route | Who | What |
|---|---|---|
| `GET mine/` | anyone signed in | own certificates, own open enrolment, `host`, `server_id`, `validity_days` |
| `POST mine/enrolment-code/` | anyone with their own open enrolment | the one-time code (no-store, 5 a minute and 20 a day) |
| `GET /` | anyone: own rows; `view` or `manage`: every row | `?engineer=<id>&state=active\|expired\|revoked&page=&page_size=` (50 a page, at most 100), plus the open `enrolments` (at most 200) |
| `POST issue/` `{user_id}` | `manage` | allow an engineer to enrol |
| `POST enrolments/<id>/cancel/` | `manage` | cancel an open enrolment |
| `POST <serial>/revoke/` `{reason}` | `manage` on any; the owner on their own | `reason` is `lost`, `left`, `admin` or `other` |
| `GET ca/` | `view` or `manage` | exists, `server_id`, dates, `expires_in_days`, `expiring` (365 days or less), counts, `master_key_available` |
| `POST ca/replace/` `{"confirm": true}` | effective superuser only | see below |

A certificate row is `{serial, short_serial, pc_label, username, engineer_id, issued_at, not_after, state, expiring, revoked_at, revoked_reason, last_used_at}`. `state` is `active`, `expired` or `revoked`. `expiring` is true for an active certificate with 30 days or less left. `last_used_at` stays empty until Core 1.18.53.

A refused permission is hidden and refused (AD-12): Core writes one `deny` audit row and answers 403. A body with an unknown key is a 400. A serial must be 32 lower-case hex characters. Write routes are limited to 30 a minute and 500 a day per person and address.

## Permissions

A new group, **Console certificates**:

- `core.console_certificates.view`: see every certificate and the CA status.
- `core.console_certificates.manage`: allow an engineer to enrol, cancel an enrolment, revoke any certificate. Manage includes view.

An effective superuser holds both. Replacing the CA is for effective superusers only.

## The validity setting

`console_certificate_validity_days` in `GET/PATCH /api/tfd/system/runtime-settings/`: a whole number from 1 to 730, default 365. Only an effective superuser changes it. It affects new certificates only. See `docs/runtime-settings.md`.

## Replacing the CA

`POST ca/replace/` retires the active CA (it is kept, marked retired), makes a new one, revokes every active certificate of the old CA with the reason `ca_replaced`, cancels every open enrolment (their codes stop working) and writes one audit row with the counts. After a replace the server id changes, so every engineer is allowed again by an administrator and enrols again.

Use it when the CA key may be exposed, when the CA is close to its end (the CA page shows `expiring` from 365 days), or after the master key was lost.

## If the master key is lost

The CA key can no longer be decrypted. Core answers `master_key_unavailable` for issuing, codes and enrolling. Fix the master key file if it was only moved or its permissions changed (see `docs/secret-store.md`). If the key is truly gone, an effective superuser replaces the CA. Engineers then enrol again.

## Clock skew

A certificate starts 5 minutes before it was made, so a Console clock a few minutes slow still accepts it. A clock that is wrong by more than that will see a new certificate as "not yet valid". Fix the PC's clock.

## Audit rows

Every row is module `core` with `operation_context.server_provenance = console-certificates`. Rows marked strict are written in the same database transaction as the change: if the row cannot be written, the change is not made (503 `audit_failed`).

| Action | Strict | When |
|---|---|---|
| `custom:console-ca-created` | yes | the first issue creates the CA |
| `custom:console-ca-replaced` | yes | the CA was replaced (counts of revoked certificates and cancelled enrolments) |
| `custom:console-cert-issue-authorised` | yes | an administrator allowed an engineer |
| `custom:console-cert-enrolment-cancelled` | yes | an administrator cancelled an enrolment |
| `custom:console-cert-issued` | yes | a certificate was signed |
| `custom:console-cert-revoked` | yes | a certificate was revoked (also for `replaced`) |
| `custom:console-cert-enrol-code` | no | an engineer asked for a code (never the code) |
| `custom:console-cert-enrol-refused` | no | an enrolment was refused (reason and address; at most one a minute per address) |
| `deny` | no | a permission refusal |

A row may hold a serial, a key fingerprint (`spki_sha256`), a PC label, a date, ids, a reason, counts and an address. It never holds a code, a ticket, a key, a signature, a proof, a header value or the CA private key.

## Not enforced yet

Core 1.18.52 only issues and records certificates. Until Core 1.18.53:

- No tunnel checks a certificate. A tunnel opens exactly as before.
- Revoking a certificate, or replacing the CA, changes the database only. It does not end a tunnel that is open or opening.
- `last_used_at` stays empty.
- The Console and the Core UI pages for this (My Account card, certificate list) ship separately. Until then use the routes above.

Do not tell an engineer that revoking a certificate stops a Console. In this release it does not.
