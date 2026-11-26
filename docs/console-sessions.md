# Engineer Console sessions

Core 1.18.56 (C1 of the Engineer Console sign-in plan, signed 26 November 2026). This page is for the people who build the Engineer Console and the modules that serve it (`networkprobe`). You can build against it without reading Core's code.

## In plain words

An engineer signs in to the Engineer Console from the Tec-Tac page in their browser. The Console never sees a password, a one-time code or a single sign-on token. Core's browser sign-in (password plus authenticator code, or single sign-on) stays exactly as it is.

1. The engineer opens the Console sign-in page in Tec-Tac. The browser asks Core for a **one-time code** for one of the engineer's own certificates (`authorise/`).
2. The browser hands that code to the Console on a loopback address (`http://127.0.0.1:<port>/`).
3. The Console swaps the code for a **session** (`token/`). It proves two things: it knows the secret the browser chose (PKCE), and it holds the private key of the PC's certificate.
4. From then on every request carries the Console's token **and a fresh signature of that exact request**. A copied token is useless without the key, and a replayed request is refused.

A Console session is a normal Tec-Tac session. Idle time, the absolute limit, the IP-change policy, the sweep and the administrator's "end this session" all apply. Every way it can end also ends the tunnels opened from it.

## Lifetimes and limits

| What | Value |
|---|---|
| One-time sign-in code | 60 seconds, works once, kept only as a SHA-256 |
| Console token | 43 characters (`secrets.token_urlsafe(32)`), kept only as a SHA-256 |
| Proof window | 120 seconds either side of Core's clock |
| Request nonce | kept 5 minutes per certificate serial |
| Idle limit, absolute limit, IP-change policy | the Tec-Tac session policy (30 minutes, 8 hours and "re-authenticate" by default) |
| `authorise/` | 10 a minute and 100 a day per person |
| `token/` | 10 failures a minute per address (IPv6 by its /64), its own counter |
| `activity/` | 30 a minute per person |
| Body of `token/` | at most 4 KiB |
| Body of a Console request | at most 64 KiB |
| Minimum Console version | `console_min_version`, 0.1.1 |

One live Console session per certificate serial: a new sign-in on the same PC ends the older one (reason `replaced`).

## Headers

| Header | Used on | Value |
|---|---|---|
| `X-Tectac-Console-Cert` | `token/` | the PC's certificate, DER, base64url without padding, at most 2048 characters |
| `X-Tectac-Console-Proof` | `token/` and every Console request | `v1.<time>.<nonce>.<signature>` |
| `Authorization` | every Console request | `TecTacConsole <43-character token>` |

`<time>` is whole seconds since 1970 (1 to 12 digits). `<nonce>` is 16 random bytes as 22 base64url characters. `<signature>` is 64 bytes as 86 base64url characters: the ECDSA P-256 / SHA-256 signature in IEEE P1363 form (`r` then `s`, 32 bytes each). base64url means the URL-safe alphabet without `=` padding, and Core refuses text that does not re-encode to itself.

## The routes

All under `/api/tfd/console-sessions/`. Every answer, refusals included, carries `Cache-Control: no-store`.

### `POST authorise/` (the browser)

A signed-in, interactive person (a Knox token). An API key or a plain Django session gets 403 `interactive_session_required` and one deny audit row.

Body, exactly these keys:

```json
{"serial": "<32 lower-case hex>", "code_challenge": "<43 base64url characters>", "redirect_port": 40123}
```

- `serial` must be an active, unexpired certificate of the active CA that belongs to the signed-in person. Anything else gives one 403 `serial_not_allowed` body, whether or not the serial exists.
- `code_challenge` is `base64url(SHA-256(verifier))`, where the verifier is 43 base64url characters the browser keeps.
- `redirect_port` is a whole number from 1024 to 65535 (not a boolean).

Answer `200`: `{"code": "<43 characters>", "expires_in": 60, "host": "<Core's host>", "server_id": "<32 hex>"}`.

Errors: 400 `invalid_request`, `unknown_field`, `host_unusable`; 403 `interactive_session_required`, `serial_not_allowed`; 429 (throttled); 503 `master_key_unavailable` (checked first, because the sign-in needs the CA key).

### `POST token/` (the Console)

No sign-in: the code, the verifier, the certificate and the proof are the credential. https only (a request the proxy says was plain text gets 403 `tls_required`).

Body, at most 4 KiB, exactly these keys plus the optional `client_version`:

```json
{"v": 1, "code": "<43 characters>", "code_verifier": "<43 characters>", "serial": "<32 hex>", "client_version": "0.1.1"}
```

Core checks, in this order, and every step fails closed:

1. The failure limit of the address (429 `rate_limited`, `Retry-After: 60`).
2. The body's shape, and the two headers' shape.
3. `client_version`, if present, is not below `console_min_version` (426 `console_update_required`; the code is **not** touched).
4. The code is taken with one atomic update (unused, unexpired, matching). From this moment it is burnt, whatever follows.
5. The code was made for this host.
6. The certificate: it parses, was issued by the active CA, the CA signature holds, the key is a P-256 key, the stored row has the same bytes, key hash and CA, and it is not revoked, expired or not yet valid. The certificate's person and serial must equal the code's person and serial and the body's serial.
7. PKCE: `base64url(SHA-256(code_verifier))` equals the stored challenge.
8. The sign-in proof (message below), within 120 seconds.
9. The account is active, not blocked from the dashboard and not an installer account.

Then, in one transaction, Core ends any older session of this PC, mints a Knox token (Tactical's own sign-in credential; only its digest is kept and the token itself is thrown away), makes the Tec-Tac session, makes the Console session, writes the strict audit rows and signs the server proof. If any step fails, none of it is kept.

Answer `201`:

```json
{
  "v": 1, "token": "<43 characters>", "idle_minutes": 30, "absolute_expires_at": "<ISO time>", "heartbeat_seconds": 60,
  "console_min_version": "0.1.1", "engineer": {"id": 7, "username": "name"}, "serial": "<32 hex>", "pc_label": "Work PC",
  "server_id": "<32 hex>", "server_proof": "v1.<86 characters>"
}
```

The Console must verify `server_proof` with the CA public key it was enrolled with (message below) before it trusts the answer.

| Status | `code` |
|---|---|
| 400 | `invalid_request`, `host_unusable` |
| 401 | `code_invalid` (one body for an unknown, used, expired or badly shaped code), `host_mismatch`, `verifier_invalid`, `certificate_required`, `certificate_invalid`, `certificate_expired`, `certificate_revoked`, `certificate_engineer_mismatch`, `proof_invalid`, `proof_stale` |
| 403 | `tls_required`, `account_inactive` |
| 413 | `body_too_large` |
| 426 | `console_update_required` |
| 429 | `rate_limited` |
| 503 | `master_key_unavailable`, `audit_failed` |

### `GET current/`, `POST activity/`, `POST sign-out/` (the Console)

These accept only `ConsoleSessionAuthentication`: `Authorization: TecTacConsole <token>` and `X-Tectac-Console-Proof` for this request.

- `current/` answers `{engineer: {id, username}, serial, short_serial, pc_label, created_at, last_activity_at, idle_expires_at, absolute_expires_at, console_min_version, heartbeat_seconds}`. It never returns a token, a digest or a key.
- `activity/` extends the idle limit like the browser's heartbeat and answers `{last_activity_at, idle_expires_at, absolute_expires_at}`. Send it every `heartbeat_seconds` while the engineer works.
- `sign-out/` revokes the Tec-Tac session (which deletes the Knox token), ends the Console session and the tunnels opened from it, and answers `{"revoked": true}`.

Refusals are `401` with `WWW-Authenticate: TecTacConsole` and one of: `token_invalid`, `session_revoked`, `certificate_revoked`, `certificate_expired`, `account_inactive`, `proof_invalid`, `proof_stale`, `proof_replayed`, or the session guard's own `session_idle_timeout`, `session_absolute_timeout`, `session_ip_change`, `session_invalid_state`. 413 `body_too_large` is a body over 64 KiB and 503 `proof_unavailable` means Core's nonce store is down (no Console request works while it is).

## The exact bytes

Every message is text in ASCII (the request message may carry UTF-8 in the path), lines joined by one LF (`\n`), **no trailing newline**. `sha256_hex(x)` is the SHA-256 of `x` as lower-case hexadecimal. `host` is Core's host in lower case without a port (`tec.example.com`); `server` is the `server_id` of the CA. A code, a verifier or a token is never signed as text: only its `sha256_hex`.

The worked example below uses these inputs. Core's tests rebuild every message from this block and require the same bytes.

```json
{
  "host": "tec.example.com",
  "server": "0123456789abcdef0123456789abcdef",
  "code": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
  "verifier": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
  "token": "RSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx",
  "serial": "00112233445566778899aabbccddeeff",
  "time": "1764158400",
  "nonce": "AAECAwQFBgcICQoLDA0ODw",
  "method": "POST",
  "path": "/api/tfd/networkprobe/console/connect/?site=3",
  "body": "{\"probe\":\"p1\"}"
}
```

### 1. The sign-in proof (the Console signs, on `token/`)

```
tectac-console-signin-v1
host=<host>
server=<server>
code=<sha256_hex(code)>
verifier=<sha256_hex(code_verifier)>
serial=<serial>
time=<time>
nonce=<nonce>
```

`verifier` is the PKCE verifier the browser step chose, so the proof is tied to the same sign-in as the code.

Worked example:

<!-- message:signin -->
```text
tectac-console-signin-v1
host=tec.example.com
server=0123456789abcdef0123456789abcdef
code=46a2199782c8827f0ac56f503be9d39efee97f40a736b92cc7d7c5f825cfd851
verifier=71d84b1859bad11abcb3dfd9353c8d1873aafd883ffaf6f2c9df7cbcfc3e1850
serial=00112233445566778899aabbccddeeff
time=1764158400
nonce=AAECAwQFBgcICQoLDA0ODw
```

### 2. The server proof (Core signs with the CA key, `server_proof` of the answer of `token/`)

```
tectac-core-signin-v1
host=<host>
server=<server>
code=<sha256_hex(code)>
serial=<serial>
token=<sha256_hex(token)>
nonce=<nonce>
```

`nonce` is the Console's own nonce from its sign-in proof, so the Console knows this answer was made for its request. `token` is the hash of the token in the same answer, so the Console knows Core issued that exact token. The value is `v1.` and the 64-byte signature as base64url.

Worked example:

<!-- message:server -->
```text
tectac-core-signin-v1
host=tec.example.com
server=0123456789abcdef0123456789abcdef
code=46a2199782c8827f0ac56f503be9d39efee97f40a736b92cc7d7c5f825cfd851
serial=00112233445566778899aabbccddeeff
token=8c9da97a46e9316a342e08f8d8b8dc13ccec197518535cc415d9cb5d6bd99423
nonce=AAECAwQFBgcICQoLDA0ODw
```

### 3. The request proof (the Console signs, on every request after the sign-in)

```
tectac-console-request-v1
host=<host>
server=<server>
serial=<serial>
method=<upper-case method>
path=<request target with its query string>
body=<sha256_hex(raw body bytes)>
token=<sha256_hex(token)>
time=<time>
nonce=<nonce>
```

- `path` is the request target exactly as the Console sends it: the path and, if there is one, `?` and the query string, percent-encoded as on the wire (Core reads it with Django's `get_full_path()`).
- `body` is the hash of the raw body bytes. A request with no body signs the hash of the empty input (`e3b0c442...b855`).
- Core keeps the nonce for 5 minutes per serial only after the signature held. Use a new nonce for every request.

Worked example:

<!-- message:request -->
```text
tectac-console-request-v1
host=tec.example.com
server=0123456789abcdef0123456789abcdef
serial=00112233445566778899aabbccddeeff
method=POST
path=/api/tfd/networkprobe/console/connect/?site=3
body=ff373b2e3cbcee2cf8043cc797c54f6bddcd16bda98126c044167b664a57a687
token=8c9da97a46e9316a342e08f8d8b8dc13ccec197518535cc415d9cb5d6bd99423
time=1764158400
nonce=AAECAwQFBgcICQoLDA0ODw
```

## What gets written to the audit log

All rows are Core rows (`module core`, `operation_context.server_provenance = console-sessions`). No row, log line, exception text or answer ever holds a code, a verifier, a challenge, a token, the Knox token, a ticket, a certificate, a proof, a signature or a header value.

| Action | Strict | Actor | When |
|---|---|---|---|
| `custom:console-signin` | yes: no row, no session | the engineer | a Console signed in; holds the session id, serial, PC label, address and the browser sign-in method |
| `custom:console-signout` | no: a failed write never blocks a revoke | the `console-sessions` service | a Console session ended; holds the session id, serial, PC label, engineer and `reason` |
| `custom:console-signin-refused` | no, at most one per address per minute | the engineer once the code matched, otherwise the `console-sessions` service | a refused `token/`; holds the reason, the address and a serial that parsed to 32 hex |
| `deny` | no | the person | an API key or plain Django session asked for a code |

The Tec-Tac session audit also gets a `session_created` event with `auth_method` `console` and `browser_auth_method` (`password` or `sso`, as the engineer's account signs in).

## How a session ends

Every way ends the Console session, deletes its Knox token, writes one `custom:console-signout` row with its reason and makes the person's live tunnels re-check within one 5-second tick (the ones opened from the ended session end within about 10 seconds; a tunnel opened from the browser is not touched).

| `reason` | Cause |
|---|---|
| `engineer` | `sign-out/` |
| `idle` | the idle limit passed (a Console request, or the sweep) |
| `absolute` | the absolute limit passed |
| `ip_change` | the IP-change policy ended it |
| `certificate_revoked` | the certificate was revoked, or its CA is no longer the active CA |
| `certificate_expired` | the certificate ended |
| `ca_replaced` | the Console CA was replaced |
| `account_inactive` | the account was deactivated, blocked from the dashboard or became an installer account |
| `admin` | an administrator ended it in Access > sessions, ended all of the person's sessions or every session, or the Knox token is gone |
| `replaced` | a newer sign-in on the same PC |

## For a module

A module that serves the Console (`networkprobe`) checks `has_capability("core.console_session")`, requires `framework >=1.18.56` and lists, on the routes the Console calls:

```python
from tec_tac.console_sessions import ConsoleSessionAuthenticated, ConsoleSessionAuthentication

class ConsoleRoute(APIView):
    authentication_classes = [ConsoleSessionAuthentication]
    permission_classes = [ConsoleSessionAuthenticated]
```

The request then carries `request.user` (the engineer), `request.tec_tac_session` and `request.auth` (a `ConsoleAuth` with `digest`, `serial`, `short_serial` and `pc_label`). The module checks its own permission as for any request. `tec_tac.console_sessions.console_info(request)` returns `{serial, short_serial, pc_label}` for such a request and `None` for anything else.

A module never sees a token, a code, a certificate or a key. It never mints or stores a Console credential and never writes a Console session row. A tunnel ticket asked for from a Console session (`issue_tunnel_ticket`) is tied to that session's certificate: the tunnel connect must use that serial, or it is refused with `certificate_engineer_mismatch`. `core.probe_transport` stays at 1.3.0.

The Console token is refused on every other route. See also `docs/console-certificates.md` (enrolment and the certificate) and `docs/probe-transport.md` (the tunnel).
