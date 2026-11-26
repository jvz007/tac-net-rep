# Tec-Tac Framework 1.18.56

Date: 26 November 2026. The Engineer Console can now sign in to Tec-Tac without ever seeing a password, and every request it makes is signed with the PC's own key. This is C1 of the Engineer Console sign-in plan (Johan, 26 November 2026). Core only. `main` stays held.

In plain words: the engineer signs in to Tec-Tac in the browser as always (password and authenticator code, or single sign-on). The browser then gives the Console a one-time code. The Console swaps that code for a session by proving it holds the private key of the PC's certificate. After that, every request carries a signature of its own bytes, so a stolen token is useless on its own and a replayed request is refused. The session is a normal Tec-Tac session: idle limit, absolute limit, IP-change policy, "end this session" in Access and the sweep all apply. Every way a session can end also ends the tunnels opened from it.

## Module-facing change

`networkprobe` is the only module that uses what changes. Everything is additive.

- **New capability `core.console_session` 1.0.0** (framework >=1.18.56), with one operation, `console_info(request)`. A module that serves the Console lists `tec_tac.console_sessions.ConsoleSessionAuthentication` as the route's authentication class and `tec_tac.console_sessions.ConsoleSessionAuthenticated` as its permission, after `has_capability('core.console_session')`, and then checks its own permission as always. `console_info(request)` answers `{serial, short_serial, pc_label}` for such a request and `None` for anything else. It never returns a token, a digest or a key. Three new contract rows, five route entries and one rule carry it; the exact bytes are in the new `docs/console-sessions.md`.
- **The tunnel connect now checks the serial.** `issue_tunnel_ticket` is unchanged in its answers, and `core.probe_transport` stays at 1.3.0. A ticket asked for from a Console session is tied to that session's certificate: the Console connect must use that serial, or Core closes it with `certificate_engineer_mismatch`, which is already one of the seven connect reasons. A ticket asked for from the browser works with any of the person's certificates, as before.
- **The Access sessions list gets one extra key.** Each row of `GET /api/tfd/access/sessions/` carries `console`: `{pc_label, short_serial}` for a Console session and `null` for any other. Existing keys are unchanged. The UI can write "Engineer Console (PC label)".
- **The caller list of Core's internal access marker grew by one function.** `access_events.mark_changed` now accepts `probe_tunnel.update_site` and `probe_tunnel.console_session_ended`, and nothing else. A call from a module is still refused. No module gains any access to access events.
- **One new refusal in the session guard.** A request that reaches a normal Core route with `X-Tectac-Console-Proof` next to another credential is refused (`session_invalid_state`). Only the Console sends that header, and only to the Console routes. No module route that works today sends it.

Nothing changes for a module that does not serve the Console.

## Closes

- The ORDER "Core 1.18.56 = C1 Console sessions" in `reviews/requests/core.md` (Johan, 26 November 2026). The release manager moves the entry; Core only names the version.
- Held Low of the 1.18.55 review: a late `ca_replaced` task ended every live tunnel session, including sessions of the new CA.
- Held Low of the 1.18.55 review: the end loop swallowed Celery's soft time limit as an ordinary fault and kept going.

## What changed and why

1. **Two new tables, migration `0050_console_sessions`.** `core_console_session` holds the Console's sign-in record: the SHA-256 of its token (never the token), the PC's certificate serial, the Tec-Tac session behind it and why and when it ended. `core_console_signin` holds one-time sign-in codes (the SHA-256 only), bound to the person, serial, PKCE challenge (the browser's proof that the same party finishes the sign-in), loopback port and host. Both are plain-integer tables with no foreign key to the user, like 0049, so no swappable dependency is needed. Written by hand; Django cannot run `makemigrations` here, so a test compares the migration with the models field for field and runs Django's own autodetector against it.
2. **Sign-in, two steps.** `POST /api/tfd/console-sessions/authorise/` (the browser, signed in as a person, not an API key) gives a code for one of the person's own active certificates: 60 seconds, once, 10 a minute and 100 a day per person. `POST /api/tfd/console-sessions/token/` (the Console, no sign-in) takes the code, the PKCE verifier, the certificate and a proof signed with the certificate's key. Every step fails closed and the code is burnt the moment it is taken, whatever follows. The failure limit is its own counter, 10 a minute per address, and it never shares the enrolment counter. A refusal writes at most one `custom:console-signin-refused` row per address per minute.
3. **One shared certificate check.** The parse, issuer, CA signature, stored-row, active-CA, revoked, expired and not-yet-valid steps of the tunnel connect moved into one helper, `_certificate_row`, that both the tunnel connect and the sign-in call. `verify_connect` keeps its exact order and answers; the 1.18.53 tests pin them and still pass unchanged.
4. **All or nothing.** The sign-in is one transaction: end the older session of this PC, mint a Knox token (Tactical's own credential table; only its digest is kept and the token is thrown away at once), make the Tec-Tac session and the Console session, write the strict `custom:console-signin` row and the `session_created` event, and sign Core's proof with the CA key. A failed audit row, or a CA key that cannot sign, rolls all of it back: no row, no session.
5. **Every request is signed.** `ConsoleSessionAuthentication` reads `Authorization: TecTacConsole <token>` and `X-Tectac-Console-Proof`. It looks the token up by hash first (before any crypto), re-reads the PC's certificate (revoked, expired or retired CA ends the session), checks the time (120 seconds), checks the signature over the method, path with query, body hash, token hash, time and nonce, and only then keeps the nonce for 5 minutes. A repeat is refused. A down cache refuses with 503, so no cache means no Console requests. The body is read only up to 64 KiB. `ConsoleSessionAuthenticated` then checks the account (active, not blocked, not an installer), that the Knox token still exists, and applies the browser's session policy unchanged.
6. **The Console token works on the Console routes only.** `current/`, `activity/` and `sign-out/` list `ConsoleSessionAuthentication` alone. No other Core route lists it and Tactical's own token class ignores the prefix. A test walks the source and the URL file to prove it.
7. **Every way a session ends ends the Console session.** One hook in the session guard's revoke covers the administrator's revoke in Access (one session, all of a person's sessions, all sessions), the idle and absolute limits, the IP-change policy and the sweep. A certificate revoke and a CA replacement end the Console sessions inside the same transaction. A deactivated or blocked account is refused and ended at its next request. After commit, the person's live tunnels re-check within one 5-second tick, and the ones opened from the ended session end (the browser-opened ones of the same person stay). A failing audit row or hook never blocks a revoke: the signout row is not strict, and each Console request re-reads its own certificate and session anyway.
8. **Serial equals session.** `issue_ticket` records the Console session's certificate serial in the ticket (cache only), and `console_open` refuses a different serial before the account check. The Console attach marker now also stores the CA id.
9. **The two held Lows.** `run_end('ca_replaced', id)` ends only sessions whose Console connected under the replaced CA (the marker's `server_id`; for a marker from before this release, the certificate row of its serial decides, and a row that cannot be read ends the session). `SoftTimeLimitExceeded` is re-raised so the 30-second limit stops the run cleanly.
10. **Docs and a stand-in client.** New `docs/console-sessions.md` carries the exact bytes of the three messages (a test rebuilds them from the document's own worked example), the routes, error codes, lifetimes, audit rows and end reasons. `examples/console-session-client.py` is a small Python Console (standard library plus `cryptography`) so the dev02 checklist can run before the Console app exists.

## Assumptions

Johan's decisions are in `reviews/questions/core.md` as information. None blocks this release.

- **Codes and sessions are database rows, not cache entries.** A one-time code is burnt by one conditional update, so it stays "used" through a cache restart. Only the request nonce is in the shared cache, and it fails closed when the cache is down.
- **`client_version` is optional.** The signed `token/` body had no version field. A Console that sends one below `console_min_version` (0.1.1) gets 426 before its code is touched; a Console that omits it is not refused. Core announces `console_min_version` in every token and `current/` answer. A field the signed shape lacks cannot be made required without changing the shape, so it is optional until Johan says otherwise.
- **One live session per PC.** A new sign-in on the same certificate serial ends the older one (reason `replaced`), so an abandoned sign-in cannot pile up Knox tokens.
- **The server proof also covers the token's hash.** One extra line in the signed message lets the Console see that Core issued that exact token to its nonce. It is inside the plan's "signed by the CA over the Console's nonce".
- **A revoke that cannot write its row still revokes.** Failing closed means the session ends, never that a revoke is blocked by the audit log. The sign-in row stays strict.
- **The plan's "five console-sessions views" is three.** Only `current/`, `activity/` and `sign-out/` accept the Console class. `authorise/` is the browser's and `token/` has no sign-in of its own.
- **The messages the plan left to the document.** The sign-in proof is `tectac-console-signin-v1` over host, server, the code's hash, the PKCE verifier's hash (as the plan lists), serial, time and nonce. The request message and Core's proof follow the plan's text. All three are in `docs/console-sessions.md`.
- **An idle or absolute refusal inside a request is rolled back, as for the browser.** The session guard raises inside its own transaction, so the request is refused every time and the sweep records the end. The Console behaves exactly like the browser here.
- **Live tunnels end through the existing access marker.** No new channel and no module access.

## New tests

- `tests/console-sessions-migration-1.18.56.py`: migration 0050 against the models field for field, Django's autodetector finds nothing left, no shadowed field names, the SQL, real SQLite unique checks.
- `tests/console-sessions-signin-1.18.56.py`: the whole sign-in with a real P-256 key; the server proof verifies against the CA key; the code works once and not after 60 seconds; a wrong verifier burns it; another person's serial, an API key, a bad port, challenge, key set, an over-size body and a plain-text connection are refused; wrong, stale, future, other-host, other-code, other-serial and other-key proofs; revoked, expired and old-CA certificates; the 11th failure is 429 and one refusal row a minute; a failed strict row and a failed server proof leave no session; a second sign-in ends the first; no code, verifier, proof, token or raw Knox token in any row, log line or the database file; message bytes pinned; `client_version` and 426; the throttles.
- `tests/console-sessions-request-proof-1.18.56.py`: a valid GET and POST; a proof for another method, path, query, body, token, host, server or serial; stale and future time; a replayed nonce, the same nonce on another PC, a down cache (503), a garbage token (no crypto); a revoked or expired certificate, a retired CA, a deactivated, blocked or installer account (each ends the row with its reason); idle, absolute and IP change as for the browser; activity; sign-out; `last_used_at` at most once a minute; a body over 64 KiB.
- `tests/console-sessions-isolation-1.18.56.py`: the Console class is listed only on the three Console-only views; the Console token is refused on Core routes; a Knox token and an API key are refused on the Console routes; a Knox Authorization with the proof header is refused; `current/` never returns a secret.
- `tests/console-sessions-revoke-1.18.56.py`: each cause (certificate revoke, CA replacement, admin revoke of one session, a person's sessions, all sessions, the session contract's user-name revoke, the idle sweep, sign-out, a deactivated account) ends the row with its reason, writes one signout row, deletes the Knox token and refuses the next request; the access marker moves; the Console-opened tunnel's re-check ends while a browser-opened one does not; `access_events` accepts exactly two functions of `probe_tunnel.py`; a failing audit write or hook never blocks a revoke; the `console` key of the Access list.
- `tests/probe-tunnel-console-serial-1.18.56.py`: serial equals session, and a browser ticket is unchanged.
- `tests/probe-tunnel-end-lows-1.18.56.py`: the two held Lows.
- `tests/console-sessions-capability-1.18.56.py`: the capability, `console_info`, the contract rows, the rule and the docs.
- `tests/console-sessions-docs-1.18.56.py`: the document's worked example rebuilt with Core's builders, byte for byte; every code, route, limit and reason in the document.
- `tests/console-sessions-example-client-1.18.56.py`: the stand-in client against the real routes.
- `tests/version-1.18.56.py`: version, notes, headings, checklist, line endings.
- Shared fixtures: `tests/console_sessions_harness.py`.

## What could not be run here

Django 6.1 and `cryptography` ran on this PC, so every test above ran for real, with real signatures and a real SQLite file. Not run here: Knox itself (the tests use a small stand-in with Knox's manager rules: `create(user, expiry as a timedelta)` returns the row and the token, and the digest is the SHA-512 of the token), Celery, Redis, channels and the websocket consumers (the 5-second tick that reads the access marker is proved through the session re-check it calls, not through a live socket), PostgreSQL, `makemigrations` and Tactical's own apps. `tests/contract-catalog-1.17.68.py` fails on this PC because it expects an older question file layout under `reviews/`; it is not in `release-integrity.sh` and has nothing to do with this release. The dev02 checklist carries the real proof.

## Johan dev02 checklist

You do not need the Console app. Use `examples/console-session-client.py` (Python 3.10 or newer and `pip install cryptography`). The setup is the same for every step.

**Setup.** On a PC with Python, run `python console-session-client.py keygen --key console.pem`. In Tec-Tac, allow yourself to enrol a Console (Console certificates, as in 1.18.55), open My Account, make an enrolment code and run `python console-session-client.py --insecure enrol --server <dev02 host> --code <code> --key console.pem --label "Test PC" --state state.json`. (`--insecure` only if dev02 has a self-signed certificate.) For each sign-in you also need the `Authorization` header value of a signed-in browser: open any Tec-Tac page, open the browser's developer tools, Network tab, click one request to `/api/` and copy the `Authorization` value (it looks like `Token abc...`). The Console app will replace this step.

**A. Sign-in with password and authenticator code.** Sign in to Tec-Tac normally with a password account. Run `authorise --state state.json --knox "<copied value>"`, then `signin --state state.json`, then `current --state state.json`. PASS: `signin` says "The server proof verifies against the CA key" and `current` answers HTTP 200 with your name and PC label. FAIL: any other status, or the server proof does not verify. Send back: the three outputs.

**B. Sign-in with single sign-on.** Repeat A as a person who signs in with SSO. PASS: it works, and the session audit (Access > session history, or `GET /api/tfd/session/audit/`) shows a `session_created` event with `auth_method` `console` and `browser_auth_method` `sso`. FAIL: it is refused, or the method says `password`. Send back: that event.

**C. Another person's certificate is refused.** Copy the `Authorization` value of a browser signed in as a different person and run `authorise` with it, using the first person's `state.json`. PASS: HTTP 403 `serial_not_allowed` and no code. FAIL: a code is given. Send back: the output.

**D. A replayed request is refused.** Run `replay --state state.json`. PASS: "first send" is HTTP 200, "replayed send" is HTTP 401 `proof_replayed`, and the last line says PASS. FAIL: the second is accepted. Send back: the output.

**E. A copied token without a proof is refused.** Open `state.json`, copy `token`, and run `curl -k -H "Authorization: TecTacConsole <token>" https://<dev02 host>/api/tfd/console-sessions/current/`. PASS: HTTP 401. FAIL: HTTP 200. Send back: the curl output (not the token).

**F. The token is refused on a normal route.** Run `curl -k -H "Authorization: TecTacConsole <token>" https://<dev02 host>/api/tfd/console-certificates/mine/`. PASS: HTTP 401 or 403 and no data. FAIL: any data. Send back: the output.

**G. The idle limit.** Leave a signed-in Console session untouched for the idle limit (30 minutes by default; you may lower it in Access > session policy for the test) and run `current`. PASS: HTTP 401 `session_idle_timeout`. FAIL: HTTP 200. Send back: the output. Then run `activity` every few minutes in another session and confirm it stays signed in (PASS: HTTP 200 each time).

**H. A revoked certificate ends the session and the tunnel.** With a live Console session (and, if you have the Console tunnel build, a tunnel open from it), revoke that PC's certificate in Console certificates. PASS: `current` is HTTP 401 `certificate_revoked` at once, the Knox token is gone from Access > sessions, and a tunnel opened from that session ends within about 10 seconds. FAIL: it still works. Send back: the audit row `custom:console-signout` for the session.

**I. Replacing the CA.** With two signed-in Console sessions, replace the CA (superuser). PASS: both sessions end with reason `ca_replaced`, and a tunnel opened from the browser by the same person stays up. FAIL: either survives, or the browser tunnel ends. Send back: the two signout rows.

**J. A deactivated account.** With a live Console session, deactivate that account. PASS: the next request is HTTP 401 `account_inactive`, the session is gone from Access > sessions and a tunnel from it ends. FAIL: it still works. Send back: the audit row.

**K. An administrator ends the session.** In Access > sessions find the row. PASS: it shows "Engineer Console (PC label)" once the UI release lands, or `console` with the PC label in the list answer until then. End it from there: `current` is HTTP 401 `session_revoked`. FAIL: it keeps working. Send back: the list row and the output.

**L. Sign-out.** Run `sign-out --state state.json`, then `current`. PASS: sign-out says `revoked: true`, then `current` is HTTP 401. FAIL: `current` still works. Send back: the output.

**M. The audit rows.** Search the audit log for `custom:console-signin`, `custom:console-signout` and `custom:console-signin-refused` (make a refusal with a wrong code, for example `signin --code AAAA... --verifier AAAA...` using 43 characters each). PASS: each row exists, the sign-in row is under your name, the refusal row is under the service name, and none holds a code, token, proof, certificate or header value. FAIL: any secret in a row. Send back: the rows.

## Not in this release

C2 (the enrolment code over a loopback address with PKCE) is Core 1.18.57. The Core UI pages (`#/console/sign-in` and `#/console/enrol`, with the Yes/No dialog and the label "Engineer Console (PC label)") are UI 0.13.8 and need Core 1.18.57. The `networkprobe` Console routes and RDP are `networkprobe` 0.2.27 and 0.2.28. The Console app, its sign-in and the probe installer fix are the probe developer's. The tunnel check-in (on hold until a dev02 cable-pull test), the access-changed event for declared modules, the `networkprobe` request to publish a tunnel's end detail and the `softwarerepository` result-check questions are not in this release. Licensing of the Console is not checked by this release.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
