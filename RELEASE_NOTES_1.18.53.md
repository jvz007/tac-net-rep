# Tec-Tac Framework 1.18.53

Date: 25 November 2026. The Engineer Console certificate now protects the tunnel. This is C4 of the signed Engineer Console certificate plan, with the held Medium finding of the 1.18.52 review. Every Console connect must carry a certificate and a proof signed with its key. Core answers with a proof of its own. Revoking a certificate or replacing the CA ends the live tunnels within seconds. Three routes that start an enrolment now refuse API keys. It is a Core-only change. `main` stays held.

## Module-facing change

`core.probe_transport` is now 1.3.0. It is additive: no operation, argument or answer shape changed. Core enforces one new refusal for an existing call.

- **`issue_tunnel_ticket` has a new denied code.** A person with no active, unexpired Engineer Console certificate of the active CA gets `{outcome: "denied", code: "console_certificate_required", message: "this engineer has no valid Engineer Console certificate; enrol from My Account"}`. Core checks it after the permission and the scope and before the probe's presence, so no slot and no rate budget is spent. It writes one deny row, as every refusal does. A fault while reading it is `unavailable` (fail closed). There is no off switch and no transition period: the Console is not released yet.
- **A Console without a certificate cannot connect.** From this release the Console connect needs the two certificate headers. The ticket is no longer enough on its own.
- **Only `networkprobe` is affected.** A search of `modules/` for `probe_transport`, `issue_tunnel_ticket`, `console_certificate`, `console-certificates`, `X-Tectac-Console` and `probe-tunnel` finds `networkprobe` only (`auth.py`, `channel.py`, `tunnel.py` and their tests and notes), and no other module. `networkprobe` maps Core's answer by `outcome` alone (`CORE_STATUS` in `tunnel.py`), so the new code shows as its generic `denied` (HTTP 403, "Your sign-in or permission could not be confirmed"). Nothing breaks. No module reads a certificate, a code or a key.
- **New end details, in Core's own end row.** `certificate_revoked`, `certificate_expired` and `ca_replaced` appear as the `detail` of the `custom:probe-tunnel-end` row (the close reason stays `ended_by_core`). They are not yet published to `tunnel_status` or `tunnel.closed`. `networkprobe`'s allow-list of end details does not know them yet; that is the request below.
- **Two more headers and a server proof header on the Console route.** They are for the Engineer Console, not for a module.

Requests for the owners (written to `reviews/requests/`): the Engineer Console side (E1-b) for `probe-developer`, and a clearer message in `networkprobe` (optional polish). Core 1.18.53 and the Console that sends the proof must reach dev02 together.

What else is new, all additive:

- `POST mine/enrolment-code/`, `POST issue/` and `POST ca/replace/` answer `403 interactive_session_required` to an API key. A signed-in browser session (a Knox token) works as before. See below.
- `last_used_at` on a certificate is now filled.
- `custom:probe-tunnel-connect` and `custom:probe-tunnel-end` carry `cert_serial`. A new non-strict row, `custom:console-cert-refused`, records a refused certificate or proof.

## Closes

- Plan item C4 of `docs/planning/networkprobe/PLAN-ENGINEER-CONSOLE-CERTS-25-11-2026.md`, sections 4, 5 and 10: the connect proof, the server proof, the certificate check on connect and every 5 minutes, revocation and CA replacement ending live sessions, the expiry watcher, `cert_serial` on the tunnel audit rows, and `console_certificate_required` from `issue_tunnel_ticket`. `last_used_at` is filled.
- The request "core: Engineer Console certificates C4, enforcement on the tunnel (Core 1.18.53, Johan, 25 November 2026)" in `reviews/requests/core.md`.
- The request "core: add to C4 (Core 1.18.53): refuse API keys on the enrolment-code route" in `reviews/requests/core.md`, which is the held Medium of the 1.18.52 review.

## What changed and why

1. **The connect proof.** The Console now sends `X-Tectac-Console-Cert` (its certificate) and `X-Tectac-Console-Proof` (`v1.<time>.<nonce>.<sig>`). The signature covers the host, the server id, the SHA-256 of the ticket, the certificate serial, the time and the nonce. That ties the proof to this ticket, this server and this moment, so a copy of it is useless. All binary values are base64url without padding and signatures are 64-byte `r||s`, as on the enrol route. `docs/console-certificates.md` ("The tunnel connect, exactly") holds the exact bytes, with a worked example.
2. **The server proof.** On success Core adds `X-Tectac-Server-Proof: v1.<sig>` to the websocket accept. It is signed by the CA key over the host, the server id, the ticket hash, the serial and the Console's own nonce. The Console checks it with its pinned CA key before it opens its local port. That tells the Console it reached the right Core. The CA key is decrypted in memory inside one function and nowhere else. If the master key cannot be used, Core closes 1013 (`master_key_unavailable`) and the ticket is gone.
3. **The checks, in a fixed order, all failing closed.** The gate, the ticket header, the shape of the two certificate headers (the ticket is not yet burnt, so a Console can fix its headers), the ticket (burnt from here), the clock (at most 120 seconds off), the certificate and its CA signature, Core's table row (stored bytes, key fingerprint, active CA, revoked, expired, not yet valid), the engineer, the proof signature, and then the existing account, permission, module, record and scope checks. Every certificate failure is an accepted websocket that closes 4401 with one of seven reasons as the close text: `certificate_required`, `certificate_invalid`, `certificate_expired`, `certificate_revoked`, `certificate_engineer_mismatch`, `proof_invalid`, `proof_stale`. After a CA replacement an old-CA certificate answers `certificate_invalid`, because its issuer is no longer the active CA.
4. **Refusals are recorded once.** Each one counts against the address and writes one non-strict `custom:console-cert-refused` row (reason, address, session id, engineer id and the serial only when it parsed to 32 hex characters; at most one a minute per address). The seven reasons write no `custom:probe-tunnel-refused` row. No row ever holds a ticket, a certificate, a proof or a header.
5. **An early, friendly refusal.** `issue_tunnel_ticket` refuses a person with no valid certificate before any slot is used. The connect check is the real gate.
6. **Revoking ends tunnels at once.** After a revoke commits, Core ends every live session that used that certificate (`end_for_certificate`). After a CA replacement it ends every live session (`end_all_sessions`). Both run after the database commit, inside a guard: a fault is logged and never undoes or blocks the revoke. The same hooks write a short-lived marker in the shared cache. Each Console socket reads both markers with one `get_many` in its existing 5-second tick. That also closes the race of a connect that passed its database check just before the revoke committed. The work for one revoke is capped at 10 seconds; what is left ends through its marker.
7. **Checks while a session runs.** Every 5 minutes Core re-reads the certificate row first. A row that is no longer active, or whose CA is no longer active, ends the session (`certificate_revoked`). A row past its end ends it (`certificate_expired`). A database fault ends it `check_failed`; a busy pool or a timeout stays transient with the existing grace. The 5-second tick also ends the session at the certificate's end.
8. **API keys.** `console_certificates.interactive_session(request)` is true only when the request's auth is a Knox token with a digest, it was not made by Tactical's API-key authenticator and it has no `X-API-KEY` header. The enrolment-code, issue and CA-replace routes call it first, before the body and the permission. Anything else gets one non-strict deny row (reason `api_key_refused`, no key and no header in it) and `403 interactive_session_required`. No code hash is stored. A plain Django session is refused too.
9. **Contract, documents and bookkeeping.** `core.probe_transport` is 1.3.0 in the code, the contract text, `docs/probe-transport.md` (a new section, "Console certificates (1.3.0)"), `docs/capabilities.md` and `docs/console-certificates.md` ("Not enforced yet" is gone, the wire format is in, with what to do about each refusal and advice for a clock that is out). The 1.18.52 release notes moved to `docs/releases/` and its version test to `tests/legacy/` (it pinned that the tunnel files never mention certificates and that the contract is 1.2.0).

## Assumptions

Johan's decisions are in `reviews/questions/core.md` as information. None blocks this release.

- **Wire format.** The plan's field list is made concrete exactly as in `docs/console-certificates.md`. The Console developer builds from that section.
- **The host in the proof.** It is the websocket `Host` header, lower case, `:443` removed, and it must be a plain host name. Any other port gives `proof_invalid`, the same stance as `host_unusable` on enrol. Tactical's nginx `/ws/` block passes `Host`, so a stock server works. A rewritten `Host` fails closed.
- **After a CA replacement.** An old-CA certificate answers `certificate_invalid`, not `certificate_revoked`. The Console's own pin check fails first anyway.
- **Ending sessions is best effort, the database is the authority.** If the cache or the broker is down, the end waits for the 5-second tick or at most the 5-minute re-check. A new connect is never let through.
- **Enforcement from the ticket on, no transition.** A tunnel session that is open when this release is installed ends when the ASGI service restarts. Tunnels are dev02-only and the Console is unreleased, so no beta tester is affected.
- **API keys on three routes only.** Revoke and cancel stay open to a key, because revoking is the safe direction. If Johan wants revoke by key refused too, it is a one-line addition. The refused requests still count against the route's throttle, as any request does.
- **One row for a refused connect.** For the seven reasons Core writes only `custom:console-cert-refused`, not `custom:probe-tunnel-refused` as well.
- **`accept(headers=...)` on Tactical 1.5.2 (Daphne) is not verified.** Tactical 1.6.1 runs uvicorn. The Console fails closed when the server proof is missing. If the header does not arrive on a 1.5.2 server, a follow-up patch will send the proof as the first binary frame instead. That fallback is not built.
- **`cert_serial` on the end row.** The request asked for it on both tunnel rows, so the end row carries it too, taken from the console side marker.
- **A pending session has no certificate yet.** `end_all_sessions` ends it with `ca_replaced`; `end_for_certificate` leaves it alone.

## New tests

- `tests/console-certificates-connect-1.18.53.py` (real Django on SQLite and real P-256 keys): golden vectors of both message byte strings; a good connect and a server proof that verifies with the CA public key; the time window to the second; every certificate reason with its own bad input (garbage, tampered DER, a certificate signed by another key with the same issuer name, a valid CA signature with no table row, a changed row, not yet valid, expired, revoked, another engineer's certificate, and the proof signed with another key, for another host, server id, ticket, nonce or time); a replaced CA; a master key that cannot sign; no CA key in any answer, log line or audit row; `last_used_at` written at most hourly; `has_usable_certificate`, `recheck`, the refusal row (one a minute per address, no secret); the hooks run after the commit, a failing hook never fails the revoke and a rolled-back revoke runs none.
- `tests/probe-tunnel-certificates-1.18.53.py` (the in-memory tunnel harness, the real tunnel files and a configurable certificate stub): the shape of both headers and the `Host` rules; close code 4401 and close text for every reason; accept headers only on success; a header-shape refusal leaves the ticket unburnt, every later one burns it and a replay is `ticket_invalid`; one `console-cert-refused` row and no `probe-tunnel-refused`; `cert_serial` on the connect row, the end row and the marker; a key that cannot sign closes 1013; the certificate is checked before the account; the probe side ignores the headers; `console_certificate_required` with one deny row and no slot, in order after the permission and scope; `end_for_certificate` and `end_all_sessions`; the time budget; the tick ending a session from the marker alone, at the certificate's end and surviving a cache fault; the 5-minute re-check.
- `tests/console-certificates-apikey-1.18.53.py` (real Django): an API key, a string token, an `X-API-KEY` header and a plain Django session each get 403 on the three routes, one deny row without the key, no stored code hash, no enrolment and no CA change; the same person with a Knox token gets 200 or 201; the refusal comes before the body and the permission; revoke and the read routes are unchanged.
- `tests/version-1.18.53.py`: bookkeeping, per-file line endings, no rebuild label, the tunnel files import the certificate logic only inside functions, and `core.probe_transport` 1.3.0.
- Changed: `tests/probe_transport_harness.py` (accept headers, a stub of `tec_tac.console_certificates`, certificate headers on every Console connect), `tests/console_certificates_harness.py` (a Knox-like token by default, an API mode, a stub tunnel layer), and the 1.18.47 contract and docs tests (1.3.0). Every other tunnel test passes unchanged.

## What could not be run here

- Django 6.1.2 and `cryptography` 50.0.2 are in the project's `.venv`, and the certificate and API-key tests ran on them. Tactical's own apps are not there, so `manage.py check` and a migration run against the whole project did not run. This release has no migration.
- `channels`, Redis, PostgreSQL, a real nginx and uvicorn are not on this PC. The tunnel tests ran on the in-memory harness. Whether `accept(headers=...)` reaches a real client through uvicorn, real concurrency, and the `Host` header through nginx are dev02 checks.

## Johan dev02 checklist

Update dev02 to Core 1.18.53 from the dev branch. There is no migration. Restart the web workers and the ASGI service (a tunnel session that is open ends when it restarts). The Engineer Console that sends the proof (E1-b) does not exist yet, so the steps use a small script. Real Console steps follow when E1-b ships. Use a browser session for the signed-in calls.

1. As an engineer with no Console certificate (and the networkprobe tunnel permission), ask for a tunnel from Network Probe.
   - PASS: the request is refused with 403, `networkprobe` shows its generic "Your sign-in or permission could not be confirmed" message, and the Audit page has one row for `custom:probe-tunnel-refused` with reason `console_certificate_required`.
   - FAIL: a launch link is returned. Send the answer and the audit row.
2. Issue and enrol a certificate (administrator `issue/`, then the engineer asks for a code and enrols with the test enrolment from the 1.18.52 notes, saving the bundle). Then ask for a tunnel again and run the connect script below within 60 seconds with the new ticket.
   - PASS: the script prints `server proof: verified` and a normal close (code 1000, because it closed itself), and no 4401.
   - FAIL: a 4401 or 1013 close, or `server proof: MISSING` or `WRONG`. Send the script output.
3. Run the script with a wrong host (set `PROOF_HOST` to another name), then with a stale time (set `TIME_SKEW` to 300). Use a fresh ticket each time.
   - PASS: `server proof: MISSING` with close 4401 and text `proof_invalid`, then 4401 and `proof_stale`, and the Audit page shows `custom:console-cert-refused` rows (at most one a minute per address) and no `custom:probe-tunnel-refused` rows for them.
   - FAIL: either connect is accepted, or a ticket, certificate or proof shows in a row.
4. Keep a session open (the script with `HOLD=1`), then revoke the certificate with `POST /api/tfd/console-certificates/<serial>/revoke/`. Then connect again with a fresh ticket.
   - PASS: the open session ends within a few seconds; the end row shows detail `certificate_revoked`; the new connect closes 4401 `certificate_revoked`.
   - FAIL: the session stays open for more than a minute. Send the Core log.
5. Set `console_certificate_validity_days` to 1 (superuser), enrol, and connect with `HOLD=1`. Wait until it ends, or set the server clock forward a day on a test server only.
   - PASS: the session ends at the certificate's end with detail `certificate_expired`, and a new connect closes 4401 `certificate_expired`.
   - FAIL: it stays open past the end. Set the setting back to 365 either way.
6. Hold a session open (`HOLD=1`), then as a superuser `POST /api/tfd/console-certificates/ca/replace/` with `{"confirm": true}`.
   - PASS: every open session ends within seconds with detail `ca_replaced`, and the old certificate now closes 4401 `certificate_invalid`.
   - FAIL: a session survives. Send the Core log.
7. As an administrator, call `POST /api/tfd/console-certificates/mine/enrolment-code/` with a Tactical API key in `X-API-KEY`.
   - PASS: 403 `interactive_session_required` and a "Blocked" row on the Audit page, and the same call from the browser session still gives a code.
   - FAIL: a code is returned to the API key.
8. Check that the server proof reaches the client on uvicorn (dev02 is 1.6.1). Step 2 already shows it.
   - PASS: `server proof: verified` with the bundle's `ca_public_key`.
   - FAIL: `server proof: MISSING` while the connect succeeded. Send the script output: the first-frame fallback is then built as a follow-up.
9. Open the Audit page.
   - PASS: the connect row shows `cert_serial`, and no row anywhere holds a ticket, a certificate, a proof or a key.
   - FAIL: any secret in a row, or a connect row without `cert_serial`. Send the row.

To keep the key and the bundle, replace the last line of the 1.18.52 test enrolment script (the `print`) with these lines:

```python
answer = urllib.request.urlopen(request).read()
open("bundle.json", "wb").write(answer)
open("key.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print(answer.decode())
```

Connect script (run it with Tactical's python; it needs the `websockets` package, which Tactical's environment has, and the bundle from the test enrolment saved as `bundle.json`; the private key must be the one the enrolment made, so keep that script's key in `key.pem`):

```python
import asyncio, base64, hashlib, json, os, time
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
HOST, TICKET = "dev02.example.com", "<ticket from the launch link>"
PROOF_HOST, TIME_SKEW, HOLD = HOST, 0, os.environ.get("HOLD") == "1"
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
bundle = json.load(open("bundle.json"))
key = serialization.load_pem_private_key(open("key.pem", "rb").read(), None)
stamp, nonce = str(int(time.time()) + TIME_SKEW), b64u(os.urandom(16))
message = (f"tectac-console-connect-v1\nhost={PROOF_HOST}\nserver={bundle['server_id']}\nticket={hashlib.sha256(TICKET.encode()).hexdigest()}\n"
           f"serial={bundle['serial']}\ntime={stamp}\nnonce={nonce}").encode()
r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
proof = f"v1.{stamp}.{nonce}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

async def main():
    headers = {"Authorization": f"Ticket {TICKET}", "X-Tectac-Console-Cert": bundle["cert"], "X-Tectac-Console-Proof": proof}
    url = f"wss://{HOST}/ws/tfd/probe-tunnel/"
    try:
        connection = websockets.connect(url, additional_headers=headers)  # websockets 13 and later
    except TypeError:
        connection = websockets.connect(url, extra_headers=headers)  # older versions
    async with connection as ws:
        response = getattr(ws, "response", None)
        got = (response.headers if response is not None else ws.response_headers).get("X-Tectac-Server-Proof")
        verdict = "MISSING"
        if got:
            expected = (f"tectac-core-connect-v1\nhost={HOST}\nserver={bundle['server_id']}\nticket={hashlib.sha256(TICKET.encode()).hexdigest()}\n"
                        f"serial={bundle['serial']}\nnonce={nonce}").encode()
            raw = unb64u(got[3:])
            ca = serialization.load_der_public_key(unb64u(bundle["ca_public_key"]))
            try:
                ca.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), expected, ec.ECDSA(hashes.SHA256()))
                verdict = "verified"
            except Exception:
                verdict = "WRONG"
        print("server proof:", verdict)
        try:  # a refusal arrives as a close right after the accept; HOLD=1 waits for whatever ends the session
            await asyncio.wait_for(ws.recv(), None if HOLD else 3)
        except (asyncio.TimeoutError, websockets.ConnectionClosed):
            pass
        await ws.close()
    print("close code:", ws.close_code, "close text:", ws.close_reason)


asyncio.run(main())
```

A refused connect still prints `server proof: MISSING` and then the close code and text (for example `4401` and `proof_invalid`). Send those lines. Use a real probe for the tunnel, so the session stays up: without a probe side Core ends the session after 15 seconds with `probe_offline`.

## Exit list

- Version 1.18.53, no rebuild label. No migration, no `install.sh`, root-helper or sudoers change. `docs/contracts` is not edited (the export runs on dev02 after signing).
- Release manager, after signing: remove both C4 entries from `reviews/requests/core.md` naming 1.18.53 (the "Engineer Console certificates C4" entry and the "add to C4: refuse API keys" entry). Append the E1-b request to `reviews/requests/_unsorted.md` and the `networkprobe` request to `reviews/requests/networkprobe.md`. Export the public contract for 1.18.53 on dev02 (`core.probe_transport` 1.3.0).
- Left out on purpose: the tunnel check-in frame (on hold until a dev02 cable test); publishing the new end details to `tunnel_status` and `tunnel.closed` (a separate additive change); the first-frame fallback for the server proof on Daphne (a dev02 check first); the access-changed event for modules; sweeping old enrolments, retired CAs and revoked certificates.
- Belongs to other areas: the Engineer Console side (E1-b, `probe-developer`); the `networkprobe` message for `console_certificate_required` and its end-detail allow-list; showing `last_used_at` in the My Account card and list (`ui`).
- Risks: Core 1.18.53 and the Console that sends the proof must reach dev02 together. `accept(headers=...)` on Tactical 1.5.2 is unverified. A PC clock that is out by more than 2 minutes gets `proof_stale`. A rewritten `Host` header at nginx fails the proof on purpose.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it. Tunnels stay dev02-only until `networkprobe` ships.
