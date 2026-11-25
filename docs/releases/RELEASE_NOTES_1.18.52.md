# Tec-Tac Framework 1.18.52

Date: 25 November 2026. Core can now issue Engineer Console certificates. This is C3 of the signed Engineer Console certificate plan: the certificate authority, the enrolment, the management routes and the audit rows. It does not protect the tunnel yet. Until Core 1.18.53 (C4), no tunnel checks a certificate, so a revoked or missing certificate stops nothing. It is a Core-only change. `main` stays held.

## Module-facing change

Nothing in `modules/` uses what this release adds. A search of `modules/` for `console_cert`, `core_console`, `console-certificates`, `runtime-settings`, `runtime_settings`, `CORE_PERMISSION_GROUPS`, `permission_catalog` and `registered_permissions` finds no module user. `networkprobe` mentions the Engineer Console only in help text and comments.

What is new, all additive:

- Nine HTTP routes under `/api/tfd/console-certificates/`. They are for the browser shell and the Engineer Console. A module has no use for them.
- Two permissions in a new group "Console certificates": `core.console_certificates.view` and `core.console_certificates.manage`. They appear in the role editor and in `permission_catalog()`. No existing role gains them.
- One new key in the answer of `GET /api/tfd/system/runtime-settings/`: `console_certificate_validity_days` (`value`, `minimum`, `maximum`, `default`). A client that does not know the key ignores it.
- No capability is registered and no Python contract changes. `core.probe_transport` stays 1.2.0 and `probe_tunnel.py`, `probe_tunnel_consumer.py` and `probe_transport.py` are not touched. A test pins that.

## Closes

- Plan item C3 of `docs/planning/networkprobe/PLAN-ENGINEER-CONSOLE-CERTS-25-11-2026.md`, sections 1, 2, 3, 7 (Core routes only), 8 and 9. Johan asked for C3 only on 25 November 2026.
- No entry of `reviews/requests/core.md` or the backlog names C3, so none is removed. The C4 entry stays open.

## What changed and why

1. **A certificate authority (CA) for Console certificates.** A CA is a key pair Core owns: its private half signs, its public half lets anyone check the signature. Core makes one at the first issue (ECDSA P-256, valid 10 years, `server_id` = the first 16 bytes of the SHA-256 of its public key). One partial unique constraint allows one active CA, and the loser of a race re-reads the winner. The private key is stored only encrypted (AES-256-GCM under the secret store's master key, table `core_console_ca`). Core decrypts it in memory for one signature. It never reaches a file, a log line, an audit row, an error text or an answer. A missing or unsafe master key, or one that cannot decrypt the row, gives `master_key_unavailable` (503) and issuing, codes and enrolling all refuse. Replacing the CA (effective superusers only) retires the old one, revokes its certificates (`ca_replaced`), cancels open enrolments and writes one strict row with the counts.
2. **Certificates.** An X.509 v3 certificate in DER. Subject `CN=<username>` (cut to 64 characters), two URI names (`tectac:server:<server_id>` and `tectac:engineer:<id>`), key usage `digitalSignature`, extended key usage `clientAuth`, `CA:false`. It starts 5 minutes before it was made, so a small clock error does not matter. It ends after the validity setting (default 365 days) and never later than the CA's end minus one day. At most 3 active certificates per engineer. Enrolling again from the same PC label replaces the older certificate (revoked as `replaced`, not counted against the 3). The table row is the authority; there is no revocation list.
3. **Enrolment.** An administrator allows an engineer (`issue/`, valid 7 days, one open at a time). The engineer asks for a one-time code (`mine/enrolment-code/`, 43 characters, 10 minutes, only its hash is stored, `no-store`). The Console calls `enrol/` with the code in the header and a proof that it holds the private key. The proof message is `tectac-console-enrol-v1\nhost=<host>\ncode=<sha256 of the code>\nkey=<sha256 of the public key>`. The code works once through one atomic update. Every failure before the code is looked up answers the same 401 body, so nobody can tell an unknown, used, expired or cancelled code apart. Every failure after it carries its own reason. Ten failures a minute from one address (an IPv6 address by its /64) give 429. Plain http is refused. The body is at most 4 KiB with exactly four keys.
4. **Management routes and permissions.** List, mine, issue, cancel, revoke, CA status and CA replace, with the two new permissions. An engineer may revoke their own certificates. A refused permission writes one `deny` row (AD-12) and answers 403. Write routes are limited to 30 a minute and 500 a day.
5. **The validity setting.** `console_certificate_validity_days`, 1 to 730, default 365, effective superusers only, through the existing runtime settings route. It changes new certificates only.
6. **Audit.** Nine row types through one private writer in `audit.py` (`_record_console_certificates`), module `core`, provenance `console-certificates`. Six are strict (the change is not made if its row cannot be written). A row holds serials, fingerprints, labels, dates, ids, reasons, counts and addresses, never a code, key, proof or header.
7. **Contract surface and documents.** Nine `HTTP_CONTRACT_DETAILS` rows, one sentence in the rules (Console certificates are Core-internal), an OpenAPI group "Tec-Tac · Console Certificates", the new `docs/console-certificates.md` (with the exact proof bytes and encodings for the Console developer), and notes in `docs/runtime-settings.md` and `docs/secret-store.md`.

**Plain statement of what is not enforced.** This release issues and records certificates. It does not check them. A tunnel opens exactly as before. Revoking a certificate, or replacing the CA, changes the database only and does not end a tunnel that is open or opening. `last_used_at` stays empty. Enforcement is Core 1.18.53.

## Assumptions

Johan's decisions are recorded in `reviews/questions/core.md` as information. None blocks this release.

- A refusal after the code was taken burns the code, not the 7-day enrolment. The engineer asks for a new code. This keeps the code single-use without sending the engineer back to an administrator after a typo.
- The state `replaced` is used when the same engineer enrols again with the same PC label. Core revokes the older certificate in the same transaction.
- Replacing the CA cancels every open enrolment, because the server id changes.
- Core's own host is `request.get_host()`, lower case, `:443` removed, accepted only if it matches the tunnel launch link's host rule. Other ports and odd hosts answer `host_unusable`.
- Binary values are base64url without padding. Keys are SPKI DER. Signatures are 64-byte `r||s`.
- Revoke and CA replace do not end live sessions in this release (see above).
- `core.probe_transport` is already 1.2.0 (Core 1.18.50). The plan said 1.2.0 for the current contract. C4 will make it 1.3.0.
- An administrator with `manage` may issue to themselves (audited). Revoking an already revoked certificate answers 200 with no new row. `null` for the validity setting is refused. An expired enrolment is computed on read.
- The address failure limiter treats a cache fault as "not limited", the same accepted rule as `endpoint_transport`. The code has 256 bits, and the cost of a fault is only database reads.
- The enrol route reads the address from `REMOTE_ADDR`, not `X-Real-IP`, as the agent download route does: nginx sets `X-Real-IP` only on Tactical's `/ws/` location.
- The CA key reuses the secret store's master key. A server whose master key is lost needs the superuser to replace the CA, and engineers enrol again.

## New tests

- `tests/console_certificates_harness.py` (shared fixtures): real Django on a temporary SQLite file, the real new modules, a real P-256 test Console.
- `tests/console-certificates-ca-1.18.52.py`: one CA however many callers race, key stored only encrypted, wrong or missing master key refused on every path, replace, the certificate fields, the CA cap, the limit of 3, replace-on-same-PC, and a sweep for the CA key in every answer, log record and audit payload.
- `tests/console-certificates-enrol-1.18.52.py`: the happy path, the bundle, the code working once (also a two-thread race), every refusal, the burnt code with an open enrolment, one refusal row per address per minute, the 11th failure, the IPv6 /64, plain http, a failed audit row rolling back the certificate, and a sweep for the code, header, proof and public key.
- `tests/console-certificates-routes-1.18.52.py`: every route's permission and deny row, the answer shapes key by key, paging, self-revoke, strict rows rolling back, the nine row types, the permission catalogue, `enrol/` as the only unauthenticated pattern, and a contract row and OpenAPI group for every route.
- `tests/console-certificates-setting-1.18.52.py`: the setting, and migration 0049 against the models, by AST and by Django's own autodetector.
- `tests/version-1.18.52.py`: release bookkeeping, line endings, and that the tunnel files are untouched.
- Unchanged and still run: `tests/result-checks-system-check-1.18.45.py` (the Django system check now also covers the three new models) and the tunnel, runtime settings and contract tests.

## What could not be run here

- Django 6.1.2 and DRF are in the project's `.venv`, and the new tests ran on them. Tactical's own apps are not there, so `manage.py check`, `makemigrations --check` and `migrate` against the whole project did not run. The migration was checked against the models with Django's autodetector on a reduced project state instead.
- Redis, PostgreSQL and a real nginx request did not run. The race tests ran on SQLite. Real concurrency on PostgreSQL and the plain-http check through nginx are dev02 checks.
- The tests that need Django skip themselves on a machine without it.

## Johan dev02 checklist

Update dev02 to Core 1.18.52 from the dev branch. Run the migration (`0049_console_certificates`), then restart the web workers. There is no Console yet and no UI page, so steps 3 to 8 of the plan wait for Core 1.18.53. Only issuing, the open enrolment, enrolling with a test key, revoking, the setting and the audit rows can be checked now. Use a browser session or an API key for the signed-in calls; the examples below name the route.

1. As an administrator, `POST /api/tfd/console-certificates/issue/` with `{"user_id": <engineer id>}`, then `GET /api/tfd/console-certificates/`.
   - PASS: 201, and the `enrolments` list shows one open enrolment for that engineer with `code_active` false.
   - FAIL: any other status, or no enrolment listed. Send the answer.
2. As that engineer, `POST /api/tfd/console-certificates/mine/enrolment-code/`, then run the test enrolment below within 10 minutes (put the code in `CODE` and the dev02 host in `HOST`).
   - PASS: the script prints a bundle with a `cert`, a `serial` and a `server_id`, and `GET mine/` lists one active certificate.
   - FAIL: any 4xx or 5xx. Send the script output and the Core log lines for `tec_tac.console_certificates`.
3. Run the script again with the same code.
   - PASS: 401 `code_invalid`.
   - FAIL: a second certificate.
4. As the engineer, `POST /api/tfd/console-certificates/<serial>/revoke/` with `{"reason": "other"}`, then try another engineer's serial.
   - PASS: your own revokes (200, `changed` true); the other one answers 403 and the audit log has a "Blocked" row.
   - FAIL: the other engineer's certificate revokes.
5. As a superuser, `PATCH /api/tfd/system/runtime-settings/` with `{"console_certificate_validity_days": 7}`, enrol again, then set it back to 365.
   - PASS: the new certificate's `not_after` is 7 days ahead. A holder of only "Runtime settings" gets 403.
   - FAIL: the date is not about 7 days ahead, or a non-superuser could change it.
6. Open the Audit page.
   - PASS: rows `custom:console-ca-created`, `custom:console-cert-issue-authorised`, `custom:console-cert-enrol-code`, `custom:console-cert-issued` and `custom:console-cert-revoked` exist, and none holds a code, a key or a proof.
   - FAIL: a missing row, or any secret in a row. Send the row.
7. Check that a tunnel still opens as before, with and without a certificate.
   - PASS: nothing changed. (This release does not check certificates.)
   - FAIL: a tunnel refuses to open. Send the Core log.

Test enrolment (run with Tactical's python, which has `cryptography`; it makes a throw-away key, nothing is stored):

```python
import base64, hashlib, json, urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
HOST, CODE = "dev02.example.com", "<code>"
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
key = ec.generate_private_key(ec.SECP256R1())
spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
message = f"tectac-console-enrol-v1\nhost={HOST}\ncode={hashlib.sha256(CODE.encode()).hexdigest()}\nkey={hashlib.sha256(spki).hexdigest()}".encode()
r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
body = json.dumps({"v": 1, "public_key": b64u(spki), "pc_label": "Test key", "proof": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}).encode()
request = urllib.request.Request(f"https://{HOST}/api/tfd/console-certificates/enrol/", body, {"Authorization": f"Enrol {CODE}", "Content-Type": "application/json"})
print(urllib.request.urlopen(request).read().decode())
```

## Exit list

- Version 1.18.52, no rebuild label. One migration (`0049_console_certificates`, three new tables and one new column). No root-helper, `install.sh` or sudoers change. `docs/contracts` is not edited (the export runs on dev02 after signing).
- Release manager: after signing, export the public contract for 1.18.52 on dev02. It lists nine new HTTP routes and no capability change. Please also add the signed Engineer Console certificate plan to the index in `docs/review-accepted-decisions.md` (already noted in `reviews/questions/core.md`).
- Left out on purpose: every tunnel check (the connect proof, the server proof, ending sessions on revoke, the 5-minute check, `cert_serial` on tunnel audit rows) is C4, Core 1.18.53, and `core.probe_transport` becomes 1.3.0 there. The UI pages (UI 0.13.6, request written to `reviews/requests/ui.md`) and the Console key store and enrol link (request written to `reviews/requests/_unsorted.md`) belong to other areas.
- Not built, not needed yet: enrolling without an administrator, TPM-backed keys, one audit row per certificate on a CA replace (one row with a count is built), and any sweep that deletes old enrolments, retired CAs or revoked certificates (the tables are small).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes it. Tunnels stay dev02-only until networkprobe 0.2.24 ships.
