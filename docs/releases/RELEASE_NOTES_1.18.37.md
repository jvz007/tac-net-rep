# Tec-Tac Framework 1.18.37

Date: 21 November 2026. Core can now hand one file a module owns, such as an agent installer, to one device over HTTPS. The device proves who it is with its own agent token. `main` stays held.

## Module-facing change

New capability `core.agent_downloads` 1.0.0 (framework >=1.18.37). It is additive. Nothing existing changed, and no module in `modules/` uses it yet. Endpoint Agent Management is not built yet and will be the first caller.

**Two operations** (`tec_tac.agent_downloads`, sync, keyword arguments after `module_id`):

- `grant_download(module_id, *, agent_id, path, sha256, ttl_seconds=600)` returns `{outcome, url, path, expires, expires_in, reason}`. `outcome` is `ok`, `denied`, `invalid` or `unavailable`.
- `revoke_download(module_id, *, agent_id, path)` returns `{outcome, revoked}`.

**Who may call.** Any verified, enabled, non-legacy extension, for its own files only. Core reads the caller from the call stack, the same way `core.endpoint_transport` does. `module_id` must equal that id. Core itself and an unverifiable caller get `denied`. No module id is written into Core.

**Where the file may be.** The module's installed plugin folder, or `/var/lib/tec-tac/<module id>/`. The path must be absolute, have no `..` and be its own real path. No part below the folder may be a symlink. The file must be a regular file of 1 to 100 000 000 bytes. Core hashes it and refuses unless the SHA-256 matches. Keep the hash of each file in your own version store.

**Reasons.** `invalid`: `bad_agent_id`, `bad_sha256`, `bad_ttl`, `bad_path`, `outside_module_folder`, `symlink_refused`, `not_a_file`, `too_large`, `hash_mismatch`. `unavailable`: `cache_unavailable`, `host_unavailable`, `audit_unavailable`, `file_unavailable`, `path_unavailable`. Nothing is stored when the outcome is `unavailable`. Call again later.

**Limits.** `ttl_seconds` is a whole number, clamped to 30..900 (15 minutes). One active grant per device and file: a new grant replaces the old one.

**The route.** `GET https://<host>/api/tfd/agent-downloads/<token>/`. The host is the first Django `ALLOWED_HOSTS` entry. The device sends `Authorization: Token <agent token>` and `X-Agent-Id`. Answers: `200` raw file with `Content-Length`; `401` identity refused; `403` plain-text proxy; `404` unknown, expired, other device or changed file; `405` not a GET; `429` too many failed checks (`Retry-After: 60`); `503` busy or fault (`Retry-After: 30`). Every refusal has an empty body. Never a redirect.

**What the module must do.** Require framework >=1.18.37, check `has_capability('core.agent_downloads')`, list it under `dependencies`, and send the URL to the device through its own channel. See `docs/agent-downloads.md`. The new `core.agent_downloads` rows are in the contract catalogue, so the next public contract export carries them.

## Closes

- The 21 November 2026 request "From endpoint-agent 0.3.5: an agent-authenticated download of the agent MSI". The release manager removes the entry, naming 1.18.37.
- Johan's ask "new contract exported": the catalogue now holds the contract. The export file is written from a running dev server, which Claude cannot do. After signing, update dev02 to 1.18.37 and export a fresh public contract into `docs/contracts` (the standing line in `reviews/questions/core.md`).
- Information for the release manager: `docs/contracts` already holds the export for Core 1.18.36, so the information entry "Public contract export for Core 1.18.34 or later" is satisfied and can be closed.

## What changed and why

Endpoint Agent Management needs to update an agent's MSI without a Tactical download. The agent only has a link. So Core serves the file, and a module only says which file goes to which device.

1. **`agent_downloads.py` (new).** The caller check, the path and file checks, the hash, the grant store, the two operations, the serving helpers and the capability metadata. It reuses `endpoint_transport` (id pattern, counters, header parsing, identity check). `endpoint_transport.py` is not edited, so 1.17.90 behaviour is untouched.
2. **`agent_download_views.py` (new) and `urls.py`.** `AgentDownloadView` takes no authenticator and no throttle class, so Tactical's Knox and API-key checks never see the agent token, and Tactical's audit middleware, which records only signed-in users, logs nothing for the URL (the link token is in it). Order of checks, all failing closed with an empty body: plain-text proxy, address over its failure limit, header and identity check, then the link. The identity check is the websocket's own code and counters.
3. **Safe serving.** Core re-checks the path, opens the file without following symlinks, hashes it through that descriptor and sends from the same descriptor. The file cannot change between the check and the send. A change gives `404` and withdraws the grant. At most 8 downloads run at once across Core (a cache counter that heals itself after 120 seconds). Over that, `503` with `Retry-After`. This keeps Tactical's uwsgi workers free.
4. **Audit (`audit.py`, `apps.py`).** A private writer `_record_agent_download` with provenance `agent-downloads`. The grant row and the served row are strict: no row, no link and no byte. Both are written before they matter. The served row says the download started, because the send gives no completion signal. Revoke and identity-refusal rows are non-strict. No row holds the link token, the link or a full path. Registration is in its own guarded block in `apps.py`.
5. **Catalogue and docs.** Two `CORE_CONTRACTS` rows, one `HTTP_CONTRACT_DETAILS` entry, one `RULES` sentence, `docs/agent-downloads.md` and a row in `docs/capabilities.md`.

Plan corrections found in the code: the plan said the revoke row is strict. A revoke is a safety action, so the grant is removed first and the row is non-strict. A failed audit write cannot keep a link alive. The plan also left the serve-time cache fault open: it gives `503` (the grant store cannot be read), never a served file.

## Assumptions

Recorded as information in `reviews/questions/core.md`. Say if you want a different choice.

- **The link works until it expires.** Not single-use. An interrupted download can retry within the window (at most 15 minutes). A link alone serves nothing: the agent token and agent id are needed as well.
- **Two folders count as the module's own:** its installed plugin folder and `/var/lib/tec-tac/<module id>/`.
- **Any verified module may call it,** for its own files only. This adds no trusted purpose: Core serves a file a module already owns to one authenticated device.
- **Grant and served rows are strict.** A database fault gives `503` and the agent retries. An unknown or expired link writes no row, so an unknown-link scan writes nothing. Identity refusals do write one non-strict row each, behind the endpoint transport's refusal budget, which is off (0) as AD-54 signs; the per-address failure limit (10 a minute) bounds one source.
- **Counters and load.** The route shares the websocket's signed AD-54 counters (10 failed checks a minute per address and per agent id). It adds a cap of 8 downloads at once. "100 MB" is read as 100 000 000 bytes. Core hashes the file at every serve, about 0.3 seconds of disk and CPU per download. Raise the cap only if a rollout needs it.
- **Host and store.** The host is the first `ALLOWED_HOSTS` entry. If it is empty or a wildcard, the grant is `unavailable`. Grants live in Django's cache. A cache restart drops open links, and the module grants again. Nothing is written to the database.

## Retired or changed checks

- `tests/version-1.18.36.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.36.md` moved to `docs/releases/`.
- No existing test changed. `contract-export-gate-1.17.66.py` and the `contract-catalog-*.py` tests compare other contracts and still apply.

## New tests

- `tests/agent-downloads-1.18.37.py`: the caller rule; every invalid reason; the ttl clamp; the hash-only cache; one grant per device and file; cache, host and audit faults; revoke; the route (good download, retry, expiry, other device, identity refusals, address limit, plain-text proxy, transient fault, changed file, symlink, removed file, the cap of 8, the slot freed after a failed stream, audit failure); no token in any log, key, row or header; the catalogue, docs, line endings.
- `tests/version-1.18.37.py`: release bookkeeping.

## What could not be run here

Django, a real Redis, uwsgi, nginx and Linux symlink behaviour (`O_NOFOLLOW`) are not on this PC. The grant store and the route ran against stubs: a fake cache, a fake Tactical token table, fake Django response classes and a stubbed symlink check. Real `FileResponse` streaming, real DRF dispatch (405 for HEAD and POST is pinned from the class settings only) and the real audit table are checked on dev02.

## Johan dev02 checklist

Update dev02 to Core 1.18.37 first. Use a throwaway module call or the Django shell to grant a link, with a real file in a module folder.

1. Grant a link for the lab VM and an MSI under `/var/lib/tec-tac/<module id>/`.
   - PASS: `outcome` is `ok`, the URL starts with `https://` and your API host, `expires_in` is 600.
   - FAIL: any other outcome. Send the `reason` and the log line.
2. Download it from the lab VM with the agent token and `X-Agent-Id` headers.
   - PASS: status 200, the file size matches, and the SHA-256 of the saved file equals the one you gave.
   - FAIL: any other status, or a different hash. Send the status and the Core log.
3. Open the same link from the VM with another agent's token and id, or with no headers.
   - PASS: 404 for the other device, 401 for no headers, both with an empty body.
   - FAIL: any file bytes, or a body with text.
4. Wait for the link to expire (use `ttl_seconds=30`), then fetch it.
   - PASS: 404, empty body.
   - FAIL: 200, or any other status.
5. Check the response of a good download for redirects.
   - PASS: no `Location` header and no 3xx at any point.
   - FAIL: a redirect. Send the headers.
6. Search the nginx access log and the Core and uwsgi logs for the link token.
   - PASS: the token appears in no Core or uwsgi log. If nginx logs the path, note it: a request goes to securityWAF.
   - FAIL: the token appears in a Core or uwsgi log line. Send that line with the token blanked.
7. Open the audit log.
   - PASS: one `custom:agent-download-granted` row and one `custom:agent-download-served` row, naming the module, file name, size and hash. No token, link or full path.
   - FAIL: a missing row, or any secret in a row.
8. Start a 90 MB download on a slow link and browse the Tactical dashboard meanwhile.
   - PASS: the dashboard stays responsive and no uwsgi worker stalls.
   - FAIL: the dashboard hangs while the download runs. Send the uwsgi log.
9. Change one byte of the file after the grant and fetch the link.
   - PASS: 404, and a second fetch is 404 too (the grant is gone).
   - FAIL: the changed file is served.

## Exit list

- Version 1.18.37, no rebuild label.
- `core.agent_downloads` 1.0.0 registered, with two operations, two catalogue rows, an HTTP entry and a rule sentence.
- The route serves only the granted file to the granted device. No redirect. No token in any log or row.
- `endpoint_transport.py` unchanged.
- Release manager: remove the request named in Closes, naming 1.18.37. Ask for the dev02 update and a fresh contract export.
- Other areas: securityWAF (access log and buffering for the new path), Endpoint Agent Management and the endpoint agent have notes in their requests files.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.

## Fixed after precheck

- The download route took the client address from `X-Real-IP`, which a caller can choose on the uwsgi location. It now uses `REMOTE_ADDR` only, so the 10-failures-a-minute limit and the refusal rows count the real peer. Test added: rotating `X-Real-IP` still reaches 429.
