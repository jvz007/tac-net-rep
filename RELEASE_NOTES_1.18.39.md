# Tec-Tac Framework 1.18.39

Date: 21 November 2026. Endpoint Agent Management can now publish one public Endpoint Agent installer that anyone can download from a fixed address, with no sign-in. Audit rows can now name the device, so the Audit page shows Agent, Client and Site on them. `main` stays held.

## Module-facing change

Additive. Nothing that works today changes. Each item needs framework >=1.18.39.

- **`core.agent_downloads` 1.1.0.** The capability version moves from 1.0.0 to 1.1.0. It gains two operations, `publish_installer(module_id, *, path, sha256, version)` and `unpublish_installer(module_id)`. `grant_download`, `revoke_download`, the route `GET /api/tfd/agent-downloads/<token>/`, their reasons and their audit rows are unchanged.
  - Only `endpoint-agent-management` may publish. Core keeps that id in one constant (`INSTALLER_PUBLISHERS`) and verifies the caller from the call stack. Any other module, Core itself and an unverifiable caller get `denied`.
  - New public route `GET /api/tfd/endpoint-agent/installer.msi`. No sign-in, no code, no expiry, never a redirect.
  - The module checks `has_capability('core.agent_downloads')` and, to call the new operations, requires framework >=1.18.39. Operation metadata carries `added_in` and `requires_framework` per operation.
- **`audit.record(..., agent_id=None)`.** One new optional keyword. When a module passes it, the row gets Tactical's `AuditLog.agent` (the hostname) and `AuditLog.agent_id`. Effect on the Audit page: the page filters rows that carry `agent_id` by the viewer's agent scope, so a person who cannot see that device no longer sees its rows. Rows without `agent_id` stay visible as before. A module opts in by passing it.
- Users found in `modules/`: `endpoint-agent-management` 0.1.0 and 0.1.1 call `grant_download` and `revoke_download` and check `has_capability('core.agent_downloads')`. They keep working: 1.1.0 only adds. 98 modules call `audit.record`; the new keyword defaults to `None` and they pay nothing. `communicator`, `endpoint-agent-management` and `endpoint-comms` already pass agent ids in their own audit helpers and will opt in later. No module is changed by this release.

## Closes

- ORDER: Core 1.18.39, public Endpoint Agent installer address (AD-74) and the agent column on audit rows (Johan, 21 November 2026).
- From Johan's Part B test (21 November 2026): agent download audit rows without the agent column.

The release manager removes both entries from `reviews/requests/core.md`, naming 1.18.39.

## What changed and why

1. **Publish and unpublish the installer.** `publish_installer` checks the caller, then the arguments, then the file. Order of the reasons: `bad_sha256`, `bad_version`, `bad_path`, `not_msi`, then the checks `grant_download` already uses (`outside_module_folder`, `symlink_refused`, `not_a_file`, `too_large`, `hash_mismatch`). The file must be inside the module's own plugin folder or `/var/lib/tec-tac/<id>/`, with no symlink, 1 to 100 000 000 bytes, and its name must end in `.msi` in any case. The version is a plain version such as `0.1.2` or `0.1.2-rc1`, at most 40 characters.
   - Only one installer exists. A new publish replaces the old one. It lives in one database row (`TecTacPublishedInstaller`, table `core_published_installer`, unique `slot`, migration 0046), so a restart or a cache flush does not lose it.
   - The store write and a strict audit row (`custom:agent-installer-published`) run in one transaction. If the row cannot be written, the store rolls back and the answer is `unavailable` with `audit_unavailable`. A store fault answers `store_unavailable`. The row holds the publisher, file name, size, SHA-256, version and the replaced version. It never holds a full path.
   - `unpublish_installer` removes the row only when it belongs to the caller. It writes a strict row (`custom:agent-installer-unpublished`) in the same transaction. Nothing to remove answers `ok` with `unpublished` false and writes no row.
2. **The public route.** `InstallerDownloadView` has no authenticator, no throttle class and answers GET only. A plain-text connection gets 403. No row, or nothing published, gets 404. A database fault gets 503 with `Retry-After: 30`. The route takes a slot from its own counter (`INSTALLER_INFLIGHT_KEY`, cap 8), so an anonymous flood cannot take slots from agent downloads, and a full device counter does not block the installer. `acquire_slot` and `release_slot` take an optional `key`, defaulting to the old counter, so the device route behaves as before.
   - Core then calls `open_verified` on the stored path: the path is re-checked, the file is opened with `O_NOFOLLOW`, and the SHA-256 is computed through the descriptor that is then sent. A changed file, the same size with other bytes, a symlink, a missing file or a publisher module that is no longer installed gives 404 with an empty body. The reason is logged as a code only. The row is kept, so the file serves again when it matches.
   - Success is 200 with `Content-Length`, `Content-Disposition: attachment` (safe file name), `X-Content-SHA256` (the published hash), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `application/octet-stream`.
   - No audit row per download. The per-address rate limit is the web application firewall's job, queued in `reviews/requests/securityWAF.md`.
   - Wiring: `urls.py`, the OpenAPI group `Tec-Tac · Agent Downloads` for `/api/tfd/endpoint-agent/`, `contracts.py` (two Python entries, the route entry, a rule sentence, the audit entry text), `docs/agent-downloads.md` and `docs/capabilities.md`.
3. **Agent column.** `audit.record` and the private `_record_row` take `agent_id=None`. A value must match `^[A-Za-z0-9._-]{1,80}$`, or `AuditContractError`. Core finds the hostname with one indexed query on `agents.models.Agent` (hostname only) and creates Tactical's `AuditLog` row with `agent` and `agent_id`. It fails soft: an unknown device keeps `agent_id` with `agent` empty, and a lookup fault is logged and never fails a write, strict or not. With no `agent_id` there is no lookup and no new key on the `create()` call. The hostname is cut at 255 characters. `object_id` keeps its meaning.
   - Core's own download rows (granted, revoked, served, and refused when the id is well-formed) pass the id they already hold, so Agent, Client and Site show on them.
   - The endpoint transport rows (`_record_endpoint_transport`) are not changed here. They are outside the order.

Plan check against the code: the plan was right on every file and every line ending. Two small decisions of mine: the installer audit rows use object type `agent-installer` (they are not about a device, so `object_id` is empty), and the private writer for them is `audit._record_agent_installer` (strict by default).

## Assumptions

Recorded as information in `reviews/questions/core.md`. Say if you want a different choice.

- **Publisher.** Only `endpoint-agent-management` may publish. AD-74 names that module, and a publisher open to any module would let any module make a file public at an address with no sign-in. Widening is one id added to `INSTALLER_PUBLISHERS`.
- **Separate installer counter** of 8, so anonymous traffic cannot starve agent downloads.
- **`.msi` only.** A file whose name does not end in `.msi` is refused with `not_msi`.
- **One-row database store with migration 0046,** not the cache. Run `makemigrations --check --dry-run` and `migrate` on dev02.
- **Full re-hash on every anonymous serve,** as ordered. With 8 slots this is one extra read pass of at most 100 MB per request. The securityWAF rate limit is the outer guard.
- **Audit scope effect.** Rows that carry `agent_id` are hidden from a person who cannot see that device on the Audit page. That is Tactical's own behaviour and the point of the change.

## Retired or changed checks

- `tests/version-1.18.38.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.38.md` moved to `docs/releases/`.
- `tests/agent-downloads-1.18.37.py` changed in one line: the metadata check now expects version `1.1.0` and four operations (the two 1.0.0 operations first, unchanged). Every other assertion holds.
- `tests/secret-store-1.17.100.py` changed in one line: the migration leaf is now `0046_published_installer` on top of `0045_communicator_service_user_retry` (as 1.18.31 did for 0045). The test is not part of release integrity and stops at an earlier, older failure on this PC (`select_release` name error in its own harness) after that line.
- `tests/agent-downloads-fixes-1.18.38.py` changed in two lines: the source check for the counter lifetime now looks for `cache.touch(key, ...)` and `release_slot(key)`, because both functions take an optional key. The behaviour checks around it did not change and still pass.

## New tests

- `tests/endpoint-agent-installer-1.18.39.py`: capability version and four operations; the publisher rule (Core, other modules, mismatch, unverifiable, `endpoint-comms` all denied); every invalid reason; strict row with no full path; replace and `replaced_version`; audit failure rolls the store back and nothing is served afterwards; store faults; unpublish by owner, by others and with nothing published; the route (no headers, 404 with nothing published, exact bytes and headers, no redirect, no `Retry-After`, no row per download); tampered bytes, same size other bytes, symlink, removed file and removed module all 404; the two counters are independent in both directions; cache, database and OS faults give 503 and free the slot; GET only; the model, migration 0046 (depends only on 0045), `urls.py`, `openapi.py` and the contract entries agree.
- `tests/audit-agent-column-1.18.39.py`: known device, unknown device, lookup fault (also strict), no `agent_id` means no lookup and an unchanged `create()` call, bad shapes, the signature (only `agent_id` added, older keywords keep position and default), Core-owned keys still refused, and the real download writer producing rows with the agent columns and no token, link or path.
- `tests/version-1.18.39.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. These run only on dev02: migration 0046 and `makemigrations --check`, the real URL resolver and route, the real Redis cache and `cache.touch`, the real `transaction.atomic` rollback, Tactical's `AuditLog` columns and the Audit page, drf-spectacular's Swagger page, and nginx and uwsgi in front of the route. The tests ran the real `agent_downloads.py`, `agent_download_views.py` and `audit.py` against stubs for the cache, the model manager, the transaction, the registry and the Tactical models.

## Johan dev02 checklist

Update dev02 to Core 1.18.39 first. Endpoint Agent Management 0.1.2 is the module that publishes the installer; steps 5 to 8 need it.

1. Run `migrate`, then `manage.py makemigrations --check --dry-run`.
   - PASS: 0046 applies and the check reports no changes.
   - FAIL: an error on 0046, or the check wants a new migration. Send the output.
2. With nothing published, open `https://<host>/api/tfd/endpoint-agent/installer.msi` in a private browser window.
   - PASS: 404 with an empty page, no sign-in prompt.
   - FAIL: a sign-in page, a redirect, a 500 or any file.
3. Check that nginx and uwsgi pass the address to Django: the 404 in step 2 must be Core's (a `Cache-Control: no-store` header), not nginx's own page.
   - PASS: the header is there. No static-file rule catches `.msi`.
   - FAIL: nginx answers with its own 404. Send the nginx location blocks.
4. Open Swagger.
   - PASS: the `Tec-Tac · Agent Downloads` group lists the installer route.
   - FAIL: the route is missing or in another group.
5. With Endpoint Agent Management 0.1.2, publish the installer, then download it from a private window with no sign-in.
   - PASS: the file downloads, `X-Content-SHA256` matches the published hash, and the Audit page shows one `Agent installer published` row with the file name, size, hash and version and no folder path.
   - FAIL: sign-in is asked for, the file is wrong, the hash differs or no row exists. Send the response headers and the audit row.
6. Download it five times in a row.
   - PASS: five files, and no new audit row.
   - FAIL: a row appears per download, or a download fails.
7. Change the published file on disk (append one byte), then download again. Put it back afterwards.
   - PASS: 404 with an empty body while it differs, the file serves again when restored.
   - FAIL: the changed file is served.
8. Start 8 slow downloads, then a ninth. In the same minute, ask for an agent update download.
   - PASS: the ninth installer download gets 503 with `Retry-After: 30`, and the agent download still gets its file.
   - FAIL: the ninth is served, or the agent download is refused as busy.
9. Grant an agent download to a device, let the device fetch it, then open the Audit page.
   - PASS: the `Agent file download granted` and `Agent file download started` rows show Agent, Client and Site, and filtering by that agent finds them.
   - FAIL: the Agent column is empty. Send the two rows.
10. Sign in as a person who cannot see that device, then open the Audit page.
    - PASS: the two rows from step 9 are hidden from that person, and rows with no device stay visible.
    - FAIL: the rows show for a person without access to the device.

## Exit list

- Version 1.18.39, no rebuild label.
- `core.agent_downloads` 1.1.0 with `publish_installer` and `unpublish_installer`; the 1.0.0 behaviour and route unchanged.
- One public route, no sign-in, hash re-checked at every serve, 404 on any mismatch.
- `audit.record(..., agent_id=None)` and the agent column on Core's own download rows.
- Release manager: remove both requests named in Closes, naming 1.18.39, and move them word for word to `_history/core.md`. The Endpoint Agent Management 0.1.2 order and the securityWAF rate limit stay queued in their own requests files. The export of the public contract for 1.18.39 is generated on a running server and stays an open request.
- Left out on purpose: every other open request in `reviews/requests/core.md`, every held finding in `reviews/core/BACKLOG-new-findings.md`, the agent column on the endpoint transport rows, a generic "any module may publish" call, a hash shortcut for repeat downloads, and a per-download audit row.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
