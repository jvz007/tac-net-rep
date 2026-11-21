# Tec-Tac Framework 1.18.40

Date: 21 November 2026. The public Endpoint Agent installer address is now cheap to serve: Core hashes the file once, when it is published, and no longer reads up to 100 MB on every anonymous request. The address also stops serving while its publisher module is disabled. `main` stays held.

## Module-facing change

Additive. Operations, signatures, the route, the capability version (`core.agent_downloads` 1.1.0) and the audit rows are unchanged. The behaviour of the anonymous route is narrower.

- **Disabled publisher is 404.** `GET /api/tfd/endpoint-agent/installer.msi` answers 404 with an empty body while the publisher module (`endpoint-agent-management`) is disabled. The published row stays, so the file is served again when the module is enabled. No republish is needed.
- **2 installer slots.** The route allows 2 downloads at once (it was 8). When both are busy the answer is an empty 503 with `Retry-After: 30`. The device route keeps its 8 slots on its own counter.
- **One additive metadata key.** `installer.limits.installer_in_flight` is 2. `downloads_in_flight` stays 8 (the device route). The metadata texts for 404 and 503 and for verification changed to match.
- Users found in `modules/`: only `endpoint-agent-management` (0.1.x). It calls `grant_download`, `revoke_download`, `publish_installer`, `unpublish_installer` and `has_capability('core.agent_downloads')`. All are unchanged. The module needs no change.

## Closes

- The two held findings of the Core 1.18.39 review (`reviews/core/core-1.18.39-20261121-205211/REPORT.md`):
  - MEDIUM: the anonymous installer route re-hashed up to 100 MB per request with 8 slots.
  - LOW: a disabled or uninstalled publisher module's installer was still served.
- No entry of `reviews/requests/core.md` is closed by this patch. The order was closed in 1.18.39. The release manager only records that both held findings shipped. The securityWAF rate-limit request stays closed without a change (Johan, 21 November 2026).

## What changed and why

1. **Hash once, at publish.** `TecTacPublishedInstaller` gets a nullable `mtime_ns` column (migration 0047, `AddField` only, depends only on 0046). `publish_installer` reads the modified time of the open descriptor it just hashed and stores it with the hash and size. `load_installer` returns it (`None` for a row published by 1.18.39).
   - `open_verified` takes one new optional keyword, `trusted_mtime_ns`. When it is given, and the descriptor's size equals the published size and its modified time equals the stored one, the read pass is skipped. The same descriptor is still rewound and sent. Any difference runs the full re-hash as before, and a hash mismatch is `hash_mismatch`, which the route answers with 404 (the row is kept).
   - The device route and publish never pass the keyword, so they behave as before.
   - **Heal.** After a good re-hash with no or a different stored time, the route stores the descriptor's modified time with one best-effort `update`, filtered on slot, path and SHA-256. A republish between the load and the write cannot receive the old file's time. A fault is logged and never fails the download. This is what stops rows published by 1.18.39 from re-hashing after their first serve.
   - **Plan correction.** `open_verified` now also checks the size and modified time again after the read pass. A file that changed while it was being hashed is `hash_mismatch`. This keeps the stored time tied to the bytes that were hashed. It applies to every caller and only changes the outcome for a file that is being written while Core reads it.
2. **Slot first.** The route order is: plain-text check (403), take a slot, load the row, check the publisher is enabled, open and verify, serve. Every exit after the slot is taken releases it exactly once, and closing the response releases it for a 200. A refused request now costs one cache increment and no database query.
3. **2 installer slots.** New constant `INSTALLER_MAX_INFLIGHT = 2`. `acquire_slot` takes an optional `limit`, default `MAX_INFLIGHT` (8), so the device route is unchanged. 2 is below the smallest uwsgi worker count (6).
4. **Disabled publisher.** New `agent_downloads.installer_publisher_enabled(module_id)` uses `module_state.is_enabled` and `load_state`. A corrupt state file reads as not enabled (fail closed): 404. A fault reading the state is 503 with `Retry-After: 30`. The reason `publisher_disabled` is logged as a code only. A module with no record in the state is enabled by default. A module that is not installed is still 404 through the folder check. No audit row is written: there is no state change by Core and no per-download row.
5. **Docs and contract text.** `docs/agent-downloads.md`, `contracts.py` (404, 503 and verification texts) and the metadata say the same thing. `docs/capabilities.md` did not quote the 8 slots and is unchanged.

Known trade-off (Johan's order accepts it): someone who can write the publisher's folder and also set the file's size and modified time back can swap the bytes without a re-hash. That needs root or the module's own write access, which already controls the trust root.

Left out on purpose: a per-address limiter in Core, an nginx change and a securityWAF change (Johan, 21 November 2026, "KISS").

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- **Migration 0047.** One nullable column, no data migration. Run `migrate` and `makemigrations --check --dry-run` on dev02.
- **Slot cap of 2** replaces the "same 8-slot cap" wording of the 1.18.39 order (Johan, 21 November 2026). On a slow link a third person waits and retries, which is fine for a first install.
- **Size and modified time** are the cheap integrity signal, not the inode change time (as ordered). The trade-off is above. A stronger signal is a one-line follow-up.
- **Heal on first serve.** The route writes the modified time once after a good re-hash.
- **A disabled module keeps its row.** The installer returns when the module is enabled again.

## Retired or changed checks

- `tests/version-1.18.39.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.39.md` moved to `docs/releases/`.
- `tests/endpoint-agent-installer-1.18.39.py` changed: the 8-download block is now 2, the fake model supports the filtered `update`, a `module_state` stub is added, the model-field set gains `mtime_ns`, and the migration checks now expect one 0046 and one 0047. Migration 0046 is still compared with the fields it created.
- `tests/secret-store-1.17.100.py` changed in one line: the leaf is `0047_published_installer_mtime` on top of 0046. The test is not part of release integrity and stops at an older failure on this PC (a `select_release` name error in its own harness) before it reaches that line. It fails the same way without this release.
- `tests/agent-downloads-fixes-1.18.38.py` is unchanged and still passes: `MAX_INFLIGHT = 8` and the `cache.touch(key, ...)` source text are kept.

## New tests

- `tests/installer-serve-cost-1.18.40.py`:
  - Publish stores size, hash and modified time.
  - A matching size and time hashes nothing and sends the exact bytes and headers.
  - A touched file re-hashes once and heals; the next serve hashes nothing.
  - Same size with different bytes and a new time is 404 with the row kept and the slot free.
  - Same size, other bytes and a restored time is served without a re-hash (the accepted trade-off, asserted so it is explicit).
  - A size change is 404.
  - A 1.18.39 row (no time) re-hashes once, heals, then takes the fast path.
  - A heal fault still serves and logs only. A republish between load and heal is not touched.
  - The slot is taken before the store is read. The cap is 2 and the device counter stays at 8 and independent in both directions.
  - Nothing published is 404 and frees the slot. Every error exit frees the slot.
  - Disabled publisher is 404 with no audit row and the row kept. Enabling it serves the same bytes with no republish. Not installed is 404. Corrupt state is 404. A state fault is 503 with `Retry-After: 30`. No record means enabled. The device route does not consult the state. The call order is slot, row, enabled check, file.
  - Static: migration 0047 is one `AddField`, depends only on 0046, equals the model field, and is the only 0047.
- `tests/version-1.18.40.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. These run only on dev02: migration 0047 and `makemigrations --check`, the real cache `incr` and `touch`, the real ORM `update` and transaction, the real `module_state` file, and nginx and uwsgi in front of the route. The tests ran the real `agent_downloads.py` and `agent_download_views.py` against the same stubs as 1.18.39, plus a settable `module_state`. `ruff` ran with the repo configuration.

## Johan dev02 checklist

Update dev02 to Core 1.18.40 first. Endpoint Agent Management with a published installer is needed for steps 3 to 8.

1. Run `migrate`, then `manage.py makemigrations --check --dry-run`.
   - PASS: 0047 applies and the check reports no changes.
   - FAIL: an error on 0047, or the check wants a new migration. Send the output.
2. Download the installer once from a private window (a row published by 1.18.39 has no stored time, so Core reads the file once and stores it).
   - PASS: the file downloads and `X-Content-SHA256` matches the published hash.
   - FAIL: a 404 or 500. Send the headers and the Core log lines with `Agent installer`.
3. Download it again and watch the server's disk reads, for example with `iotop` or the time the request takes for the 100 MB file.
   - PASS: the second download starts at once and Core does not read the file a second time for hashing.
   - FAIL: it pauses as long as the first one did.
4. Append one byte to the published file, download, then put the file back and restore its modified time with `touch -r`.
   - PASS: 404 with an empty body while it differs. After the restore the file serves again.
   - FAIL: the changed file is served.
5. Start 2 slow downloads, then a third.
   - PASS: the third gets an empty 503 with `Retry-After: 30`. An agent update download still gets its file.
   - FAIL: the third is served, or the agent download is refused as busy.
6. Disable Endpoint Agent Management, then download the installer.
   - PASS: 404 with an empty body and `Cache-Control: no-store`.
   - FAIL: the file is served.
7. Enable the module again and download the installer, without publishing again.
   - PASS: the same file serves again.
   - FAIL: 404 until a new publish.
8. Open the Audit page after steps 6 and 7.
   - PASS: no row for the downloads, and none for the disable or enable that Core did not make.
   - FAIL: an unexpected download row.

## Exit list

- Version 1.18.40, no rebuild label.
- Installer hash computed once at publish; `mtime_ns` column (migration 0047); re-hash only when size or modified time differ; heal on first serve.
- 2 installer slots taken before the store is read; 503 with `Retry-After: 30` when busy.
- Disabled publisher module is 404; the row stays.
- `core.agent_downloads` stays 1.1.0; no module change.
- Release manager: record that both held findings of the Core 1.18.39 review shipped. No request entry is closed by this patch.
- Left out on purpose: a per-address limiter in Core, an nginx change, a securityWAF change, and every other open request or held finding.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
