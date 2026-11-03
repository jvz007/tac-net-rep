# Tec-Tac Framework 1.17.103

Date: 3 November 2026. The online catalogue lists the modules your licence includes, and installs them, again. It works through the Licensing module. Core holds no Licensing Server credential. It only receives a short-lived download permission.

Closes: items C3 (listing) and C4 (install) of `reviews/core/LICENSING-COMPATIBILITY-DIFF-2-11-2026.md`, and the four items under "held from 1.17.102" in `reviews/requests/core.md`.

## What changed and why

1. **A licensed source in the catalogue (C3).** Core seeds one repository of kind `licensing` (id `tec-tac-licensing`) beside the old retired entry. The seed is once-only and upgrade-safe: a server on 1.17.102 gets it on the next scheduler tick, the old record is not touched, and a source you remove stays removed. A sync asks `licensing.catalogue.module_catalogue(channel=...)` and stores the answer in the cache shape every repository already uses. Dependency lists become objects. `release_id`, `publisher_id`, `key_id` and `entitled` are kept. The cache holds no credential and no address.
2. **Fail closed (AD-56).** A Licensing module that is missing, disabled, unhealthy or refuses Core gives `licensing_unavailable` and an empty list. Not registered, revoked, expired, grace ended, refused and `channel_not_permitted` are plain states with their own sentence. Core never shows an unrestricted list. A short fault keeps the last good list. Every other state empties it.
3. **The channel is a setting of each source (AD-58 D6).** Empty means the licence's own channel. A module manager can set another name through the existing `PATCH /api/tfd/modules/repositories/<id>/` (`{"channel": "testing"}`). The Licensing Server decides what the licence allows. A refused channel shows `channel_not_permitted`. Core never switches channels. A change writes a strict audit row first (no row, no change) and clears the list of the old channel.
4. **Installs work again (C4).** Staging a licensed release writes a strict audit row first. Then Core asks `download_grant(release_id=..., channel=...)`, fetches the three relative paths on the pinned address from `get_licensing_server_url()` with the bearer, and follows no redirect. The fetch has size caps and time limits. The bearer lives in one local variable, is removed from the grant object, and never reaches a log, a cache, an audit row, an answer or an exception. An expired grant (HTTP 401, or its own five minutes) gets one new grant, then stops with `grant_expired`. 403 and 404 and other faults are plain states.
5. **Core checks the files itself.** The file name comes from the validated `release.json`, never from a URL. Core checks the SHA-256 against both the catalogue and `release.json`, the publisher and key against the catalogue, and the Ed25519 signature with `verify_release_files(require_signed=True)` on this server's trusted publisher keys. The catalogue is a cross-check, never proof. Only then does the existing staging take the files with both sidecars (the same code as an upload). The existing install queue and Module Manager do the install. There is no second installer. A staged result that is not signed and verified, or that is another module or version, is discarded.
6. **Four Lows held from 1.17.102.** (a) The secret store's decrypt-failure log line is written every time. The limiter now caps only the audit row. (b) `install.sh` writes `key-group` to a temporary file and moves it with `mv -f`, so Core never sees a half-written record. (c) A group name outside `^[a-z_][a-z0-9_.-]{0,63}$` now warns, removes any stale record and skips writing it. The install goes on and the secret store stays closed (`wrong_group`). (d) `docs/secret-store.md`, `docs/troubleshooting-diagnostics.md` and the contract text now say `root:<group in key-group>` (normally `tactical`).
7. **Help and troubleshooting.** `docs/module-repositories.md` has "The licensed catalogue (1.17.103)" with a table of every message. `docs/troubleshooting-diagnostics.md` lists each one (footer last). The 1.17.102 notes moved to `docs/releases/`.

## Module-facing changes

All additive. A grep of `modules/` found no module that calls the repository routes or `module_repository`, so nothing existing breaks.

* **Repository records and routes (browser only).** A record may carry `kind` (`licensing`; none means an index repository, as before) and `channel`. `sync.licensing_state`, `availability.licensing_state` and new `availability.state` values (the Licensing states) appear. A release row of a licensing source also has `release_id`, `publisher_id`, `key_id`, `entitled`, `category`, `entitlement_source` and `availability`, and no `download_url`. `stage_repository_package(..., request=None)` and `upsert_repository(..., request=None)` take an optional request for the audit row.
* **Consuming `licensing.catalogue` 1.0.0 (Licensing 0.10.0).** Core is the caller. It calls the provider from one fixed file, `framwork/tec_tac/licensing_catalogue_source.py`, with keyword arguments only. Licensing can allow exactly that file. No other Core file and no module-controlled path calls it. Answer to Licensing's request for a "Core is the caller" marker: Core does not add one in this release, because that file is the only caller. See `reviews/questions/core.md`.
* **New audit rows** (`licensed_module_release`, action `run`, results `started` and the outcome; `module_repository`, action `modify`, for a channel change). No credential in any of them.

## Assumptions (recorded in `reviews/questions/core.md`)

* **Seeded enabled, priority 50.** The licensed source is the working path, so it is on, and ahead of the old entry (priority 100, disabled). With no registered Licensing module it only shows a state.
* **A licence state is attention, not a failed run.** The daily sync counts `not_registered`, revoked, expired, grace ended, refused and a refused channel as `licensing_attention`. A Licensing module that is down still fails the run.
* **One licensing source, created by Core only.** An administrator edits name, priority, enabled and channel. Kind, address and trust are Core's.
* **A temporary fault keeps the last list.** `licensing_unavailable`, `invalid_response` and `audit_unavailable` do. Installs still need a fresh grant, so nothing installs without the licence.
* **Staging still runs in the request, as today.** Sync and staging already ran there. No new slow work was added to any other request. The catalogue page reads the cache only.
* **Files kept to the standing limits.** Package at most `MAX_PACKAGE_BYTES`, `release.json` 256 KiB, signature 16 KiB; 20 s for the small files and 60 s for the package; the grant's five minutes bound the whole download.

## Tests

* New: `tests/licensing-repository-1.17.103.py` and `tests/licensing-download-1.17.103.py`. Real Ed25519 signatures and Core's real trusted-publisher check; a fake provider with the real keyword-only signatures. They cover the listing, the seed and upgrade from 1.17.102, provider missing or unhealthy, per-source channels and `channel_not_permitted`, grant expiry and its single retry, 401, 403 and 404, a revoked grant mid-download, SHA-256 and signature tampering, filename binding, a redirect to another host, plain http, the token absent from logs, audit rows, cache, answers and exceptions, an unsigned release, the strict audit row first, and the docs.
* Changed (they held assumptions this release changes): `tests/secret-store-hardening-1.17.101.py` (log every time; the `mv -n` stub), `tests/secret-store-group-1.17.102.py`, `tests/default-repository-1.17.42.py`, `tests/repository-seed-1.17.43.py`, `tests/repository-seed-lock-1.17.43.py`, `tests/module-repository-skipped-1.17.39.py`, `tests/licensing-override-1.17.58.py`. Two of these (`repository-seed-lock-1.17.43.py`, `repository-daily-sync-1.17.42.py`) were already failing on 1.17.102 with a missing helper name; their name lists are fixed.
* Re-run: the 1.17.99 to 1.17.102 tests and `tests/release-integrity.sh`.

## Checks on the test server (Johan)

Do A first. B needs the Licensing module registered, which needs Sol's issuer key.

**A. Not registered (works today)**

1. Update Core. Open Settings → Modules → Repositories. **Expected:** within a few scheduler ticks, "Tec-Tac licensed modules (Licensing)" appears, enabled, channel empty, next to the old entry. **FAIL:** it is not there after 15 minutes. Send the Core log lines that contain "default module repository".
2. Press Sync on it. **Expected:** a message "This server is not registered with the Licensing Server..." and the Online catalogue shows state `not_registered` with no modules. **FAIL:** any module is listed, or the message is a generic error.
3. On the test server only, disable the Licensing module and Sync again. **Expected:** "Core could not get an answer from the Licensing module...", an empty list. Enable it again. **FAIL:** a list appears while the module is off.
4. Set the channel to `testing`, then to `Production`. **Expected:** `testing` saves and the Audit log shows a `modify` row on `module_repository` with `channel_before: default` and `channel_after: testing`; `Production` is refused. Clear the channel. **FAIL:** no audit row, or `Production` saves.
5. Upload a signed `.zip`, `.zip.sig` and `.release.json` on Settings → Modules. **Expected:** it stages as before. **FAIL:** any change from 1.17.102.
6. `sudo ls -a /etc/tec-tac/secrets` then `sudo cat /etc/tec-tac/secrets/key-group`. **Expected:** `key-group` and `master.key` only (no `.key-group.*` leftovers), and the group name. **FAIL:** a leftover file or a missing record.
7. `manage.py makemigrations tec_tac --check --dry-run`. **Expected:** no changes (this release has no migration). **FAIL:** a migration is proposed.

**B. Registered (after Licensing is registered)**

8. Sync the licensed source. **Expected:** the Online catalogue lists the modules your licence includes, with versions and dependencies. **FAIL:** an empty list with no state, or a message other than a Licensing state.
9. Stage a small module from it. **Expected:** it stages, Module Manager shows the publisher as verified, and the normal install works. The Audit log has two `licensed_module_release` rows (`started`, `staged`). **FAIL:** a Core message in the table under "The licensed catalogue (1.17.103)". Send the message and the Core log lines.
10. Set a channel your licence does not allow and Sync. **Expected:** `channel_not_permitted`, an empty list, the channel unchanged. **FAIL:** Core lists another channel.
11. If the test licence can be revoked on the Licensing Server: Sync. **Expected:** the licence-revoked message and an empty list. **FAIL:** a list stays.
12. `sudo grep -il "token" /var/lib/tec-tac/module-manager/repositories/cache/tec-tac-licensing.json`. **Expected:** no output. **FAIL:** a file name is printed.

## Not done here

* **Not run on this PC.** Django, a Linux shell with `fcntl` and a network were not available. `module_repository.py` is tested by reading its functions with `ast` and running them with stubs, like the earlier repository tests. The new Licensing file, the real trusted-publisher check and Ed25519 signatures run for real. A real download against the Licensing Server has not been done.
* C5 (browser routes), C6 and C7 (grace display) are separate items.
* No UI change. A channel field on the repository form is a request in `reviews/requests/ui.md`. Until then the channel is set through the existing route, and `sync.error` already shows the Licensing message.
* No marker for "Core is the caller" (see Module-facing changes).

---
Tech Flow Dynamics · techxflow.co.za
