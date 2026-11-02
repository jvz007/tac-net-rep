# Tec-Tac Framework 1.17.99

Date: 2 November 2026. The online module catalogue now tells the truth when a repository no longer offers public downloads, and Core can read the Licensing Server address from a root-owned setting. Nothing in this release calls the Licensing Server.

Closes: item C1 of `reviews/core/LICENSING-COMPATIBILITY-DIFF-2-11-2026.md` (the online catalogue broke because the Licensing Server removed public repository downloads). Built under AD-56 (Johan, 2 November 2026): the Licensing module is the only Licensing Server client, and Core holds no Licensing Server credentials. C2 to C7 are not in this release.

## What changed and why

1. **A retired repository is named as such (`module_repository.py`).**
   * A sync that gets HTTP 401, 403, 404 or 410 marks the repository **retired**: the cache file gets `retired: true`, `retired_at` and `error_status`, and the repository status row gets `sync.retired`. Core keeps `status: "error"`, so nothing that reads `status` changes.
   * When every enabled repository is retired, `availability.state` is **`repository_retired`** and the message reads: "This module repository no longer offers public downloads. Install modules by uploading the signed .zip, .zip.sig and .release.json on Settings → Modules until the licensed catalogue arrives." The existing Online catalogue page already shows `availability.message`, so no UI change is needed.
   * A network error, a timeout, a TLS error, HTTP 429 and any 5xx are **not** retired. The state and the cached list stay as they were (1.17.41 behaviour).
   * A transient failure after a retired sync keeps the retired state. A later successful sync rewrites the cache and clears it.
2. **No dead install buttons.** Releases cached from a retired repository carry `download_unavailable: true` and `download_unavailable_reason`. They are left out of `modules[]`, so the page has nothing to install, and `stage_repository_package` refuses them with the retired message before any download. An installed module that was offered only by a retired repository moves to `installed_only[]`, as 1.17.41 already does for any module no repository offers.
3. **The Licensing Server address (`licensing_server_url.py`, new).** `TEC_TAC_LICENSING_SERVER_URL` in `/opt/tec-tac/etc/tec-tac.conf` is read through `get_licensing_server_url()`, which returns `{url, source, configured, reason}`.
   * Valid means https, a host, and no user info, query, fragment, space, control character, backslash, `..` segment or `;` in the path. An invalid value is treated as unset, the default `https://lic-service.tec-tac.techxflow.net.za` applies, and the reason is logged once. The value itself is never logged or returned for an invalid entry.
   * No route, view or setting reads or writes the key, so it cannot be changed from the web. The function makes no network call and reads one small file.
4. **`install.sh`** carries an existing `TEC_TAC_LICENSING_SERVER_URL` line over unchanged (valid or not) when it rewrites the config. On a first install it writes the key only when the installer environment supplies one, and refuses a value with a CR or LF. With neither, no line is written and the default applies.
5. **Text.** Help and troubleshooting entries for every new message: `docs/module-repositories.md` (new section and troubleshooting table) and `docs/troubleshooting-diagnostics.md`. Both end with the footer. The contract text for the online catalogue route gained the 1.17.99 note.
6. `RELEASE_NOTES_1.17.98.md` moved to `docs/releases/`.

## Module-facing changes

All additive. Checked in `modules/`: no module calls `catalog/online`, `module_repository`, `repository_status` or `online_catalog`.

* **New contract row:** `tec_tac.licensing_server_url.get_licensing_server_url()` (and `validate_licensing_server_url(value)`), read-only, for the Licensing module. Needs framework >=1.17.99.
* **`GET /api/tfd/modules/catalog/online/`:** new `availability.state` value `repository_retired`, new `availability.retired_repositories`, new `sync.retired` on repository rows, `download_unavailable` on cached releases. Existing keys and values keep their meaning. A caller that does not know the new state sees an empty `modules[]` with a message, as for `sync_failed`.
* **`POST .../catalog/online/stage/`:** answers 400 with the retired message for a release of a retired repository.
* A fresh contract export is needed (`reviews/requests/core.md` pattern).

## Assumptions (recorded in `reviews/questions/core.md`)

* "Cached releases of a failed/retired repository" is read as **retired only**. A repository that failed for a network reason or a 5xx keeps its old list, because 1.17.41 and this task both say a transient failure keeps its current state.
* Releases of a retired repository are removed from `modules[]` rather than shown with a disabled button, because the UI has no field for it yet. If the UI should show them disabled with the reason, that is a `ui.md` request.
* A 1.17.98 cache has no flag. Its stored error text `Repository request returned HTTP 401|403|404|410.` is read as retired with no migration step.
* The sync itself is unchanged: still the manual Sync action and the 03:00 Scheduler job, no new work in a request. Marking retired is part of the cache write the sync already makes, so no new audit action was added.
* The URL may carry a path (for example a reverse-proxy prefix); a trailing slash is removed. C4 should still pin the origin.

## Tests

* New: `tests/repository-retired-1.17.99.py` (401/403/404/410 mapping; 429/500/502/503, timeouts, network errors and bad index not retired; first-ever sync; stale cache not offered or staged and no fetch made; healthy repository beside a retired one; recovery; the 1.17.98 cache upgrade with 404, 503, healthy, odd-text and corrupt files; 5xx after retired; URL validation with 6 valid and 22 invalid values, the default, the last line wins, no secret in the answer or the log; `install.sh` run under bash for absent, env-supplied, existing, invalid-existing, CRLF and newline injection; contract, docs and footer; no module uses the repository code).
* Changed: `tests/online-catalog-availability-1.17.41.py` and `tests/module-repository-skipped-1.17.39.py` read the new names from the source. The second also allows the word "licensed" in the new message (its source scan bans entitlement checks, and none was added).

## Checks on the test server (Johan)

1. `sudo grep TEC_TAC_LICENSING_SERVER_URL /opt/tec-tac/etc/tec-tac.conf` after the update. **Expected:** no line on a server that never set it (the default applies). **FAIL:** a line you did not write.
2. Settings → Modules → Online catalogue, press Sync on the official repository (enable it first). **Expected:** if the server still answers 401, 403, 404 or 410, the page shows "This module repository no longer offers public downloads..." and lists no modules. **FAIL:** a list of modules with install buttons. Send the answer of `GET /api/tfd/modules/catalog/online/`.
3. Upload the signed `.zip`, `.zip.sig` and `.release.json` together. **Expected:** it installs as before. **FAIL:** any new refusal. Send the job log.
4. Optional: add `TEC_TAC_LICENSING_SERVER_URL=http://x` to the config and look at the Core log. **Expected:** one warning "is not used: only https addresses are accepted". Remove the line afterwards.

## Not done here

* **Django is not installed on this PC.** The Django test runner, the views against a real DRF stack and a live Licensing Server did not run. `module_repository.py` is tested through `ast` extraction with stubs; the real `_fetch` was not exercised (the change there is one subclass raised for non-2xx statuses).
* C2 to C7 (secret store, catalogue provider, grant download, licensed route, signed bootstrap, status wiring) are not started. Nothing calls the Licensing Server.
