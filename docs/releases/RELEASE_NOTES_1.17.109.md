# Tec-Tac Framework 1.17.109

Date: 3 November 2026. A fix for a regression in 1.17.108. On dev02, 1.17.108 hid every licensed module, because the Licensing Server lists them all with no category. You can now install them again on a development server, with a plain warning. What a production server may install does not change.

Closes: the regression Johan found on 3 November 2026 (HAR `debug/har/module catalog.har`). `GET /api/tfd/modules/catalog/online/` listed nine releases from `tec-tac-licensing` (wapm four times, licensing twice, backups, serverhealth, welcome). All had `category: null`, so all were in `unavailable[]` as `unclassified`. Before 1.17.108 they were offered, and WAPM 0.4.29 was installed from them that day. It also fixes three Lows held from the 1.17.108 review.

## What changed and why

1. **A licensed release with no category is treated as `test` (AD-21).** AD-21 says Core treats a module without a category as `test`: refused outside a dev server, at install only. Handoff v0.1.44 section 2 says `development_all` covers unclassified modules only in `development`. So, for a release whose Licensing Server category is missing or not core, server or premium:
   * On a development server, in the `development` channel, it is offered. The row and the catalogue item carry `category_warning`: "Unclassified on the Licensing Server: treated as test".
   * On any other server, or in the `testing` or `production` channel, it stays `unclassified` and is never offered. Staging it is refused with its reason.
   * "Development server" is Core's existing test, `module_category.is_development_server()` (root config `TEC_TAC_ENVIRONMENT=development`). It is the same test the install uses for `test` modules, and it fails closed. Nothing new was invented.
2. **The install still uses the signed manifest's category.** The Licensing Server's category is for display and filtering only. A licensed release still goes through Core's install queue, where the AD-21 check reads the signed manifest. Nothing the server says widens what a manifest says.
3. **A cache from 1.17.108 is worked out again when it is read.** A mark Core set itself for a licence state (`unclassified`, `blocked_by_channel` and so on) is recomputed on each read, so this request's development-server answer decides. You do not need to sync. A retired or refused-credentials mark is never cleared.
4. **Held Lows from 1.17.108:**
   * `unavailable[].category` is now always `core`, `server`, `premium` or null, also for an old cache.
   * Staging with no version given names the reason of the newest release, not of whichever release came first in the cache.
   * The online catalogue reads each repository cache once per request (it was read twice for the licensed source), and the development-server test once.
5. **New fields on `modules[]` items:** `category` and `category_warning`, taken from the selected release. Additive. A request for the warning chip is in `reviews/requests/ui.md`. Until the UI ships it, the release is offered without the chip.

## Module-facing changes

* None that a module calls. The online catalogue route is used by the browser only; the new keys are additive.
* `module_updates.list_updates` reads the online catalogue. On a development server, an unclassified licensed release in the development channel is now offered as an update there too, as it was before 1.17.108. On any other server nothing changes.
* A grep of `modules/` found no module that reads `availability_state`, `unavailable[]` or `category_warning`.

## Assumptions (recorded in `reviews/questions/core.md`)

* The channel tested is the release row's own `channel` (the Licensing Server's word for that release), compared as `development` after trimming and lower-casing. A release with no channel is not offered.
* The warning is shown only on rows that are offered. A refused row keeps the 1.17.108 `unclassified` reason, now reworded to say Core treats it as test and offers it only on a development server in the development channel.

## Tests

* New: `tests/licensing-unclassified-test-1.17.109.py`. A development server in the development channel offers with the warning; a production server refuses; the testing channel refuses; a categorised row is unchanged on both servers; the HAR's shape (nine rows, category null) on a development server gives all nine offered, and on a production server all nine refused; each cache and the development test are read once per request; `unavailable[].category` is normalised; staging with no version names the newest release's reason; the licensed install never reads the server's category; docs, contract, version and line endings.
* Re-run and passing: `tests/licensing-repository-1.17.103.py`, `tests/licensing-download-1.17.103.py`, `tests/licensing-sync-skip-1.17.105.py`, `tests/release-integrity.sh`. `RELEASE_NOTES_1.17.108.md` moved to `docs/releases/`.
* `tests/licensing-availability-1.17.108.py` no longer runs as is: its stubs lack the new `is_development_server` name and it pins version 1.17.108 and its notes. Its row-state cases are covered again, with the new rule, by the 1.17.109 test.
* `ruff check` on the changed files: no new findings (34 before and after, all existing).
* Not run here: anything that needs Django, which is not installed on this PC.

## Checks on the test server (dev02)

1. After the upgrade, open Settings, Modules, Online catalogue. Expected: wapm, licensing, backups, serverhealth and welcome are listed with an Install or Update button. FAIL: any of them is missing, or still listed as unclassified. Send back `/api/tfd/modules/catalog/online/` (the `modules` and `unavailable` keys only).
2. Open `/api/tfd/modules/catalog/online/` while signed in. Expected: each of those items has `category: null` and `category_warning: "Unclassified on the Licensing Server: treated as test"`, and `unavailable` is empty. FAIL: `unavailable` still lists them.
3. Install WAPM 0.4.32 from the catalogue. Expected: it stages and installs as before 1.17.108. FAIL: staging refuses it. Send back the message.
4. If you have a non-development server: the same rows must be in `unavailable` as `unclassified` and must not stage. FAIL: they can be staged.
5. Installed modules keep working after the upgrade. FAIL: any installed module is disabled.
