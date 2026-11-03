# Tec-Tac Framework 1.17.104

Date: 3 November 2026. Core now tells you when an installed module has a newer version. Superusers get one notice per new version, and the Modules page can show which modules have an update, at what level, and why it can't install yet. Core installs nothing by itself in this release.

Closes: phase 1 of `docs/planning/module-auto-update/SPEC-MODULE-AUTO-UPDATE.md` (Johan, 3 November 2026: "notify and highlight only"). The automatic install (policy, window, approval queue, scheduled install) is the later phase and is not built here.

## What changed and why

1. **Update detection.** For every installed module, Core reads the Online catalogue as the Modules page already sees it: the cached repository indexes, the installed versions and the compatibility check. It lists each module with a newer release (`update_available`). Each row gets a level: `patch`, `minor` or `major` from plain `X.Y.Z` versions. Anything else is `other`, for example a pre-release, a `-N` rebuild, build metadata or a two-part version. A row also says whether the update can install now and, if not, why:
   * `core_required`: it needs a newer Tec-Tac Core;
   * `ui_required`: it needs a newer UI;
   * `runtime_unknown`: it needs a component Core can't check;
   * `dependency_missing`: a required module isn't installed;
   * `dependency_update`: an installed dependency is too old;
   * `source_changed`: the installed copy came from another repository.
2. **When it runs.** Detection runs in a Celery worker, never in a web request. A manual sync (one repository or all) queues it, with one short broker attempt and no retry. The daily repository sync (03:00) runs it at the end of its own Celery run. The daily run is the "once a day" check.
3. **Notices for superusers.** Each new module version raises one Core notice ("Module update available", level info, source `core`, action "Open Modules") for the active effective superusers only. It uses the existing `publish_system_notice` path, the same one failed module jobs use. A version is announced once. It is never announced again, even after the notice is read or cleared, and an older version offered again is never announced. A newer version announces again. The dedupe record is one small file beside the repository caches (`update-notices.json`), one entry per module.
4. **Audit.** The first detection of a version writes one row: action `custom:update-detected`, object type `module_update`, actor `system (module update detection)` (service `module-updates`). The row holds the versions, the level, the blocked-reason codes, the repository id, the trigger and how many people were notified.
5. **Offline or licence refused: no notice.** Core announces only releases from a repository whose last sync succeeded. A failed sync (offline), a refused licence or any Licensing state other than ok, refused credentials, a retired repository or a source never synced announces nothing. The read route still shows what the cached catalogue shows, marked `source_current: false`. A licensed source lists only entitled releases, and a refused licence empties that list, as in 1.17.103.
6. **Read routes for the UI** (module-manage permission, `core.privileged_operations`; anyone else gets 403):
   * `GET /api/tfd/modules/updates/` returns `updates[]` (module, installed version, new version, level, release-notes link, `installable`, `blocked_reasons[]`, `blocked_reason`, `source_current`), `count`, `installable_count`, `levels`, `availability` and `last_detection`;
   * `GET /api/tfd/modules/updates/count/` returns the badge numbers.

   Both read the cache only. They make no network call and write nothing. Each web process keeps the answer for up to 30 seconds, so a badge many browsers load stays cheap.
7. **Release-notes link.** A repository index entry may carry `release_notes`. Core keeps it as `release_notes_url` only when it's an `https` link with no credential, query or fragment, at most 500 characters. Core never fetches it. Anything else becomes null and never invalidates the entry. The licensed catalogue carries no link yet, so its rows show null.
8. **Help.** New page: `docs/module-updates.md`. The 1.17.103 notes moved to `docs/releases/`.

## Module-facing changes

All additive. A grep of `modules/` found no module that calls the repository routes, `module_repository` or the sync views, so nothing existing changes.

* **New contract `core.module_updates` 1.0.0** (Python, `tec_tac.module_updates.updates_for_module()`). It's read-only and returns the same payload as `GET /api/tfd/modules/updates/`. Only a **server** module may call it: the caller must be an installed, enabled module whose catalog category is `server`, calling from its own server-side code, verified from the call stack (AD-26). Any other caller (a core, premium or test module, Core, a library) gets `ModuleUpdatesError` `caller_not_allowed` (403) and one `deny` audit row (object type `module_update`, rate limited to one per caller and reason every 5 minutes per process). Feature-detect with `has_capability('core.module_updates')` and require framework `>=1.17.104`.
* **Repository index field `release_notes`** (optional). Release rows in the Online catalogue now carry `release_notes_url` (https or null).
* **New Celery task** `tec_tac.detect_module_updates` (Core-internal, not a contract).

## Assumptions (recorded in `reviews/questions/core.md`)

* **No email in this release.** The notice is enough for phase 1. The Priority 1 email path is kept for failures.
* **Superusers only.** These are the people `system_notice_recipients` already uses: active effective superusers, with no extra names.
* **New permissions aren't a blocked reason yet.** A repository index doesn't list a release's permissions, so Core can't know them before the package is staged. The install preview still shows them before anyone installs.
* **The dedupe record is a file, not a table.** That avoids a migration for one small record. The automatic-install phase will move policy, queue and history into Core's database, as the spec says.
* **An unreadable record is rebuilt quietly.** Core marks what is offered now as announced, sends no notice and logs one warning. Re-announcing everything would flood the superusers, and a record that never recovered would silence detection for good.
* **The contract is limited to server modules** (coordinator decision, 3 November 2026). That's the fail-closed choice: a read for every module would be a new global read. A wider read waits for Johan.

## Tests

* New: `tests/module-updates-1.17.104.py`. It covers:
  * levels, including odd and pre-release versions as `other`;
  * detection and every blocked reason;
  * one notice per version: a second run, a cleared notice, an older version again, and a newer version notifying again;
  * superusers only, with one audit row and the system actor;
  * no notice while offline, with a refused licence or licence state, refused credentials, a retired repository or a source never synced;
  * a failed notice retried with no audit row, and an unreadable record rebuilt without a flood;
  * a catalogue fault that never raises;
  * the badge, and the contract's caller check: a server module allowed; an unverified caller, a premium, core or test module and an unknown module refused with one rate-limited deny row;
  * both routes refusing a person without module-manage, and a plain 503;
  * the sync routes only queue the check, the daily sync runs it, the Celery task exists and the capability is registered;
  * the release-notes link rules.
* Changed: `tests/licensing-repository-1.17.103.py` reads its notes from `docs/releases/` and accepts a later version, as earlier releases did.

## Checks on the test server (Johan)

1. Update Core. Open Settings → Modules → Repositories and press **Sync all**. **Expected:** the sync answers as fast as before. **FAIL:** the sync is noticeably slower or times out. Send the Core and Celery log lines that contain "module update".
2. If an installed module has a newer release in an enabled repository, open the notices (bell). **Expected:** within a minute, one "Module update available" notice per module, saying from which version to which, and the level. Only superusers get it. **FAIL:** no notice while `GET /api/tfd/modules/updates/` lists the update with `source_current: true`, or a non-superuser gets it.
3. Press **Sync all** again, and clear the notice. Sync again. **Expected:** no second notice for the same version. **FAIL:** the notice comes back.
4. Open `/api/tfd/modules/updates/` and `/api/tfd/modules/updates/count/` as a superuser. **Expected:** the list, with `level`, `installable` and `blocked_reason`, and the same count. **FAIL:** an error, or a module listed that is already up to date.
5. Open the same two addresses as a user without module management. **Expected:** 403. **FAIL:** any data.
6. Audit log: filter on object type `module_update`. **Expected:** one `custom:update-detected` row per announced version, actor `system (module update detection)`. **FAIL:** no row, or a row per sync.
7. `manage.py makemigrations tec_tac --check --dry-run`. **Expected:** no changes (no migration in this release). **FAIL:** a migration is proposed.

## Not done here

* **Not run on this PC.** Django, Celery, a Linux `fcntl` and a database aren't available here. `module_updates.py` loads Django code only inside its functions, so the test runs the real file with stubs for notices, audit and the catalogue. The routes run with stubbed DRF classes. The real notice table, the broker and the lock run only on a server.
* **No automatic install.** There's no policy, window, approval queue, Celery install run or rule-5 fallback. These wait for the later phase, after this phase works (Johan, 3 November 2026).
* **No UI change.** The badge, highlighted rows, the "Updates available" filter and the notice display are a request in `reviews/requests/ui.md`.

---
Tech Flow Dynamics · techxflow.co.za
