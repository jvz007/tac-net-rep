# Tec-Tac Framework 1.18.43

Date: 22 November 2026. System update can now list every build on the server's update source and stage the one you pick, not only the latest. A downgrade has three safety limits, so a build that would break the server is never offered or installed. This is the Core half (AD-77). The version dropdown is the matching UI patch. `main` stays held.

## Module-facing change

- **New route (additive): `GET /api/tfd/system/updates/versions/?component=framework|ui`.** Session-authenticated, module-manager rights, as the branches route. It lists builds newest first as `{version, commit, date, operation, installable, reason}`, plus `source`, `installed_version`, `lowest_installable`, `migration_check` and, when GitHub's limit is exhausted and a saved list is shown, `github_rate_limit_error`. The source is the server's saved update source, never a client value.
- **New value (additive): `source_type: "version"` on `POST /api/tfd/system/updates/online/stage/`**, with `version` and an optional `commit`. A version that is not a row of the list read now answers 409 `stale_candidate`. A row that is not installable answers 400 with its reason. A tree with no valid signed release file is discarded and answers 400. The existing `release` and `branch` shapes are unchanged.
- **Added to the 201 preview:** for a downgrade that crosses a limit, `installable` is false and `install_block_reason` holds the sentence. The install route already refuses such a package.
- **The limits apply to every downgrade**, also an offline upload and the stable release, not only a version picked from the list.
- Users found in `modules/`: no module calls `/api/tfd/system/updates/*` or imports `system_update`. Nothing in `modules/` changes behaviour.

## Closes

- `reviews/requests/core.md`, "ORDER: Core patch after 1.18.42, System update version picker (AD-77, Johan 22 November 2026)", parts 1 and 2.
- The matching UI order (`reviews/requests/ui.md`, "ORDER: UI patch after the version-picker Core") waits on this release.

## What changed and why

Beta testers sometimes need one specific build to get past a problem. Until now Core offered only the latest. Now you choose the build, and Core keeps the server safe while you do.

1. **List builds (`system_update.list_versions`).** On a branch source it reads the 100 newest commits (one cached request) and keeps those whose message is a plain version such as `1.18.42`. A `-N` rebuild label and ordinary commits are skipped. On a release source it reads the published releases and skips drafts and prereleases. A release row has `commit` null: Core resolves the tag when you stage it. A release older than the first signed Core (1.15.37) is listed as not installable, because Core installs only signed builds by version.
2. **Smaller saved copy.** `_reduce_body` now trims a saved commits list to `{sha, first message line, committer date}` and a releases list to six fields. Before, a 100-commit list would have stored 100 full commit objects in `release-cache.json`.
3. **Stage by version.** `stage_online_package(..., source_type="version", version=, commit=, source=)` re-reads the list (5 minutes, ETag-revalidated), finds the exact version and downloads `zipball/<commit>`. The source dict has the same four keys as today, so the root helper's sanitised copy and `_installed_source_commit` keep working. After staging, the preview must show a verified signed tree (`signed` and `verified` true, `legacy` false). Otherwise Core discards the stage and answers "Core only installs signed builds by version; this one has no valid signed release file." The development unsigned override does not apply here. Core also refuses a tree whose `VERSION` is not the version listed.
4. **Three downgrade limits (`downgrade_problem`).** Only a downgrade is limited. An update or reinstall is never touched.
   - Limit 1, modules: the version must meet the highest `>=` or `>` floor that an installed module sets in `requires.framework` (Core) or `requires.ui` (UI). The sentence names the module, for example "Module governance and 1 more needs Tec-Tac Framework 1.18.35 or newer."
   - Limit 2, migrations (Core only): a build that lacks a `tec_tac` migration this server already applied is refused: "This Core version lacks migration 0004_d that this server already applied. A downgrade never crosses a migration; restore the server backup instead." `inspect_archive` compares the real package's migration names with Django's applied set. List rows have no package, so a binary search over the older rows reads the migration folder at about 7 commits (`contents` API, saved by commit). The stage-time check on the real archive is always the authority.
   - Limit 3, UI (Core only): a Core build outside the installed UI's `requires.tec-tac-framework` range (every comma part checked, upper bound included) is refused: "The installed UI 0.13.1 needs Tec-Tac Framework >=1.18.35,<2.0.0. Downgrade the UI first."
   - Anything Core cannot read (a module manifest, the applied migrations, the UI's requirements) refuses the downgrade with a plain sentence.
   - `lowest_installable` is the oldest listed row that passes every limit.
5. **Route, OpenAPI group, contract and docs.** `urls.py` names `tec-tac-system-update-versions`. `openapi.py` maps `SystemUpdateVersionsView` to "Tec-Tac · System Updates" (a route with no group fails the F11 coverage test, as in 1.18.37). `contracts.py` (CRLF kept) has the new route and additive text on the stage route and the 201 preview. `docs/update-source.md` has a short section.

### Plan corrections found in the code

- The plan said `release_trust.legacy` is False only for a verified tree. It is also False for an unsigned tree on a branch source. The check therefore requires `signed` true, `verified` true and `legacy` false together.
- The plan expected stubs in `system-update-linux-staging-1.17.98.py` and `update-source-1.17.4.py`. Neither calls `inspect_archive`, so neither needed a change. `system-update-stale-head-1.17.106.py` did (its three hooks are stubbed to "none") and `update-source-1.17.3.py` lists the request keys the stage view reads (now including `version`).
- The module-manifest scan, the migration read and the UI read are done once per list, not once per row, so a 100-row list costs one scan.

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- **The limits apply to every downgrade**, because a migration crossing is equally unsafe whichever way the older package arrives.
- **`migrations_ahead` is not built.** AD-77 answer "a" refuses a crossing instead of warning, so the refusal sentence and the row reason are enough.
- **Branch source lists the 100 newest commits.** A release row's commit is resolved at stage time. Paging can follow on request.
- **Fail closed, with no root-helper change.** The root helper still re-verifies the signed tree and applies its own downgrade policy. It does not re-check modules or migrations. Core's refusal plus the superuser `allow_downgrade` confirmation is the same trust level as the existing downgrade gate.

## Retired or changed checks

- `tests/version-1.18.42.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.42.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs `system-version-picker-1.18.43.py` and `version-1.18.43.py` in place of the retired one.
- `tests/system-update-stale-head-1.17.106.py`: three stubs for the new hooks. The limits are not weakened. They have their own test.
- `tests/update-source-1.17.3.py`: the stage view now also reads `version`.

## New tests

- `tests/system-version-picker-1.18.43.py`: the real `system_update.py` against stubs and a fake GitHub that counts requests. Branch and release lists, the reduced saved copy, the 5-minute cache with no request, a rate limit with a saved list, every refusal on stage, the signed-tree rule on a development server, the release tag resolved at stage time, the three limits (highest minimum, missing migration, UI range with an upper bound), fail-closed reads, the probe count on 100 rows, a failed probe, and source checks on the view, urls, openapi and contracts.
- `tests/version-1.18.43.py`: release bookkeeping.

## What could not be run here

Django has no settings and no database on this PC, so the view, the real `MigrationRecorder` hook and the web routes were checked by source assertions, with the hook replaced in tests. Django is not available to run the contract-export check either. The root helper test `system-update-linux-staging-1.17.98.py` skips (it needs root on Linux). Several older tests fail on this PC for reasons that predate this release (`fcntl`, `pwd`, a stale migration number); they fail the same way without this change.

## Johan dev02 checklist

Update dev02 to Core 1.18.43 first. The dropdown needs the matching UI patch. Until then, call the routes from the browser console while signed in as a superuser.

1. Open `/api/tfd/system/updates/versions/?component=framework`.
   - PASS: you see builds newest first, only plain versions, each with `installable` and a `reason` when false. The newest is the installed one with `operation` reinstall.
   - FAIL: the list is empty, holds `-1` rebuilds, or answers an error. Send the body.
2. Open `/api/tfd/system/updates/versions/?component=ui`.
   - PASS: UI builds listed the same way, `migration_check` is `not_applicable`.
   - FAIL: the list is empty or Core answers 400. Send the body.
3. Look at the rows below the installed Core.
   - PASS: a row older than an installed module's minimum says which module needs a newer Core. A row that would lose a migration says "restore the server backup instead". `lowest_installable` is the oldest row without a reason.
   - FAIL: a row you know breaks a module or a migration shows `installable` true. Send the row and the module list.
4. Reload the list twice inside 5 minutes.
   - PASS: the second and third loads are quick and `journalctl` shows no new GitHub request.
   - FAIL: every load waits several seconds or sends requests. Send the timings.
5. POST `/api/tfd/system/updates/online/stage/` with `{"component": "framework", "source_type": "version", "version": "<an older listed version>"}`, then read the preview.
   - PASS: you get 201 with `operation` downgrade, a signed `release_trust`, and `installable` true. Nothing installs until you confirm in the install step.
   - FAIL: Core answers 400 about a signed release file for a build you know is signed, or stages an unsigned tree. Send the commit and the body.
6. POST the same with `"version": "0.0.1"`.
   - PASS: Core answers 409 `stale_candidate`.
   - FAIL: Core stages something or answers 500.

## Exit list

- Version 1.18.43, no rebuild label. No migration. No root-helper, `install.sh` or sudoers change.
- New route `system/updates/versions/`; new stage `source_type` `version`; three downgrade limits on every downgrade.
- Release manager: close the ORDER "Core patch after 1.18.42, System update version picker (AD-77...)" in `reviews/requests/core.md`, naming 1.18.43. The UI order in `reviews/requests/ui.md` can start after this release is signed. It can use the route name and the row fields listed above.
- Left out on purpose: every other open Core request (including the two contract-file requests from endpoint-comms 0.6.20 and reportmanager 0.9.1), paging past the 100 newest commits, resolving every release row's commit at list time, and every held finding.
- Still open, held (not touched here): the two Mediums from the Core 1.18.42 review (a batch bundle loses repository provenance at install; the 240 second batch deadline can pass the uwsgi harakiri) and the Medium from 1.18.41 (Run now on a non-superuser schedule).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
