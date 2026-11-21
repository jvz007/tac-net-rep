# Tec-Tac Framework 1.18.38

Date: 21 November 2026. Bulk upgrade now plans the same release the single Upgrade installs. The agent download link token stays out of the Core log, the new route has its own Swagger group, and the in-flight download counter no longer expires under load. `main` stays held.

## Module-facing change

None to the call shape of any module. No field, code, route or capability is added or removed.

- Bulk upgrade (`POST /api/tfd/modules/catalog/online/plan/` and `.../install/` with `purpose: "upgrade"`) now plans more modules: the ones the single Upgrade already offers. Before, it only planned modules the Licensing allowed list named with a release. A module in the development channel, such as `sentinelone` on dev02, was blocked in bulk and installed fine on its own.
- `purpose: "install"` and a request with no `purpose` are unchanged. They still follow the allowed list (not ticked, no release, not available, not in the cache).
- Users found in `modules/`: Welcome calls the plan and install routes without a `purpose`, so it sees install behaviour only. Licensing reads the allowed list and the catalogue, not the plan. No module sends `purpose: "upgrade"` or imports the plan, the run or the repository selection. Only the Core UI bulk Upgrade selected uses it, and it already knows every blocked code returned here.
- `contracts.py` and `docs/module-repositories.md` now say that an upgrade takes its release from the repository the single Upgrade uses.

## Closes

- Week plan item 3b2, request "From Johan's test of Core 1.18.35 bulk upgrade (21 November 2026): bulk upgrade blocks a module the single Upgrade installs". The release manager removes the entry, naming 1.18.38.
- Core 1.18.37 review, held Medium: the live link token reached `django_debug.log` through `django.request` on a 5xx.
- Core 1.18.37 review, held Medium: the new route had no OpenAPI group, so the F11 coverage test failed.
- Core 1.18.37 review, held Low: the in-flight counter's lifetime reset every 120 seconds while downloads ran.

## What changed and why

1. **Bulk upgrade follows the single Upgrade.** The single Upgrade picks its release in `online_catalog()`: the repository the module is installed from first, then repository priority, then the highest version, and never a release marked unavailable. That choice now lives in one helper, `module_repository.select_release()`, which `online_catalog()` calls. Behaviour of the catalogue did not change. `upgrade_selector()` reads the enabled repositories' caches and the installed list once and answers `select(module_id)` with the same row. The development channel and availability rules apply as in the single path.
   - `module_install_plan.build_plan` takes a new `upgrade_release` argument. For an upgrade it takes the release from there, not from the allowed list. It still blocks `protected`, `not_installed` and `other_source`, and now also `other_source` when the selected release sits in another repository than the one the module is installed from, or in a repository that is not a licensing one. A missing row gives `not_in_catalogue_cache`, as before. `already_installed`, `older_than_installed`, `bad_version` and `disabled_install` are unchanged. Calling it for an upgrade without `upgrade_release` raises `ValueError`: there is no silent fallback to the allowed list. The install path is untouched.
   - `module_install_run._recheck_upgrade` makes the run follow the plan. Without it the run would have skipped the same module with `no_release` at its first tick. An upgrade run asks `env.upgrade_release(module_id)`, skips with `not_in_catalogue_cache` when nothing is offered and with `version_changed` when the version moved, and stages from the selected row's repository. It never reads the allowed list. An install run keeps its allowed-list recheck.
   - Nothing is offered that the single Upgrade does not already offer. Licence enforcement (AD-72) will add the plan check to both paths together.
2. **Log redaction.** New `log_redaction.py` holds a logging filter on the `django.request` logger. It rewrites `/api/tfd/agent-downloads/<token>/` to `/api/tfd/agent-downloads/<redacted>/` in the message, the arguments (tuple or dict) and the request attached to the record. The record gets a read-only wrapper of the request. The real request is never changed. A record without the route passes through as the same object. The filter never drops a record, so the 503 and every other status stay logged. It is installed once from `apps.py`, in a guarded block, and works whatever handlers Tactical's settings attach.
3. **OpenAPI group.** `Tec-Tac · Agent Downloads` is in `CORE_CALLBACK_GROUPS` and `CORE_PATH_GROUPS`. There is still no catch-all. `tests/f11-openapi-final-1.15.178.py` passes again.
4. **Counter lifetime.** `acquire_slot` and `release_slot` now call `cache.touch` on the counter. While downloads keep coming, it no longer expires at 120 seconds. It still heals after 120 seconds of no activity (a dead worker). A cache fault in `acquire_slot` still raises, so the view answers 503. A fault in `release_slot` is still swallowed with the warning.

Plan correction found in the code: the plan names `TecTacConfig.ready`. The class is `TecTacFrameworkConfig`. The guarded call sits in its `ready`. The plan also asked to extend a contract metadata sentence about logging. There is none to extend: the promise "never logged" in the metadata and the docs is still true, and the docs now say where the redaction lives.

## Assumptions

Recorded as information in `reviews/questions/core.md`. Say if you want a different choice.

- **Plan state stays fail-closed for an upgrade.** The plan still reads the allowed list for its state, revision and time. If Licensing answers a state that is not ok, the plan returns that state and offers nothing, as today. The release itself no longer depends on the list. Staging needs the licence server for the grant anyway.
- **An upgrade run stages from the repository of the release the single Upgrade selects,** not from the first licensing repository that has the version.
- **The token is kept out of the log with a filter,** not by answering below 500 and not by moving it to a header. The 503 and its `Retry-After` are part of the signed contract and the route shape must not change. The filter is Core-wide, redacts only this route and never drops a record.

## Retired or changed checks

- `tests/version-1.18.37.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.37.md` moved to `docs/releases/`.
- `tests/online-upgrade-run-1.18.35.py` changed: its fake plan call and its fake run environment now supply `upgrade_release`, because an upgrade plan without it now raises. Every assertion it had still holds. `online-install-plan-1.18.19.py`, `online-install-run-1.18.20.py` and `online-install-chain-1.18.21.py` needed no change.

## New tests

- `tests/online-upgrade-release-1.18.38.py`: the shared selection (pinned repository first, priority before version, unavailable rows skipped, input not reordered, `online_catalog` calls the helper); an upgrade plans a development-channel module the allowed list does not carry, including a row that is not ticked, has no release or is not entitled; the blocks that stay; the install purpose exactly as in 1.18.19; no silent fallback; an upgrade run stages from the selected repository, skips `version_changed`, never reads `allowed()`; an install run still skips `no_release`.
- `tests/agent-downloads-fixes-1.18.38.py`: the token is absent from a real handler for a record built the way Django builds it, for dict args, a path in the message and a request that carries it; the real request is unchanged; plain records pass untouched; the install is idempotent; the OpenAPI group by path and callback; the counter keeps its lifetime across 200 seconds of use, heals after 120 idle seconds, stays at the cap of 8, and survives cache faults as before.
- `tests/version-1.18.38.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. The real URL resolver, a real `django.request` log line written by `log_response`, drf-spectacular's Swagger page, Redis and the `FileStore` (it uses `fcntl`), staging and the helper queue run only on dev02. `select_release` ran from its own source with a stubbed version check. The plan and the run ran against fake collaborators. The filter ran against hand-built records in Django's shape.

## Johan dev02 checklist

Update dev02 to Core 1.18.38 first.

1. In Modules, tick `sentinelone` (development channel, not in the licence plan) and press Upgrade selected.
   - PASS: the plan offers it and the run installs the same release the single Upgrade offers.
   - FAIL: it is blocked, or a different version is installed. Send the blocked code and the run progress.
2. Install a module that is not in the licence plan through the bulk install.
   - PASS: it is still blocked (`not_in_allowed_list` or `no_release`).
   - FAIL: it installs. Send the plan body.
3. Start downloads until 8 are open, then start a ninth.
   - PASS: the ninth gets 503 with `Retry-After: 30`.
   - FAIL: it is served, or it gets any other status.
4. Trigger a 503 on a download link, then search `django_debug.log` for the link token.
   - PASS: the line shows `/api/tfd/agent-downloads/<redacted>/` and the token is nowhere in the log.
   - FAIL: the token appears. Send that line with the token blanked.
5. Open the Swagger page.
   - PASS: it lists the `Tec-Tac · Agent Downloads` group.
   - FAIL: the route sits in no group or in another one.

## Exit list

- Version 1.18.38, no rebuild label.
- Bulk upgrade plans and runs from the single Upgrade's selection; install purpose unchanged.
- The link token is in no Core log line; the 503 stays logged.
- `tests/f11-openapi-final-1.15.178.py` passes.
- Release manager: remove the request named in Closes, naming 1.18.38, and move it word for word to `_history/core.md`. Mark the three Core 1.18.37 findings in `reviews/core/BACKLOG-new-findings.md` closed by 1.18.38. After the update, ask Johan to check that Upgrade selected on `sentinelone` gives the same result as the single Upgrade.
- Left for the next small patch: the held Low "Upgrade run does not re-check that the module is still installed before staging" (the upgrade re-check was rewritten here, but this finding is not closed), and the held Low "other_source check is coarser than the stage step's pin check" (the new repository comparison narrows it but it is not claimed closed).

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
