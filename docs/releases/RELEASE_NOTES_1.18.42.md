# Tec-Tac Framework 1.18.42

Date: 22 November 2026. "Upgrade selected" in the online catalogue can now follow the same path as the single Upgrade for every selected module. Core stages all selected modules as one batch, and the existing batch install runs them as one job. This release also removes the separate bulk-upgrade run, and it fixes the module install helper so a job survives the Celery restart that every install ends with. `main` stays held.

## Module-facing change

- **New route (additive): `POST /api/tfd/modules/catalog/online/stage/batch/`.** Body `{"items": [{"repository_id", "module_id", "version"}, ...]}`, 1 to 50 items. Answers 201 with one batch (`kind` `batch`, `upload_id`, `created_at`, `artifacts`, `packages`, `plan`), the same shape `stage_multiple_packages` gives. The old single stage route and its contract text are unchanged.
- **Removed: purpose `upgrade` on `POST modules/catalog/online/plan/` and `POST modules/catalog/online/install/`.** Both routes now take only `install` (or no `purpose`). Anything else, including `upgrade`, answers 400 `purpose must be "install"`. The body of the plan and the run still carries `purpose` with the value `install`, so a reader sees no change. In `modules/`, only Welcome (1.2.x, `register.js` and `test_welcome_1_2_16_install.py`) calls these routes, and it sends no purpose. The plan codes `not_installed` and `other_source` are gone with the purpose.
- **Changed internally: the module helper's `--dispatch`.** No route, capability or sudoers line changes. No module calls the helper directly.
- Users found in `modules/`: no module calls `stage_repository_package`, `stage_multiple_packages`, `module_install_run`, `module_install_plan` or the helper dispatch outside Welcome's two routes above.

## Closes

- `reviews/requests/core.md`, "ORDER: Core patch after the 3c patch, Upgrade selected = the single Upgrade for every selected module (Johan, 22 November 2026)", parts 1, 2 and 3.
- The matching UI order (`reviews/requests/ui.md`, "ORDER: UI patch after the matching Core") waits on this release.

## What changed and why

Johan found that the bulk upgrade from the online catalogue stuck on the first module. The cause was the helper, not the plan.

1. **Batch stage route.** `module_repository.stage_online_batch(items, request)` calls `stage_repository_package` once per item, unchanged: the same checks, strict licence audit row, grant, SHA-256, publisher signature, identity check and pinned-repository rule, and no source change. It then writes one batch through two helpers taken out of `stage_multiple_packages` (`_flatten_staged` and `_write_batch` in `module_manager_v2.py`). `stage_multiple_packages` calls the same helpers and behaves as before. The answer is always a batch, also for one item, so the UI treats it uniformly. A plan problem is in `plan.valid` and `plan.problems`, not an error.
2. **Any refusal discards everything.** `ModuleRepositoryError`, `ModuleManagerError` and `ModuleManagerV2Error` (including `LicensingRequirementError`) discard every package already staged and answer 400 with `<module id>: <Core sentence>`. Any other exception discards, then re-raises. No licence override is accepted: `licence_override_reason`, `license_override_reason` and `disable_replaced` answer 400.
3. **Time limit (performance).** A deadline of 240 seconds is checked before each item. Past it, everything is discarded and Core answers "The batch took too long to download. Select fewer modules." A request never holds a web worker for minutes.
4. **Purpose `upgrade` removed.** `module_install_plan.py` (`PURPOSES`, `clean_purpose`, the upgrade branch of `build_plan`, `upgrade_release`, `licensing_repo_ids`, the two upgrade-only texts), `module_install_run.py` (`_recheck_upgrade`, the upgrade branch of `_advance`, the live `upgrade_release` wiring, the "Module upgrade run started" text), both views, and `module_repository.upgrade_selector()` are gone. `select_release` stays because `online_catalog` uses it. A run file written by 1.18.35 to 1.18.41 with purpose `upgrade` still reads and shows `upgrade`. Welcome's install run is unchanged.
5. **Helper dispatch survives a Celery restart.** `dispatch()` started the root worker with `Popen(start_new_session=True)` from a sudo call that came out of the Celery worker. The worker stayed in `celery.service`'s cgroup, and the job's own `systemctl restart celery` killed it. The job then stayed on `running / runtime-sync` for ever. `dispatch()` now starts the worker as a transient unit (`systemd-run --quiet --collect --unit=tec-tac-module-v2-job-<job id> --property=Type=exec`), as `system-update-helper.py` and `server-backup-helper.py` already do. If systemd-run fails, the job is marked failed (stage `dispatch`, `DispatchError`), the claimed inputs are removed and the helper exits with the message. There is no fallback to the old start. The helper already runs as root and already calls systemctl, so there is no new sudo line and no new right.
6. **Contract and docs.** `contracts.py` has the new route entry and no longer offers `upgrade` on the plan, install and progress routes. `docs/module-repositories.md` has the matching rows.
7. **Plan correction.** The plan listed `module_install_plan.py`, `module_install_run.py` and both install views as LF, and `module_repository_views.py` and `urls.py` as LF. That is right (checked with `git ls-files --eol`). `_flatten_staged` takes the `artifacts` and `flattened` lists and fills them, instead of returning a value, so a bundle with no packages still leaves its upload in `artifacts` to be discarded, exactly as before.

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- **One batch request is capped at 50 modules and 240 seconds.** The single Upgrade is unchanged.
- **Purpose `upgrade` answers 400** (fail closed) rather than being treated as install. The dev UI's bulk upgrade stops working until the matching UI patch ships. It was stuck anyway. A run file on disk with purpose `upgrade` is checked against the allowed list from now on. No such run survives the Celery restart of this update.
- **The helper may use systemd-run.** It needs no wider right than it has.
- **A job already stuck on dev02 before this update is not repaired.** The fix covers new dispatches only. Clear it by hand or let the 15-minute stale rule end its run.

## Retired or changed checks

- `tests/version-1.18.41.py`, `tests/online-upgrade-run-1.18.35.py` and `tests/online-upgrade-release-1.18.38.py` moved to `tests/legacy/`. The two upgrade tests asserted the removed purpose. Their `select_release` cases moved into the new test, so that behaviour stays pinned.
- `RELEASE_NOTES_1.18.41.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs the three new tests and no longer runs the retired ones.
- `tests/reporting-schedule-run-1.18.41.py` now reads the 1.18.41 release notes from `docs/releases/` when they are no longer in the root. Nothing else in it changed.
- `online-install-plan-1.18.19.py`, `online-install-run-1.18.20.py` and `online-install-chain-1.18.21.py` are unchanged and still pass.

## New tests

- `tests/online-upgrade-batch-1.18.42.py`: `stage_online_batch` with fake collaborators (arguments passed per item, one batch for three items, a bundle item flattened, one item still a batch, refusal and licence refusal discarding the first item, a failing write discarding all, the 240 second deadline on a fake clock), body validation, the shared helpers against `stage_multiple_packages`, source-level wiring (urls, view permission, contract, docs), purpose `upgrade` refused and gone from the source, Welcome's run path unchanged, the `select_release` cases, and line endings.
- `tests/module-dispatch-unit-1.18.42.py`: `dispatch()` run from its source with fake collaborators. The command, the failure path, no `Popen`, and the unchanged sudoers line.
- `tests/version-1.18.42.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC, and it has no systemd and no root. These ran as source extraction with fakes. These run only on dev02: the views, the real `stage_repository_package` and download, the real batch install queue, the Celery restart, and `systemd-run` in the helper. No migration is involved.

## Johan dev02 checklist

Update dev02 to Core 1.18.42 first. Steps 1 and 2 need the matching UI patch. Without it, test the route from the browser console or skip to steps 3 to 5.

1. In the online catalogue, select several upgradable modules and press Upgrade selected, then accept the install.
   - PASS: Core lists every selected module in one batch before the install starts, and the batch installs to the end.
   - FAIL: the batch stops on the first module or never lists them all. Send the job log and the audit rows.
2. Select one module that cannot be staged (for example a retired repository) together with a good one.
   - PASS: nothing is staged, and you read "<module id>: <sentence>". The staged folder holds no new package.
   - FAIL: the good module stays staged, or the sentence has no module id.
3. After a batch install, check the job and Celery.
   - PASS: Celery restarts, and the job ends `succeeded`. It never stays on `running / runtime-sync`.
   - FAIL: the job stays on `running / runtime-sync`. Send `journalctl -u celery` and `systemctl status tec-tac-module-v2-job-<job id>`.
4. Run a Welcome install of a licensed module.
   - PASS: the install run completes as before.
   - FAIL: the run stalls or the plan answers 400. Send the progress body.
5. Send `POST /api/tfd/modules/catalog/online/plan/` with `{"modules": ["x"], "purpose": "upgrade"}`.
   - PASS: Core answers 400 `purpose must be "install"`.
   - FAIL: Core answers 200 with a plan.

## Exit list

- Version 1.18.42, no rebuild label. No migration.
- New route `modules/catalog/online/stage/batch/`; purpose `upgrade` removed from the plan and install routes; the helper dispatch uses a transient systemd unit.
- Release manager: close the ORDER "Core patch after the 3c patch, Upgrade selected" in `reviews/requests/core.md`, naming 1.18.42. The UI order in `reviews/requests/ui.md` can start after this release is signed.
- Left out on purpose: every other open Core request, every held finding, the same Popen start in the other helpers (`module-job-helper.py`, the module hotfix helper; no known failure), repair of a job already stuck on dev02, and the public-contract file for 1.18.27 or newer.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
