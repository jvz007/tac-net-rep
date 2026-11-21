# Tec-Tac Framework 1.18.35

Date: 21 November 2026. You can now upgrade several modules from the online catalog in one run. Core also fixes the transfer end row that a failed call could use up. `main` stays held.

## Module-facing change

`core.tactical_operations` stays at 1.18.0. Everything below is additive. A caller that sends no `purpose` gets the behaviour of 1.18.34. Welcome 1.2.16 is the only module in `modules/` that calls the plan and install routes (body `{modules: [...]}`), and it is unchanged by this release.

**Online plan and install routes** (`POST /api/tfd/modules/catalog/online/plan/`, `.../online/install/`):

- New optional body field `purpose`: `"install"` (default) or `"upgrade"`. Anything else is 400 `bad_request`.
- With `purpose: "upgrade"` the plan blocks a module that is not installed with the new code `not_installed`. It blocks a module installed from another repository with the new code `other_source`. It adds no dependency module, so a missing new dependency is reported by the shared resolver as `missing_dependency`, as a single upgrade does today.
- The plan body, the install answer and the progress body carry `purpose`. Each module in the progress body carries `current_version` (the installed version for a replace, otherwise null). A run file from before this release reads as `install`.
- Every audit row of a run carries `correlation_id` equal to the `run_id`: the start row, each module outcome, the end row, Stop requested, and the licensed-release grant rows of the modules in the run. The start row of an upgrade run reads "Module upgrade run started" and holds `purpose`.

**Remote Background (file transfers):** the failed end row of a transfer has its own once-only key (`tectac:transfer-end-failed:<session id>`). A 400 (bad `sha256`, "not ready to complete") no longer stops the later successful `complete` from writing its `completed` row. A 404 takes no key and writes no end fields. After the success end row exists, a failed call writes no end fields. The capability metadata key `refusal_codes_without_row_added_in_1_18_0` is back as an empty list. These codes now write the limited `core_refused` row (`chunk_refusal_row_codes`).

## Closes

- ORDER "Core next patch, upgrade several modules at once from the online catalog" in `reviews/requests/core.md` (Johan, 21 November 2026). The release manager removes that entry, naming 1.18.35. The matching UI order stays in `ui.md` until the UI release ships.
- The held Medium of the Core 1.18.34 review: a failed end row took the once-only success key (`tactical_operations.py`).
- The held Low of the Core 1.18.34 review: the old metadata key `refusal_codes_without_row_added_in_1_18_0` is restored.

## What changed and why

**Upgrade already worked through the install plan.** An installed module whose licence release is newer is offered by `module_install_plan.offer()` as a `replace` with `current_version`. The run installs one module at a time, reports each module, continues past a failed one and skips only its dependants. So this release adds no route. It adds what the browser needs to upgrade safely:

1. **`purpose` guard** (`module_install_plan.py`, `module_allowed_views.py`, `module_install_run_views.py`). `clean_purpose()` reads the field. `build_plan` gets the keyword `purpose="install"`, so every old positional call and Welcome stay the same. In upgrade mode the plan refuses to install a module that is not installed, so "Upgrade selected" cannot install something new by accident.
2. **`other_source` block.** `plan_online_install` passes the enabled licensing repositories as `licensing_repo_ids`. A module whose recorded source repository is another one is blocked up front, because `stage_repository_package` would refuse it halfway through a run. A module with no recorded repository is not blocked, as the stage step does not refuse it either. `None` skips the check, so old tests pass.
3. **Run changes** (`module_install_run.py`). `start_run` takes `purpose`, passes it to the plan (only when it is not `install`, so a plain `env.plan(selection)` keeps working), stores it in the run file and in the start row. The module record and progress body gain `current_version`.
4. **One correlation id per run.** `write_audit` passes `correlation_id=run["run_id"]` to `audit.record`. The Stop view passes it through a new optional keyword on `_audit_allowed`. `stage_repository_package`, `_stage_licensing_release` and `_licensing_audit` gain the optional keyword `correlation_id=None`, so the grant rows of each module share the run's id. The single online stage route does not pass it and is unchanged. The helper's own job rows are not Core audit rows and are not linked. The live wiring offers a second call, `stage_in_run`, that carries the run id; a plain test env without it still uses `stage`.
5. **Failed end row** (`tactical_operations.py`). New `_failed_end_row_key` and `_failed_end_row_forget`, and a read-only `_end_row_written` (fails open to "not ended"). `_failed_end_fields` returns no fields for a 404 and for a session whose success end row exists, and takes the new key otherwise. The success branch still uses only `_end_row_once`, so a later 2xx `complete` or `cancel` writes its row even after a failed one. 401, 403, 408 and 429 stay excluded.
6. **Metadata key restored** next to `chunk_refusal_row_codes`, value `[]`, with a comment.
7. Docs and contract text: `docs/module-repositories.md`, `docs/tactical-operations.md` and `contracts.py` (both CRLF, kept; `module_repository.py` is CRLF too and kept).

No new trust: still no licence override, no `disable_replaced`, no forced path, no downgrade, no same-version reinstall, no uninstall, enable or disable.

## Assumptions

- **`purpose` field, no new route.** Chosen over a new upgrade route or sending bare installed ids. It keeps Welcome unchanged and lets an upgrade refuse a not-installed id. Recorded in `reviews/questions/core.md`.
- **No dependency modules are added in an upgrade run.** A single upgrade refuses a missing dependency today, and nothing is installed that the person did not tick.
- **A module from an index repository or pinned elsewhere is blocked `other_source`.** The plan and run cover the licensed catalogue only. Use the single Upgrade button for it.
- **The run id is the correlation id.** No second id.
- **A 5xx can still say `failed` for an outcome that was unknown**, as recorded for 1.18.34 (the row action says `custom:outcome-unknown` next to it).
- **Left out:** the third Low of the 1.18.34 review (`read_binary_body` without `params` limits chunk refusal rows per user and operation for two hours). The fix the reviewer prefers is Remote Background passing `params`; that request already stands in `reviews/requests/remote-background.md`.

## Retired or changed checks

- `tests/online-install-run-1.18.20.py`: the pin "the start view reads only `modules` from the body" now allows `modules` and `purpose`. The view still reads no order, version or override.
- `tests/tactical-operation-file-transfer-audit-1.18.34.py` (extended, see below): the shared-key assertions (404 takes the key; a cancel or success after a failed end row writes none) now say the opposite, as the Medium asked. The metadata check expects the old key back as an empty list.
- `tests/tactical-operation-file-transfer-1.18.33.py`: the test cache stub gains `get`.
- `tests/version-1.18.34.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.34.md` moved to `docs/releases/` with a one-line pointer to this release.
- `tests/release-integrity.sh` also runs the three online install tests and the new one.

## New tests

- `tests/online-upgrade-run-1.18.35.py`: `purpose` parsing (bad values raise); an upgrade plan with installed older modules gives `replace` with `current_version`; the default purpose and old positional calls are unchanged; `not_installed`, `other_source` (and the two cases that are not blocked), `already_installed`, `older_than_installed`; a missing new dependency adds nothing and is reported by the resolver while install mode still adds it; a four-module run goes one at a time in plan order, the second fails, the third still runs and the dependant is skipped `dependency_failed`; progress carries `purpose` and `current_version`; the run id is passed with every staged module; Stop ends the rest `skipped`; an old run file reads as install; source checks that the correlation id is forwarded through the stage, grant and audit calls, that the single stage route is unchanged, and that the views, contract and docs carry the text.
- `tests/tactical-operation-file-transfer-audit-1.18.34.py`, extended: a 400 on `complete` then a valid `complete` writes the completed row; a 404 takes no key and writes no end fields; a second failed `complete` writes no second failed end fields; a failed `complete` after a completed one writes none (also for a 5xx); a 5xx carries the failed end fields once; 401, 403, 408 and 429 unchanged; the failed key is freed when the failure row does not record; the old metadata key is an empty list, `chunk_refusal_row_codes` is unchanged and the capability stays 1.18.0.
- `tests/version-1.18.35.py`: release bookkeeping and line endings.

## What could not be run here

Django, Tactical, Redis and `fcntl` are not available on this PC. The views, `FileStore`, the Celery task, the live resolver (`resolve_install_plan`) and the real stage and queue path could not run. The tests use fake collaborators and source-level checks. Dev02 covers the live wiring.

One thing to check on dev02: an installed licensed core module's allowed row must be `selected: true`. If it is not, the plan blocks it `not_selected` and an upgrade of core modules shows as blocked. That is a Licensing allowed-list fact, not a Core change.

## Johan dev02 checklist

You need Core 1.18.35 on dev02 and two or three installed licensed modules with a newer licensed release.

1. Update dev02 to Core 1.18.35 and check the version.
   - PASS: `VERSION` and the package say 1.18.35 and Core starts with no error in the log.
   - FAIL: the update stops or Core does not start. Send the update log.
2. `POST modules/catalog/online/plan/` with `{"modules": [<two upgradable ids>], "purpose": "upgrade"}`.
   - PASS: `order` lists both with `action` replace and `current_version` set, `purpose` is `upgrade`, `valid` is true.
   - FAIL: an id is blocked that you can upgrade today with its own Upgrade button, or `current_version` is empty. Send the body.
3. Plan again with an id that is not installed and `purpose: "upgrade"`.
   - PASS: that id is blocked `not_installed`; the others still plan.
   - FAIL: it is planned as an install. Send the body.
4. Start the run with the same body on `.../online/install/`, then poll the progress route.
   - PASS: one module at a time, each with `current_version`, and a failing module does not stop the others.
   - FAIL: two modules install at once, or one failure ends the run. Send the progress body.
5. Start another run and press Stop while the first module installs.
   - PASS: that module finishes, the rest end `skipped`, status `stopped`.
   - FAIL: a module starts after Stop. Send the progress body.
6. Open the Audit page for the run.
   - PASS: the start row, one row per module, the licensed-release rows and the end row share one correlation id, equal to the run id.
   - FAIL: rows with different ids, or a missing start or end row. Send the rows.
7. Install a fresh module through Welcome.
   - PASS: it installs as before.
   - FAIL: any new error. Send the message and the time.
8. Start a Remote Background upload, send a `complete` with a wrong `sha256`, then a good `complete`.
   - PASS: the audit log holds a failed end row for the first call and a `completed` end row for the second.
   - FAIL: no `completed` row after the good call. Send the rows.

## Exit list

- `purpose` on the plan and install routes, `not_installed`, `other_source`, `current_version`, one correlation id per run, the failed end row key, the restored metadata key, docs, contract text, tests: done.
- Signing, review, dev02 install and a fresh public contract export (still open for 1.18.32 to 1.18.34): not done here. The export is generated on a running server.
- Not done: the third Low of the 1.18.34 review (see Assumptions), the end-of-run notification for an install run, and the other open requests in `reviews/requests/core.md`. None is in this order.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
