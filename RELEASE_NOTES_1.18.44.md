# Tec-Tac Framework 1.18.44

Date: 22 November 2026. A module can now follow a bulk run after the person closes the tab. When the results are in, Core tells that person once, in the bell, and the link opens one row per endpoint with its state and exit code. This is the Core half of B2 (`core.result_checks` 1.0.0). Script Execution 0.7.1 and UI 0.13.4 adopt it next. `main` stays held.

## Module-facing change

- **New capability and contract (additive): `core.result_checks` 1.0.0.** `tec_tac.result_checks.register_reader(*, id, module_id, reader)` from `AppConfig.ready()`, and `tec_tac.result_checks.start(user, *, reader_id, label, endpoint_ids, job_ref, deadline_seconds)`. Only the module that owns the reader may call `start`; Core, an unverified caller and another module get `ResultCheckRefused`. The reader runs as the person, once a minute, in a Celery worker, for at most 500 endpoints. It must be idempotent and read-only.
- **New route (additive): `GET /api/tfd/ui/result-checks/<uuid:check_id>/`**, paged (`page`, `page_size` up to 100). The person who started the check only. Everyone else gets the same 404.
- **New Celery task `tec_tac.run_result_check`.** Restart the Celery worker after the update so it knows the task.
- **New migration `0048_result_checks`:** two tables.
- Nothing existing changes. Users found in `modules/` and `workspace/ui`: none (a search for `result_checks`, `result-checks` and `/results/` finds only an unrelated check-results test in `modules/patchmanagement`). Script Execution 0.7.1 (framework >=1.18.44) and UI 0.13.4 are the planned adopters; their orders already exist in `reviews/requests/`.

## Closes

- `reviews/requests/core.md`, "ORDER: Core 1.18.44, `core.result_checks` 1.0.0 (B2)", parts 1, 2 and 3. Plan: `reviews/plans-21-11-2026/B2-result-checks.md`, release 1.

Nothing else was built. The held Medium and Low findings of the 1.18.43 and 1.18.42 reviews stay open, and so does every other open request in `reviews/requests/core.md`, as the order says.

## What changed and why

You start a bulk script on 40 endpoints and close the tab. Before, nothing told you how it went. Now the module that started the run asks Core to follow it.

1. **The engine (`result_checks.py`).** `register_reader` checks the module is installed, enabled and not legacy, and that the reader's code lies in the module's own folder (the same checks as event jobs). Registering the same definition twice is fine; a different one is refused. `start` verifies the caller by the frame walk (rule 1.10, AD-26), the person (active, not an installer or agent account, not blocked from the dashboard), and every limit: label 1 to 80 printable characters, 1 to 1000 unique endpoint ids of at most 200 characters, `job_ref` a JSON object of at most 2 KiB, `deadline_seconds` 60 to 86400. At most 20 open checks per person, counted under a row lock on the user, so two parallel starts cannot pass the cap. A refusal from a wrong caller writes at most one audit row `custom:result-check-refused` per module and reason every 5 minutes (reason code only).
2. **Two tables, no output text.** `TecTacResultCheck` and `TecTacResultCheckItem` (endpoint id, hostname, state, exit code, check time). States: running, done, failed, offline, no_result. A test asserts no output field exists on either model.
3. **One pass (`run_check`).** The row is claimed with an atomic filtered update on a lease, so a duplicate delivery runs nothing twice. The starter is loaded fresh from the database; if they are now inactive or blocked, the check closes with no notice and one audit row. The reader is called once, as the starter, with a copy of `job_ref` and at most 500 running endpoint ids: never-checked first, then the ones checked longest ago, so a 1000-endpoint check rotates and none starves. The answer is checked strictly. Anything else leaves the item running. A reader that raises, or a module that is gone or disabled, leaves items running and the next minute tries again. No trusted global read is added.
4. **Closing.** The check closes when nothing is running or at the deadline (running items become no_result). A filtered update decides the winner, so exactly one call sends the one notice (`<label>: N done, M failed, K offline[, L no result]`, level success when everything is done, else warning, link `/results/<id>`) and writes one audit row `custom:result-check-closed` (counts, check id and reader id; never hostnames or endpoint ids).
5. **The tick step and the task.** The Scheduler tick calls `queue_due_checks`: at most 20 due open checks, each claimed with a 5 minute lease and sent through one bounded broker attempt. A broker failure clears the lease and stops the loop. The tick never calls a reader or any module code. The Celery task `tec_tac.run_result_check` (`acks_late`, soft limit 100 s, hard limit 120 s) calls `run_check`. The same step deletes closed checks older than 30 days, at most 200 a tick. The tick's own output line is unchanged.
6. **The read route.** `ResultCheckView` is session-guarded. A missing id, another person's check (a superuser included), a check past retention and an inactive person all answer the same `404 {"detail": "Not found."}`. A success body uses `message`, never `detail` or `error`, and holds no output text, job reference, reader id or module id.
7. **Contract, docs, OpenAPI.** Three `CORE_CONTRACTS` rows, one `HTTP_CONTRACT_DETAILS` entry and one `RULES` sentence in `contracts.py` (CRLF kept), `docs/result-checks.md`, one line in `docs/capabilities.md`, and the view in the OpenAPI group "Tec-Tac · UI Runtime".

### Plan corrections found in the code

- The plan said the migration depends only on 0047. The check links to the user, so it also carries the standard `migrations.swappable_dependency(settings.AUTH_USER_MODEL)`, as `0039_run_started_by.py` does. It adds no floating dependency.
- The plan listed an anonymous caller among the 404 cases. DRF's session guard answers an anonymous caller before the view runs, with the same refusal for every id, so existence is still not revealed. The view also answers 404 if it is ever reached anonymously, and the test covers that.
- The plan called `_norm` and `_under` from `event_jobs`. `result_checks.py` uses the identical helpers in `caller_identity`, which is already imported for the caller check and loads no models.
- Ordering "never-checked first" uses two small queries instead of `ORDER BY checked_at NULLS FIRST`, because PostgreSQL sorts nulls last on ascending order and the test stub cannot model `F()`.

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- Above 500 endpoints the 500 checked longest ago are read first, so all 1000 rotate.
- `offline` is final. An endpoint that comes back later is not followed. Dev02 checks this in Johan's test.
- The reader's hostname (at most 255 characters) is stored on the item, so the page needs no second Tactical read. It is deleted with the check after 30 days and only the starter can read it.
- The starter can still read a check after their scope shrinks. They see the hostnames and states they already received. No later scope re-check is made on stored rows.
- The notice goes to the starter only, with the dedupe key `result-check:<id>`.
- A closing notice that cannot be stored is logged, not retried. The check is still closed and the page still works.

## Retired or changed checks

- `tests/version-1.18.43.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.43.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs `result-checks-1.18.44.py` and `version-1.18.44.py` in place of the retired one.

## New tests

- `tests/result-checks-1.18.44.py`: the real `result_checks.py`, `result_check_views.py` and `caller_identity.py` against an in-memory ORM and stubs, with module code compiled under a temporary extensions folder. Registration (once, identical again, different refused, code outside the folder, disabled, legacy, generated), the caller rule (owner, another module, Core, unverified, disabled, unknown reader) and its throttled audit row, every validation limit, the 20 open cap, the reader called once as the starter with at most 500 ids, rotation of 1000 endpoints, strict answer handling, closing, the deadline, exactly one notice, a duplicate delivery, an inactive starter, the tick step (20 of 25, live lease, lapsed lease, broker down), retention with its 200 cap, source checks on the task, the tick and the models, and the read route (paging, identical 404, no secrets in the body, retention), plus `contracts.py` parsed with `ast`.
- `tests/version-1.18.44.py`: release bookkeeping.

## What could not be run here

Django, Celery, the database and the migration cannot run on this PC. The tests use stubs, and the migration is written by hand. The release manager runs `manage.py makemigrations --check --dry-run` on dev02: the models and `0048_result_checks.py` must agree. The exported contract file for 1.18.44 is made on dev02, so the contract-export gate reports "not run" here.

## Johan dev02 checklist

Update dev02 to Core 1.18.44 first. Migration 0048 applies. Restart the Celery worker so it knows the new task. The click path needs Script Execution 0.7.1 and UI 0.13.4, so steps 1 to 4 check Core on its own. Steps 5 to 7 are the full click path once those two are installed.

1. Run `manage.py makemigrations --check --dry-run`, then `manage.py showmigrations tec_tac`.
   - PASS: no changes detected, and `0048_result_checks` is applied.
   - FAIL: Django wants to create a migration, or 0048 is not applied. Send the output.
2. Run the Scheduler tick once and read its output line.
   - PASS: the line has the same fields as before, and `journalctl` shows no "result check" warning.
   - FAIL: the line changed or the tick shows a result-check warning. Send the line and the log.
3. Open `/api/tfd/ui/result-checks/00000000-0000-0000-0000-000000000000/` while signed in.
   - PASS: you get `404` with `{"detail": "Not found."}`.
   - FAIL: any other answer. Send the body.
4. Open `/api/tfd/capabilities/`.
   - PASS: `core.result_checks` 1.0.0 is listed and healthy.
   - FAIL: it is missing. Send the Core log lines around start-up.
5. With Script Execution 0.7.1 and UI 0.13.4 installed: select about 40 endpoints, switch one off, choose "one off", run a quick script and close the tab.
   - PASS: within the script timeout plus about 2 minutes the bell shows "Run script: N done, M failed, 1 offline". Opening it shows one row per endpoint with state and exit code, and no output text.
   - FAIL: no notice after 5 minutes, a wrong count, or output text on the page. Send the check id and the `journalctl` lines.
6. Open the same link as another technician.
   - PASS: "not found".
   - FAIL: you see the rows. Send the username pair.
7. Check the offline endpoint and a script that timed out.
   - PASS: the offline endpoint is counted offline and the timed-out script has the exit code Tactical reports, shown as failed.
   - FAIL: the offline endpoint stays running until the deadline, or a timeout counts as done. Send the rows. This is the behaviour the plan says dev02 settles.

## Exit list

- Version 1.18.44, no rebuild label. One migration (`0048_result_checks`). No root-helper, `install.sh` or sudoers change.
- New capability `core.result_checks` 1.0.0, route `ui/result-checks/<uuid:check_id>/`, Celery task `tec_tac.run_result_check`, tick step `queue_due_checks`.
- Release manager: remove the ORDER "Core 1.18.44, `core.result_checks` 1.0.0 (B2)" from `reviews/requests/core.md`, naming 1.18.44. The Script Execution 0.7.1 and UI 0.13.4 orders stay open. Run `makemigrations --check --dry-run` on dev02 and export the contract file for 1.18.44 there.
- Left out on purpose: every other open Core request (the contract-file exports for 1.18.38 and 1.18.41, the securityWAF nginx request and older ones), the held findings of the 1.18.41 to 1.18.43 reviews, every module adopter, and a start rate limit or superuser view of other people's checks.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
