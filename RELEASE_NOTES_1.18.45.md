# Tec-Tac Framework 1.18.45

Date: 22 November 2026. Core 1.18.44 does not install, and this release fixes that. Django stopped the install at its start-up check, before any migration ran, with `models.E020`: the field `check` on `TecTacResultCheckItem` shadowed Django's own `Model.check()` method. 1.18.44 never installed anywhere, and 1.18.45 replaces it. Nothing else changes. `main` stays held.

## Module-facing change

None. The field, the column and the constraint are internal to Core. The contract `core.result_checks` 1.0.0, the route `GET /api/tfd/ui/result-checks/<uuid:check_id>/`, the Celery task `tec_tac.run_result_check` and the audit metadata key `check_id` are exactly as in 1.18.44. A search of `modules/` for `TecTacResultCheckItem` finds no user: Script Execution 0.7.1, Patch Management and their stubs only use the `core.result_checks` contract.

## Closes

- `reviews/requests/core.md`, "ORDER Core 1.18.45, fix: Core 1.18.44 does not install (models.E020: TecTacResultCheckItem.check shadows Model.check())".

Nothing else was built. Every other open request in `reviews/requests/core.md` waits, as the order says. That includes the contract-file exports (Report Manager 0.9.1, Endpoint Comms 0.6.20, Script Execution 0.7.1).

## What changed and why

1. **Field renamed.** `TecTacResultCheckItem.check` is now `result_check` (column `result_check_id`). `related_name="items"` and `on_delete=CASCADE` are unchanged. The unique constraint now uses `("result_check", "endpoint_id")` and the index `("result_check", "state")`. Their names, `tectac_rescheckitem_unique` and `tectac_rescheckitem_state_idx`, stay.
2. **Migration 0048 edited in place.** The field name, the constraint and the index follow the model. This is safe because the system check stops every install before `migrate`, so no server ever applied 0048. 1.18.44 was rolled back to 1.18.43 on dev02. A server that did apply it would need a rename migration. None exists.
3. **Lookups renamed.** `check_id=` on the item model became `result_check_id=` in `result_checks.py` (the bulk create, the running-items filter, the two filters at closing, and the "nothing running" test) and in `result_check_views.py` (the summary and the page). The unrelated `check_id` function parameters, the URL kwarg and the audit key are untouched. No behaviour changes.
4. **A test that catches this class of error before signing.** `tests/result-checks-system-check-1.18.45.py` runs two passes. When Django can be imported, it loads the `tec_tac` models under minimal settings and asserts `django.core.checks.run_checks()` returns no error. Always, as a second pass, it reads `models.py` with `ast` and refuses any model field named after a `Model` attribute or method. It also checks that `TecTacResultCheckItem` declares `result_check` and not `check`, and that models.py and migration 0048 agree on the field names, the constraint fields and the index fields. It was run against the old field name and failed with `models.E020`, as it should.

### Plan corrections found in the code

- The plan said Django is not installed on this PC. It is importable from the project's `.venv` (Django 6.1.2), so the real `run_checks()` branch ran here and passed. `manage.py check` and `makemigrations --check --dry-run` still cannot run here, because the project's settings and Tactical's `accounts` app are not available (migration 0038 depends on it).
- `tests/result-checks-1.18.44.py` needed two more edits than the plan listed. Its "no output text field" scan matches the word `result`, so the new field name `result_check` tripped it. The scan now skips that one link field. Its "no hostnames or endpoint ids in the audit row" check looked for the bare text `a2`, which a random check id contains by chance, so it failed about one run in four, with or without this change. It now looks for `'a2'` in quotes, like the line beside it.

## Assumptions

None needs Johan.

- No server has migration 0048 applied, as the order states. 1.18.44 was rolled back on dev02 before `migrate` ran.

## Retired or changed checks

- `tests/version-1.18.44.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.44.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs `result-checks-system-check-1.18.45.py` and `version-1.18.45.py` in place of the retired one.
- `tests/result-checks-1.18.44.py` uses `result_check_id` in its fake item and in its filters, and the field-count check compares against `Item.fields.keys() - {"result_check_id"}`. Its two scan fixes are listed above.

## New tests

- `tests/result-checks-system-check-1.18.45.py`: described above.
- `tests/version-1.18.45.py`: release bookkeeping, LF and CRLF guards, and the rebuild-label guard for 1.18.45.

## What could not be run here

- `manage.py check` and `manage.py makemigrations --check --dry-run`: no project settings and no Tactical `accounts` app on this PC. The new test's `run_checks()` branch did run, with minimal settings, for the `tec_tac` app only. It does not load the migrations, so only dev02 shows whether the models and 0048 agree in Django's own eyes. The AST pass compares them by hand.
- Celery, the real database and the contract-export gate (the contract file for 1.18.45 is made on dev02).

## Johan dev02 checklist

Update dev02 to Core 1.18.45.

1. Run `manage.py check`.
   - PASS: "System check identified no issues (0 silenced)."
   - FAIL: any `models.E020` or other error. Send the output.
2. Update dev02 to 1.18.45 through the normal installer.
   - PASS: the install finishes, and migration `0048_result_checks` applies.
   - FAIL: the install stops or rolls back. Send the installer log.
3. Run `manage.py makemigrations --check --dry-run`, then `manage.py showmigrations tec_tac`.
   - PASS: no changes detected, and `0048_result_checks` is applied.
   - FAIL: Django wants to create a migration, or 0048 is not applied. Send the output.
4. Restart the Celery worker, then open `/api/tfd/capabilities/`.
   - PASS: `core.result_checks` 1.0.0 is listed and healthy.
   - FAIL: it is missing. Send the Core log lines around start-up.
5. Open `/api/tfd/ui/result-checks/00000000-0000-0000-0000-000000000000/` while signed in.
   - PASS: you get `404` with `{"detail": "Not found."}`.
   - FAIL: any other answer, such as a 500. Send the body.
6. Run the Scheduler tick once and read its output line.
   - PASS: the line has the same fields as before, and `journalctl` shows no "result check" warning.
   - FAIL: the line changed, or the tick shows a result-check warning. Send the line and the log.

The full click path (a bulk run, the bell notice, the results page) is steps 5 to 7 of the 1.18.44 checklist in `docs/releases/RELEASE_NOTES_1.18.44.md`. Run it once Script Execution 0.7.1 and UI 0.13.4 are installed.

## Exit list

- Version 1.18.45, no rebuild label. No new migration (0048 edited in place). No root-helper, `install.sh` or sudoers change.
- Release manager: remove the ORDER "Core 1.18.45, fix: Core 1.18.44 does not install" from `reviews/requests/core.md`, naming 1.18.45. Run `manage.py check` and `makemigrations --check --dry-run` on dev02 and export the contract file for 1.18.45 there.
- Left out on purpose: every other open Core request and the held review findings.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
