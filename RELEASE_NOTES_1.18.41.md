# Tec-Tac Framework 1.18.41

Date: 22 November 2026. A scheduled report can now read server-wide data (for example a SentinelOne posture snapshot) only when the person who last saved the schedule is a superuser. Core checks this on every run. When the check fails, the person reads a plain message in the report history and never gets an empty report. This is Core's half of CQ93 option 2. `main` stays held.

## Module-facing change

Additive. No existing operation, signature or route changes. One new public Python entry point in the reporting contract, plus a stricter rule for models that declared `scoped_report_manager(server_wide=True)`.

- **New: `tec_tac.reporting.schedule_run(owner_username)`** (requires framework >=1.18.41). A context manager that marks the code inside it as one scheduled report run and yields `owner_ok`. Core looks the owner up by exact username and checks `is_effective_superuser` at that moment. It never raises by itself, so a report with no server-wide model still runs for a demoted owner. Only Report Manager is expected to call it.
- **New: `tec_tac.reporting.ScheduledReportRefused`**, a `PermissionError` carrying: *A scheduled report may show server-wide data only when the person who last saved the schedule is a superuser.* Tactical's `run_report` stores any exception text as the error of the report history.
- **Changed for `server_wide=True` models only:** `Model.objects.using(alias)` raises `ScheduledReportRefused` outside `schedule_run`, and inside it when the owner is not an effective superuser. Inside a run, `filter_by_role` is decided by the owner alone (the person who clicked Run now is ignored).
- **Unchanged:** client and site scoped managers, pathless managers, on-screen runs (a superuser still sees every server-wide row, anyone else none, no raise), `model_row_scope` (`enforced` true, `server_wide` true) and the `scoped_report_manager` signature.
- Users found in `modules/`: `sentinelone` is the only module that declares `scoped_report_manager(server_wide=True)` in non-test code (`SentinelOnePostureSnapshot`). No module calls `Manager.using()` on a server-wide model. `objects.create` and `bulk_create` do not go through `Manager.using`, so SentinelOne's sync is unaffected. Report Manager does not call `schedule_run` yet.
- **Until Report Manager ships its wrapper, a scheduled server-wide report fails with the plain message.** It fails closed and is never empty. Nothing existing relies on it: SentinelOne retired its posture report in 0.5.4.

## Closes

- `reviews/requests/core.md`, "ORDER: Core next patch, CQ93 option 2 (week plan 3c, AD-76, Johan 22 November 2026)", Core part only. Plan: `reviews/plans-21-11-2026/3c-CQ93-option-2.md`.
- AD-76 (Johan, 22 November 2026). Recipients are not limited ("yes drop it ..."). The editors of the template or saved query are not checked (option b).

## What changed and why

1. **`schedule_run` and a context variable** in `framwork/tec_tac/reporting.py`. The state is `None` outside a run and `{"owner_ok": bool}` inside. It is always reset in a `finally` block, also after an exception. A nested run restores the outer state. An empty, None, non-string or unknown username and any lookup or rbac error mean the owner is not OK.
2. **`_server_wide_queryset`.** Inside a run the owner alone decides: OK returns the queryset, not OK raises. Outside a run it is exactly as in 1.17.30 and never raises.
3. **`ScopedReportManager.using(alias)`.** Tactical's scheduler passes no user and reads `Model.objects.using('default')`. When `filter_by_role` raises, Tactical swallows the error and falls back to the same call (`ee/reporting/utils.py`, `build_queryset`). Raising from `filter_by_role` alone would not stop the run. Raising from `using()` does. It applies only when `server_wide` is true.
4. **Contract and docs.** `contracts.py` has a new `schedule_run` row and a "Since 1.18.41" sentence on `scoped_report_manager`. The statements that a user-less scheduled run is unscoped and that Core cannot scope it are removed for server-wide models. They stay for client and site scoped models, which are unchanged. `docs/module-reporting.md` replaces the "Johan has been asked (CQ93)" text and the Limits line with the AD-76 rule. The words "no signed-in user" and "unscoped" stay in the server-wide section, which `tests/reporting-server-wide-scope-1.17.30.py` asserts.
5. **Plan correction.** The plan said `reporting.py`, `contracts.py` and the docs have no CR. They are CRLF in the index and the working tree. The edits keep CRLF. `release-integrity.sh` and the tests are LF. `tests/version-1.18.41.py` now asserts CRLF for the three CRLF files.

## Assumptions

Recorded as information in `reviews/questions/core.md`.

- **The owner alone decides inside a run.** A non-superuser who clicks Run now on a superuser's schedule gets the rows, because the editor of the schedule chose the recipients (AD-76). A superuser who clicks Run now on a non-superuser's schedule is refused. The clicker cannot widen access.
- **`using()` on a server-wide model raises outside a run.** Any code that calls it for such a model outside `schedule_run` is refused. No module does today.
- **No migration.** Nothing in the database changes.

## Retired or changed checks

- `tests/version-1.18.40.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.40.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` runs the two new tests and no longer runs the retired version test.
- `tests/reporting-server-wide-scope-1.17.30.py` is unchanged and still passes.

## New tests

- `tests/reporting-schedule-run-1.18.41.py`, on the fake Django harness of `tests/reporting-row-scope-1.17.4.py` with the real `is_effective_superuser`:
  - `using()` raises the plain message outside a run.
  - A Django superuser owner and a role superuser owner pass `using()` and `filter_by_role`.
  - A plain user, scoped role, no role, inactive user, unknown username, None, empty name, blank name, non-string name and a failing role cache each fail with the message.
  - A lookup error and a raising rbac fail closed. `schedule_run` never raises.
  - Run now: the owner decides, the clicker is ignored in both directions.
  - Tactical's fallback path is refused for a failing owner and passes for a good one.
  - The variable is `None` after a normal exit, after an exception and after nested runs.
  - Scoped and pathless managers and on-screen runs are unchanged. `model_row_scope` is unchanged.
  - The contract row, the docs and these notes.
- `tests/version-1.18.41.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. The tests ran the real `reporting.py` against fake Django, users, roles and models. These run only on dev02: Tactical's real `run_report` and `run_scheduled_report`, the real user table lookup, the real manager `using()` and the Celery schedule runner. No migration is involved.

## Johan dev02 checklist

Update dev02 to Core 1.18.41 first. Steps 3 and 4 need a Report Manager that wraps `run_scheduled_report` in `schedule_run`. That release is a separate request (`reviews/requests/reportmanager.md`). Until it ships, do steps 1, 2 and 5 only.

1. Open a report on a scoped model (for example Agents) on screen as a non-superuser, then schedule it and use Run now.
   - PASS: the report runs and shows the same rows as before this release.
   - FAIL: an error or a missing row. Send the report history entry.
2. Open a server-wide report on screen as a superuser (needs a module that registers one, for example SentinelOne once it returns).
   - PASS: every row shows. A non-superuser sees none.
   - FAIL: a non-superuser sees rows, or the superuser sees none.
3. With Report Manager's wrapper installed, save a schedule on a server-wide report as a superuser and press Run now.
   - PASS: the run succeeds and the report history shows the rows.
   - FAIL: the plain message appears for a superuser owner.
4. Demote that owner (or save the schedule as a non-superuser) and press Run now as a superuser.
   - PASS: the run fails with "A scheduled report may show server-wide data only when the person who last saved the schedule is a superuser." and the history has no empty report.
   - FAIL: rows are returned, or the history entry is empty.
5. Before Report Manager's wrapper exists, run a scheduled server-wide report.
   - PASS: it fails with the same plain message.
   - FAIL: it returns rows.

## Exit list

- Version 1.18.41, no rebuild label. No migration.
- `tec_tac.reporting.schedule_run` and `ScheduledReportRefused` added; server-wide `using()` guarded; contract row and docs updated (CQ93, AD-76).
- Release manager: close the "ORDER: Core next patch, CQ93 option 2" entry of `reviews/requests/core.md`, naming 1.18.41. Report Manager (`reportmanager`) and SentinelOne (`sentinelone`) parts are open in their own request files. The backups question can be answered once this ships.
- Left out on purpose: recipient limiting, a template or saved-query editor check, public-contract file regeneration, every other open Core request.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
