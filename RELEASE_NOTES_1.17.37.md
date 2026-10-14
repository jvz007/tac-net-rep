# Tec-Tac Framework 1.17.37

Date: 14 October 2026.

This patch release closes three items of the Core 1.17.37 plan. The Tactical UI probe that failed on the dev server was a fault in the probe, not in Core, and it is fixed. The browser contract export gets the row for module preferences. The four Python functions of `core.module_preferences` now check which module is calling, so one module cannot read or change another module's preferences (AD-26, CQ110 option a).

## Module-facing changes

- **`core.module_preferences` 1.1.0 (tightening).** The Python functions `get`, `set`, `delete` and `list_for` now verify the calling module. A call may use only the module named in `module_id`. Any other caller is refused with `caller_not_allowed` (status 403) before any name, value or row is read or written. Core is never a caller, so a call from Core code, a library, a generated frame, a disabled module or a legacy module is refused too. Requires `tec-tac-framework >=1.17.37`. No module in `modules/` uses these functions (checked by grep), so nothing breaks. The browser route is unchanged: the path id is still a claim, because the browser cannot prove who is calling (CQ109 a is still open).
- **Browser contract row `ui.authenticated.modulePreferences` (documentation only).** It lists `get`, `getAll`, `set` and `remove` for `context.modulePreferences` (UI 0.12.106). It needs Core 1.17.35 or later and UI 0.12.106 or later. No value a module consumes changes.

## What changed and why

1. **Tactical UI probe fixed (`tests/tactical-ui-preferences-runtime-1.17.37.py`, renamed from the 1.17.35 name).** The hot-path step asserted `date_format == 'YYYY-MM-DD HH:mm'`, a value set by an earlier step. The empty-date step before it cleared that value in the same transaction, so the probe failed on the scalar, not on a missing key. The hot-path step now sets its own known state first, re-reads the stored row, checks every name in `TACTICAL_UI_SCALAR_FIELDS` against it, and checks the exact key set. Core behaviour does not change: `account_self_service.py` is not touched.
2. **Browser contract row (`contracts.py`, `docs/module-preferences.md`).** The row `ui.authenticated.modulePreferences` sits after `ui.authenticated.terminal`. The terminal row (1.17.35) and the server-terminal facts of the websocket row (1.17.35) were checked and are still present.
3. **Verified caller for `core.module_preferences` (`module_preferences.py`, AD-26, CQ110 option a).** The public functions call Core's private caller check (`calling_module_for_core_provider`, the same check `core.accounts` uses under AD-31) and then call the private functions `_get`, `_set`, `_delete` and `_list_for`, which hold the logic as before (name and value checks, the 4 KiB and 5 level limits, the 50 names limit, the transaction). The browser views (`module_preference_views.py`) call the private functions with the path id, so the routes, bodies, status codes and the write throttle are unchanged. Capability `core.module_preferences` moves from 1.0.0 to 1.1.0, with `requires_framework >=1.17.37` and a `caller` note in its metadata. The Python rows and the rule text in `contracts.py` say the same. `docs/module-preferences.md` now describes the verified caller and the known limit (AD-26 condition 4). The `user` argument stays the caller's responsibility: a module can pass any user for its own id, but it can never reach another module's rows.
4. **Tests.** New: `tests/tactical-ui-preferences-probe-1.17.37.py` (runs the real probe end to end with stubs, and a negative control with the 1.17.35 step order that fails with "the scalars are published"), `tests/browser-contract-rows-1.17.37.py` (the new row, the renderers, and the terminal and websocket rows), and `tests/module-preferences-caller-1.17.37.py` (the verified caller for all four functions, every refusal case with no row read or written, the refusal coming before name and value checks, the views on the private path, and the capability and contract text). Changed: `tests/browser-contract-catalog-1.15.170.py` (the pinned id set gets the new row); `tests/module-preferences-1.17.35.py` (calls the private functions, which the test frame needs, and pins 1.1.0 and 1.17.37; the limit, name and cascade assertions are unchanged); `tests/module-preferences-runtime-1.17.35.py` (calls the private functions, because `manage.py shell` is not an installed module).
5. **Release notes location.** `RELEASE_NOTES_1.17.36.md` moved to `docs/releases/`, because `tests/release-integrity.sh` allows exactly one root note.

## Closes

- `reviews/requests/core.md`: "Module user preferences: the browser contract row `ui.authenticated.modulePreferences` (UI 0.12.106)". Its section is removed, and 1.17.37 is named in the shipped list.
- The held Medium from the 1.17.35 review, "Python contract takes any user and any module id with no verified caller" (CQ110). Option (a) is applied. The browser route stays a claim (CQ109 a).

## Not in this release

- The browser route of `core.module_preferences` is still not verified, because the browser names the module id. CQ109 a is open.
- The `tactical_ui` row of `GET /api/tfd/account/` still says "plus allowed choices". That answer does carry the choice lists, so the wording is right and is unchanged. The runtime context row (hot path) already says it has no choice lists.
- Sign-off of the verified caller as an accepted decision (AD-36) is asked in `reviews/questions/core.md` as CQ111. No AD entry is written until Johan signs it. The hot-path choice lists question is CQ112 (assumption: scalars only).
- Module migration drift (`makemigrations tec_tac --check --dry-run` prints "Migrations for" for licensing, notifications, sentinelone, softwarerepository and wau). These are module work and are routed to `reviews/requests/core-modules.md` and `reviews/requests/premium-modules.md`. The tec_tac package itself is clean.
- The Core requests left open, unchanged: the audit row for an export by a person with only Tactical's List checks flag (a security trade-off for Johan, AD-12), and the two terminal socket entries (waiting on a real browser test on the dev server).

## Dev server

`reviews/questions/core.md`, "Note (14 October 2026), Core 1.17.37", has the steps and the full commands. The probes are `tests/tactical-ui-preferences-runtime-1.17.37.py` and `tests/module-preferences-runtime-1.17.35.py` (both roll back). There is no database change and no migration.

## Tests

Added: `tests/tactical-ui-preferences-probe-1.17.37.py`, `tests/browser-contract-rows-1.17.37.py`, `tests/module-preferences-caller-1.17.37.py`. Changed: `tests/browser-contract-catalog-1.15.170.py`, `tests/module-preferences-1.17.35.py`, `tests/module-preferences-runtime-1.17.35.py`, `tests/tactical-ui-preferences-runtime-1.17.37.py` (renamed and fixed).

## Checks run on this PC

- `bash tests/release-integrity.sh`: passes. This PC's `python3` is the Windows Store alias, so the run used a shim that calls the same Python 3.12, as for 1.17.36.
- The new and touched tests, all pass: `tests/tactical-ui-preferences-probe-1.17.37.py`, `tests/browser-contract-rows-1.17.37.py`, `tests/module-preferences-caller-1.17.37.py`, `tests/module-preferences-1.17.35.py`, `tests/tactical-ui-preferences-1.17.35.py`, `tests/browser-contract-catalog-1.15.170.py`, `tests/browser-contract-rows-1.17.35.py`, `tests/browser-contract-rows-1.17.33.py`, `tests/browser-contract-rows-1.17.32.py`, `tests/contract-export-ui-pin-1.17.35.py`, `tests/caller-identity-core-provider-1.17.27.py`, `tests/f4-core-ui-context-1.15.178.py` and `tests/migration-model-id-agreement-1.17.36.py`.
- Every test file in `tests/` was run on this PC and on a clean export of the 1.17.36 commit. The sets of failing files are the same. Each failing file needs Django or a database, which this PC does not have.
- `python -m py_compile` on `module_preferences.py`, `module_preference_views.py`, `contracts.py` and the new and changed tests: passes.
- `ruff check` with the pipeline gate rules (`--select E9,F63,F7,F82`): passes. The pyflakes rules (`F`) pass on the new and changed Python files.

## What could not run on this PC

Django is not installed here. So `tests/tactical-ui-preferences-runtime-1.17.37.py`, `tests/module-preferences-runtime-1.17.35.py`, the migration check (`manage.py makemigrations tec_tac --check --dry-run`) and the real caller-frame check inside Django can only run on the dev server. The new tests use narrow stubs of the Django and DRF pieces.

## Versions

Core 1.17.37. `core.module_preferences` 1.1.0. A module that uses the Python functions must require `tec-tac-framework >=1.17.37`. No module uses them yet.
