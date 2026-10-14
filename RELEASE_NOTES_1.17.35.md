# Tec-Tac Framework 1.17.35

Date: 14 October 2026.

This patch release closes the five items of the Core 1.17.35 plan. Every Tactical UI preference a person saves now goes through Core, so the route no longer loses the fields it did not know. A new per-person module preference lets a module remember one small choice, such as the Remote Background header collapse. The email ledger keeps each old marker's own time, which closes the held Low from 1.17.34. The browser export rows for the shared terminal widget (UI 0.12.104) and the server terminal socket (UI 0.12.105) are written, as documentation. The contract export test no longer pins the indent of the shell's context object, so the Core suite passes against UI 0.12.105.

Capability: `core.module_preferences` 1.0.0 (new, additive). `core.tactical_websocket` stays at 1.1.0. **Migration `0031_module_preferences` runs**: one new table, written by hand because Django is not installed on the development PC.

Closes these requests in `reviews/requests/core.md` (the entries are removed in this commit): "Save all UI preferences: Core storage" (the Core half), "module user preferences: one per-person choice for a module's window" (remote-background 0.5.0), and "Browser contract export row: `ui.authenticated.terminal`" (UI 0.12.104, with its UI 0.12.105 sentence). The UI and module halves that follow from this release are in `reviews/requests/ui.md` and `reviews/requests/core-modules.md`.

## Module-facing changes

- **`core.module_preferences` 1.0.0 (new, additive).** Python: `tec_tac.module_preferences.get(user, name, *, module_id, default=None)`, `set(user, name, value, *, module_id)`, `delete(user, name, *, module_id)` and `list_for(user, *, module_id)`. HTTP, signed-in person only: `GET /api/tfd/module-preferences/<module_id>/` and `PUT` or `DELETE /api/tfd/module-preferences/<module_id>/<name>/` (the PUT body is exactly `{"value": ...}`). Limits: the name matches `[a-z0-9][a-z0-9._-]{0,63}`; the value is a JSON scalar, list or object of at most 4 KiB stored and 5 levels deep; 50 names per person and module (a 51st gives 400 `preference_limit`); 120 changes a minute per person. Refusals: 400 `invalid_name` or `invalid_value`, 401, 404 `module_not_found` (core, tec-tac, or an unknown or disabled module), and 429. Not audited. A module that uses it must require `tec-tac-framework >=1.17.35`. The module id is a claim, as for `notices.publish` (see `docs/module-preferences.md`).
- **`tactical_ui` (additive, 1.17.35).** `GET` and `PUT /api/tfd/account/tactical-ui/` now save and return every Tactical UI preference. Booleans: `dark_mode`, `show_community_scripts`, `clear_search_when_switching`. Choices (from Tactical's model): `default_agent_tbl_tab` (server, workstation, mixed) and `client_tree_sort` (alphafail, alpha). `client_tree_splitter` is a whole number from 1 to 99. The colours `loading_bar_color` and `dash_info_color`, `dash_positive_color`, `dash_negative_color`, `dash_warning_color` are Quasar colour names or `#` colours of 3, 4, 6 or 8 digits, at most 40 characters. `date_format` is empty or null for the server default, else at most 30 letters, digits, spaces and `: / - . , [ ]`. The answer adds `default_agent_tbl_choices` and `client_tree_sort_choices`. The PUT is a partial update and all or nothing. `block_dashboard_login` is refused: it is a login block, not a UI preference. The runtime context `tactical_ui` keeps `agent_dblclick_action`, `url_action_id` and `can_run_url_actions`, and adds the scalars above (no choice lists). `context.dateTimeFormat` does not change.
- **Browser contract rows (documentation only, no value changes).** `ui.authenticated.terminal` (UI 0.12.104): the 19 operations, the options and the limits, and the rule that the scope is bound to the calling module. `ui.authenticated.websocket` now describes the server-terminal kind (UI 0.12.105) in place of the 1.17.34 sentence that said the helper did not open it yet.

## What changed and why

1. **Module user preferences (`core.module_preferences`).** Browser storage is refused for UI modules, so Remote Background could not keep its header collapse per person. The preference is its own table, not the reserved `extensions` object: a PUT to that object replaces the whole document, so a stale tab would overwrite a module's choice. Files: `models.py` (`TecTacModulePreference`), `migrations/0031_module_preferences.py`, `module_preferences.py`, `module_preference_views.py`, `urls.py`, `throttles.py` (`ModulePreferenceWriteMinThrottle`), `apps.py` (registration, guarded like `core.accounts`), `notices.py` (the enabled-extension check moved to `enabled_extension_id`; `_publishing_module` calls it and behaves as before), `contracts.py`, `docs/module-preferences.md`.
2. **Tactical UI preferences (`account_self_service.py`).** The route saved two of Tactical's UI fields, so the rest were lost when someone saved from Tec-Tac. Core now writes the same User columns Tactical's UI writes (parity, AD-25), with checks stricter than Tactical's model. The audit row still names the changed fields only, never the values. Files: `account_self_service.py`, `contracts.py`, `docs/my-account.md`, `docs/user-preferences.md`.
3. **The ledger copy keeps the marker's time (`module_failure_notices.py`, `notices.ledger_add`).** Held Low from the 1.17.34 review. A copied row got `created_at` = now, so 25 old email markers could use up the hourly cap of 20 for an hour. Each copied row now keeps its marker's own time (an update after the create, because `auto_now_add` only sets the time on the first save). A marker with no readable time falls back to now. `ledger_add` takes an optional keyword `created_at` (one datetime, or a mapping of user id to datetime). It runs in one transaction, so a failed call leaves none of its rows behind. The copy still logs one warning per tick and stops at the first failure. No migration and no capability change.
4. **Browser export rows (`contracts.py`).** Documentation only. See above.
5. **Contract export test pin (`tests/contract-export-1.17.18.py`).** The test required exactly eight spaces before `tacticalScope` in `workspace/ui/src/main.js`. UI 0.12.105 has six, so the Core suite was red against a correct UI. The pin is now the three names in order, with any indent and either line ending. No UI file was touched.

## Tests

Added: `tests/browser-contract-rows-1.17.35.py`, `tests/module-failure-notices-1.17.35.py`, `tests/tactical-ui-preferences-1.17.35.py`, `tests/module-preferences-1.17.35.py` and `tests/contract-export-ui-pin-1.17.35.py`. Dev-server runtime scripts (each rolls back and leaves nothing): `tests/module-failure-notices-ledger-runtime-1.17.35.py`, `tests/module-preferences-runtime-1.17.35.py` and `tests/tactical-ui-preferences-runtime-1.17.35.py`.

Changed to match the release (the assertions that encoded the old behaviour): `tests/module-failure-notices-1.17.34.py` (the fake `ledger_add` takes the keyword, and the marker read seam is `_default_marker_times`); `tests/f4-core-ui-context-1.15.178.py` (the context now carries the scalars, and the three old keys keep their values); `tests/my-account-features-1.15.167.py` (the stub user and fields gained the Tactical UI columns); `tests/browser-contract-catalog-1.15.170.py` (the new row id); `tests/contract-export-1.17.18.py` (the whitespace-tolerant pin).

## Checks run on this PC

- `bash tests/release-integrity.sh` passes. This PC has no `python3` command, so the run used a shim that calls the same Python 3.12.
- The pipeline's ruff gate (`ruff check` with `--select E9,F63,F7,F82`, as in `pipeline/tectac/checks.py`) on `workspace/core` passes.
- `python -m py_compile` passes on every new and changed Python file.
- The 23 targeted tests (contract rows and catalog, contract export and its UI pin, failure notices, preferences, the account and runtime-context tests, the notice publish test, the migration pins and the OpenAPI grouping) pass, and so does `tests/user-preferences-foundation.sh`.
- Every Python test in `tests/` was run. Each test that fails on this PC also fails on the clean 1.17.34 commit, for an environment reason (Django, Postgres, root, WSL, a Windows privilege, or a dev-server runtime script). Three tests that the release itself changed were fixed: the OpenAPI grouping and two newest-migration pins, which moved from 0030 to 0031 (`tests/update-source-1.17.2.py`, `tests/session-theme-1.17.24.py`, `tests/runtime-settings-upload-1.17.14.py`).

## What could not run on this PC

Django is not installed here. Not run: the migration `0031` (applied and checked with `makemigrations --check`), the ORM paths (the `created_at` update, the JSON column, the unique constraint, the cascade), the real Tactical User choices, the DRF views and the write throttle, and the sweep against the real database. The stub tests cover the logic. The dev-server scripts cover the database paths, and their steps are in `reviews/questions/core.md` ("Note (14 October 2026), Core 1.17.35").

## Left out, on purpose

- `block_dashboard_login`: refused as an unknown field. It is a login block, not a UI preference (plan, and the Users admin path if Johan wants it).
- `context.dateTimeFormat` does not follow the person's date format (CQ108). The person's value is published as `tactical_ui.date_format` only.
- Tactical's `dark_mode` and Tec-Tac's theme stay independent (CQ107).
- The UI half (saving and applying the Tactical preferences, binding the module id) and the module halves (Remote Background, Endpoints) are requests, not Core work.
- The browser route and the Python functions trust the module id, as `notices.publish` does (CQ109). A verified caller check is not built.

## Versions

Core 1.17.35. Modules that use `core.module_preferences` require `tec-tac-framework >=1.17.35`.
