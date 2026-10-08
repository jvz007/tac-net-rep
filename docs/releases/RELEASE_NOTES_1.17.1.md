# Tec-Tac Framework 1.17.1

This release does four things. Core now ends expired sessions' Tactical tokens on its own. Core stores the module `register()` time limit. The retired reporting POC is gone. And the Core scheduler question (CQ7) is answered in writing.

Nothing here breaks an existing module. Every change to something modules consume is additive. See "Module-facing changes".

## Expired sessions lose their Tactical token (CQ4)

Johan asked whether a Tec-Tac logout or timeout also ends the user's Tactical token. We checked `session_security.py` and the logout path.

- **Logout.** The UI calls Tactical's own `/logout/` (Knox `LogoutView`). That deletes the one token. Core does not hook it and does not need to.
- **Timeout while a request arrives.** `ensure_request_session` revokes the row and deletes the exact Knox token on an idle or absolute timeout. That runs only when a request reaches a Core view. The UI heartbeat reaches Core, so it works while a tab is open.
- **Timeout with no request.** A closed tab, a dead browser, or a module that only calls Tactical routes never reaches Core. Knox keeps the token alive for its own 5 hours and refreshes it on every use. This was the gap.

### The sweep

`session_security.sweep_expired_sessions(now=None, limit=500)` runs on every scheduler tick (about one minute). It:

- finds unrevoked trust rows that have a `knox_digest` and are past the current global policy;
- handles each row in its own transaction with `select_for_update(skip_locked=True)`, so it cannot race a live request;
- revokes the row (`idle-timeout` or `absolute-timeout`), writes the matching `session_idle_timeout` or `session_absolute_timeout` audit event with `requested_by` `tec-tac-scheduler`, and deletes that exact Knox token;
- skips rows with no `knox_digest` and counts them. Revoking those would delete every token of that username and end the user's other live sessions;
- deletes any live token whose digest belongs to an already revoked row.

`tec_tac_scheduler_tick` calls the sweep in its own try/except. A failure prints `session_expiry_sweep=error` and the tick carries on. The tick line now also prints `sweep_revoked`, `sweep_skipped_no_digest` and `sweep_orphan_tokens`.

`cleanup_session_history` now deletes the Knox token of a stale unrevoked row before it deletes the row.

Expiry is worked out from `created_at` and `last_activity_at` with the policy in force now, the same way a live request does it. The sweep does not use the stored `*_expires_at` columns. If it did, lengthening the policy would let the sweep expire sessions a live request would still accept.

**Not covered.** The IP-change policy still applies only to requests that reach a Core view. Enforcing it on Tactical routes needs a wrapper around Tactical's Knox authentication class (CQ4 option b). Johan has not chosen that, so it is not built.

No model, migration or contract change for this item. `core.session_security` stays 2.0.0. There is no new Tactical touchpoint. `docs/session-security.md` has a new section.

## Module `register()` time limit (UI Q3)

Core stores how long a module's `register()` may run. Default 30 seconds, range 5 to 300 whole seconds. The UI applies it. Modules do not.

- New singleton model `TecTacRuntimeConfig`, migration `0022_runtime_config`.
- `GET /api/tfd/ui/context/` has a new top-level key, `module_register_timeout_seconds` (integer).
- `GET` and `PATCH /api/tfd/system/runtime-settings/`. Any signed-in user can read. `PATCH` needs privileged operations (effective superuser or `core.privileged_operations`). It refuses booleans, floats, strings, `null` and out-of-range values with 400, writes a strict Core audit row (module `core`, object type `runtime_settings`, action `modify`, before and after), and uses a write throttle (10 a minute, 200 a day).
- `get_module_register_timeout_seconds()` never raises. If the database cannot be read it returns 30, because it sits on the startup path.
- Contract rows, a Swagger group ("Tec-Tac · Runtime Settings") and `docs/runtime-settings.md` are added.

The authority for changing it (privileged operations) and the range are assumptions. They are asked in `reviews/questions/core.md` (CQ10). The UI half is in `reviews/requests/ui.md`. Until the Core UI has a settings control, an administrator changes the value through the API.

## Reporting POC retired (CQ2)

Johan approved dropping `extensions/reporting/tfdreporting`. It was a proof of concept and no module uses it.

### Step 1: the RBAC table moves, with no change to the database

`ExtensionRolePermission` now lives in `tec_tac.models`. It keeps its table name (`tfdreporting_extensionrolepermission`), fields, ordering, constraint (`tfd_unique_role_permission`) and index (`tfd_role_perm_lookup`), so an existing server needs no DDL. `role_id` is still a plain integer.

Migration `0023_extension_role_permission` has two operations, in this order:

1. a state-only `SeparateDatabaseAndState` that declares the model;
2. a separate `RunPython`, `create_if_missing`, that creates the table only when it is absent. A fresh install no longer runs the old app's migrations, so something must create it. Its reverse drops the table.

### Step 2: the app goes

- Migration `0024_retire_tfdreporting_poc` drops `tfdreporting_networkavailability` (`DROP TABLE IF EXISTS`) and deletes extension-permission rows whose codename starts with `tfdreporting.`. It prints how many network rows it dropped. It is **irreversible by design** (approved by Johan). It does not touch the `django_migrations` rows of the old app, so an older Core restored over this database still sees them as applied.
- `rbac.py` and `module_identity.py` import the model from `.models`. The public `has_extension_permission`, `effective_permissions` and `get_plugins` signatures do not change.
- `registry.legacy_plugins()` is deleted. `legacy-reporting-poc` is no longer a protected plugin id (`example` stays).
- Deleted: `extensions/reporting/`, `scripts/reporting-permission.sh`, `tests/network-reporting-api.sh`, `tests/network-reporting-server.sh`.
- `install.sh`: no `migrate tfdreporting` step, no reporting-permission prompt, no network-availability route check. The model check now looks at `tec_tac.ExtensionRolePermission` and its `db_table`. The installer no longer copies `extensions/reporting`, and it no longer cleans up an ancient in-tree copy in the Tactical backend.
- `uninstall.sh --purge-data` keeps today's effect (the extension-permission table is removed) by rolling `tec_tac` back to `0022_runtime_config`, and only when `0023` is applied.
- `scripts/install-extension.sh` and `scripts/remove-extension.sh` import the model from `tec_tac.models`. `remove-extension.sh` loses its legacy-id guard.
- `scripts/system-update-helper.py` is deliberately **not** changed (it runs as root and is rollback-sensitive). `('extensions', 'reporting')` stays in `FRAMEWORK_OWNED_PLUGIN_PATHS`. On an upgraded server the old directory stays on disk. It is inert, because the registry no longer reads it. `install.sh` does not delete it either, so a rollback to the previous Core still finds it.

### Data

The ingest endpoint `/api/tfd/reporting/network-availability/` and its data are gone. Take a server backup before upgrading. It keeps the old rows.

## Module-facing changes

All additive. No module uses anything removed.

- **New `ui/context` key.** `GET /api/tfd/ui/context/` returns `module_register_timeout_seconds`, an integer. Default 30, range 5 to 300. The UI applies the limit. Modules must not read it to change their behaviour. The shipped UI (0.12.80) ignores the key.
- **New endpoint.** `GET` and `PATCH /api/tfd/system/runtime-settings/` (see above). A new Python function `tec_tac.runtime_settings.get_module_register_timeout_seconds` is listed as informational.
- **New contract rule.** The UI, not modules, applies the module `register()` time limit.
- **RBAC table moved, same table name.** `ExtensionRolePermission` is now `tec_tac.models.ExtensionRolePermission`. Modules do not import it (grep of `modules/` is empty). The Python functions modules do use (`tec_tac.rbac.has_extension_permission`, `effective_permissions`, `tec_tac.registry.get_plugins`) are unchanged. No contract row mentioned the old app, so there is no compatibility shim.
- **Removed.** The tfdreporting ingest endpoint and its data. No module called them.
- **Nothing changes** for `core.session_security` (still 2.0.0).

## Closes

- `reviews/requests/core.md`: "Check the session-to-Tactical-token link (CQ4)", "Retire `extensions/reporting/tfdreporting` (CQ2)" and "Core setting for the module `register()` time limit (UI Q3)". All three shipped in 1.17.1.
- CQ7 (what the Core scheduler already offers a module job): **documentation only** in this release. The finding is in `reviews/design-review-08-10-2026/core.md`. The request is now a scoped system-action contract, waiting on Johan's choice of mechanism (CQ8).

## Left for later

- The IP-change policy on Tactical routes (CQ4 option b). Johan has not chosen it.
- A Core system-action contract (CQ7). It needs Johan's choice of mechanism (CQ8).
- Report Manager taking over the reporting bridge (CQ1). It waits on the `reportmanager` core module.
- The Content-Security-Policy for the nginx snippet belongs to the UI (`reviews/requests/ui.md`).

## What could not be run on the development PC

Django, PostgreSQL, the Tactical runtime and root are not available here. The sweep, the settings view and the migrations are covered by stub and static tests only. Before this release is trusted, the dev server should:

- run `migrate tec_tac` on an upgraded database and on an empty one (0022, 0023 and 0024);
- run `install.sh` and `uninstall.sh --purge-data`;
- let the scheduler tick run once with an expired session and check `session_expiry_sweep=ran` and that the Tactical token is gone.

## Tests

New: `tests/session-expiry-sweep-1.17.1.py`, `tests/runtime-settings-1.17.1.py`, `tests/extension-permission-move-1.17.1.py`. Extended: `tests/session-retention-scheduler.py`, `tests/session-retention-deletion.py`. `tests/session-security-foundation.sh` now runs the sweep test and `tests/session-knox-revocation.py`, which was not wired in before.
