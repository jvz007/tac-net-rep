# Tec-Tac Framework 1.17.2

This release does four things. A role can now be given the right to change runtime settings without full privileged access. Core remembers which update source each component follows. The browser contract catalog lists everything `register(context)` provides. And a held Low from the 1.17.1 review is fixed.

Nothing here breaks an existing module. Every change to something modules or the UI consume is additive. See "Module-facing changes".

## Runtime-settings permission (CQ10)

Johan decided that superusers and users with the RBAC right for Core may change runtime settings.

- New grantable Core codename `core.runtime_settings.manage`, in a new permission group "Runtime settings". It appears in `registered_permissions`, `permission_catalog` and the role editor.
- New `tec_tac.rbac.can_manage_runtime_settings(user)`. True for an effective superuser, a holder of the new codename, or a holder of `core.privileged_operations`. The last stays so 1.17.1 administrators lose nothing. It never raises and returns False on any error.
- `PATCH /api/tfd/system/runtime-settings/` uses it. The 403 message names both rights. `GET` stays open to any signed-in user.
- The role editor does not gate the new codename to superusers. Only `core.privileged_operations` is superuser-only to grant. Role managers can grant `core.runtime_settings.manage`, as Johan's CQ10 answer says.
- The new codename does not allow staging or installing updates. That still needs `core.privileged_operations`.

Closes the CQ10 request in `reviews/requests/core.md`. Tests: `tests/runtime-settings-permission-1.17.2.py`. `tests/runtime-settings-1.17.1.py` now stubs the new function.

## Remembered update source per component

Core now stores `{type: release|branch, ref}` for `framework` and `ui`. The default is `release` with `ref` null, which is how updates worked before.

- **Storage.** New JSON column `update_sources` on `TecTacRuntimeConfig`, migration `0025_runtime_update_sources` (depends on `0024_retire_tfdreporting_poc`). A missing or invalid stored value reads as the default and never raises.
- **Endpoint.** `GET` and `PATCH /api/tfd/system/update-source/`. `GET` is open to any signed-in user. `PATCH` uses `can_manage_runtime_settings` and the runtime-settings write throttles. Body: `{component, type, ref}`. A branch needs a strict name (at most 200 characters, only letters, digits and `. _ / -`, no `..` or `//`, no leading `-` or `/`, no trailing `/`, `.` or `.lock`). `release` forces `ref` to null. Unknown fields and components get 400. A change writes a strict Core audit row (module `core`, object type `update_source`, object id the component, action `modify`, before and after) in the same transaction. A failed audit write rolls the change back. Setting the same value writes nothing. The branch is not checked against GitHub on save, so saving works offline.
- **Online check.** `online_status(component, force, source=None)`. For a release source the response is exactly as before. For a branch source it keeps every key and adds `source`, `branch` and `branch_error`. `branch` has the head commit and date from GitHub (cached 5 minutes in the release cache file, `force` bypasses it), the installed commit, and `state` (`same`, `differs` or `unknown`) with `differs` (`true`, `false` or `null`). A branch failure sets `branch_error` and does not hide the release data.
- **How "installed" is known.** It cannot be `source_git.update_head`. The root helper commits the verified bytes to a local branch, so that SHA never equals GitHub's head. Instead `queue_install` puts the staged package's `source` into the job, and the root helper's `claim_job` copies a sanitised version (type `release`, `branch` or `offline`; repository and ref as bounded strings; commit only if 40 hex) into the history row. Core compares the head with the commit of the most recent succeeded install of that component. If that install came from another repository, from an offline upload, or from before 1.17.2, the state is `unknown`. This is slightly stricter than "the most recent install from this repository": an offline upload after a branch install means the branch commit is no longer what runs, so it reads `unknown`. Stage and install once with 1.17.2 or later and the check is exact. The question is in `reviews/questions/core.md` (CQ11).
- **Staging.** The online stage view uses the saved source when the request has no `source_type`. An explicit `source_type` wins. With no saved source the default stays `release`.
- **Status.** `GET /api/tfd/system/updates/` has a new key `update_sources` so the UI gets the saved source in the call it already makes.
- The remembered source is provenance and a default only. The root helper still re-verifies trust as root. A holder of only `core.runtime_settings.manage` can change the default but cannot stage or install. That is asked in `reviews/questions/core.md` (CQ12).
- Docs: `docs/update-source.md` (new) and a note in `docs/system-update-signed-releases.md`. HTTP contract entries, a Python contract row (`tec_tac.runtime_settings.get_update_source`), the Swagger grouping, and the route in `install.sh` route verification.

Tests: `tests/update-source-1.17.2.py`. The UI half is already filed in `reviews/requests/ui.md`.

## Browser contract rows for the module runtime surface

`BROWSER_CONTRACTS` now lists what `register(context)` provides, matching the UI source and docs. Documentary only. No runtime behaviour changes.

- `ui.authenticated.transport`: the error shape (`status`, `payload`, `code`) and the `rejectErrorPayload` rule.
- `ui.authenticated.runtime-context`: `server_url` and `module_register_timeout_seconds`.
- New rows: `ui.authenticated.navigation` (`addNavigation`, with `permission` and `permissions`), `ui.authenticated.router` (the guarded module router) and `ui.authenticated.permissions` (`hasPermission`).
- `ui.authenticated.help`: `openContext` and `list`. `ui.authenticated.code-editor`: `languages`. `ui.authenticated.module-status`: `has`, `isActive`, `version` and `satisfies`.
- Rows may carry an optional `details` list. `render_markdown` and `render_text` print it.

The newest file in `docs/contracts/` stays 1.17.1 until Johan re-exports from the dev server. The UI docs the new rows point to (`module-runtime-api.md`) still need sections for the router, `hasPermission` and `codeEditor.languages`. That is filed in `reviews/requests/ui.md`.

Tests: `tests/browser-contract-runtime-surface-1.17.2.py`. `tests/browser-contract-catalog-1.15.170.py` has the new id set.

## Held Low from the 1.17.1 review: sweep orphan step honours the limit

`sweep_expired_sessions` used to load the digest of every revoked row into Python on every scheduler tick. The orphan-token step now selects at most `limit` digests of tokens that still exist, through a subquery on the trust table, and deletes exactly those. Old revoked rows whose tokens are already gone cannot use up the limit. Leftovers go on the next tick. `orphan_tokens_deleted` keeps its meaning. No new Tactical touchpoint. `docs/session-security.md` says so.

Tests: `tests/session-sweep-limit-1.17.2.py`. The `tests/session-expiry-sweep-1.17.1.py` stub gained `values()` and a queryset-valued `digest__in`.

## Module-facing changes

All additive. No module under `modules/` uses the runtime-settings or system-update endpoints or `sweep_expired_sessions`. Every module that imports `tec_tac.rbac` uses only `has_extension_permission` or `effective_permissions`.

- New Core permission codename `core.runtime_settings.manage` (group "Runtime settings"). It now appears in the permission catalog and in the effective permission set of a holder or superuser.
- New Python: `tec_tac.rbac.can_manage_runtime_settings(user)` and `tec_tac.runtime_settings.get_update_source(component)`.
- New HTTP: `GET` and `PATCH /api/tfd/system/update-source/`. New keys on existing responses: `update_sources` on `GET /api/tfd/system/updates/`, and `source`, `branch`, `branch_error` on `GET /api/tfd/system/updates/online/` for a branch source only. These are UI-facing.
- New browser contract rows (`ui.authenticated.navigation`, `.router`, `.permissions`) and extended rows. Documentary.
- Browser contract rows may now carry `details`.

## Migration and install

Migration `0025_runtime_update_sources` adds one JSON column with default `{}`. It is reversible and safe to run on a live server. The new route is in the `install.sh` route verification.

## Not built

- The server-side audit path (CQ6), the system-action contract (AD-13), module route mounting, general secret storage, the report bridge shim, module mutual exclusion, and the other separate Core contract items. Each needs its own release.
- A `VERSION`-at-branch-head fallback when the installed commit is unknown. Until an install made with 1.17.2 or later records its commit, the branch check reports `unknown`.
- Wrapping Tactical's Knox authentication (CQ4 option b). Johan has not chosen it.

## What could not run on the development PC

Django is not installed here. The new tests load the real modules against stubs, and check wiring by source. These did not run: the migration against a database, the PostgreSQL subquery in the orphan step, the GitHub calls, and the root helper. Verify them on the dev server after the update.
