# Tec-Tac Framework 1.18.10

Date: 18 November 2026. Welcome can now show which modules your licence allows, and let an administrator untick the premium ones they do not want. Core gets three new routes for it. A second, small change makes the diagnostics report more robust. Nothing is installed or removed by this release.

## What changed and why

### The modules this licence allows

Licensing already keeps a list of the modules your licence allows. A premium module is a paid module that adds functions Tactical RMM does not have. Licensing's list is Core-only by design (AD-56), so Welcome, which is a module, could not read it. Core now reads it for the browser, through three routes. All three need `core.privileged_operations` (a module manager) and check it first. Anyone else gets 403.

| Route | What it does |
|---|---|
| `GET /api/tfd/modules/catalog/allowed/` | Returns the saved list. No call to the Licensing Server. |
| `POST /api/tfd/modules/catalog/allowed/refresh/` | Asks Licensing to refresh. Licensing limits itself to one server call a minute and answers `cached` inside it. Audited (`run`, `allowed_modules`). |
| `PUT /api/tfd/modules/catalog/allowed/selection/` | Body `{"module_id": "...", "selected": true or false}`. Ticks or unticks one licensed premium module. Audited. |

Without the refresh route a freshly registered server would only ever show `not_fetched`.

**Core and Server modules** are `locked` and always `selected`. Only an entitled premium module can be unticked.

**What comes back.** Each row holds `id`, `name`, `category`, `entitled`, `availability`, `locked`, `optional`, `selected`, `in_plan`, `required_by`, `notes`, `category_source` and a trimmed `release` (`release_id`, `version`, `channel`, `dependencies`). The top level holds `ok`, `state`, `message`, `plan_state`, `plan_revision`, `channel`, `plan_issued_at`, `plan_expires_at`, `fetched_at`, `from_cache`, `count`, `modules` and `last_refresh_state`. Core copies each field by name and checks its type. Strings are cut to a safe length and stripped of control characters. An unknown key is dropped. A row in the wrong shape, a duplicate id or more rows than the cap makes the whole answer `invalid_response` with no rows. No key, grant, token, Licensing Server address, SHA-256, publisher id or key id leaves Core.

**Fail closed.** A Licensing module that is missing, disabled, unhealthy or refuses Core gives `licensing_unavailable` (503) and an empty list. It is never an unrestricted list. Every other Licensing state (`not_fetched`, `plan_expired`, `licence_revoked` and so on) comes back with its sentence and no rows.

**How the untick works.** Core refuses before it calls Licensing: a bad id or a value that is not true or false (400), an id that is not on the list (404), and a Core, Server or unlicensed row (403, `locked`). Only then does it call Licensing's own `set_selection`. Licensing keeps its own `required_by` refusal (409) and its row-locked write. Core writes the audit row: `modify` with the before and after lists on success, `deny` for each refusal. If Licensing has no `set_selection`, the answer is `licensing_unavailable`. Core tries no other path.

**Where it lives.** All provider calls are in `licensing_catalogue_source.py`, the one Core file Licensing accepts as caller. The views never touch the provider. Licensing's frame check is covered by a test.

### Diagnostics containment (held Low from the 1.18.9 review)

The two install checks added in 1.18.9, `core.install.source-ownership` and `core.ui.module-sync`, could let an unexpected error out of the report. Reachable causes: odd text from `systemctl` that cannot be decoded, or a NUL byte in a configured path. Both checks now catch any error. They log only the check id and the error class name, and return one `unknown` row with the same id and label. The summary reads "This check could not run (ErrorClass). The rest of the report is unaffected." `unknown` counts as a warning in the overall result, which is the honest answer for a check that could not run. The report still returns HTTP 200 with every other check.

## Module-facing change

- Three new, additive browser routes (above), listed in `contracts.py` and `docs/module-repositories.md`. No existing route, field or contract changes.
- A provider is the module that answers a capability. Core reads the Core-only capability `licensing.allowed_modules` 1.0.0 as before. `grep modules/` found no module that calls the new routes. Welcome 1.2.15 is the first reader.
- Licensing: `set_selection` exists on its provider but is not one of the published operations and has no Core-only gate. Core calls it by that name. A request to make it a gated Core-only operation is in `reviews/requests/licensing.md`. Core keeps working when the gate lands, because the caller is the file Licensing accepts.
- Diagnostics: no id, field or status changes. The two ids can now be `unknown` after an error.

## Closes

- The Welcome 1.2.14 request for a browser-callable allowed-modules read route and a Core-mediated premium untick, in `reviews/requests/core.md`.
- The read part of request R1 for the picker. The batch install that reads this list stays open for R1.
- The held Low from the Core 1.18.9 review (check wrappers did not contain unexpected errors).

## Assumptions

- Who may use the routes: module managers only (`core.privileged_operations`), for read, refresh and write. Core cannot check a module's own permission without a new trusted purpose. The person running Welcome's install is a Core administrator anyway.
- The refresh route is included although it was not named. A fresh server cannot show a list without it. It is audited, manager-only and limited by Licensing to one call a minute.
- The release object is trimmed. Welcome only needs the id, version, channel and dependencies. Core re-verifies the artifact when it installs.
- Core calls `set_selection` from the one allowed file and does not fall back to anything else.
- The earlier plan said every touched file was CRLF. Only `contracts.py` and `docs/module-repositories.md` are. Each file keeps the line endings it had.

## What is not in this release

- The batch install (R1, R1a to R1d). This release installs nothing.
- R3, the core-module rule, the sandbox patches and every other open request.
- Reading the list as a Welcome-only user (`welcome.view` without `core.privileged_operations`). Widening that gate is Johan's call (see `reviews/questions/core.md`).
- Showing `plan_state`, `plan_revision` and `fetched_at` on Core's licence status page.

## What could not be run

Django is not installed on this PC. The three views and the URL registration were checked at source level and by `py_compile`, not called. `allowed-modules-route-1.18.10.py` runs the real `licensing_catalogue_source.py` against a fake provider. `diagnostics-check-containment-1.18.10.py` runs the two real wrappers from `diagnostics.py` with stubbed imports. A real Licensing module, a real session and a real audit write need dev02, so the checklist covers them.

## Johan test checklist (dev02)

1. As an administrator, call `GET /api/tfd/modules/catalog/allowed/`. **PASS:** `state` is `ok` (or `not_fetched` on a fresh server), Core and Server rows are `locked` and `selected`, Premium rows are `optional`. **FAIL:** any key, token, URL or `sha256` appears, or the call returns 500.
2. Call the same route as a user without `core.privileged_operations`. **PASS:** 403 and no rows. **FAIL:** any rows come back.
3. Call `POST /api/tfd/modules/catalog/allowed/refresh/` twice within a minute. **PASS:** the first answers `ok` or a Licensing state, the second answers `cached`, and each leaves one audit row (`run`, `allowed_modules`). **FAIL:** a 500, or no audit row.
4. Call `PUT /api/tfd/modules/catalog/allowed/selection/` with `{"module_id": "<a premium id>", "selected": false}`. **PASS:** `state` is `saved`, the row now shows `selected` false on the next GET, and the audit row (`modify`, `module_selection`) holds before and after. Then repeat with a Core module id: **PASS** is 403 `locked` and a `deny` row. An id that is not on the list is refused with 404. **FAIL:** anything is installed, removed or disabled, or a Core module can be unticked.
5. Call `GET /api/tfd/system/diagnostics/`. **PASS:** 200 with every check, including both install checks. The containment itself is proven by the test, not by a live fault.

**Send back:** the response bodies (module ids only, no secrets) and the audit rows from steps 3 and 4.

## Files

New: `framwork/tec_tac/module_allowed_views.py` (the three views, in their own file so `module_repository_views.py` stays cache-only, as the 1.17.103 test requires), `tests/allowed-modules-route-1.18.10.py`, `tests/diagnostics-check-containment-1.18.10.py`, `tests/version-1.18.10.py`. Changed: `framwork/tec_tac/licensing_catalogue_source.py`, `framwork/tec_tac/urls.py`, `framwork/tec_tac/contracts.py`, `framwork/tec_tac/openapi.py`, `framwork/tec_tac/diagnostics.py`, `docs/module-repositories.md`, `docs/troubleshooting-diagnostics.md`, `VERSION`, `tec_tac_package.json`. Moved: `RELEASE_NOTES_1.18.9.md` to `docs/releases/`, `tests/version-1.18.9.py` to `tests/legacy/` (root resolved as `parents[2]`).
