# Module categories (AD-21)

Every module says what kind of module it is. Core uses that to decide what the module may do. Johan set the rule on 9 October 2026 (AD-21). Core 1.17.13 builds it.

## The four categories

Write one of these in the manifest key `category` (`tec_tac.json`).

| Category | What it is | What it may call |
| --- | --- | --- |
| `core` | Wraps one Tactical API group. It is the middleware between Tactical and every other module. | Tactical's routes for its own group, through Core. Core's contracts. |
| `server` | Manages or enhances the Tec-Tac or Tactical server itself: health, updates, backups. | Core's contracts. It wraps no Tactical group. Licensing alone owns `core/codesign/` (AD-16). |
| `premium` | Does something Tactical does not do. | Core's contracts and the core modules' contracts, and its own vendor APIs. Never Tactical directly. A premium module that replaces a core module may call that module's routes while it is the one installed (AD-20). |
| `test` | A development module. | The same as a premium module. Core installs and enables it on a development server only. |

Anything else in `category` is refused when Core reads the manifest. Reportsets may not declare a category.

## A missing category counts as `test`

A manifest with no `category` is treated as `test`. Core tells you so, in plain English, and nothing breaks today:

- On a **development server** the module still runs. The warning says so.
- On a server that is **not a development server**, Core refuses to install it. Since 1.17.14 the refusal applies at install only. A module that is already installed keeps loading and can be enabled. The warning still names the missing category. Nothing stops at start-up.

The fix is the same either way. The module's next release needs to carry its category.

A development server is one where the root-owned Tec-Tac config sets `TEC_TAC_ENVIRONMENT=development`. Core reads it through the same setting that picks the default update trust level. A module, a browser or an environment variable of the web process cannot change it. If Core cannot read the setting, it treats the server as not a development server.

## What Core adds to module status

These fields are additive. Older UI builds ignore them.

| Field | Meaning |
| --- | --- |
| `category` | The category the manifest declares, or `null`. |
| `effective_category` | The category Core acts on. A missing category is `test`. |
| `category_missing` | `true` when the manifest states no category. |
| `category_refused` | `true` when the effective category is `test` and the server is not a development server. Since 1.17.14 it means "an install is refused"; an installed module can still be enabled. |
| `category_warning` | Plain English for a badge or a hint, or `null`. |

They appear on every `module_status` row of `GET /api/tfd/ui/context/` (legacy plugins carry `null` and `false`), and on every extension row of the `modules/v2` installed catalogue. The catalogue also carries `category_state` (what the install wrote to module state) and `category_mismatch`. Core reads the manifest first. A different value in state is flagged, never trusted.

## What Core enforces

1. **Install only (CQ38, 1.17.14).** An install plan for an effective `test` module off a development server returns the problem type `category_refused`, with `module`, `category`, `effective_category` and a plain-English `message`. The package preview of the direct install route (`/api/tfd/modules/packages/<id>/install/`) and the local single-package path refuse it the same way. Both root job helpers (v1 and v2) check the install again from the root-owned package or manifests and the root config. An upgrade is an install, so it is checked too. Enabling or disabling an installed module is never refused for its category, and neither is a hand-back. It writes the manifest category into the module's state entry in the same state write as the install.
2. **Tactical operations (AD-21 condition 3).** The executor uses the effective category. A `premium`, `server` or `test` module is refused every route, even one the owner table lists by id. The refusal names the category. Licensing keeps `core/codesign/` (AD-16). An honoured AD-20 replacement keeps its rights.
3. **Replacement (AD-20).** A replacement must be `premium`. A replacement with no category is honoured on a development server only. Otherwise the status reports the reason code `replacement-category`. A `test` module may not declare `replaces`, and neither may a `core` or `server` module. The capability prefix rule (a capability begins with the module's own id) stays for `core` and `server` only.

4. **A core module always stays installed and on (1.18.11, Johan, 18 November 2026).** Disable and Uninstall are refused for a module whose signed category is `core` (or whose category recorded at install is `core`; a difference fails closed). The refusal is HTTP 400 with `code: core_module_locked` and a plain `detail`, and Core writes one `deny` audit row. The check sits in Core's queue functions, and both root job helpers re-check it from root-owned manifests, because the job files are Tactical-writable. Enabling is never refused, so a core module that was switched off earlier can always come back, and then cannot be switched off again in the browser. A `server` or `premium` module is not covered.

   The lock does not apply in two cases:
   - **A development server** (`TEC_TAC_ENVIRONMENT=development`).
   - **An honoured premium replacement.** While a premium module replaces the core module (see `module-replacement.md`), the replacement flow switches the core module off and the core module may be uninstalled. A premium module's install, enable and hand-back work as before.

   Three ways round the lock:
   1. Install a premium module that replaces it.
   2. Use a development server.
   3. Run the server command as root: `sudo /usr/local/sbin/tec-tac-module-v2-job --server-command disable <module id>` (or `enable`, with `--cascade` to switch off the modules that need it). It is the root-only `--server-command` mode of the module helper, which is not reachable by sudo from the web side. The helper writes the audit row by running `manage.py tectac_module_state` demoted to the Tactical user with `runuser`; manage.py is never run as root. It enables and disables only; it never uninstalls. It writes one `modify` audit row with the actor `server command (tectac_module_state)`, and nothing when the module is already in that state.

   The catalogue rows of `GET /api/tfd/modules/v2/` carry `always_on`, `lifecycle_locked` and `lifecycle_lock_reason` so a UI can show the state.

Core does not build the production gate (AD-21 condition 6) in this release. A module without a category is still treated as `test`, not refused at load time.

## What a module author does

- Write the category in the manifest at the next release.
- A manifest that writes `premium` or `test` must require `requires.framework` of `>=1.17.13`. An older Core rejects the value, so the requirement keeps the module from installing there.
- A premium module that replaces a core module writes `premium`, `replaces` and `capabilities`. Without `premium` Core will not honour it off a development server.
