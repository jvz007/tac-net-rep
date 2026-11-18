# Tec-Tac Framework 1.18.11

Date: 18 November 2026. Core modules now always stay installed and on. Nobody can disable or uninstall one from the browser by accident. Three ways remain for when you really need to: a premium module that replaces it, a development server, or a command on the server. Nothing is installed or removed by this release, and no module that is off today is switched back on.

## What changed and why

Core modules wrap Tactical's own functions (agents, checks, patching and so on). Every other module relies on them. Switching one off breaks the modules above it. Johan asked for a hard rule: "core modules should always be installed, they can only be disabled by premium modules or if the server is in dev mode, or cli command."

### The rule

A module is locked when its signed category is `core`. Core also checks the category recorded in module state when the module was installed. If the two disagree and either says `core`, the module counts as locked.

A locked module cannot be disabled or uninstalled. That includes a disable that reaches it through another module's cascade (the "also switch off the modules that need it" option). Enabling is never refused, so a core module that was switched off earlier can always come back.

The refusal is plain English: "Agents is a core module and always stays installed and on. A premium module that replaces it can take over, and a development server can switch it off." The route answers HTTP 400 with `{"detail": ..., "code": "core_module_locked"}`. That is the same status as every other refusal, so the Modules page already shows the text. Every refusal writes one Core audit row (`deny`, object `module`, with the module, the action and the reason).

### Three places check it

The rule sits in Core's queue functions, not only in the views, so a module's backend gets the same refusal. It sits again in both root job helpers. The job files are writable by the Tactical user, so the helpers decide from the root-owned manifests and module state, never from what the job says about itself.

### When the lock does not apply

1. **A premium module that replaces it.** While a premium module honourably replaces the core module (for example Patch Management over Windows Patching), the existing replacement flow switches the core module off. The replaced core module may then be uninstalled. Installing, enabling and disabling the replacement work as before, including the hand-back.
2. **A development server.** `TEC_TAC_ENVIRONMENT=development` in the root-owned config. A browser cannot change it.
3. **The server command.** See below.

### The server command

```
sudo /usr/local/sbin/tec-tac-module-v2-job --server-command disable <module id> [--cascade]
sudo /usr/local/sbin/tec-tac-module-v2-job --server-command enable <module id>
```

The helper must run as root. Module state is root-owned, so the Tactical user cannot write it. The root entry point is the module helper itself (`--server-command`); manage.py only writes the audit row, as the Tactical user. The web side and the Tactical user cannot reach that mode: the sudoers lines allow `--dispatch *` only, and this release does not change them. The command applies the same dependants rule (a disable with enabled dependants needs `--cascade`) and the same replacement rules as the browser. It skips only the core-module lock. An enable that would switch a replacement off is refused with the list. It writes one `modify` audit row with the actor `server command (tectac_module_state)`. If the module is already in that state it says so and writes nothing. The command enables and disables only. It never uninstalls.

### Status fields

Each module row of `GET /api/tfd/modules/v2/` carries three new fields:

| Field | Meaning |
|---|---|
| `always_on` | The signed category is core. |
| `lifecycle_locked` | Disable and Uninstall are refused right now: `always_on`, not a development server, no honoured replacement. |
| `lifecycle_lock_reason` | The plain sentence, or `null`. |

`GET /api/tfd/modules/v2/<id>/remove-check/` also answers `locked` and `message`. Core reads the development flag once per catalogue build and reuses the replacement model it already builds, so a page load does no extra disk reads per row.

## Module-facing change

- Additive, on `GET /api/tfd/modules/v2/`: `always_on`, `lifecycle_locked`, `lifecycle_lock_reason`. Legacy rows carry `false`, `false`, `null`.
- New refusal: `POST /api/tfd/modules/v2/<id>/state/` (disable) and `POST /api/tfd/modules/<id>/remove/` answer HTTP 400 with `code: core_module_locked` for a locked core module. `GET /api/tfd/modules/v2/<id>/remove-check/` keeps `valid` and `dependants` as before (`valid` means no enabled module needs it) and adds `locked` and `message`. The UI stops on `valid: false`, so a locked core module passes the check and the remove call answers the 400 with the plain sentence and writes the deny row. Python callers of `queue_set_enabled`, `queue_remove` and `validate_disable` get `ModuleCoreLockedError` (a `ModuleManagerV2Error`, so existing handlers catch it).
- Replacement flow unchanged: `apply_enable_job`, `apply_install_prepare_disable` and `verify_install_disables` are not touched. Enabling a replacement still disables the core module it replaces, and disabling a replacement still hands the core module back. A test runs this for Patch Management over Windows Patching.
- `grep` of `modules/` and `workspace/ui` found no module that calls the state or remove routes or these queue functions (one premium test file mentions `queue_set_enabled` as text). The UI Modules page (`modules.js`) uses state, remove-check and remove. It keeps working: remove-check keeps `valid` unchanged, so the UI goes on to the remove call, which answers HTTP 400 with `detail`.
- Public contract text (`contracts.py`) lists the fields, the error code and the remove-check change. No capability version changes.

## Closes

- The request "core: core-category modules cannot be disabled or uninstalled (Johan, 18 November 2026)" in `reviews/requests/core.md`.

## Assumptions

- Uninstalling a core module is allowed only while an honoured premium replacement of it exists, or on a development server. The command offers enable and disable only. Johan named only those two for the command.
- The helper is root only. The request said "root or Tactical user". A Tactical-user path would need a new sudoers line and widens trust, so it is not built (recorded in `reviews/questions/core.md`).
- A core module that is already off on a server today stays off. It can be enabled, and then cannot be disabled in the browser again.
- A `server` module is not covered. The request names `core`.
- A module row with an odd or missing manifest category and a category of `core` in module state is locked (fails closed).
- The v1 helper's remove check is one rule narrower than Core's: it requires the replaced module to be off and an enabled premium module to replace it, and does not re-run the capability-parity check. Core's queue function runs that check first.
- Nothing is switched on or off by the installer. The UI and Welcome changes are requests (see below).

## What is not in this release

- The Modules page label ("Always on") and hidden buttons: request in `reviews/requests/ui.md`. Welcome showing the state: request in `reviews/requests/welcome.md`. Neither is needed for the rule to work.
- Online multi-install (R1), first-install intake (R3), the remaining part of R2, and the sandbox patches (AD-65). `SANDBOX_ENABLED` stays `False`.
- The held Core 1.18.10 review findings and the other open requests.
- Any command option to uninstall.

## What could not be run

Django REST framework is not installed on this PC, and nothing runs as root here. The browser routes and the real audit table were not run: the views are checked at source level and the audit writer is a recorder in the tests. The two root helpers and the command were tested with stubs only (stubbed state, manifests, sync and sudo). A real disable, uninstall and runtime reload on a server are covered by the checklist below.

## Johan test checklist for dev02

Update dev02 to Core 1.18.11 first. Use a server where `TEC_TAC_ENVIRONMENT` is not `development` for steps 1 to 5 and 7.

1. **Refusal in the browser.** Open Module Manager. Try Disable, then Uninstall, on a core module (for example Agents).
   - Expected: nothing is queued. You see "Agents is a core module and always stays installed and on. ..." for both. The audit log shows two `deny` rows on the module.
   - FAIL: a job starts, the module goes off or disappears, or no audit row appears.
   - Send back: the module id, the text you saw, and the newest job in the module job list.
2. **Status fields.** Open `/api/tfd/modules/v2/` (signed in). Find a core module.
   - Expected: `always_on` true, `lifecycle_locked` true, `lifecycle_lock_reason` the sentence. A server or premium module shows false, false, null.
   - FAIL: a field is missing or wrong.
   - Send back: the row for one core and one premium module.
3. **Other modules.** Disable and then enable a server or premium module. Uninstall one you can spare.
   - Expected: both still work as before.
   - FAIL: either is refused with the core sentence.
   - Send back: module id and the text shown.
4. **Server command.** As root on the server run `sudo /usr/local/sbin/tec-tac-module-v2-job --server-command disable <core id>`. Then run `sudo /usr/local/sbin/tec-tac-module-v2-job --server-command enable <core id>`. Then run the same enable again.
   - Expected: the first prints that the module is now off, the second that it is now on. Both lines name the module id, never the word "disable" or "enable". The audit log shows two `modify` rows. Each row's object is the core module id, with the actor `server command (tectac_module_state)`. The third run says "<core id> is already on. Nothing changed." and writes no row.
   - FAIL: an error, no audit row, a row whose object is `disable` or `enable`, or a row with another actor.
   - Send back: the command output and the two audit rows.
5. **Not root.** Run the same helper command as the Tactical user. Then run `manage.py tectac_module_state <id> --disable` as root.
   - Expected: the helper stops with "must run as root". manage.py as root stops with "Do not run manage.py as root". Run as the Tactical user, the same manage.py command only prints the helper command to use. Nothing changes.
   - FAIL: the module changes.
   - Send back: the output.
6. **Development mode.** With `TEC_TAC_ENVIRONMENT=development` in the config, disable a core module in the browser, then enable it again.
   - Expected: both work.
   - FAIL: the browser refuses.
   - Send back: the config line and the text shown.
7. **Replacement flow.** Switch Patch Management over Windows Patching, then switch back.
   - Expected: both switches work exactly as in 1.18.10, with the usual confirmations. While Patch Management is on, Windows Patching can be uninstalled; do not do that on a server you need.
   - FAIL: the switch is refused with the core sentence, or Windows Patching does not come back on the way back.
   - Send back: the job log of the failed switch.

## Fixed after review

Review round 1 blocked 1.18.11 with one High finding: the server command asked the owner to run Tactical's `manage.py` as root. That imports Tactical's virtualenv, settings and `local_settings.py` as root, which a compromised Tactical account could plant code in.

- **The root entry point is now the helper.** Run `sudo /usr/local/sbin/tec-tac-module-v2-job --server-command enable|disable <module id> [--cascade]`. It changes the state and prints the result. No Tactical code runs in the root process.
- **The audit row is written as the Tactical user.** After a change, the helper runs `runuser -u <tactical user> -- <python> manage.py tectac_module_state <id> --record-outcome <json>`, the same demotion `system-update-helper.py` uses. If that step fails, the state change stays and the helper says the audit row could not be written.
- **`tectac_module_state` refuses to run as root** (euid 0) and no longer calls the helper. Run as the Tactical user with `--enable` or `--disable`, it only prints the helper command to use.
- Docs (`docs/module-categories.md`) and these notes no longer tell anyone to run manage.py as root.
- Sudoers is unchanged: `--dispatch *` only. The Tactical user still cannot reach `--server-command`.
- Test: `tests/core-module-state-command-1.18.11.py` now asserts no coded or documented path runs manage.py as root. The helper and runuser step ran with stubs only; nothing ran as root here.

### Fixed after review, round 2 (1.18.11)

The AI review of 1.18.11-1 passed. Two held findings and one signing stop remain, and this rebuild closes them.

- **The audit row and the printed lines now name the module.** The helper took the action word as the module id in four places. The audit row (object and `metadata.module`), the "already on/off" and "is now on/off" lines, and the "also switched" filter now use the module id. The `server_command` call itself was already right. The branch is now a function, `server_command_main`, so a test can run it without root.
- **Checklist step 4 uses the forms the helper accepts** (`--server-command disable <id>`, `--server-command enable <id>`). Step 5 now describes manage.py as built.
- **Signing stopped at promotion.** Core refuses to promote when the rebuild number appears in a source file. The two source files that named the earlier rebuild now say `1.18.11`. A new test scans the tree so it cannot come back.
- Test: `tests/core-module-state-command-1.18.11.py` runs `server_command_main` with stubs (runuser argument, printed lines, no audit when nothing changed, the audit row) and scans the notes and the tree. Nothing ran as root here.
- Core 1.18.11 still needs the contract export refresh recorded in `reviews/questions/core.md`.

### Fixed after precheck (18 November 2026)

- **remove-check keeps `valid` as it was.** `GET /api/tfd/modules/v2/<id>/remove-check/` had started to answer `valid: false` for a locked core module. The Modules page reads that as "required by" and stopped before the remove call, so the core sentence and the deny row never showed. `valid` now means only "no enabled module needs it". `locked` and `message` are new, additive fields. The remove call then answers 400 `core_module_locked` and writes the deny row.
- **The test suite is green again.** `tests/version-1.18.11.py` is now `tests/version-1.18.11.py` and reads `VERSION` instead of pinning the rebuild. The rebuild text is out of the other tests.
