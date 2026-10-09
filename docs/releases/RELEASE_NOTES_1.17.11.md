# Tec-Tac Framework 1.17.11

Enabling or installing a replacement module now tells you which module it will disable, asks you to confirm, and disables it in the same job. If state ever shows both enabled, Core keeps the replaced module, drops the replacement and says so in the log and the audit trail. A replacement also stands in for the module it replaces when another module depends on it, and server modules can now be replaced as well as core modules.

Closes: the "AD-20 amendments" entry in `reviews/requests/core.md` (Johan's answers to CQ27, CQ28 and CQ30, 9 October 2026), the two entries under "Module replacement and tactical operations (from ui 0.12.88)", and the four Lows held from the 1.17.10 review.

## What changed

### Enabling or installing a replacement names the module it will disable (CQ27, 1a and 1b)

- **Enable.** Enabling a module that declares `replaces` is no longer refused because the replaced module is enabled. Core checks every other rule as if the replaced module were already disabled: it is installed, it is a core or server module, it declares `capabilities`, the replacement has parity, and no rival replacement is enabled. If they pass, the answer names the module in `will_disable`. Each row of `GET /api/tfd/modules/v2/` carries `will_disable`, and so does `validate_enable()`.
- **Confirm.** `POST /api/tfd/modules/v2/<id>/state/` takes an optional `disable_replaced` list. It must name exactly the list the operator was shown. Without it, or with an out-of-date list, the answer is HTTP 400 with `code: replacement_confirmation_required`, a plain `detail` that names the module, and the fresh `will_disable`. An old caller that sends no list sees a refusal and nothing changes. With the list, the job carries `disable_modules`.
- **Install.** The install plan and each action carry `will_disable` for a fresh install of a replacement whose replaced module is installed and enabled. The plan stays valid. `POST /api/tfd/modules/v2/packages/<upload_id>/install/` takes the same `disable_replaced` list and gives the same 400. Single packages, bundles and batches pass the list into the job. A single local package that would disable something goes through the v2 worker, as a rename does, because only the v2 worker can disable in the same job. An upgrade of an installed replacement names nothing and behaves as before. A replaced module installed fresh in the same batch is still refused.
- **Two queued jobs cannot both pass.** The pending-job model now applies the `disable_modules` of queued enable and install jobs.
- **Still refused.** Enabling the core or server module while an enabled replacement points at it (`replacement_conflict`, naming the replacement), and enabling a replacement while a rival replacement is enabled. Core does not disable a replacement on your behalf for that case (see "Questions" below).
- **The root job helper checks again.** The helper runs as root and cannot import the Tactical-writable tree, so it carries its own copy of the rules and its own manifest reader. Under the module-state lock it reads `REPO_ROOT/extensions/*/tec_tac.json` (regular, root-owned files that nobody else can write), re-runs the rules, and requires what it would disable to sit inside the confirmed `disable_modules` list. Anything unconfirmed fails the job with nothing changed. Then one state write enables the replacement and disables the replaced module. If the runtime sync fails, the helper puts every flag the job changed back. An install does the same check after the packages land and before any state is written, disables after the versions are recorded, and re-enables the module if it has to roll back. A drift-guard test runs Core's rules and the helper's copy over 1,296 scenarios and requires the same answer.
- **Audit.** When the job is queued, Core writes one audit row per disabled module: module `core`, action `custom:module-replacement-disabled`, object the replaced module, actor the requesting user. It never blocks the job.

### If state shows both enabled, Core drops the replacement and says so (CQ27, amendment 2)

`module-state.json` is root-owned, so the Tactical process cannot rewrite it. Core acts in three steps and never stops Tactical:

1. **At load.** `load_extensions()` leaves the replacement out of the modules it loads. The replaced module loads as normal. One warning per pair.
2. **In what the UI sees.** `module_status` reports such a replacement as `enabled: false` and `active: false`, so the UI does not load a module whose backend is not loaded. The `replacement` object on the Modules rows gains `conflict`.
3. **For good.** The scheduler tick queues one `disable` job for the replacement (requested by `system`, reason `replacement_conflict`) through the same sudo dispatch as a user job, writes an audit row (`custom:module-replacement-conflict-resolved`, with both module ids and the job id) and logs a warning. It skips a pair that already has a queued, dispatched or running disable job and queues at most one job per replacement an hour, so a failing dispatch cannot loop every minute. A failure in this step is logged and never raised. The helper also settles a pair it finds when it runs an enable job.

The 1.17.9 warning that said Core "disables neither" now says what Core does.

### An honoured replacement satisfies a hard dependency (CQ28, amendment 3)

`module_replacement.satisfies_dependency(model, dep_id)` returns the honoured replacement. Only the enabled test is substituted. The version constraint still applies to the replaced module's own installed version, because it stays installed and disabled. Catalogue `dependency_status` rows gain `satisfied_by` (`enabled` stays truthful), `validate_enable` and the install plan no longer raise `disabled_dependency` while the replacement is honoured, and a plan is judged on the modules as they will be after the install. Disabling the replacement is blocked while enabled modules depend on the replaced module, and the existing `cascade` option disables them first. The enable job that switches over does not cascade, because the replacement keeps them satisfied. No module in `modules/` needed a change.

### Server modules can be replaced (CQ30, amendment 4)

The manifest `category` accepts `server` as well as `core`. A reportset still may not declare one. The capability id prefix rule, the registration rule and the enable and install checks apply to both. A module with no category as the target is still `target-not-core` (the code keeps its name for compatibility; the wording changed to "not a core or server module"). A server module cannot declare `replaces`, as a core module cannot. A server module has no Tactical routes, so an honoured replacement of one joins no Tactical owner rule. Core reads the manifest only, never the catalog, so a server module opts in by writing `category: server` in `tec_tac.json`. No existing server manifest changes in this release. API groups for such a module are named `Server module · <name>`.

### `module_status[].replaces` and the browser contract rows (UI request 0.12.88)

Each `module_status` row of `GET /api/tfd/ui/context/` gains `replaces`: the id the manifest declares, or null (also null for a legacy plugin). It is the declared value, not the honoured one, and Core's executor still re-checks honouring on every call. The `ui.authenticated.tactical-operation` row no longer says UI 0.12.87 does not enforce the scoping rule. It now states what UI 0.12.88 does, what the held 0.12.88 review finding still leaves open (calls made through `api`, `apiRaw`, `apiBlob` or `apiText` straight to the executor path), and that Core's own checks are the guarantee until then. The `ui.authenticated.runtime-context` and `ui.authenticated.module-status` rows describe `replaces`.

### The four Lows held from 1.17.10

- **Contract rows.** `replacement_status` and the `modules[].replacement` entry now describe `registered_mismatch`, say that `degraded` is also set by a registration mismatch, and describe `conflict`.
- **A refused registration drops the name.** When a re-registration is refused, Core now removes an earlier registration of the same id by the same module under the capability lock, so the name really stays unavailable (accepted at 1.2.0, refused at 2.0.0). A registration owned by another module is never removed.
- **Release note correction.** The 1.17.10 note said no manifest declares `capabilities`. That was wrong: Endpoints declares `{}` on a core module (see below). The archived note is corrected and now lives in `docs/releases/`.
- **Docs.** `docs/capabilities.md` says `registered_mismatch` covers only replacement version refusals, and that a core or server module's undeclared-id refusal is logged once and nothing else.

## Module-facing changes

All of these are additive. A module that does not use the replacement keys sees no difference.

- `GET /api/tfd/modules/v2/`: `modules[].will_disable` (array of module ids, empty when none), `modules[].dependency_status[].satisfied_by` (id or null), `modules[].replacement.conflict` (boolean).
- Install plan (`POST /api/tfd/modules/v2/packages/inspect/` and bundle previews): `plan.will_disable` and `actions[].will_disable`.
- Request field `disable_replaced` (array of module ids) on `POST /api/tfd/modules/v2/<id>/state/` and `POST /api/tfd/modules/v2/packages/<upload_id>/install/`.
- Error code `replacement_confirmation_required` (HTTP 400, with `detail`, `code` and `will_disable`). It is a refusal, so an old caller still sees one. An ordinary refusal keeps its old shape.
- `GET /api/tfd/ui/context/`: `module_status[].replaces` (string or null).
- Manifest `category: "server"`. A module that writes it must require `framework >=1.17.11`, because older Core rejects the value.
- Jobs: an enable or install job carries `disable_modules`. The scheduler tick can queue a `disable` job with `requested_by: system` and `reason: replacement_conflict`. A job history row for it is expected.
- `module_status` shows a conflicted replacement as not enabled and not active (the effective state).
- Python: `module_replacement.disable_plan`, `install_disables`, `satisfies_dependency`, `conflicted_replacements`, `reconcile_conflicts` and `REPLACEABLE_CATEGORIES`. `replacement_status` gains `conflict`. `validate_enable` returns `will_disable`. `queue_set_enabled`, `queue_v2_install` and `queue_batch_install` gain optional `disable_replaced` and `actor` arguments.
- Scheduler tick output: `replacement_conflicts_queued=N` is appended at the end of the line. Existing fields keep their order.
- `_enabled_dependants` (used by `validate_remove` and the disable check) also lists the enabled dependants of the replaced module when the module is its honoured replacement, marked `via`.
- **Endpoints' empty capability map.** `modules/endpoints/package/extensions/endpoints/tec_tac.json` declares `"capabilities": {}` on a core module. Under the 1.17.10 rule no capability id can be registered by Endpoints. That is harmless today because Endpoints registers none. It becomes a refusal the day Endpoints publishes one, so the request to Endpoints is to drop the key or list each id. It is filed in `reviews/requests/core-modules.md`.
- **Licensing.** A premium module that replaces Licensing (a server module) is honoured for capabilities and hard dependencies, but it does not take over Licensing's `core/codesign/` route. That route stays with Licensing's named exception.

## What was not exercised here

Django and Tactical are not installed on the development PC. These run only against stubs and are not proven until the dev server runs them:

- the bootstrap drop against a real Tactical start-up, the scheduler tick as a real management command, the real sudo dispatch of the system job, and the audit rows reaching Tactical's AuditLog;
- the root helper as root (real root-owned files, `flock`, the real reload and the Celery restart). Its pure rules, the one-write enable, the install ordering and both rollbacks ran against a temporary repo root and state file, and its source is loaded with the Linux-only parts stubbed.

`tests/module-replacement-reconcile-runtime-1.17.11.py` is the dev-server script for the audit write and the dispatch. Run it with `manage.py shell` on a temporary extensions root. It reports PASS or FAIL for each step and touches no real module, job or state file.

## Tests

- New: `tests/module-replacement-enable-1.17.11.py`, `module-replacement-install-1.17.11.py`, `module-replacement-helper-1.17.11.py`, `module-replacement-conflict-1.17.11.py`, `module-replacement-dependency-1.17.11.py`, `module-replacement-server-1.17.11.py`, `module-replacement-server-owner-1.17.11.py`, `module-status-replaces-1.17.11.py`, `module-replacement-held-lows-1.17.11.py`, and the dev-server script above.
- Changed by design: `tests/module-replacement-1.17.9.py` (enabling or installing a replacement next to its enabled core module is no longer a refusal; it names the module instead) and `tests/browser-contract-ui-helpers-1.17.10.py` (the stale "does not enforce" wording must be gone).
- Re-run and unchanged: `module-replacement-capabilities-1.17.9.py`, `module-replacement-owner-1.17.9.py`, `module-replacement-registration-1.17.10.py`, `browser-contract-runtime-surface-1.17.2.py`, `tactical-permission-context-1.17.7.py`.

## Questions for Johan

Filed in `reviews/questions/core.md` with the assumption each was built on: how Core knows a module is a server module (CQ31, built as `category: server` in the manifest), whether enabling the replaced module should disable its enabled replacement (CQ32, built as a refusal), and what happens to dependants when the replacement is disabled (CQ33, built as a block with `cascade`).
