# Replacing a core or server module (AD-20)

Some premium modules do the whole job of a core or server module and do it better. Advanced Patch Management replaces Windows Patching. Core lets one module take over another's place, safely, without both ever running.

This page is for module authors and administrators. The decision is AD-20 (`docs/review-accepted-decisions.md`). Johan's amendments of 9 October 2026 (Core 1.17.11), the hand-back (Core 1.17.12) and the warnings that replaced two refusals (Core 1.17.14) are marked below.

## The two manifest keys

Both keys are optional and additive. A manifest without them parses and behaves exactly as before. Only an extension may use them. A reportset that declares either is refused.

```json
{
  "id": "patchmanagement",
  "replaces": "patching",
  "capabilities": {
    "patching.windows": "1.2.0",
    "patching.scan": "1.1.0",
    "patchmanagement.extra": "1.0.0"
  }
}
```

| Key | Meaning |
| --- | --- |
| `replaces` | The id of one core or server module this module replaces. Refused on a core or server module and on the module itself. |
| `capabilities` | A map of capability id to `X.Y.Z`: the public contracts the module publishes. Core reads this from the manifest because a disabled module's code is never loaded. A core or server module's ids must begin with its own id and a dot. |

A module that a replacement could target must declare `capabilities`. An empty `{}` is fine for a module that publishes none. A missing key is not: it would let the module hide a contract, so Core refuses to honour any replacement of it.

A module that uses either key must require `framework >=1.17.9`.

### Server modules can be replaced too (1.17.11)

The replaced module may be a core module or a server module. Core reads only the manifest, never the catalog, so a server module opts in by writing `"category": "server"` in its `tec_tac.json`. A module that does this must require `framework >=1.17.11`, because older Core rejects the value. No existing server manifest changes in 1.17.11.

A server module has no Tactical routes. An honoured replacement of a server module still takes over its capability names and satisfies hard dependencies on it, but it joins no Tactical owner rule. That includes Licensing's `core/codesign/` route, which stays with Licensing.

A module with no category is neither. A replacement that names one is not honoured (`target-not-core`).

## When Core honours a replacement

Core works this out from manifests and module state on every call. It never looks at what is registered at run time, so start-up order cannot change the answer. A replacement is honoured only when all five hold:

1. The replacement is enabled.
2. The replaced module is installed, is a core or server module, and is **disabled**.
3. No other enabled module replaces the same module.
4. The replaced module declares `capabilities`.
5. The replacement declares every one of those ids at the **same major version**, with a minor and patch that are not lower. Extra capabilities are fine.

Otherwise the replacement is simply not honoured, and its status says why:

| Reason | What it means |
| --- | --- |
| `replacement-disabled` | The replacement is not enabled. |
| `target-missing` | The replaced module is not installed. |
| `target-not-core` | The module it names is not a core or server module. (The code keeps its old name so existing callers still match it.) |
| `target-enabled` | Both modules are enabled. |
| `competing-replacement` | Another enabled module replaces the same module. |
| `capabilities-undeclared` | The replaced module declares no `capabilities` key. |
| `capability-missing` | The replacement lacks one of the replaced module's capabilities. |
| `capability-major-mismatch` | A capability is at a different major version. |
| `capability-version-lower` | A capability has the same major version but a lower minor or patch. |

`replacement_status(module_id)` returns the status object. It carries:

- `conflict` (1.17.11): true when the replacement and the module it replaces are both enabled.
- `degraded`: true when a declared capability is not registered at run time, and also when `registered_mismatch` is not empty. It is information, never a refusal.
- `registered_mismatch` (1.17.10): one `{capability, declared, registered, reason}` row for each capability the replacement tried to register outside its declared version. Only replacement version refusals are listed here. A core or server module's undeclared id is logged once and nothing else.

## What Core checks at registration (1.17.10, 1.17.11)

Declaring is not the same as registering, so Core compares the two when a module registers a capability. It never raises out of `AppConfig.ready()`. It logs one warning, registers nothing, and the name stays `capability-unavailable`.

- A core or server module that declares `capabilities` registers exactly those ids. A module with no `capabilities` key is unchanged. If Core cannot read module state, it lets the registration through.
- An honoured replacement registers a replaced module's id at the declared major version, with a minor.patch that is not lower. `capability-major-mismatch` and `capability-version-lower` are the reason codes, the same as the parity check.
- Since 1.17.11 a refused registration also removes an earlier registration of the same id by the same module, so the name really stays unavailable (accepted at 1.2.0, refused at 2.0.0). A registration owned by another module is never removed.
- `replacement_status` lists each refused replacement registration in `registered_mismatch`, and `degraded` becomes true. The list lives in the running process and clears on restart.

## Enabling or installing a replacement (1.17.11)

Enabling a replacement used to be refused while the replaced module was enabled. Now Core says which module it will disable, asks you to confirm, and disables it in the same job.

1. Read `modules[].will_disable` from `GET /api/tfd/modules/v2/` for an enable. For an install, read `plan.will_disable` (and `actions[].will_disable`) from the inspect answer. The list is empty when nothing would be disabled.
2. Show the list to the person in plain words, and ask before going on.
3. Send the same list back as `disable_replaced` on `POST /api/tfd/modules/v2/<id>/state/` or `POST /api/tfd/modules/v2/packages/<upload_id>/install/`.

The list must match exactly. If it is missing or out of date, the answer is HTTP 400 with `code: replacement_confirmation_required`, a plain `detail` that names the module, and the fresh `will_disable`. An old caller that sends no list sees a refusal and nothing changes.

The job carries the confirmed list as `disable_modules`. Two queued jobs still cannot both pass, because a queued job's disable counts as done when the next one is checked.

The root job helper does not trust the web side. Under the module-state lock it reads the installed manifests itself (regular, root-owned files under `extensions/` only), runs the same rules again, and requires what it would disable to be inside the confirmed list. Anything else fails the job with nothing changed. It then enables the replacement and disables the replaced module in one state write. If the runtime sync fails, it puts the flags back. An install does the same check after the packages land and before any state is written, disables after the versions are recorded, and re-enables the module if it has to roll back.

Audit follows what happened (1.17.12). When the job is queued, Core writes one row that records the request: module `core`, action `custom:module-replacement-switch-queued`, object the module being enabled, actor the person who asked, message "Module X was asked to switch: job J will disable A". It claims no change. The rows that say what the job did are written after it finishes. See "Audit rows" below.

What still stays refused:

| Action | Problem type |
| --- | --- |
| Enable a replacement while another enabled module replaces the same module | `replacement_conflict` |
| Enable or install a replacement whose target is missing or whose capabilities do not cover the replaced module's | `replacement_incomplete` |
| Install a replaced module and its replacement in the same batch | `replacement_conflict` |

An upgrade of an installed replacement is unchanged. It names nothing. A single local package that would disable a module goes through the v2 worker, because only that worker can disable in the same job.

## If both end up enabled anyway (1.17.11)

A hand-edited state file, or a privileged job that races, can leave both enabled. `module-state.json` is root-owned, so the Tactical process cannot rewrite it. Core never stops Tactical for this, and it acts in three steps:

1. **At load.** The replacement is left out of the modules Core loads. The replaced module loads as normal. Core logs one warning for each pair.
2. **In what the UI sees.** `module_status` reports the replacement as `enabled: false` and `active: false`, so the UI does not load code whose backend is not loaded. The `replacement` object gains `conflict: true`.
3. **For good.** The scheduler tick queues one `disable` job for the replacement (requested by the system, reason `replacement_conflict`), through the same dispatch as a user job. It writes an audit row (`custom:module-replacement-conflict-resolved`, with both module ids and the job id) and logs a warning. This job never hands back: the replaced module is already enabled in that state. It skips a pair that already has a queued, dispatched or running disable job, and queues at most one job per replacement an hour, so a failing dispatch cannot loop every minute. The root helper also settles a pair it finds when it runs any enable job.

Until the job runs, the replacement is not honoured: it gets no routes and no capability names. The replaced module keeps both.

## Hard dependencies (1.17.11)

A module can list the replaced module's id in `dependencies`. While a replacement is honoured, it satisfies that dependency. Only the enabled test is substituted. The version constraint still applies to the replaced module's own installed version, because it stays installed.

- Catalogue rows gain `dependency_status[].satisfied_by`: the replacement's id, or null. `enabled` stays truthful.
- Enabling a dependant, and an install plan that includes one, no longer raise `disabled_dependency` while the replacement is honoured. A plan is judged on the modules as they will be after the install.
- Disabling the replacement used to be blocked while enabled modules depended on the replaced module. Since 1.17.12 it switches the replaced module back on in the same job (see "Hand back"), so those dependants stay satisfied throughout and do not block it. A dependant of the replacement itself still needs the `cascade` option. The enable job that switches over does not cascade, because the replacement keeps those modules satisfied.

## What changes while a replacement is honoured

- **Tactical routes.** The replacement joins the owners of every Tactical operation rule the replaced core module owns, and of no other. For Windows Patching that is `winupdate/` and `automation/patchpolicy/`. Core refuses everything else to it. A server module has no routes, so a replacement of one joins none. See `docs/tactical-operations.md`.
- **Capability names.** The replacement may register the replaced module's capability ids, only the ones it declares. Consumers keep calling the same names and get whichever module is installed (`docs/capabilities.md`).
- **Hard dependencies.** See above.
- **Catalogue.** Rows from `GET /api/tfd/modules/v2/` carry `replaces`, `replacement` (the status object), `replaced_by` and `will_disable`. Since 1.17.12 they also carry `will_enable` and `second_confirmation_required` (see "Hand back").
- **Browser rows.** Each `module_status` row of `GET /api/tfd/ui/context/` carries `replaces` since 1.17.11: the declared id, or null. It is the declared value, not the honoured one, and Core's executor re-checks honouring on every call. UI 0.12.88 reads it to scope `tacticalOperation` to the AD-20 module the caller replaces. See `docs/tactical-operations.md`.

## Hand back (1.17.12)

Handing back works in both directions, in one job, with the same rollback and audit as an enable. Johan decided it on 9 October 2026 (CQ32 and CQ33). The two modules are never both enabled, and you never have to remember the order.

### Enabling the replaced module while its replacement is enabled

Before 1.17.12 Core refused this and said "Disable X first". Now Core names the replacement, asks twice, and switches it off in the same job.

1. Read `modules[].will_disable` from `GET /api/tfd/modules/v2/` for the replaced module. It now names the enabled replacement. `modules[].second_confirmation_required` is true, so the UI knows before it asks.
2. Show the list and ask. Send it back as `disable_replaced` on `POST /api/tfd/modules/v2/<id>/state/`. If the list is missing or out of date, the answer is HTTP 400 with `code: replacement_confirmation_required` and the fresh `will_disable`. This is the first confirmation, and it works as it did in 1.17.11.
3. Show a warning that names the replacement and says it will be switched off. Send `confirm_replacement_switch: true` as well. If the list is right but the flag is missing or false, the answer is HTTP 400 with `code: replacement_second_confirmation_required`, a plain `detail`, the fresh `will_disable` and `module` (the id being enabled). A value that is not true or false is a plain 400 refusal with no code.

Enabling a replacement keeps its single confirmation. It never needs the second flag.

Since 1.17.14 (CQ35) an enabled module that depends on the replacement no longer stops the enable. Core warns instead. See "Warnings instead of refusals (1.17.14)". Until 1.17.14 Core refused with the problem type `replacement_has_dependants`; that type is gone.

The job carries `disable_modules` (the replacements to switch off) and `replacement_confirmed: true`. Two queued jobs cannot both pass, because a queued job's changes count as done when the next one is checked.

The root job helper checks all of this again from root-owned manifests and the root-owned copy of the job. It adds the enabled replacement to what it disables, requires that to sit inside the confirmed list, and requires `replacement_confirmed` to be exactly true when the list holds a replacement of a module being enabled. Otherwise the job fails with nothing changed. Both flags change in one state write. If the runtime sync fails, it puts both back and syncs again.

### Disabling a replacement

Disabling an enabled replacement now switches its replaced module back on in the same job. No confirmation is needed: Johan asked only for a warning on the enable direction, so the UI names the module that comes back.

- `modules[].will_enable` names it. It is set only when the replaced module is installed, is a core or server module, is disabled, and no other enabled module replaces it. It is empty when the replaced module is already enabled (the "both enabled" case), so that case is never "handed back".
- The job carries `enable_modules`. Core checks that the replaced module can be enabled with the replacement off: its own dependencies, versions and runtime requirements. In 1.17.12 and 1.17.13 a module that could not come back made Core refuse the disable. Since 1.17.14 (CQ34) Core warns and asks you to confirm instead. See "Warnings instead of refusals (1.17.14)".
- Dependants of the replaced module stay satisfied throughout and do not block the disable. Dependants of the replacement still need `cascade`, as before.
- The root helper re-checks each module it would enable: it must be the replaced module of a replacement the job disables, a core or server module, disabled now, and have no other enabled replacement. It makes the disable and the enable in one state write. If the sync fails, it puts both flags back and syncs again.
- The reconcile job from "If both end up enabled anyway" never hands back.

Removing (uninstalling) a replacement does not enable the replaced module. It stays disabled until someone enables it.

### Job fields

A job row from `GET /api/tfd/modules/v2/jobs/` carries `disabled_modules`, `enabled_modules` and `reconciled_modules` once the root helper has run it. Since 1.17.14 a disable job also carries `hand_back_skipped`, the replaced modules a confirmed disable left off. They are additive and absent on older jobs. The request fields (`disable_modules`, `enable_modules`, `replacement_confirmed`) are not exposed.

### Audit rows

Audit follows what happened. Every row is module `core`, object type `module`, and non-strict (a failed write is logged and never stops a job).

| When | Action | Actor | Says |
| --- | --- | --- | --- |
| The job is queued | `custom:module-replacement-switch-queued` | the person who asked | "Module X was asked to switch: job J will disable A and enable B". A request, not a change. Written for every job that carries `disable_modules` or `enable_modules`: enable, disable, and the install paths. Since 1.17.14 it also names the modules the request confirmed to leave off (`hand_back_skipped` in the metadata), and is written for a disable that skips a hand-back even when nothing is switched on. |
| The job succeeded | `custom:module-replacement-disabled` | system service | A module in `disabled_modules` was switched off. |
| The job succeeded | `custom:module-replacement-enabled` | system service | A module in `enabled_modules` was switched back on. |
| The job succeeded (1.17.14) | `custom:module-replacement-disabled` | system service | For a disable job with `hand_back_skipped`: "Replacement X was disabled. The module it replaces, Y, stayed off because it cannot be enabled." Object the replacement. |
| The job succeeded | `custom:module-replacement-conflict-resolved` | system service | A replacement in `reconciled_modules` was found enabled next to its replaced module and disabled by the helper. |
| The job failed | `custom:module-replacement-switch-failed` | system service | A failed job that had a planned list. The message says whether the flags were put back or nothing changed, and gives the stage and the error. |

The outcome rows come from `module_replacement.audit_finished_jobs()`, which the scheduler tick calls every minute, so a row appears within about a minute of the job finishing. Each row's metadata carries `job_id`, `requested_by`, `replacement` and `replaced`.

The sweep is bounded and safe. It looks at jobs that finished in the last 7 days and at most 200 jobs a tick, newest first. Before it writes a row it looks for one with the same action, object and `job_id` in Tactical's audit log, so a second tick never duplicates a row. If that lookup fails, it writes nothing and tries again next tick. It never raises, and the reconcile job keeps its single queue-time row (`custom:module-replacement-conflict-resolved`) rather than getting a second one.

## Categories (AD-21, 1.17.13)

Core 1.17.13 reads the manifest category (`core`, `server`, `premium`, `test`; see `docs/module-categories.md`).

- A replacement must be `premium`. A replacement with no category (which counts as `test`) is honoured on a development server only, so a
  replacement that has not shipped a category still works on the dev server. Off a development server the status reports the reason
  code `replacement-category`, with a plain-English message, and the module does not own the replaced module's routes or capabilities.
- A module that writes `test` may not declare `replaces`. The registry refuses the manifest.
- The capability prefix rule stays for `core` and `server` only. A `premium` module publishes the same capability names as the module
  it replaces (AD-20), so it cannot follow a prefix rule.
- The root job helper carries the same rule and checks it again from root-owned manifests and the root config. A drift test runs both
  over one scenario matrix.
- A manifest that writes `premium` or `test` must require `requires.framework` of `>=1.17.13`.

The reason code is added to `replacement.reason` in module status, and to the enable and install problems of type
`replacement_incomplete`. Additive.

### Audit rows (1.17.13)

Every row Core writes for a module switch now carries the correlation id `module-replacement:<action>:<job id>`, where `<action>` is the
audit action without its prefix (`disabled`, `enabled`, `conflict-resolved`, `switch-failed`, `switch-queued`). The audit writer replaces
oversized metadata but never drops the correlation id, so the outcome sweep always finds a row it has written. It still finds a row from
1.17.12 by its `metadata.job_id`. The switch-failed row cuts the error to 300 characters and the planned list to 10 ids.

The root helper records what actually happened when a switch fails. `rolled_back` is set only after the flags were put back.
`rollback_error` is set when putting them back raised. The row says "The flags were put back as they were." only for the first. For the
second it says Core could not put the flags back and the operator must check the Modules page. A failure at the runtime-sync or rollback
stage with neither field (including a job file from 1.17.12) says the outcome is not confirmed. A failure before any change says
"Nothing was changed." The row metadata carries `rolled_back`: true, false or null.

## Warnings instead of refusals (1.17.14)

Johan answered CQ34 to CQ36 on 9 October 2026. Two refusals became warnings, and a failed module job now tells people. Nothing here changes AD-20 condition 3: a replacement still has to publish every contract of the module it replaces, and that is what keeps other modules working.

### Disabling a replacement whose replaced module cannot come back (CQ34)

Core no longer refuses. It works out who can come back and who cannot.

- `modules[].will_enable` lists only the modules that can come back.
- `modules[].hand_back_unavailable` lists the others: `[{module, reasons[], required_modules[]}]`. `reasons` is plain English: a missing or disabled dependency, a version that does not fit, a runtime requirement, or a module that cannot be managed from the UI. `required_modules` names the modules behind the missing, disabled or out-of-range dependency, so you can tell the person what is needed.
- `modules[].hand_back_confirmation_required` is true when that list is not empty.

The first `POST /api/tfd/modules/v2/<id>/state/` with `enabled: false` is answered with HTTP 400, `code: replacement_hand_back_confirmation_required`, a plain `detail`, `module`, `will_enable` and `hand_back_unavailable`. Nothing is queued. Send the request again with `confirm_without_hand_back: true` to go ahead. Only `true` confirms: `false` is the same as missing, and any other type is a plain 400. The job then disables the replacement and hands back only what can come back. `enable_modules` holds that filtered list, so the root helper is unchanged and still re-checks every rule. The job records `hand_back_skipped` (the ids left off), the queue-time audit row names them, and the outcome row says the module stayed off.

An old caller that sends no flag sees a refusal and changes nothing. Core does not offer to install a missing module: the module catalogue is not online, so the warning only names the module that is needed.

### Enabling a replaced module whose replacement has dependants (CQ35)

Core no longer refuses. The catalogue row of the replaced module carries `replacement_dependants`: `[{replacement, modules[]}]`, the enabled modules that name the replacement directly in `dependencies`. Modules that depend on the replaced module are not listed. It is the module coming back, and the replacement's contract parity keeps the others satisfied. The `replacement_second_confirmation_required` answer carries the same list as `dependants`, so the warning appears in the confirmation you already show. Nothing cascades and nothing is disabled beyond the confirmed list. The job and the root helper are unchanged.

### A deliberate disable always hands back (CQ36)

Hand-back belongs to a deliberate disable job only. It never happens on a rollback, a failed job, a reconcile job (`reason: replacement_conflict`) or a fault. Since 1.17.14 it also covers a replacement that is disabled as part of a deliberate cascade (it depends on the module being disabled): the replaced module is handed back too, with no extra confirmation. Uninstalling a replacement hands back too since 1.17.15 (CQ43); see the next section.

### A failed module job tells people (CQ36, CQ41)

The scheduler tick (`module_failure_notices.sweep_failed_jobs`) stores one notice for each failed module job: enable, disable, install, bundle install and batch install. It is a normal Core notice (`tec_tac.notices.publish_system_notice`): source `core`, level `error`, title "Module job failed", `client_id` `module-job-failed:<job id>`, and an action that opens `/modules`. The text is plain English with no paths. A failed switch says whether the flags were put back, from what the root helper recorded.

- Recipients: every active superuser (a Django superuser or a superuser role), plus the user who started the job when that user is active. Installer and agent accounts never receive one. This is the smallest audience, and it is Johan's question CQ41 if he wants more.
- One notice per job and person. The next tick does not store it again, and a notice that has been read stays read.
- It looks only at jobs finished in the last 7 days, at most 200 a tick, newest first, and never raises.
- The browser toast for a new server-created notice is a UI change. Until it ships the notice appears in the notice history.

### Uninstalling a replacement hands back (CQ43)

Since 1.17.15 an uninstall of an enabled replacement hands the replaced module back by the same rules as a disable, with the same confirmation (`confirm_without_hand_back: true`) when the replaced module cannot come back. The job records `enable_modules` and `hand_back_skipped`.

Since 1.17.16 the outcome audit rows follow. For each module that came back, Core writes the audit action `custom:module-replacement-enabled` ("Module X was enabled again because its replacement Y was uninstalled"). When a confirmed uninstall left a module off, Core writes one more row (`custom:module-replacement-disabled`), with the same metadata as the disable case (`replacement`, `replaced`, `hand_back_skipped`): "Replacement Y was uninstalled. The module it replaces, X, stayed off because it cannot be enabled." Before 1.17.16 that row was written for a disable only. Rows are written once per job id.

## What this does not do

- It adds no general `conflicts_with` key. AD-20 decides replacement only.
- There is no allow-list of which module may replace which. The guards are signed packages, an operator confirming what gets disabled, full capability parity, and routes limited to the replaced module's own rules.
- Core does not choose between two replacements. It refuses the second.
