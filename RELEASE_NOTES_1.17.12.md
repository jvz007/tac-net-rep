# Tec-Tac Framework 1.17.12

Switching between a core or server module and the premium module that replaces it now works in both directions, in one job. Enable the replaced module and Core switches its replacement off, after you confirm twice. Disable the replacement and Core switches the replaced module back on. Audit rows now describe what happened, not what was asked.

Closes: the "AD-20 hand-back" entry in `reviews/requests/core.md` (Johan's answers to CQ32 and CQ33, 9 October 2026), the "ui.authenticated.tactical-operation row after UI 0.12.89" entry, and the two findings held from the 1.17.11 review: the helper-side reconcile that wrote no audit row (Medium) and the audit row written at queue time before anything had changed (Low).

## What changed

### Enabling the replaced module switches its replacement off (CQ32)

Before 1.17.12, enabling a core or server module while its replacement was enabled was refused with "Disable X first". Now Core names the replacement, asks twice, and switches it off in the same job.

- **Names it.** `modules[].will_disable` on the replaced module now lists its enabled replacement(s). A new row field, `modules[].second_confirmation_required`, is true for that case, so the UI knows before it asks. `module_replacement.enable_problems` no longer reports the "Disable X first" `replacement_conflict` for this direction.
- **First confirmation.** The request field `disable_replaced` must equal `will_disable` exactly. Otherwise the answer is the existing HTTP 400, `code: replacement_confirmation_required`, with the fresh list. This is the 1.17.11 behaviour, unchanged.
- **Second confirmation.** After the list is right, the request must also carry `confirm_replacement_switch: true`. If it does not, the answer is HTTP 400 with `code: replacement_second_confirmation_required`. The payload carries `detail` (plain English, naming the replacement and saying it will be switched off), `will_disable`, and `module` (the id being enabled). A value that is not true or false is a plain 400 refusal. `false` counts as missing.
- **One confirmation for a replacement.** Enabling a replacement, which disables the replaced module, keeps its single 1.17.11 confirmation and never needs the second flag.
- **Dependants block it, with no cascade.** If an enabled module hard-depends on the replacement that would be switched off, Core refuses the enable and lists them (problem type `replacement_has_dependants`). You disable those modules first. A dependant of the replaced module itself is not affected: that module is the one coming on.
- **The job.** It carries `disable_modules` (the replacements) and `replacement_confirmed: true`. Two queued jobs cannot both pass, because the pending-job model already applies `disable_modules`.
- **The root job helper checks again.** `plan_enable_disables` no longer refuses because another module replaces the target. It adds that replacement to the modules it disables. It still re-checks every rule from root-owned manifests, still requires the computed disables to sit inside the confirmed list, and now requires `replacement_confirmed` to be exactly true when the list holds a replacement of a module being enabled. Otherwise the job fails with nothing changed. A forged web request therefore cannot switch a replacement off. One state write carries both flags, and the existing rollback (`restore_enabled_flags`, then a resync) covers a failed runtime sync.
- **No drift.** The helper's copy of the rule and Core's copy are held to the same answer by the drift-guard matrix, which this release extends.

### Disabling a replacement switches the replaced module back on (CQ33)

- **Plan.** `module_replacement.hand_back_plan` returns the replaced module only when the disabled module declares `replaces`, is enabled, the target is installed and is a core or server module, the target is disabled, and no other enabled module replaces it. When both are enabled (the reconcile case) it returns nothing.
- **Visible.** `modules[].will_enable` names the module that comes back. New `validate_disable()` reports it with any reason it cannot.
- **No confirmation.** Johan asked for a warning on the enable direction only. The UI names the module that comes back.
- **Refused if it cannot come back.** Core checks that the replaced module can be enabled with the replacement off: its own dependencies, versions and runtime requirements. If not, the disable is refused with a plain-English reason and nothing changes, so you are never left with both modules off. This was an assumption (see "Questions for Johan").
- **Dependants.** Dependants of the replaced module stay satisfied throughout, so they no longer block the disable. Dependants of the replacement itself still need `cascade`.
- **The job.** It carries `enable_modules`. The pending-job model applies it, so a second queued job sees the state after the first.
- **The root job helper.** New `apply_disable_job` writes the disable flags and the replaced module's enabled flag in one state write under the lock. It re-reads root-owned manifests and re-checks that each module it enables is the replaced module of a replacement the job disables, is a core or server module, is disabled now, and has no other enabled replacement. The enables must sit inside the job's `enable_modules`. If the runtime sync fails, it restores both flags and syncs again, as the enable branch does. A plain disable with no hand-back behaves as before, including its lack of a rollback.
- **The reconcile job never hands back.** The replaced module is already enabled in that state.
- **Jobs show what happened.** A job row now carries `disabled_modules`, `enabled_modules` and `reconciled_modules` once the helper has run it.

### Audit follows what happened (held from 1.17.11)

- **Queue time.** The row written when a job is queued is now a request: `custom:module-replacement-switch-queued`, "Module X was asked to switch: job J will disable A and enable B". It is written for every job that carries `disable_modules` or `enable_modules`: enable, disable, and the install paths. It claims no change.
- **Outcome rows.** `module_replacement.audit_finished_jobs()` runs from the scheduler tick, in the same never-raises pattern as `reconcile_conflicts`. For a succeeded job it writes one row per module in `disabled_modules` (`custom:module-replacement-disabled`), `enabled_modules` (`custom:module-replacement-enabled`) and `reconciled_modules` (`custom:module-replacement-conflict-resolved`). That last one closes the Medium: the helper-side reconcile now has a row. For a failed job that had a planned list, it writes `custom:module-replacement-switch-failed`, which says whether the flags were put back or nothing changed, with the stage and error. The actor is the system service. The metadata carries `job_id`, `requested_by`, `replacement` and `replaced`.
- **Safe to repeat.** It looks only at jobs finished in the last 7 days, at most 200 per tick, newest first. Before it writes a row it looks for one with the same action, object and `job_id` in Tactical's audit log, so a second tick never duplicates it. If that lookup fails, it writes nothing and tries again on the next tick. The reconcile job keeps its single queue-time row. Nothing raises.

### Contract row wording: `ui.authenticated.tactical-operation` after UI 0.12.89

The row no longer says calls straight to the executor path are scoped only from the UI release that closes the finding. It now says what UI 0.12.89 does: `api`, `apiRaw`, `apiBlob` and `apiText` refuse a tactical-operations path for an id other than the module's own or the one it replaces. The replaced id is a snapshot taken before any `register()` runs. The guard is a helper-level guard, not a sandbox against a module that calls `fetch` itself, so Core's own checks stay the authority. A path hidden behind tab, CR, LF or other control characters is stated as a finding held for the UI, not as fixed. `docs/tactical-operations.md` carries the same sentence. Wording only. It needs UI 0.12.89, which is signed on `dev`.

## Module-facing changes

All of these are additive. One behaviour changes: enabling the replaced module next to its enabled replacement is no longer refused for that reason (Johan, CQ32). An old caller that sends no list, or a list but no second flag, gets a refusal and nothing changes. No module in `modules/` declares `replaces`, calls `GET /api/tfd/modules/v2/`, sends `disable_replaced`, reads `will_disable` or imports `tec_tac.module_replacement`, so no module needed a change.

- `GET /api/tfd/modules/v2/`: new `modules[].second_confirmation_required` (boolean) and `modules[].will_enable` (array of module ids). `modules[].will_disable` also names the enabled replacement(s) of a disabled core or server module (same field, new meaning for the replaced module).
- Request field `confirm_replacement_switch` (boolean) on `POST /api/tfd/modules/v2/<id>/state/`.
- Error code `replacement_second_confirmation_required` (HTTP 400, with `detail`, `code`, `will_disable` and `module`). Problem type `replacement_has_dependants` (a plain 400 refusal that names the dependants). A disable that cannot hand back is a plain 400 refusal that says why.
- Jobs: `GET /api/tfd/modules/v2/jobs/` rows carry `disabled_modules`, `enabled_modules` and `reconciled_modules` (additive). The request fields `disable_modules`, `enable_modules` and `replacement_confirmed` are not exposed. A disable job can now carry `enable_modules`, and an enable job `replacement_confirmed`.
- Audit action names: `custom:module-replacement-switch-queued` replaces `custom:module-replacement-disabled` as the queue-time row. `-disabled`, `-enabled`, `-conflict-resolved` and `-switch-failed` are outcome rows written by the scheduler tick within about a minute of the job finishing. No module in `modules/` reads these names.
- Python: `module_replacement.replacements_of`, `switches_replacement`, `hand_back_plan`, `audit_switch_queued` and `audit_finished_jobs` are new. `audit_replaced_disabled` is gone (it was never a published contract). `module_manager_v2.validate_disable` is new, and `queue_set_enabled` gains an optional `confirm_replacement_switch` argument. `ModuleReplacementSecondConfirmationRequired` is a subclass of `ModuleManagerV2Error`, so code that catches that error still sees a refusal.
- Scheduler tick output: `replacement_audit_rows=N` is appended at the end of the line. Existing fields keep their order.
- Contract rows (`contracts.py`) and `docs/module-replacement.md` ("Hand back" rewritten, with an audit table) describe all of this.

## Questions for Johan

Filed in `reviews/questions/core.md` with the assumption each was built on: CQ34 (disabling a replacement when the replaced module cannot be enabled, built as a refusal), CQ35 (enabling the replaced module when other modules depend on its replacement, built as a refusal with no cascade) and CQ36 (whether disabling a replacement needs a confirmation, built as none). A low-stakes note records the new audit row names. After the dev server runs 1.17.12, export a fresh contract into `docs/contracts/`.

## What was not exercised here

Django and Tactical are not installed on the development PC. These ran only against stubs, and are not proven until the dev server runs them:

- the AuditLog JSON lookup that stops a duplicate row, the real audit write, and the scheduler tick as a real management command;
- the real sudo dispatch of a hand-back job;
- the root helper as root (real root-owned files, `flock`, the real reload).

The helper's rules, one-write changes and rollbacks ran against a temporary repo root and state file, with the source loaded and the Linux-only parts stubbed. `tests/module-replacement-handback-runtime-1.17.12.py` is the dev-server script. Run it with `manage.py shell`. It reports PASS or FAIL for each step on a temporary extensions root, and touches no real module, job or state file.

## Tests

- New: `tests/module-replacement-handback-1.17.12.py` (the Core side of both directions, the two confirmations, dependants, refusals, pending jobs, the view), `tests/module-replacement-helper-handback-1.17.12.py` (the root helper for both directions, rollback, state changes after confirmation, and 144 drift-guard scenarios), `tests/module-replacement-audit-1.17.12.py` (queue-time and outcome rows, the window and cap, idempotence, never raising, the tick), `tests/browser-contract-tactical-operation-1.17.12.py` (the reworded row and doc), and the dev-server script `tests/module-replacement-handback-runtime-1.17.12.py`.
- Changed by design, because they asserted the old refusal or the old audit name: `tests/module-replacement-1.17.9.py`, `module-replacement-enable-1.17.11.py`, `module-replacement-server-1.17.11.py`, `module-replacement-helper-1.17.11.py`, `module-replacement-install-1.17.11.py`, `module-replacement-dependency-1.17.11.py` (disabling the replacement hands the module back, so the replaced module's dependants no longer block it) and `module-replacement-reconcile-runtime-1.17.11.py`.
