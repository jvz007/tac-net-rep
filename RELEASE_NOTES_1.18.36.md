# Tec-Tac Framework 1.18.36

Date: 21 November 2026. Core can now run the fixed-template command row for Software Repository, so its deploys can run unattended. Communicator stays on a legacy path, so the installed 0.6.17 keeps working. `main` stays held.

## Module-facing change

`core.system_actions` stays at 1.6.0. Everything below is additive. Communicator's registration, schedule and run behave as in 1.18.35.

**The row `agent.command` (registered by `remote-background`, unchanged):**

- New accepted caller and registrant: `softwarerepository`. It registers its fixed templates from `AppConfig.ready()` with `register_command_template(...)`. The default right is now `softwarerepository.deploy`.
- `communicator` moves to `legacy_callers`. It is still accepted as registrant and caller, with the same rights as before. The contract metadata now reads `callers: ["softwarerepository"]` and `legacy_callers: ["communicator"]`, plus `legacy_callers_reason`, `rights_by_module` and `one_module_per_schedule`.
- `register_command_template(..., right=None)`: `None` means the module's base right. A right of another module is refused. Communicator passes `right=` itself, so its registrations do not change.
- Rights are per module. `softwarerepository`: `softwarerepository.deploy`. `communicator`: `communicator.send`, `communicator.reboot`. The confirmed `rights` must hold the module's base right and nothing from another module.
- One module per schedule. Every id in `allowed_templates` must belong to one module, and that module must be the one that owns the schedule. Otherwise creating the schedule is refused `bad_parameters`.
- At run time a template that belongs to another module than the verified caller is refused `action_not_allowed`, before the claim and before anything is sent. So Software Repository cannot name a Communicator template, and cannot attest a Communicator right.
- Audit rows: `run_as` now names the calling module (it was always `communicator`). New additive key `caller_module`. The 'before' message reads "Run as the softwarerepository module for ...". Communicator rows are the same as before. No row holds the command text, the output, the token or the host.
- The service user `tectac-communicator` serves both callers. It is not renamed. Its refusal text now reads "The command service user (tectac-communicator) is not installed ...".
- Software Repository requires framework >= 1.18.36.

**What Software Repository must plan for (typed slots, unchanged by this release):**

- An int slot is limited to -10^9 to 10^9. A package size above about 953 MiB does not fit. Carry the size in a text slot with `chars` of `0123456789`.
- A text slot never starts with `-` or `/`, has no spaces unless the spec says so, and excludes `=` and other shell characters. A grant token must be hex or URL-safe without padding. The module's own tests must prove its token fits.
- A template runs for 1 to 60 seconds. Core hashes the template; a changed template needs a new confirmation (`template_changed`).

**One thing the module must know about the Scheduler.** The Scheduler keeps one scheduled action per id. The id of this row is `remote-background.command`. While Communicator 0.6.17 holds that id, a second module's `register_scheduled_action` for it is refused ("already registered"). This is how the Scheduler already worked; nothing here changes it. So Software Repository's Schedule release needs Communicator 0.6.17 disabled or removed on that server. The new integration test pins this. See Assumptions.

## Closes

- ORDER "Core next patch, the command row" (Johan, 21 November 2026, plan B1): step 2 (softwarerepository as trusted registrant and caller) and step 1 (retire communicator, with the compatibility path the order asks for). The release manager removes the entry, naming 1.18.36.
- The 7 November 2026 request "Scheduled deploys for softwarerepository: unattended fixed-template command". The release manager removes it, naming 1.18.36.
- Not a Core change, information for the release manager: the held Low of the 1.18.34 review (chunk refusal rows without `params`) is resolved by remote-background 0.11.5, which passes `params` already.

## What changed and why

**AD-13 check (recorded as information in `reviews/questions/core.md`).** CQ175 and AD-46 list commands and uninstall of a software package among the schedulable rows, "each with the strictest guards ... built only when its owning module asks for it". AD-60 (7 November 2026) J2 signs fixed module scripts (extending AD-49) and J3 says scheduled, unattended installs are to be built. Johan's 7 November widening says the module is the authority for sending the commands. That covers exactly one Software Repository fixed-template command, so it is built. It adds no new trusted purpose: same row, same service user, same guards, fixed templates only, no free text through Core.

**Why a second caller is not a one-line change.** The row's allow-list was one tuple. But the rights were Communicator-only, and `resolve` never checked that a template belongs to the calling module. With one caller that was harmless. With two, a Software Repository schedule could name Communicator templates and attest Communicator rights. So this release adds the per-module rights table, the one-module-per-schedule rule and the template-belongs-to-caller check, at creation and at run time.

1. **`system_commands.py`.** `CALLERS`, `LEGACY_CALLERS`, `REGISTRANTS = CALLERS + LEGACY_CALLERS`, `RIGHT_DEPLOY`, `RIGHTS_BY_MODULE`, `BASE_RIGHT`. `RIGHTS` stays as the Communicator pair. `register_command_template` resolves `right=None`. `parameters()` requires one module and that module's rights. `resolve(command, cleaned, caller=None)` refuses a template of another module. New `templates_belong_to(cleaned, module_id)`. `_meta` and the 'before' message name the caller. The service-user text names the command service user.
2. **`system_actions.py`.** The row now has `callers=_sc.REGISTRANTS`. `_run` passes `caller=identity.module_id` to `resolve`. The contract metadata gains the keys above.
3. **`system_action_confirmation.py`.** After `validate_parameters`, a command row also checks `templates_belong_to(cleaned, action.module_id)`. A failure is `bad_parameters`. The check uses `entry.callers` to recognise a command row, because an older pin (`delegated-targets-task-only-1.17.74.py`) keeps the name `KIND_COMMAND` out of this file.
4. **Contract text and docs.** `contracts.py` (the `run_system_command` purpose text) and `docs/system-actions.md` name both callers, the per-module rights and `legacy_callers`.

A person-started Software Repository deploy needs no Core code. It runs as a one-off Scheduler run of the same action, so the same checks apply.

Plan corrections found in the code: `system_actions.py`, `tests/release-integrity.sh` and the 1.17.75 tests are LF, not CRLF (kept as they are). The plan did not mention the Scheduler's one-action-per-id rule (above). The old 1.17.75 integration test had stopped running on this PC because it faked neither route guard added in 1.17.79 and 1.17.84; two stub lines fix that.

## Assumptions

- **Communicator on a legacy path, not cut.** The installed 0.6.17 still registers three templates and the catalogue says it keeps working on dev02. Dropping it later is one constant (`LEGACY_CALLERS = ()`) plus the Communicator tests. Only Johan lifts that hold (AD-54, seventh amendment, correction of 29 October 2026).
- **Rights attested by the module.** Core cannot read a module permission. Software Repository attests `softwarerepository.deploy` in the confirmed `rights`. Core checks it against the template's right and the one-module rule, and re-checks that the owner exists and is active at every run.
- **The size stays in a text slot.** No Core change to the int bound. We widen a validation range only when a module needs it.
- **The service user is not renamed.** A rename needs a migration and changes to every Communicator-era test and doc. It is not in the order.
- **Scheduler one-id rule left alone.** Making the scheduled-action registry per module and id would be a wider Scheduler change that touches runs, schedules and the worker. The safe result today is a refused registration, never a cross-wired handler. Recorded in `reviews/questions/core.md`.

## Retired or changed checks

- `tests/system-command-1.17.75.py`: the row pin `callers=("communicator",)` now reads `callers=_sc.REGISTRANTS`.
- `tests/system-command-integration-1.17.75.py`: the `resolve` spy accepts the new `caller` keyword; the route and view guards are stubbed (they need Tactical's urls).
- `tests/version-1.18.35.py` moved to `tests/legacy/`. `RELEASE_NOTES_1.18.35.md` moved to `docs/releases/`.
- `tests/release-integrity.sh` also runs the two new tests.

## New tests

- `tests/system-command-callers-1.18.36.py` (no Django; `system_commands.py` loaded alone): the constants and the row text; registration (default right, a right of another module, an unknown module, a caller that is not the module it names, Communicator unchanged); `parameters` (accepted and refused cases, mixed modules, the Communicator cases unchanged); `resolve` (both directions `action_not_allowed`, `permission_lost`, token, SHA-256, size and host slots, limits, `template_changed` on a changed file); `templates_belong_to`; the audit rows for both modules (names the caller, no command, token, host or output); the contract and docs text.
- `tests/system-command-callers-integration-1.18.36.py` (the Scheduler harness, real `_run`, `resolve`, `run_one`, creation checks): each module creates its schedule and runs it; the rows name the module; mixed-module schedules are refused when made; a stored mixed schedule is refused at run time before the claim; the registrant and unrelated modules cannot schedule the row; the metadata; the one-scheduled-action-per-id limit.
- `tests/version-1.18.36.py`: release bookkeeping.

## What could not be run here

Django, Tactical and Celery are not installed on this PC. The scheduler, the worker task, the real `send_raw_cmd` dispatch and the module registry could not run for real. The tests use the stub harness and source checks. Dev02 proves the live path.

Already failing before this release, with the same errors with and without it: `tests/system-command-1.17.75.py`, `system-command-1.17.79.py`, `system-command-failed-reason-1.17.82.py` and `-1.17.83.py` (they need `django.urls`), `system-command-worker-schedule-1.17.77.py` (`('client', {}, [])`) and `delegated-targets-compat-1.17.74.py` (reads the `modules/` tree). `ruff check` on the changed files reports the same 21 findings as before; none is on a changed line.

## Johan dev02 checklist

You need Core 1.18.36 on dev02 with Communicator 0.6.17 still installed.

1. Update dev02 to Core 1.18.36 and check the version.
   - PASS: `VERSION` and the package say 1.18.36 and Core starts with no error in the log.
   - FAIL: the update stops or Core does not start. Send the update log.
2. Export the public contract (or open the `core.system_actions` contract view) and read the `command` section.
   - PASS: `callers` shows `softwarerepository` and `legacy_callers` shows `communicator`.
   - FAIL: `callers` still shows only `communicator`. Send the section.
3. Restart Tactical and search the Core log for "Command template".
   - PASS: no line says a template "is refused".
   - FAIL: Communicator's templates are refused. Send those log lines.
4. With Communicator enabled, create one Communicator background send as you did before and let it run.
   - PASS: it runs and the run shows `ran`.
   - FAIL: the Scheduler run shows `permission_lost` or `action_not_allowed`. Send the run and the audit rows.
5. Open the Audit page and find the 'before' row of that send.
   - PASS: it shows `run_as` and `caller_module` both `communicator`, and no command text.
   - FAIL: either key is missing or wrong, or the command text appears. Send the row.
6. Software Repository has nothing to test until its release that turns Schedule on. That release needs Communicator 0.6.17 disabled or removed on the server first (see Module-facing change).
   - PASS: nothing to do now.
   - FAIL: not applicable.

## Exit list

- Both callers, per-module rights, one-module-per-schedule, the caller check at creation and run time, `legacy_callers`, `caller_module`, contract text, docs, tests: done.
- Signing, review, dev02 install and a fresh public contract export: not done here. The export is generated on a running server.
- Not done, by design: removing the Communicator path (Johan's call), renaming the service user, raising the int slot bound, a per-module Scheduler action registry.
- Open requests for other areas are written to `reviews/requests/softwarerepository.md` and `reviews/requests/remote-background.md`. The other open entries in `reviews/requests/core.md` are not part of this order.

## Fixed after review

Round 1 (AI review, High): the new caller `softwarerepository` inherited the AD-50 exemption (no Tactical `can_send_cmd` needed), which widened trust beyond AD-60.

- Fail closed. `system_commands.REQUIRED_FLAGS` lists the Tactical flags the owner must hold per calling module: `softwarerepository` needs `can_send_cmd`. `communicator` keeps its signed AD-50 behaviour (no flag).
- At creation and edit, `_controls` refuses `not_permitted` when the owner lacks the flag (keyed on the action's module id, so it holds when remote-background registers the row with no flags).
- At every run, `run_system_command` also checks the flags with `held_at_creation`, so an unattended run refuses `permission_lost` when the stored creation-time flags lack it. Nothing is sent.
- Module-facing: a Software Repository schedule now needs an owner with Tactical `can_send_cmd`. Communicator is unchanged. The wider option is in `reviews/questions/core.md` for Johan.
- Tests: `tests/system-command-callers-integration-1.18.36.py` registers the row with no flags and covers all three cases.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
