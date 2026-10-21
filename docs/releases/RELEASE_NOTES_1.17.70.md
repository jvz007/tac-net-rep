# Tec-Tac Framework 1.17.70

Date: 21 October 2026. No migration. No new route. `core.system_actions` goes from 1.2.0 to 1.3.0 (additive).

This release adds the second kind of system action: a write. It lets the module that honourably replaces Windows Patching (today Advanced Patch Management) push its approve, ignore and do-nothing decisions for Windows updates into Tactical on a schedule. Johan answered CQ203 on 21 October 2026 ("yes every Premium module", for the Tactical group the module replaces; AD-45). Nothing else moves.

What changes for a person:

- **Nothing changes for an engineer today.** No module uses the new row yet. Advanced Patch Management 0.13.0 will be the first.
- **When it is used, the Yes or No dialog says what will happen.** It names the decisions the module may make (approve, ignore, do nothing), says Core records the earlier and the new decision of every update, and says Tactical keeps the decisions if the module is later removed.
- **A decision a person makes in Tactical wins.** If someone changes an update's decision after Core read it and before Core writes, Core leaves that update alone and says so in its audit log.

## What changed and why

1. **A table row has a kind (CQ203, AD-45).** `SystemFunction` gains three defaulted fields: `kind` (`task` or `write`), `replacement_only` and `confirmation_line`. Every earlier row and every module keeps working untouched: they are tasks, as before. A module still names only a key of Core's fixed table. It can never name a callable.
2. **One write row: `winupdate.set_action`.** It owns the approve, ignore or do-nothing decision of one Windows update. In Tactical v1.5.2 that is `PUT winupdate/<update_id>/`, which needs `can_manage_winupdates` and then saves `WinUpdateSerializer(update, data, partial=True)`. Tactical has no Celery task for it, so Core makes the same save itself, in its own process, with the same serializer and the one key `action`. The row is `replacement_only`, `dangerous` and never delegable.
3. **Who may register it.** Only the module that is the honoured replacement of `patching` right now. Windows Patching itself is refused (it uses a person's own request). A premium module that replaces nothing, or replaces another group, or is not the honoured one, is refused; a replacement that is not honoured at that moment is logged and not registered, as for the other rows. The registration must say `dangerous=True` and leave `delegable_to` empty.
4. **`run_system_write(context, *, action_id, changes)`** is the new public function (capability operation `run_write`). `changes` is a list of `{update_id, action}`. It applies the checks of `run_system_action` in the same order: a context Core issued for a run still going, the verified caller is the run's module and owns the action, the action is listed in the signed manifest now, the module is enabled now, the replacement is honoured now, the parameters come from the confirmed record only, then the owner, count, scope and targets. A task row refuses here as `wrong_kind`, and a write row refuses in `run_system_action` the same way. `run_system_action` keeps its signature and behaviour.
5. **Core reads each update's endpoint itself** (one fixed read of Tactical's WinUpdate id and agent), requires every update to exist, and judges the resulting endpoint set like `agent_ids`: inside the run's snapshotted targets (never widened), inside the owner's role scope for a person-started run, inside the stored creation-time scope for an unattended run on a module-owned target type. One miss refuses the whole call and nothing is written. No id is named in a message.
6. **A strict shape.** Exactly `update_id` and `action` per item, whole numbers only, each update once, at most 40 000 items a call (2000 per group, 20 groups; refused above, never cut). Every action must be one of the `allowed_actions` the person confirmed, a subset of `approve`, `ignore` and `nothing`. `inherit` is refused: it has no meaning on one update row. Any other key is refused, so a write can touch only the `action` column, never `installed`, `kb` or `result`. New refusal reasons: `wrong_kind`, `bad_changes`, `unknown_update`, `action_not_allowed`.
7. **Each group, in order.** Core marks the group, reads the current decision of every update (the "before"), writes one strict audit row per chunk of at most 500 changes before it writes (`[update_id, before, after]`, with the run, schedule, creator, confirmer, action id and group digest), then writes inside one transaction with row locks, through `WinUpdateSerializer(partial=True)` with `{"action": value}`. A row whose decision changed after the "before" was read is not overwritten and is counted as `changed_meanwhile`. A change equal to the current decision is counted as `unchanged` and not written. One closing audit row (`custom:write-closed`) per group carries the counts and the decisions actually saved. If an audit row cannot be written, nothing is written for the group and the mark is aborted, so the retry writes once. A failed save is outcome-unknown, as for a task: the group is never written again.
8. **Creation-time controls.** The row's parameters are `{allowed_actions: [...]}`, validated by the row against the confirmed record and never against the caller. The confirmation id is bound to them, so an id made for one list does not open a schedule with another. The Yes or No text gets a row-specific line. The "Script number ..." line is now guarded by row and shows only for `scripts.run`.
9. **Delegation refuses a write row** (`not_delegable`, by the empty `delegable_to` and by a kind check). Existing delegation paths do not change.
10. **Docs and contract.** `docs/system-actions.md` has a new section, "The second kind: a write", with AD-45 and the plain limit below. `contracts.py` has a new `run_system_write` row, and the `register_system_action`, `SystemActionRefused` and system-actions rows describe the second kind.

Closes the rule-push part of CQ203 (and the old CQ174 and CQ192). The reboot part of CQ203 is not Core's: see "Not in this release".

## Module-facing changes

Module-facing, for the honoured replacement of Windows Patching (needs `requires.framework >=1.17.70`):

- `core.system_actions` is 1.3.0. New operation `run_write`; new public function `tec_tac.system_actions.run_system_write(context, *, action_id, changes)`.
- New table row `winupdate.set_action`. `list_actions`, `get_action` and the contract metadata now carry `kind` and `replacement_only` for every row, and the metadata has a `write` block.
- New refusal reasons: `wrong_kind`, `bad_changes`, `unknown_update`, `action_not_allowed`.
- The Yes or No text of a write row names the allowed decisions. The text of every task row is unchanged.

Plain limit: **Tactical's own audit log does not show Core's write**, because Core saves the column in its own process and not through Tactical's route. Core's strict audit rows (the update, the decision before and the decision after) are the record.

What I checked in `modules/`: only `patchmanagement` registers system actions (`apps.py`, `tec_tac.json`, `scheduling.py`), and only task rows. No module calls `run_system_write`, names `winupdate.set_action`, or reads `kind`, `replacement_only` or `confirmation_line`. `patching`, `scriptexecution` and `maintenance` use other Core paths. `scheduler.py` is not touched. Everything is additive, so no module needs a compatibility path. `tests/system-writes-compat-1.17.70.py` pins this.

## Tests

New, on the existing stub harness (`tests/system-writes-harness-1.17.70.py` builds on `scheduler-completion-harness-1.17.61.py` and adds an in-memory Tactical `WinUpdate` and serializer, so the real `system_writes.py` seams run): `system-writes-table-1.17.70.py`, `system-writes-registration-1.17.70.py`, `system-writes-run-1.17.70.py`, `system-writes-creation-1.17.70.py`, `system-writes-contract-1.17.70.py`, `system-writes-compat-1.17.70.py`, and `system-writes-runtime-1.17.70.py` (a small script for `manage.py shell`; its one write is rolled back).

**Existing tests changed on purpose (the plan said none would change; eleven test files pinned the exact surface this release adds to, so those pins could not hold).** Each pinned the exact table, version or operation list that this release adds to. Each change moves the pin forward and keeps the earlier part of the assertion; nothing was deleted, skipped or loosened:

- Table rows: `tests/system-actions-table-1.17.61.py` (two assertions) and `tests/system-actions-table-1.17.66.py` say the table has exactly four rows (was three) and now include `winupdate.set_action`. `tests/system-actions-registry-1.17.61.py` and `tests/contract-catalog-1.17.66.py` likewise list the four function rows in the metadata.
- Capability version: `tests/system-actions-unattended-1.17.63.py`, `tests/scheduler-compat-1.17.67.py`, `tests/system-actions-groups-1.17.66.py`, `tests/system-actions-registry-1.17.61.py`, `tests/contract-catalog-1.17.61.py`, `tests/contract-catalog-1.17.66.py`, `tests/contract-catalog-1.17.67.py`, `tests/contract-catalog-1.17.68.py` and `tests/delegation-compat-1.17.68.py` say 1.3.0 (was 1.2.0).
- Operations list: `tests/delegation-compat-1.17.68.py`, `tests/contract-catalog-1.17.66.py`, `tests/contract-catalog-1.17.68.py` and `tests/system-actions-registry-1.17.61.py` say the nine earlier operations in order plus `run_write` (was exactly nine). The earlier part of each assertion is unchanged.

I kept every other pin as it was. The opening of the system-actions rule in `contracts.py` ("System actions (core.system_actions 1.2.0 since Core 1.17.68, ...") and the "core.system_actions 1.2.0" wording in `docs/system-actions.md` stay, because other tests read them; the 1.3.0 statement is added next to them.

`RELEASE_NOTES_1.17.69.md` moved to `docs/releases/`, as every release does for the one before it (`tests/release-integrity.sh` allows exactly one note at the root).

## Not in this release

- **Reboot with a result.** Not Core's. It comes from Communicator's `communicator.messaging` contract, with Tactical's own reboot through the Agents core module's contract as the fallback, both built by module lanes (Johan, 21 October 2026). Written as requests for `communicator` and `agents`.
- **Tactical's `WinUpdatePolicy` rows.** Not asked; the patch lockdown makes a policy write unnecessary.
- **Other write rows.** Only `winupdate.set_action`. Software package uninstall, checks, tasks and reports (CQ193), `commands.run` (CQ194) and refusing Tactical's own native `winupdate/` and `automation/patchpolicy/` mutating routes stay out.
- **Held LOW finding from 1.17.69** (`scheduler.py`, `_names_no_endpoints` runs the resolver twice). `scheduler.py` is not touched, so it stays in `reviews/core/BACKLOG-new-findings.md`.
- **Hardening batches H1 to H3**, the Scheduler progress call, `groups.usage`, the plugin-registry dependencies field, the external-audit items and the licensing enforce flip: not in this release.
- **The signed public contract export for Core 1.17.69 and 1.17.70.** It is generated on a running server. Johan runs the export on the dev server (step 8 below).

## What I could not do here

- **Django is not installed on this PC.** `manage.py makemigrations --check` (this release has no migration; it must say "No changes detected") and every test that needs the ORM wait for the dev server. The write seams (`_read_update_agents`, `_read_actions`, `_write_locked`) run here against an in-memory stand-in of Tactical's `WinUpdate` and serializer, not the real tables.
- **`tests/system-writes-runtime-1.17.70.py` did not run here.** It needs the dev server.
- Three older tests fail on this PC with and without this release, because they scan `modules/` and Advanced Patch Management already uses the names they watch: `system-actions-compat-1.17.61.py`, `scheduler-compat-1.17.63.py` and `scheduler-compat-1.17.66.py`. They are not touched.

## Checklist for the dev server (Johan)

Go in order. Each step says what you should see, what counts as a FAIL and what to send back.

1. **Update and restart.** Update the dev server to Core 1.17.70 from the dev branch, restart Core and the Celery workers. Run `manage.py makemigrations --check --dry-run`. Expected: "No changes detected". FAIL: any migration is listed. Send back: the output.
2. **Runtime script.** Run `tests/system-writes-runtime-1.17.70.py` through `manage.py shell`. Expected: the last line says PASS and there is no FAIL line. FAIL: any FAIL line or a traceback. Send back: the full output.
3. **Modules and Scheduler.** Open the Modules page and check Advanced Patch Management is still enabled and the Scheduler page still lists its scan and install schedules. Expected: nothing changed. FAIL: a module refused or disabled, or a schedule missing. Send back: a screenshot and the Core log lines around the restart.
4. **Capability.** In `manage.py shell` run `from tec_tac import system_actions as sa; print(sa.CAPABILITY_VERSION); print(list(sa.system_actions_contract_metadata()['functions']))`. Expected: `1.3.0` and a list with `winupdate.scan`, `winupdate.install`, `scripts.run`, `winupdate.set_action`. FAIL: any other version or a missing row. Send back: the printed lines.
5. **Wrong registrant.** In the same shell run `sa.register_system_action('patching.setaction','patching','Test','winupdate.set_action',['can_manage_winupdates'],dangerous=True)`. Expected: `SystemActionRegistrationError` saying only the module that honourably replaces `patching` may register it. FAIL: it registers. Send back: the error text or the returned object.
6. **The dialog (waits for a signed Advanced Patch Management release that uses the row; if none exists yet, skip 6 and 7 and say so).** Create the rule-push schedule on one test endpoint and press Yes. Expected: a plain Yes or No text listing approve, ignore and do nothing, and "Tactical keeps the decisions even if the module is later removed". FAIL: no dialog, a typed confirmation, or an error. Send back: a screenshot of the dialog.
7. **The run.** Run the schedule once on that endpoint, then open Tactical's Patch Management tab for it and the Audit page. Expected: the updates show the approve or ignore decisions Advanced Patch Management chose; the Audit page shows one "run" row before the write with update number, before and after, and one closing "write-closed" row with counts. FAIL: a decision in Tactical that Advanced Patch Management did not choose, no audit row, or a row with no before value. Send back: the Audit rows, the endpoint's update list and the Scheduler run result.
8. **Contract export.** Export a fresh public contract into `docs/contracts` and run `manage.py tec_tac_check_contract_export` on it. Expected: PASS. FAIL: any listed mismatch. Send back: the output and the file name.

Ends when the checklist passes (steps 6 and 7 wait for Advanced Patch Management).
