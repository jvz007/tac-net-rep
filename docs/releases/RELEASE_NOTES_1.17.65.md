# Tec-Tac Framework 1.17.65

A scheduled run no longer stops because the person who made the schedule was demoted or deactivated. This is how Tactical works, and Johan signed it.

Date: 20 October 2026. Every earlier route, field and contract signature stays. No migration. No new route.

## What changed and why

Johan signed the amended AD-13 condition 2 in chat on 20 October 2026 (CQ184 b, the wide rule; CQ186 yes; CQ189 yes). It is recorded in `docs/tec-tac-module-standard.md` section 1a, `docs/review-accepted-decisions.md` row 13, the development rules (1.7) and checklist line A2.

Before this release, Core read the creator's account, rights and scope again on every scheduled run. Now:

- Every run the schedule starts on its own, on a **user-owned** schedule, skips that re-check. This holds for every registered action. The `unattended=True` flag is no longer needed.
- A **module-owned** schedule with a stored creator name (CQ176) is exempt only while its action is still listed in the module's signed manifest `system_actions` and registered with `core.system_actions`. So it behaves as in 1.17.63, without the flag.
- A run a person starts (a manual run or a one-off run) keeps every re-check, exactly as before.
- Any error, an unregistered action, an unreadable manifest, or a schedule with no stored creator name and a deleted creator (made before migration 0036) answers "re-check", so Core fails to the stricter side.

The one decision point is `scheduler._is_unattended_scheduled_run`. The tick, `verify_run_context` and the system-action code all reach the exemption only through it. `scheduler.AD13_CONDITION_2_AMENDED` is now `True`.

Still checked on every scheduled run: the caller, that the module is enabled and honoured, that the action is declared in the signed manifest, the snapshotted targets, the 2000-endpoint cap, at-most-once sending and the audit row (with run kind, creator and confirmer).

The plain cost: a person who is demoted or deactivated later keeps their schedules running until someone removes or edits them, as in Tactical. Administrators can list schedules by creator (`created_by`, since 1.17.63) and remove or disable them.

Closes: the scheduled-run part of the AD-13 amendment entry in `reviews/requests/core.md` (it stays open for the rows of CQ173 to CQ175), and the 1.17.64 held item that the switch was not built.

## Module-facing

Behaviour changes. No signature changes. Needs framework 1.17.65 to rely on it.

- `register_scheduled_action(..., unattended=...)`: still accepted, still validated (a bool; True only for an action id listed in the module's signed manifest `system_actions`). It now has no effect (CQ188). It is removed only in a later signed major.
- `verify_run_context`: a scheduled run of a user-owned schedule now verifies without the owner re-check, for every action. A manual run and a one-off run are still checked (`SchedulerRunContextInvalid`, "The person who owns this schedule may no longer run it."). `require_owner=True` still refuses a run with no person behind it.
- `VerifiedSchedulerRun.unattended` is True for every such scheduled run. `creator_username` and `confirmed_by_username` carry the stored names.
- `VerifiedSchedulerRun.has_tactical_permission` and `resource_context()` still read the owner fresh at every call and fail closed. A module that wants its own live check keeps it with these two (CQ187: Core adds no other switch).
- `run_system_action`: for a scheduled run, `owner_inactive`, `permission_lost` and `out_of_scope` are skipped (as for an unattended run in 1.17.63), now for every user-owned scheduled run. Every other refusal stays.
- Contract rows `register_scheduled_action`, `verify_run_context`, `run_system_action` and the `core.system_actions` capability notes say this.

## What I checked in modules/

I grepped `modules/` for `register_scheduled_action`, `verify_run_context`, `reconcile_schedule`, `run_system_action`, `unattended=`, `owner_user_id` and `owner_username` before finishing.

| Module | Uses | Effect of this release |
|---|---|---|
| 24 modules: alerts, backups, certificatemanagement, checks, communicator, cybercns, cyberhoot, governance-compliance, halopsa, huntress, licensing, maintenance, networkprobe, notifications, patching, patchmanagement, reportmanager, scoutdns, scriptexecution, sentinelone, softwarerepository, tacticalupdater, userinvite, wau | `register_scheduled_action` | None passes `unattended=`, so none changes. |
| patchmanagement | `verify_run_context`, then `verified.has_tactical_permission` (scheduling.py) and `verified.resource_context()` | Verify now passes for a scheduled run of a demoted or deactivated owner. Its own `has_tactical_permission` and `resource_context` still re-read the owner and fail closed, so its handlers still refuse that owner with their own deny row. No change needed. |
| scriptmanager | Names `verify_run_context` in comments only | None. |
| certificatemanagement, patching | `owner_username` (audit or notice names), patching also `owner_user_id` in a one-off context | None. A one-off run is still re-checked. |
| backups | `owner_username` (notice names). Its `scheduled_actions.py` retention docstring (line 93) and its Help (`help/overview.md` lines 75 and 109, `help/troubleshooting.md` lines 61 and 131) say the Scheduler checks that the owner still holds `backups.delete` (and `backups.run`) before a scheduled run | **Behaviour changes.** From 1.17.65 a scheduled backup (`backups.run`), check (`backups.run`) and retention (`backups.delete`, which deletes archives) of a user-owned schedule keeps running after its owner is demoted or deactivated, and the "run was skipped" notice never fires for it. Backups' handlers never read the person, so nothing else refuses. Module-owned schedules are unchanged. Backups needs no code change. Its Help and docstring wording is asked in `reviews/requests/core-modules.md` under backups. |
| Handlers of the other modules | Never read the person | The tick check was their only person check. A demoted creator's user-owned schedule now runs until removed or edited. This is the signed wide rule. |
| Module-owned schedules (alerts, backups, certificatemanagement, checks, cyberhoot, governance-compliance, huntress, licensing, networkprobe, notifications, patchmanagement retention, scoutdns, scriptexecution, sentinelone, tacticalupdater, userinvite) | `reconcile_schedule` | Never re-checked by the tick. Unchanged. |
| Callers of `start_one_off_run` | One-off runs | Still re-checked. |
| (none) | `run_system_action`, `unattended=` | No module calls either today. |

scriptmanager and globalsettings register no scheduled action. They are covered only through Core's Scheduler page when a person schedules another module's action.

Security note for Johan (CQ191): the signed wording says "as in Tactical", but the wide rule also drops the re-check of Tec-Tac extension permissions (`backups.delete`, scriptexecution, softwarerepository deploy), which Tactical never had. Your answer to CQ184 (b) covers it, so there is no code change. It is in `reviews/questions/core.md` for your sight only.

Also asked of another area: backups' Help and docstring still say Core checks the owner for a scheduled run (`reviews/requests/core-modules.md`, backups).

Asked of another area (not built here): the patchmanagement comments (`scheduling.py` module docstring and catalogue-sync docstring, `verification.py` around lines 18 and 364 to 378) still say Core re-reads the owner for a scheduled run. That is a comment fix for the `core-module-developer`; it is in `reviews/requests/core-modules.md` under patchmanagement. No behaviour change is needed.

The scheduler settings card in the Core UI (`SchedulerSettingsView.vue`) stays true for manual and one-off runs. No UI request.

## Tests

New:

- `tests/scheduler-wide-recheck-1.17.65.py` (stub harness): the wide rule for ordinary and system actions, the manual and one-off cases that stay checked, every refusal that stays, module-owned schedules, the keyword, the one-helper source read, the document and contract wording, the release-notes headings and the rebuild literal check.
- `tests/scheduler-wide-recheck-runtime-1.17.65.py` (dev server only, see the checklist).

Changed, and why:

| Test | Why |
|---|---|
| `scheduler-unattended-gate-1.17.63-1.py` (rewritten, same name) | It now requires the switch to be True and the documents to carry the amended wording. The "switch False refuses" part is gone. The module-owned binding checks stay. |
| `scheduler-unattended-owner-1.17.63.py` | An ordinary user-owned schedule is now queued, not skipped. A module-owned ordinary action stays unexempt. The source needle follows the helper. |
| `system-actions-unattended-1.17.63.py` | The ordinary scheduled case flips. The manual cases stay. |
| `system-actions-run-1.17.61.py`, `system-actions-audit-1.17.61.py`, `system-actions-targets-1.17.62.py` | Their owner re-read cases used a scheduled user-owned run. They are now manual (person-started) runs, which keep the re-read. The audit deny row says `run_kind` person. |
| `scheduler-completion-harness-1.17.61.py` | `make_run` takes `manual=False`, so a test can start a person-started run. |
| `contract-catalog-1.17.61.py`, `module-job-contract-rows-1.17.60.py`, `scheduler-compat-1.17.63.py` | The three version pins the 1.17.64 review held. Each now accepts its version and any later one (tuple compare, `-N` stripped). No fixed list. |

Unchanged and passing: `scheduler-module-owned-creator-1.17.63.py`, `scheduler-tactical-permission-1.17.17.py`, `scheduler-run-context-1.17.19.py`, the one-off tests, `review-followup-1.15.79.py`, `scheduler-closure-1.15.149.py`, `scheduler-filter-value-compat-1.15.134-2.py` and `scheduler-claim-lock-1.17.55.py`.

`RELEASE_NOTES_1.17.64.md` moved to `docs/releases`, so the integrity check sees one root note.

## What is not in this release

- CQ173: a scheduled install for Advanced Patch Management stays refused (`reapproves_by_policy`).
- CQ174: pushing rule decisions to Tactical on a schedule.
- CQ175 rows: reboot, uninstall, script, command, check, task and report rows of the system-action table.
- CQ177: pending completion changes.
- CQ178: groups above 2000 endpoints. The cap stays 2000 and a larger set is refused, never truncated.
- CQ187: no Core code path for a module-signed alternative. The alternative is the module's own live check.
- Removing `unattended=`: kept, no effect, until a later signed major.

## What could not run on this PC

Django, Celery, Postgres and Tactical are not installed here. So the tick on a real database, the DRF views and the runtime probe did not run. The stub-harness tests did.

## Dev-server checklist

**Step 1.** Update the dev server to 1.17.65 and restart Core and the Celery workers. Run `manage.py makemigrations --check --dry-run`. Expect: no changes. **FAIL**: any change is listed. Send back the output.

**Step 2.** Run `tests/scheduler-wide-recheck-runtime-1.17.65.py` through `manage.py shell` with `TECTAC_PROBE_USER` and `TECTAC_PROBE_AGENT` set (see the top of the file; the three-step form covers a demoted user). Expect: every line PASS and a last line `PASS scheduler wide recheck runtime 1.17.65`. **FAIL**: any FAIL line. Send back the output.

**Step 3.** As a test user, create a schedule for a harmless action (the Scheduler test event). Demote that user (remove the role or deactivate the account). Wait for the next tick. Expect: the run shows `succeeded` and the creator is named in the schedule list. **FAIL**: the run shows `AuthorizationRevoked`. Send back the run row and the Core log.

**Step 4.** As the demoted user, start a manual run of that schedule (or ask an administrator to sign in as that user). Expect: the run is refused. **FAIL**: it runs. Send back the run row.

**Step 5.** Export a fresh public contract into `docs/contracts`. Expect: it exports with no error and the three rows (`register_scheduled_action`, `verify_run_context`, `run_system_action`) carry the 1.17.65 text. **FAIL**: an error, or old text. Send back the output.

**Step 6.** Re-enable the test user, then delete the test schedule. Expect: it disappears from the list. **FAIL**: it stays. Send back the Core log.
