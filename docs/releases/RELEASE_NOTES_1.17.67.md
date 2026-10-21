# Tec-Tac Framework 1.17.67

Core now refuses to guess when it cannot read what it needs to protect a system-action schedule. A retry can no longer send one endpoint twice. You can open and download the System Updates and server-maintenance logs. The Audit page says what a finished update did.

Date: 20 October 2026. Every earlier route, field and contract signature stays. No migration. Three new routes. Capabilities `core.system_actions` and `core.server_maintenance` stay at 1.1.0.

## What changed and why

This release closes the two held Mediums of the 1.17.66 review and Johan's Q83 (the UI 0.12.119 requests).

1. **The creation gate fails closed (held Medium a).** In 1.17.66 a failed read of the signed manifest or of the registry counted as "not a system action", so the permission checks and the one Yes or No were skipped. Now `scheduler.system_action_state(module_id, action_id)` answers `declared`, `not_declared` or `unknown`. The gate needs two facts: the action is listed in the signed manifest `system_actions` and it is registered with `core.system_actions`. A definite no from either fact means `not_declared`, so an ordinary action never needs the manifest (the cheap memory check runs first) and is never refused for a read fault. Both facts true means `declared`. A failed read that the other fact did not settle means `unknown`. For `unknown`, `require_creation` and `describe_confirmation` refuse with the new reason `declaration_unreadable` ("Core could not read the signed manifest or the registry just now, so it did not create or change this schedule. Try again in a minute."), write one deny row, save nothing, queue nothing and issue no confirmation id. The deferred flag is set before the state call, so `reconcile_schedule` keeps its deny row after its rollback. This covers `POST` and `PATCH /api/tfd/scheduler/schedules/`, `reconcile_schedule` with `confirmed_by_request`, `start_one_off_run` and `POST /api/tfd/scheduler/system-actions/confirmation/`. `_action_declared_as_system_action` is not changed: at run time a failed read still keeps every re-check, which is the safe side there.
2. **The group plan is fixed on the first attempt (held Medium b).** Group digests used to depend on the current endpoint list, so a retry could send an endpoint twice. Core now stores one plan mark per call on the run (`kind: "plan"`: the endpoint numbers as ranges and the digest of every group; no audit row, no send) under the same row lock as the group marks. A call is identified by its full sorted id set. The groups of a retry are cut from the stored plan, never from the live list.
   - Same ids: a retry, as before.
   - No endpoint in common with an earlier plan of the run: a new call (two disjoint calls in one handler stay legal).
   - A different list that overlaps a plan, after any group of that plan was claimed, sent or left unknown: the run ends failed as `OutcomeUnknown` with the plain text "The endpoint list changed after part of this run was sent, so Core did not send again. Check the endpoints.", one `custom:outcome-unknown` row, counts only. An endpoint is never sent twice. A scan may be missed.
   - A different list when nothing was sent yet (every group mark is absent or aborted): the plan is replaced and the call goes on.
   - `MAX_MARKS_PER_RUN` is 105 (five full calls of 20 groups and five plan marks). The plan marks count in the limit check. A mark without a `kind` stays a group mark.
   - The other option the reviewer allowed (send only the endpoints no sent group covers) is not built. It needs per-endpoint accounting for groups left unknown, and refusing is the safe side.
3. **Job logs (Q83 part 1, UI 0.12.119).** `GET /api/tfd/system/updates/jobs/<id>/log/` and `GET /api/tfd/system/maintenance/jobs/<id>/log/` (`?download=1`; the maintenance one also `?part=all|log|stdout|stderr`). Same scrub, 5 MB head-and-tail cap, headers (including `Access-Control-Expose-Headers` on a 200) and strict audit row (503 and no text if it cannot be written) as the module job log. The three routes build their answer in one helper (`module_job_logs.log_response` and `serve_log`); the module route's output is unchanged. `module_job_logs._open_log` and `_log_size` gained a `suffix` argument (default `.log`), and `read_log_for` reads one or several files with a shared cap. The maintenance log redacts the job's own sensitive parameter values first. A job of an action that needs a permission is hidden as the same 404 as an unknown job, also with `?download=1`. The system update list is `GET /api/tfd/system/updates/jobs/` (`page`, `page_size`, `component`, `status`; jobs folder and history merged, history wins; the newest 500 files by modification time; no log text and no backup path). `GET system/updates/jobs/<id>/` now falls back to history. Every system update job answer gains `log_bytes` and `has_log`. See `docs/system-update-logs.md`.
4. **Audit wording for a finished system update (Q83 part 2).** The root helper cannot write Django audit, so the Scheduler tick (a new guarded step, `system_update_audit.audit_finished_system_updates`) writes one row per job that finished in the last 24 hours, newest first, at most 20 a tick. `Update installed successfully 1.17.16 -> 1.17.17` (action `install`, object type `system_update`, actor `core / system-update / system`, requester in the metadata). A failed update reads `Update failed 1.17.16 -> 1.17.17. 1.17.16 was restored.` or `... The rollback did not finish, check the server.`, or `Update failed to 1.17.17.` when the old version is not known (action `custom:system-update-failed`). No error text and no path. The helper (`scripts/system-update-helper.py`) records `installed_version` right after it reads the old version. The update to 1.17.67 itself is run by the older helper, so its row reads `Update installed successfully to 1.17.67`. A job gets one row (correlation id `system-update:<installed|failed>:<job id>`).

Closes: the two UI 0.12.119 Core requests (job logs, audit wording), Q83 (yes), and the two held Mediums of the 1.17.66 review. The two held Lows (`Access-Control-Expose-Headers` and the kit props rows) were already shipped in 1.17.66; this release only pins them in tests.

## Module-facing

Needs framework 1.17.67 for the three new routes. The rest is fail-closed or additive on a path no module uses yet.

- **`reconcile_schedule` and `start_one_off_run`.** For a system action (listed in the signed manifest and registered with `core.system_actions`) a failed read of either source now raises `SystemActionCreationRefused` with the new reason `declaration_unreadable`. Nothing is saved, queued or issued. For every other action nothing changes, also while a read fails. Signatures are unchanged.
- **`SystemActionCreationRefused` and `SystemActionRefused`.** New reason `declaration_unreadable` (a refusal at creation, edit, switch-on or one-off start).
- **`run_system_action`.** Retry rule and plan mark (above). A handler that sends the same endpoint list on a retry sees no change. A handler that sends a changed, overlapping list in one run now gets `OutcomeUnknown`. `MAX_MARKS_PER_RUN` is 105. The result shape and the `duplicate` flag are unchanged.
- **New routes** (framework >=1.17.67): `GET /api/tfd/system/updates/jobs/`, `GET /api/tfd/system/updates/jobs/<id>/log/`, `GET /api/tfd/system/maintenance/jobs/<id>/log/`. Additive keys `log_bytes` and `has_log` on the system update job answer. The detail route reads history.
- **New audit rows.** `view` of `system_update_job_log` and `server_maintenance_job_log` (strict, no log text); `install` and `custom:system-update-failed` of `system_update` (non-strict).
- **`core.server_maintenance` stays 1.1.0.** `read_job_log(job_id, user, part)` is a function of `tec_tac.server_maintenance`, not an operation of the capability. A module that reads a job keeps using `get_job`.
- **Contract rows.** New: the system update list, detail and log routes and the maintenance log route. Updated: `run_system_action`, `SystemActionCreationRefused`, `SystemActionRefused`. The capability metadata lists the new reason.

## What I checked in modules/

I grepped `modules/` for `run_system_action`, `register_system_action`, `describe_confirmation`, `system_action_state`, `reconcile_schedule`, `start_one_off_run`, `system/updates/jobs`, `maintenance/jobs/.../log`, `read_job_log` and `core.server_maintenance`.

| Module | Uses | Effect of this release |
|---|---|---|
| (none) | `run_system_action`, `register_system_action`, `describe_confirmation`, a `system_actions` manifest key, the new routes, `read_job_log` | No module calls any of them, so the fail-closed gate, the plan mark and the new routes are pure additions for now. |
| alerts, backups, certificatemanagement, checks, cyberhoot, governance-compliance, huntress, licensing, networkprobe, notifications, patching, patchmanagement, scoutdns, scriptexecution, sentinelone, tacticalupdater, userinvite (17) | `reconcile_schedule` | None of their actions is both listed in a signed manifest `system_actions` and registered with `core.system_actions`, so the gate answers `not_declared` and nothing changes, also when a read fails. (The plan counted 16: `patching` is the seventeenth.) |
| backups, checks, patching, patchmanagement (4) | `start_one_off_run` | Same rule. |
| certificatemanagement, securityWAF, tacticalupdater (3) | `core.server_maintenance` `get_job` | The capability is unchanged (still 1.1.0, same four operations). |

`tests/scheduler-compat-1.17.67.py` reads `modules/` as source and proves the first row; `tests/system-actions-creation-failclosed-1.17.67.py` proves an ordinary action is created, started and described while a read fails.

## What was left out, and what ends each wait

- **Rule push, Reboot with a result, Software package uninstall, Commands, Checks run, tasks run and reports rows.** Johan said not to build them. CQ192, CQ193 and CQ194 stay open with assumption (a): nothing is built. They end when Johan signs a design.
- **CQ195 (the 20-group ceiling), CQ196 (flags and owner of `scripts.run`) and CQ197 (confirmation id strength).** Johan's design points. They are not recorded as signed here and no constant changes. They end when he answers in chat.
- **The authority documents (CQ198, CQ173, CQ174, CQ175, CQ176, CQ177, CQ178).** `docs/tec-tac-module-standard.md` 1a, `docs/review-accepted-decisions.md` row 13, rule 1.7 and checklist A2 are not Core's to edit. The release-manager records the signed words for CQ173, CQ175, CQ178 and CQ197 after this sign-off. CQ187 and CQ191 stay as filed.
- **A module-owned target type resolver contract** (a target type that Core cannot read as endpoints stays `targets_unresolved`), **R-36** (install re-approval, not built, as Johan said), **the native patching paths switch-off**, the `licensing_enforcement_mode` flip, the production category gate and general secret storage: open requests that wait on Johan or another area.
- **The "send only endpoints not yet covered" option** for a changed list on retry (CQ199): not built; the retry is refused as `OutcomeUnknown`.
- **A history or paging list for server-maintenance jobs.** The existing `GET /api/tfd/system/maintenance/jobs/` lists them and maintenance has no history folder. Only the log route was asked for.
- **UI 0.12.119 and 0.12.118 Lows** (the job id in the URL is not encoded and the others) are the UI's, in `reviews/requests/ui.md`.
- **The Download buttons.** The UI enables them in a later release (`reviews/requests/ui.md`, "From Core 1.17.67").

## Questions I filed

CQ199 (a retry whose list changed: refuse, assumption a), CQ200 (an unreadable declaration: refuse only a possible system action, assumption a), CQ201 (the audit wording: please confirm the failed wording and the actor) and CQ202 (one combined maintenance download). All in `reviews/questions/core.md`, each with its assumption. Nothing waits.

## Not run here

- Django is not installed on this PC. Every Django-dependent test runs on the stub harness (module code under stubs for Django, DRF, the audit writer and the file roots). The views of `views.py` are read with `ast` and run on stubs.
- `tests/system-update-logs-runtime-1.17.67.py` was not run (dev server only). It writes its job and log files under temporary folders, not under `/var/lib/tec-tac`, because those are root-owned. It does not cover `reconcile_schedule` (that needs a real signed-in request object); the stub test covers it.
- The root helper `scripts/system-update-helper.py` was not run (root, Linux). A source test pins that `run_job` sets `job["installed_version"]`.
- No dev-server run, no real export (`tec_tac_check_contract_export` needs the running server), no pack and no signature (not Core's step).

## Dev-server checklist

Johan or the release-manager runs these on dev02 after the update. Send back the step number and the output of any FAIL.

**Step 1: update.** Update to 1.17.67, restart Core and the Celery workers. Expect Core to start with no error in its log. **FAIL** if Core or a worker does not start. Send back the log lines.

**Step 2: migrations.** `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py makemigrations --check --dry-run`. Expect "No changes detected". **FAIL** on any change. Send back the output.

**Step 3: the runtime script.** `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/system-update-logs-runtime-1.17.67.py`. Expect the last line `PASS` and no `FAIL`. **FAIL** if any step prints FAIL or the last line is not PASS. Send back the whole output.

**Step 4: open and download the logs in the UI or with curl.** Open the System Updates log of the last job and the log of a maintenance job (UI, or `curl -i -H "Authorization: Token ..." https://<server>/api/tfd/system/updates/jobs/<id>/log/`). Expect `200`, text, no secret (no `password=` value, no token), and the headers `X-Tec-Tac-Log-Truncated`, `X-Tec-Tac-Log-Bytes`, `X-Tec-Tac-Log-Kept` and `Access-Control-Expose-Headers`. Add `?download=1` and expect `Content-Disposition: attachment; filename="system-update-framework-<date>.log"`. **FAIL** if a secret is visible, a header is missing, the answer is not 200, or a plain person (no privileged-operations right) can read it. Send back the status line, headers and the first ten lines.

**Step 5: one audit row per read.** On the Audit page filter object type `system_update_job_log` and `server_maintenance_job_log`. Expect exactly one row per read you did, with the job id and no log text. **FAIL** if a read left no row, two rows, or any log text. Send back a screenshot.

**Step 6: the 5 MB cap.** Only if a log over 5 MB exists, or by the runtime script (step 3 covers it). Expect `X-Tec-Tac-Log-Truncated: true` and a marker line "bytes were left out of the middle". **FAIL** if the whole file comes back. Send back the headers.

**Step 7: the audit row of the update.** Two minutes after the update to 1.17.67 ended, open the Audit page and look for object type `system_update`. Expect `Update installed successfully to 1.17.67` (this first update is run by the older helper, which does not record the old version). The next update shows `Update installed successfully 1.17.67 -> 1.17.68`. **FAIL** if no row appears within two minutes, two rows appear for one update, or the text carries an error text or a path. Send back the Audit page row and `journalctl -u tec-tac-scheduler` lines from that minute.

**Step 8: the fail-closed gate (done in the runtime script).** The script makes the manifest read and then the registry read fail inside the shell only (no manifest is renamed) and proves that `POST /api/tfd/scheduler/schedules/`, `start_one_off_run` and `describe_confirmation` for a probe system action are refused with `declaration_unreadable`, nothing is saved, and an ordinary action is not refused. Expect step 3 to show both "manifest unreadable" and "registry unreadable" PASS lines. **FAIL** if either line is missing or printed FAIL. Send back the output.

**Step 9: the contract export.** Export a fresh public contract into `docs/contracts` and run `manage.py tec_tac_check_contract_export <that file>`. Expect it to report no difference and list the three new routes. **FAIL** on any difference. Send back the command output.

## Tests

New (all on the stub harness, none needs Django):

- `tests/system-actions-creation-failclosed-1.17.67.py`: `system_action_state` for every combination; POST, PATCH-on, `reconcile_schedule`, `start_one_off_run`, `describe_confirmation` and the capability are refused with `declaration_unreadable` when the manifest or the registry read fails; nothing saved or queued; one deny row (also after the `reconcile_schedule` transaction); no confirmation id; an ordinary action (not registered, or listed but not registered) is not refused; the run-time exemption still answers False; the healthy read still needs permission, flags, scope and the id.
- `tests/system-actions-groups-1.17.67.py`: 4500 endpoints, group 1 sent, the audit write for group 2 fails; the same list sends groups 2 and 3 once; a list that gained an id, lost an id of group 1 or of group 3, or moved an id of group 2 ends `OutcomeUnknown` with nothing new sent and no endpoint twice; a changed list when nothing was sent is planned again; two disjoint calls both send; an overlapping second call is refused; five full calls (105 marks) fit and a sixth is refused; a mark without a kind stays a group mark.
- `tests/scheduler-compat-1.17.67.py`: the run-time exemption keeps its answer, the signatures are unchanged, the capabilities keep 1.1.0, and `modules/` uses none of the changed names (17 modules call `reconcile_schedule`, 4 call `start_one_off_run`).
- `tests/job-log-routes-1.17.67.py`: both log routes (scrub, headers, download name, 5 MB cap, shared cap between parts, symlinks, bad id, missing job and log, history, strict audit and the 503 with no body, the permission hidden as 404, `?part`), the list route (paging, filters, merge, no log text or path, `log_bytes`, `has_log`) and the history fallback of the detail route.
- `tests/system-update-audit-1.17.67.py`: the exact wording, one row per job, history, the older-helper wording, the failed wordings with no error text, odd versions, nothing for old, running or symlinked jobs, a failing lookup writes nothing, at most 20 a tick, and source pins for the helper and the tick.
- `tests/contract-catalog-1.17.67.py`: the new rows, the plan rule, the new reason, the docs and these notes.
- `tests/system-update-logs-runtime-1.17.67.py` (dev server only, see the checklist).

Changed on purpose, and why:

| Test | Why |
|---|---|
| `system-actions-groups-1.17.66.py`, `system-actions-run-1.17.61.py` | A call now leaves one plan mark next to its group marks, so they count group marks (`kind` is not `plan`). In `system-actions-run-1.17.61.py` the line "another endpoint list in the same run is its own send" used a subset of the first list. A list that overlaps a sent plan is now refused, so the test uses a list with no endpoint in common (and widens the run's targets to include it). |
| `module-job-log-expose-headers-1.17.66.py` | The header is now built once in `module_job_logs.log_response`, shared by the three log routes. The test pins that place and that the module view uses it. |
