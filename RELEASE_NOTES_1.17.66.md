# Tec-Tac Framework 1.17.66

Core can now run a system action on thousands of endpoints in safe groups. It can run a script on a schedule. A person who sets up such a schedule gets the permission check and one plain Yes or No when they do it. The exported contract can no longer drift from the code without a test failing.

Date: 20 October 2026. Every earlier route, field and contract signature stays. No migration. One new route. Capability `core.system_actions` moves from 1.0.0 to 1.1.0 (additive, still major 1).

## What changed and why

Johan answered the open system-action questions in chat on 20 October 2026. This release builds what Core can build safely today. What it cannot build yet is listed further down, with the reason and what ends each wait.

Johan also agreed CQ176 and CQ177 as built (Core 1.17.63 and 1.17.61) and CQ187 to CQ191 as written. Nothing changes for them. His answers are written into `reviews/questions/core.md` as they were relayed to me.

1. **Groups of at most 2000 (CQ178).** A run used to be refused above 2000 endpoints. Now Core splits it. The whole set is judged first: shape, count, scope for a person-started run, `outside_targets`, `targets_unresolved`, parameters, declared, enabled and honoured. One failure refuses the whole call and nothing is sent. The ids are sorted and cut into groups of at most 2000 (`MAX_AGENTS_PER_GROUP`). Each group has its own mark, its own strict audit row written before its own send, and is sent at most once. A failed audit write sends nothing for that group, and a retry sends it once. A group already sent is skipped. A group whose mark is stuck, or whose send raised, ends the run failed as `OutcomeUnknown`, is never sent again, and every later group stays not started. The result keeps `outcome`, `agents` (the total) and `message`, and gains `groups` (`total`, `sent`, `failed`, `not_started`) and a plain `summary`. The failure text carries the same counts. Counts only: no endpoint ids in any row.
   - The ceiling is **20 groups, 40 000 endpoints** a run, refused above and never truncated. That number is my assumption. I asked Johan (CQ195). Changing it is one constant.
2. **The `scripts.run` row (CQ175).** Script Execution owns it. It calls Tactical's own `bulk_script_task` with keywords only. It needs `can_run_bulk` AND `can_run_scripts`. Tactical's bulk route needs only `can_run_bulk`, so this is stricter on purpose (CQ196). Core passes the creator's stored name (the first 50 characters, as Tactical does) as the username, and never a name from the caller. Each row now declares its own call shape and its own parameter schema.
3. **Parameters come only from what the person confirmed.** They are read from the run's confirmed record (`system_action_parameters` in the schedule's parameters). The `parameters` argument of `run_system_action` must be `None`, `{}` or equal to that record, or the run is refused as `parameters_changed`. For scripts the schema is `script_pk`, `args`, `env_vars`, `timeout` and three booleans, with bounds. Any other key is refused, so there is no free-form command. Audit rows carry `script_pk` and the counts of arguments and environment values, never the values.
4. **Install for the honoured replacement (CQ173, Johan: yes).** The registration refusal and the run-time refusal are gone. Core shows a fixed warning in the confirmation and writes it in the audit row of every install: "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere." R-36 is not built, as Johan said. The reason code `reapproves_by_policy` stays in the list but is no longer returned.
5. **Creation-time controls and the one Yes or No (AD-13 as amended).** For a declared system action Core checks, when a person creates or edits the schedule or starts a one-off run: the owning module's permission, every Tactical flag of the row with no manager bypass, the person's Tactical scope over every target, that the targets read as endpoints within the ceiling, the parameters, and that the module is enabled and a replacement honoured. It then needs a **confirmation id** that Core issued for that person, action, targets, parameters and timing in the last 600 seconds. The new route `POST /api/tfd/scheduler/system-actions/confirmation/` (and the capability operation `describe_confirmation(request, ...)`) returns the plain text for the UI's Yes/No dialog and the id. The id proves the text was produced for that request. It does **not** prove the person pressed Yes, because Core cannot see the button. I asked Johan whether that strength is right (CQ197). A refusal writes one deny audit row. An allowed creation or edit writes one strict row with creator, confirmer, schedule, total, groups and timing. A scheduled run is not re-checked against its creator, as signed in 1.17.65.
   - `reconcile_schedule` and `start_one_off_run` gain one optional keyword, `confirmation_id`. `POST` and `PATCH /api/tfd/scheduler/schedules/` read `confirmation_id` from the body. Nothing changes for an action that is not a declared system action.
   - `reconcile_schedule` does its work in one database transaction, and a refusal rolls it back. So it writes the deny audit row after the transaction ends (a thin wrapper, `_after_refusal_record_deny_row`), and the row is kept. The browser routes and `start_one_off_run` write it at once. A module that calls `reconcile_schedule` inside a transaction of its own can still lose that row if it rolls back.
   - I put the permission and flag checks in the same place for every way in. A schedule that stays off, and an edit that changes only a name or a policy of a schedule that is already on, need no id.
6. **The contract-export gate (the held Low of the 1.17.65 review).** `tests/contract-export-gate-1.17.66.py` fails when the exported contract differs from `contracts.py` or `system_actions_contract_metadata()`: a changed capability field, a missing block or row, a changed purpose text, a wrong framework version, and two stale phrases. The new command `manage.py tec_tac_check_contract_export <file>` builds the live catalog on the dev server and fails on any difference with the exported file. I cannot export (the file is made on the running dev server), so the gate says "not run" plainly until an export for this version is in `docs/contracts`.
7. **UI 0.12.118 requests.** `GET /api/tfd/modules/v2/jobs/<id>/log/` now sets `Access-Control-Expose-Headers: X-Tec-Tac-Log-Truncated, X-Tec-Tac-Log-Bytes, X-Tec-Tac-Log-Kept, Content-Disposition` on a 200, so a browser on another origin can read them. No other route and no other header changed. The `ui.authenticated.components` row now lists the 0.12.118 props, all off by default: `EditorWindow` `floating` and `readOnly`, `FormRow` `stacked`, `TagEditor` `inputId` and `describedBy`, and the kit layer 1050 order. Documentation only. The operations list is unchanged. The request named only the first and last header in Johan's note and all four in the UI's list. I sent all four.

Closes: the two UI 0.12.118 requests (job log headers, kit props), the 1.17.64 dev-server note, the groups, install, scripts and creation parts of the AD-13 entry in `reviews/requests/core.md`, and the contract-export gate held by the 1.17.65 review.

## Module-facing

Needs framework 1.17.66 for each item. Everything is additive. No signature loses anything.

- **`core.system_actions` 1.1.0.** New operation `describe_confirmation(request, *, action_id, targets, parameters=None, when=None)`. `run` returns `groups` and `summary` besides `outcome`, `agents` and `message`. New metadata fields `max_agents_per_group`, `max_groups`, `parameters_key`, per-row `parameters`, and `http`. `max_agents` is now 40000 and `delivery` reads "at most once per group".
- **`run_system_action`.** More than 2000 endpoints are split, not refused. The ceiling is 40000 (`agent_count`). New reason `parameters_changed`. `reapproves_by_policy` is no longer returned. `bad_parameters` now means the confirmed parameters do not fit the row's schema. The `parameters` argument may only repeat the confirmed record.
- **`register_system_action`.** New key `scripts.run` (Script Execution only, flags `can_run_bulk` and `can_run_scripts`). `winupdate.install` is accepted for the honoured replacement.
- **New module `tec_tac.system_action_confirmation`.** `describe_confirmation(user, action_id, targets, parameters, when)` and `SystemActionCreationRefused` (a `SchedulerNotAllowed`, with `.reason`: `not_permitted`, `confirmation_required`, `confirmation_invalid` and the existing codes).
- **`reconcile_schedule(..., confirmation_id=None)` and `start_one_off_run(..., confirmation_id=None)`.** One optional last keyword each. Read only for a declared system action. For `reconcile_schedule` it is read only with `confirmed_by_request` and an enabled schedule.
- **`POST /api/tfd/scheduler/system-actions/confirmation/`.** For the UI. Asks for `action_id`, `targets`, `parameters` and `when`. Answers `required`, `text`, `confirmation_id`, `total`, `groups` and `expires_in`.
- **Audit rows.** The `run` row of a system action gains `total_agents`, `group` and `groups` (and `script_pk`, `args_count` and `env_vars_count` for scripts, `warning` for install). A created or edited system-action schedule writes `add` or `modify` with `total_agents`, `groups` and `when`.
- **Job log route.** Four headers are exposed to the browser (above).
- **Contract rows.** `register_system_action`, `run_system_action`, `reconcile_schedule`, `start_one_off_run` and `SystemActionRefused` are updated. New rows: `describe_confirmation`, `SystemActionCreationRefused`, the HTTP route and the 0.12.118 components line. The unattended text is unchanged from 1.17.65.

## What I checked in modules/

I grepped `modules/` for `run_system_action`, `register_system_action`, `describe_confirmation`, `confirmation_id`, `SystemActionCreationRefused`, the manifest key `system_actions`, `confirmed_by_request` and `MAX_AGENTS`.

| Module | Uses | Effect of this release |
|---|---|---|
| (none) | `run_system_action`, `register_system_action`, a `system_actions` manifest key, `describe_confirmation`, `confirmation_id`, `confirmed_by_request` | No module calls any of them, so every change to the system-action contract is a pure addition for now. |
| alerts, backups, certificatemanagement, checks, cyberhoot, governance-compliance, huntress, licensing, networkprobe, notifications, patchmanagement, scoutdns, scriptexecution, sentinelone, tacticalupdater, userinvite | `reconcile_schedule` | The new check fires only for an action that is both listed in the signed manifest `system_actions` and registered with `core.system_actions`. None is, so nothing changes. Their audit rows keep their 1.17.65 keys. |
| backups, checks, patching, patchmanagement | `start_one_off_run` | Same rule. Their one-off audit row keeps its keys. |
| 23 modules that register Scheduler actions (the above and communicator, cybercns, halopsa, maintenance, reportmanager, softwarerepository, wau) | `register_scheduled_action` | None. The signature is unchanged. |
| agent-management, audit, debug, scriptexecution | A local `MAX_AGENTS` of their own (1000, a header for audit's own route, 50 and 100) | None. They do not read Core's constant. |
| (none) | The job log route headers | The UI is the only reader. |

`tests/scheduler-compat-1.17.66.py` proves this for an ordinary action, for a registered-but-not-declared action, for the HTTP views (read as source) and for the keyword signatures. `tests/system-actions-compat-1.17.61.py` and `tests/scheduler-compat-1.17.63.py` read every module under `modules/` as source.

## Tests

New:

- `tests/system-actions-groups-1.17.66.py` (stub harness): 2000 is one group. 2001, 4500 and 6000 split with no id twice and none lost. 20 groups run and 40 001 is refused whole. A bad endpoint in the last group refuses before group 1. An audit write that fails on group 2 sends nothing for it, and the retry sends it once without sending group 1 again. A crash in group 2 leaves it `OutcomeUnknown`, group 3 not started. A duplicate delivery changes nothing. No endpoint id in any row.
- `tests/system-actions-rows-1.17.66.py`: the `scripts.run` row end to end, the parameters rules, every guard, and install for the honoured replacement with the warning.
- `tests/system-actions-table-1.17.66.py`: three rows. The pinned v1.5.2 keyword list of `bulk_script_task` matches the call Core builds (and the real source in `reference/tacticalrmm`, which it read and matched).
- `tests/system-actions-creation-1.17.66.py`: the text, the id (wrong person, action, targets, parameters, timing, expired, tampered), each control, the audit rows, the one-off run and the capability operation.
- `tests/scheduler-compat-1.17.66.py`: an ordinary action behaves exactly as in 1.17.65, a person-started run is still re-checked and a scheduled one is not, the HTTP views.
- `tests/contract-export-gate-1.17.66.py`, `tests/contract-catalog-1.17.66.py`, `tests/browser-contract-rows-1.17.66.py`, `tests/module-job-log-expose-headers-1.17.66.py`.
- `tests/system-actions-signed-rows-1.17.66.py`: the answers are on record and these notes name every question and every left-out row.
- `tests/system-actions-runtime-1.17.66.py` (dev server only, see the checklist).

Changed on purpose, and why:

| Test | Why |
|---|---|
| `system-actions-run-1.17.61.py`, `system-actions-targets-1.17.62.py`, `system-actions-unattended-1.17.63.py`, `scheduler-wide-recheck-1.17.65.py` | 2001 endpoints were refused. Now they split, so these tests refuse 40001 and check the result, the audit keys and the install case. |
| `system-actions-table-1.17.61.py` | Three rows, not two. A username is allowed for `scripts.run` only. |
| `system-actions-registry-1.17.61.py`, `system-actions-audit-1.17.61.py` | Install is accepted for the replacement. The capability is 1.1.0 with a new operation. The run row has three more keys. |
| `contract-catalog-1.17.61.py` | Capability 1.1.0. It no longer reads the requests files, which move on as modules ship what they asked for (the record is the questions file). |
| `system-actions-compat-1.17.61.py` | `start_one_off_run` has one more keyword. The module search looks for the system-action names only, because certificatemanagement has adopted `pending_completion`. This test was failing before this release for that reason. |
| `scheduler-compat-1.17.63.py` | `reconcile_schedule` and `start_one_off_run` each have one more last keyword. |
| `scheduler-module-owned-creator-1.17.63.py` | Its first five sections prove the CQ176 mechanics of an ordinary action, so nothing is registered with `core.system_actions` there. Section 6 registers them as before. |
| `module-job-contract-rows-1.17.60.py` | It no longer reads `requests/ui.md`: the UI worked that request and removed it. |

## What was left out, and what ends each wait

I left these out because Core cannot build them safely, or because Johan has not signed the design. Each one has a question for him (`reviews/questions/core.md`) and a request to the module that needs it (`reviews/requests/`).

- **Rule push (CQ174, CQ192).** Johan said yes, and "never a synthetic request". Core's executor for declared operations needs a real authenticated request, and a scheduled run has none. AD-19 says Core never substitutes a user. Running `PUT winupdate/<id>/` in a schedule would need a request Core builds itself, which is the CQ8 option Johan rejected. Both parts of his answer cannot hold, so nothing is built. Ends when he chooses how. Advanced Patch Management keeps a person-started "apply now" button.
- **Reboot with a result (CQ193).** Tactical v1.5.2 has no Celery task for it. Its reboot-now view calls `agent.nats_cmd` and waits for the answer, and AD-13 says Core calls Tactical's own task functions. Tactical's reboot-later (`PATCH agents/<id>/reboot/` with a date) is a declared operation a person makes at creation time and needs no Core row. A recurring or unattended reboot needs a dispatch path Johan has not signed. Ends when he signs one.
- **Software package uninstall (CQ193).** No task function either. Tactical builds a raw command from the endpoint's own installed-software record and sends it over NATS. A patch KB uninstall ships as a script run through `scripts.run` (Script Execution's contract), so Core builds no command text.
- **Commands (CQ194).** `bulk_command_task` exists, but the command text would have to be held in the schedule and shown in the list, the run snapshot and the audit row. AD-32 masks commands in audit rows, and Johan listed "no free-form command from a caller". The owner would be remote-background (AD-18). Ends when he decides how it is stored and masked.
- **Checks run, tasks run and reports (CQ193).** Not table rows. Tactical has no task function for "run checks", `run_win_task` takes a task number and not endpoint numbers, and a report email takes free recipients. Tactical already schedules all three natively. Ends when Johan answers.
- **A module-owned target type.** The target-resolver contract (`reviews/requests/core.md`) is design work for a new contract that Johan has not seen. Maintenance and Advanced Patch Management profile targets stay refused as `targets_unresolved`.
- **R-36 and Tactical's native patching paths.** Johan said not to build R-36. Switching off Tactical's own patching paths while a replacement is honoured is a separate large item with its own review.
- **Not Core's, or waiting for Johan's word.** `core.tactical_operations` allowing `deny` in `audit.action_by_body`, flipping `licensing_enforcement_mode` to enforce (Johan has not named the release), and the two newer UI 0.12.119 requests (System Updates and server-maintenance job logs, and the audit wording for a finished system update) are not in this release's plan.
- **The authority documents.** `docs/review-accepted-decisions.md` row 13, `docs/tec-tac-module-standard.md` section 1a (the AD-13 line), `docs/tec-tac-development-rules.md` rule 1.7 and `docs/review-checklist.md` A2 should record the signed rows, the groups, install for the honoured replacement with a warning and the rule-push sign-off. These are not Core's files. The coordinator or release manager records them from Johan's chat words. His answers are written in `reviews/questions/core.md` as they were relayed to me, quoted there.

## What could not run on this PC

- Django is not installed here. The tests use the existing stub harness. `scheduler_views.py` is read as source, and its new helper is run under a spy. The real `POST` and `PATCH` views, the new route under a real Django, and `manage.py tec_tac_check_contract_export` have not run.
- `makemigrations --check` and `migrate` could not run. There is no model change and no migration in this release.
- `tests/system-actions-runtime-1.17.66.py` and the export check need the dev server.
- I cannot export the public contract. The gate reports "not run" until an export for 1.17.66 is in `docs/contracts`.

Checks that ran here: `bash tests/release-integrity.sh`, every test named above, the tests that pin earlier behaviour (all of `tests/system-actions-*`, `tests/scheduler-*` and the contract tests), `python -m py_compile` on every changed file, and the pipeline's own ruff gate (`ruff check --select E9,F63,F7,F82`).

## Dev-server checklist (PASS or FAIL for each step)

Do this after the signed build is installed. Do not test while an install is running. Use dev02 and two test endpoints.

**Step 0. Update, migrate and check.**
1. Update Core from the dev branch.
2. Run: `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py migrate tec_tac`
3. Expect: `No migrations to apply.`
4. Run: `../env/bin/python manage.py makemigrations --check --dry-run`
5. Expect: `No changes detected`.
- **FAIL** if a migration is applied, or if `makemigrations` wants to write a file. Send back the full output of both commands.

**Step 1. Restart.**
1. Restart Core and the Celery workers (the same commands as for 1.17.65).
2. Run: `curl -i -X POST https://<dev server>/api/tfd/scheduler/system-actions/confirmation/`
3. Expect: `401` (or `403`), not `404` and not `500`. The route exists and wants a signed-in person.
- **FAIL** if the answer is `404` or `500`, or if Core does not start. Send back the answer and the last 50 lines of the Core log.

**Step 2. Groups, confirmation and the run, on real endpoints.**
1. Pick a Tactical user whose role holds `can_manage_winupdates` and `can_run_bulk` and covers two test endpoints. Note the two agent numbers.
2. Run: `cd /rmm/api/tacticalrmm && TECTAC_PROBE_USER=<username> TECTAC_PROBE_AGENT=<agent 1> TECTAC_PROBE_AGENT2=<agent 2> ../env/bin/python manage.py shell < /path/to/tests/system-actions-runtime-1.17.66.py`
3. Expect: seven `PASS` lines (1 to 7) and `PASS Core 1.17.66 system actions runtime`. Both endpoints show a Windows update scan in Tactical within a minute or two.
- **FAIL** if any line says `FAIL`, or if only one endpoint is scanned. Send back the whole output.

**Step 3. Export and compare.**
1. Export a fresh public contract into `docs/contracts` (the way you did for 1.17.65).
2. Run: `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py tec_tac_check_contract_export "/path/to/docs/contracts/<the new file>.md"`
3. Expect: `PASS: <file> matches the contract of Core 1.17.66.`
4. Check that the file says `Framework: **1.17.66**` and that `core.system_actions` shows capability version `1.1.0`, operations `list_actions`, `get_action`, `run`, `describe_confirmation`, and three functions.
- **FAIL** if the command prints any `FAIL:` line. Send back every line. A line about a module's own capability text (not Core's) is worth a look, but send it back anyway.

**Step 4. The job log headers in the browser.**
1. Open Module Manager, History, and open the full log of any job.
2. In the browser's developer tools, Network tab, open the log request (`.../modules/v2/jobs/<id>/log/`).
3. Expect: the response headers include `Access-Control-Expose-Headers` with the four names `X-Tec-Tac-Log-Truncated`, `X-Tec-Tac-Log-Bytes`, `X-Tec-Tac-Log-Kept` and `Content-Disposition`, and the three `X-Tec-Tac-Log-` headers.
4. Open the same log with `?download=1`. Expect `Content-Disposition: attachment; filename="module-job-...log"`.
- **FAIL** if `Access-Control-Expose-Headers` is missing, names fewer than four headers, or the log no longer opens. Send back the response headers.

**Step 5. An ordinary schedule is unchanged.**
1. In the Scheduler page, create a schedule for an ordinary action (for example a Backups action), then press Run now.
2. Expect: it saves and runs exactly as before. No confirmation text is asked for.
- **FAIL** if the save is refused with a confirmation message, or the run does not start. Send back the answer text.

**Step 6. No system-action schedule without the id.** The Scheduler page cannot show the confirmation text yet: that is the UI request ("From Core 1.17.66" in `reviews/requests/ui.md`). Until then a person can create a system-action schedule only through a module that passes the id. No module registers a system action yet, so this step is a read of the answer, not a test you can run today.
- **FAIL** only if you find a way to create a schedule for a system action through `POST /api/tfd/scheduler/schedules/` without a `confirmation_id` and it saves. Send back the request and the answer.
