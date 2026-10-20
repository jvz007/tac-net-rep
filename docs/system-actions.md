# System actions (core.system_actions 1.1.0, Core 1.17.66)

A system action lets Core run a small, fixed piece of Tactical work when nobody is signed in. The first use is a scheduled patch scan: "scan these endpoints for Windows updates every night". The person who set up the schedule is still the owner.

**Where the check sits (since 1.17.65 and 1.17.66).** Core checks the person's permission and Tactical scope, and asks one plain Yes or No, when the person **creates or edits** the schedule or starts a one-off run (see "Creating or editing a schedule"). A run a person starts keeps every re-check. A **scheduled** run is not re-checked against its creator, as in Tactical (see "Scheduled runs are not re-checked").

**What is new in 1.17.66 (capability version 1.1.0, additive).** A run of more than 2000 endpoints is split into groups of at most 2000 instead of being refused (CQ178). The table gains `scripts.run` (CQ175). `winupdate.install` may be registered by the honoured replacement, with a fixed warning (CQ173). Parameters come only from what the person confirmed. A person who creates or edits a schedule gets the permission and scope check and one Yes or No at that moment.

This page is for module developers and for administrators who want to know what a module with this power can and cannot do.

## What it is, and what it is not

- **It is typed.** Core holds one fixed table, `SYSTEM_FUNCTIONS`, of the Tactical functions it will reach. A module picks a row by key. It never names a function, a path or a URL.
- **It is in-process.** Core imports the Tactical task named in the table and calls `.delay()` on it, the same way Tactical's own bulk view does. There is no loopback HTTP call, no API key, no service account, no model write and no route call.
- **It is queued, not done.** The result says `Queued in Tactical; the result shows in each endpoint's update list.` Core never says "done".
- **It is not a free path into Tactical.** Reboot, uninstall, commands, checks, tasks and reports are not in the table. A new row is a Core release, like a new route owner.

This is AD-13 (rules 1.7, standard section 1a). Core calling Tactical's own task functions is the named exception to "Core talks to Tactical's auth and accounts only". It reaches only what the table lists.

## The table today

| Key | Tactical function (v1.5.2) | Owner | Minimum flags | Notes |
|---|---|---|---|---|
| `winupdate.scan` | `winupdate.tasks.bulk_check_for_updates_task(pks)` | `patching`, or its honoured replacement | `can_manage_winupdates` and `can_run_bulk` | Fire and forget. |
| `winupdate.install` | `winupdate.tasks.bulk_install_updates_task(pks)` | `patching`, or its honoured replacement (since 1.17.66) | `can_manage_winupdates` and `can_run_bulk` | Re-approves updates by patch policy first (`reapproves_by_policy`). Core shows a fixed warning. |
| `scripts.run` | `scripts.tasks.bulk_script_task(script_pk, agent_pks, args, timeout, username, run_as_user, env_vars, custom_field_pk, collector_all_output, save_to_agent_note)`, keywords only (since 1.17.66) | `scriptexecution` | `can_run_bulk` and `can_run_scripts` | Takes the creator's stored name as the username and the parameters the person confirmed. |

The minimum flags are stricter than either Tactical route alone. Tactical's single-agent route needs `can_manage_winupdates`. Its bulk route needs `can_run_bulk`. Core needs both. For `scripts.run` Core needs `can_run_bulk` and `can_run_scripts`: Tactical's bulk route needs only `can_run_bulk`, so this is stricter on purpose.

**Install and the warning (CQ173, Johan: yes, 20 October 2026).** Tactical's bulk install task calls `approve_updates()` first, and that flips an update the replacement set to Ignore back to Approve when the patch policy approves its severity. Since 1.17.66 the honoured replacement (Advanced Patch Management) may register and run install, and Windows Patching keeps it. Core does not stop Tactical doing this (R-36 is not built). Core shows this fixed text in the confirmation and writes it in the audit row of every install: "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere."

**Username.** The two winupdate tasks take no username, so only Core's audit row names the owner for them. `scripts.run` takes one: Core always passes the creator's stored name (the first 50 characters, as Tactical does for its own bulk script route). A name from the caller is never used. The `username_param` setting is refused for a function that takes none.

**Parameters.** A row with a parameter schema reads its parameters only from the run's confirmed record (the schedule's parameters under the key `system_action_parameters`, copied onto the run when it starts). The `parameters` argument of `run_system_action` must be `None`, `{}` or equal to that record, otherwise the run is refused as `parameters_changed`. A shape the schema does not allow is `bad_parameters`. For `scripts.run` the schema is: `script_pk` (whole number, required), `args` and `env_vars` (lists of at most 50 texts of at most 1000 characters), `timeout` (1 to 86400 seconds, default 90), and the booleans `run_as_user`, `collector_all_output` and `save_to_agent_note`. Any other key is refused, so there is no free-form command. The audit rows carry `script_pk` and the counts of arguments and environment values, never the values.

## The five AD-13 conditions and how each is met

1. **Typed actions only.** `register_system_action` takes a table key. The action id must also be listed in the module's signed manifest under `system_actions`, so the manifest shows an administrator that the module can run unattended Tactical work.
2. **Permission and scope where Tactical checks them.** The save-time checks stay where they were (the action permission and the target scope when a schedule or one-off run is created or edited). A run a **person starts** (a manual run or a one-off run) also re-reads the owner at that run: active, not an installer user, every Tactical flag the action needs, and the owner's Tactical role scope. A **scheduled** run of a user-owned schedule skips only that re-read (since 1.17.65, see "Scheduled runs are not re-checked" below).
3. **Run as the creator.** The audit row names the person who created the schedule as the actor, with `requested_by` set to `scheduler`, and says who confirmed it and whether a person or the schedule started the run. When the creator's user row is gone, the actor is a Core service actor and the stored name is in the row.
4. **No HTTP, no keys.** In-process only (see above).
5. **Only the owning core module registers.** The table names the owner. The premium module that honourably replaces it (AD-20) may register too, and only while that is honoured.

## Declaring and registering (a module developer's steps)

Needs `requires.framework >=1.17.61`. An older Core refuses a manifest that has the new key.

1. List the ids in `tec_tac.json`:

   ```json
   { "system_actions": ["patching.scan", "patching.install"] }
   ```

   A list of at most 20 ids, each `<module id>.<name>` in lowercase letters, digits, `-` and `_`. Extensions only; a reportset may not declare it. The root job helpers keep no allow-list of manifest keys, so they ignore it.

2. Register each one from `AppConfig.ready()`:

   ```python
   from tec_tac.system_actions import register_system_action, SystemActionRegistrationError

   try:
       register_system_action(
           "patching.scan", "patching", "Scheduled patch scan", "winupdate.scan",
           ["can_manage_winupdates", "can_run_bulk"],
       )
   except SystemActionRegistrationError:
       logger.exception("system action not registered")
   ```

   It touches memory only. A module may add flags to `permissions`, never remove one.

3. In your own Scheduler handler, pass the context you received:

   ```python
   from tec_tac.system_actions import run_system_action

   def scan_handler(context):
       return run_system_action(context, action_id="patching.scan", agent_ids=[12, 13, 14])
   ```

   `agent_ids` are Tactical agent numbers (database ids). The schedule needs a person behind it: a user-owned schedule or a one-off run (`start_one_off_run`). A module-owned recurring schedule has no owner today, so a system action refuses it (CQ176).

## Registration refusals

| Refusal | Why |
|---|---|
| Not a key of the table (a dotted path, a callable, unknown text) | A module cannot name its own callable. |
| Not the table's owner or its honoured replacement | Only the owning core module may register. |
| The owner is not a core module | AD-21. |
| Replacement not honoured right now | Logged. Nothing is registered. `None` comes back, no exception, so `ready()` never fails. |
| Flags below the table minimum, an unknown flag, more than 8 flags | A module may add flags, never remove one. |
| Id not in the signed manifest, badly formed, or another module's prefix | The manifest is what the administrator sees. |
| `username_param` for a function that takes none | Core would pass a name Tactical does not read. |
| Disabled, legacy, missing or unreadable module | Fail closed. |

Registering the identical definition again is idempotent. A different definition under the same id is refused.

## Every run: the checks, in order

Each refusal ends the run `skipped` with error type `SystemActionRefused`, writes **one** `deny` audit row and raises `SystemActionRefused` (a `SchedulerPermanentError`, so the worker does not retry). The exceptions are `caller_unverified` and `wrong_module`: they write the row and raise, but they do not end the run, so code that is not the run's module cannot end another module's run. The run's own handler then fails with the refusal.

| Reason code | Check |
|---|---|
| `context_invalid` | The context is the object Core issued for a run that is still going. A copy, a hand-built dict and a context from a finished run are refused. |
| `owner_refused` | The person who owns the schedule may still run it (the same check as `verify_run_context`). |
| `no_owner` | A person is behind the run: a user-owned schedule, a one-off run, or (since 1.17.63) a scheduled run that has a stored creator name. A module-owned run with no person and no stored creator is refused. |
| `caller_unverified` | Core can name the calling module from the call stack. |
| `wrong_module` | The caller is the run's module and the action's registered module. |
| `unknown_action` | The action is registered. |
| `action_not_declared` | Since 1.17.63: the action id is still listed in the module's signed manifest under `system_actions` right now. Before, Core checked it only when the action was registered. |
| `module_disabled` | The owning module is enabled right now (read fresh, never cached). |
| `replacement_not_honoured` | An action registered by a replacement still has an honoured replacement right now. |
| `owner_inactive` | The owner, read again from the database, is active and not an installer user. **Skipped for a scheduled run (1.17.65).** |
| `permission_lost` | The owner holds every Tactical flag now. **Skipped for a scheduled run (1.17.65).** |
| `bad_parameters` | The confirmed parameters fit the row's schema (the winupdate rows take none). |
| `parameters_changed` | Since 1.17.66: the `parameters` argument is `None`, `{}` or equal to what the person confirmed. |
| `bad_agents`, `agent_count` | 1 to 40000 whole endpoint numbers (20 groups of 2000, since 1.17.66; 2000 before). Above the ceiling is refused whole, never truncated. |
| `out_of_scope` | Every endpoint exists and lies inside the owner's Tactical role scope. One endpoint outside refuses the whole call. Nothing is narrowed silently. A scheduler manager gets no bypass here, because Core's scheduler-manager shortcut would widen rights for a Tactical function. **Skipped for a scheduled run (1.17.65)** (the scope was checked when the schedule was made, and `outside_targets` below still holds the run to the saved targets). |
| `reapproves_by_policy` | Not returned since 1.17.66 (CQ173). The code stays in the list so a module that names it does not break. |
| `function_unavailable` | Core can import the Tactical function. A Tactical upgrade can never make Core call something else. |
| `mark_limit` | A run holds at most 100 marks (one per group; five full calls of 20 groups). Judged before any group is sent. |
| `not_permitted`, `confirmation_required`, `confirmation_invalid` | Since 1.17.66, at creation, edit or a one-off start (see "Creating or editing a schedule"). They are raised as `SystemActionCreationRefused`, not by `run_system_action`. |
| `outside_targets` | Since 1.17.62: every endpoint is one of the run's snapshotted schedule targets. A run never widens the schedule's set. A target that no longer exists is counted in the refusal text. |
| `targets_unresolved` | Since 1.17.62: Core can read the run's snapshot as endpoints (a client, a site, endpoints, or the Tactical scope of a dynamic target, which is an upper bound: the module's own filter only narrows it). A module-owned target type cannot be read, so it is refused. `none` names no endpoint, so it refuses as `outside_targets`. |

The count and shape are judged before any database lookup. The targets check (1.17.62) runs after the scope check, so the owner's role scope still decides first.

A system action that names endpoints needs a schedule that targets them. A module whose schedule uses a module-owned target type has to give Core a way to read it: that is a request to Core (a target resolver contract), not a private path. Until it exists the run is refused with `targets_unresolved` and nothing is sent.

## Scheduled runs are not re-checked (Core 1.17.65, AD-13 condition 2 amended)

Johan signed this on 20 October 2026 (CQ179, CQ184 b, CQ186, CQ189). It is recorded in `docs/tec-tac-module-standard.md` section 1a and `docs/review-accepted-decisions.md` row 13, and `scheduler.AD13_CONDITION_2_AMENDED` is True. Core follows Tactical: a scheduled task keeps running after the person who made it is demoted or deactivated, because the right is checked when the task is created or edited, not at each run (reference `autotasks/views.py` `AutoTaskPerms` and `RunAutoTaskPerms`, `autotasks/models.py` `create_task_on_agent` over NATS, `apiv3/views.py` `TaskRunner.patch`).

**What is exempt.** Every run the schedule starts on its own (never `manual`, never a one-off) on a user-owned schedule, for every registered action. A module-owned schedule with a stored creator name is exempt only while the action id is still listed in the module's signed manifest `system_actions` and registered with `core.system_actions` by that module. A schedule with no stored creator name and a deleted creator (made before migration 0036) is still refused. The `unattended=True` keyword of `register_scheduled_action` is still accepted, still validated, and has no effect. The one place that decides this is `tec_tac.scheduler._is_unattended_scheduled_run`.

**What changes for a scheduled run.** Core does not re-read the creator's rights. In the tick, a demoted or deactivated creator no longer causes `AuthorizationRevoked`. In `verify_run_context` the run verifies with `creator_username`, `confirmed_by_username` and `unattended` set. In `run_system_action` exactly three refusals are skipped: `owner_inactive`, `permission_lost` and `out_of_scope`.

**What stays, for every run.** The signed context and the caller check (`context_invalid`, `caller_unverified`, `wrong_module`), `unknown_action`, `action_not_declared`, `module_disabled`, `replacement_not_honoured`, `bad_parameters`, `bad_agents`, `agent_count` (2000 at most, refused above), `outside_targets` (the snapshot is never widened), `targets_unresolved`, `reapproves_by_policy`, `function_unavailable`, `mark_limit`, the at-most-once mark and the strict audit row before the send. `has_tactical_permission` and `resource_context` stay fresh reads.

**What a person-started run keeps.** A manual run and a one-off run keep every re-check, exactly as before (CQ50 a).

**Who is on the record.** Migration 0036 adds `created_by_username` and `confirmed_by_username` to the schedule. Creating a schedule stores the signed-in person as both. An edit sets the editor as `confirmed_by_username`, after the unchanged permission and scope checks. A row made before 0036 reads its creator from `created_by`. Every `run`, `deny` and `custom:outcome-unknown` row of a system action carries `run_kind` (`scheduled` or `person`), `creator` and `confirmed_by`. An administrator can list schedules by creator or confirmer: `GET /api/tfd/scheduler/schedules/?created_by=<name>&confirmed_by=<name>` (see `docs/scheduler.md`).

**The cost, in plain words.** A person who is demoted or deactivated later keeps their schedules running until someone removes or edits them. That is how Tactical works. An administrator can find those schedules by creator and remove or disable them. A module whose handler wants its own live check can call `has_tactical_permission` or `resource_context` on the verified run: both still read the owner fresh.

**When targets vanished.** If some snapshotted targets no longer exist but the endpoints you name are all still targets, the run goes ahead and the result gains `vanished_targets` (a count). The run's audit row carries it too. If you name an endpoint that is not a target, the whole call is refused as `outside_targets`, and the text says how many targets no longer exist.

## Groups: more than 2000 endpoints (Core 1.17.66, CQ178)

Johan signed this on 20 October 2026: more than 2000 splits into groups of at most 2000. Core never truncates and never refuses for size alone.

1. **The whole set is judged first.** Shape, the count against the ceiling, the scope for a person-started run, `outside_targets`, `targets_unresolved`, the parameters, declared, enabled and honoured. One failure refuses the whole call. Nothing is sent and no mark is written.
2. **The ceiling is 20 groups: 40000 endpoints in one run** (an assumption that Johan has been asked to confirm, CQ195). Above it the call is refused with `agent_count`.
3. **The ids are sorted and cut into groups of at most 2000.** No id appears twice and none is lost.
4. **Each group is its own at-most-once send:** its own mark (a digest of the run id, the action id and that group's ids), its own strict audit row and its own `.delay()`.
5. **A failed audit write sends nothing for that group.** The mark is set to `aborted` and the run fails as a transient error. A retry sends that group once. A group that was already sent is skipped.
6. **A group whose mark is stuck at `claiming`, or whose send raised, ends the run failed as `OutcomeUnknown`.** It is never sent again, and every later group stays not started.
7. **The result** keeps `outcome`, `agents` (the total) and `message`, and gains `groups` (`{total, sent, failed, not_started}`) and one plain `summary` line, for example "4500 endpoint(s) in 3 group(s): 3 sent, 0 failed, 0 not started." A failure text carries the same counts. Counts only: no endpoint ids in any row, result or text.

Core does not hold the Tactical work back between groups. Each group is queued at once and Tactical runs them as its workers allow.

## Then: at most once, audited, sent (each group)

1. Core writes a mark on the run row (`{action_id, targets_digest, state: "claiming"}`) under a row lock and commits.
2. Core writes one **strict** audit row: action `run`, object type `system_action`, object id the action id, actor the creator (or a Core service actor when the user row is gone), metadata `requested_by`, `run_id`, `schedule_id`, `owner_module`, `function`, `agent_count` (this group), `total_agents`, `group`, `groups`, `targets_digest` and, since 1.17.63, `run_kind`, `creator`, `confirmed_by` (and `vanished_targets` when some targets no longer exist; for `scripts.run` also `script_pk`, `args_count` and `env_vars_count`; for install also `warning`). No endpoint ids and no hostnames. The digest is a short hash bound to the run id. It is not a secret.
3. Only if both commits worked, Core calls the Tactical task with `.delay()` and sets the mark to `sent` with the Celery task id.

What follows from that:

- **If the audit row cannot be written, nothing is sent for that group.** The mark is set to `aborted`. The run fails as a transient error, so a retry sends once.
- **A retry or duplicate delivery that finds a `sent` mark sends nothing again.** It returns the same result with `duplicate: true`.
- **A mark stuck at `claiming`, or a send that raised, fails the run as `OutcomeUnknown`** and is never sent again. One `custom:outcome-unknown` audit row is written.
- The trade is plain: a scan may be missed. An install is never done twice.

## Creating or editing a schedule (Core 1.17.66, AD-13 as amended)

The amended AD-13 puts the whole check where the person acts. For a **declared system action** (the action id is listed in the module's signed manifest `system_actions` and registered with `core.system_actions`; the scheduled action id equals the system action id) Core checks the following when a person creates or edits the schedule, or starts a one-off run. The paths are `POST` and `PATCH /api/tfd/scheduler/schedules/`, `reconcile_schedule(..., confirmed_by_request=request, confirmation_id=...)` and `start_one_off_run(..., confirmation_id=...)`.

1. The owning module's own permission (the `permission` entries of the scheduled action).
2. Every Tactical flag of the table row and of the registration, with **no bypass for a scheduler manager**.
3. The person's Tactical scope over every target endpoint. One miss refuses the whole call.
4. The targets read as endpoints (a module-owned target type stays refused as `targets_unresolved`) and the total is within the ceiling.
5. The parameters fit the row's schema.
6. The module is enabled and a replacement is honoured now.
7. A **confirmation id** that Core issued for this person, action, targets, parameters and timing in the last 600 seconds.

**The one Yes or No.** The UI (or a module with the person's own request) calls `POST /api/tfd/scheduler/system-actions/confirmation/` with `action_id`, `targets`, `parameters` and `when`. Core runs checks 1 to 6 first, so a person who may not create the schedule gets a refusal and one deny audit row, never a text. Otherwise the answer holds a plain text and the id. The text names what will happen, the endpoints, the total, the number of groups, when, the fixed warning where there is one, and the plain cost: "It runs as a schedule. Core does not check your rights again when it runs, so it keeps running until someone edits or removes it." The UI shows the text in its plain Yes/No dialog (no typing), and sends the id back as `confirmation_id`. The capability operation `describe_confirmation(request, *, action_id, targets, parameters=None, when=None)` gives a module the same answer for the person behind a real, session-checked request.

**What the id proves.** It proves the text was produced for that person, action, targets, parameters and timing. It does **not** prove the person pressed Yes, because Core cannot see the button. It is signed with the server's secret, valid for 600 seconds and never stored.

**What is audited.** A refusal writes one `deny` row (a reason code, no endpoint ids). An allowed creation or edit writes one strict row (`add` or `modify` on the schedule) with the creator, the confirmer, the schedule, `total_agents`, `groups` and `when`. A vanished target is reported in the text, the run result and the audit row.

**What is not touched.** A scheduled action that is not a declared system action behaves exactly as before. A schedule that stays switched off, and an edit that changes only the name or the policies of a schedule that is already on, need no id. A scheduled run is never re-checked against its creator.

## The honest limits

- Modules run in the same Python process as Core. Code that deliberately reaches into Core's private state is outside what this stops. The caller check (`docs/caller-identity.md`) names the module whose own code calls the function. Core code, library code, generated code, and disabled and legacy modules are refused.
- Tactical's own winupdate tasks take no username. Only Core's audit row names the person for them.
- An unattended schedule outlives the creator's rights, as in Tactical (see "Unattended scheduled runs"). It is opt-in per action, and the audit row and the creator filter make it visible.
- Core does not follow the work after the send. Tactical shows the result in each endpoint's update list.
- There is one HTTP route for system actions, the confirmation route. There is no global off switch. Disable the owning module, or its schedule, to stop a run.
- The confirmation id does not prove that a button was pressed (see above).
- Core holds no run back between groups, and a group already queued in Tactical cannot be recalled.
- Pushing patch-rule decisions to Tactical on a schedule is not built (CQ174, answered yes by Johan, see "Not in this release").
- Commands, reboot with a result, software package uninstall, checks, tasks and reports are not in the table (see "Not in this release").

## Not in this release

Johan answered CQ173 (yes), CQ174 (yes), CQ175 (the whole list is signed) and CQ178 (groups of at most 2000) on 20 October 2026. Core 1.17.66 builds scheduled install for the honoured replacement, groups, and the `scripts.run` row. What waits, and why:

- **Pushing rule decisions (CQ174).** Johan said it runs the same Tactical operation a person uses, "never a synthetic request". Core's executor for declared operations needs a real authenticated request, and a scheduled run has none, so the two cannot both hold. A new question (CQ192) asks him how. Advanced Patch Management keeps a person-started "apply now" meanwhile.
- **Reboot with a result, software package uninstall and checks.** Tactical v1.5.2 has no Celery task function for them. Its views send NATS commands in-process, and AD-13 says Core calls Tactical's own task functions. Tactical's own "reboot later" (`PATCH agents/<id>/reboot/` with a date) is a declared operation a person makes at creation time and needs no Core row. A new question (CQ193) asks Johan which dispatch path he signs.
- **Commands.** `bulk_command_task` exists, but the command text would have to be stored in the schedule and shown in the list, the run snapshot and the audit row. A new question (CQ194) asks how it is stored and masked.
- **Patch KB uninstall.** Tactical has no such function. It runs as a script through `scripts.run` (Script Execution's contract), so Core builds no command text.
- **Tasks and reports.** `run_win_task` takes a task number, not endpoint numbers, and a report email takes free recipients. Tactical already schedules tasks and reports natively. They wait on CQ193.
- **A module-owned target type.** Maintenance and Advanced Patch Management profile targets stay `targets_unresolved` until a target resolver contract exists.
- Module-owned recurring schedules with a named acting person are built in 1.17.63 (CQ176, `reconcile_schedule(..., confirmed_by_request=request)`, see `docs/module-scheduling.md`).
- Polling a module's capability for a final state from the tick (CQ177). A run that finishes later uses `pending_completion` (see `docs/scheduler.md`).
- A UI for system actions. The Scheduler page shows a waiting run once the UI release for 1.17.61 ships.
