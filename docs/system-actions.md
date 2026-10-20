# System actions (core.system_actions 1.0.0, Core 1.17.61)

A system action lets Core run a small, fixed piece of Tactical work when nobody is signed in. The first use is a scheduled patch scan: "scan these endpoints for Windows updates every night". The person who set up the schedule is still the owner. Core checks that person again at every run.

This page is for module developers and for administrators who want to know what a module with this power can and cannot do.

## What it is, and what it is not

- **It is typed.** Core holds one fixed table, `SYSTEM_FUNCTIONS`, of the Tactical functions it will reach. A module picks a row by key. It never names a function, a path or a URL.
- **It is in-process.** Core imports the Tactical task named in the table and calls `.delay()` on it, the same way Tactical's own bulk view does. There is no loopback HTTP call, no API key, no service account, no model write and no route call.
- **It is queued, not done.** The result says `Queued in Tactical; the result shows in each endpoint's update list.` Core never says "done".
- **It is not a free path into Tactical.** Reboot, uninstall, scripts and commands are not in the table. A new row is a Core release, like a new route owner.

This is AD-13 (rules 1.7, standard section 1a). Core calling Tactical's own task functions is the named exception to "Core talks to Tactical's auth and accounts only". It reaches only what the table lists.

## The table today

| Key | Tactical function (v1.5.2) | Owner | Minimum flags | Notes |
|---|---|---|---|---|
| `winupdate.scan` | `winupdate.tasks.bulk_check_for_updates_task(pks)` | `patching`, or its honoured replacement | `can_manage_winupdates` and `can_run_bulk` | Fire and forget. |
| `winupdate.install` | `winupdate.tasks.bulk_install_updates_task(pks)` | `patching` only | `can_manage_winupdates` and `can_run_bulk` | Re-approves updates by patch policy first (`reapproves_by_policy`). |

The minimum flags are stricter than either Tactical route alone. Tactical's single-agent route needs `can_manage_winupdates`. Its bulk route needs `can_run_bulk`. Core needs both.

`winupdate.install` is refused for a replacement (Advanced Patch Management) while R-36 is open. Tactical's bulk install task calls `approve_updates()` first, and that flips an update the replacement set to Ignore back to Approve when the patch policy approves its severity. Windows Patching has Tactical's own behaviour, so it may register install. This is CQ173.

Neither Tactical task takes a username. Only Core's audit row names the owner for these two rows. A later row that has a username parameter will pass the owner's name through. The `username_param` setting is refused for a function that takes none.

## The five AD-13 conditions and how each is met

1. **Typed actions only.** `register_system_action` takes a table key. The action id must also be listed in the module's signed manifest under `system_actions`, so the manifest shows an administrator that the module can run unattended Tactical work.
2. **Permission and scope where Tactical checks them.** The save-time checks stay where they were (the action permission and the target scope when a schedule or one-off run is created or edited). A run a **person starts** (a manual run or a one-off run) also re-reads the owner at that run: active, not an installer user, every Tactical flag the action needs, and the owner's Tactical role scope. A **scheduled** run of an action the module flagged `unattended` skips only that re-read (since 1.17.63, see "Unattended scheduled runs" below).
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
| `winupdate.install` for a replacement | R-36 / CQ173, above. |
| Disabled, legacy, missing or unreadable module | Fail closed. |

Registering the identical definition again is idempotent. A different definition under the same id is refused.

## Every run: the checks, in order

Each refusal ends the run `skipped` with error type `SystemActionRefused`, writes **one** `deny` audit row and raises `SystemActionRefused` (a `SchedulerPermanentError`, so the worker does not retry). The exceptions are `caller_unverified` and `wrong_module`: they write the row and raise, but they do not end the run, so code that is not the run's module cannot end another module's run. The run's own handler then fails with the refusal.

| Reason code | Check |
|---|---|
| `context_invalid` | The context is the object Core issued for a run that is still going. A copy, a hand-built dict and a context from a finished run are refused. |
| `owner_refused` | The person who owns the schedule may still run it (the same check as `verify_run_context`). |
| `no_owner` | A person is behind the run: a user-owned schedule, a one-off run, or (since 1.17.63) a scheduled unattended run that has a stored creator name. A module-owned run with no person and no stored creator is refused. |
| `caller_unverified` | Core can name the calling module from the call stack. |
| `wrong_module` | The caller is the run's module and the action's registered module. |
| `unknown_action` | The action is registered. |
| `action_not_declared` | Since 1.17.63: the action id is still listed in the module's signed manifest under `system_actions` right now. Before, Core checked it only when the action was registered. |
| `module_disabled` | The owning module is enabled right now (read fresh, never cached). |
| `replacement_not_honoured` | An action registered by a replacement still has an honoured replacement right now. |
| `owner_inactive` | The owner, read again from the database, is active and not an installer user. **Skipped for a scheduled unattended run.** |
| `permission_lost` | The owner holds every Tactical flag now. **Skipped for a scheduled unattended run.** |
| `bad_parameters` | The function takes none. |
| `bad_agents`, `agent_count` | 1 to 2000 whole endpoint numbers. Above 2000 is refused, never truncated. |
| `out_of_scope` | Every endpoint exists and lies inside the owner's Tactical role scope. One endpoint outside refuses the whole call. Nothing is narrowed silently. A scheduler manager gets no bypass here, because Core's scheduler-manager shortcut would widen rights for a Tactical function. **Skipped for a scheduled unattended run** (the scope was checked when the schedule was made, and `outside_targets` below still holds the run to the saved targets). |
| `reapproves_by_policy` | A function that re-approves updates is not run for a replacement. |
| `function_unavailable` | Core can import the Tactical function. A Tactical upgrade can never make Core call something else. |
| `mark_limit` | A run sends at most 20 different system actions. |
| `outside_targets` | Since 1.17.62: every endpoint is one of the run's snapshotted schedule targets. A run never widens the schedule's set. A target that no longer exists is counted in the refusal text. |
| `targets_unresolved` | Since 1.17.62: Core can read the run's snapshot as endpoints (a client, a site, endpoints, or the Tactical scope of a dynamic target, which is an upper bound: the module's own filter only narrows it). A module-owned target type cannot be read, so it is refused. `none` names no endpoint, so it refuses as `outside_targets`. |

The count and shape are judged before any database lookup. The targets check (1.17.62) runs after the scope check, so the owner's role scope still decides first.

A system action that names endpoints needs a schedule that targets them. A module whose schedule uses a module-owned target type has to give Core a way to read it: that is a request to Core (a target resolver contract), not a private path. Until it exists the run is refused with `targets_unresolved` and nothing is sent.

## Unattended scheduled runs (Core 1.17.63, CQ179 b)

Johan answered "yes follow tactical's implementation" in chat on 20 October 2026. **Status since 1.17.63-1: the exemption described below is built but switched off** (`scheduler.AD13_CONDITION_2_AMENDED = False`), because the amended AD-13 condition 2 is not yet recorded in `docs/review-accepted-decisions.md` and `docs/tec-tac-module-standard.md` section 1a. Every scheduled run keeps the run-time re-check until the release that records it also sets the switch to True. Core follows Tactical here once that is done. In Tactical, a scheduled task keeps running after the person who made it is demoted or deactivated: the right is checked when the task is created or edited, not at each run (reference `autotasks/views.py` `AutoTaskPerms` and `RunAutoTaskPerms`, `autotasks/models.py` `create_task_on_agent` over NATS, `apiv3/views.py` `TaskRunner.patch`). Core now does the same for one narrow kind of run.

**What is unattended.** A module registers its Scheduler action with `register_scheduled_action(..., unattended=True)`. Core accepts that only when the scheduled action's own id is listed in the module's signed manifest `system_actions`; at decision time the id must still be listed and registered with `core.system_actions` by that module, else the run is re-checked as an ordinary one. A run is unattended only when all of these hold: the action is flagged; the run was started by the schedule (never `manual`, never a one-off); a creator name is stored on the schedule (or `created_by` still holds it). The one place that decides this is `tec_tac.scheduler._is_unattended_scheduled_run`.

**What changes for such a run.** Core does not re-read the creator's rights. In the tick, a demoted or deactivated creator no longer causes `AuthorizationRevoked`. In `verify_run_context` the run verifies with `creator_username`, `confirmed_by_username` and `unattended` set. In `run_system_action` exactly three refusals are skipped: `owner_inactive`, `permission_lost` and `out_of_scope`.

**What stays, for every run.** The signed context and the caller check (`context_invalid`, `caller_unverified`, `wrong_module`), `unknown_action`, `action_not_declared`, `module_disabled`, `replacement_not_honoured`, `bad_parameters`, `bad_agents`, `agent_count` (2000 at most, refused above), `outside_targets` (the snapshot is never widened), `targets_unresolved`, `reapproves_by_policy`, `function_unavailable`, `mark_limit`, the at-most-once mark and the strict audit row before the send. `has_tactical_permission` and `resource_context` stay fresh reads.

**What a person-started run keeps.** A manual run and a one-off run keep every re-check, exactly as before (CQ50 a).

**Who is on the record.** Migration 0036 adds `created_by_username` and `confirmed_by_username` to the schedule. Creating a schedule stores the signed-in person as both. An edit sets the editor as `confirmed_by_username`, after the unchanged permission and scope checks. A row made before 0036 reads its creator from `created_by`. Every `run`, `deny` and `custom:outcome-unknown` row of a system action carries `run_kind` (`scheduled` or `person`), `creator` and `confirmed_by`. An administrator can list schedules by creator or confirmer: `GET /api/tfd/scheduler/schedules/?created_by=<name>&confirmed_by=<name>` (see `docs/scheduler.md`).

**The cost, in plain words.** A person who is demoted or deactivated later keeps their unattended schedules running until someone removes or edits them. That is how Tactical works. An administrator can find those schedules by creator and remove or disable them. Nothing else changes for an ordinary action: an action not flagged `unattended` is re-checked at every scheduled run as before.

**When targets vanished.** If some snapshotted targets no longer exist but the endpoints you name are all still targets, the run goes ahead and the result gains `vanished_targets` (a count). The run's audit row carries it too. If you name an endpoint that is not a target, the whole call is refused as `outside_targets`, and the text says how many targets no longer exist.

## Then: at most once, audited, sent

1. Core writes a mark on the run row (`{action_id, targets_digest, state: "claiming"}`) under a row lock and commits.
2. Core writes one **strict** audit row: action `run`, object type `system_action`, object id the action id, actor the creator (or a Core service actor when the user row is gone), metadata `requested_by`, `run_id`, `schedule_id`, `owner_module`, `function`, `agent_count`, `targets_digest` and, since 1.17.63, `run_kind`, `creator`, `confirmed_by` (and `vanished_targets` when some targets no longer exist). No endpoint ids and no hostnames. The digest is a short hash bound to the run id. It is not a secret.
3. Only if both commits worked, Core calls the Tactical task with `.delay()` and sets the mark to `sent` with the Celery task id.

What follows from that:

- **If the audit row cannot be written, nothing is sent.** The mark is set to `aborted`. The run fails as a transient error, so a retry sends once.
- **A retry or duplicate delivery that finds a `sent` mark sends nothing again.** It returns the same result with `duplicate: true`.
- **A mark stuck at `claiming`, or a send that raised, fails the run as `OutcomeUnknown`** and is never sent again. One `custom:outcome-unknown` audit row is written.
- The trade is plain: a scan may be missed. An install is never done twice.

## The honest limits

- Modules run in the same Python process as Core. Code that deliberately reaches into Core's private state is outside what this stops. The caller check (`docs/caller-identity.md`) names the module whose own code calls the function. Core code, library code, generated code, and disabled and legacy modules are refused.
- Tactical's own tasks for the first two rows take no username. Only Core's audit row names the person.
- An unattended schedule outlives the creator's rights, as in Tactical (see "Unattended scheduled runs"). It is opt-in per action, and the audit row and the creator filter make it visible.
- Core does not follow the work after the send. Tactical shows the result in each endpoint's update list.
- There is no HTTP route for system actions and no global off switch. Disable the owning module, or its schedule, to stop a run. (CQ178.)
- Scheduled install for Advanced Patch Management is not unblocked by this release. Only scan is. (CQ173.)
- Pushing patch-rule decisions to Tactical on a schedule is not built. Tactical has no task function for it. (CQ174.)
- Scripts, commands, reboot and uninstall are not in the table. (CQ175.)

## Not in this release

- Scheduled install for Advanced Patch Management (CQ173), groups above 2000 endpoints (CQ178), more table rows such as reboot, uninstall, scripts, commands, checks, tasks and reports (CQ175), and pushing rule decisions (CQ174) still wait for Johan's sign-off.
- Module-owned recurring schedules with a named acting person are built in 1.17.63 (CQ176, `reconcile_schedule(..., confirmed_by_request=request)`, see `docs/module-scheduling.md`).
- Polling a module's capability for a final state from the tick (CQ177). A run that finishes later uses `pending_completion` (see `docs/scheduler.md`).
- A UI for system actions. The Scheduler page shows a waiting run once the UI release for 1.17.61 ships.
