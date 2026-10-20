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
2. **Permission and scope where Tactical checks them.** The save-time checks stay where they were (the action permission and the target scope when a schedule or one-off run is created). At every run Core also re-reads the owner (active, not an installer user), every Tactical flag the action needs, and the owner's Tactical role scope.
3. **Run as the owner.** The audit row names the owner as the actor, with `requested_by` set to `scheduler`.
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
| `no_owner` | A person is behind the run. A module-owned run with no person is refused (AD-13 condition 2). |
| `caller_unverified` | Core can name the calling module from the call stack. |
| `wrong_module` | The caller is the run's module and the action's registered module. |
| `unknown_action` | The action is registered. |
| `module_disabled` | The owning module is enabled right now (read fresh, never cached). |
| `replacement_not_honoured` | An action registered by a replacement still has an honoured replacement right now. |
| `owner_inactive` | The owner, read again from the database, is active and not an installer user. |
| `permission_lost` | The owner holds every Tactical flag now. |
| `bad_parameters` | The function takes none. |
| `bad_agents`, `agent_count` | 1 to 2000 whole endpoint numbers. Above 2000 is refused, never truncated. |
| `out_of_scope` | Every endpoint exists and lies inside the owner's Tactical role scope. One endpoint outside refuses the whole call. Nothing is narrowed silently. A scheduler manager gets no bypass here, because Core's scheduler-manager shortcut would widen rights for a Tactical function. |
| `reapproves_by_policy` | A function that re-approves updates is not run for a replacement. |
| `function_unavailable` | Core can import the Tactical function. A Tactical upgrade can never make Core call something else. |
| `mark_limit` | A run sends at most 20 different system actions. |

The count and shape are judged before any database lookup.

## Then: at most once, audited, sent

1. Core writes a mark on the run row (`{action_id, targets_digest, state: "claiming"}`) under a row lock and commits.
2. Core writes one **strict** audit row: action `run`, object type `system_action`, object id the action id, actor the owner, metadata `requested_by`, `run_id`, `schedule_id`, `owner_module`, `function`, `agent_count`, `targets_digest`. No endpoint ids and no hostnames. The digest is a short hash bound to the run id. It is not a secret.
3. Only if both commits worked, Core calls the Tactical task with `.delay()` and sets the mark to `sent` with the Celery task id.

What follows from that:

- **If the audit row cannot be written, nothing is sent.** The mark is set to `aborted`. The run fails as a transient error, so a retry sends once.
- **A retry or duplicate delivery that finds a `sent` mark sends nothing again.** It returns the same result with `duplicate: true`.
- **A mark stuck at `claiming`, or a send that raised, fails the run as `OutcomeUnknown`** and is never sent again. One `custom:outcome-unknown` audit row is written.
- The trade is plain: a scan may be missed. An install is never done twice.

## The honest limits

- Modules run in the same Python process as Core. Code that deliberately reaches into Core's private state is outside what this stops. The caller check (`docs/caller-identity.md`) names the module whose own code calls the function. Core code, library code, generated code, and disabled and legacy modules are refused.
- Tactical's own tasks for the first two rows take no username. Only Core's audit row names the owner.
- Core does not follow the work after the send. Tactical shows the result in each endpoint's update list.
- There is no HTTP route for system actions and no global off switch. Disable the owning module, or its schedule, to stop a run. (CQ178.)
- Scheduled install for Advanced Patch Management is not unblocked by this release. Only scan is. (CQ173.)
- Pushing patch-rule decisions to Tactical on a schedule is not built. Tactical has no task function for it. (CQ174.)
- Scripts, commands, reboot and uninstall are not in the table. (CQ175.)

## Not in this release

- Module-owned recurring schedules with a named acting person (CQ176).
- Polling a module's capability for a final state from the tick (CQ177). A run that finishes later uses `pending_completion` (see `docs/scheduler.md`).
- A UI for system actions. The Scheduler page shows a waiting run once the UI release for 1.17.61 ships.
