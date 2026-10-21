# System actions (core.system_actions 1.3.0, Core 1.17.70)

A system action lets Core run a small, fixed piece of Tactical work when nobody is signed in. The first use is a scheduled patch scan: "scan these endpoints for Windows updates every night". The person who set up the schedule is still the owner.

**Where the check sits (since 1.17.65 and 1.17.66).** Core checks the person's permission and Tactical scope, and asks one plain Yes or No, when the person **creates or edits** the schedule or starts a one-off run (see "Creating or editing a schedule"). A run a person starts keeps every re-check. A **scheduled** run is not re-checked against its creator, as in Tactical (see "Scheduled runs are not re-checked").

**What is new in 1.17.66 (capability version 1.1.0, additive).** A run of more than 2000 endpoints is split into groups of at most 2000 instead of being refused (CQ178). The table gains `scripts.run` (CQ175). `winupdate.install` may be registered by the honoured replacement, with a fixed warning (CQ173). Parameters come only from what the person confirmed. A person who creates or edits a schedule gets the permission and scope check and one Yes or No at that moment.

**What is new in 1.17.68 (capability version 1.2.0, additive; Johan, 21 October 2026).** Four things, each in its own section below. (1) A schedule keeps the scope its person had when they created or last edited it, and the next person who edits it becomes its owner: "Creation-time scope and ownership". (2) A module-owned target type reads as endpoints through a resolver its module registers: "A module-owned target type". (3) Maintenance's unattended patch step can start Advanced Patch Management's scheduled install through a grant a person confirmed once: "Delegation". (4) While Advanced Patch Management is honoured, Tactical's own patch policy is switched off, so Core no longer shows the re-approve warning for its install: `docs/patch-lockdown.md`.

**What is new in 1.17.70 (capability version 1.3.0, additive; Johan, 21 October 2026, CQ203 and AD-45; core.system_actions 1.2.0 was Core 1.17.68).** A second kind of row, a **write**, for the premium module that is the honoured replacement of Windows Patching. The first and only write row is `winupdate.set_action`. See "The second kind: a write". Every row and every module before it is untouched.

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

| `winupdate.set_action` | A write, not a task: `WinUpdateSerializer(update, data={"action": value}, partial=True).save()`, the same save as Tactical's `PUT winupdate/<update_id>/` (since 1.17.70) | `patching`, **honoured replacement only** | `can_manage_winupdates` | Sets one update's decision to `approve`, `ignore` or `nothing`. Takes `allowed_actions`. Always `dangerous`, never delegable. |

The minimum flags are stricter than either Tactical route alone. Tactical's single-agent route needs `can_manage_winupdates`. Its bulk route needs `can_run_bulk`. Core needs both. For `scripts.run` Core needs `can_run_bulk` and `can_run_scripts`: Tactical's bulk route needs only `can_run_bulk`, so this is stricter on purpose.

**Install and the warning (CQ173, Johan: yes, 20 October 2026).** Tactical's bulk install task calls `approve_updates()` first, and that flips an update the replacement set to Ignore back to Approve when the patch policy approves its severity. Since 1.17.66 the honoured replacement (Advanced Patch Management) may register and run install, and Windows Patching keeps it. Core shows this fixed text in the confirmation and writes it in the audit row of every install: "Tactical installs what its own patch policy approves, including updates set to Ignore elsewhere." **Since 1.17.68 (Johan, 21 October 2026: "the tactical patch policy must be disabled when APM is installed so that this doesn't happen")** Core's patch lockdown makes Tactical's own approve inert while the replacement is honoured (`docs/patch-lockdown.md`). For the replacement's install the warning then goes from the confirmation, from `list_actions` and from the audit row, which carries `patch_lockdown: active` instead, but only while the guard is installed in the process that shows or sends it. Windows Patching's own install, an inactive lockdown and a missing guard keep the warning.

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
| A `replacement_only` row (`winupdate.set_action`) from the owner itself, from a module that replaces nothing or another group, or from a replacement that is not honoured | Only the honoured replacement of `patching` may register it. Windows Patching is refused. A replacement that is not honoured right now is logged and not registered (`None`). |
| A write row with `dangerous` false, or with `delegable_to` set | A write to a Tactical table must say it is dangerous and can never be started for someone else. |
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
| `mark_limit` | A run holds at most 105 marks (one per group and one plan mark per call; five full calls of 20 groups). Judged before any group is sent. |
| `declaration_unreadable` | Since 1.17.67, at creation, edit, switch-on or a one-off start (and when the confirmation text is asked for). Core could not read the signed manifest or the registry just now, so it cannot tell whether the action is a system action. Nothing is saved, queued or issued, and one deny row is written. Try again in a minute. An action that the registry or the manifest already shows is not a system action is never refused for it, so an ordinary schedule is unaffected by a read fault. At run time a failed read still keeps every re-check. |
| `not_permitted`, `confirmation_required`, `confirmation_invalid` | Since 1.17.66, at creation, edit or a one-off start (see "Creating or editing a schedule"). They are raised as `SystemActionCreationRefused`, not by `run_system_action`. |
| `outside_targets` | Since 1.17.62: every endpoint is one of the run's snapshotted schedule targets. A run never widens the schedule's set. A target that no longer exists is counted in the refusal text. |
| `targets_unresolved` | Since 1.17.62: Core can read the run's snapshot as endpoints (a client, a site, endpoints, or the Tactical scope of a dynamic target, which is an upper bound: the module's own filter only narrows it). A module-owned target type is read through the resolver its module registered (since 1.17.68, see "A module-owned target type"); with no resolver it cannot be read, so it is refused. `none` names no endpoint, so it refuses as `outside_targets`. |

The count and shape are judged before any database lookup. The targets check (1.17.62) runs after the scope check, so the owner's role scope still decides first.

A system action that names endpoints needs a schedule that targets them. A module whose schedule uses a module-owned target type registers a resolver for it (since 1.17.68, next section). With no resolver the run is refused with `targets_unresolved` and nothing is sent.

## A module-owned target type (Core 1.17.68)

A schedule's targets are a Tactical client, site, endpoint or dynamic scope, which Core reads itself, or a type that a module owns, for example a Maintenance or Advanced Patch Management profile. Core cannot read a module's own type. Since 1.17.68 the owning module tells Core how its type reads as endpoints, once, in memory, from `AppConfig.ready()`:

```python
from tec_tac.scheduler_target_resolvers import register_target_resolver

register_target_resolver("maintenance", "profile", resolve_profile_targets)

def resolve_profile_targets(targets):      # read-only and fast; it receives a copy of the targets object
    return [...]                           # Tactical agent numbers (whole numbers) or agent ids (text)
```

The rules, all fail closed:

- **Who.** Core names the caller from the call stack (`docs/caller-identity.md`). It must be the module `module_id`, calling from its own code.
- **Which type.** Not `none`, `client`, `site`, `endpoint`, `agent` or `dynamic` (or their plurals). A plain lowercase word. It must be listed in `target_types` of one of the module's registered scheduled actions. That is checked at registration when the module already has a scheduled action, and again every time the type is read.
- **Same key twice.** The same resolver again is accepted. A different one is refused (`TargetResolverRegistrationError`, a `ValueError`).
- **What Core does with the answer.** It turns every returned id into a Tactical agent number and checks that the endpoint exists. A bad token, an id that names no endpoint, an ambiguous id (a number that is one endpoint's number and another endpoint's agent id), more than 40000 ids, a result that is not a list and any exception all mean "unresolved". Nothing is guessed, narrowed or truncated.

What this changes. A system action on a schedule with such a type is no longer refused as `targets_unresolved` at creation or at run. A scoped person (a role limited to some clients or sites) may now create a schedule with such a type when **every endpoint the resolver names lies inside their own Tactical scope**. One miss refuses it. Before, a module-owned type needed unrestricted scope. A scheduler manager keeps the shortcut they had. A type with no resolver keeps the old rule. A run with the stored scope (see "Creation-time scope and ownership") never reaches an endpoint outside that scope, whatever the resolver names.

What it does not do. The resolver decides no right. It names endpoints, and the person's scope, or the scope stored with the schedule, still bounds them. It adds no HTTP route and no private path. The honest limit: the resolver is module code that runs inside Core's process, like every module, so Core cannot stop a module that returns endpoints it should not name. That is why the result is always cut to a scope before anything is sent.

## Scheduled runs are not re-checked (Core 1.17.65, AD-13 condition 2 amended)

Johan signed this on 20 October 2026 (CQ179, CQ184 b, CQ186, CQ189). It is recorded in `docs/tec-tac-module-standard.md` section 1a and `docs/review-accepted-decisions.md` row 13, and `scheduler.AD13_CONDITION_2_AMENDED` is True. Core follows Tactical: a scheduled task keeps running after the person who made it is demoted or deactivated, because the right is checked when the task is created or edited, not at each run (reference `autotasks/views.py` `AutoTaskPerms` and `RunAutoTaskPerms`, `autotasks/models.py` `create_task_on_agent` over NATS, `apiv3/views.py` `TaskRunner.patch`).

**What is exempt.** Every run the schedule starts on its own (never `manual`, never a one-off) on a user-owned schedule, for every registered action. A module-owned schedule with a stored creator name is exempt only while the action id is still listed in the module's signed manifest `system_actions` and registered with `core.system_actions` by that module. A schedule with no stored creator name and a deleted creator (made before migration 0036) is still refused. The `unattended=True` keyword of `register_scheduled_action` is still accepted, still validated, and has no effect. The one place that decides this is `tec_tac.scheduler._is_unattended_scheduled_run`.

**What changes for a scheduled run.** Core does not re-read the creator's rights. In the tick, a demoted or deactivated creator no longer causes `AuthorizationRevoked`. In `verify_run_context` the run verifies with `creator_username`, `confirmed_by_username` and `unattended` set. In `run_system_action` exactly three refusals are skipped: `owner_inactive`, `permission_lost` and `out_of_scope`.

**What stays, for every run.** The signed context and the caller check (`context_invalid`, `caller_unverified`, `wrong_module`), `unknown_action`, `action_not_declared`, `module_disabled`, `replacement_not_honoured`, `bad_parameters`, `bad_agents`, `agent_count` (2000 at most, refused above), `outside_targets` (the snapshot is never widened), `targets_unresolved`, `reapproves_by_policy`, `function_unavailable`, `mark_limit`, the at-most-once mark and the strict audit row before the send. `has_tactical_permission` and `resource_context` stay fresh reads.

**What a person-started run keeps.** A manual run and a one-off run keep every re-check, exactly as before (CQ50 a).

**Who is on the record.** Migration 0036 adds `created_by_username` and `confirmed_by_username` to the schedule. Creating a schedule stores the signed-in person as both. An edit sets the editor as `confirmed_by_username`, after the unchanged permission and scope checks. A row made before 0036 reads its creator from `created_by`. Every `run`, `deny` and `custom:outcome-unknown` row of a system action carries `run_kind` (`scheduled` or `person`), `creator` and `confirmed_by`. An administrator can list schedules by creator or confirmer: `GET /api/tfd/scheduler/schedules/?created_by=<name>&confirmed_by=<name>` (see `docs/scheduler.md`).

**The cost, in plain words.** A person who is demoted or deactivated later keeps their schedules running until someone removes or edits them. That is how Tactical works. An administrator can find those schedules by creator and remove or disable them. A module whose handler wants its own live check can call `has_tactical_permission` or `resource_context` on the verified run: both still read the owner fresh.

**When targets vanished.** If some snapshotted targets no longer exist but the endpoints you name are all still targets, the run goes ahead and the result gains `vanished_targets` (a count). The run's audit row carries it too. If you name an endpoint that is not a target, the whole call is refused as `outside_targets`, and the text says how many targets no longer exist.

## Creation-time scope and ownership (Core 1.17.68, Johan 21 October 2026)

Johan's words: "If an engineer was responsible to configure APM and leaves the business his account will be disabled, but the work that he has done shouldn't be undone. When a profile is then edited by another engineer the ownership will move to him."

**What Core stores.** When a person creates or edits a schedule, Core stores one small record on the schedule (`creation_scope`, migration 0037): who it was, when, their Tactical client and site scope (unrestricted, the whole clients they hold, the sites they hold) and the Tactical role flags they held (the true ones). It is stored by `reconcile_schedule` whenever a call carries a person's request, and by the browser create and edit when the owner saves. It is **not** stored by `start_one_off_run`, by a module call with no request, or when another person only switches the schedule off. A schedule made before 1.17.68 has none, and Core never invents one.

**What a module reads.** `VerifiedSchedulerRun` gains four reads. For an unattended run they use only that record and never the owner's live row, so a disabled or demoted owner changes nothing:

| Read | Answer |
|---|---|
| `has_creation_scope` | True when the record is there. |
| `creation_scope_info()` | A copy of the record, or None. |
| `held_at_creation(flag)` | Whether the person held that Tactical role flag when they saved the schedule. For a run a person started it is `has_tactical_permission(flag)`, as before. |
| `resolved_endpoints(*, whole_scope=False, limit=40000)` | The endpoints of the run's targets that lie inside the stored scope, as rows `{pk, agent_id, hostname, platform, client_id, site_id}`. Never wider than the targets AND the scope. `none` gives [] unless `whole_scope=True`. More than `limit` raises, never truncates. |

With no stored record, an unattended run's `held_at_creation` and `resolved_endpoints` raise `CreationScopeUnavailable` ("This schedule was made before Core kept its scope. Edit it and save it once."). `has_tactical_permission` and `resource_context` are unchanged: they still read the owner fresh and fail closed. A module that keeps calling them for an unattended run keeps the old behaviour until it adopts the new reads. Core cannot do that for it.

**Ownership moves to the next editor.** A call to `reconcile_schedule(confirmed_by_request=request)` **is** an edit by that person. If they are not the stored owner, then after the unchanged permission and scope checks Core moves the ownership to them (`created_by`, `created_by_username`, `confirmed_by_username`, `updated_by`), stores their scope and writes one strict `modify` audit row that names `owner_changed_from`, `owner_changed_to` and `previous_confirmed_by`. The browser edit does the same when a person other than the owner changes an edit field (the action, targets, parameters or timing) or switches the schedule on. A rename alone, and switching a schedule off, move nothing.

**It never widens a schedule (CQ205, option a).** The new owner's own Tactical scope must cover every target. A scheduler manager gets no shortcut for this. If it does not, the call is refused with the plain text "You cannot take over this schedule: some of its targets are outside your Tactical scope." (`TakeoverRefused`, 403 reason `takeover_out_of_scope` from the browser), nothing changes, and one `deny` audit row is written. The schedule keeps its old owner and its old scope, even when that owner is disabled.

**What is not changed.** `verify_run_context(require_owner=True)` still refuses a run whose creator row was deleted (CQ190). A module call without a request still cannot change a person's schedule: it can only switch it off or leave it alone. The owner re-check of a run a person starts (a manual run, a one-off run) is unchanged.

**The honest limit.** The stored record bounds what a schedule can reach. It does not remove a module's own live checks, and it is only as good as the module that reads it.

## Delegation (Core 1.17.68, S4)

Johan signed this on 21 October 2026: AD-43 (CQ204, "3) yes") for the grant, the ticket and the delegated start, AD-42 for the scope a person had when they confirmed it, and AD-44 for a narrower engineer who edits it. The delegated start is live in Core. Nothing calls it until a signed Maintenance release uses it and a signed Advanced Patch Management release switches `start_install` on.

**The problem.** Maintenance runs its patch step later, in its own Celery engine, with nobody signed in and after its Scheduler run has ended. Advanced Patch Management (APM) owns the install. `run_system_action` answers only the module that owns the run (`wrong_module` stays exactly as it is) and `describe_confirmation` needs a person's own request, so neither can serve Maintenance. Delegation is the supported path. It adds no way to reach Tactical: the work is still `run_system_action` inside a Core one-off run, with its groups, its at-most-once marks and its strict audit rows.

**The path.** Every caller is named by Core from the call stack, never by an argument. Since 1.17.69 this holds inside `delegation.py` as well: its five functions take no caller at all and read it themselves, skipping every frame of `delegation.py` and `system_actions.py`. A module that imports `tec_tac.delegation` directly is named by its own frames, so it cannot pass another module's id. The first frame outside both files must be an enabled, non-legacy module, or the call is refused with `caller_unverified`. The five public functions, the capability operations and the reason codes are unchanged.

1. **The provider allows it.** APM registers its install with `register_system_action(..., delegable_to=("maintenance",))`. This only names who may ask.
2. **The person confirms once.** When a person saves a Maintenance profile, Maintenance calls `describe_delegation(request, owner_module="maintenance", provider_module="patchmanagement", action_id=..., targets=..., parameters=...)`. Core runs every creation-time check for that person (the action's permission, every Tactical flag with no bypass for a scheduler manager, the scope of every resolved endpoint, the ceiling, the parameters, the modules enabled, the replacement honoured). It answers the plain Yes or No text and a confirmation id valid for 600 seconds, signed with its own prefix so that an id issued for a schedule cannot be reused here. Maintenance shows the text in the shell's dialog.
3. **Core stores the grant.** On Yes, Maintenance calls `register_delegation_grant(request, ..., grant_key="profile:<id>", confirmation_id=...)`. Core stores the confirmed action, targets and parameters, the person (by row and by stored name) and the person's scope at that moment (migration 0037, `TecTacDelegationGrant`). At most 20 grants per owner module. One strict audit row. A second person who saves the profile takes the grant over, only if their own scope covers every target (see "Creation-time scope and ownership"), judged by the resolver of the owner module (1.17.69: Maintenance's resolver for a profile, not the provider's); a resolver that names no endpoint refuses the takeover. `remove_delegation_grant(owner_module=..., grant_key=...)` removes it, for example when the profile is deleted.
4. **Maintenance's live run gets a ticket.** Inside its own LIVE Scheduler run, Maintenance calls `issue_delegation_ticket(context, grant_key=...)`. The ticket is signed, bound to that run, the grant and the grant's digest as it is now, and valid for 24 hours. The digest changes with every save of the grant, so editing, re-saving, switching off or removing the grant revokes every ticket.
5. **APM starts the run.** Maintenance's patch step hands the ticket to APM. APM calls `start_delegated_run(ticket, action_id=..., agent_ids=[...])`. Core re-reads the grant (there, enabled, same digest, the provider and action it names), the declaration of the action, both modules and the replacement. It resolves the grant's targets and reads the endpoints inside the person's stored scope. Every endpoint passed must be in both, or the call is refused as `outside_grant` and nothing starts. Then Core creates APM's own one-off schedule and run: `created_by` the person who confirmed (the stored name when the user row is gone), targets exactly the endpoints passed, parameters exactly what was confirmed plus a marker Core signed for that schedule. APM's handler calls the unchanged `run_system_action`. APM reads the run with `get_one_off_run(run_id, owner_module="patchmanagement")`, and Maintenance reads it through APM.

**What the person reads.** One wording: the module starts it later with nobody signed in; Core checks at run time that the confirmation is unchanged, that the modules are on, that the replacement is still honoured and that every endpoint is inside the confirmed targets and the stored scope; Core does not look at the account again, so the run goes on if the account is later disabled; editing or removing the profile stops it.

**Why this run is not re-checked against the person (AD-43).** A scheduled run is not re-checked against its creator (AD-13 condition 2 as amended). A one-off run a person starts is. This one-off is the continuation of a schedule the person confirmed, so it is treated as unattended, but **only while its marker verifies** (HMAC with the server's secret, bound to that very schedule) **and its grant is still enabled with the same digest**. A marker copied to another schedule, a plain one-off, the switched-off amendment (`AD13_CONDITION_2_AMENDED` False) and an edited or removed grant keep every re-check (CQ50).

**Retry.** A call with the same ticket and the same endpoints names the same run, so a retry returns that run and never starts a second install. A failed or unknown run is not started again from here, because its marks may show a send.

**Audit.** One strict `add` row for each grant (`delegation_grant`), one strict `add` row for each delegated run (`scheduler_run`, naming the owner module, the provider, the creator, the confirmer, the grant key, the total and the groups, never an endpoint id), one `delete` row when a grant is removed, one `deny` row for each refusal with a reason code.

**Refusals** (`DelegationRefused`, a `SchedulerNotAllowed` and a `SchedulerPermanentError`, with `.reason`): `caller_unverified`, `wrong_module`, `no_person`, `bad_grant_key`, `bad_module`, `unknown_action`, `not_delegable`, `action_not_declared`, `module_disabled`, `replacement_not_honoured`, `grant_limit`, `confirmation_required`, `confirmation_invalid`, `takeover_out_of_scope`, `context_invalid`, `grant_missing`, `grant_disabled`, `grant_changed`, `ticket_invalid`, `ticket_expired`, `ticket_used`, `creation_scope_unavailable`, `targets_unresolved`, `bad_agents`, `agent_count`, `outside_grant`, `queue_failed`. The shared creation-time controls refuse with `SystemActionCreationRefused` as before.

**What Maintenance and APM do next** (not Core's work): see `reviews/requests/core-modules.md` and `reviews/requests/premium-modules.md`, "From Core 1.17.68". Until a signed Maintenance release uses this and a signed APM release switches `start_install` on, nothing calls it.

## Groups: more than 2000 endpoints (Core 1.17.66, CQ178)

Johan signed this on 20 October 2026: more than 2000 splits into groups of at most 2000. Core never truncates and never refuses for size alone.

1. **The whole set is judged first.** Shape, the count against the ceiling, the scope for a person-started run, `outside_targets`, `targets_unresolved`, the parameters, declared, enabled and honoured. One failure refuses the whole call. Nothing is sent and no mark is written.
2. **The ceiling is 20 groups: 40000 endpoints in one run** (an assumption that Johan has been asked to confirm, CQ195). Above it the call is refused with `agent_count`.
3. **The ids are sorted and cut into groups of at most 2000.** No id appears twice and none is lost.
4. **Each group is its own at-most-once send:** its own mark (a digest of the run id, the action id and that group's ids), its own strict audit row and its own `.delay()`.
5. **A failed audit write sends nothing for that group.** The mark is set to `aborted` and the run fails as a transient error. A retry sends that group once. A group that was already sent is skipped.
6. **A group whose mark is stuck at `claiming`, or whose send raised, ends the run failed as `OutcomeUnknown`.** It is never sent again, and every later group stays not started.
7. **The plan is fixed on the first attempt (1.17.67).** Core stores one plan mark per call (`kind: "plan"`, the endpoint numbers as ranges, the digest of every group). A retry cuts its groups from the stored plan, never from the live endpoint list. A call is identified by its full sorted id set.
   - Same ids: a retry, as before.
   - No endpoint in common with an earlier plan of the run: a new call, planned on its own.
   - A different list that overlaps a plan, after any group of that plan was claimed, sent or left unknown: the run ends failed as `OutcomeUnknown`, nothing more is sent, one `custom:outcome-unknown` row (counts only). An endpoint is never sent twice. A scan may be missed, so check the endpoints.
   - A different list that overlaps a plan when nothing was sent yet (every group mark is absent or aborted): the plan is replaced and the call goes on.
   The plan mark carries no audit row and sends nothing.
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
4. The targets read as endpoints (a module-owned target type reads through the resolver its module registered since 1.17.68, otherwise it stays refused as `targets_unresolved`) and the total is within the ceiling.
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
- A resolver, a stored scope and a delegation grant are module code and data read inside Core's process. They bound what Core sends. They cannot stop deliberately hostile signed module code (signed-module review stays the defence).
- Tactical's own audit log does not show the update-decision write of 1.17.70. Core's strict audit rows are the record.
- Commands, reboot with a result, software package uninstall, checks, tasks and reports are not in the table (see "Not in this release").

## The second kind: a write (Core 1.17.70, CQ203, AD-45)

Some Tactical work has no task. A person's decision on one Windows update is a `PUT winupdate/<update_id>/` that saves one column. Johan signed (21 October 2026, AD-45) that the premium module which honourably replaces a core module is the one that talks to Tactical for the piece it replaces, through Core's own channels. For Advanced Patch Management that is this row, in Core's own channel, with the same limits as a task: a typed action, run as the schedule's owner, groups of at most 2000, up to 20 groups, one Yes or No, a strict audit row before the write, at most once, fail closed.

**What the module does.** It lists the action in its signed manifest `system_actions`, registers it from `ready()` with function `winupdate.set_action`, `dangerous=True` and permissions that include `can_manage_winupdates`, and creates its schedule with `confirmed_by_request`, `confirmation_id` and parameters `{"system_action_parameters": {"allowed_actions": ["approve", "ignore"]}}`. From its own Scheduler handler it calls `run_system_write(context, action_id=..., changes=[{"update_id": 1234, "action": "approve"}, ...])`. The module works out the decisions each time its rules run. The person confirms only the **envelope**: the schedule's endpoints, the allowed decisions and the count ceiling of 40 000. Core checks every decision against it.

**What Core checks, in the same order as a task.** A context Core issued for a run that is still going; the verified caller is the run's module and owns the action; the action is listed in the signed manifest now; the module is enabled now; the replacement is honoured now; the parameters come from the confirmed record only; then the owner, the count, the scope and the targets. A task row refuses in `run_system_write` as `wrong_kind`, and a write row refuses in `run_system_action` the same way.

**The changes.** Exactly `update_id` and `action` per item, whole numbers, each update once, 1 to 40 000 items (refused above, never cut). The action must be one of the confirmed `allowed_actions` (a subset of `approve`, `ignore`, `nothing`). `inherit` has no meaning on one update row and is refused. Any other key is refused, so a write can touch only the action column, never `installed`, `kb` or `result`. Reasons: `bad_changes`, `action_not_allowed`, `unknown_update`.

**The endpoints.** Core reads each update's endpoint itself (one fixed read of Tactical's WinUpdate id and agent) and requires every update to exist. It then judges that endpoint set exactly like `agent_ids`: inside the run's snapshotted targets (never widened), inside the owner's role scope for a person-started run, inside the stored creation-time scope for an unattended run on a module-owned target type. One miss refuses the whole call and nothing is written. No id is named in the message.

**Each group (at most 2000 updates).** Core marks the group, reads the current decision of every update (the "before"), then writes **one strict audit row per chunk of at most 500 changes before it writes**. Each row carries `[update_id, before, after]` and the run, schedule, creator, confirmer, action id and group digest. If a row cannot be written, nothing is written for the group and the mark is aborted. Then Core writes inside one transaction, with row locks, through Tactical's own `WinUpdateSerializer(partial=True)` with `{"action": value}`. A row whose decision changed after the "before" was read is **not overwritten**: a person's later decision wins, and it is counted as `changed_meanwhile`. A change that equals the current decision is counted as `unchanged` and not written. One closing audit row per group (`custom:write-closed`) carries the counts and the decisions actually saved. A failed write is outcome-unknown, as for a task: the group is never written again.

**The Yes or No text** names the allowed decisions in plain words, says the module decides each time it runs, says Core records the earlier and the new decision of every update, and says Tactical keeps the decisions if the module is later removed. The script line of `scripts.run` shows only for that row.

**A retry is bound to its decisions (Core 1.17.71).** The run key of a write, and the mark of every group, now cover the decisions (the sorted `update_id:action` pairs) as well as the updates. A retry of the same run with the same updates and the same decisions finds the same plan and works as before (a retry after a failed audit row writes once). A retry with the **same updates and other decisions** is never written. If no group had been claimed, sent or left unknown, the run ends `skipped` with the refusal `decisions_changed` ("This run already tried these updates with other decisions, so Core wrote nothing new. Start a new run if you want the new decisions.") and one deny row. If part of the run was already started, it ends `OutcomeUnknown` and says the decisions changed and that Core did not write again. A run that was in flight across the upgrade and holds a 1.17.70 plan is treated the same way on retry: it is refused or ends outcome-unknown, which is the safe side. A second call of the same run with other update numbers still works. `core.system_actions` stays at 1.3.0: this is a behaviour fix inside the existing write contract plus one added refusal reason. Task rows keep their digests unchanged.

**Honest limits.** Tactical's own audit log does not show this write, because Core saves the column in its own process and not through Tactical's route. Core's strict rows are the record. Core writes only the decisions the module hands it, inside the envelope. It cannot judge whether a decision is wise. Reboot with a result is not part of this row.

## Not in this release

Johan answered CQ173 (yes), CQ174 (yes), CQ175 (the whole list is signed) and CQ178 (groups of at most 2000) on 20 October 2026. Core 1.17.66 builds scheduled install for the honoured replacement, groups, and the `scripts.run` row. What waits, and why:

- **Pushing rule decisions (CQ174).** Johan said it runs the same Tactical operation a person uses, "never a synthetic request". Core's executor for declared operations needs a real authenticated request, and a scheduled run has none, so the two cannot both hold. A new question (CQ192) asks him how. Advanced Patch Management keeps a person-started "apply now" meanwhile.
- **Reboot with a result, software package uninstall and checks.** Tactical v1.5.2 has no Celery task function for them. Its views send NATS commands in-process, and AD-13 says Core calls Tactical's own task functions. Tactical's own "reboot later" (`PATCH agents/<id>/reboot/` with a date) is a declared operation a person makes at creation time and needs no Core row. A new question (CQ193) asks Johan which dispatch path he signs.
- **Commands.** `bulk_command_task` exists, but the command text would have to be stored in the schedule and shown in the list, the run snapshot and the audit row. A new question (CQ194) asks how it is stored and masked.
- **Patch KB uninstall.** Tactical has no such function. It runs as a script through `scripts.run` (Script Execution's contract), so Core builds no command text.
- **Tasks and reports.** `run_win_task` takes a task number, not endpoint numbers, and a report email takes free recipients. Tactical already schedules tasks and reports natively. They wait on CQ193.
- **A module-owned target type.** Built in 1.17.68 (see above). Until Maintenance and Advanced Patch Management register their resolvers, their profile targets are still refused as `targets_unresolved`.
- **Pushing rule decisions (CQ203): built in 1.17.70** as the `winupdate.set_action` write row (see "The second kind: a write").
- **Reboot with a result (CQ203).** Not Core's. It comes from Communicator's `communicator.messaging` contract, with Tactical's own reboot through the Agents core module's contract as the fallback, both built by module lanes (Johan, 21 October 2026).
- **Tactical's policy rows (`WinUpdatePolicy`).** Not asked. The patch lockdown makes a policy write unnecessary.
- **Refusing Tactical's own `winupdate/` and `automation/patchpolicy/` mutating routes.** Not built. The patch lockdown already stops the harm Johan described (see `docs/patch-lockdown.md`).
- **A list of delegation grants in the browser.** The audit rows and the capability carry the record for now.
- Module-owned recurring schedules with a named acting person are built in 1.17.63 (CQ176, `reconcile_schedule(..., confirmed_by_request=request)`, see `docs/module-scheduling.md`).
- Polling a module's capability for a final state from the tick (CQ177). A run that finishes later uses `pending_completion` (see `docs/scheduler.md`).
- A UI for system actions. The Scheduler page shows a waiting run once the UI release for 1.17.61 ships.
