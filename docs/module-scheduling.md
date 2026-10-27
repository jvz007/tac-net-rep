# Using Tec-Tac Scheduling from a Module

**Framework requirement:** Tec-Tac Framework 1.8.0 or later.

This document defines the contract for a Tec-Tac extension that wants to expose work to the shared scheduler.

## Rule: modules define what, framework defines when

A module must not create its own timer, cron entry, Celery Beat schedule, or browser-based timeout for ordinary user-configurable scheduling.

Instead:

```text
Module
  -> registers schedulable action

Tec-Tac Scheduler
  -> stores schedule
  -> determines due time
  -> dispatches via Tactical Celery
  -> records execution history

Module handler
  -> validates module-specific parameters/targets
  -> performs the action
  -> returns a JSON-safe result
```

This keeps scheduling behaviour consistent across Patch Management, Communicator, Automation, reporting, and future extensions.

## 1. Register an action

Register actions from the extension Django `AppConfig.ready()` path so the action exists in the web, management-command, and Celery runtimes.

```python
from django.apps import AppConfig


class CommunicatorConfig(AppConfig):
    name = "tec_tac_communicator"

    def ready(self):
        from tec_tac.scheduler import register_scheduled_action
        from .scheduled_actions import send_message_handler

        register_scheduled_action(
            id="communicator.message",
            module_id="communicator",
            label="Send message",
            description="Send a Southern Horizon Maintenance Messenger message.",
            target_types=("endpoint", "endpoints", "site", "client", "dynamic"),
            permission="communicator.send",
            handler=send_message_handler,
        )
```

### Registration fields

`id`
: Globally unique namespaced action ID. Use `<module-id>.<action>`.

`module_id`
: Stable Tec-Tac module/extension ID that owns the action.

`label`
: Human-readable label shown by the scheduler UI.

`description`
: Short operational description.

`target_types`
: Target types the action accepts. The scheduler validates `targets.type` against this list before saving a schedule.

`permission`
: Who may create/manage/manual-run this action for non-server-maintenance users. Prefer a real module permission such as `communicator.send` or `patching.install`. Since 1.17.17 it may also be a Tactical role flag written `tactical:can_manage_winupdates`, or a list or tuple of entries meaning **any-of** (Tec-Tac codes and `tactical:` flags may be mixed; at most 8 entries, no duplicates). A module that mirrors a Tactical flag declares `permission="tactical:can_manage_winupdates"` and needs no Tec-Tac permission of its own. A flag that does not exist fails closed. The flag is read again just before a one-off run, so a run whose owner lost it is skipped. Requires `requires.framework >=1.17.17`.

`handler`
: Callable invoked by the Celery execution task.

`dangerous`
: Metadata for actions that deserve stronger UI treatment/confirmation. Modules must still enforce their own safety rules in the handler.

## 2. Handler contract

A handler receives one `context` dictionary:

```python
def send_message_handler(context):
    schedule_id = context["schedule_id"]
    run_id = context["run_id"]
    module_id = context["module_id"]
    action_id = context["action_id"]
    target_mode = context["target_mode"]
    targets = context["targets"]
    parameters = context["parameters"]
    scheduled_for = context["scheduled_for"]
    manual = context["manual"]

    # Validate and execute module-specific work here.
    ...

    return {"ok": True, "delivered": 12}
```

Context fields:

| Field | Meaning |
| --- | --- |
| `schedule_id` | UUID of the owning schedule. |
| `run_id` | UUID of this execution-history record. |
| `module_id` | Owning module ID. |
| `action_id` | Registered action ID. |
| `target_mode` | `snapshot` or `dynamic`. |
| `targets` | JSON target definition/snapshot stored on the run. |
| `parameters` | Action-specific JSON configuration. |
| `scheduled_for` | Due datetime represented by this run. |
| `manual` | `True` for Run now, otherwise `False`. |

## 3. Return values

Prefer returning a JSON-serializable dictionary.

Good:

```python
return {
    "ok": True,
    "requested": 25,
    "delivered": 23,
    "offline": 1,
    "failed": 1,
}
```

If a handler returns another value, the framework falls back to a string representation. Structured results are strongly preferred because they can later drive richer history/reporting UI.

## 4. Failures and retries

Raise an exception when the action has failed and the schedule should use its configured retry policy.

```python
if provider_unavailable:
    raise RuntimeError("Communicator provider is unavailable")
```

The framework records the error/error type and lets Celery retry according to:

```text
retry_count
retry_delay_seconds
```

Do not implement a second retry loop inside the handler unless the module is retrying a lower-level operation within one scheduler attempt for a deliberate reason.

## 5. Downstream dispatch and execution success

**Transport acknowledgement is not operation success.**

The Scheduler marks a run successful when the registered handler returns without raising an exception. Therefore the handler is responsible for distinguishing each lower-level state correctly.

For endpoint, queue, NATS, API, webhook, or message-bus execution, use semantics such as:

```text
requested
  -> dispatched        transport accepted/sent the request
  -> executed          downstream operation completed successfully
  -> failed            downstream operation returned an execution failure
  -> unknown/pending   transport succeeded but final execution state is not yet known
```

Do **not** report `delivered`, `executed`, `succeeded`, or `ok: true` merely because a transport returned a response. A response may itself contain a shell error, application error, non-zero exit status, timeout, or partial failure.

For synchronous endpoint commands:

1. capture the raw transport response;
2. inspect the downstream execution result/exit status when the transport exposes one;
3. treat command/application failure as handler failure;
4. raise an exception so Scheduler history and configured retry behaviour reflect the real result;
5. return structured success only after execution success is verified.

If the transport does not provide a final execution result, report only what is known, for example `dispatched: 1` with `execution_state: "unknown"`; do not upgrade transport success into delivery/execution success.

Example:

```python
response = send_to_agent(...)

if not response.transport_ok:
    raise RuntimeError(f"Agent transport failed: {response.error}")

if response.exit_code not in (0, None):
    raise RuntimeError(
        f"Endpoint command failed with exit code {response.exit_code}: {response.stderr}"
    )

if response.exit_code is None:
    return {"ok": True, "dispatched": 1, "execution_state": "unknown"}

return {"ok": True, "dispatched": 1, "executed": 1}
```

### Raw OS command shell safety

When a module dispatches a raw operating-system command, build and test that command for the **exact shell selected by the agent transport**. Do not assume quoting rules are interchangeable between `cmd.exe`, PowerShell, Bash, or another shell.

Windows executable paths containing spaces are a common failure point. For a Tactical raw command using `shell: "cmd"`, verify the exact command through `cmd.exe`. One robust pattern is to change directory first and invoke the executable by name:

```cmd
cd /d "C:\Program Files\Vendor Product\cli" && Product.Cli.exe send ...
```

If using `cmd /c` with a quoted executable path, apply `cmd.exe`'s nested-quote rules deliberately and test the final generated string end-to-end.

Never mark a raw command as delivered merely because NATS/API transport returned text. Persist the response for diagnostics and classify the operation from the actual execution result.

## 6. Targets: snapshot vs dynamic

Core has a canonical shape for Tactical-native client, site and endpoint targets so the values checked by scheduler authorization are the same values delivered to a handler. Module-specific/custom target types remain module-owned.

### Snapshot

Use when the exact targets selected at schedule creation should remain fixed. Tactical-native snapshot targets use `type` plus an `ids` array.

Example:

```json
{
  "type": "endpoints",
  "ids": ["agent-a", "agent-b"]
}
```

### Dynamic

Use when membership should be resolved at execution time. The canonical Tactical scope is `scope: {type, ids}` and the optional `filter` remains module-owned.

Canonical example:

```json
{
  "type": "dynamic",
  "scope": {"type": "client", "ids": [17]},
  "filter": {"os": "windows", "online": true}
}
```

For backwards compatibility, Core also accepts the established legacy scope aliases as **input** and normalizes them before authorization, persistence and handler dispatch. Supported legacy scope aliases include `client_id` / `client_ids`, `site_id` / `site_ids`, and `agent_id` / `agent_ids` (plus the equivalent endpoint aliases). For example, this remains valid input:

```json
{
  "type": "dynamic",
  "scope": {"client_id": 17},
  "filter": {"os": "windows"}
}
```

Core stores/delivers that definition in canonical form:

```json
{
  "type": "dynamic",
  "scope": {"type": "client", "ids": [17]},
  "filter": {"os": "windows"}
}
```

Rules for Tactical-native dynamic targets:

- `scope` must resolve unambiguously to exactly one client, site or endpoint scope; conflicting aliases are rejected.
- Tactical target identifiers belong in `scope`, not in `filter`. Top-level filter keys that are Tactical target aliases are rejected. Tactical scope aliases are also rejected when they appear as filter value tokens (for example `{"field":"site_id"}` in a generic filter DSL).
- Nested filter objects are module-owned and may use ordinary **keys** such as `id`, `ids` or names that resemble Tactical scope fields. Core does not reinterpret those nested keys as target scope, but reserved Tactical scope aliases may not be carried as filter values.
- `reconcile_schedule()` accepts the legacy scope aliases above and persists the canonical form.

The module handler owns the meaning of `filter` and resolves final dynamic membership **within the canonical Tactical scope**.

For patch policies, dynamic targeting will usually be preferable. For a one-time Communicator message to selected endpoints, snapshot targeting will usually be preferable.

## 7. Parameters belong to the module

The scheduler intentionally treats `parameters` as opaque JSON. This lets each module evolve without adding module-specific columns to the framework scheduler.

Communicator example:

```json
{
  "title": "Maintenance",
  "message": "Maintenance begins at 20:00.",
  "severity": "information"
}
```

Patch example:

```json
{
  "update_policy": "approved",
  "reboot": "if_required"
}
```

Validate required fields, allowed values, lengths, and safety constraints inside the module handler (and preferably in the module's schedule-creation UI before submission as well).

## 8. Permissions and unattended execution

The `permission` declared on the action controls who may see/use that action through the Scheduler API unless they have native server-maintenance/superuser scheduler authority.

The saved schedule then runs as a **system automation object**. Scheduled execution:

- does not require a user to be logged in;
- does not require an open browser;
- does not replay the creator's Tactical token;
- records the creator/updater on the schedule for audit;
- records each execution separately in scheduler run history.

Therefore, the handler must not depend on `request.user`, session state, browser storage, or a short-lived user token.

If the underlying external integration needs credentials, use the module's normal server-side credential/configuration mechanism.

## 9. Do not use JavaScript-only registration

A scheduler action must exist in server-side Python because scheduled work executes with no browser present.

The module UI may provide a convenient schedule form or deep-link into Operations -> Schedules, but JavaScript registration is not authoritative for execution.

## 10. Communicator example

Recommended action:

```python
register_scheduled_action(
    id="communicator.message",
    module_id="communicator",
    label="Send message",
    target_types=("endpoint", "endpoints", "site", "client", "dynamic"),
    permission="communicator.send",
    handler=send_message_handler,
)
```

The handler should:

1. resolve the requested endpoints;
2. confirm Southern Horizon Maintenance Messenger is installed where required;
3. validate message parameters;
4. dispatch through the Communicator module's native backend/agent path;
5. return delivery/offline/failure counts.

Do not schedule PowerShell scripts merely to provide timing. The framework scheduler should call the Communicator module action directly.

## 11. Patch Management example

Recommended action:

```python
register_scheduled_action(
    id="patching.install",
    module_id="patching",
    label="Install approved patches",
    target_types=("endpoint", "endpoints", "site", "client", "group", "dynamic"),
    permission="patching.install",
    dangerous=True,
    handler=install_patches_handler,
)
```

The handler should resolve targets and then use the Patch Management module's normal Tactical execution path. It should return useful operational counts, for example:

```json
{
  "requested": 42,
  "dispatched": 42,
  "succeeded": 39,
  "failed": 2,
  "offline": 1,
  "reboot_required": 11
}
```

## 12. Action availability during module lifecycle

The action registry exists in process memory. If a module is removed or its Django app no longer registers an action, a due schedule cannot execute that action. The framework records a skipped run with `ActionUnavailable` rather than silently doing nothing.

Module upgrades should preserve stable action IDs where possible. Renaming an action ID is a schedule-breaking change unless migration/compatibility handling is provided.

## 13. Testing checklist

For every module action, test at least:

- action appears in `GET /api/tfd/scheduler/actions/` for an authorized user;
- unauthorized users do not gain the action through the UI alone;
- Run now reaches the handler and produces history;
- a true scheduled-time run works with all users logged out;
- snapshot targets are preserved correctly;
- dynamic targets resolve at execution time;
- invalid parameters fail clearly;
- retry behaviour is correct;
- duplicate/concurrent execution behaves as intended;
- removing/disable-changing the module does not create silent scheduler failures;
- handler result is JSON-safe and useful in history;
- transport acknowledgement is not mistaken for downstream execution success;
- endpoint/shell/application failures propagate into Scheduler run failure;
- raw OS commands are tested through the same shell selected by the production agent transport, including paths with spaces.

## 14. Operator-facing schedule UI

The shared schedule administration surface is:

```text
Operations -> Schedules
```

A module may also expose a context-specific `Schedule` button from its own page, but it should create/edit the same framework `TecTacSchedule` records rather than maintain a second schedule store.

## Inter-module dependencies inside scheduled actions

A scheduled action may depend on another module or framework capability, but it must follow the Tec-Tac interoperability rules in `docs/module-interoperability.md`.

Framework 1.9.0 scheduled handlers resolve another module through the Python capability registry, not HTTP:

```python
from tec_tac.capabilities import get_capability, build_operation_context

def install_approved_patches(context):
    communicator = get_capability(
        "communicator.messaging",
        version=">=1,<2",
        required=False,
    )
    if communicator:
        communicator.send(
            ...,
            context=build_operation_context(
                source_module="patching",
                source_action=context["action_id"],
                source_run_id=context["run_id"],
                requested_by="system",
            ),
        )
```

The Scheduler does not resolve provider internals. The scheduled action owns the capability lookup and soft-failure decision.

In particular:

- do not import another module's private models/helpers as the integration contract;
- declare hard or optional version dependencies in `tec_tac.json`;
- re-check dependency availability when the scheduled run actually starts;
- soft fail the dependent action if the provider is missing, disabled, incompatible, or unhealthy;
- keep unrelated features in the consumer module available;
- record a clear dependency error in scheduler history;
- do not blindly retry permanent version incompatibilities.

A schedule may outlive the module/version state that existed when it was created, so dependency validation belongs in the execution path as well as package installation/enablement.
## Live discovery/export

Framework 1.10.0 includes registered scheduler actions in the Developer Contract catalog and Markdown/Text exports. Module authors can use `Administration -> Public Contracts` in UI 0.9.0 to produce a current handoff for another coding agent.



## Scheduler hardening in Framework 1.11.0

- Completed or expired one-off schedule definitions are cleaned automatically after the configured retention period. The default is 48 hours and operators may configure 1-720 hours from the Scheduler configuration surface. Run history is preserved independently of the schedule definition.
- Scheduler diagnostics expose tick freshness, queue/dispatch state, enabled schedule count, queued/running runs and recent failures.
- Framework self-tests cover immediate dispatch, true scheduled execution, deliberate permanent failure and retry/recovery.
- Permanent failures must not be blindly retried. Module handlers may raise `SchedulerPermanentError` or `SchedulerTransientError`; capability unavailable/version mismatch/disabled and validation-style failures are treated as permanent.
- A handler must only report success after its owned downstream operation has completed successfully. Transport acknowledgement alone is not business-operation success.

## 11. Interval policy schedules and reconciliation (Framework 1.15.14)

For module-owned recurring policy work, use the framework `interval` schedule type instead of cron, Celery Beat, a module timer, or direct `TecTacSchedule` model access.

```python
from tec_tac.scheduler import reconcile_schedule

reconcile_schedule(
    owner_module="checks",
    owner_key=f"provider-check:{check.uuid}",
    action_id="checks.provider-run",
    schedule_type="interval",
    interval_seconds=check.effective_interval_seconds,
    targets={"type": "none"},
    parameters={"check_id": str(check.uuid)},
    enabled=check.enabled,
)
```

Rules:

- `interval_seconds` must be an integer >= 60;
- the Core scheduler still ticks once per minute;
- interval occurrences are derived from a stable `interval_anchor_at`, never from handler completion time;
- omitted `interval_anchor_at` is created once when the owned interval schedule is first created and is retained on later reconciliations;
- `(owner_module, owner_key)` is the idempotency identity;
- the registered action must belong to `owner_module`;
- `enabled=False` disables an existing owned schedule and does not create a useless disabled row when none exists;
- `disable_owned_schedule()` and `remove_owned_schedule()` are available for explicit lifecycle operations;
- Core continues to own missed-run policy, concurrency, retry, diagnostics and run history.

Checks acceptance examples:

```text
Ping default    -> interval_seconds=300
TCP default     -> interval_seconds=900
SNMP default    -> interval_seconds=900
SNMP override   -> interval_seconds=60
```

When a check interval changes, reconcile the same `owner_key`; do not create a new schedule. When a definition is disabled, disable its owned schedule. Re-enabling reconciles/re-enables the same schedule. A global check-type default change should trigger reconciliation only for definitions that do not carry an explicit interval override.

## Schedule ownership surfaces

Core uses one scheduling engine but exposes two ownership classes:

- `user` — created explicitly by an operator through the Core Scheduler UI/API;
- `module` — reconciled by backend modules through `reconcile_schedule()`.

Module-owned schedules are read-only through the generic Scheduler management API. Their owning module remains authoritative for edits and removal. `Run now` remains available when the caller has permission for the registered action. Execution history snapshots ownership so deleted schedules remain attributable.

List APIs accept `?owner_type=user` or `?owner_type=module` for clean separation without creating a second scheduler runtime.



## Scheduler durability and recovery

Core 1.15.48 adds durable run snapshots and stale-run recovery. Each registered action may declare `timeout_seconds` (default 3600). Queued runs that remain undispatched past the configured queue-stale window and running jobs beyond the action timeout plus recovery grace are failed with `error_type=Stale`, allowing later occurrences to proceed. Missed occurrences are written to history as `SKIPPED`, including `MissedSkip`, `MissedExpired`, or `MissedRecoveryWindowExpired`. A three-minute scheduler lateness tolerance prevents short timer/broker delays from being classified as missed.

User schedules can only be changed/run/deleted by their creator or a scheduler manager. A force delete explicitly fails active runs as `ForceDeleted` before removing the definition; historical runs retain their snapshot fields after the schedule is gone. Terminal run history is retained according to Core scheduler configuration instead of growing without bound.

## Tactical target-scope authorization

Framework 1.15.54 enforces Tactical client/site visibility at the Scheduler API boundary for Tactical-native targets.

Tactical-native target objects have a strict canonical shape. Core normalises and stores only these fields so authorization is performed over the exact values delivered to a module handler:

```json
{"type": "clients", "ids": [17, 21]}
{"type": "sites", "ids": [31, 32]}
{"type": "endpoints", "ids": ["agent-uuid-a", "agent-uuid-b"]}
```

The singular aliases (`client`, `site`, `endpoint`, `agent`) are also valid target types, but the identifier field is always `ids`. Client/site IDs are positive Tactical database IDs. Endpoint/agent IDs are stored canonically as Tactical `agent_id` strings. Legacy database PK input is resolved to `agent_id` at the authenticated Scheduler boundary only when it identifies exactly one visible Agent; ambiguous numeric identifiers are rejected. No extra keys are accepted on Tactical-native static targets.

Dynamic Tactical targeting has one explicit canonical scope plus an optional non-scope filter:

```json
{
  "type": "dynamic",
  "scope": {"type": "client", "ids": [17]},
  "filter": {"os": "windows", "online": true}
}
```

The canonical dynamic target root contains only `type`, `scope`, and optional `filter`, and canonical `scope` contains only `type` and `ids`. For backwards compatibility, Core accepts the established Tactical scope aliases (`client_id` / `client_ids`, `site_id` / `site_ids`, `agent_id` / `agent_ids`, and endpoint equivalents) as input in `scope` and converts them before persistence/dispatch. Known legacy root scope aliases are also consumed and canonicalized rather than forwarded to handlers. Conflicting or ambiguous scope aliases are rejected. Tactical identity aliases are forbidden as **top-level filter keys** and as **filter value tokens at any depth**. Equivalent field-reference spellings such as `site.id`, `site__id`, `siteId`, `clientIds`, and `agent.id` are treated as the same Tactical scope channel. Nested filter objects remain module-owned and may contain ordinary keys such as `id` or `site_id`; generic module references such as `ticket.id` remain valid values. This blocks generic field/value filter DSLs from carrying unauthorized Tactical scope past Core without reinterpreting nested module-owned keys as target scope.

For non-manager operators:

- `client` / `clients` targets require explicit Tactical `can_view_clients` membership; site-only access to part of a client does not authorize a whole-client target;
- `site` / `sites` targets may reference only sites visible through Tactical role scope;
- `endpoint` / `endpoints` / `agent` / `agents` targets may reference only agents visible through Tactical role scope;
- `dynamic` targets require exactly one explicit client, site, endpoint, or agent scope.

Core re-checks target scope when a user schedule is created or edited, when a schedule is read or manually run, when it is deleted, and when schedule/run history is listed. A user who later loses Tactical access to a target no longer gains visibility or Run-now access through Scheduler simply because the schedule was created earlier.

Effective Tactical/role superusers and Core scheduler managers retain global Scheduler target authority. Module-specific target types such as custom groups remain the owning module's responsibility because Core cannot infer their membership safely.

Scheduled unattended execution remains a system automation operation: it uses the already-authorized saved target definition and does not require the creator to remain logged in.

### Scheduler revision and history invariants

Creating or materially editing a schedule establishes a new scheduling baseline. An occurrence that predates that revision is marked consumed without creating a synthetic `MissedSkip`/`MissedExpired` row for work that was never scheduled under the new definition.

Migration `0015_scheduler_target_canonicalization` may repair mutable schedule definitions, but run-history `targets_snapshot` values are immutable evidence and are never rewritten by the migration.

Queued stale-run recovery applies a database timestamp prefilter before row locking, then evaluates the authoritative retry-aware deadline per candidate. Retry recovery and Celery execution share the same 60-second fallback when an old run has no stored retry delay.


## One-off runs and reading an owned schedule (Core 1.17.16)

Two server-side calls sit next to `reconcile_schedule`. Both need framework >=1.17.16. The full description is in `docs/scheduler.md`.

- `start_one_off_run(user=..., owner_module=..., action_id=..., targets=None, parameters=None, name=None, retry_count=0, retry_delay_seconds=60)` starts one run of your own registered action for a user and returns the queued run. Core re-checks the user's access just before your handler runs, on every attempt. Since 1.17.18 the two retry keywords (0 to 10 retries, 1 to 86400 seconds) let a transient failure (`SchedulerTransientError`) retry without your handler waiting inside the run; they need framework 1.17.18 or later. `get_one_off_run(run_id, owner_module=...)` reads its state.
- `get_owned_schedule(owner_module, owner_key)` returns `{enabled, schedule_type, next_run_at, last_run_at, last_run_status, last_run_finished_at}` or `None`, so a module can show the real next run instead of an estimate.

The handler context has six more keys: `owner_type`, `owner_module`, `owner_key`, `owner_user_id`, `owner_username` and `one_off`. The user keys are set only for a one-off run and a user-owned schedule.

One-off schedules show in the module schedule list as managed by the module, disabled, with an `owner_key` that starts `one-off:`. Do not reconcile, disable or remove them yourself. Core removes them after the once-retention.

## Work that starts from an event: use an event job, not a schedule (Core 1.17.45)

A schedule runs an action at a time. When a module must do small background work because something happened (a signal, a webhook), it registers
an event job with `tec_tac.event_jobs.register_event_job` from `AppConfig.ready()` and publishes from the signal receiver. Core stores the job,
runs the handler on a worker, retries it, limits it and audits it. A module does not start its own thread, timer or event-started Celery task for
this. A scheduled action's handler context is a different object (`verify_run_context`); the event job context has no user and is checked with
`verify_event_job_context`. See `docs/event-jobs.md`.

## A run that finishes later, and system actions (Core 1.17.61)

Both need framework >=1.17.61. The full descriptions are in `docs/scheduler.md` and `docs/system-actions.md`.

- **Pending completion.** A handler that only starts work returns `tec_tac.scheduler.pending_completion("module", job_id)` (or `"server_maintenance_job"` with the job's UUID). The run stays `running`. Your own job later calls `complete_pending_run(run_id, external_job_id=..., outcome=...)` from your own code, after the handler has returned. A run nobody completes fails with `CompletionTimeout` after the action's `timeout_seconds`. `serialize_run` gains a `completion` key. A handler that returns a dict is unchanged.
- **System actions.** For unattended Tactical work (today a patch scan), list the id under `system_actions` in your manifest, register it from `ready()` with `register_system_action`, and call `run_system_action(context, action_id=..., agent_ids=...)` from your own handler. The schedule needs a person behind it (a user-owned schedule or a one-off run). Core re-checks the owner, the flags and the scope for a run a person starts; a scheduled run is not re-checked against its creator (1.17.65). Core sends at most once and audits it.
- Neither feature changes `register_scheduled_action`, `reconcile_schedule`, `start_one_off_run` or `get_one_off_run`.

## Unattended work and a schedule a person confirms (Core 1.17.63)

Both need framework >=1.17.63 and are opt-in. Nothing changes for a module that uses neither.

- **`unattended=True`** on `register_scheduled_action` is still accepted and, since 1.17.65, has no effect. Every *scheduled* run of a user-owned schedule is not re-checked against its creator's current rights, flagged or not, as in Tactical: the right was checked when the person created or edited the schedule, and Core stores and audits who that was. A manual or one-off run is always re-checked. Plain cost: a person who is demoted or deactivated later keeps their schedules running until someone removes or edits them. If your handler needs its own live check, call `verified.has_tactical_permission` or `verified.resource_context()`: both still read the owner fresh. Full rules: `docs/system-actions.md`.
- **`confirmed_by_request=request`** on `reconcile_schedule` stores the person behind a module-owned schedule. Pass the real request of that person from your own view. Core checks their permission and scope and audits the creation and every change. Without it, a schedule that has a stored creator can only be switched off or left alone. See `docs/scheduler.md`.
- **`confirmation_id=...`** (Core 1.17.66, framework >=1.17.66) on `reconcile_schedule` and `start_one_off_run`. It is read only for a declared system action (listed in your signed manifest `system_actions` and registered with `core.system_actions`) and, for `reconcile_schedule`, only with `confirmed_by_request` and an enabled schedule. Core then checks the person's permission, Tactical flags and scope at that creation, edit or one-off start, and refuses without a valid id (`SystemActionCreationRefused`, a `SchedulerNotAllowed`; it writes one deny audit row). Get the id from the person's own signed-in request: `POST /api/tfd/scheduler/system-actions/confirmation/` from the browser, or the capability operation `describe_confirmation(request, ...)` from your own view. The id is for that person, action, targets, parameters and timing, valid for 600 seconds. For any other action the argument is ignored. Parameters of a system action sit under the key `system_action_parameters` of the schedule's `parameters`. See `docs/system-actions.md`.
- `VerifiedSchedulerRun` gains `creator_username`, `confirmed_by_username` and `unattended` (last, with defaults). `get_owned_schedule` gains `created_by_username`.
- Event job ids and `<module id>.server_job_finished` now keep the module id's own spelling, so a module with capital letters can use them.

## The scope a schedule keeps, a resolver and a delegation grant (Core 1.17.68)

All three need framework >=1.17.68 and are additive. The full text is in `docs/system-actions.md`.

- **The one new rule for modules: a `reconcile_schedule` call with a person's request IS an edit.** Core stores that person's Tactical scope and role flags on the schedule, and if the person is not the stored owner the ownership moves to them (their own scope must cover every target, or `TakeoverRefused` and nothing changes). Pass a request only when a person really saves something. Do not pass it on a page load.
- **Read the stored scope for an unattended run** with `run.has_creation_scope`, `run.held_at_creation(flag)` and `run.resolved_endpoints()` instead of `has_tactical_permission` and `resource_context()`. The live reads still fail closed for a disabled owner. The stored reads do not. A schedule made before 1.17.68 raises `CreationScopeUnavailable` until someone edits and saves it once.
- **A module-owned target type** (a profile) is registered with `register_target_resolver(module_id, target_type, resolver)` from `AppConfig.ready()`. The type must be listed in `target_types` of one of your scheduled actions. Core resolves the ids, checks they exist and refuses the whole answer on any doubt.
- **A module that starts another module's scheduled install** (Maintenance and Advanced Patch Management) uses `describe_delegation`, `register_delegation_grant`, `remove_delegation_grant`, `issue_delegation_ticket` (owner module) and `start_delegated_run` (provider), with `delegable_to=` on the provider's `register_system_action`. `run_system_action` and `wrong_module` are unchanged. Johan signed the delegated start (AD-43, with AD-42 and AD-44); it is live in Core, and nothing calls it until Maintenance and Advanced Patch Management ship their side.
- **Patch policy.** While Advanced Patch Management is honoured, Tactical's own patch policy is off (`core.patch_lockdown`, `docs/patch-lockdown.md`). `core.patch_lockdown.status()` tells a replacement when it may drop its own warning.

## A module's own scheduled action that needs a person (Core 1.17.80)

Needs framework >=1.17.80. Additive. For a Scheduler action that is **not** a Tactical function (a notice, a restart prompt, a background send) and still needs the person who saved the schedule.

1. List the action id in your signed manifest under **`scheduler_person_actions`** (a JSON list of `<module id>.<name>`, at most 20, extensions only). Set `requires.framework` to >=1.17.80.
2. Register the action with `register_scheduled_action` from your own module. Core honours an id only for the module that registers it.
3. Create the schedule with `reconcile_schedule(..., confirmed_by_request=request)`. Core checks the person's permission and scope, stores the creator and writes the audit row, as for any module-owned schedule.
4. In the handler call `verify_run_context(context, expected_module_id=..., expected_action_id=..., require_owner=True)`. A scheduled run gives `user` = the creator, with `unattended` False.

This is not a system action and not the AD-13 exemption. On every run the creator must be active and still hold the action permission and the target scope. If not, the tick skips the run (`AuthorizationRevoked`) and `verify_run_context` raises `SchedulerRunContextInvalid`. A manual run, a one-off, a schedule with no stored creator, an action not listed or one registered by another module gets no person (`This run has no person behind it.`). Core writes one audit row (`run`, `run_as` = `creator`) per run that uses the creator.
