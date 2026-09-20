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
: Extension permission required to create/manage/manual-run this action for non-server-maintenance users. Prefer a real module permission such as `communicator.send` or `patching.install`.

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

### Snapshot

Use when the exact targets selected at schedule creation should remain fixed.

Example:

```json
{
  "type": "endpoints",
  "ids": ["agent-a", "agent-b"]
}
```

### Dynamic

Use when membership should be resolved at execution time.

Example conceptual definition:

```json
{
  "type": "dynamic",
  "scope": {"client_id": 17},
  "filter": {"os": "windows", "online": true}
}
```

The scheduler stores/transports this object; the **module handler** owns the meaning of `scope` and `filter` and resolves the final targets.

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
