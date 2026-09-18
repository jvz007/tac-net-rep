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

## 5. Targets: snapshot vs dynamic

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

## 6. Parameters belong to the module

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

## 7. Permissions and unattended execution

The `permission` declared on the action controls who may see/use that action through the Scheduler API unless they have native server-maintenance/superuser scheduler authority.

The saved schedule then runs as a **system automation object**. Scheduled execution:

- does not require a user to be logged in;
- does not require an open browser;
- does not replay the creator's Tactical token;
- records the creator/updater on the schedule for audit;
- records each execution separately in scheduler run history.

Therefore, the handler must not depend on `request.user`, session state, browser storage, or a short-lived user token.

If the underlying external integration needs credentials, use the module's normal server-side credential/configuration mechanism.

## 8. Do not use JavaScript-only registration

A scheduler action must exist in server-side Python because scheduled work executes with no browser present.

The module UI may provide a convenient schedule form or deep-link into Operations -> Schedules, but JavaScript registration is not authoritative for execution.

## 9. Communicator example

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

## 10. Patch Management example

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

## 11. Action availability during module lifecycle

The action registry exists in process memory. If a module is removed or its Django app no longer registers an action, a due schedule cannot execute that action. The framework records a skipped run with `ActionUnavailable` rather than silently doing nothing.

Module upgrades should preserve stable action IDs where possible. Renaming an action ID is a schedule-breaking change unless migration/compatibility handling is provided.

## 12. Testing checklist

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
- handler result is JSON-safe and useful in history.

## 13. Operator-facing schedule UI

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

