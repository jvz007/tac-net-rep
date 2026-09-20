# Tec-Tac Cross-Module Capability Registry

**Framework baseline:** 1.9.0+

The capability registry is the supported backend boundary between Tec-Tac modules.

```text
Consumer module
    -> tec_tac.capabilities
    -> public capability contract
    -> provider module
```

Backend modules must not import another module's private models/helpers, depend on its package layout, or call another Tec-Tac module through localhost HTTP.

## Public imports

```python
from tec_tac.capabilities import (
    register_capability,
    get_capability,
    has_capability,
    capability_status,
    list_capabilities,
    build_operation_context,
    CapabilityUnavailable,
    CapabilityDisabled,
    CapabilityVersionMismatch,
    CapabilityUnhealthy,
    CapabilityOperationError,
)
```

## Provider registration

Register from the provider extension's `AppConfig.ready()`.

```python
from tec_tac.capabilities import register_capability

register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.0.0",
    provider=communicator_service,
    description="Send endpoint communication through Communicator.",
    health=communicator_service.health,
    operations=("send", "endpoint_status"),
)
```

Capability IDs are stable and namespaced. For extension providers the ID must begin with `<module_id>.`.

The capability version is the public contract version, not the package version. A Communicator module `0.4.0` may expose `communicator.messaging` `1.0.0`.

## Consumer lookup

Hard/runtime-required integration:

```python
from tec_tac.capabilities import get_capability

messaging = get_capability(
    "communicator.messaging",
    version=">=1.0.0,<2.0.0",
)
```

Optional integration:

```python
messaging = get_capability(
    "communicator.messaging",
    version=">=1.0.0,<2.0.0",
    required=False,
)

if messaging is None:
    # Disable/degrade only the communication feature.
    ...
```

Never cache an optional provider forever. Resolve/check it at the point of use when runtime availability matters.

## Availability and diagnostics

```python
status = capability_status(
    "communicator.messaging",
    version=">=1.0.0,<2.0.0",
)
```

States:

```text
available
missing
disabled
unhealthy
version-incompatible
capability-unavailable
```

The status includes provider module ID, installed module version, capability contract version, required version range, description, operations, health details and a readable reason.

Boolean check:

```python
if has_capability("communicator.messaging", version=">=1,<2"):
    ...
```

Registered capability diagnostics:

```python
rows = list_capabilities()
```

## Health callback

A provider may supply a lightweight health callback. It may return:

```python
True
False
(True, "reason")
{"healthy": True}
{"healthy": False, "reason": "provider offline", "queue": "down"}
```

Health callback exceptions are converted to `unhealthy`; they do not break registry discovery.

Provider health is not target health. For example, core can report that `communicator.messaging` is healthy, while Communicator remains responsible for deciding whether Messenger is installed on endpoint X.

## Errors

Required lookups raise framework-level exceptions:

```text
CapabilityUnavailable
CapabilityDisabled
CapabilityVersionMismatch
CapabilityUnhealthy
```

Providers/consumers may use `CapabilityOperationError` for a public capability operation that failed after successful resolution.

The exception carries a structured `.status` dictionary suitable for API, Scheduler, automation and audit diagnostics.

## Common operation context

Use the helper when one module calls another so providers can audit the source without knowing consumer internals:

```python
from tec_tac.capabilities import build_operation_context

context = build_operation_context(
    source_module="patching",
    source_action="patching.install-approved",
    source_run_id=str(run_id),
    requested_by="system",
)

messaging.send(..., context=context)
```

Common fields:

```text
source_module
source_action
source_run_id
requested_by
```

Providers may document additional fields but should not require consumer-private objects.

## Package dependency vs capability dependency

Module package dependencies remain declared in `tec_tac.json`:

```json
{
  "optional_dependencies": {
    "communicator": ">=0.4.0,<1.0.0"
  }
}
```

That controls module lifecycle/version planning.

At runtime, resolve the public capability separately:

```python
get_capability("communicator.messaging", version=">=1,<2", required=False)
```

These versions intentionally describe different contracts.

## Lifecycle behaviour

Capability availability is evaluated at lookup time against live module state.

- disabled provider -> unavailable immediately;
- missing/removed provider -> unavailable;
- incompatible capability contract -> unavailable;
- unhealthy provider -> unavailable;
- optional consumer integration -> soft fail only that feature.

Module install/upgrade/removal and Module Manager enable/disable refresh the Celery worker so capability and scheduled-action registrations are consistent between Django requests and unattended jobs.

## Scheduler use

A scheduled action handler consumes capabilities exactly like normal backend code:

```python
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

No browser token or localhost HTTP call is involved.

The Scheduler still owns recurrence, execution, retry, history and concurrency. The provider owns its business operation.

## HTTP boundary

Authenticated diagnostic endpoints:

```text
GET /api/tfd/capabilities/
GET /api/tfd/capabilities/<capability-id>/
GET /api/tfd/capabilities/<capability-id>/?version=>=1,<2
```

Use HTTP from the Tec-Tac browser UI, an external system, or another host/process.

Inside the Tec-Tac Django/Celery backend, use Python imports from `tec_tac.capabilities`.
## Live discovery/export

Framework 1.10.0 includes registered capabilities in the Developer Contract catalog and its Markdown/Text exports. This is intended for module developers and coding agents; it does not expose provider-private implementation objects. See `docs/developer-contracts.md`.



## Framework-owned Core capabilities

Capability providers may also be owned directly by Tec-Tac Core rather than an installed extension. Core-owned IDs use the `core.` namespace and are always resolved against the framework runtime rather than Module Manager installed/enabled state. The first privileged Core provider is `core.server_backup` `1.x`; see `docs/server-backup-capability.md`.
