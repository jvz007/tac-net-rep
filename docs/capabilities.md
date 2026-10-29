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

### A replacement provides the replaced module's capabilities (AD-20, 1.17.9)

The capability id must begin with the provider module id and a dot. One exception: the honoured replacement of a core module (see `docs/module-replacement.md`) may register that core module's capability ids, and only the ids it lists in its manifest `capabilities`. Any other id still raises the same `must begin with provider module prefix` error.

Since 1.17.10 Core also checks what is registered against the manifest. A core module that declares `capabilities` registers exactly those ids (a server module too, since 1.17.11). A replacement registers a replaced id at the declared major version, with a minor.patch that is not lower. Otherwise Core logs one warning and registers nothing (it never raises out of `AppConfig.ready()`). Since 1.17.11 a refused registration also drops an earlier registration of the same id by the same module, so the name stays `capability-unavailable`; a registration owned by another module is never dropped.

`registered_mismatch` in `replacement_status` covers only replacement version refusals. A core or server module's undeclared-id refusal is logged once and nothing else.

Consumers do not change. They keep calling the same capability name. `capability_status` reports the module that registered it as the provider (`module_id`) and adds `replaces` (the replaced module's id, or `null`). While the replaced module is disabled and its honoured replacement has not registered a name, the state is `capability-unavailable` and the reason names the replacement. If the replacement stops being honoured while the process still holds its registration (the core module was enabled again), the capability is `capability-unavailable` until the worker restarts.

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

Authenticated capability discovery endpoints:

```text
GET /api/tfd/capabilities/
GET /api/tfd/capabilities/<capability-id>/
GET /api/tfd/capabilities/<capability-id>/?version=>=1,<2
```

These endpoints are metadata-only by default and do not execute provider health callbacks. This keeps ordinary authenticated discovery read-only with respect to downstream systems.

Operators with `core.privileged_operations` may explicitly request live provider health evaluation:

```text
GET /api/tfd/capabilities/?live=true
GET /api/tfd/capabilities/<capability-id>/?live=true
```

A non-privileged caller that requests `live=true` receives HTTP 403 before any provider health callback is executed. Payloads expose `health_checked` (and list responses also expose `live`) so callers can distinguish metadata-only state from an active provider-health result.

Use HTTP from the Tec-Tac browser UI, an external system, or another host/process.

Inside the Tec-Tac Django/Celery backend, use Python imports from `tec_tac.capabilities`.
## Live discovery/export

Framework 1.10.0 includes registered capabilities in the Developer Contract catalog and its Markdown/Text exports. This is intended for module developers and coding agents; it does not expose provider-private implementation objects. See `docs/developer-contracts.md`.



## Framework-owned Core capabilities

Capability providers may also be owned directly by Tec-Tac Core rather than an installed extension. Core-owned IDs use the `core.` namespace and are always resolved against the framework runtime rather than Module Manager installed/enabled state. The first privileged Core provider is `core.server_backup` `2.x`; see `docs/server-backup-capability.md`.


## Core endpoint transport

`core.endpoint_transport` 1.0.0 (framework >=1.17.90) is the endpoint agent websocket: `register_owner`, `request`, `send_many` and `presence`, for the one owning module `endpoint-comms` only (Core verifies the caller; `nats-comms` is accepted until the dev server has moved). See `docs/endpoint-transport.md`.

## Core server maintenance

`core.server_maintenance` is the generic durable privileged-job capability. See `docs/server-maintenance-capability.md`. It exposes registered actions only; it does not provide arbitrary root-shell execution.

### Metadata-only discovery

### Health checks that call each other (since 1.17.58)

A provider's health callback may ask for the status of another capability, and that provider's callback may ask for the first one. Before 1.17.58 that loop
recursed until the web worker was killed (a dev-server request held a worker for 300 seconds). Core now keeps, per thread, the ids whose health callback is running.
A nested `capability_status` for an id already running, or nested more than 8 deep, returns at once with:

```json
{"available": false, "state": "health-reentrant", "reason": "Capability health check re-entered: A -> B -> A"}
```

The reason names only capability ids, never provider text. `get_capability` raises `CapabilityUnhealthy` for it, and that class's `state` stays `unhealthy`, so a caller that
handles `unhealthy` needs no change. A caller that compares the status dict's `state` against a list of names should treat any state other than `available` as not available.
The stack is always popped, even when a callback raises, and it is per thread: another thread is unaffected. `check_health=False` never runs a callback, so it is unchanged.
A provider should still not call another capability's status from its health callback when it can avoid it. Test: `tests/capability-health-reentrancy-1.17.58.py`.

`check_health=false` is discovery-only. Core returns registered capability metadata without calling provider health callbacks, but it reports `available=false`, `state=health-unchecked`, and `health_checked=false`. Runtime callers must use the default live health check before treating a capability as available.

`core.caller_identity` 1.0.0 (Core 1.17.21): the verified identity of the module whose code is calling a provider. See `docs/caller-identity.md`.

`core.event_jobs` 1.1.0 (Core 1.17.45; 1.1.0 in 1.17.47 verifies the caller of every publish): event-started, time-limited system jobs a module publishes from a signal. Core stores, retries, limits and audits them. See `docs/event-jobs.md`.

`core.system_actions` 1.2.0 (Core 1.17.68, additive: `delegable_to` and five delegation operations; 1.1.0 in Core 1.17.66; 1.0.0 in Core 1.17.61): typed Tactical functions that Core runs unattended for a named owner, in groups of at most 2000 endpoints, at most once per group, with one strict audit row per group. A person who creates or edits a schedule for one gets the permission, Tactical flags and scope check and one plain Yes or No (`describe_confirmation`); a person-started run keeps every re-check; a scheduled run is not re-checked against its creator. Three table rows today (winupdate scan and install, and scripts.run). Since 1.17.68 a module-owned target type reads as endpoints through a resolver its module registers, a schedule keeps the scope its person had and moves to the next editor, and one module may start another's scheduled install through a grant a person confirmed once. See `docs/system-actions.md`.

`core.patch_lockdown` 1.0.0 (Core 1.17.68, read-only `status()`): whether Tactical's own patch policy is switched off because a replacement of Windows Patching (Advanced Patch Management) is honoured. On while that replacement is honoured and does nothing otherwise (AD-41, Johan, 21 October 2026). See `docs/patch-lockdown.md`.

`core.module_dependants` 1.0.0 (Core 1.17.71, `dependants()`): which installed modules name the calling module in their signed `dependencies` or `optional_dependencies`. Answers only about the caller itself, fails closed. See `docs/module-dependants.md`.
