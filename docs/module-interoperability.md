# Tec-Tac Module Interoperability

**Framework baseline:** Tec-Tac Framework 1.9.0 or later.

This document defines how Tec-Tac modules may depend on and integrate with other modules without turning the product into a web of private imports and brittle runtime coupling.

## Core rule

Modules may depend on another module's **public contract**, but must not depend on another module's private implementation.

Do not directly import another extension's models, views, internal helpers, package-private classes, filesystem paths, or undocumented database tables.

Bad:

```python
from tec_tac_tags.models import TagAssignment
```

Preferred architecture:

```text
Consumer module
    -> Tec-Tac interoperability contract
    -> provider capability/service/API
    -> provider module
```

The provider owns its storage and implementation. Consumers know only the stable contract.

## Dependency types

Tec-Tac uses three dependency categories.

### 1. Hard dependency

Use a hard dependency only when the consumer cannot provide its core purpose without the provider.

Manifest example:

```json
{
  "dependencies": {
    "required-provider": ">=1.0.0,<2.0.0"
  }
}
```

Module Manager must prevent installation/enabling when the required provider is missing or version-incompatible.

Even with a hard dependency, the consumer must **soft fail at runtime** if the provider later becomes unavailable because of an operational fault, manual disablement, partial upgrade, broken import, or other state drift. A dependency fault must not crash Tec-Tac, Django startup, navigation loading, Celery startup, or unrelated modules.

### 2. Optional dependency

Use an optional dependency when the consumer remains useful without the provider but gains extra capability when it is present.

```json
{
  "optional_dependencies": {
    "tags": ">=1.0.0,<2.0.0"
  }
}
```

An optional dependency must never prevent the consumer module itself from loading.

The integration-specific feature should be unavailable with a clear reason when the dependency is:

- not installed;
- disabled;
- unhealthy/broken;
- version-incompatible;
- missing the required capability.

### 3. Framework service

Capabilities that are broadly useful across many modules should belong to the Tec-Tac framework rather than forcing many modules to depend on one feature module.

Examples include the Scheduler, the 1.9.0 capability registry, and future shared resource metadata/tags.

A framework service becomes part of the Tec-Tac module-development contract and should be consumed through its documented framework interface.

## Soft-failure requirement

**Inter-module failures are feature failures, not product failures.**

A consumer module must remain loadable whenever possible even if an integration dependency is unavailable.

Required behaviour:

```text
Dependency healthy
    -> integration available

Dependency missing / disabled / incompatible / broken
    -> consumer module still loads
    -> unrelated features still work
    -> integration feature is disabled or degraded
    -> operator sees the exact reason
    -> backend refuses unsafe/incomplete operations cleanly
```

Do not allow an optional integration import in `AppConfig.ready()` to raise an exception that prevents Django from starting.

Do not allow one broken module to prevent the Tec-Tac shell from loading other modules.

Do not silently pretend an integration succeeded when its provider is unavailable.

## Runtime dependency states

Consumers should treat dependency availability as more than installed/not-installed.

At minimum distinguish:

```text
available
missing
disabled
incompatible
unhealthy
capability_missing
```

UI treatment should be explicit, for example:

```text
Tag targeting unavailable
Tags module is installed but disabled.
```

or:

```text
Tag targeting unavailable
Installed Tags 2.0.0 is outside the supported range >=1.0.0,<2.0.0.
```

This is preferable to hiding the control without explanation or throwing a generic server error.

## Public contract vs private implementation

A provider module should expose a narrow stable contract for other modules.

Good contract examples:

```text
resolve resources by tag
list tags for a resource
assign/remove a tag
send a communicator message
query communicator installation/presence
request a patch workflow execution
```

Bad integration points:

```text
provider ORM models
provider migration tables
provider view functions
provider private helper functions
provider UI implementation details
provider filesystem layout
```

The provider should be free to replace its database schema or internal implementation without forcing every consumer module to change.

## Service and capability discovery

Framework 1.9.0 implements the Tec-Tac-owned cross-module capability registry:

```text
Tec-Tac Framework
├── Scheduler service              implemented in 1.8.0
├── Capability registry            implemented in 1.9.0
├── Resource metadata / Tags       planned shared service
└── Event/inter-module signalling  planned
```

Providers register a narrow public contract from `AppConfig.ready()`:

```python
from tec_tac.capabilities import register_capability

register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.0.0",
    provider=communicator_service,
    health=communicator_service.health,
    operations=("send", "endpoint_status"),
)
```

Consumers resolve the capability without importing the provider module:

```python
from tec_tac.capabilities import get_capability

communicator = get_capability(
    "communicator.messaging",
    version=">=1.0.0,<2.0.0",
    required=False,
)
```

Use `capability_status()` when the UI/backend needs the exact reason an integration is unavailable. Use `has_capability()` for a simple boolean check. Use `list_capabilities()` for diagnostics.

Capability versions describe the public contract and are independent from provider package versions. Package/module lifecycle relationships still belong in `dependencies` / `optional_dependencies` in `tec_tac.json`.

Backend modules use the Python registry directly. Browser/external callers use HTTP. Do not loop back through `/api/tfd/...` from backend module code.

See `docs/capabilities.md` for the complete contract and `docs/core-functions.md` for the core-function index.

## Cross-module operation result semantics

A public capability or provider operation must distinguish **transport state** from **business/execution state**.

A queue publish, NATS response, HTTP 2xx, webhook acknowledgement, or task ID normally proves only that a lower-level transport accepted or answered the request. It does not automatically prove that the remote application or endpoint command completed successfully.

Provider contracts should expose the strongest state they can actually verify, for example:

```text
requested -> dispatched -> executed
                      \-> failed
                      \-> pending/unknown
```

Consumers and scheduled handlers must not translate `dispatched` into `succeeded` unless the provider contract explicitly guarantees that the returned result represents completed execution. Preserve downstream error text/exit status for diagnostics and propagate operation failure through the public contract.

For raw endpoint commands, the provider also owns shell correctness. Build and test the final command against the exact shell used by the agent transport (`cmd.exe`, PowerShell, Bash, etc.). Paths containing spaces, nested quotes, environment expansion, redirection, and shell-specific escaping are part of the provider's execution contract, not incidental implementation details.

## Tags example

Tags are a good example of a capability that should become framework-owned resource metadata because many modules can consume it:

```text
Endpoints
    -> display/edit tags on agents

Patch Management
    -> resolve dynamic patch targets by tags

Communicator
    -> resolve message recipients by tags

Automation
    -> target actions by tags

Reporting
    -> filter/group by tags
```

The intended model is:

```text
Tec-Tac Resource Metadata / Tags
    -> stable tag/resource contract

Endpoint module
Patch Management module
Communicator module
Automation module
Reporting module
    -> consume that contract
```

No consumer should query the Tags storage tables directly.

## Example: optional tag targeting in Patch Management

Manifest:

```json
{
  "id": "patching",
  "optional_dependencies": {
    "tags": ">=1.0.0,<2.0.0"
  }
}
```

Behaviour:

```text
Tags healthy + compatible
    -> show Tag targeting option
    -> resolve dynamic membership at execution time

Tags unavailable
    -> Patch Management still loads
    -> normal client/site/group/manual targeting still works
    -> Tag targeting control is disabled with diagnostic reason
    -> existing schedules that require tag resolution fail/skip cleanly with dependency diagnostic
```

A broken Tags integration must not prevent patch catalog, rules, approvals, manual patching, or unrelated Patch Management pages from working.

## Scheduled actions and dependencies

Scheduler handlers must apply the same soft-failure rule.

If a scheduled action requires another capability, validate it when the run begins. Do not assume that because the dependency existed when the schedule was created it still exists months later.

Recommended flow:

```text
scheduled run starts
    -> validate dependency availability/version/capability
    -> resolve targets
    -> execute provider call
    -> record structured result
```

If the dependency is temporarily unavailable, return/raise a clear module-specific dependency error so scheduler history explains why the run did not execute. Use the scheduler retry policy only when retrying can realistically recover the condition.

For a permanent incompatibility, repeated blind retries are usually inappropriate.

## UI behaviour

A module integration should show one of these states explicitly:

- Available
- Unavailable: module not installed
- Unavailable: module disabled
- Unavailable: incompatible version
- Degraded: provider error
- Unavailable: capability not supported by this provider version

Do not use color alone. Include readable text/reason.

## Backend authority

Frontend availability checks improve UX but are not authoritative.

Every backend operation that crosses a module boundary must independently validate that the required provider/capability is available and that the caller/action is allowed to use it.

## Versioning rules

Treat each registered capability's public contract as independently versioned API surface. The capability version does not need to match the provider module package version.

- breaking capability contract change -> capability major version;
- additive compatible capability change -> capability minor version;
- bug fix without contract change -> capability patch version (when useful).

Package compatibility remains separately declared in `tec_tac.json`. Consumers should request the narrowest realistic compatible capability range rather than an unbounded minimum.

Prefer:

```json
"tags": ">=1.2.0,<2.0.0"
```

over:

```json
"tags": ">=1.2.0"
```

when compatibility with an unknown future major version has not been tested.

## Module author checklist

Before shipping an interdependent module:

- Is the dependency hard, optional, or really a framework concern?
- Is the version range declared in `tec_tac.json`?
- Does the integration use a documented public contract rather than provider internals?
- Does the consumer still load when an optional provider is absent?
- Does the consumer survive a provider import/runtime failure?
- Does the UI explain missing/disabled/incompatible/unhealthy states?
- Does the backend independently validate dependency availability?
- Do scheduled actions re-check dependencies at execution time?
- Are permanent incompatibilities distinguished from retryable temporary failures?
- Can the provider change its internal storage without breaking the consumer?

If any answer is no, the modules are too tightly coupled.
