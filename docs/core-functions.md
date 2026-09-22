# Tec-Tac Core Functions — Module Developer Reference

**Framework baseline:** 1.9.0+

Use Python framework contracts inside the Tec-Tac/Tactical backend. Use HTTP at browser/external process boundaries.

## Scheduler — `tec_tac.scheduler`

```python
from tec_tac.scheduler import (
    register_scheduled_action,
    reconcile_schedule,
    disable_owned_schedule,
    remove_owned_schedule,
    get_scheduled_action,
    scheduled_actions,
    SchedulerError,
)
```

Primary module use: `register_scheduled_action(...)` from `AppConfig.ready()`. Modules that own generated recurring definitions use `reconcile_schedule(...)` with a stable `(owner_module, owner_key)` rather than importing scheduler models directly.

The module defines **what** can run. Tec-Tac Scheduler defines **when** it runs.

## Capabilities — `tec_tac.capabilities`

```python
from tec_tac.capabilities import (
    register_capability,
    get_capability,
    has_capability,
    capability_status,
    list_capabilities,
    build_operation_context,
)
```

Provider:

```python
register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.0.0",
    provider=service,
)
```

Consumer:

```python
service = get_capability(
    "communicator.messaging",
    version=">=1,<2",
    required=False,
)
```

See `docs/capabilities.md` for lifecycle, health and exception handling.

## Plugin registry — `tec_tac.registry`

```python
from tec_tac.registry import get_plugin, get_plugins, RegistryError
```

Use `get_plugin(<module-id>, "extension")` to inspect installed plugin identity/version. Do not use it instead of the capability registry for calling another module's business logic.

## Module runtime state — `tec_tac.module_state`

```python
from tec_tac.module_state import (
    is_enabled,
    is_visible,
    module_record,
    version_satisfies,
    ModuleStateError,
)
```

`is_visible()` is navigation state only; it is not a health or dependency check.

Capability consumers normally use `capability_status()` / `get_capability()` rather than rebuilding these checks manually.

## RBAC — `tec_tac.rbac`

```python
from tec_tac.rbac import (
    has_extension_permission,
    effective_permissions,
    registered_permissions,
    permission_groups,
)
```

Backend permission checks remain authoritative.

## Boundary rule

```text
Backend module -> Python tec_tac.* contract
Browser UI     -> /api/tfd/... HTTP
External host  -> authenticated HTTP
```

Do not POST from one Tec-Tac backend module to another module's localhost API merely to invoke framework/module functionality.

## Quick decision table

| Need | Supported core function |
|---|---|
| Register a schedulable operation | `register_scheduled_action()` |
| Create/update an owned schedule idempotently | `reconcile_schedule()` |
| Disable/remove an owned schedule | `disable_owned_schedule()` / `remove_owned_schedule()` |
| Consume another module's public backend contract | `get_capability()` |
| Optional capability check | `has_capability()` / `capability_status()` |
| Register provider contract | `register_capability()` |
| Check installed plugin metadata | `get_plugin()` |
| Check module enablement | `is_enabled()` |
| Compare semantic version ranges | `version_satisfies()` |
| Check Tec-Tac extension permission | `has_extension_permission()` |
| Build cross-module audit source | `build_operation_context()` |
## Live contract catalog

Framework 1.10.0 exposes the current public core/runtime contracts through `GET /api/tfd/contracts/` and canonical Markdown/Text exports. See `docs/developer-contracts.md`.



## Scheduler failure classification (Framework 1.11.0)

Provider handlers may import:

```python
from tec_tac.scheduler import SchedulerPermanentError, SchedulerTransientError
```

Use `SchedulerPermanentError` when retry cannot repair the request (invalid parameters, unsupported target/operation, incompatible dependency). Use `SchedulerTransientError` when recovery is realistic (temporary transport/provider outage). The scheduler also treats disabled/missing/incompatible capability lookups and validation-style failures as non-retryable.

The handler context includes `attempt`, starting at 1.

## Session security — `tec_tac.session_security`

Framework 1.15.16 adds the Core-owned server-side session-security contract used
by the future Security module.

```python
from tec_tac.session_security import (
    get_effective_policy,
    update_global_policy,
    list_sessions,
    list_audit_events,
    revoke_session,
    revoke_user_sessions,
    SessionAuthenticated,
)
```

Backend modules should normally consume the versioned `core.session_security`
capability instead of importing implementation details. Do not import Core
session models directly.

See `docs/session-security.md` for policy, trusted-proxy and revocation semantics.

## Managed module hotfix lifecycle (1.15.25)

Urgent module fixes may use the Core-managed hotfix package contract instead of shipping module-owned privileged patch/revert scripts. Hotfixes are exact-module-version, before/after-SHA-256-bound replacements of existing files inside the owning extension/reportset roots. Core owns staging, backup, privileged application, validation, UI sync/Django reload, history and reverse-order rollback.

Module authors should read [`module-hotfixes.md`](module-hotfixes.md) before creating a hotfix. A normal module release remains the authoritative long-term delivery mechanism and automatically supersedes active hotfix state.


## Optional module integrations

Optional cross-module enrichment must degrade cleanly when its provider is missing or disabled. UI code uses the Core `modules` runtime service for presentation; backend code uses optional capability resolution (`get_capability(..., required=False)`) for execution. See `docs/optional-module-integrations.md`.
