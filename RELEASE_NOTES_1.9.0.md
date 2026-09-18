# Tec-Tac Framework 1.9.0

## Cross-module capability registry

Framework 1.9.0 adds the supported Python contract for module-to-module backend integration.

New public module:

```python
from tec_tac.capabilities import (
    register_capability,
    get_capability,
    has_capability,
    capability_status,
    list_capabilities,
)
```

Providers register namespaced, independently versioned public contracts from `AppConfig.ready()`. Consumers resolve those contracts without importing provider-private packages or calling Tec-Tac HTTP APIs over localhost.

The registry distinguishes `available`, `missing`, `disabled`, `unhealthy`, `version-incompatible`, and `capability-unavailable` runtime states. Required lookups raise framework exceptions; optional lookups can return `None` so only the dependent feature degrades.

Additional changes:

- capability versions are independent from module package versions;
- optional provider health callbacks and operation metadata;
- authenticated capability diagnostics under `/api/tfd/capabilities/`;
- `tec_tac.capability_probe` Celery diagnostic task;
- common `build_operation_context()` helper for cross-module audit/source context;
- extension install/upgrade/removal and Module Manager enable/disable refresh the Celery worker so web and unattended Scheduler runtimes see the same capability/action registrations;
- new capability foundation regression tests;
- developer, Scheduler, interoperability, Markdown tutorial, and HTML tutorial documentation updated for the implemented 1.9.0 contract.

The Scheduler architecture is unchanged: modules still register **what** can run; the Scheduler owns **when** it runs. The capability registry independently defines how one module safely discovers another module's public backend contract.
