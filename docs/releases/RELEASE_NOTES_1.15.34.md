# Tec-Tac Framework 1.15.34

## Troubleshooting & Diagnostics

- adds a Core-owned read-only diagnostics service at `GET /api/tfd/system/diagnostics/`;
- reports Framework/UI version discovery, Django system checks, Core/module migration drift, runtime service state, Scheduler health, privileged helper presence, module dependency/runtime state, capability registration, Public Contracts generation, AuditLog compatibility and storage health;
- performs migration drift detection in memory without creating migration files or mutating the database;
- treats Core migration drift as a failure and installed module migration drift as a warning owned by the module package;
- keeps capability discovery metadata-only by default so slow external providers cannot block the page;
- supports explicit `?live_capabilities=1` provider health checks for troubleshooting;
- requires Core server-maintenance authority and exposes no repair/mutation action;
- adds operator/developer documentation and diagnostics regression coverage.
