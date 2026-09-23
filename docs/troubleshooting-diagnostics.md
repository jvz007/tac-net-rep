# Troubleshooting & Diagnostics

Tec-Tac Core exposes a read-only troubleshooting report at `GET /api/tfd/system/diagnostics/` for authenticated users with server-maintenance authority.

The report is designed for operator diagnosis, not automated repair. It covers Framework/UI version discovery, Django system checks, Core and module migration drift, Tactical/Tec-Tac service state, Scheduler health, Core privileged helper presence, module dependency/runtime state, capability registration, Public Contracts generation, AuditLog compatibility and runtime storage health.

## Capability health

The normal report does **not** call module/provider health callbacks. This keeps diagnostics responsive even when an external provider is slow or offline.

An operator can explicitly request live provider health with:

```text
GET /api/tfd/system/diagnostics/?live_capabilities=1
```

Live capability health may take longer because providers are allowed to contact external systems.

## Migration drift

Migration detection is performed in memory with Django's migration loader/autodetector. It does not create migration files or alter the database.

- Core `tec_tac` drift is a failure because Core releases must carry their migrations.
- Installed `tec_tac_*` module drift is a warning because the owning module must ship the required migration in its next package.
- Operators should not use `makemigrations` on production as the permanent repair path.

## Security

Diagnostics require the same Core server-maintenance authority used by other system administration surfaces. Backend authorization remains authoritative. The report is read-only and does not expose secrets or raw authentication tokens.
