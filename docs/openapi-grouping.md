# Tec-Tac Swagger / OpenAPI grouping

Core groups every endpoint below `/api/tfd/` in Tactical's drf-spectacular schema.

Core-owned prefixes are grouped by subsystem (for example `Tec-Tac · Scheduler`, `Tec-Tac · Modules`, and `Tec-Tac · Clients, Sites & Agents`). Any other first path segment is treated as a module ID and grouped as `Tec-Tac Module · <module-id>`.

This grouping is applied as a drf-spectacular post-processing hook, so module authors do not need to add repetitive Swagger tags merely to obtain a module group. Module-specific `summary`, request/response schemas and operation descriptions remain owned by the module.
