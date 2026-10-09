# Tec-Tac Swagger / OpenAPI grouping

Core owns grouping for every `/api/tfd/` operation. Modules document their operations and schemas, but they do not choose their Swagger group.

Ownership is derived from the drf-spectacular callback. An installed module therefore keeps ownership even when its URL prefix looks like a Core route; for example, a module mounted below `/api/tfd/audit/` is still grouped with that module rather than Core Audit.

## Module groups

An extension manifest may declare:

```json
{
  "id": "example",
  "name": "Example",
  "category": "core"
}
```

`name` is the readable Swagger name and defaults to the stable module ID for older packages. `category` is optional; the supported values are `core` and `server` (`server` since 1.17.11; a module that writes it must require framework >=1.17.11, because older Core rejects the value).

- `category: "core"` -> `Core module · <name>`
- `category: "server"` -> `Server module · <name>`
- no category -> `Module · <name>`

Reportsets do not declare a category.

## Core groups

Core routes are explicitly classified by their owning `tec_tac.*` view module/class. The current groups include My Account, Access & Security, Authentication, Sessions, Dashboards, Saved Views, Developer Contracts, Clients/Sites/Agents, Audit, Tactical Operations (1.17.7), Capabilities, Scheduler, UI Runtime, Diagnostics, **System Updates**, **Backup & Restore**, **Server Maintenance**, **Storage**, **Module Repository**, **Module Hotfixes**, and Modules.

There is deliberately **no Framework catch-all**. A new Core HTTP surface must be added to the explicit ownership table. This makes an ungrouped `/api/tfd/` operation a detectable schema regression instead of silently hiding it in a generic bucket.

Tactical endpoints outside `/api/tfd/` are left unchanged.
