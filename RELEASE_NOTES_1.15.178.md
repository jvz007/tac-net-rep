# Tec-Tac Core 1.15.178

## F11 — authoritative Swagger ownership and grouping

This release closes the remaining F11 contract drift.

- Extension manifests now accept a readable `name` and optional `category: "core"`; both are exposed by the registry/catalogue while older manifests remain compatible.
- Module Swagger groups are now `Core module · <name>` or `Module · <name>` instead of `Tec-Tac Module · <id>`.
- Installed module callback ownership wins over URL prefixes, including module routes mounted below `/api/tfd/audit/`.
- Core operations are classified from their owning `tec_tac.*` view module/class, with separate System Updates, Backup & Restore, Server Maintenance, Storage, Module Repository and Module Hotfixes groups.
- The generic `Tec-Tac · Framework` catch-all has been removed. Unknown Core surfaces stay unclassified so schema coverage detects the missing ownership rule instead of silently masking it.
- Public contract/developer documentation now describes the current F11 ownership contract.

The release is unsigned.
