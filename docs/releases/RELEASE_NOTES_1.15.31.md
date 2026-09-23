# Tec-Tac Framework 1.15.31

## Core-owned audit write contract

- adds `tec_tac.audit.record(...)` as the supported server-side audit writer for Tec-Tac modules;
- writes Tec-Tac events into Tactical's native `AuditLog` table without changing existing Tactical records;
- derives the actor from the authenticated Tactical user and prevents username/provenance spoofing;
- adds module ID/version, source, object ID and request/correlation provenance in `debug_info`;
- maps `before` / `after` to Tactical `before_value` / `after_value`;
- preserves Tactical audit payload limits and safely degrades oversized module metadata;
- defines a standard action vocabulary with controlled `custom:<slug>` fallback;
- adds `POST /api/tfd/audit/record/` for the Core-owned browser runtime;
- keeps persistence failures non-fatal by default while logging them visibly, with explicit backend strict mode available;
- documents the public contract and adds regression coverage for actor identity, permissions, payload compatibility, oversized metadata and failure behavior.
