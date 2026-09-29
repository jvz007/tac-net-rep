# Tec-Tac Core 1.15.179

## Network Probe public contract requests

- Adds Core-owned `service_audit_actor(...)` and `device_audit_actor(...)` constructors for standards-compliant non-human audit provenance.
- `tec_tac.audit.record(...)` now accepts those actors, persists human/service/device provenance in Tactical-compatible AuditLog rows, and accepts `operation_context` so source/run/correlation data from `build_operation_context(...)` is retained.
- Publishes `locale`, `timeZone`, and `dateTimeFormat` in `ui.authenticated.runtime-context`. `timeZone` is sourced from Tactical/Core's configured default time zone and `dateTimeFormat` from Tactical's configured date format.
- Updates the public contract catalog and module audit documentation.
- Adds targeted regressions for the new contracts.

This delivery is unsigned.
