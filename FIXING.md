# FIXING.md - Core 1.15.131

## Review scope

This release is intentionally limited to tracker items **M17, L18, L20 and L23**.

Review that:

1. Client/site create and update changes cannot succeed without a persisted Core audit record.
2. Schedule DELETE requires current permission to use the schedule's action.
3. `force=true` schedule deletion is strictly audited before deletion.
4. Restricted Tactical users cannot create/edit/delete/run schedules whose `none` or module-defined targets provide no enforceable Tactical resource scope.
5. Native Scheduler managers retain their existing repair/management bypass.

## Explicitly out of scope

- Other Scheduler Low findings (L19, L21-L25).
- Backup, trust-policy, module-install, housekeeping, MFA and UI tracker items.
