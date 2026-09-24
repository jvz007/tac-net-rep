# Tec-Tac Framework 1.15.41

## Scheduler ownership split

- Added explicit `user` versus `module` schedule ownership while preserving one Core Scheduler engine.
- Existing backend-owned schedules are migrated to `module`; existing operator schedules remain `user`.
- Scheduler list and run-history APIs support `owner_type=user|module`.
- Module-owned schedules are read-only through the generic Scheduler edit/delete API and must be changed by their owning module.
- `Run now` remains available subject to the registered action permission.
- Schedule-run records snapshot ownership so history remains attributable after a schedule is deleted.
- Added ownership indexes for efficient split views.
- Module removal now disables module-owned schedules before action registrations are removed, while preserving definitions and execution history for audit/reinstall reconciliation.
