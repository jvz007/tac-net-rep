# Tec-Tac Core 1.15.131

## Resource and Scheduler authorization/audit hardening

- M17: Client and site create/update operations now emit strict Core audit records. Updates include before/after resource snapshots where available, and audit persistence participates in the mutation transaction.
- L18: Schedule deletion now re-checks the scheduled action permission instead of relying only on ownership/manager and target-scope checks.
- L20: Forced schedule deletion emits a strict Core audit record before deleting the schedule, including the number of active runs failed by the operation.
- L23: Scope-less (`none`) and module-defined scheduler targets now require unrestricted Tactical client/site scope for non-manager callers.

## Tests

- Added `tests/resource-scheduler-audit-scope.py` for Resource Directory audit behavior, scope-less/module-target authorization, delete action authorization, and forced-delete audit coverage.
- Existing Resource Directory, D5 scope, Scheduler foundation, durability, target-shape, run-now, and history-scope regressions remain green.
