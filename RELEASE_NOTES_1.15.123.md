# Tec-Tac Core 1.15.123

## Scope

This release continues from the review-passed 1.15.122 baseline and closes **D3** from the supplied open-review list. No UI findings, Low findings, or other Decision items are included.

## Fixed

### D3 — restore returns the server to its pre-operation service state

Core already performed transactional restore/rollback and verified required Tactical services, but the recovery helper restarted every known Tactical service after restore or rollback. That could silently start optional services such as MeshCentral or NATS that had intentionally been inactive before recovery.

Core now snapshots the active/inactive runtime state of the known Tactical services before the first destructive restore action. After a successful restore, a Tec-Tac-only reintegration, or a rollback, Core restores that captured service state before reporting completion. Required Tactical services (`rmm`, `celery`, `celerybeat`, and `nginx`) remain mandatory for a successful recovery and are still verified healthy.

For compatibility with older snapshots that do not contain service-state metadata, Core starts only the required Tactical services and leaves optional services stopped instead of blindly starting all known services.

The persisted pre-restore job summary now records the captured service-state map so recovery diagnostics show the intended post-operation runtime state.

## Regression coverage

- `tests/server-backup-d3-service-state.py` verifies capture and restoration of active/inactive service state, including backward-compatible handling of snapshots without service metadata.
- Existing D2/D3, restore rollback, recovery trust, and backup security regressions remain authoritative.
