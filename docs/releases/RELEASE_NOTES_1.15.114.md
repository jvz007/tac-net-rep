# Tec-Tac Core 1.15.114

## Review scope
M17 only. No additional Medium or Low findings are included in this rebuild.

## M17 — Scheduler history query efficiency
- Add a `(status, -created_at)` index for filtered run-history pages.
- Add an `(action_id, -created_at)` index for scoped-operator history, whose authorization prefilter constrains permitted scheduler actions before count/offset/page retrieval.
- Keep the existing newest-first run ordering and existing PostgreSQL target-scope prefilter unchanged.

These indexes align the retained-history database layout with the paged query shapes already used by `SchedulerRunListView`, reducing avoidable scans/sorts as Scheduler history grows.

## Tests
- Add `tests/scheduler-history-query-efficiency.py` to verify model/migration index definitions remain aligned with the history query paths and syntax-check the touched Python sources.
