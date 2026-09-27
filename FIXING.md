# FIXING.md — Core 1.15.120

This build continues from the review-passed 1.15.119 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass.

## M14 — scoped run-history fallback is now bounded

- PostgreSQL continues to use the set-based JSONB scope prefilter for scoped Scheduler run history.
- Alternate/test database backends no longer walk an unbounded retained-history queryset in Python.
- The fallback query is sliced in SQL to at most 5,001 candidates: 5,000 permitted candidates plus one sentinel used to detect overflow.
- If the fallback ceiling is exceeded, Core returns an explicit Scheduler error instead of continuing an unbounded scan.
- The normal paged response remains unchanged when the candidate set is within the bounded fallback limit.

## Regression coverage

- `tests/scheduler-history-bounded-scope-scan.py`
- `tests/scheduler-run-pagination.py`
- existing Scheduler scope-snapshot and history-query-efficiency regressions
