# Tec-Tac Core 1.15.120

## Scope

This release continues from the review-passed 1.15.119 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass. This pass closes **M14** from the supplied open-review list. No UI or Decision items are included.

## Fixed

### M14 - scoped Scheduler run-history fallback is explicitly bounded

Scoped Scheduler run history already uses a set-based PostgreSQL JSONB prefilter in Tactical production, avoiding per-row Tactical scope queries. The remaining fallback path for alternate/test database backends still iterated the complete retained-history queryset in Python to calculate visibility and paging.

Core now applies an explicit SQL slice before fallback scope evaluation. At most **5,001 candidates** are read: 5,000 allowed candidates plus one overflow sentinel. If that sentinel is reached, the request fails with a clear Scheduler error rather than continuing an unbounded history walk. PostgreSQL behavior remains unchanged and continues to use database-side count, offset, limit, and JSONB scope filtering.

This closes the residual “no limit” part of M14 without weakening scoped authorization or changing Tactical's PostgreSQL production path.

## Regression coverage

- `tests/scheduler-history-bounded-scope-scan.py` guards the PostgreSQL set-based path and requires the fallback SQL slice and explicit overflow failure.
- `tests/scheduler-run-pagination.py` verifies the fallback ceiling remains part of the paged history implementation.
- Existing Scheduler history scope-snapshot and query-efficiency tests continue to guard the no-per-row-query design and database indexes.
