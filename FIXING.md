# FIXING.md — Core 1.15.135

## Review scope

This release is intentionally limited to **M14 + L79** from the current Core tracker.

### M14 — scoped run-history query efficiency

The production PostgreSQL history path already resolves `resources_adapter.scheduler_scope_snapshot()` once per request and applies action/target filtering before count and pagination through the JSONB SQL scope prefilter. The compatibility fallback is bounded to 5,000 candidates and reuses the same scope snapshot. This release adds behavioral coverage proving that neither path performs Tactical scope resolution per row.

### L79 — deleted schedule health identity

`_authorization_revoked_health()` now uses the run's immutable `schedule_snapshot_id` and `schedule_name` before consulting the nullable live schedule relation. A deleted schedule therefore retains a meaningful health identity.

## Expected review outcome

- A scoped PostgreSQL history page resolves Tactical scope exactly once and does not call per-row scope evaluation.
- The bounded alternate-backend path may evaluate rows locally, but still resolves Tactical scope exactly once for the request.
- A deleted schedule's latest `AuthorizationRevoked` health record reports the saved schedule id/name rather than `None`/blank.

No other tracker findings are intentionally changed.
