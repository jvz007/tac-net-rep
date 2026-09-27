# FIXING.md — Core 1.15.125

This build continues from the review-passed 1.15.124 baseline.

## D5 — follow Tactical's scope rule everywhere

- Core already centralizes Tactical Client/Site/Agent model access and `filter_by_role(user)` scope in `resources_adapter.py`.
- Scheduler save-time checks, execution-time checks and scoped run-history snapshots continue to consume the same Resource Directory scope decisions.
- A new release invariant now rejects direct Tactical resource-model imports or direct `filter_by_role` scope calls anywhere else in Core.
- The guard also requires Scheduler and the Resource Directory HTTP layer to keep using the centralized adapter helpers.

## Regression coverage

- `tests/d5-scope-boundary.py`
- existing `tests/d5-completion.py`
- existing `tests/resource-directory-foundation.py`
- existing `tests/resource-directory-write-hardening.py`
- existing Scheduler scope foundations
