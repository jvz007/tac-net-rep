# Tec-Tac Core 1.15.125

## Scope

This release continues from the review-passed 1.15.124 baseline and closes **D5** from the supplied open-review list. No UI findings, Low findings, or other Decision items are included.

## Closed

### D5 — follow Tactical's scope rule everywhere

The behavioral work for D5 was already present: Core's Resource Directory is the compatibility boundary for Tactical Client/Site/Agent models, interactive reads delegate to Tactical's native `filter_by_role(user)` semantics, write helpers apply the same role relations deliberately, and Scheduler uses the Resource Directory's centralized scope decisions for save-time authorization, execution-time authorization and retained run-history visibility.

This release closes the remaining drift risk with a release invariant. Core now fails its test pipeline if any other Core module directly imports Tactical Client/Site/Agent models or directly invokes `filter_by_role`, or if Scheduler stops consuming the centralized Resource Directory scope helpers. That makes Tactical's scope rule a single Core boundary rather than a convention that can silently diverge.

## Regression coverage

- `tests/d5-scope-boundary.py` enforces the single Tactical resource/scope boundary across Core.
- `tests/d5-completion.py` continues to exercise unrestricted versus restricted Scheduler target behavior and authorization-revoked health reporting.
- Existing Resource Directory and Scheduler scope foundations continue to cover read/write and target authorization behavior.
