# Review scope: Core 1.15.111

## Tracker item in this release

- **M13 — Scheduler dynamic-filter scope checks inspect keys but not values.**

## Expected behavior

- Tactical client/site/endpoint identifiers remain authoritative only through canonical `targets.scope`.
- Dynamic filter top-level keys may not be Tactical target aliases.
- Dynamic filter values/tokens at any depth may not equal Tactical target aliases such as `client_id`, `site_id`, `agent_id`, `endpoint_id`, `id`, or `ids`.
- This blocks generic filter DSL forms such as `{"field":"site_id","value":999}` from becoming an alternate Tactical scope channel.
- Nested module-owned filter **keys** may still use ordinary names such as `id` or `site_id`; Core does not reinterpret those nested keys as scope.

## Files/areas changed

- `framwork/tec_tac/scheduler_targets.py`
- `tests/scheduler-target-shape.py`
- `docs/module-scheduling.md`

## Regression coverage

- `tests/scheduler-target-shape.py` exercises direct top-level aliases, generic field/value DSLs, nested/list value tokens, valid nested module-owned keys, canonical scope, and legacy aliases.
- Existing Scheduler foundation, durability, scope, run-now, stale-run, unrestricted-role, pagination and interval tests remain green.

## Explicitly not in scope

- M14 and later Medium items.
- Module-specific custom target-type semantics.
- UI changes.
