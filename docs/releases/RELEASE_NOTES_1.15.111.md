# Tec-Tac Core 1.15.111

## Fixed

- **M13 — Scheduler dynamic-filter scope value enforcement**
  - dynamic filters can no longer encode Tactical scope aliases as filter values/tokens, including generic DSL shapes such as `{"field":"site_id"}`;
  - top-level Tactical scope aliases remain forbidden as filter keys;
  - nested module-owned keys may still use ordinary names such as `id` or `site_id` without Core reinterpreting those keys as scope;
  - canonical `targets.scope` remains the only Core-recognized Tactical client/site/endpoint authority channel.

## Regression coverage

- Extended `tests/scheduler-target-shape.py` with value-token bypass cases, nested/list expressions and compatibility assertions for nested module-owned keys.
- Existing Scheduler foundation, durability, scope, run-now, stale Celery revocation/time-limit, unrestricted-scope, pagination and interval regressions remain green.
