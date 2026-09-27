# FIXING.md — Core 1.15.98

## Review scope

This release is intentionally limited to **D5 completion** from Claude's tracker.

### D5 — unrestricted Tactical scope and Scheduler health coverage

Review that:

1. A Tactical role with both `can_view_clients` and `can_view_sites` empty is treated as unrestricted for `dynamic_unscoped` Scheduler targets.
2. A role with either relation populated is still denied `dynamic_unscoped` unless it uses an explicit supported resource scope.
3. Save-time and runtime authorization use the same Resource Directory unrestricted-scope decision.
4. `AuthorizationRevoked` health output is exercised behaviorally, including count and latest-run detail.

## Files/areas changed

- `framwork/tec_tac/resources_adapter.py`
- `framwork/tec_tac/scheduler_views.py`
- `framwork/tec_tac/scheduler.py`
- `tests/d5-completion.py`

## Expected outcome

D5's remaining tracker gaps are closed without widening scope for restricted Tactical roles.

## Explicitly out of scope

- D6a and later Medium items.
- Other Scheduler Low findings.
- Historical release-note archive cleanup beyond the normal current-release housekeeping.
