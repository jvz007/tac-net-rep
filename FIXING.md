# FIXING.md — Core 1.15.124

This build continues from the review-passed 1.15.123 baseline.

## D4 — session history retention is a Tec-Tac policy setting

- `history_retention_days` remains Core-owned session-security policy state with a default of 30 days and supported range of 1–3650 days.
- The administrator `session/policy/` HTTP boundary is now explicitly regression-tested to expose and mutate retention policy.
- Non-superusers remain unable to read or modify the global policy.
- Invalid retention values return HTTP 400 through the policy boundary.
- The built-in Core policy documentation now includes the retention setting and default.

## Regression coverage

- `tests/session-retention-http-policy.py`
- existing `tests/session-retention-policy.py`
- existing `tests/session-retention-deletion.py`
- existing `tests/session-retention-scheduler.py`
