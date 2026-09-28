# Tec-Tac Core 1.15.124

## Scope

This release continues from the review-passed 1.15.123 baseline and closes **D4** from the supplied open-review list. No UI findings, Low findings, or other Decision items are included.

## Closed

### D4 — session history retention is a Tec-Tac policy setting

Core already stored and enforced `history_retention_days` in `TecTacSessionSecurityConfig`, audited policy changes, and ran the configured cleanup from the Core scheduler. This release closes the remaining contract gap so that behavior cannot drift back into an internal-only setting.

The administrator `GET/PUT /api/tfd/session/policy/` contract is now regression-tested to expose and mutate `history_retention_days` as part of the global Core session-security policy. The existing bounds remain 1–3650 days, non-superusers remain unable to read or mutate the global policy, and invalid retention values return a stable HTTP 400.

The built-in policy documentation now lists the 30-day retention default alongside the other Core session-policy settings.

## Regression coverage

- `tests/session-retention-http-policy.py` verifies the administrator HTTP policy boundary, round-trip mutation, validation and authorization.
- `tests/session-retention-policy.py` continues to verify storage, auditing and capability isolation.
- `tests/session-retention-deletion.py` and `tests/session-retention-scheduler.py` continue to verify actual deletion and scheduled execution.
