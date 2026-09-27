# FIXING.md — Core 1.15.129

## Review scope

This release is intentionally limited to the tracker test/documentation batch:

- M18 — stale tests that no longer pass against current hardened contracts.
- L50 — administrator MFA recovery endpoint documentation closure.
- L51 — durable regression against the removed `timedelta` import.
- L54 — durable regression for stable pagination error text.
- L61 — root-dependent security tests must execute in ordinary-user CI.
- L62 — correct the 1.15.83 release-note overstatement about regression coverage.

## Expected outcome

No production authorization, backup, scheduler, module-management, or session behavior should change. Review should focus on test correctness, privilege-independent fixtures, documentation accuracy, and release metadata.
