# Tec-Tac Core 1.15.94

## D1 completion — L85 and L86

- Added a root-owned privileged audit boundary for every account-security-policy mutation. The helper records the actual sudo invoker separately from the application actor label before changing policy, and refuses the mutation if that root audit cannot be written safely.
- Retained the strict Core audit as the application-level second audit record for API-driven changes.
- Reworked D1 policy regressions so the main policy suite runs unprivileged and behaviorally tests the mutation/audit boundary rather than requiring root.
- Added behavioral view coverage for non-superuser policy denial, effective-superuser success, strict audit state, and audit-failure rollback.
- Documented the root audit trail at `/var/log/tec-tac/account-security-policy-audit.jsonl`.
