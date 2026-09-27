# FIXING.md — Core 1.15.94

## Review scope

This release is the final D1 account-security-policy hardening pass. Review only the tracker items below plus regressions caused by these changes.

### L85 — privileged policy mutation had no root audit
- Every `--set-account-security-policy` root-helper mutation now requires a durable root-owned audit intent before the policy file is written.
- Root audit path: `/var/log/tec-tac/account-security-policy-audit.jsonl`.
- The audit records the actual sudo invoker, application actor label, prior state, requested state and timestamp.
- If the root audit cannot be written safely, the policy mutation is refused.
- The existing strict Core audit remains a separate second record for API-driven changes.

### L86 — policy test depended on root / grep checks
- `tests/account-security-policy.py` now runs without root and behaviorally exercises the privileged mutation/audit boundary with narrow filesystem privilege stubs.
- `tests/account-security-policy-edge-cases.py` now behaviorally checks non-superuser denial, effective-superuser success, strict audit contents, and audit-failure rollback.

## Explicitly not in this release
- D2–D6a follow-up items.
- M2–M31 outside already-completed M28/M29.
- Other Low items.

## Primary files to inspect
- `scripts/system-update-helper.py`
- `framwork/tec_tac/account_security_views.py` (regression target; no new behavior beyond 1.15.93)
- `tests/account-security-policy.py`
- `tests/account-security-policy-edge-cases.py`
- `docs/account-security-policy.md`
