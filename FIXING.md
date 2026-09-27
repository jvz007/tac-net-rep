# FIXING.md — Core 1.15.126

This build continues from the review-passed 1.15.125 baseline.

## D1 — superuser account protection is a policy setting

- Core already stores `protect_superuser_accounts` as a root-owned global policy and exposes it through `/api/tfd/access/security-policy/`.
- The policy remains default-off when no policy file exists, so existing Tactical account-management behaviour is preserved unless protection is explicitly enabled.
- Existing-superuser account edit/delete/reset/API-key protections continue to consult the policy at the native Tactical mutation boundary.
- The separate privilege-grant boundary remains unconditional: ordinary administrators still cannot grant/revoke Tactical superuser authority regardless of the optional D1 policy.
- Corrupt explicit policy data continues to fail closed, while policy mutation remains effective-superuser-only and strictly audited.
- A new release invariant now fails if those D1 decision boundaries drift.

## Regression coverage

- `tests/d1-account-protection-policy-boundary.py`
- existing `tests/tactical-superuser-guard.py`
- existing `tests/account-security-policy.py`
- existing `tests/account-security-policy-edge-cases.py`
- existing `tests/account-security-policy-corrupt-schema.py`
