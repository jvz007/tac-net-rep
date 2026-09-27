# Core 1.15.126

## D1 — superuser account protection remains policy-controlled

This release closes D1 as a Core release invariant. `protect_superuser_accounts` remains a root-owned Tec-Tac policy setting rather than an unconditional lockout: the setting defaults off when absent, can be changed only by an effective superuser, and is consulted by the native Tactical account guard for operations against existing superuser accounts.

The independent superuser privilege-grant/revoke boundary remains unconditional, so disabling D1 does not permit an ordinary administrator to create a superuser role, assign a superuser role, or change superuser authority.

Corrupt explicit policy data continues to fail closed, and policy changes retain the privileged/root audit plus strict Core audit requirements.

### Regression coverage

- `tests/d1-account-protection-policy-boundary.py`
- existing Tactical account-guard and account-security policy suites
