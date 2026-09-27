# Tec-Tac Framework 1.15.86

## Account security policy (D1)

- Adds a root-owned `/etc/tec-tac/policy/account-security-policy.json` policy with `protect_superuser_accounts`, defaulting to `false`.
- Only an effective Tactical/role superuser may change the policy through Core.
- Successful policy changes are written through the privileged helper and require a Core audit record; an audit failure triggers a best-effort rollback.
- When enabled, non-superuser account administrators cannot edit/delete an existing superuser account, reset its password/TOTP, or create/change/delete API keys for it.
- Native self-service password reset, 2FA reset and TOTP setup remain valid for the protected superuser acting as themselves.
- The existing rule that only an effective superuser may grant/revoke superuser authority remains unconditional whether the policy is on or off.

## Low-risk review cleanups

- `uninstall.sh` no longer sources `tec-tac.conf`; it uses the existing data-only config parser.
- Privileged Python invocations cited in `install.sh` and `scripts/recovery/*.sh` now use `/usr/bin/python3 -I` instead of resolving `python3` from `PATH`.

## Verification

- Added D1/root-policy regression coverage and expanded Tactical native account-guard coverage.
- Existing root-Python boundary, release-integrity and related account guard tests remain green.

## Rebuild 2

- When superuser account protection is enabled, non-superuser API-key listings now redact secrets owned by protected superuser accounts while preserving metadata and normal-user key visibility.
- Effective superusers retain Tactical's native API-key visibility.
- Extended the Tactical superuser guard regression to cover protected API-key secret reads.

## Rebuild 3

- Fixed D1 account/API-key guards on PostgreSQL by locking only the base User/APIKey row with `select_for_update(of=("self",))`; nullable role state is resolved separately instead of participating in the lock join.
- Added `tests/tactical-superuser-guard-postgres.py`, a real Tactical Django/PostgreSQL integration regression covering guarded user updates/deletes, password/TOTP resets, and API-key create/update/delete with protection both Off and On and targets with/without roles.
- No unrelated functional changes.
