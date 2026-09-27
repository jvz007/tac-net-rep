# Tec-Tac Core 1.15.92

## D1 / R5 - superuser role mutation closure

- M28: native Tactical `GetUpdateDeleteRole.delete` is now guarded. A non-superuser role manager cannot delete a role whose `is_superuser` flag is set; effective superusers retain the native action.
- M29: native full role PUTs now mirror Tactical serializer semantics for omitted boolean fields. Omitting `is_superuser` is treated as a requested `False`, so form-encoded/full PUT cannot silently demote a superuser role outside the unconditional R5 boundary.
- Both protections are unconditional R5 rules and do not depend on the optional `protect_superuser_accounts` policy.

## Low - account-security corrupt schema fails closed

- L83: non-numeric account-security policy schema values are converted to `AccountSecurityPolicyError` rather than leaking `ValueError` into guarded account requests.
- `protection_enabled()` therefore retains fail-closed behavior for malformed policy files.

## Regression coverage

- Extended `tests/tactical-superuser-guard.py` with behavioural delete and omitted-checkbox demotion cases.
- Added `tests/account-security-policy-corrupt-schema.py` for malformed-schema fail-closed behavior.

## Compatibility

- No database migration is required.
- UI 0.12.40 remains compatible; no UI release is required.
