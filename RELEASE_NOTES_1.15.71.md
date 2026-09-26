# Tec-Tac Core 1.15.71

## Security: Tactical native superuser-role guard (R5)

Core now protects Tactical's native `/accounts/roles` and `/accounts/users` mutation paths without modifying Tactical source.

Only an effective superuser may:

- create a role with `is_superuser=true`;
- change an existing role's `is_superuser` state; or
- assign a role whose `is_superuser` state is true to another account.

Ordinary Tactical role/account managers retain their normal workflows. Full-form saves that resend an unchanged `is_superuser` value or an already assigned role are not treated as privilege changes.

The guard is installed idempotently from `TecTacFrameworkConfig.ready()` around Tactical's four native create/update handlers. Update paths hold the relevant role/user rows with `select_for_update()` while Tactical's original serializer executes so a concurrent role transition cannot bypass the decision. A refused privilege transition exits the transaction before Core writes its denial audit, ensuring the audit row is not rolled back with the blocked mutation.

Denied operations are recorded through the Core audit contract as `deny` events using `role_superuser_change` or `superuser_role_assignment` object types.

No public `core.*` capability or API contract changes are introduced.

## Validation

- `tests/tactical-superuser-guard.py`
- `tests/access-security-foundation.sh`
- `tests/access-api-foundation.sh`
- `tests/contracts-foundation.sh`
- `tests/release-integrity.sh`

## Review rebuild

- Fixed the native Tactical user-create guard so boolean role values are interpreted exactly as Tactical interprets them (`True` -> role pk 1, `False` -> role pk 0). This closes the `role=true` superuser-role assignment bypass found during review.
- Added direct and wrapped-endpoint regressions proving a non-effective-superuser cannot create a user with `role=True` when role 1 is a superuser role.
