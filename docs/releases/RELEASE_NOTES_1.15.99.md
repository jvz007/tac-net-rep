# Tec-Tac Framework 1.15.99

## D6a startup-safety completion

- M26: invalid UTF-8 in extension manifests now becomes `RegistryError`, and invalid UTF-8 in module-state data becomes `ModuleStateError`, allowing bootstrap to degrade safely to Core-only startup rather than propagating `UnicodeDecodeError`.
- M27: the precise Tactical account-guard import is now inside the guarded startup boundary; the fail-closed guard is implemented in an independent module so a precise-guard import/syntax/runtime failure cannot remove the emergency privilege boundary.
- The independent fallback remains stricter than normal operation: non-superusers cannot mutate native roles/users/API keys or self-service credentials, and API-key secrets are redacted from non-superuser listings.
- Added behavioural regressions for invalid UTF-8, precise-guard import isolation and the independent fallback.

UI is unchanged.
