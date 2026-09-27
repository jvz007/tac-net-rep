# Tec-Tac Core 1.15.89

## D6a — Tactical startup independence

- Tec-Tac extension discovery is now additive to Tactical startup: `RegistryError` or `ModuleStateError` during bootstrap degrades to Core-only extension loading instead of aborting Django startup.
- The precise native Tactical role/account compatibility guard is now startup-safe. If installation fails because an upstream Tactical view changed, Core logs the compatibility failure and immediately installs a coarse fail-closed role/user mutation boundary instead of raising from `AppConfig.ready()`.
- In fail-closed compatibility mode, only effective superusers may mutate Tactical roles/users. Ordinary account managers are denied until the precise compatibility guard is repaired; startup availability is never recovered by silently dropping the privilege boundary.
- Added regressions for registry failure, module-state failure, AppConfig continuation after guard failure, and fail-closed role/user mutation enforcement.

## Low-risk cleanup

- Restored the pre-pagination no-parameter compatibility behavior for Module Manager lifecycle history and session-security audit history: no-parameter calls return the bounded legacy 200-row response, while explicit pagination/filter parameters use the paged contract.
- Documented that browser module-audit affordances may be hidden by the UI, but Core remains authoritative and returns HTTP 403 for direct audit writes without the required module permission.


## Rebuild 1.15.89

- Extended the D6a fail-closed Tactical account compatibility guard to cover API-key listing and mutation handlers plus self-service password/TOTP handlers.
- In fail-closed mode, non-superusers receive redacted API-key secrets and only effective superusers may mutate API keys or protected account credential handlers.
- Added regressions for API-key privilege escalation and the AppConfig recovery path when an upstream self-service view is missing.
