# FIXING — Core 1.15.99

Review scope for this release: **D6a only**.

## Tracker items

- **M26** — invalid UTF-8 in Tec-Tac extension registry manifests or module-state data must never stop Tactical starting. Decode failures are converted into `RegistryError` / `ModuleStateError`, which the existing bootstrap boundary degrades to Core-only extension loading.
- **M27** — the precise Tactical account-guard import is now inside its startup try boundary, and the emergency fail-closed installer lives in the independent `tactical_account_guard_fallback.py` module. A precise-guard import/runtime failure therefore cannot take out both protection layers.

## Behavioural regressions

- `tests/d6a-invalid-utf8.py` exercises the real registry and module-state readers with invalid UTF-8.
- `tests/d6a-guard-import-isolation.py` simulates a precise-guard import failure and proves AppConfig continues through the separate fallback, reporting bridge and Core route registration.
- `tests/apps-ready-startup-safety.py` covers precise wrapper-install failure with the independent fallback.
- `tests/tactical-superuser-guard.py` executes the independent fallback against native role/user/API-key/self-service handlers and verifies idempotence, non-superuser denial, API-key redaction and effective-superuser access.

## Not in scope

No M2+ Medium backlog work, UI work, or unrelated Low items are included.
