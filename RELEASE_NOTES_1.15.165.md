# Tec-Tac Core 1.15.165

Rebuild of 1.15.165 for the blocking Scheduler run-now authorization regression.

## Fix

- Run-now now repairs legacy endpoint identities with the global identity resolver before authorization.
- Caller Tactical scope is checked before any repaired target is persisted.
- `PermissionDenied` is no longer treated as broken target data and therefore cannot disable or invalidate a schedule.
- Genuine target normalization/identity errors still quarantine the broken schedule.

## Regression coverage

- `tests/scheduler-run-now-scope-1.15.165.py` proves an out-of-scope module-action user receives 403 without changing `enabled`, `target_state` or `targets`.
- The same regression proves a scope-restricted `can_do_server_maint` manager receives 403 on another user's schedule with no mutation.
- Existing run-now canonicalization, Scheduler compatibility, Scheduler foundation and release integrity suites remain green.
