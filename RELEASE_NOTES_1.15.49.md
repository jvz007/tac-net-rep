# Tec-Tac Framework 1.15.49

## Scheduler retry durability

- Adds `TecTacScheduleRun.last_queued_at` and backfills existing queued runs.
- Stale queued-run recovery now measures age from the most recent queue/re-queue event, falling back to `created_at` only for legacy rows.
- Celery retries update `last_queued_at` before the retry countdown starts, so valid delayed retries are not incorrectly failed as `Stale`.

## Trust-policy downgrade step-up

- Trust-floor reductions initiated from Tec-Tac now require a fresh TOTP code from an effective Tactical/role superuser.
- The root-owned verifier independently validates the current Knox bearer token against PostgreSQL, confirms effective-superuser authority, and verifies TOTP before changing the root-owned policy.
- Knox token and TOTP proof are passed to the privileged helper over stdin rather than command-line arguments.
- Raising the trust floor remains a normal privileged operation.
- Direct root-console policy changes remain available as the break-glass path.
- Privileged trust-policy failures now return concise errors instead of Python tracebacks.
