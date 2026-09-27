# Tec-Tac Framework 1.15.97

## D4 — automatic Session Security retention

- Runs Core-owned session/audit retention automatically from the existing Tec-Tac Scheduler timer.
- Persists `last_history_cleanup_at` and runs cleanup only when 24 hours have elapsed.
- Advances the due marker only after successful cleanup, so failures retry on the next scheduler tick.
- Keeps general schedule dispatch available if retention cleanup fails.
- Adds behavioural regressions that execute actual cleanup deletion logic and prove Scheduler-tick invocation.

UI remains unchanged at 0.12.42.
