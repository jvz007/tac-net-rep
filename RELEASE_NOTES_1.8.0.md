# Tec-Tac Framework 1.8.0

- Adds first-class Tec-Tac Scheduler models and execution history.
- Adds module-facing schedulable action registry.
- Supports once, daily, weekly and monthly schedules with IANA timezones.
- Supports snapshot/dynamic target definitions, missed-run policy, concurrency policy and retries.
- Uses a Tec-Tac-owned minute timer for due evaluation and Tactical Celery for execution.
- Adds scheduler APIs and a harmless built-in scheduler test action.
- Does not modify Tactical tracked source files.
