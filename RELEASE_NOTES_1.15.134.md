# Tec-Tac Core 1.15.134

## Blocking review fix: dynamic filter value alias compatibility

- Narrowed the Scheduler dynamic-filter value guard so it rejects only explicit Tactical scope field references instead of suffix-matching ordinary module data.
- Descriptive values such as `Main Site`, `Johannesburg site`, `ssh agent`, `backup-client`, `windows_agent` and `ticket.client` are accepted again.
- Explicit field references such as `site.id`, `site__id`, `siteId`, `payload.clientIds`, `selector/site_id` and `agent.id` remain rejected as alternate Tactical scope channels.
- Existing dynamic schedules containing ordinary descriptive filter values therefore remain enabled during `dispatch_due_schedules()` instead of being disabled as `InvalidTargetShape`.
- The 1.15.134-1 legacy endpoint-PK compatibility fix remains unchanged.

## Regression coverage

- Added `tests/scheduler-filter-value-compat-1.15.134.py` covering the required accepted/rejected values and the real `dispatch_due_schedules()` control flow for a saved `filter.name="Main Site"` schedule.
- Extended `tests/scheduler-hardening-1.15.134.py` with ordinary-value compatibility cases.
- Wired the blocker regression into `tests/scheduler-foundation.sh`.

## Rebuild scope

This is a blocking rebuild of 1.15.134-1 only. No held-back non-blocking review findings are included.
