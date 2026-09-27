# FIXING.md — Core 1.15.134

## Review scope

Blocking rebuild of Core 1.15.134-1 for the HIGH finding that the dynamic-filter scope-alias guard treated ordinary descriptive values as Tactical scope references and could disable existing schedules during dispatch.

Review that:

1. `normalize_scheduler_targets()` accepts `Main Site`, `Johannesburg site`, `ssh agent`, `backup-client` and `windows_agent` as ordinary filter values.
2. It still rejects explicit Tactical scope field references including `site.id`, `site__id`, `siteId`, `payload.clientIds` and `agent.id`.
3. Bare scope nouns inside a longer module path such as `ticket.client` are not treated as alternate scope selectors.
4. A saved dynamic schedule with `filter.name="Main Site"` remains enabled when `dispatch_due_schedules()` processes it and queues normally.
5. Existing M13 scope-channel protections and the 1.15.134-1 endpoint-PK compatibility fix remain intact.

## Files changed

- `framwork/tec_tac/scheduler_targets.py`
- `tests/scheduler-filter-value-compat-1.15.134.py`
- `tests/scheduler-hardening-1.15.134.py`
- `tests/scheduler-foundation.sh`
- release metadata/notes only

## Explicitly out of scope

- Held-back non-blocking review findings.
- Other Scheduler behavior or contract changes.
