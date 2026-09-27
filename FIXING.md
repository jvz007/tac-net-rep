# FIXING — Core 1.15.97

## Review scope

This release is intentionally limited to finishing **D4 — Tec-Tac-owned Session Security retention** from Claude's tracker.

### D4

Problem: `cleanup_session_history()` existed and used the Core retention policy, but nothing invoked it periodically. History therefore never aged out unless a module called the capability manually. The previous test also mocked the ORM without exercising deletion behavior.

Expected result:
- the existing `tec-tac-scheduler.timer` path invokes a due-check every minute;
- cleanup runs at most once per 24 hours after a successful run;
- failed cleanup does not advance the timestamp and is retried on the next tick;
- Scheduler dispatch continues even when retention cleanup fails;
- expired unrevoked trust rows, dead revoked tombstones and old audit rows are actually deleted;
- live revoked credentials remain protected.

## Files/areas to inspect

- `framwork/tec_tac/session_security.py`
- `framwork/tec_tac/models.py`
- `framwork/tec_tac/migrations/0017_session_history_cleanup_schedule.py`
- `framwork/tec_tac/management/commands/tec_tac_scheduler_tick.py`
- `tests/session-retention-deletion.py`
- `tests/session-retention-scheduler.py`
- `tests/session-security-foundation.sh`
- `docs/session-security.md`
- `docs/scheduler.md`

## Explicitly out of scope

No other Medium/Low tracker IDs are being claimed closed in this release. In particular, M30 capability-version compatibility and L80 ambiguous empty Knox digest retention remain separate tracker items.
