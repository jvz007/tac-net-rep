# Tec-Tac Framework 1.15.51

## Trust-policy temporary lowering durability

- Replaced the 1.15.50 transient `systemd-run` auto-revert with static root-owned systemd units:
  - `tec-tac-trust-policy-revert.service`
  - `tec-tac-trust-policy-revert.timer`
- The service reads `/etc/tec-tac/policy/pending-trust-policy-revert.json` and restores the previous trust floor once `expires_at` has passed.
- The service is enabled at boot and the timer checks every two minutes, so temporary lowering survives server restarts and downtime.
- Framework installation runs one immediate revert check to recover already-expired pending changes from 1.15.50.
- No NOPASSWD path was added; lowering remains a root-console operation using normal sudo authentication.

## Trust-policy audit

- Added `console_change_requested` to the accepted Core audit action vocabulary so UI requests for a lower trust floor are actually persisted instead of being rejected by audit validation.

## Scheduler retry stale recovery

- Stale queued recovery is now retry-countdown aware.
- Initial queued runs retain the normal configured stale window.
- Re-queued retries become eligible for stale recovery only after `last_queued_at + retry_delay_seconds_snapshot + queued_stale_window`.
- This prevents retries with delays longer than the stale window from being marked `Stale` before Celery is expected to redeliver them.
- Added a pure timing regression test covering a 60-minute retry with a 10-minute stale window.

## Compatibility

- No database migration is required.
- No UI update is required; Tec-Tac UI 0.12.23 remains compatible.
