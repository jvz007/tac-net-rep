# Tec-Tac Framework 1.17.56

Backups can now apply retention and read free space without waiting for the job. Backups 0.8.0 shipped both switched off. This build gives it what it needs to switch them on.

This is one change. `core.server_backup` moves from 1.10.0 to 1.11.0. Every earlier operation, argument and response field stays. Backups pins `>=1.6.0,<2.0.0`, so it still resolves.

## What is new

- **`start_get_status(destinations=None, context)`.** The non-waiting twin of `get_status`. It runs the same destination check and returns `{job_id, status: "queued", action: "get_status"}` at once.
- **`start_apply_retention(policies, context)`.** The non-waiting twin of `apply_retention`. It runs the same policy check, with the same error text, and returns `{job_id, status: "queued", action: "apply_retention"}` at once. Both twins now share one check, so they cannot drift apart.

The waiting `get_status` (120 s) and `apply_retention` (7200 s) are unchanged.

## Module-facing change (core.server_backup 1.11.0)

All additive.

- **Operations.** The registered list gains `start_get_status` and `start_apply_retention`. The fifteen earlier names stay.
- **`metadata.dangerous_operations`** becomes `["restore_backup", "start_restore_backup", "start_apply_retention"]`, because retention deletes archives. Nothing in Core or in `modules/` reads that list today.
- **Result rule.** `get_job_status` already returns the scrubbed `result` for any job started by a `start_` operation, failed jobs included. Nothing changed there. A test now proves it for these two actions.
- **No new authority.** The calling module keeps its own role check, its own retention plan guards and its own confirmation, as with `start_restore_backup`.
- **Backups.** Backups 0.8.0 can switch retention and the free-space row back on. Its rebuild must raise its pin to `>=1.11.0,<2.0.0` when it uses them. Until then `>=1.6.0,<2.0.0` still resolves.
- **Retention caveat.** A `manual` archive counts as `unclassified` since 1.17.54. Retention deletes an old `manual` archive beyond `keep_unclassified` (CQ162).
- **Helper age.** `start_get_status` needs the 1.17.54 helper. An older helper refuses the job. Core publishes no helper version. A missing `stage` in a `validate_destination` result is the only signal that the helper is older than 1.17.54.
- **Contract export.** The row for `core.server_backup` shows 1.11.0 and the two new operations once the release manager exports it from the signed build.

## What does not change

- `scripts/server-backup-helper.py`. It already allows `apply_retention` and `get_status`, so no installer or helper update is needed.
- The waiting operations, `health()`, the browser Backup & Restore views and every other contract.

## Tests

- New: `tests/server-backup-start-retention-status-1.17.56.py`.
- Version pins moved from 1.10.0 to 1.11.0 in `tests/d3-ad3-closure-1.15.189.py`, `tests/server-backup-capability-compat-1.15.189-1.py`, `tests/server-backup-foundation.sh` and `tests/server-backup-nonwaiting-1.17.54.py`.

## Dev-server checklist (Johan)

Install the signed 1.17.56 build first. Then, on dev02 as the root helper user:

1. **Capability.** In the Django shell, `get_capability("core.server_backup", version=">=1.11.0,<2.0.0")`. Expected: version 1.11.0. FAIL: any other version or an import error. Send back the error.
2. **Status.** Call `start_get_status` for one local backup folder, then `get_job_status` until done. Expected: the call returns a job id in under 2 seconds, and the job ends `succeeded` with `free_bytes` and `tactical_backup_schedule` in `result`. FAIL: the call blocks, there is no `result` key, or it succeeds without `free_bytes`. Send back the job id and the last 20 log lines.
3. **Retention on a throwaway folder.** Call `start_apply_retention` with one policy on an empty throwaway local folder (keep_daily 1, keep_weekly 1, keep_monthly 1, keep_unclassified 10000). Expected: a job id at once, and the job ends `succeeded` with nothing deleted. FAIL: any file in a real destination disappears, or the job stays `queued` for over 2 minutes. Never run this on a real backup folder.

## Requests closed or answered

- Closed: Backups' request for `core.server_backup` 1.11.0 with `start_apply_retention` and `start_get_status` (`reviews/requests/core.md`).
- Answered: the helper-age question. See "Helper age" above.

## Not run on the build PC

Django is not installed on this PC. The new test needs `fcntl`, so it runs on Linux or WSL only. Static checks and the pure-Python checks were run here.
