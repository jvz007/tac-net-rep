# Tec-Tac Framework 1.17.64

This release closes the held Low finding of the 1.17.63 review: a finished server job can no longer stay hidden because its job file kept the same modification time.

Date: 20 October 2026. Every earlier route, field and contract stays. No migration. No module has to change.

## What changed and why

The server job hook skips a job file it has already read as "not finished", so a stuck job costs no read every minute. Until now it trusted the file's modification time (mtime) alone. A rewrite that restored the mtime would hide a finished job for good. Now:

- The skip stamp is the mtime in nanoseconds plus the file size, taken from the same directory scan (no extra read).
- A skip entry lives at most `WAITING_TICKS` (5) ticks. After that Core reads the file once more and remembers it again. A truly stuck job costs one read every few minutes, still inside the per-tick read budget.
- The 1.17.63 protection stays: unfinished files inside the memory cost no read and use none of the 50 hand-overs per tick.

Files: `framwork/tec_tac/server_job_hooks.py`. Test: `tests/server-job-hook-skip-cache-1.17.64.py`.

## Module-facing

None. No module imports `server_job_hooks`. The handler payload, the event job id and every contract are unchanged.

## What is not in this release

The plan for 1.17.64 also asked to switch on the amended AD-13 condition 2 (no run-time creator re-check for scheduled runs, CQ184 b wide, CQ186). That change was not built in this run: the permission system blocked the edit as a security relaxation. `scheduler.AD13_CONDITION_2_AMENDED` is still `False`, so Core still re-checks the owner at every scheduled run. This is flagged for human review. The switch, the module compatibility proof, the test changes and the dev-server checklist for it wait for Johan's go-ahead.

## Dev-server checklist

1. Update the dev server to 1.17.64 and restart Core and the Celery workers. PASS: `makemigrations --check --dry-run` shows no changes. FAIL: any change is listed. Send back the output.
2. Start a server-maintenance job from a module that registers a `server_job_finished` hook (for example a Certificate Management renewal) and close the browser tab. PASS: within a few minutes the module records the outcome once. FAIL: no record, or two records. Send back the Core log lines containing `server_job_hooks`.
3. Export a fresh public contract into `docs/contracts`. PASS: it exports with no error and no change in the contract text.
