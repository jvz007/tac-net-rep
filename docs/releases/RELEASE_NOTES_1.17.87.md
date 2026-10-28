# Tec-Tac Framework 1.17.87

Date: 28 October 2026. Fixes the held findings of the 1.17.86 review. No migration, no new route, no contract change.

## What changed and why

1. **Pause and resume no longer move `updated_at` (Medium).** `updated_at` is the schedule's revision baseline: an occurrence older than it counts as pre-edit and is consumed. The 1.17.86 pause and resume saves wrote `updated_at`, so a `once` schedule whose occurrence fell inside the pause was consumed on the resume tick: no run, no missed row, and Core switched the person's `enabled` off. Both saves now write `paused_reason` only. The occurrence now runs, or is written as a missed row, under the schedule's missed policy.
2. **1.17.86 notes and `docs/module-scheduling.md` corrected (Medium).** 1.17.86 did not close Johan's dev02 report. `checks.provider-run` belongs to Checks, and Core pauses only for the module that owns the schedule, so a disabled Network Probe does not pause it. Checks 0.17.2 skips cleanly. The Checks request in `reviews/requests/core-modules.md` ("From networkprobe 0.2.0") stays open. A Core pause by declared dependency is proposed in `reviews/questions/core.md`, not built.
3. **Run now strict scope tested by behaviour (Low).** The source grep is gone. A test now calls the real `SchedulerRunNowView.post`.
4. **Tests that scan `modules/`.** Fixed, see below.

## Module-facing change

None. Schedules of a module that is disabled and then enabled keep their `updated_at`, which is the behaviour `updated_at` had before 1.17.86.

## Tests

- `tests/scheduler-module-pause-1.17.87.py` (new): a `once` schedule inside a pause, for `run_on_recovery` (queued) and `skip` (a missed row). `updated_at` and `enabled` are unchanged by the pause and the resume. The stub save stamps `updated_at` like `auto_now`. It fails if `updated_at` goes back into the two saves.
- `tests/scheduler-run-now-person-strict-1.17.87.py` (new): a scheduler manager outside the targets' Tactical scope on a declared person action gets 403, no run and one `deny` row. An undeclared action keeps the manager bypass. It fails if `strict=person_run` is reverted.
- `tests/scheduler-module-pause-1.17.86.py`: the source grep removed.
- Scan tests repaired (they failed before 1.17.86 too): `scheduler-compat-1.17.61/63/66/67/68`, `server-job-hook-compat-1.17.62`, `system-actions-compat-1.17.61`, `filter-sets-1.17.50`, `event-jobs-refusal-audit-1.17.48`, `event-jobs-refusal-bound-1.17.49`. Cause: they were written as "no module uses the new names yet" guards for the release that added them. Modules (Communicator, Patch Management, Remote Background, Certificate Management, Groups) have since adopted those names, which is intended, so the tests now print the adoption and keep the signature checks. Two pinned "the last five migrations" and Groups' `STRING_OPERATORS`, which Groups moved. These are not module breakage. No request to a module owner is needed.
- Not drift in the code: `fcntl` and `accounts` import errors (`audit-browser-provenance-hardening`, `d6a-invalid-utf8`, `state-atomic-hardening-1.15.153`, `module-replacement-*-runtime-1.17.13`, `update-trust-policy`) come from running on Windows without Django. They run on the Linux pipeline.
