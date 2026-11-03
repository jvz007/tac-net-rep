# Tec-Tac Framework 1.17.110

Date: 3 November 2026. Core now works on Tactical 1.5.2 and 1.6.1. Your servers run 1.5.2 today and keep working exactly as before. When a server moves to 1.6.1, Core's server backup, restore and long schedule runs keep working too. Install this release **before** you upgrade any server to Tactical 1.6.1, because Tactical's own update runs `backup.sh`.

Closes: the two Core compatibility items of the impact review `docs/planning/tactical-1.6.1/IMPACT-TACTICAL-1.6.1.md` ("Core impact": server backup, server restore, scheduler; "Upgrade risks": dev02 tests 1 and 3). The file-browser parity items (route owners, `uuid` route kind, long path queries, binary chunk transport, session audit) are left for later releases.

## What changed and why

1. **Server backup works with `backup.sh` v34 and v35.**
   * Why: Tactical 1.6.1's `backup.sh` v35 builds its work folder with `mktemp -d -p /var/tmp` (`reference-1.6.1/tacticalrmm/backup.sh`, line 68). That ignores `TMPDIR`, and the script has no other variable for it. Core's privileged helper refused any folder outside its job staging area (`scripts/server-backup-helper.py`, `_validate_tactical_workspace`), so the root-owned copies failed and Core's archive check stopped the backup.
   * Now: Core reads `SCRIPT_VERSION` from `backup.sh`. For v34 (Tactical 1.5.2) nothing changes: the work folder is in Core's staging area through `TMPDIR`. For v35, Core first checks that `/var/tmp` is a real, root-owned folder with the sticky bit. It writes a root-only binding file (`staging/tactical-workspace-<job>.json`, mode 0600) listing the `tacticalrmm-*` folders already there. The privileged helper then accepts exactly one new folder, `/var/tmp/tacticalrmm-` plus 21 letters or digits. It must not be in that list, must not be a link (checked with `lstat`, opened with `O_NOFOLLOW` at every step), must be owned by the Tactical account and must have mode 0700, as `mktemp` creates it. The first folder accepted is recorded, and every other folder is refused for the rest of the job. When the script ends, Core removes that folder with link-safe removal, and removes the binding.
   * Any other `backup.sh` version is refused before anything is created: "Tactical backup.sh vN is not a version Core has checked (v34 or v35); refusing to run it. Update Tec-Tac Core first."
   * The staging-area rule for v34 is unchanged. In v34 mode a `/var/tmp` folder is still refused.
2. **Server restore picks the matching `restore.sh`.**
   * Why: Tactical 1.6.1's `restore.sh` v68 accepts only Debian 13 and Ubuntu 26.04 (`reference-1.6.1/tacticalrmm/restore.sh`, lines 70-83) and writes its OS check in a different form. Core's `target.os` override was bound to v67 only, and Core's own OS list was Debian 11/12 and Ubuntu 22.04 (`scripts/server-backup-helper.py`, `TACTICAL_RESTORE_OS_GATE`, `validate_target_preflight`, `_prepare_tactical_restore_script`).
   * Now: `TACTICAL_RESTORE_PROFILES` holds one profile per checked version. v67 (Tactical 1.5.2): Debian 11 and 12, Ubuntu 22.04. v68 (Tactical 1.6.1): Debian 13, Ubuntu 26.04. Restore validation reads the installed `restore.sh` and uses that profile for `target.os`. A `target.os` override removes only that version's exact OS check.
   * A new check, `target.restore_script` ("Tactical restore script"), shows the version and the systems it supports. An unknown version fails this check, and no override can accept it. The restore itself also refuses an unknown `restore.sh` before any destructive step, with or without an override.
   * `compatibility_baseline` in the validation report now reads `"34, 35"` and `"67, 68"`. The native archive layout is the same for both versions, so the archive check is unchanged.
3. **Schedule runs set their own soft and hard time limits.**
   * Why: Tactical 1.6.1 starts its Celery worker with `--time-limit=14400 --soft-time-limit=14100 --autoscale=10,4` (impact review, "Celery"). `tec_tac.execute_schedule_run` set a hard limit only (`framwork/tec_tac/tasks.py`; `apply_async` in `framwork/tec_tac/scheduler.py`, `_queue_run`). A task with no soft limit inherits the worker's 14 100 seconds, so a run longer than 3 h 55 min would have been cut.
   * Now: `_queue_run` sends `time_limit` = action timeout + 300 seconds (as before) and `soft_time_limit` = that limit - 60 seconds. The new `tec_tac.scheduler.schedule_run_time_limits(timeout_seconds)` returns the pair. The task declares the seven-day pair (`time_limit=605100`, `soft_time_limit=605040`) as a backstop. The soft limit always falls after the action's own timeout, so the worker default never applies. On Tactical 1.5.2 a run behaves as before.
   * No other Core task runs anywhere near 14 100 seconds (event jobs stop at 615 seconds, module-update detection at 300), so no other task changed.
4. **Documented: what a 2 000-endpoint run should expect against the 10-worker cap.** See `docs/scheduler.md`, "Time limits and worker slots on Tactical 1.5.2 and 1.6.1". In short: one run holds one worker slot for its whole duration; 2 000 endpoints at 1 to 2 seconds each take about 35 to 70 minutes; on 1.6.1 an offline agent costs its full command timeout; set `timeout_seconds` to cover the run with margin (at least 7 200 seconds for 2 000 endpoints); and use pending completion for work that waits on something outside Core.

## Module-facing changes

* **None that a module must act on.** No capability, contract or route version changed, and no module calls the backup helper directly.
* Server backup (`core.server_backup`, used by the Backups module): same operations and the same result shapes. Validation reports gain one target check, `target.restore_script`, and `compatibility_baseline` values now list both versions. A grep of `modules/` found no module that reads `compatibility_baseline` or names target check ids other than `target.os`.
* Scheduler: a module's `timeout_seconds` now also sets the soft limit. A handler that runs past its declared timeout gets `SoftTimeLimitExceeded` 60 seconds before the hard stop, and Core records it like any other exception. The new `schedule_run_time_limits` is a helper, not a contract.

## Works on Tactical 1.5.2 and 1.6.1

This release works on Tactical 1.5.2 and 1.6.1. On 1.5.2 (`backup.sh` v34, `restore.sh` v67) backup and restore behave as before. On 1.6.1 (`backup.sh` v35, `restore.sh` v68) they use the new paths above.

## Assumptions (recorded in `reviews/questions/core.md`)

* `backup.sh` v35 has no work-folder variable, so Core allows exactly the script's own new `/var/tmp` folder, under the checks above. A `tacticalrmm-*` folder the job never claimed is left alone and logged, because it may belong to a manual backup.
* Core runs only the script versions it has checked. A newer Tactical with new scripts needs a Core update first.
* An upgraded Debian 12 or Ubuntu 22.04 server can run Tactical 1.6.1, but `restore.sh` v68 refuses that system. A restore there needs the existing audited `target.os` override, or a new server on Debian 13 or Ubuntu 26.04. Core keeps no copy of v67.
* A run that reaches its soft limit is retried while retries remain, then fails, the same as any other exception. This matches the event-jobs contract for `SoftTimeLimitExceeded`.

## Tests

* New: `tests/tactical-1.6.1-compat-1.17.110.py`. Covers: v34 and v35 mapping; v36 refused before any folder exists; `/var/tmp` must be sticky and not a link; a missing or readable binding refused; wrong mode, pre-existing, misnamed, outside, `..`, relative, linked and foreign-owned folders refused; first folder claimed, second refused; writes stay 0600 and never follow a linked sub-folder; the shim's v35 paths; cleanup removes only the claimed folder; v34 staging unchanged. For restore: the v67 and v68 OS checks match the upstream scripts exactly; exact copy without an override and only the OS check removed with one; a mismatched check and v69 refused; preflight for v67 and v68 on Debian 12/13 and Ubuntu 22.04/26.04, and v69. For the scheduler: limit arithmetic, the `apply_async` keywords and the task decorator. Also the docs, version and line endings.
* Updated so they run against the new keyword (fake `apply_async` now accepts `soft_time_limit`): `tests/scheduler-stale-revocation.py`, `tests/scheduler-completion-harness-1.17.61.py`, `tests/scheduler-one-off-retry-1.17.18.py`, `tests/scheduler-one-off-run-1.17.16.py`. All pass.
* Re-run and passing on Linux (WSL Ubuntu 24.04, Python 3.12): `tests/server-backup-foundation.sh`, `tests/backup-closure-1.15.145.py`, `tests/d2-d3-restore-orchestration-1.15.173.py`, `tests/housekeeping-backup-hardening-1.15.138.py`, `tests/server-backup-d3-destructive-restore-1.15.189.py`, `tests/server-backup-decision-closure-1.15.166.py`, `tests/tracker-behavior-closure-1.15.161.py`, `tests/tracker-final-review-1.15.164.py`, `tests/release-integrity.sh`.
* The new test also runs on Windows, where it checks the scheduler, docs and release parts and says plainly that it skipped the Linux-only helper part.
* `python -m py_compile` on every changed Python file: clean.
* `ruff check` with the repo's config on the changed files: no new findings in changed source (193 before and after, all existing). The new test has one S102 (`exec`), the same pattern the existing scheduler tests use.
* `RELEASE_NOTES_1.17.109.md` moved to `docs/releases/`.
* Not run here: anything that needs Django, which is not installed on this PC. The Celery limits are checked by source inspection, not on a live worker.

## Checks on the test server (dev02)

On Tactical 1.5.2, before the upgrade:

1. Run a Core server backup (Backups module, Back up now). Expected: it succeeds as before; the job log names "backup.sh v34" and "work folder: staging". FAIL: it fails, or the log names v35. Send back the job log.
2. Validate a restore of that backup (mode `tactical`). Expected: "Tactical restore script" passes with "restore.sh v67 (Tactical 1.5.2)", and Operating system passes on Debian 12. FAIL: either check fails. Send back the validation report.
3. Open the Scheduler and Run now on any short schedule. Expected: it succeeds as before. FAIL: it fails with a time-limit error.

After the upgrade to Tactical 1.6.1:

4. Run a Core server backup. Expected: it succeeds; the log names "backup.sh v35", "work folder: var-tmp" and "removed backup.sh work folder /var/tmp/tacticalrmm-...". Afterwards `ls -ld /var/tmp/tacticalrmm-*` lists no folder from this backup. FAIL: the backup fails, or the folder is still there. Send back the job log.
5. Validate a restore (mode `tactical`) on the same server. Expected: "Tactical restore script" passes with "restore.sh v68 (Tactical 1.6.1)". Operating system **fails** on Debian 12 or Ubuntu 22.04 (v68 supports only Debian 13 and Ubuntu 26.04) and offers the override. FAIL: Operating system passes on Debian 12, or the restore-script check fails. Send back the validation report.
6. Start a schedule whose action runs longer than 4 hours (if one exists), or check with `celery -A tacticalrmm inspect active` that `tec_tac.execute_schedule_run` shows `soft_time_limit` above 14100. Expected: the run is not cut at 3 h 55 min. FAIL: the run ends with `SoftTimeLimitExceeded` before its own timeout.
