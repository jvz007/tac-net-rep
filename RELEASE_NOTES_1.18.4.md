# Tec-Tac Framework 1.18.4

Date: 18 November 2026. This release closes the two held findings from the 1.18.3 review. Both concern the lifecycle lock. It changes no contract.

## What changed and why

* **A server-backup restore now takes the lifecycle lock.** Before, a full or Tec-Tac restore never took `/var/lib/tec-tac/lifecycle.lock`. The UI sync publish path unit could rename the UI sync tools folder while the restore was installing the same folder. Now `server-backup-helper.py` takes the lock in the restore, right after the job reaches the "restore-prepared" stage and before the first pre-restore snapshot, service stop, Tactical tree move or `restore.sh`. It does this only for the `full` and `tec_tac` modes, the two that install Tec-Tac components. A Tactical-only restore installs nothing from Tec-Tac and is unchanged.
* **A busy lock refuses the restore before anything changes.** The job fails with `another Tec-Tac lifecycle operation is already running; the restore was not started`. Services keep running, the Tactical tree and the UI stay as they were, and there is nothing to roll back. The restore's own `server-backup.lock` is still released. The restore does not wait or retry: a refusal is the safe choice, and you can start it again when the other job ends. If the lock file cannot be opened or locked for another reason, the restore refuses the same way with a one-line reason.
* **Where the lock sits, and why.** It is taken in the parent restore, not in the `--install-restored` step of `system-update-helper.py`. That step runs as a child of the restore, after services are stopped and the tree is moved. A lock there would come too late, and a second lock request from the child would be refused by the parent's own lock and break every restore. The step now says in a comment that it runs only under the restore's lock and never takes it. Lock order is `server-backup.lock`, then `lifecycle.lock`, both non-blocking, so no deadlock with System Update (update lock, then lifecycle) or module jobs.
* **The restored installer and the path unit skip their own publish.** While the restore holds the lock, `install.sh` (restored) and the path unit run `--publish-ui-sync`, find the lock busy, print the skip line and exit 0. The restore's own UI step still publishes the tools.
* **Any other lock failure in `--publish-ui-sync` is one line, not a traceback.** Before, only "busy" was handled, so a read-only disk, a wrong owner or a missing folder under `/var/lib/tec-tac` ended in a Python traceback. Now `acquire_lifecycle_lock()` closes its file handle on any other error and re-raises it. The `--publish-ui-sync` branch writes `[TEC-TAC] UI module sync script not published: <reason>` to stderr and exits 1. "Busy" still prints the skip line on stdout and exits 0, and it is still checked first, so it can never exit 1. `install.sh` already turns a non-zero exit into its one-line warning without stopping the install. No staging, verification or ownership check was loosened.

## Correction to the 1.18.3 notes

The 1.18.3 notes said the lifecycle lock excludes every other publisher and that a restore holds it. That was wrong for restore. 1.18.3 did not cover a restore. 1.18.4 does. The 1.18.3 notes are kept unchanged in `docs/releases/`.

## Requests closed

* Held MEDIUM (1.18.3 review), `reviews/core/BACKLOG-new-findings.md`: a server-backup restore never takes `lifecycle.lock` (`system-update-helper.py:2809` area). Closed in 1.18.4.
* Held LOW (1.18.3 review), `reviews/core/BACKLOG-new-findings.md`: any lock failure other than busy gives a traceback in `--publish-ui-sync`. Closed in 1.18.4.

The release manager moves both after signing.

## Module-facing

None. A grep of `modules/` found no user of `lifecycle.lock`, `--install-restored`, `server-backup-helper`, `system-update-helper` or `--publish-ui-sync`, apart from one mention in `modules/backups/TEST_CHECKLIST_0.8.0.md`, which is a test checklist and not code. No contract, capability or endpoint changed, so no new public contract export is needed. The export still waiting from 1.18.2 stays valid.

## What is not in this release

* A lock for a Tactical-only restore. It runs no Tec-Tac installer and cannot race the UI sync publish. If you want restores to exclude module jobs entirely, that is a later patch.
* Waiting or retrying for the lock. The restore refuses up front instead.
* Any other open request or held finding.

## Checks run here

`bash tests/release-integrity.sh`, `tests/version-1.18.4.py`, `tests/lifecycle-lock-restore-1.18.4.py`, `tests/ui-sync-auto-publish-1.18.3.py`, `tests/backup-recovery-system-update-1.15.140.py`, `python -m py_compile` on both helpers and the new tests, and `ruff check`. Could not run on this PC: `fcntl` behaviour (the new test drives the lock logic against a fake `fcntl`, and the real `flock` run is skipped with a printed note), `systemd` behaviour (the path unit firing), Django-dependent tests and the Docker-only `tests/system-update-linux-staging-1.17.98.py`.

## Johan test checklist (beta server)

Update the server to Core 1.18.4 first.

1. Update to 1.18.4.
   * PASS: the version shows 1.18.4.
   * FAIL: the update fails or the version stays. Send the System Update log.
2. With a System Update or a module job running, start a full server-backup restore.
   * PASS: the restore job fails at once with `another Tec-Tac lifecycle operation is already running; the restore was not started`. Services are still running. The Tactical tree and the UI are untouched.
   * FAIL: services stop or the Tactical tree moves. Send the job log and `systemctl status` for the Tec-Tac and Tactical services.
3. On an idle server, run a full restore.
   * PASS: the restore completes. `/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh` exists and is owned by root. `journalctl -u tec-tac-ui-sync-publish.service` shows the skip line or the published line, with no rename error.
   * FAIL: an ENOENT or ENOTEMPTY error, or a missing tools folder. Send the restore log and the journal.
4. Make `/var/lib/tec-tac` read-only or give it the wrong owner on a test box, then run `sudo python3 -I /usr/local/lib/tec-tac-system-update/system-update-helper.py --publish-ui-sync`.
   * PASS: one stderr line, `[TEC-TAC] UI module sync script not published: ...`, exit code 1 (`echo $?`), no traceback.
   * FAIL: a Python traceback. Send the output.
5. Hold the lock with `sudo flock -n /var/lib/tec-tac/lifecycle.lock sleep 60 &`, then run the same command.
   * PASS: the skip line on stdout and exit code 0, as in 1.18.3.
   * FAIL: it publishes, errors or waits. Send the output.
