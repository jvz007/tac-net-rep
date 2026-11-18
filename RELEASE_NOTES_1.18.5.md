# Tec-Tac Framework 1.18.5

Date: 18 November 2026. This release closes the two items from Johan's dev02 test of Core 1.18.3. It changes no contract, route or permission.

## What changed and why

* **A System Update job shows Finished only after it lets go of the locks.** Before, the job record said `succeeded` or `failed` while the helper still held `lifecycle.lock` and `update.lock`. A UI reinstall started in that gap failed with "another Tec-Tac lifecycle operation is already running". Now `system-update-helper.py` releases both locks in the `finally` of `run_job`, before it writes the final status and the history copy. The cleanup after that (package, sidecars, request file, log permissions) is job-specific and needs no lock. `mark_failed` also releases the lifecycle lock before it writes a failed status. Nothing is loosened: the locks are still `LOCK_EX | LOCK_NB`, and nothing that changes the system runs after the release.
* **A short wait at job start.** `acquire_lifecycle_lock` takes an optional `wait_seconds` (default 0). Only `run_job` uses it: it polls every 0.25 s for at most 10 s. This absorbs the moment a process that just finished is still shutting down, and the short hold of the UI sync path unit. After 10 s a real overlap is still refused with the same message. Any other lock error (read-only disk, wrong owner) is raised at once and is not retried. `--publish-ui-sync`, the server-backup restore and every other caller behave as before.
* **A job that failed at the lock now shows `<installed> -> <target>`.** `mark_failed` fills `installed_version` from root-held state when the job has none, best effort, and never raises. "Started" stays empty because the job never started.
* **"Could not satisfy the request Accept header" on the log view.** The UI asks for a job log with `Accept: text/plain`. Tactical's production settings give Django REST framework only a JSON renderer, so it refused the request with 406 before the view ran. New `framwork/tec_tac/log_negotiation.py` holds `LogNegotiationMixin`, which picks the first renderer and never refuses (the same approach `ContractExportView` already uses). It is applied to the three plain-text log routes: System Update (`SystemUpdateJobLogView`), Module Manager v2 (`ModuleV2JobLogView`) and Server Maintenance (`ServerMaintenanceJobLogView`). Authentication, permissions, the manager check and the strict audit row are untouched and still run. Error bodies stay JSON with their status codes. This is Core, not the UI: the UI's header is right for a text answer. We could not run Django here, so the cause is confirmed from the code and settings, not from a live request. Checklist step 4 proves it on dev02. If it turns out not to be the cause, the mixin is harmless hardening.
* **`tectac_session_policy --ip-change` writes nothing when nothing changes.** If the policy already has that value, the command prints `ip_change_policy unchanged: <value>`, saves nothing and writes no `session_policy_changed` audit row. A different value works as in 1.18.2. `--show` still prints afterwards. The settings page and its audit rows are unchanged.

## Requests closed

The two entries under "From Johan's dev02 test of Core 1.18.3 (18 November 2026)" in `reviews/requests/core.md`: the lock still held at Finished, and the Accept-header error with the empty Versions row. The release manager removes them after signing.

## Module-facing

None. A grep of `modules/` for `tectac_session_policy`, `session_policy_changed`, `system-update-helper`, `lifecycle.lock`, `updates/jobs`, `module_job_logs` and `serve_log` found no user. The log routes and the helper are not in the public contract. No contract, capability or endpoint changed, so the export waiting from 1.18.2 stays valid.

## Correction to the 1.18.4 notes

The helper is installed at `/usr/local/lib/tec-tac-updater/system-update-helper.py`, not under the old `tec-tac-system-update` folder. The copy of the 1.18.4 notes in `docs/releases/` now has the right path. This checklist uses it too.

## What is not in this release

* The module job helpers (`module-job-helper.py`, `module-v2-job-helper.py`, `module-hotfix-job-helper.py`) keep their non-waiting lifecycle lock and are not changed. A module job started straight after another module job can still see "busy".
* The path unit for `--publish-ui-sync` is unchanged. The 10 s wait in `run_job` absorbs its short hold. We did not make the unit queue behind updates.
* Every other open request in `reviews/requests/core.md`.

## Checks run here

`tests/session-policy-unchanged-1.18.5.py`, `tests/session-policy-command-1.18.2.py` (edited: each pass now starts from a different value), `tests/system-update-lock-order-1.18.5.py`, `tests/log-accept-negotiation-1.18.5.py`, `tests/version-1.18.5.py`, `tests/lifecycle-lock-restore-1.18.4.py`, `python -m py_compile` on every changed file, `ruff check`, and `bash tests/release-integrity.sh`. `tests/backup-recovery-system-update-1.15.140.py` got a one-line edit (its lock stub now accepts `wait_seconds`). `tests/version-1.18.4.py` moved to `tests/legacy/`.

Could not run on this PC: Django and DRF content negotiation, real `flock` under systemd (the lock test uses a fake `fcntl`, and its real-flock part runs on Linux only), and tests that need `fcntl` or Django to import.

## Johan test checklist (dev02)

Update the server to Core 1.18.5 first.

1. As the Tactical user, run `manage.py tectac_session_policy --ip-change audit` twice.
   * PASS: the second run prints `ip_change_policy unchanged: audit`. Audit shows one `session_policy_changed` row, not two.
   * FAIL: a second row, or a `changed: audit -> audit` line. Send the output and the audit rows.
2. Run a Core System Update. The moment the page shows Finished, run `sudo flock -n /var/lib/tec-tac/lifecycle.lock true && echo FREE`, then start a UI reinstall straight away.
   * PASS: `FREE` appears at once and the reinstall starts.
   * FAIL: the lock is busy, or the job fails with "another Tec-Tac lifecycle operation is already running". Send `sudo journalctl -u 'tec-tac-system-update-*' --no-pager | tail -80` and the job log.
3. Hold the lock with `sudo flock -n /var/lib/tec-tac/lifecycle.lock sleep 60 &`, then start a System Update.
   * PASS: it fails after about 10 s with the busy message. The detail view shows `<installed> -> <target>`, and Started stays empty.
   * FAIL: the Versions row shows a dash for the installed version, or the job waits longer than about 15 s. Send a screenshot and the job log.
4. Open the log of that failed job, and of a finished job in Module Manager History.
   * PASS: you see the log text, or the plain answer that Core kept no log text.
   * FAIL: "Could not satisfy the request Accept header" appears. Send the browser network tab entry for `.../system/updates/jobs/<id>/log/`.
5. Optional: run `sudo python3 -I /usr/local/lib/tec-tac-updater/system-update-helper.py --publish-ui-sync` right after a UI update.
   * PASS: it publishes or prints the skip line. No error about the lock.
   * FAIL: a lock error or a traceback. Send the output.
