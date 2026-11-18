# Tec-Tac Framework 1.18.3

Date: 18 November 2026. This release closes the two held findings from the 1.18.2 review. Both concern the UI module sync script publish. It changes no contract.

## What changed and why

* **The automatic UI sync publish now takes the lifecycle lock.** The path unit added in 1.18.2 could fire while a System Update, a restore or a module job was renaming the same folders. Now `system-update-helper.py --publish-ui-sync` takes `/var/lib/tec-tac/lifecycle.lock` (the same non-blocking lock those jobs hold) before it stages, verifies or renames anything. When the lock is busy it prints one line to stdout, `[TEC-TAC] UI module sync script not published: a System Update, restore or module job is running; it publishes the script itself or the next UI install does`, and exits 0. The lock stays held until the process ends. Staging, verification and the failure path (one stderr line, exit 1) are unchanged. No sudoers line and no helper mode were added.
* **`install.sh` keeps the helper's output.** Before, it threw stdout away, so the "published" line and the skip reasons never reached the install log. Now stdout goes to the normal install output and only stderr feeds the warning text. A failed publish still never stops the install.

Why a skipped publish is safe: a UI System Update, a restore and the rollback path each call `publish_ui_sync_tools` themselves under their own lock after the UI installer returns. A later UI install fires the path unit again. A wait-and-retry loop was rejected, because it could hold a oneshot service and the installer open for a whole update.

Side effect: when `install.sh` runs inside a Core System Update (which holds the lock), its direct `--publish-ui-sync` call now skips with the skip line. Nothing is lost, because the script comes from the UI checkout, which a Core update does not change, and the previously published copy stays. A by-hand Core install with the lock free still publishes.

## Requests closed

* Held MEDIUM (1.18.2 review), `reviews/core/BACKLOG-new-findings.md`: the automatic UI sync publish ran without the lifecycle lock (closed in 1.18.3).
* Held LOW (1.18.2 review), `reviews/core/BACKLOG-new-findings.md`: `install.sh` discarded the helper's stdout (closed in 1.18.3).

The release manager moves both after signing.

## Module-facing

No module-facing change. A grep of `modules/` found no user of `--publish-ui-sync`, `UI_SYNC_SCRIPT`, `lifecycle.lock` or `system-update-helper`. No contract, capability or endpoint changed, so no new public contract export is needed. The export still waiting from 1.18.2 stays valid.

## What is not in this release

* A guard on the path unit itself (`ConditionPathExists` or a lock check). The in-helper lock covers the race without new unit-file behaviour.
* A second lock inside `publish_ui_sync_tools`, or locking the root config write. The lifecycle lock already excludes every other publisher.
* Request counts per route in System Diagnostics, a public operation returning a request's client IP, and further start-up import cuts.

## Checks run here

`bash tests/release-integrity.sh`, `tests/version-1.18.3.py`, `tests/ui-sync-auto-publish-1.18.3.py`, `python -m py_compile scripts/system-update-helper.py`, `ruff check` with the repo config and `bash -n install.sh`. Could not run on this PC: Django-dependent tests, `fcntl` behaviour (the lock-busy and lock-held runs in the test are skipped here with a printed note; the branch is checked statically), `systemd` behaviour (the path unit firing) and the Docker-only `tests/system-update-linux-staging-1.17.98.py`.

## Johan test checklist (beta server)

Update the server to Core 1.18.3 first.

1. Fresh or reset server: install Core, then install the UI from its signed package. Do not run Core `install.sh` again.
   * PASS: module screens load. `/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh` exists and is owned by root. `systemctl status tec-tac-ui-sync-publish.path` shows active. `journalctl -u tec-tac-ui-sync-publish.service` shows the published line.
   * FAIL: "Authenticated UI not reported" stays. Send the service journal and the output of `sudo python3 -I /usr/local/lib/tec-tac-updater/system-update-helper.py --publish-ui-sync`.
2. On a test box, make `/opt/tec-tac-src` group-writable, then install the UI.
   * PASS: one line, `[TEC-TAC] UI module sync script not published: ... not root-owned ...`, in the journal, and nothing is published.
   * FAIL: the script is published anyway, or there is no reason line. Send the journal.
3. Run `manage.py tectac_session_policy --show`, then `--ip-change audit`, then `--show`. Try `--ip-change bogus`.
   * PASS: the value changes to `audit`. The Session policy audit list shows one `session_policy_changed` row with the actor `server command (tectac_session_policy)`. `bogus` is refused.
   * FAIL: no audit row, the wrong actor, or the value unchanged. Send the command output.
4. Sign in with a correct password and a wrong backup code.
   * PASS: it takes about as long as before.
   * FAIL: it is noticeably faster or slower. Send both timings.
5. Hold the lock with `sudo flock -n /var/lib/tec-tac/lifecycle.lock sleep 60 &`, then run `sudo python3 -I /usr/local/lib/tec-tac-updater/system-update-helper.py --publish-ui-sync`.
   * PASS: one skip line on stdout, exit code 0 (`echo $?`), and no change to `/usr/local/lib/tec-tac-ui-sync`.
   * FAIL: it publishes, errors or waits. Send the output and `ls -l /usr/local/lib/tec-tac-ui-sync`.
6. Start a UI System Update and watch `journalctl -u tec-tac-ui-sync-publish.service` while it runs.
   * PASS: the update finishes OK and the UI sync script exists afterwards. The unit prints either the skip line or the published line, never an error.
   * FAIL: the update rolls back with a rename error. Send the update log and the journal.
7. Run Core `install.sh` by hand and read the install output.
   * PASS: the helper's line (`published root-owned at` or the skip reason) shows in the output.
   * FAIL: no UI sync line at all. Send the install output.
