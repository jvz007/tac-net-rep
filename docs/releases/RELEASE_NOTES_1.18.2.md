# Tec-Tac Framework 1.18.2

Date: 18 November 2026. This release fixes two install problems found on the beta server and closes one small held finding. It changes no contract.

## What changed and why

* **The UI module sync script is published after a UI install, with no second Core install.** Before, a fresh server needed Core's `install.sh` run a second time after the UI was installed, or "Authenticated UI not reported" stayed. Now `install.sh` also installs a root `systemd` path unit, `tec-tac-ui-sync-publish.path`, and a oneshot service, `tec-tac-ui-sync-publish.service`. The path unit watches the deployed UI `VERSION` file (`TEC_TAC_UI_DEPLOY_ROOT/VERSION`, default `/var/lib/tec-tac/ui/tec-tac/VERSION`). When the UI installer rewrites it, the service waits 5 seconds and runs `system-update-helper.py --publish-ui-sync` as root, from the root-owned updater copy. Nothing is loosened: the helper still stages the signed UI checkout, still checks the installed version from root-held state and still insists on root-owned parent folders. No sudoers line and no helper mode were added. The direct call in `install.sh` stays, so a Core install after a UI install still publishes.
* **A skipped publish now says why.** The helper prints exactly one line to stderr, `[TEC-TAC] UI module sync script not published: <reason>` (for example "... is not root-owned or is group/world writable"), and exits non-zero. `install.sh`'s warning now includes that reason and says a later UI install publishes the script automatically.
* **A new server command sets the session IP-change policy.** `python manage.py tectac_session_policy --show` prints the effective policy (`ip_change_policy` first). `--ip-change off|audit|reauthenticate|terminate` sets it through the same validated function as the settings page, so the same `session_policy_changed` audit row is written, with the actor `server command (tectac_session_policy)`. Open sessions follow the new policy on their next request. It adds no web route, no permission and no contract entry. It needs shell access on the server, the same trust as `manage.py shell`. Use it to recover when the setting signs everyone out. Documented in `docs/session-security.md`.
* **Held Low from the 1.18.1 review closed.** `burn_backup_code_hash_cost` returns before building the dummy hash when the budget is 0 or less. No caller passes 0 (the only partial caller guards `checks < BACKUP_CODE_COUNT`), so the hash budget on every failed sign-in path is unchanged.

## Requests closed

* `reviews/requests/core.md`: publish the UI sync script after the UI install (shipped in 1.18.2).
* `reviews/requests/core.md`: a server command to set the session IP-change policy (shipped in 1.18.2).
* Held Low, `reviews/core/BACKLOG-new-findings.md`: `burn_backup_code_hash_cost` builds a dummy hash when `checks <= 0` (closed in 1.18.2).

## Module-facing

No module-facing change. A grep of `modules/` found no user of `burn_backup_code_hash_cost`, `_update_global_policy`, `tectac_session_policy`, `--publish-ui-sync` or `UI_SYNC_SCRIPT`. No contract, capability or endpoint changed.

## What is not in this release

* Request counts per route in System Diagnostics.
* A public operation that returns a request's client IP.
* Further start-up import cuts (they wait for beta-server numbers, see 1.18.1).
* Any change to Tactical's uWSGI `max-requests`.
* The UI installer is not edited (UI area); the Core path unit replaces the need.
* The in-app Help entry for the new command (UI area, requested in `reviews/requests/ui.md`).
* `uninstall.sh` does not remove the new path and service units, the same as it removes none of Core's other timers today.

## Checks run here

`bash tests/release-integrity.sh`, `tests/version-1.18.2.py`, `tests/ui-sync-auto-publish-1.18.2.py`, `tests/session-policy-command-1.18.2.py`, `tests/mfa-backup-lazy-dummy-1.18.2.py`, `python -m py_compile` and `ruff check` on the changed files. Could not run on this PC: Django-dependent tests, `systemd` behaviour (the path unit firing), the helper's real `--publish-ui-sync` run (no `fcntl` on Windows, so its entry test checks the branch statically) and the Docker-only `tests/system-update-linux-staging-1.17.98.py`.

## Johan test checklist (beta server)

Update the server to Core 1.18.2 first.

1. Fresh or reset server: install Core, then install the UI from its signed package. Do not run Core `install.sh` again.
   * PASS: module screens load. `/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh` exists and is owned by root. `systemctl status tec-tac-ui-sync-publish.path` shows active. `journalctl -u tec-tac-ui-sync-publish.service` shows the published line.
   * FAIL: "Authenticated UI not reported" stays. Send the service journal and the output of `sudo python3 -I /usr/local/lib/tec-tac-updater/system-update-helper.py --publish-ui-sync`.
2. On a test box, make `/opt/tec-tac-src` group-writable, then install the UI.
   * PASS: one line, `[TEC-TAC] UI module sync script not published: ... not root-owned ...`, in the journal, and nothing is published.
   * FAIL: the script is published anyway, or there is no reason line. Send the journal.
3. Run `manage.py tectac_session_policy --show`, then `--ip-change audit`, then `--show`. Try `--ip-change bogus`.
   * PASS: the value changes to `audit`. The Session policy audit list in the UI shows one `session_policy_changed` row with the actor `server command (tectac_session_policy)`. `bogus` is refused.
   * FAIL: no audit row, the wrong actor, or the value unchanged. Send the command output.
4. Sign in with a correct password and a wrong backup code.
   * PASS: it takes about as long as before.
   * FAIL: it is noticeably faster or slower. Send both timings.
