# Tec-Tac Framework 1.17.105

Date: 3 November 2026. A small fix-only release so beta servers can update from `dev` by 6 November 2026. A UI update no longer stops on old build files in the UI source folder. Servers without the Licensing module no longer get a failed sync every night. Four held Lows are closed.

Closes: "Held from 1.17.103" and "Held from 1.17.104" in `reviews/requests/core.md`, plus one updater fault found on dev02 on 3 November 2026.

## What changed and why

1. **The UI update skips its build folders (found on dev02).** A UI update stopped with "a root-owned file with more than one hard link" on a file in `/opt/tec-tac-src/ui/node_modules/@esbuild/...`. An old `npm install` run as root left it there. The step that hands the source checkout to the Tactical account no longer walks the UI checkout's top-level `node_modules` and `dist`. Both are Git-ignored build folders. Nothing runs from them and the update never copies them. They keep their owner and nothing removes them: the update already leaves ignored files alone, as `docs/system-update-signed-releases.md` says. A `node_modules` or `dist` deeper down is still walked. The Framework checkout is walked whole, as before.
2. **The hard-link refusal stays, with a clearer message.** A root-owned file with a second hard link anywhere else is still refused and never handed over. The message now names the top-level folder that holds it, for example: "Remove the top-level folder /opt/tec-tac-src/ui/public that holds it (Git restores tracked files on the next update), then update again." A file at the top level still says "Remove it". A path owned by a third account is still refused with the `chown` command.
3. **Daily sync without the Licensing module (held from 1.17.103).** On a server with no Licensing module, the licensed source (`tec-tac-licensing`) was the only enabled source and failed every night. Now the daily sync skips it, writes one info log line, and counts it as `licensing_skipped` in its audit row. Only a Licensing module that is not installed counts. One that is installed but disabled or unhealthy still fails the run, so you see it. If Core can't read the module state, nothing is skipped. The Sync action on the Repositories page is unchanged.
4. **No leftover `.key-group` file (held from 1.17.103).** If `chown` or `chmod` on the temporary key-group file failed, `install.sh` stopped and left `.key-group.XXXXXX` in `/etc/tec-tac/secrets`. Both commands now remove it before stopping, as `printf` and `mv` already did.
5. **Release-notes link: null, not stripped (held from 1.17.104).** A `release_notes` link with a query, a fragment or `;params` became the same link without them. It is now null, as the contract and `docs/module-updates.md` say.
6. **Each caller gets its own copy of the update list (held from 1.17.104).** `list_updates()` returned the cached list itself. A module that changed its `core.module_updates` result changed what the routes served for up to 30 seconds. Every caller now gets a deep copy.

## Module-facing changes

* **`core.module_updates` 1.0.0:** the result is now the caller's own copy. Same fields, same values. A grep of `modules/` found no caller that relies on changing it.
* **Repository index `release_notes`:** a link with a query, fragment or `;params` now gives `release_notes_url: null` instead of a shortened link. No module in `modules/` publishes a repository index.
* No contract, route or permission was added or removed.

## Assumptions (recorded in `reviews/questions/core.md`)

* **Only a missing Licensing module is skipped.** A disabled or unhealthy one is something to fix, so it still fails the run.
* **Only the UI checkout's build folders are skipped.** The UI's `.gitignore` ignores `node_modules` and `dist`. The Framework's doesn't, so its checkout is walked whole.

## Tests

* New: `tests/system-update-build-folders-1.17.105.py`. It runs the real hand-over walk against an in-memory checkout: the dev02 layout passes and nothing in `node_modules` or `dist` changes; a deeper `node_modules`, and the Framework checkout, are still walked; the hard-link refusal names the top-level folder; a third account is still refused.
* New: `tests/licensing-sync-skip-1.17.105.py`: no Licensing module (only source, and beside another source); disabled, unhealthy and unreadable states still fail; the Sync action is unchanged; a disabled source isn't counted.
* New: `tests/module-updates-held-lows-1.17.105.py`: null for `?a=1`, `#x` and `;p`; a changed contract result leaves the routes and the badge as they were; the `install.sh` clean-up.
* Changed: `tests/module-updates-1.17.104.py` expects null for a link with a query and fragment. `tests/licensing-repository-1.17.103.py` loads the new helper function.

## Checks on the test server (Johan)

1. On dev02, put back a root-owned, hard-linked file in the UI build folder: `sudo mkdir -p /opt/tec-tac-src/ui/node_modules/.probe && sudo touch /opt/tec-tac-src/ui/node_modules/.probe/a && sudo ln /opt/tec-tac-src/ui/node_modules/.probe/a /opt/tec-tac-src/ui/node_modules/.probe/b`. Update Core to 1.17.105, then run a UI update. **Expected:** the UI update passes the ownership step. **FAIL:** "more than one hard link" for a file under `node_modules`. Send the update log. Afterwards: `sudo rm -rf /opt/tec-tac-src/ui/node_modules/.probe`.
2. On a server without the Licensing module, wait for the 03:00 sync, or run it from the Scheduler page. **Expected:** the run succeeds; its audit row shows `licensing_skipped: 1`; the Celery log has one line "the Licensing module is not installed". **FAIL:** the run is marked failed. Send the run history row.
3. On dev02 (Licensing installed), run the same sync. **Expected:** as before: a licence state counts as attention, no `licensing_skipped`. **FAIL:** `licensing_skipped` appears while the Licensing module is installed.
4. Run the installer again (a Core update does this). **Expected:** `ls -a /etc/tec-tac/secrets` shows no `.key-group.*` file. **FAIL:** one is there.

## Not done here

* **Not run on this PC.** Django, Celery and Linux are not available here, and Docker is not running. `tests/system-update-linux-staging-1.17.98.py` (the real walk as root on Linux) skips here. The new updater test runs the real function against an in-memory file system instead.
* The build folders are not removed. That isn't documented behaviour, so they stay.

---
Tech Flow Dynamics · techxflow.co.za
