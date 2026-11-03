# Tec-Tac Framework 1.17.107

Date: 3 November 2026. A fix-only release. Root runs no longer leave root-owned lock files in the System Update cache. This is the root cause of the stale branch head that 1.17.106 worked around. It also closes the two Lows held from 1.17.105.

Closes: the dev02 finding of 3 November 2026 (root-owned `github-refresh-*.lock` and `release-cache.lock`), and "Held from 1.17.105" (both Low items) in `reviews/requests/core.md`.

## What happened on dev02

* `/var/lib/tec-tac/system-updates/cache` is `root:tactical`, mode 2770 (setgid). That is correct.
* The lock files in it were `root:tactical`, mode 0640. The Tactical account could not open them for writing, so Core fell back to a 26-hour-old branch head.
* Two locks that were Tactical-owned at 16:18 were root-owned an hour later, after `sudo bash install.sh` of 1.17.106.

The cause is in `install.sh`. It ran `chown -R root:tactical` over the whole System Update folder, the cache included. Core creates its lock files as the Tactical account, and with umask 022 they get mode 0640. The recursive chown handed them to root with that mode, so the Tactical account lost write access to its own files. System Update runs the same installer as root, so every update did it again.

## What changed and why

1. **install.sh leaves the cache contents alone.** The owner change now uses `find -P ... -prune` and skips everything inside `cache/`. The cache folder itself still gets `root:tactical` 2770. `chown -h` changes a link itself and never follows it. Everything else in the System Update folder is handled exactly as before.
2. **install.sh repairs old locks.** It deletes any root-owned `*.lock` file directly in the cache folder and logs one line with the count. Core re-creates each lock as the Tactical account on its next check. Deleting a name never follows a link, so this is safe against a swapped name. `release-cache.json` is left as it is (`root:tactical` 0660 is fine, and the Tactical account replaces it by rename).
3. **A root run never creates a lock file.** In `system_update.py`, `_file_lock` checks whether it runs as root (for example a management command under `sudo`). As root it opens an existing lock read-only (`flock` needs no write access) and never creates one. With no lock file it holds nothing, and callers already fail closed: they use the saved answer and send no request. A root run no longer creates the cache folder either; `install.sh` owns it.
4. **No link is followed.** Every lock open now has `O_NOFOLLOW`. The Tactical account still creates its locks with mode 0660, and the 1.17.106 read-only fallback stays.
5. **Held Low: a broken registry is not "Licensing not installed".** `_licensing_sources_without_provider` reads the module registry first. A registry that fails validation raises, so nothing is skipped, a warning gives the reason, and the Licensing source fails the sync as before. Only a Licensing module that is really not installed is skipped quietly.
6. **Held Low: the UI build folders are owner-checked again.** The owner hand-over still does not enter the UI checkout's top-level `node_modules` and `dist`. It now checks the owner of those two folders themselves. Root or the Tactical account is allowed; a third account is refused with the `chown` command, as everywhere else.

We looked for other root paths into the cache. `scripts/system-update-helper.py` never opens the cache, and its Django checks run as the Tactical account through `runuser`. `migrate-layout.sh` and the housekeeping helper do not touch it.

## Module-facing changes

* None. No capability, contract, permission or route changed. A grep of `modules/` found no caller of the changed functions.

## Assumptions (recorded in `reviews/questions/core.md`)

* Root-owned lock files are deleted, not handed to the Tactical account. Deleting is safe against a swapped name. A `chown` plus `chmod` from a shell is not.
* A root run that finds no lock file does not refresh. It shows the saved answer, as any run without the lock does.
* A root-owned `node_modules` or `dist` is allowed, because an old root `npm install` leaves exactly that and nothing runs from them.

## Tests

* New: `tests/system-update-root-cache-locks-1.17.107.py`. It covers: root with no lock (nothing held, no `O_CREAT`, no file made); root with an existing lock (read-only, `O_NOFOLLOW`); the Tactical account (created 0660 with `O_NOFOLLOW`, and the read-only fallback); the `install.sh` text, order and LF endings, and the prune expression run with `find` against a real folder (cache contents left out); a registry validation error skipping nothing with a warning, and a real "not installed" still skipped; and `node_modules` and `dist` owned by a third account refused, root-owned allowed, contents never entered, a deeper folder still walked.
* Re-run and passing: `tests/licensing-sync-skip-1.17.105.py`, `tests/system-update-build-folders-1.17.105.py`, `tests/system-update-stale-head-1.17.106.py`, `tests/release-integrity.sh`.
* Not run here: `tests/system-update-linux-staging-1.17.98.py` (needs Linux as root) and anything that needs Django, which is not installed on this PC.

## Checks on the test server (Johan)

1. Before updating, run `sudo ls -l /var/lib/tec-tac/system-updates/cache/`. **Expected:** you note which `*.lock` files are owned by `root`.
2. Update Core to 1.17.107 with `sudo bash install.sh` or System Update. **Expected:** the install log has one line "Removed N root-owned System Update cache lock file(s)" when step 1 found any. **FAIL:** the install stops, or no line when step 1 showed root-owned locks. Send the install log.
3. Run `sudo ls -l /var/lib/tec-tac/system-updates/cache/` again. **Expected:** no `*.lock` file is owned by `root`. `release-cache.json` is unchanged. **FAIL:** a root-owned lock. Send the listing.
4. Open System Update and press Refresh. Run the listing again. **Expected:** the locks are back, owned by `tactical`. The `dev` row shows the live head with `head_stale: false`. **FAIL:** `head_stale: true` with `not_refreshed` after a Refresh. Send the HAR and the listing.
5. Run `sudo bash install.sh` a second time, then the listing. **Expected:** the `tactical` locks are still `tactical`-owned. **FAIL:** any lock turned `root`. Send the listing.
