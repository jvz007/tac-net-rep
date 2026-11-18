# Tec-Tac Framework 1.18.7

Date: 18 November 2026. Core now keeps every server backup private. Before this release any local user on the server could read them.

## What changed and why

Each recovery bundle holds `local_settings.py`, a database dump, MeshCentral data and TLS keys. On dev02 the bundles were `644` (readable by everyone) in a `755` folder. Johan's check, `sudo -u nobody find /rmmbackups -type f -readable`, listed all of them. This is a High security finding, so it is fixed first.

* **Every recovery file is `0600`.** That covers the bundle (`tec-tac-backup-*.tgz`), its `.tectac.json` sidecar, its `.sha256` hash, and Tactical's native `rmm-backup-*.tar`. Core writes them under a private umask (a default that strips group and other access), copies with `0600` from the first byte (the old `shutil.copy2` copied the source mode), and reads the mode back after publishing. The archive keeps its modification time, so listing and retention still sort correctly.
* **Only root reads a bundle.** We checked every reader: the list, sidecar, download, store and retention paths, the scp, rclone and ftp uploads, and the restore all run in the root helper. The web code (Tactical user) never opens a bundle. So `0600` is enough and no group reader was added.
* **`/rmmbackups` is `0700`, owned by the Tactical user and group.** Tactical's own `backup.sh` writes and rotates `rmm-backup-*.tar` there as the Tactical user, so the folder must stay writable by that user. Root reads everything. A folder Core creates itself for a local destination is `0700`.
* **Repair on install and on every backup run.** New root-only helper argument `--repair-backup-permissions` runs once at the end of the helper install in `install.sh`. A failure logs a WARNING and does not stop the install. The same repair runs at the start of each backup after the lock is taken and logs one line, for example `[TEC-TAC-BACKUP] backup permissions: /rmmbackups 0700 tactical, 3 file(s) set to 0600, 11 already private`. It follows no symlinks and ignores unrelated files.
* **Folders Core does not own keep their mode.** `/backup`, `/backups`, `/mnt`, `/media`, `/srv` and an operator's NAS mount get their Core-named files set to `0600`. The folder is left alone, and Core logs one NOTICE when it is readable by every user.
* **A filesystem without Unix modes does not fail the backup.** On some CIFS or vfat mounts the mode will not stick. Core logs one WARNING and the destination result carries `mode_private: false`.
* The backup format, manifest, checksums, sidecar fields and restore flow are not touched.
* **Housekeeping.** `RELEASE_NOTES_1.18.6.md` moved to `docs/releases/`. `tests/version-1.18.6.py` moved to `tests/legacy/` (`ROOT` now `parents[2]`). `tests/legacy/version-1.18.5.py` `ROOT` fixed the same way (the Low from the 1.18.6 review; test-only). `tests/client-address-1.18.6.py` points at the moved paths.

## Fixed after review

Round 1 blocked 1.18.7 on one High finding. Nothing else in the release changed.

* **Root no longer follows a planted link when it writes the hash file.** `/rmmbackups` is writable by the Tactical user. Store wrote `<bundle>.sha256.partial` with `write_text` and then `os.chmod` by path, so a symlink planted at that name made root overwrite and chmod any file. The hash file is now created through a new `_private_write_text`: `O_CREAT|O_EXCL|O_NOFOLLOW` at `0600`, written and `fchmod`ed on the open file, never by path. A planted link makes the store refuse and the target stays untouched.
* **Sibling fixed in the same commit.** `_private_copy` set the modification time by path after closing the file. It now sets it on the open file (`os.utime(fd)`), so a swapped link cannot redirect it. The sidecar already used `atomic_json` (temp file made in the folder, then rename), and the archive copy already used `O_EXCL|O_NOFOLLOW`.
* **Test.** `tests/server-backup-bundle-modes-1.18.7.py` now checks that `_store_local` has no `write_text` or `os.chmod` on a path, and (Linux) plants `<bundle>.sha256.partial` as a symlink to a sentinel file and asserts the store refuses and the sentinel's contents and mode are unchanged.
* Not done: publishing into a root-owned subfolder (the reviewer's defence in depth). It changes the backup layout that Tactical's `backup.sh`, listing and restore rely on, so it needs its own release.

## Requests closed

"core: server backups are world-readable (HIGH, security first)" in `reviews/requests/core.md`. The release manager removes it after signing, naming 1.18.7. It ends when Johan's re-run of the `find` command prints nothing (checklist step 2).

## Module-facing

No contract, capability, route or import changes. `core.server_backup` keeps its version and its results; the destination result gains one extra field, `mode_private`, which no module has to read. On-disk modes change.

* **Backups module:** reaches bundles only through `core.server_backup`, which runs the root helper. No change needed.
* **Tactical Updater:** runs `backup.sh` as the Tactical user, then reads `/rmmbackups` as root. Both still work with a `0700` tactical-owned folder. No change needed.
* A grep of `modules/` for `rmmbackups`, `rmm-backup`, `tec-tac-backup`, `server_backup` and `.tectac.json` found no other reader.
* **For people:** the Tactical user can no longer read Core bundles. A manual `tar -xzf` of a bundle now needs `sudo`.

## Assumptions (also in `reviews/questions/core.md`)

* `/rmmbackups` is `0700 tactical:tactical`, not `0750 root:tactical`. The second would stop Tactical's own `backup.sh` writing and rotating there.
* Roots Core does not own get files-only repair plus a NOTICE. Forcing those folders to `0700` could break other software on the path; it is a one-line follow-up if you want it.
* A filesystem that cannot hold modes warns and records `mode_private: false` instead of failing the backup. Failing offsite backups on such a mount would be a new outage.

## What is not in this release

* Core-category modules cannot be disabled or uninstalled: still open in `reviews/requests/core.md`.
* Sandbox patches and every other open request.
* A nightly timer to re-tighten Tactical's own cron backups. Tactical's `backup.sh --auto` recreates `rmm-backup-*.tar` as `0644` each night. The `0700` folder still blocks other users, and Core tightens the file at the next install or backup run.

## What could not be run on the PC

Django is not installed, and the helper imports `pwd`, `grp` and `fcntl`, so the behaviour half of `tests/server-backup-bundle-modes-1.18.7.py` (real modes, repair, a second user failing to read) did not run here. The static half did. The pipeline validator and the checklist below cover the rest.

## Johan test checklist (dev02)

1. Update dev02 to Core 1.18.7. **PASS:** the install log shows a `backup permissions:` line. **FAIL:** no such line, or a WARNING about permission repair. Send the install log tail.
2. Without running a backup, run `sudo -u nobody find /rmmbackups /backup /backups -maxdepth 2 -type f -readable 2>/dev/null`. **PASS:** it prints nothing. **FAIL:** it prints any path. Send the list, `ls -ld /rmmbackups`, and `ls -l` of that path. (`2>/dev/null` hides the Permission denied lines the `0700` folder causes.)
3. Run `ls -ld /rmmbackups`. **PASS:** `drwx------ ... tactical tactical`. **FAIL:** anything else. Send the line.
4. Start a full backup from the Backups page to the default local destination. **PASS:** the job succeeds, the job log has one `backup permissions` line, and the new `tec-tac-backup-*.tgz`, `.tectac.json` and `.sha256` are `-rw------- root`. **FAIL:** the job fails or any mode differs. Send the job log and `ls -l /rmmbackups`.
5. Open the Backups page. **PASS:** the new bundle is listed with size and class, and Validate restore (not restore) passes. **FAIL:** the bundle is missing or its sidecar status is not ok. Send the list row.
6. Run Tactical's own backup as the Tactical user (`/rmm/backup.sh`), then repeat step 2. **PASS:** still nothing. **FAIL:** any path. Send the output.
7. Repeat step 2 as a normal local user (`find ... -readable 2>/dev/null` without `sudo -u nobody`). **PASS:** nothing. **FAIL:** any path. Send the list.
