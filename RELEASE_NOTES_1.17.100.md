# Tec-Tac Framework 1.17.100

Date: 2 November 2026. Core now has a secret store: a place where a module can keep a token or a private key, encrypted, readable only by that module. This release also closes the two held Lows from 1.17.99.

Closes: item C2 of `reviews/core/LICENSING-COMPATIBILITY-DIFF-2-11-2026.md` and the two held Lows from the 1.17.99 review. Built under AD-57 (Option A of `reviews/requests/SECRET-STORE-DESIGN-19-10-2026.md`, built as its section 6 describes), AD-56 (the Licensing module is the only Licensing Server client and will keep its secrets here) and rule clause 1.14. Requests closed in `reviews/requests/core.md`: the secret storage entries (general secret storage, rule 3.10; and the licensing 0.9.x identity key). C3 to C7 are not in this release.

## What changed and why

1. **`core.secrets` 1.0.0 (`tec_tac/secret_store.py`, new).** `put(name, value)`, `get(name)`, `delete(name)`, `configured(name)` and `list_names()`.
   * The owner is the module whose code makes the call. Core finds it from the call stack (`core.caller_identity`, AD-26). Nothing is passed in, so a module cannot name another module's secrets. Core, a library, a generated frame, a disabled module and a legacy module get 403 `caller_not_allowed` and one `deny` audit row.
   * A value is read by its owner only, in server-side code. No HTTP route, view, serializer or setting returns a value, for any role.
   * Every `put` (add or modify) and `delete` writes one strict audit row **before** the change, in the same transaction. The row names the owner, the name, the size, the value type and the key id. It never holds the value. If the row cannot be written, nothing changes (503 `audit_failed`).
   * A successful read writes no audit row, because a licence key is read on every download. The row keeps a read count and a last-read time. A failed update of those never fails the read.
2. **Storage (`TecTacSecret`, table `core_secret`, migration `0044_core_secret`).** AES-256-GCM through `cryptography`. A new random 96-bit nonce for every write. The owner id and the name are bound in as authenticated data, so a row copied to another owner or name does not decrypt. Each row stores the id of the master key that made it (`k1-` and 12 hex characters of a hash), ready for a later rotation. One new table, no existing table touched.
3. **The master key.** `/etc/tec-tac/secrets/master.key`: 32 random bytes, `root:tactical`, mode 0640, in a `root:tactical` 0750 folder.
   * `install.sh` creates it, and only `install.sh`. It never overwrites an existing key: an existing 32-byte file keeps its bytes and only gets its owner and mode put right. A link, a non-file or a wrong-size file stops the install with the path named, because a new key would make every stored secret unreadable. The key is never printed.
   * Core never creates, repairs or replaces it. A missing key, a link, a wrong size, a file not owned by root, a file group-writable or readable by others, an all-zero key or an unsafe folder is a loud fault: 503 `master_key_unavailable`, one error line with the reason (never a key byte), nothing read, written or audited, and no silent new key. The key is read on every call (32 bytes), so a swapped key is never served from a stale copy; rows of another key give 503 `secret_unreadable` and one `custom:decrypt-failed` audit row.
4. **The master key is not in a backup (design 6.5).** The routine server backup now excludes `/etc/tec-tac/secrets`, and a restore refuses a bundle that carries it. Without this the key would sit beside the encrypted rows in every backup. Keep one offline copy (see the checklist).
5. **Limits.** A name is `[a-z0-9][a-z0-9._-]{0,63}`. A value is text or bytes, 1 byte to 16 KiB. A module may keep 100 names.
6. **Held Low 1 (`module_repository.py`).** A 401 or 403 from a repository that is set up with credentials (a stored `auth_token`) is now reported as **credentials rejected**: cache key `credentials_rejected`, `sync.credentials_rejected`, `availability.state` `credentials_rejected` and the plain message "A module repository refused the credentials set up for it. Check them with the repository owner, then sync again. Nothing is offered from it until it accepts them." Nothing is offered or staged, and no download is made. A repository with no credentials (the public default) keeps the 1.17.99 behaviour: 401 and 403 mean retired. 404 and 410 are retired for both. A 1.17.98 cache is read from its error text as before, now with the repository's credentials considered. The credential is never returned.
7. **Held Low 2 (`scripts/system-update-helper.py`).** A rollback, or a restore that installs an older Core, runs that release's own `install.sh`. An installer older than 1.17.99 writes the config without `TEC_TAC_LICENSING_SERVER_URL`, which dropped an administrator's own address. Decision: **re-apply it.** The helper reads the line from the root-owned config just before it runs the installer. If the installer left the key out, the helper writes the line back exactly as it was, with the existing atomic root-owned writer, and says so in the job log (never the value). A key the installer kept is not touched. A config that is not root-owned, or a failure to write, never fails the rollback: the log says so and the troubleshooting text says how to set the line. A forward update is not touched (its installer is the new one).
8. **Text.** New `docs/secret-store.md`. Help and troubleshooting for every new message and reason in `docs/troubleshooting-diagnostics.md` and `docs/module-repositories.md` (footers last). Five contract rows and one rule line in the contract export. `RELEASE_NOTES_1.17.99.md` moved to `docs/releases/`.

## Module-facing changes

All additive. Checked in `modules/`: no module uses `tec_tac.secret_store`, `core.secrets` or the repository code that changed. Modules that wait on secret storage (licensing, halopsa, sentinelone, huntress, cybercns, cyberhoot, scoutdns, rustdesk, whatsapp_notifications, ai, alerts) may now adopt it.

* **New capability `core.secrets` 1.0.0** and the Python contract `tec_tac.secret_store` (`put`, `get`, `delete`, `configured`, `list_names`). Needs framework >=1.17.100. Feature-detect with `has_capability('core.secrets')`. Errors: `SecretStoreError` with `code` and `status_code` (`invalid_name`, `invalid_value`, `secret_limit` 400; `caller_not_allowed` 403; `master_key_unavailable`, `secret_unreadable`, `audit_failed` 503).
* **`GET /api/tfd/modules/catalog/online/`:** new `availability.state` value `credentials_rejected`, new `availability.credentials_rejected_repositories`, new `sync.credentials_rejected` on repository rows and `download_unavailable_state` on cached releases. Existing keys and values keep their meaning. A caller that does not know the new state sees an empty `modules[]` with a message, as for `repository_retired`.
* A fresh contract export is needed (`reviews/requests/core.md` pattern).

## Assumptions (recorded in `reviews/questions/core.md`)

* **Rotation is not built.** Section 6.3 describes a root command `tec-tac-secrets rotate`. The task and AD-57 name a single 32-byte key file, so this release stores a key id per row and stops there. The rotation command (and Option B, systemd credentials) is a later release.
* **Reads are counted, not audited** (design 6.4, the recommended option): a read count and last-read time, no row per read.
* **"Credentials" means a stored `auth_token`** on the repository record. Core 1.17.100 does not yet send that token on a request (nothing in 1.17.99 did either), so the state is for the day it does and for a hand-edited record. Say so to Johan if the Licensing grant work (C4) should decide otherwise.
* **Excluding the key from backups and refusing it on restore** was added because design 6.5 says so, although the task did not list it.
* **Rows of a removed module stay** until the administrator deletes them (design 6.1); there is no remove-flow hook yet.
* **No status route.** Design 6.1 allows one for a manager. Nothing in this release shows names in the browser, so there is no UI change and no `ui.md` request.
* The re-apply of the Licensing Server address happens for rollback and restore only; a forward update runs the new installer, which keeps the line.

## Tests

* New: `tests/secret-store-1.17.100.py`.
  * Store: round trip of text and bytes; no plain text in the stored row, any log line, any audit row or any exception; a fresh nonce per write; AAD binding (another owner, another name, a flipped bit); the caller check (another module sees nothing; Core, a library, a generated frame, a disabled and a legacy module and the test file are refused with one deny row and no read or write); a missing, short, long, empty, all-zero, group-writable, other-readable, wrong-owner, non-file, linked or folder-unsafe key fails closed and creates nothing; a swapped key and a wrong key id are `secret_unreadable`; audit first and fail closed; name and value limits; no route or view touches a value; the migration is one new table on top of the 1.17.99 leaf (0043), with fields equal to the model; the backup excludes the key and a restore refuses it.
  * `install.sh` under real bash with the privileged commands stubbed: fresh create (32 bytes, 0640, not printed), an existing key never overwritten, a wrong-size key, a link or a file in the folder's place stops with no change.
  * Held Low 1: credentialed 401 and 403, the public default unchanged, 404 and 410, 5xx and network faults, recovery, mixed repositories, a 1.17.98 cache, no credential in any answer.
  * Held Low 2: put back, kept when the installer kept it, no key before, last line wins, an untrusted config, a line break, and the order of the three call sites.
* Changed: `tests/repository-retired-1.17.99.py`, `tests/online-catalog-availability-1.17.41.py` and `tests/module-repository-skipped-1.17.39.py` read the new names from the source.

## Checks on the test server (Johan)

1. After the update, check the key file. **Expected:** the folder `root:tactical 750`, the file `root:tactical 640 32`.
   ```
   sudo ls -ld /etc/tec-tac/secrets
   sudo ls -l /etc/tec-tac/secrets/master.key
   sudo stat -c '%U:%G %a %s' /etc/tec-tac/secrets/master.key
   ```
   **FAIL:** a different owner, a mode other than 640, a size other than 32, or no file. Send the install log.
2. Save the key for yourself, offline (password manager). Do not paste it anywhere: `sudo base64 /etc/tec-tac/secrets/master.key`.
3. Run the installer again (a System Update to the same or a later release). **Expected:** the log says "Secret store master key: kept" and the `stat` line is unchanged. Compare the checksum before and after: `sudo sha256sum /etc/tec-tac/secrets/master.key`. **FAIL:** the checksum changed.
4. `cd /rmm/api/tacticalrmm && sudo -u tactical /rmm/api/env/bin/python manage.py migrate tec_tac --check` and `... manage.py makemigrations tec_tac --check --dry-run`. **Expected:** nothing to apply, no changes detected (migration 0044 and the model agree). **FAIL:** either one asks for a change. Send the output.
5. `... manage.py shell -c "from tec_tac.capabilities import capability_status; print(capability_status('core.secrets'))"`. **Expected:** available, version 1.0.0, five operations.
6. Take a server backup, then `sudo tar -tzf <the backup's tec-tac archive> | grep -c secrets`. **Expected:** `0`. **FAIL:** a path under `etc/tec-tac/secrets`.
7. Online catalogue, official repository, Sync. **Expected:** unchanged from 1.17.99 (the retired message if the server still refuses). A repository with credentials is not on this server, so the new state is not visible here.
8. After a rollback test, if you use a custom `TEC_TAC_LICENSING_SERVER_URL`: `sudo grep TEC_TAC_LICENSING_SERVER_URL /opt/tec-tac/etc/tec-tac.conf`. **Expected:** your value is still there, and the job log says "put back" when the older installer dropped it. **FAIL:** no line and no "could not be put back" message.
9. Optional, destructive (a test server only): move the key aside (`sudo mv /etc/tec-tac/secrets/master.key /root/master.key.bak`), call the store from a module, and expect `master_key_unavailable` with reason `missing` in the Core log and no new key file. Move it back afterwards.

## Not done here

* **Django is not installed on this PC.** The Django test runner, the real model and migration, `makemigrations --check`, the views, `manage.py` and a real `root:tactical` file did not run. The migration is hand-written and checked with `ast` against the model; the store ran against a fake table and a fake audit writer with the real `cryptography` and the real caller check. Root ownership was simulated by replacing the two `stat` calls. The symlink case runs only where the PC allows symlinks.
* **Nothing was run as root.** `install.sh` ran only its key block, under bash, with `chown` and `install` stubbed.
* Rotation, Option B, a status route, a remove-flow hook and the Licensing module's own migration of its keys are not built.
* C3 to C7 of the compatibility diff (catalogue provider, grant download, licensed route, signed bootstrap, status wiring) are not started.
