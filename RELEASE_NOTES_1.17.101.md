# Tec-Tac Framework 1.17.101

Date: 2 November 2026. A hardening patch for the secret store that shipped in 1.17.100. The Licensing module will read a secret on every download, so this release makes that read cheaper and the store harder to misuse. No contract call changes shape.

Closes: every item under "held from 1.17.100" in `reviews/requests/core.md`, and the four 1.17.100 Lows in `reviews/core/BACKLOG-new-findings.md`. Built under AD-57 and rule clause 1.14. The four Lows held from 1.17.98 and the UI additive asks are not in this release.

## What changed and why

1. **Cheaper caller check on `get()` (Medium).** `secret_store.get()` asked Core to re-read every module's enabled state on every call (`cache_seconds=0`). It now uses the same short snapshot as event jobs (`event_jobs_policy.ENABLED_CACHE_SECONDS`, 5 seconds). The cost: a module disabled a moment ago can still read for up to 5 seconds. `put`, `delete`, `configured` and `list_names` still read the state every time.
2. **Read counting can no longer hurt a caller (Medium).** The counter update is now `F("read_count") + 1` inside its own savepoint, and it runs at most once a minute per secret (only when `last_read_at` is older than 60 seconds). A lost race adds a count instead of losing one, a failure rolls back to its own savepoint and never poisons the caller's transaction, and a secret read on every download no longer contends on its row. `read_count` now counts the minutes in which a secret was read, not every read.
3. **No importable function takes an owner (Low, treated seriously).** The old `_put`, `_get`, `_delete`, `_configured` and `_list_names` took an owner and skipped the caller check, and any module could import them. They are gone. The five public functions now find the owner themselves and do their own table work. The helpers that remain (audit, encryption) take a small `_Scope` object made in one place, and none of them reads or writes a secret row. A test checks the source and the live signatures: no function takes an owner argument, and only the five public functions (and the read counter, which gets a row) touch the table. A module can still import a name that starts with an underscore. Isolation holds for modules that use the contract, and the docs now say so. A pipeline gate that rejects such imports is a separate request.
4. **Audit rows cannot flood (Low).** A `deny` row and a `custom:decrypt-failed` row are written at most once per owner, name and reason every 5 minutes in each Core process. The next row says how many were left out (`left_out_since_last_row`). The Core log line for an unreadable secret follows the same limit. The memory behind it is capped at 512 entries. When it is full and nothing has expired, further rows are left out, so a flood of names cannot make Core write more.
5. **A concurrent first `put` no longer raises a raw database error (Low).** The loser of two first writes of one name is retried once as a replace. A second collision gives a plain 409 `secret_conflict` ("Try again"). The 100-name limit stays a soft limit under a race (documented in the code and in `docs/secret-store.md`).
6. **Key file group and folder link (Low).** The key file must be in the `tactical` group. A file in another group, or a group Core cannot find, is `master_key_unavailable` with the new reason `wrong_group`. The key folder is now read with `lstat`, so a link in its place is `folder_unsafe`, as is anything that is not a folder.
7. **`install.sh` and `mv -n` (Low).** On coreutils 9.2 to 9.4, `mv -n` can exit non-zero when it skips a file, which would end the install under `set -e`. The status is now handled explicitly and logged. Then the installer checks that the key exists (and is no link) and that `stat` reports exactly `root:tactical 640 32`. Anything else stops the install and prints what it saw (never a key byte).
8. **Text.** `docs/secret-store.md`, `docs/troubleshooting-diagnostics.md` (footer last), the contract export text. `RELEASE_NOTES_1.17.100.md` moved to `docs/releases/`.

## Module-facing changes

Additive. Checked in `modules/`: no module imports `tec_tac.secret_store` or uses `core.secrets` yet, so nothing breaks. The Licensing module may start using the store.

* **New error code** `secret_conflict` (409) from `put()`. Handle it as "try again". Existing codes keep their meaning.
* **New master key reason** `wrong_group` under `master_key_unavailable` (503), and `folder_unsafe` now also covers a link.
* **`read_count`** is throttled (see 2). It is not exposed through any contract.
* **`deny` and `custom:decrypt-failed` audit rows** are rate limited (see 4). A module must not count them.
* **Removed:** the underscore helpers `_put`, `_get`, `_delete`, `_configured`, `_list_names`. They were never part of the contract, and `modules/` does not use them.
* A fresh contract export is needed (`reviews/requests/core.md` pattern).

## Assumptions (recorded in `reviews/questions/core.md`)

* **Short cache for `get()` only.** The task named `get`. A 5 second window for a disabled module is the same trade-off event jobs already makes.
* **Throttle is 60 seconds, so `read_count` is approximate.** Nothing reads it yet. If the Licensing module needs an exact count, it keeps its own.
* **The rate limit is per Core process.** Several workers can each write one row per interval. Sharing it through the database would add a write to a refused call, which is the thing we are trying to avoid.
* **Group name is `tactical`**, a constant (`KEY_GROUP`), matching the installer's `id -gn` of the Tactical user on a standard install. A server with a differently named group would see `wrong_group` and must name it in a request.
* **Core's own later use of the store (backup destinations)** needs its own caller rule. The owner-taking helpers it would have used are removed on purpose.
* **`mv -n` is kept** (it protects a key that appeared in the meantime) and its status is no longer trusted. The checks after it decide.

## Tests

* New: `tests/secret-store-hardening-1.17.101.py`. It reuses the fakes of `tests/secret-store-1.17.100.py` and covers each item: the cache argument of every operation; five reads in a minute make one `F()+1` update in its own savepoint, the next is due after 60 seconds, and a failing update neither fails the read nor leaves a committed or open transaction; no function takes an owner (by AST and by signature) and only the allowed functions touch the table; one row per owner, name and reason per interval, the left-out count, and a flood of names that cannot grow memory or the log; a collided first put retried once, a second collision as 409; a key in the wrong group, a group that cannot be found, a link or a file in the folder's place; `install.sh` under real bash with `mv` stubbed to exit 1 after moving, to fail without moving, and to do nothing; a wrong owner, mode or size after the move; docs, footer, notes and version.
* Changed: `tests/secret-store-1.17.100.py` follows the new seams (`_lstat`, the group lookup, `F()`), expects one deny row per name, one counted read a minute, and the install key check.
* Re-run: `tests/repository-retired-1.17.99.py`, `tests/secret-store-1.17.100.py`, `tests/release-integrity.sh`.

## Checks on the test server (Johan)

1. After the update, check the key file. **Expected:** the folder `root:tactical 750`, the file `root:tactical 640 32`, and a group of `tactical`.
   ```
   sudo ls -ld /etc/tec-tac/secrets
   sudo stat -c '%U:%G %a %s' /etc/tec-tac/secrets/master.key
   ```
   **FAIL:** any other owner, group, mode or size. Send the install log.
2. Run the installer again (a System Update to the same or a later release). **Expected:** the log says "Secret store master key: kept". `sudo sha256sum /etc/tec-tac/secrets/master.key` is the same before and after. **FAIL:** the checksum changed, or the installer stopped at the key block.
3. Fresh install only (a new test server): **Expected:** "Secret store master key: created", then the `stat` line above. A log line that says "mv -n reported a non-zero status" is fine if the key is created and verified. **FAIL:** the installer stops with "was not created" or "wrong owner, mode or size". Send the log.
4. `cd /rmm/api/tacticalrmm && sudo -u tactical /rmm/api/env/bin/python manage.py makemigrations tec_tac --check --dry-run`. **Expected:** no changes detected. This release adds no migration.
5. Capability still there: `... manage.py shell -c "from tec_tac.capabilities import capability_status; print(capability_status('core.secrets'))"`. **Expected:** available, version 1.0.0, five operations.
6. Key group check. On the test server only, set the group wrong: `sudo chgrp root /etc/tec-tac/secrets/master.key`. Call the store from a module that has a secret. **Expected:** `master_key_unavailable` with reason `wrong_group` in the Core log, nothing read. Put it back: `sudo chgrp tactical /etc/tec-tac/secrets/master.key`. **FAIL:** the secret is still returned with the wrong group.
7. Flood check. Open `manage.py shell` and call `secret_store.get('licence_key')` 20 times (the shell is not a module, so Core refuses each call). **Expected:** `caller_not_allowed` 20 times and exactly one `deny` audit row for that name in the next 5 minutes. **FAIL:** 20 rows.
8. Read statistics: a module reads a secret several times within a minute. **Expected:** `read_count` rises by 1 per minute at most. **FAIL:** it rises by 1 per read, or a read fails.

## Fixed after review

* **`install.sh` had Windows (CRLF) line endings on every line** and the pipeline's shell-syntax check refused it. It is back to LF, as at 1.17.100, and the diff against 1.17.100 shows only the real key-block change. `tests/secret-store-1.17.100.py` and these notes had been converted the same way and are LF again. Files that were CRLF at 1.17.100 (`secret_store.py`, `contracts.py`, the two docs) keep CRLF. The new test checks that `install.sh` has no carriage return.

## Not done here

* **Django is not installed on this PC.** The Django test runner, the real model and its `F()` expression, real savepoints, a real `IntegrityError` from PostgreSQL, `makemigrations --check` and a real `root:tactical` file did not run. The store ran against a fake table and a fake audit writer with the real `cryptography` and the real caller check. Root ownership and the group id were simulated.
* **Nothing was run as root.** `install.sh` ran only its key block, under bash, with `chown`, `install`, `mv` and the owner part of `stat` stubbed.
* Not in this release: a gate for module imports of underscore names in `tec_tac.secret_store` (pipeline), rotation, Option B, a status route, the four held Lows from 1.17.98, and the UI additive asks.
