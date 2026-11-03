# Tec-Tac Framework 1.17.102

Date: 3 November 2026. A small patch for the secret store. Servers whose Tactical group is not called `tactical` now install and work, and one flood of refused calls can no longer hide a decrypt failure.

Closes: the two items under "held from 1.17.101" in `reviews/requests/core.md`.

## What changed and why

1. **One source for the key group (Medium).** Core assumed the group `tactical`. The installer uses the real group of the Tactical service user. On a server with another group name, the install passed and every secret call failed with `wrong_group`. Now `install.sh` writes the group it gave the key to `/etc/tec-tac/secrets/key-group` (root-owned, mode 0640, replaced atomically on every install). Core reads that record and checks the key file against it. The record must be a regular file (no link), owned by root, not writable by group or others, and hold one plain group name that exists. Anything else fails closed as `master_key_unavailable` with reason `wrong_group`. The hard-coded `KEY_GROUP` is gone.
2. **Separate cap per audit row type (Low).** Deny rows and decrypt-failed rows shared one 512-entry table. A flood of refused calls from unverified callers could fill it and silence decrypt-failed rows. Each row type now has its own 512-entry cap.
3. **Text.** `docs/secret-store.md` and `docs/troubleshooting-diagnostics.md` (footer last). The 1.17.101 notes moved to `docs/releases/`.

## Module-facing changes

None. No contract, endpoint or error code changes. `wrong_group` now means "not the recorded group". `modules/` does not use the secret store.

## Assumptions (recorded in `reviews/questions/core.md`)

* **A record file, not the Tactical user's name in `tec-tac.conf`.** Resolving the user in Core would need a second lookup that could drift from the installer. The record holds exactly what the installer used.
* **No fallback to `tactical`.** A server upgraded from 1.17.101 gets the record when the installer runs. Until then secret calls fail closed with `wrong_group`. No module uses the store yet.

## Tests

* New: `tests/secret-store-group-1.17.102.py`. A `tactical` and a non-`tactical` group pass and fail correctly; a missing, empty, unknown, malformed, over-long, non-root or group-writable record is `wrong_group`; deny and decrypt-failed rows are capped separately and still expire; `install.sh` has no CR and records the group; docs, footer, notes, version.
* Changed: `tests/secret-store-hardening-1.17.101.py` final version and notes checks follow the new release.
* Re-run: `tests/secret-store-1.17.100.py`, `tests/secret-store-hardening-1.17.101.py`, `tests/release-integrity.sh`.

## Checks on the test server (Johan)

1. After the update: `sudo stat -c '%U:%G %a' /etc/tec-tac/secrets/key-group` and `sudo cat /etc/tec-tac/secrets/key-group`. **Expected:** `root:tactical 640` (the Tactical user's group) and the group name. **FAIL:** missing, or another owner or mode. Send the install log.
2. `sudo stat -c '%G' /etc/tec-tac/secrets/master.key`. **Expected:** the same name as in `key-group`. **FAIL:** a different name.
3. Run the installer again. **Expected:** "Secret store key group: recorded" and "master key: kept". **FAIL:** the installer stops at the key block.
4. On the test server only: `sudo chgrp root /etc/tec-tac/secrets/master.key`, then call the store from a module that has a secret. **Expected:** `wrong_group` in the Core log, nothing read. Put it back with `sudo chgrp <group in key-group> ...`. **FAIL:** the secret is returned.
5. `manage.py makemigrations tec_tac --check --dry-run`. **Expected:** no changes (no migration).

## Not done here

* No pipeline gate against importing underscore names (separate request).
* No test on a real Linux server with a non-`tactical` group: this PC has neither Django nor `grp`. The lookup is tested with a stand-in.

---
Tech Flow Dynamics · techxflow.co.za
