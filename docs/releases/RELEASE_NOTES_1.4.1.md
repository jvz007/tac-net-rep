# Tec-Tac Framework 1.4.1

Framework 1.4.1 is a corrective release for Module Management v2.

## Fixed

- Module state is now runtime-readable by all Tactical service identities while remaining writable only by privileged lifecycle code.
- `/var/lib/tec-tac/module-manager` is installed as traversable `0755` runtime configuration storage.
- `module-state.json` is created and maintained as root-owned `0644`.
- The v2 lifecycle worker no longer recreates module state as `0660` or assigns it to the Tactical service account.
- Prevents Daphne/ASGI startup failures caused by `PermissionError` while importing Tec-Tac from `local_settings.py`.

## Installer integration

- The Module Management v2 helper is now installed by the normal framework `install.sh`.
- Installs `/usr/local/sbin/tec-tac-module-v2-job` and its narrowly scoped sudoers rule.
- Creates and permissions the v2 runtime and bundle-backup directories during a normal framework install.
- Adds runtime readability checks for the module state file against the configured users of `rmm`, `daphne`, `celery`, and `celerybeat`.
- Service restart verification now tolerates the normal transition to active state before declaring an installation failure.

## Release cleanup

- Restores the normal framework repository README.
- Removes patch-only `apply.sh` and `install-v2-helper.sh` files accidentally included in the 1.4.0 repository update.
- Restores `tec_tac_package.json` to the normal `tec-tac-framework` package type.
- Adds the missing 1.4.0 release notes and this 1.4.1 release note.

## Validation target

After installation and after Module Management v2 enable/disable operations, all Tactical runtime services must remain active:

```text
rmm
 daphne
 celery
 celerybeat
```
