# Tec-Tac Framework 1.18.54

Date: 26 November 2026. The tunnel server and the module tasks can now read the secret store master key. On dev02 the Engineer Console connect failed with `master_key_unavailable` because `daphne` (the websocket service) had no way to read the key. This release gives every Core service that can call the secret store the same access `rmm` already had. It is a Core-only change. `main` stays held.

## Module-facing change

None. No contract, capability, endpoint or import changes. Modules that use `core.secrets` (certificatemanagement, licensing, cyberhoot, ai) now also work in celery tasks. The diagnostics report gains one check id, `core.secret_store.service-access`. It is additive.

## Closes

- The request "core: ORDER Core 1.18.54, daphne cannot read the master key (tunnel connect fails with master_key_unavailable)" in `reviews/requests/core.md`, from Johan's dev02 finding of 26 November 2026. The journal showed `Core secret store cannot use its master key (unreadable)` in `uvicorn`. The key is `root:tactical` mode 640, and `rmm` had the Tactical group while `daphne` did not.

## What changed and why

1. **One drop-in for four services.** `install.sh` now writes `<service>.service.d/tec-tac.conf` for `rmm`, `daphne`, `celery` and `celerybeat`. Each file holds `[Service]` and `SupplementaryGroups=<tactical group>`, owned by root, mode 0644. A supplementary group is an extra group the system adds to a service on top of its main one. The units run with `Group=www-data`, which hides the Tactical account's own group. Nothing new is opened: the key file, its mode, its group and `key-group` are not touched, and nothing is granted to `www-data` or anyone else. The step is a small function, run once, with one `daemon-reload` and one log line per service. It rewrites the file each time, so a fresh install and an upgrade behave the same.
2. **A stronger post-install check.** After the restart the installer checks all four services. Each must list the group in `systemctl show -p SupplementaryGroups`, and its live process must carry the Tactical group id in `/proc/<pid>/status`. A failure names the service and says the key was not changed. The installer never reads the key.
3. **A diagnostics check.** `core.secret_store.service-access` (Runtime services section) compares each running service's group list with the key file's group number. It only stats the key file and never opens it. Per service the answer is `ok`, `missing_group`, `not_running` or `unknown`. A missing group is a fail that names the service and the fix. A stopped service is not a fail. A value it cannot read is `unknown`, never `pass`. It runs inside the existing "could not run" containment.
4. **Uninstall.** `uninstall.sh` removes the four drop-ins and reloads systemd, as it already did for `rmm`.
5. **Documents.** `docs/secret-store.md` and `docs/troubleshooting-diagnostics.md` explain the `unreadable` reason that shows in `uvicorn`, `daphne` or `celery` only, and list the new check.

## Assumptions

Johan's decisions are in `reviews/questions/core.md` as information. None blocks this release.

- **All four services get the group.** `daphne` (tunnel certificates) and `celery` (module tasks that read secrets) certainly need it. `celerybeat` only schedules but imports the same app. One rule is easy to check and explain. If Johan prefers only three, it is a one-word change in `KEY_GROUP_SERVICES`.
- **Johan's manual file is left alone.** `/etc/systemd/system/daphne.service.d/tec-tac-groups.conf` stays. The installer writes its own `tec-tac.conf`. Two identical `SupplementaryGroups=` lines are harmless because it is a list. Johan can delete the manual file after the upgrade test. `uninstall.sh` does not remove it.
- **The check lives in Core diagnostics, not in Welcome.** Welcome owns no Core check and reads the Core report. If it needs a tile, it asks in `reviews/requests/core.md`.

## New tests

- `tests/install-service-key-group-1.18.54.sh`: `bash -n`; the function run against a temporary folder with a fake `systemctl` and `chown`; all four drop-ins (content, mode, log line, one `daemon-reload`); idempotent second run; a stale file rewritten; the manual `tec-tac-groups.conf` byte for byte unchanged; the post-install check text for all four services in both tests; `uninstall.sh`; LF endings.
- `tests/diagnostics-secret-key-access-1.18.54.py`: pass, fail naming `daphne`, stopped service, nothing running (`unknown`), unreadable `/proc` or key stat (`unknown`), no key opening (a fake `open` raises), no key content in the answer, and a raising reader giving the "could not run" row.
- `tests/version-1.18.54.py`: version, notes, docs, line endings. `tests/version-1.18.53.py` moved to `tests/legacy/`.

## What could not be run here

Django, systemd, root and a real service restart are not available on this PC. The installer paths are proven by text and fake-`systemctl` tests only. `tests/module-management-foundation.sh` needs `fcntl` and does not run on Windows. It was not changed, and the literal `SupplementaryGroups=${TACTICAL_GROUP}` it greps for is still in `install.sh`. The dev02 checklist below carries the real proof.

## Johan dev02 checklist

**A. Fresh install.** Run the installer on a clean server. PASS: one "Installed <service>.service supplementary-group drop-in" line for each of rmm, daphne, celery, celerybeat, then four "Verified live ... runtime group" lines. FAIL: the installer stops and names a service. Send back: the installer tail and `systemctl show daphne celery celerybeat rmm -p SupplementaryGroups`.

**B. Upgrade, with and without your manual drop-in.** Run the installer on dev02 (keep `tec-tac-groups.conf`; remove nothing). PASS: both files exist for daphne, the service starts, and `grep Groups /proc/$(systemctl show -p MainPID --value daphne)/status` includes the tactical gid, and the same for celery, celerybeat and rmm. Then repeat on a server without the manual file. FAIL: any service lacks the gid. Send back: that `grep` line and the drop-in listing for the service.

**C. Engineer Console connect.** Connect from the Console. PASS: the connect passes `sign_server_proof` and reaches the tunnel. FAIL: `master_key_unavailable` in `journalctl -u uvicorn` or `-u daphne`. Send back: the journal lines.

**D. Diagnostics.** Open the diagnostics report. PASS: `core.secret_store.service-access` shows pass. Then `sudo rm` the daphne `tec-tac.conf` and the manual file, `sudo systemctl daemon-reload`, restart daphne. PASS: the check now fails and names `daphne.service`. Restore the files and restart. FAIL: it still passes, or it shows unknown while daphne runs. Send back: the check's details.

**E. Key unchanged.** Run `stat -c %U:%G %a %s /etc/tec-tac/secrets/master.key`. PASS: `root:tactical 640 32`. FAIL: anything else.

## Not in this release

The two held Lows of the 1.18.53 review (connect-refusal rows share the per-minute limiter; the revoke and CA-replace hooks end sessions synchronously) wait for the next patch. The uvicorn ping interval and `--ws-max-size` changes stay deferred as Johan set on 25 November 2026.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
