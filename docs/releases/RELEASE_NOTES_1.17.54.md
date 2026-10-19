# Tec-Tac Framework 1.17.54

Backups can now start a backup job without waiting for it. Retention no longer fails on manual archives. Core can report free space and Tactical's own backup schedule. A failed destination check now says which step failed.

This is the smallest build that covers the four Backups requests. Every earlier operation, argument and response field stays. `core.server_backup` moves from 1.9.0 to 1.10.0. Backups pins `>=1.6.0,<2.0.0`, so it still resolves.

## What is new

- **Non-waiting operations (Backups R1).** Five new provider operations: `start_create_backup`, `start_validate_restore`, `start_validate_destination`, `start_list_backups` and `start_restore_backup`. Each takes exactly the arguments of its waiting twin, runs the same checks, and returns `{job_id, status: "queued", action}` at once. `action` is the helper action (`start_create_backup` reports `create_backup`).
- **Retention and manual archives (Backups R2).** A `manual` archive now counts as `unclassified` in `apply_retention`. Before, the helper raised `KeyError: 'manual'` and the whole retention job failed. Result rows record `backup_class: "unclassified"` for these archives.
- **Free space and Tactical's cron entry (Backups R3).** New operation `get_status`. It returns free and total bytes for each local destination, and the lines of the Tactical user's crontab that run `backup.sh --auto`. It is read-only. `health()` is not touched: it runs on every capability listing, and it must stay fast.
- **Which step failed (Backups R5).** `validate_destination` keeps every field and every short reason text. It also returns `stage`, `protocol`, `host`, `port`, `reason_code` and `detail`.

## Module-facing change (core.server_backup 1.10.0)

All additive. Read the new keys with `.get`.

- **Operations.** The registered list gains the five `start_` names and `get_status`. The nine earlier names stay. `metadata.dangerous_operations` becomes `["restore_backup", "start_restore_backup"]`. Nothing in Core or in `modules/` reads that list today.
- **Result rule for `get_job_status`.** A job started by a `start_` operation carries `"nonwaiting": true` in its job file. For such a job, `get_job_status` returns a `result` key: the same content the waiting twin returns, with every string value passed through the log scrubber. It is present for failed jobs too, so a module can read a failed validation. Jobs started by the waiting operations carry no flag, and their `get_job_status` output is byte-identical to 1.17.53. The three registered actions keep returning `result` exactly as before.
- **`start_restore_backup` adds no authority.** The calling module makes the same checks it makes before `restore_backup` (role-based access and the signed install). The browser job route used by Backup & Restore stays limited to its three actions, so `start_` jobs are not readable through it.
- **`get_status(destinations=None, context)`.** Rows `{id, path, available, free_bytes, total_bytes}` for `local` destinations only. The path goes through the existing allow-list. A folder that does not exist yet is measured through its nearest existing parent, and nothing is created. `tactical_backup_schedule` is `{checked, present, entries: [{schedule, command}], writes_to: ["/rmmbackups/daily", "/rmmbackups/weekly", "/rmmbackups/monthly"]}`. Only the Tactical user's crontab is read. Root's crontab and `/etc/cron.d` are not. If `crontab` is missing or fails, `checked` is false, `present` is null and `reason` says why. A user with no crontab at all gives `checked: true, present: false`.
- **`validate_destination` stage.** `stage` is one of `name_resolution`, `tcp_connect`, `tls_handshake`, `certificate`, `login`, `data_connection`, `path_access`, `write`, `read`, `delete`, `configuration`, `integrity`, `unknown`, or `complete` on success (`reason_code` `ok`). `configuration` and `integrity` are not in the request's list: two existing checks need them. FTP gets full detail. scp, sftp, s3 and webdav are a best guess from the client's message, and `unknown` where Core cannot tell. `detail` is the library or client message, scrubbed in the helper (the destination's own secret values and the usual patterns) and again in Core, capped at 500 characters.
- **Contract export.** The row for `core.server_backup` shows version 1.10.0, the new operations and the new metadata. The export is generated on the dev server from the registration, so it follows once the signed build is installed.

## What does not change

- The waiting operations (`create_backup`, `list_backups`, `restore_backup`, `validate_destination`, `validate_restore`) still go through the same request and return what they returned. Their argument checks and error texts are the same.
- The eight check names, their values and the short reason texts (`connection failed`, `authentication failed` and the rest).
- `get_job_status` for any job without the flag: the same keys, and no `result` for an action that is not one of the three registered ones.
- `health()`, `store_secret`, `delete_secret`, `apply_retention` for daily, weekly, monthly and unclassified archives, and the browser Backup & Restore views.
- A legacy retention policy with no `keep_unclassified` still keeps 10000, so it never deletes a manual archive.
- The `ftp_connect` helper takes an optional `progress` argument. Without it, the backup upload path runs exactly as before.

## Retention side effect

A policy that sets a small `keep_unclassified` can now delete old manual archives. Retention used to refuse to touch them because it crashed first. This is what Backups R2 asks for (manual counts as unclassified). A policy with no `keep_unclassified` is unaffected.

## Helper rollout

The root helper `/usr/local/sbin/tec-tac-server-backup` is installed by Core's installer. The five `start_` operations use only helper actions that already exist, so they work even with the old helper. R2, R3 and R5 are helper changes. With the old helper:

- retention still fails on manual archives,
- `get_status` is refused as an invalid job, and Core raises a clean `ServerBackupError` (dispatch failed). Nothing else breaks,
- `validate_destination` lacks the new keys.

Backups must read the new keys with `.get`.

## Backups R4 is not in the tree

`reviews/requests/core.md` and `modules/backups/PLAN_0.7.0.md` list R1, R2, R3, then R5. There is no R4. It was not invented. Question written to `reviews/questions/core.md`.

## Tests

- New `tests/server-backup-nonwaiting-1.17.54.py`: each `start_` method returns at once and never reads the job file or sleeps; its request equals what the waiting twin sends; bad arguments raise the same error text; the flag appears only on `start_` jobs; `get_job_status` scrubs a marker secret for succeeded and failed jobs. The same file holds the compatibility proof: waiting operations unchanged, the old key set for unflagged jobs, the three registered actions unscrubbed as before, the nine original names present, the range `>=1.6.0,<2.0.0` resolving, `health()` keeping its shape, and `get_status` sent with the validated destinations.
- New `tests/server-backup-retention-manual-1.17.54.py`: fails on 1.17.53 with `KeyError: 'manual'`, passes now.
- New `tests/server-backup-status-1.17.54.py`: faked disk usage, parent fallback with nothing created, non-local destinations skipped, allow-list refusal, crontab present, absent, missing or failing, `crontab` called with a list and no shell, no marker secret in the result.
- New `tests/server-backup-validate-stage-1.17.54.py`: a stubbed FTP library fails at each step and the right stage and code come back; scp and rclone samples; success gives `complete`/`ok`; check names and short reasons unchanged; a marker secret in the password, an exception message and a banner never appears in the result or the log.
- Pinned `1.9.0` became `1.10.0` in `tests/d3-ad3-closure-1.15.189.py`, `tests/server-backup-capability-compat-1.15.189-1.py` and `tests/server-backup-foundation.sh`. The FTP stub in `tests/server-backup-foundation.sh` accepts the new optional `progress` argument.
- `RELEASE_NOTES_1.17.53.md` moved to `docs/releases/`, because the release-integrity check allows one root note.

## What ran here, and what could not

- Django is not installed on this PC, and Core's modules import `fcntl`, so they do not import on plain Windows. Every test above ran in WSL Ubuntu (python3 3.12.3 with `cryptography`). The real root-helper path (a real validate job, a real crontab read) can only be tested on the dev server.
- `python -m py_compile` on both changed Python files, and `ruff check` with the pipeline's gate rules (`E9,F63,F7,F82`) on `framwork`, `scripts` and the server-backup tests: clean. The repository has no ruff config of its own. A wider rule set shows older findings in the helper that this release does not touch.
- The earlier server-backup, backup, recovery and D2/D3 tests ran in WSL and pass. `server-backup-root-layout.py` and `server-backup-transport-security.py` need a path argument without spaces, so they ran through a symlink.

## Dev-server checklist (Johan)

Install the signed 1.17.54 build first. Then:

1. **Capability.** In the Django shell, `get_capability("core.server_backup", version=">=1.6.0,<2.0.0")`. Expected: version 1.10.0. FAIL: any other version or an import error. Send back the error.
2. **Backups page.** Open Backups in the browser and list the registered destinations. Expected: the same as before the install. FAIL: an empty list or an error. Send back the page text.
3. **Retention on a manual archive.** Make a manual backup, then run retention with `keep_unclassified` set high. Expected: the job succeeds and nothing is deleted. FAIL: the job fails with `KeyError`. Send back the job id.
4. **Status.** Call `get_status(destinations=[<a local destination>])`. Expected: free and total bytes, and `tactical_backup_schedule.checked` true. FAIL: a dispatch error (the helper was not updated) or `checked` false with a reason. Send back the whole answer.
5. **Validate a destination that cannot work** (a wrong FTP host or port). Expected: `ok` false, `reason` `connection failed`, plus a `stage`. FAIL: `stage` missing, or a password anywhere in the answer. Send back the answer with the password blanked.
6. **Non-waiting.** `start_list_backups(destinations=[...])` returns at once. Then `get_job_status(job_id=...)` shows a `result` when it finishes. FAIL: the call waits, or no `result`. Send back the job id.

## Requests closed or answered

- Closed: Backups R1 (non-waiting operations), R2 (retention and manual), R3 (free space and cron read) and R5 (stage on `validate_destination`), all from Backups 0.7.0.
- Left out on purpose: everything else in Release A of the plan, to keep this build small. Those items wait for later releases.
