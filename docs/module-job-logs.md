# Module job history, full logs and retention

Core 1.17.60. Three additions to the Module Manager's job records. Nothing that existed changes.

- **History list.** `GET /api/tfd/modules/v2/jobs/history/` lists module jobs and hotfix jobs. No row carries log text.
- **Full log.** `GET /api/tfd/modules/v2/jobs/<uuid:job_id>/log/` returns one job's whole log as plain text, scrubbed and capped.
- **Retention.** Finished job records are removed after 180 days. Their logs follow at the next module job.

Why: the Module Manager page showed only the last 40 log lines of a job, which is rarely enough to see why an install failed (Johan, 20 October 2026).

## Who may read

The same check as every other module-management route: `core.privileged_operations`. There is no new permission. Anyone else gets a 403 and no log is read. A 403 writes no audit row.

## History list

`GET /api/tfd/modules/v2/jobs/history/`

| Query | Meaning |
|---|---|
| `page` | Whole number, 1 or more. Anything else is a 400. |
| `page_size` | Whole number, 1 to 100, default 50. A larger value is cut to 100. Anything else is a 400. |
| `module` | Exact module id. Matches any module the job names, so a batch matches each of its modules. |
| `action` | For example `install`, `enable`, `disable`, `remove`, `visibility`, `apply`, `rollback`. |
| `status` | For example `failed`, `succeeded`. |
| `kind` | `module` or `hotfix`. |

The answer has the same envelope as `GET /api/tfd/modules/v2/jobs/`: `jobs`, `count`, `total`, `page`, `page_size`, `pages`, `next_page`, `previous_page`. Rows are newest first by `created_at`, ties by id.

Each row is built from a fixed list of fields. Nothing else can reach it.

| Field | Meaning |
|---|---|
| `id`, `kind` | The job id and `module` or `hotfix`. |
| `action` | As stored. A rename is an install or replace whose plan action is `rename`, so look at `renamed_from`. |
| `switch` | `true` for a replacement switch: an enable or disable that moved other modules, or the system's replacement-conflict disable. |
| `renamed_from` | The old module id, or `null`. |
| `module_ids` | The modules the job names. `batch` is not a module and is not listed. |
| `versions` | `{module id: version}`, or `null` when the job carries none (the plain single-package install). |
| `requested_by`, `created_at`, `started_at`, `finished_at`, `status`, `stage` | As stored, trimmed to printable text. |
| `error` | One short plain sentence: first line only, printable ASCII, scrubbed, file paths replaced, at most 200 characters. `null` when none. |
| `has_log`, `log_bytes` | Whether a regular log file exists, and its size. A symlink counts as no log. The UI can warn before opening a very large log. |
| `disabled_modules`, `enabled_modules`, `reconciled_modules`, `hand_back_skipped` | Lists of module ids, empty when the job moved none. |

A row never carries `log_tail`, a path, a package path or hash, or publisher trust. A record that cannot be read, or is not a JSON object, is skipped.

The older `GET /api/tfd/modules/v2/jobs/` keeps its exact answer, including `log_tail` on every row. Use the history route for new screens.

## Full log

`GET /api/tfd/modules/v2/jobs/<uuid:job_id>/log/`

- The job id is looked up as a module job, then as a hotfix job. An unknown id is a 404 ("That module job was not found."). A job with no log file is a 404 ("No log was kept for this job.").
- The default answer is inline text for a window. `?download=1` sends the same text as a file named `module-job-<module>-<action>-<YYYY-MM-DD>.log`. The module and action parts keep only `a-z`, `0-9` and `-`, cut to 40 characters.
- Headers: `Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.
- `X-Tec-Tac-Log-Truncated`: `true` or `false`.
- `X-Tec-Tac-Log-Bytes`: the size of the log file on disk, before any cut.
- `X-Tec-Tac-Log-Kept`: `all` or `head-and-tail`.
- Show the text as text. Never put it in the page as HTML.

### The 5 MB cap

A log up to 5 MB comes back whole. A larger one comes back as its first 2.5 MB and its last 2.5 MB, each cut at a line boundary, with one line between them:

```
[... N bytes were left out of the middle of this log ...]
```

Core never reads the whole file: it seeks to the two parts on the open file. The headers and the marker both say the log was cut.

### How the file is opened

Only `<logs folder>/<canonical lowercase uuid>.log` ever reaches a path. The id is checked, parsed and rebuilt first. The folder must be a plain directory, not a symlink. The file is opened without following symlinks and must be a regular file (a directory, a FIFO or a symlink is refused as "no log was kept"). No name from the caller is used as a path.

### What gets scrubbed

Scrubbing is pattern-based, runs after the cap and on each part separately, and replaces a value with `<redacted>`:

- Private-key blocks, whole, from the `BEGIN` line to the `END` line. A block cut by the 5 MB cap is redacted to the end of the head, and the tail is redacted up to its first `END` line.
- `Authorization`, `Proxy-Authorization`, `X-API-KEY`, `X-Auth-Token` and cookie headers.
- `Bearer`, `Basic` and `Token` values. Knox tokens are 64 hex characters.
- The user and password in a URL (`user:pass@`).
- `key=value` and `key: value` for password, passwd, pass, secret, token, api_key, apikey, access_key, secret_key, licence or license key, private_key, knox, authorization, cookie, csrf and session. A command-line `--password value` too.
- File paths whose name carries secret, token, key, pem, password, credential, `.env`, `id_rsa`, `tec-tac-trust` or the GitHub token path. They become `<redacted path>`.
- NUL, colour codes and other control characters are removed. Bad UTF-8 is replaced.

A package `sha256=` value is kept: the helper logs it and it is not a secret.

### Honest limits

Pattern scrubbing cannot catch every secret. A secret in an unusual shape, a base64 blob on its own line, or a password with spaces after `=` can survive. Some ordinary words are hidden too, such as the value after `session:`. This is why every read is audited and why only people who manage modules can read a log.

### Audit

Every successful read writes one row: module `core`, action `view`, object type `module_job_log`, object id the job id. The metadata is `job_id`, `kind`, `action`, `module`, `bytes`, `truncated` and `download`. It never holds log text. The row is strict: if it cannot be written, Core answers 503 and sends no log text.

## Retention

One number sets it: `MODULE_JOB_RETENTION_DAYS = 180` in `framwork/tec_tac/module_job_logs.py`. Change that one number and restart the scheduler tick (or Core). Nothing else holds a number of days.

### Records (Core, every minute)

The scheduler tick calls `module_job_logs.prune_expired()`. It runs at most once an hour (a cache marker), and a cache error runs it anyway. It never raises and never stops the tick.

- It removes at most 200 job records per run, oldest first, from the module jobs folder and the hotfix jobs folder.
- It removes only a regular, non-symlink file named `<canonical uuid>.json`.
- It removes only a finished job: status other than `queued`, `dispatched` and `running`. A queued, dispatched or running job is never touched, however old.
- It removes only a record whose `finished_at` (or `created_at` when there is no finished time) is older than the cutoff and can be read. A missing or unreadable time keeps the record.
- It keeps the newest job (by `created_at`) for every module the job names, so the last known state of a module is never lost.
- Hotfix `applied/` and `history/` records are not touched.
- A sweep that removed something writes one audit row: action `custom:module-job-retention`, object type `module_job_retention`, counts only (`retention_days`, `records_removed`, `hotfix_records_removed`, `kept_newest_per_module`, `kept_active`, `logs_awaiting_root_sweep`). A sweep that removed nothing writes none.

`prune_expired(dry_run=True)` returns the counts and deletes and audits nothing.

### Logs (the root helpers, at the next job)

The logs folders belong to root and are read-only for the Tactical group, so Core cannot delete a log. Making them writable would let a planted symlink steer root's append, so that was rejected.

Instead the two root helpers (`scripts/module-v2-job-helper.py` and `scripts/module-hotfix-job-helper.py`) each carry one small function, `sweep_orphan_logs`, called once when a job is claimed. It removes a log only when:

- it is a regular file named `<uuid>.log` (not a symlink, not a directory),
- its job record `<uuid>.json` no longer exists,
- it is older than one day,
- and no more than 100 go per call.

It reads no job state, so the log of a kept record, a running job or the newest job for a module always stays. It swallows every error and changes nothing about install, enable, disable, uninstall or hotfix behaviour. The module v2 helper's folder is shared with the older v1 helper, so its logs are covered too.

**Honest limit:** a log goes at the next module job after its record is removed, not on a timer, because only root can delete it. If no module job ever runs again, nothing grows either.
