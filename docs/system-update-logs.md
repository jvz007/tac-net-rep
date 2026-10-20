# System update and server-maintenance job logs (Core 1.17.67)

Johan asked on 20 October 2026 for a way to open and download the log of a system update and of a server-maintenance job, and for the Audit page to say what an update did. This page is the contract. UI 0.12.119 asked for the routes.

All routes need an authenticated Tec-Tac session with `core.privileged_operations`. A caller without it gets 403, with no audit row.

## System update jobs

| Route | What it does |
|---|---|
| `GET /api/tfd/system/updates/jobs/` | Lists jobs, newest first. Query: `page`, `page_size` (1 to 100, default 50), `component` (`framework` or `ui`), `status`. Reads the jobs folder and the history folder, merged by job id (history wins). Reads only the newest 500 files by modification time. |
| `GET /api/tfd/system/updates/jobs/<id>/` | One job. Since 1.17.67 a job that is no longer in the jobs folder is read from history instead of answering 404. |
| `GET /api/tfd/system/updates/jobs/<id>/log/` | The log as plain text. `?download=1` sends a file named `system-update-<component>-<YYYY-MM-DD>.log`. |

A list row has the same whitelisted fields as the detail answer, without `log_tail` and without `backup_path`. Every job answer (list and detail) gains two additive keys: `log_bytes` (the size of the kept log, or `null`) and `has_log`. The UI shows the Download button only when `has_log` is true.

## Server-maintenance job logs

`GET /api/tfd/system/maintenance/jobs/<id>/log/` returns the helper log, stdout and stderr. By default (`?part=all`) it is one text with three headed sections: `== log ==`, `== stdout ==` and `== stderr ==`. `?part=log`, `stdout` or `stderr` returns one file, with no header. A file that does not exist is left out. `?download=1` sends `server-maintenance-<action>-<YYYY-MM-DD>.log`.

A job of an action that needs a Tec-Tac permission is hidden from a caller who does not hold it. The answer is the same 404 as for a job that does not exist, with or without `?download=1`.

## What every log route does the same way

- The text is scrubbed: private keys, Authorization and API-key headers, Bearer and Basic values, URL passwords, `password=`, `secret=`, `token=` and key fields, and secret-named paths. A maintenance job's own sensitive parameter values are removed first, as the job detail does.
- A log over 5 MB is cut to its head and tail with one marker line. For a maintenance log with several parts the 5 MB is shared between the non-empty parts.
- Headers: `Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Tec-Tac-Log-Truncated`, `X-Tec-Tac-Log-Bytes`, `X-Tec-Tac-Log-Kept`, and on a 200 `Access-Control-Expose-Headers`. They are built in one helper, `module_job_logs.log_response`, shared with the module job log.
- Safe file access: the id is parsed and rebuilt, the folder must be a plain directory, and a symlink or a file that is not regular is refused (404).
- Every successful read writes one strict audit row (no log text). If it cannot be written the answer is 503 and no text is sent.
- Errors: 400 `invalid_job_id` (or `invalid_part`), 404 `job_not_found`, 404 `no_log`, 503.
- Show the text as text, never as HTML.

## The audit row of a finished update

The Scheduler tick writes one row per finished system update. The wording and the keys are in `docs/module-audit.md` ("Core's own rows for job log reads and finished system updates"). The root helper records the version that was installed before the update (`installed_version` in the job file) from Core 1.17.67 on. The update to 1.17.67 itself is run by the older helper, so that row reads `Update installed successfully to 1.17.67`. The next update reads `1.17.67 -> 1.17.68`.

## For modules

Nothing a module calls changes. `core.server_maintenance` stays 1.1.0: `read_job_log` is a function of `tec_tac.server_maintenance`, not an operation of the capability. A module that reads a maintenance job keeps using `get_job`.
