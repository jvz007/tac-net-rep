# Tec-Tac Framework 1.17.60

You can now read the whole log of a module job, not just its last 40 lines. A new job history lists every module and hotfix job without log text. Finished job records are removed after 180 days.

Date: 20 October 2026. Every earlier route, field and contract stays. The three new surfaces are additive.

## What changed and why

Johan, 20 October 2026: the Module Manager page showed only 40 log lines, so a failed install could not be diagnosed from the page. This release adds the Core side. The page that shows it is UI work and is requested below.

This closes Johan's request of 20 October 2026 (chat). It closes no entry in `reviews/requests/core.md`.

### 1. Full module job log

`GET /api/tfd/modules/v2/jobs/<uuid:job_id>/log/`

- **Who:** the same check as the other module-management routes (`core.privileged_operations`). No new permission. A 403 writes no row and reads no file.
- **What:** the whole log as plain text (`text/plain; charset=utf-8`, `nosniff`, `no-store`). Inline by default. `?download=1` sends a file named `module-job-<module>-<action>-<YYYY-MM-DD>.log`, with the parts forced through `a-z`, `0-9` and `-` and cut to 40 characters.
- **Where it looks:** the id is looked up as a module job, then as a hotfix job. An unknown id is a 404. A job with no log is a 404 ("No log was kept for this job.").
- **How the file is opened:** only `<logs folder>/<canonical uuid>.log`, opened without following symlinks, and it must be a regular file. The folder must not be a symlink. A directory, a FIFO or a symlink is refused. No name from the caller reaches a path.
- **The 5 MB cap:** a log over 5 MB comes back as its first 2.5 MB and its last 2.5 MB, cut at line boundaries, with one marker line, `[... N bytes were left out of the middle of this log ...]`. Core seeks to the two parts and never reads the whole file. The answer says so in the headers `X-Tec-Tac-Log-Truncated` (`true` or `false`), `X-Tec-Tac-Log-Bytes` (original size) and `X-Tec-Tac-Log-Kept` (`all` or `head-and-tail`), and in the marker.
- **Scrubbing:** private-key blocks in full (the older log scrubber in `server_backup.py` redacts only the `BEGIN` line and leaves the key body; it is not changed), Authorization and API-key headers, Bearer, Basic and Token values, URL passwords, password, secret, token and key fields, and secret-named paths. A package `sha256=` value is kept. Each of the two cut parts is scrubbed on its own, so a key that straddles the cut cannot leak. The full rules and their limits are in `docs/module-job-logs.md`.
- **Audit:** every successful read writes one strict row: module `core`, action `view`, object type `module_job_log`, object id the job id, metadata `job_id`, `kind`, `action`, `module`, `bytes`, `truncated`, `download`. No log text. If the row cannot be written, Core answers 503 and sends no log (CQ171).
- **No permission change on the logs folders.** The Django user already reads these logs (`public_job` does today).

### 2. Module job history

`GET /api/tfd/modules/v2/jobs/history/`

- A separate route. `GET /api/tfd/modules/v2/jobs/` keeps its exact answer, including `log_tail` on every row. The new list carries no log text.
- Same permission. Filters `module` (exact id, matches any module the job names), `action`, `status`, `kind` (`module` or `hotfix`). Paging with `page` (1 or more) and `page_size` (1 to 100, default 50); a bad value is a 400. Same envelope as the old paged route.
- Rows come from module jobs and hotfix jobs together, newest first. Each row is built from a fixed list of fields: `id`, `kind`, `action`, `switch`, `renamed_from`, `module_ids`, `versions`, `requested_by`, the four times and stage, `status`, a short scrubbed `error`, `has_log`, `log_bytes`, and the four module lists of a replacement switch. No path, token, package path, hash or publisher trust can appear.
- `error` is one sentence: first line only, printable ASCII, scrubbed, paths replaced, 200 characters at most.
- `log_bytes` lets the UI warn before it opens a very large log. A symlinked log counts as no log.

### 3. Retention

- **One number:** `MODULE_JOB_RETENTION_DAYS = 180` in `framwork/tec_tac/module_job_logs.py`. To change the period, change that one number and restart the scheduler tick (or Core). Nothing else holds a number of days.
- **Records, on the scheduler tick (Core side):** one new guarded step runs at most once an hour. It removes at most 200 finished job records per run, oldest first, from the module jobs and hotfix jobs folders. It touches only a regular file named `<canonical uuid>.json`. It never touches a queued, dispatched or running job, a record whose time is missing or unreadable, or the newest job for any module it names. Hotfix `applied/` and `history/` stay. One audit row per sweep that removed something (`custom:module-job-retention`, counts only); none when nothing went. The step never raises and writes nothing to the tick's output line.
- **Logs, in the two root helpers (root side):** the logs folders are `root:tactical 2750`, so the Tactical user cannot delete a log. Loosening them to group-writable was rejected: the root helper appends to `<uuid>.log`, so a writable folder would let a planted symlink steer root's append. Instead `scripts/module-v2-job-helper.py` and `scripts/module-hotfix-job-helper.py` each gain one small function, `sweep_orphan_logs`, and one guarded call in `claim_job`. It removes a log only when the log is a regular file named `<uuid>.log`, its `<uuid>.json` is gone, it is over a day old, and no more than 100 go per call. It reads no job state and swallows every error. The retention period therefore lives in one place.
- **Honest limit:** a log goes at the next module job after its record is removed, not on a timer, because only root can delete it. If no module job ever runs again, nothing grows either.
- `prune_expired(dry_run=True)` returns the counts and deletes and audits nothing. Use it to check.

## Module-facing

New routes only. Nothing changes for a module.

- No module in `modules/` uses these routes. A search found no call to `/modules/v2/jobs/` in `modules/`. `modules/backups` and `modules/tacticalupdater` read `log_tail` from their own Core jobs, not from module-manager jobs.
- The older routes `/modules/v2/jobs/`, `/modules/jobs/<id>/` and `/modules/hotfixes/jobs/<id>/` are unchanged, and a test pins the source of `public_job`, `get_job` and the list code to 1.17.59.
- Two route entries are added to the contract catalog, next to `/api/tfd/modules/v2/jobs/`. The public export is generated on a running server, so the file in `docs/contracts` is not edited here (see the question file).

## Questions for Johan (assumption used; no wait)

- CQ170: who deletes old logs (record prune on the tick, log sweep in the two root helpers). Assumed (a).
- CQ171: a log read fails closed when its audit row cannot be written. Assumed (a).

## Request for the UI

Not Core work, so not built here. `reviews/requests/ui.md` now holds "From Core 1.17.60: Module Manager History tab and full logs (UI 0.12.118, requires Core >=1.17.60)": a History tab, a window for the full log with a Download button, the truncation line, the 403 wording, and Johan's note of 20 October 2026 that the Module Manager tab is still on the old design and must follow `docs/ui-brand-board` (P1 to P10). The ui-developer plans that part.

## Docs

New `docs/module-job-logs.md`: routes, fields, scrubbing rules and limits, who may read, audit rows, the 180-day constant and how to change it, and the root-side log sweep. One pointer line in `docs/module-replacement.md`. Release notes of earlier versions moved to `docs/releases/`.

## Tests

New, in `tests/`:

- `module-job-logs-1.17.60.py`: id checks before any file access, refused symlink, symlinked folder, directory and FIFO, scrubbing of a list of fake secrets, the 5 MB cap and its marker, no leak across the cut, a hostile module id in the file name, the headers, a hotfix job, 404s, 403 with no file read, one audit row without log text, a 503 without text when the row fails, and `log_tail` unchanged.
- `module-job-history-1.17.60.py`: every kind of job, newest first, the fixed field list, no leaks, the short error, `has_log` and `log_bytes`, filters, paging and 400s, corrupt records skipped, 403, and the old route unchanged.
- `module-job-retention-1.17.60.py`: age, status, newest per module, odd names and file types, the 200 bound, the audit row, the hourly gate, the dry run, the wrapped tick step, a byte-for-byte check that each root helper equals 1.17.59 apart from one function and one call, and a run of the real sweep function on a tempdir.
- `module-job-contract-rows-1.17.60.py`: the two contract entries, a contract entry and a doc mention for each new route, these notes and the version.

### What could not run on this PC

- Django is not installed. The new views run through the stub harness of the 1.17.58 licensing tests. The tick step is checked by reading its source and by calling it with a stub that raises. Nothing ran under a real Django.
- Symlinks and FIFOs cannot be created on this PC. Where the OS refuses, the tests fake the file type that `os.lstat` reports, which is the check the code makes. `O_NOFOLLOW` does not exist on Windows.
- The root helper function is tested on a tempdir with the root checks left out. Nothing ran as root and nothing ran on a server.
- `tests/release-integrity.sh`, `python -m py_compile` on every changed file, and `ruff check` with the repo's pipeline configuration ran. See the final report for the results.

## Dev-server checklist (PASS or FAIL)

First update dev02 from the dev branch and re-run the usual Core install, so the two root helpers are replaced.

1. **Make a failing job.** As a person who manages modules, open the Module Manager and run one install that fails (for example, upload a package with a bad checksum, or an unsigned test package). Note the job id from the page. PASS: you have an id. FAIL: you cannot get a failed job; tell me what happened.
2. **History row.** Signed in, open `/api/tfd/modules/v2/jobs/history/?status=failed` in the browser. PASS: your job is first, with a plain one-line `error`, `has_log` true and `log_bytes` above 0, and no path, no token and no log text. FAIL: log text, a path or a secret in the row; send the field name, not the value.
3. **Full log.** Open `/api/tfd/modules/v2/jobs/<id>/log/`. PASS: the full text, longer than 40 lines when the job wrote more, starting at the first helper line and ending at the failure line. FAIL: only 40 lines, an error page, or the text starts or ends in the wrong place.
4. **Download.** Open the same URL with `?download=1`. PASS: a file named `module-job-<module>-<action>-<date>.log` is saved, and the name has no odd characters. FAIL: another name, or the text shows in the browser instead.
5. **Redaction.** Open the file and search (Ctrl+F) for `password`, `token`, `Bearer`, `BEGIN` and `secret`. PASS: each hit shows `<redacted>`, or there is no hit. FAIL: a real value shows. Send the line number, not the value.
6. **Permission.** Sign in as a person without `core.privileged_operations` and open the same two URLs. PASS: both say 403. FAIL: either one shows data.
7. **Audit.** In Tactical's Audit Manager, find the two `view` rows for `module_job_log` (steps 3 and 4), with the job id and no log text. PASS: two rows, no log text. FAIL: a row is missing, or one holds log text.
8. **Retention check.** On the server, run: `manage.py shell -c "from tec_tac import module_job_logs as m; print(m.MODULE_JOB_RETENTION_DAYS, m.prune_expired(dry_run=True))"`. PASS: it prints `180` and the counts, with no traceback. FAIL: a traceback; send it. Expect no record to be removed on dev02 yet, because no job is 180 days old.


## Fixed after review (precheck, 20 October 2026)

- The log scrubber could hang a request worker. The key/value pattern in `module_job_logs.py` had an ambiguous tail, so a line such as `password-a-a-a-...` took exponential time. The tail is now unambiguous (`(?:[_-]+[A-Za-z0-9]+)*`) and any line over 20 000 characters is cut before scrubbing. Output for normal lines is unchanged.
- Regression test: `tests/module-job-logs-1.17.60.py` scrubs 5 000 dash and underscore pairs after password, token, secret, key and session, and must finish in under 1 s each.
