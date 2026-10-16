# Tec-Tac Framework 1.17.48

Three small changes. Core now records refused event-job publishes in the audit log, once an hour. A short read fault no longer costs the owning module five
seconds of lost events. The installer now keeps `TEC_TAC_API_URL` in `tec-tac.conf`.

## Module-facing changes

These touch `core.event_jobs`, which only Alerts uses. The capability stays 1.1.0 and `requires_framework` stays `>=1.17.47`. Everything here is additive.

- **New audit action `custom:event-job-refused`.** It is listed in the contract's `audit_actions`, in the `event-jobs` rows of the contract export and in
  `docs/event-jobs.md`. A module that lists or filters Core audit actions will now see it.
- **New reason sentence 'the caller could not be verified'.** When Core cannot read the module list or a module's state while it checks the caller, the
  publish answers `PublishResult("error", "the caller could not be verified")`. Before, that case said 'the caller is not the module that owns this job'.
  The outcome is still `error` and the outcomes list is unchanged, so a module that reads only `result.outcome` is not affected. Alerts 0.10.0 reads only the
  outcome (checked in `modules/alerts`). A module that matched the old text for a fault would need to change. None in `modules/` does.
- The foreign-caller reason, 'the caller is not the module that owns this job', is unchanged.

## What changed and why

### Refused publishes are counted and audited once an hour (CQ138, Johan, 16 October 2026)

Johan asked for an audit row for a refused publish, once per module and job per hour, with a count, and no counter column.

- When the caller check finds a real caller that is not the owner (another module, a library frame, a generated frame, a Core frame, a disabled or legacy
  module), Core adds one to a tally. The publish still answers `error`, still stores nothing and still logs the throttled warning.
- The tally lives in Django's shared cache (Redis on a Tactical server). The key holds the owner module id, the job id and the clock hour, never a key or a
  payload. It lives about three hours. If the cache raises, Core uses a small process-local count (at most 256 entries) so a cache outage never breaks or
  slows a publish.
- The Scheduler tick has a new step, `_tick_report_refusals`, after the drop step. For each known job it reads the two hours before the current one, so a
  tick that missed an hour still reports it. It skips a zero count. It takes a guard with `cache.add`, so two ticks or two workers never write the same row. Then
  it writes one Core audit row, action `custom:event-job-refused`, with the count, `window_seconds` (3600) and `hour_start`. `recover_event_jobs` returns a
  new `refused_reported` count.
- The row never appears before its hour ends. The immediate signal is the existing warning in the log.
- A caller that could not be verified is not a refusal. It is not counted and writes no row.
- No migration, and no new field on `TecTacEventJobStat`.

Limits, in plain words:

- A cache flush or restart inside the hour can lose that hour's count. A count is a count, not proof.
- With a per-process cache (local development) the tick only sees its own process's tally. A production Tactical server uses the shared Redis cache.

### A short read fault costs the owner at most one second, not five (held Low from the 1.17.47 review)

In 1.17.47 a failed scan of the module list, or a failed read of a module's state, was kept for the whole five second window. The owner's own publishes were
refused for that long and the events were lost.

- Core still fails closed. It now also tells a fault from a foreign caller. A new private helper, `caller_identity.core_provider_caller_checked`, returns
  the identity and an `unverifiable` flag. It is not a contract and is not exported. `unverifiable` is true when the plugin scan raised, the state read
  raised or reported a corrupt state, the frame helper is missing, or the walk itself raised. It is false for every real answer.
- `calling_module_for_core_provider` keeps its signature and its None-means-refuse behaviour. It is now a thin wrapper over the same walk, so `accounts`,
  `audit` and `module_preferences` are unchanged. The public `calling_module` is unchanged and still uncached.
- New `FAILED_READ_SECONDS = 1`. A failed scan is kept for one second at most. A failed state read is remembered for one second and then read again. A corrupt
  state counts as a failed read, not as 'disabled'. A good read keeps the five second window, so the normal cost is the same as in 1.17.47.
- A publish made during the fault is refused with 'the caller could not be verified' and is lost: nothing is stored to retry. The next publish after about one
  second is checked again. It writes no audit row and no tally. It logs its own throttled warning, 'Event job <id>: the caller could not be verified; this
  publish was not stored', which never hides a foreign-caller warning.
- `docs/event-jobs.md` said an unreadable state answers `disabled`. That is true only for the publish's own five second module-enabled check. It now says so, and
  says that when that check is warm and the caller check's read fails, the answer is 'the caller could not be verified'.

### The installer keeps `TEC_TAC_API_URL` (request 'From UI 0.12.113', Johan chose option b)

`install.sh` rewrote `tec-tac.conf` from scratch and dropped the key, so an address given only in the environment was lost at the next install or update.

- Core only keeps the key. The UI installer owns the address order (environment, `tec-tac.conf`, the file it wrote last time, Tactical's `PROD_URL`) and checks the
  format. Core does not validate the URL.
- `install.sh` reads the caller's `TEC_TAC_API_URL` before it loads the config, because the loader would otherwise let the file override the caller. The caller wins, as in the UI
  installer. A value with CR or LF is refused with the usual message. When there is a value, `install.sh` appends exactly one `TEC_TAC_API_URL=<value>` line (as data, never sourced).
  With no value it writes no line. The file stays 0644 root:root.
- `scripts/migrate-layout.sh` rewrites the conf too. It now reads the key from the caller's environment first, else from the first `TEC_TAC_API_URL=` line of the
  existing conf (read as data), applies the same CR/LF check and writes it back.
- Update, restore and module paths need no code change. `system-update-helper.py` still strips every `TEC_TAC_*` variable on purpose, because a caller-controlled
  override must never reach a root installer. `install.sh` now rewrites the key from the root-owned conf on every run, and the UI installer reads that conf itself.
  `server-backup-helper.py` restores `opt/tec-tac/etc/` and then runs `install.sh`, which keeps the key.
- A snapshot taken before 1.17.48 carries no key. Restoring it onto a clean host is still refused by the UI installer with its plain message until the address is
  added. There is nothing for Core to build there.
- The server installer that first installs Tec-Tac must pass `TEC_TAC_API_URL`. That belongs to the installer agent, through Johan, and is not Core code.
- The key is documented in the README, next to the layout.

## Requests closed

- 'From UI 0.12.113: install.sh and tec-tac.conf keep TEC_TAC_API_URL' (with option b as the outcome; the entry's text still described the older assumption).
- 'From Johan via CQ138: Core 1.17.48 audit row for a refused event-job publish'.

Both are removed from `reviews/requests/core.md`. The held Low from 1.17.47 is closed here; the release manager updates the backlog line.

## Tests

- `tests/event-jobs-refusal-audit-1.17.48.py` (new): seven refusals in one hour give no row before the hour ends and then exactly one row with count 7; a second tick,
  a second worker and the next hour write nothing more; a second job has its own row; a tick that missed an hour still reports it; a zero count writes no row; no key or payload in the row; a raising cache falls back to the local tally; faults and the owner's own publishes add no tally; the capability stays 1.1.0;
  no migration and no new field.
- `tests/event-jobs-caller-1.17.47.py` (extended): the two assertions that pinned the old reason for a fault now expect 'the caller could not be verified'. New: a scan fault, a state fault and a corrupt state each cost the owner at most one second; a good snapshot still lasts five seconds (100 publishes cost one scan and one state read); the helper tells a fault from every real answer; the two warnings are separate and throttled.
- `tests/install-api-url-1.17.48.sh` (new): the loader, the caller capture and the config write of `install.sh` and `migrate-layout.sh`, extracted by their text and run against a temporary conf; `bash -n`; `privileged_env` still strips `TEC_TAC_*`.
- `tests/caller-identity-core-provider-1.17.27.py`, `tests/caller-identity-1.17.21.py` and `tests/caller-identity-server-module-1.17.26.py` pass unchanged.

What could not run on this PC: Django is not installed, so the real tick, the real shared cache and the real `audit.record` ran only through stubs. `install.sh` and `migrate-layout.sh` need root, systemd and
Tactical, so only the extracted snippets and `bash -n` ran. Please run `tests/event-jobs-caller-runtime-1.17.47.py` on the dev server after install and check one refusal tally across a web process and the Celery tick (see `reviews/questions/core.md`).

Earlier notes are in `docs/releases/`.
