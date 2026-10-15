# Tec-Tac Framework 1.17.42

This patch release gives a fresh server one official module repository, syncs the enabled repositories once a day, and fixes a failing
Tactical file stream. Everything is additive. No migration, no database change, and no change to a key a module already reads.

1. **The official module repository is seeded once, disabled (CQ121).** A fresh server, and the dev server, get one repository, `tec-tac-official`.
   It is disabled, so nothing is synced until someone enables it. An administrator can edit, enable, disable or remove it, and Core never puts back
   a removed entry.
2. **The enabled repositories sync every day at 03:00 (CQ122).** The sync is a Scheduler action owned by Core. It shows on the Scheduler page
   with its time, zone, next run and history. Each run writes one count-only audit row.
3. **A failing Tactical file stream is a normal refusal.** Held MEDIUM from the 1.17.41 review. A stream that breaks part way used to surface as
   an unhandled error. It is now `tactical_call_failed` (502), with the outcome-unknown row for a change.
4. **Browser contract row `ui.authenticated.components` is in the public export.** Held Low from the UI 0.12.111 review. Documentation only.

**Assumptions to check (Johan, CQ125 and CQ126 in `reviews/questions/core.md`).**
- The address of the official repository is `https://lic-service.tec-tac.techxflow.net.za`, and the index path is the assumed
  `/modules/index.json`. No document in the tree names the index path. The trust label is `official`.
- Whether that index needs a licence token is unknown. Core holds no token and does not start the licensing integration. The entry stays
  disabled until the path is confirmed.
- The 03:00 run uses Django's `TIME_ZONE`. Tactical's runtime context reads Tactical's own default time zone first, so the two can differ.

**Answered, no change (CQ123).** The 25 MiB cap on a relayed Tactical answer stays. Nothing is built for it.

## What changed

- **Default repository (`tec-tac-official`).** `module_repository.py` holds one data record, `DEFAULT_REPOSITORIES`: id `tec-tac-official`,
  name "Tec-Tac official modules (Tech Flow Dynamics)", trust `official`, priority 100, enabled `false`, and the assumed index URL. The Scheduler
  tick calls `seed_default_repositories()` once a minute. The seed writes the record through the same URL check as a manual add. It records the id
  in a new top-level key `defaults_seeded` in `repositories.json`. An id on that list is never seeded again. If a repository with the same id or the
  same address already exists, only the marker is written, and an existing entry is never overwritten. The seed never raises. An unreadable or
  unwritable configuration logs a warning and the next tick tries again.
- **Daily sync.** `scheduler.py` registers `tec-tac.module-repository-sync` (module `tec-tac`, no target, permission none, timeout 900 seconds). Its
  handler runs `sync_all(enabled_only=True)`, the same path as the Sync action, so the SSRF guard and the size limits apply unchanged. It writes one
  audit row (`sync` on `module_repository`, actor the Core service, counts only: repositories, ok, failed, entries skipped). It returns the same counts
  as its run result. A failed repository never fails the run. The run raises `SchedulerPermanentError` only when every enabled repository fails.
  `ensure_repository_sync_schedule()` creates the owned schedule (daily, 03:00, the `TIME_ZONE` setting, run on recovery within 360 minutes, skip while
  running, no retry) only when no schedule holds the owner tuple `tec-tac` / `module-repository-sync`. An existing schedule is never re-saved, so an
  administrator's change to it survives. A deleted schedule is recreated on the next tick. Neither call raises.
- **Repository list.** `GET /api/tfd/modules/repositories/` adds `sync_schedule`: `enabled`, `time` (`03:00`), `timezone`, `next_run_at`,
  `last_run_at` and `last_run_status`, or `null` when the schedule does not exist. It holds no address.
- **Tick output.** The line ends with two new keys, `repository_defaults_seeded` and `repository_sync_schedule_created`. The keys before them are unchanged.
- **Stream failure (`tactical_operations.py`).** The stream read after a `file_response` dispatch is wrapped. A break part way is logged, the stream is
  closed (as before), and the call is refused as `tactical_call_failed` (502) with the outcome-unknown row for a non-GET call, and no row for a GET. The
  message is "Tactical failed while sending its answer." No file name or bytes are written. Capability `core.tactical_operations` stays 1.11.0, because
  this fixes behaviour that was already documented.
- **Contract rows (`contracts.py`).** New browser row `ui.authenticated.components` (`SearchSelect` and `TagEditor`), placed after
  `ui.authenticated.modulePreferences`. Documentation only. New HTTP row for `GET /api/tfd/modules/repositories/`, which had no row before, with the
  `sync_schedule` key.
- **Documentation.** `docs/module-repositories.md` has "Default repository (1.17.42)" and "Daily sync (1.17.42)". `docs/scheduler.md` has
  "Built-in repository sync (Core 1.17.42)". `docs/tactical-operations.md` says that a stream which fails part way is outcome-unknown, under "Added in
  1.17.41".
- **Release housekeeping.** The root release note of 1.17.41 moved to `docs/releases/RELEASE_NOTES_1.17.41.md`.

## Module-facing changes

All additive. No breaking change, and no contract version moves.

- **Scheduler action `tec-tac.module-repository-sync`.** New in the exported `scheduler_actions` rows. Modules do not call it.
- **Repository list key `sync_schedule`.** New on `GET /api/tfd/modules/repositories/`. Browser only: no module in `modules/` calls the repository
  routes, the online catalog or the Python repository functions (grepped).
- **Browser row `ui.authenticated.components`.** New documentation row for the shared components of UI 0.12.111. Modules that want them need UI 0.12.111
  and Core 1.17.41 or later, as the row says.
- **`core.tactical_operations` 1.11.0.** No change. No module in `modules/` declares `file_response` (grepped), so the stream fix changes no module's behaviour.

## Closes

- Johan's answers CQ121 (seed an official repository, not hard coded, disableable) and CQ122 (a daily sync at 3 am). Applied as above, with the
  open items CQ125 and CQ126.
- Held MEDIUM from the 1.17.41 review: a failing Tactical file stream becomes a normal outcome-unknown error.
- Held Low from the UI 0.12.111 review: `ui.authenticated.components` is now in the public contract export. The export itself is generated on the
  dev server after the release, so it appears there once the dev server runs 1.17.42.
- The 1.17.41 held Low "Online catalog `modules[]` changed meaning": the UI half shipped in UI 0.12.111, which reads `installed_only` and
  `availability` and requires Core 1.17.41. Core changes nothing here.

## Not built, on purpose

- The licensing integration. A licence token, if the index needs one, is a separate question (CQ125).
- The 25 MiB cap change (CQ123 answered no change).
- A manager's switch on the Scheduler page for the daily sync (CQ126 option b). The module-owned schedule is not editable there.
- Anything from the held items waiting on Johan or on another area. See `reviews/requests/core.md`.

## Not run on the development PC

- Django is not installed on this PC. The tests added here read the real functions with `ast` and run them with stubs. They do not need Django.
- Not run: a real repository sync against a live index, a real Celery run of the scheduled action, the Scheduler page, and the runtime probes that need
  a Tactical database. Run these on the dev server after the release.
- Tests that need POSIX features (`fcntl`, `pwd`, `geteuid`) or Postgres fail on this Windows PC both before and after this release. The failing list is
  the same as on the 1.17.41 source.

## Checks run

- `tests/tactical-operation-stream-failure-1.17.42.py`, `tests/browser-contract-rows-1.17.42.py`, `tests/default-repository-1.17.42.py`,
  `tests/repository-daily-sync-1.17.42.py`: pass.
- Re-run unchanged: `tests/tactical-operation-file-response-1.17.41.py`, `tests/browser-contract-rows-1.17.40.py`,
  `tests/contract-browser-doc-cells-1.17.19.py`, `tests/online-catalog-availability-1.17.41.py`: pass.
- `tests/browser-contract-catalog-1.15.170.py`: its pinned browser id list gained `ui.authenticated.components`. It passes.
- Full `tests/` folder against the 1.17.41 source and against this release: the same set passes, plus the four new tests. No test that passed before fails now.
- `python -m py_compile` on every changed Python file. `ruff check --select E9,F63,F7,F82` (the pipeline's gate for Core) passes on the whole tree.
  The default rule set reports two `BLE001` (blind except) findings on the new best-effort seed and schedule functions. The same pattern is used by the
  existing best-effort tick steps.
