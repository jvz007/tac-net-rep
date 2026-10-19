# Tec-Tac Framework 1.17.55

Scheduler runs work again on PostgreSQL. This is a hotfix. It changes two lines and nothing else.

## What broke

Scheduler runs stayed queued and nothing ran. That includes `backups.create`, `backups.follow`, `checks.provider-run` and `licensing.reconcile`. The worker log on dev02 shows `NotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join`.

## Cause and fix

When a worker picks up a run, it locks the run row so a duplicate delivery cannot run it twice. The query also loaded the run's schedule in the same statement. A run's schedule link can be empty, so the database joins the schedule table in a way that lets it be missing. PostgreSQL refuses to lock across that kind of join.

The lock now covers the run row only: `select_for_update(of=("self",))`. The schedule is still loaded in the same query, so there is no extra database call. The run is still claimed once. Its status must still be `queued`, and it then moves to `running`.

## Same fault in the schedule delete view

`DELETE /api/tfd/scheduler/schedules/<id>/` had the same pattern. It locked the schedule and loaded `created_by` and `updated_by`, which can also be empty. It failed for every schedule. It now locks the schedule row only. The delete flow is unchanged, including the lock on active runs.

We swept every `select_for_update` in `framwork/tec_tac` (68 calls, tests excluded). These two were the only ones combined with `select_related`. The rest are single-table lookups.

## Module-facing change

None. No contract, capability, endpoint or import changes. Backups, Checks and Licensing do not change. Their Scheduler runs start working again, and that is all.

## Why it was not found earlier

The claim line dates from 1.15.48 (25 September 2026). The empty-able schedule link has existed since migration 0002. Git shows no change to either since, so this is not a Django or psycopg upgrade in this repository. PostgreSQL has always refused this lock.

Every test used stubs or SQLite. Those never send `FOR UPDATE`, so nothing could catch it. Only the dev02 worker log shows it.

We could not read the dev02 worker log (`w1-1.log`) or run Django on the dev PC. We therefore do not know the date the first run failed. We also cannot rule a Django or psycopg change on dev02 in or out. It may be that runs worked earlier because no module had registered a schedule yet. The log shows the error since at least 14:38 on 19 October 2026.

## Tests

- `tests/scheduler-claim-lock-1.17.55.py` runs anywhere, without Django. It checks the real claim against a stub, scans the source for the unsafe pattern, and checks the delete view. On 1.17.54 it fails. On 1.17.55 it passes.
- `tests/scheduler-claim-postgres-1.17.55.py` runs on dev02 only. It checks the compiled SQL, runs both queries with empty links, and runs `execute_schedule_run` on a probe action. Everything rolls back. **It could not run on the dev PC** (Django, psycopg and PostgreSQL are not installed). It has not been run.
- Stubs in the earlier Scheduler tests now accept the `of` keyword. `scheduler-durability-review.sh` looks for the new call text.

## Administrator steps after installing

Restart `celery.service` and `celerybeat.service` so the worker loads the fixed task. Never `sh-celery` or `sh-celerybeat`.

## Dev-server check

1. **Backups.** Use Run now on a backup run that is safe on dev02 (a validate or create run). Watch Scheduler runs.
   - PASS: it leaves queued within a minute and reaches running, then succeeded or a normal failed result with a reason.
   - FAIL: it stays queued, or the worker log still shows `NotSupportedError: FOR UPDATE`. Send the last 50 lines of the celery log.
2. **Checks.** Within two minutes, new runs for `checks.provider-run` should appear.
   - PASS: at least two new runs, all succeeded.
   - FAIL: any stays queued, or fails with a `DispatchError`. Send the run ids and the worker log.
3. **Old queued runs.** This release does not touch the stale-run sweep. The sweep runs on each Scheduler tick. It does not re-queue old rows. It marks a queued run older than the dispatch window (10 minutes by default) as `failed` with type `Stale`. Old queued rows should turn into failed Stale rows on their own. We do not promise the backlog of about 6288 lines clears at once or that those runs execute. They fail, they do not run. Later rows may take more than one tick.
4. **Optional, on dev02.** Run `python tests/scheduler-claim-postgres-1.17.55.py` with the Tactical Django settings. PASS: every step says PASS. FAIL: send the output.
