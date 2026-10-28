# Tec-Tac Framework 1.17.88

Date: 28 October 2026. Monthly schedules can run on the nth weekday of the month, for example the second Tuesday. Adds a migration. Closes Johan's request relayed for Advanced Patch Management (APM).

## What changed and why

Until now a monthly schedule had one choice, `day_of_month`. Patch windows are usually "the second Tuesday", not "the 12th". A monthly schedule now uses either a day number or a week and a weekday.

1. **New fields on `TecTacSchedule` (migration 0041, additive, nullable).** `month_week` is 1, 2, 3, 4 (the first to the fourth) or -1 (the last). `month_weekday` is 0 (Monday) to 6 (Sunday). Existing rows keep `day_of_month` and get null in both. No data migration.
2. **Strict validation with plain messages.** A monthly schedule needs exactly one of `day_of_month` or the pair. The pair is both or neither. Booleans, strings, floats and out-of-range numbers are refused. There is no "fifth": weeks 1 to 4 exist in every month, and -1 means the last (the fifth when the month has five). So no month is ever skipped.
3. **Next and latest run.** `next_occurrence` and `latest_occurrence` find the date in the schedule's own timezone and keep the local `run_time`, exactly as `day_of_month` does. A `day_of_month` of 29 to 31 still falls on the last day of a shorter month. One-time schedules are unchanged: `run_at` is an exact moment.
4. **Module path.** `reconcile_schedule` takes `month_week=None, month_weekday=None` (keyword-only, after interval_anchor_at). A changed pair counts as a timing change and resets the due key, as `day_of_month` does. Both fields are locked on a schedule a person created, like every other timing field.
5. **Browser API.** `GET`, `POST` and `PATCH /api/tfd/scheduler/schedules/` accept and return `month_week` and `month_weekday`. On `PATCH`, sending one monthly mode replaces the other, so the UI can switch a schedule by sending only the new fields. Both modes sent together is refused. Audit rows are the ones the other schedule edits write, and an edit that changes the new fields is an edit field like the others (system-action ownership and the Yes/No confirmation apply).
6. **System-action confirmation.** The timing key includes the pair only when it is set, so the key of every other timing, and any confirmation id issued before this release, is unchanged. The plain text reads "on the second Tuesday of every month at 03:00 (UTC)".
7. **Docs.** `docs/module-scheduling.md` (new section), `docs/scheduler.md`, and the `reconcile_schedule` contract entry.

## Module-facing change

Additive. Needs framework >=1.17.88 for a module that passes the new keywords.

- `reconcile_schedule(..., month_week=None, month_weekday=None)`. Omit both and nothing changes. To move a schedule between the two monthly modes, call with the new mode only: the other mode's fields are cleared.
- The schedule payload returned by the API gains `month_week` and `month_weekday` (null when unused). `day_of_month` is null for a schedule that uses the pair.
- Anything that reads `day_of_month` on a monthly schedule must now handle null. Users found by grep in `modules/`: patchmanagement (passes it to `reconcile_schedule`, reads it in its own views and notice stage) and networkprobe (its own serializer). None of them breaks: they only pass `day_of_month` or read their own stored copy. No module reads Core's schedule row for it.

## Tests

- `tests/scheduler-nth-weekday-1.17.88.py` (new): every week (1 to 4, last) and weekday over every month of 2024 to 2027 against `calendar`; a month with four of a weekday and one with five; month and year boundaries both ways; a 36-month walk; the schedule's zone (Johannesburg, and London across daylight saving); validation (ranges, types, booleans, pairs, both modes, neither); the edit switch; `reconcile_schedule` (store, change, switch back, refusals, an old call unchanged, weekly untouched); the serializer; the confirmation key (old keys unchanged) and text; `day_of_month` 31 in February unchanged.
- `tests/scheduler-completion-harness-1.17.61.py`: the stub schedule gets the two new fields.

## Not run here

Django is not installed on this PC. The migration was written by hand and the view code (`scheduler_views.py`) was not run: the tests exercise `scheduler.py` and `system_action_confirmation.py` through the stub harness. Run `manage.py makemigrations --check --dry-run` on the pipeline.

## Request for the UI

The schedule form needs the monthly choice "Day of the month" or "Nth weekday" (week: first, second, third, fourth, last; weekday: Monday to Sunday). Filed in `reviews/requests/ui.md`.
