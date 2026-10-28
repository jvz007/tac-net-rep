# Tec-Tac Framework 1.17.85

Date: 28 October 2026. Fixes Run now on a module's scheduled action that needs a person. Closes the request from Johan on dev02 (28 October 2026, 13:28). One migration (0039), no new route, no new setting.

## What changed and why

Running the Advanced Patch Management notice schedule by hand ended `failed` with "A manual run has no person behind it, so nothing was sent."

**Cause.** `verify_run_context` gave a declared `scheduler_person_actions` action a person only for a scheduled run (the creator). A manual run was left out on purpose, and Core never recorded who pressed Run now, so the handler had nobody to act for.

**Fix.** The Run now route records the signed-in person on the run (`started_by`, `started_by_username`). For a declared person action Core:
1. refuses the run before queueing, with a plain message and one `deny` audit row, when that person lacks the action permission or the target scope;
2. re-checks them live at run time (active, permission, scope), through the same check scheduled runs use for the creator;
3. gives them to the handler through `verify_run_context`: `user`, `owner_user_id`, `owner_username` are the clicker, `unattended` is False, and the new `started_by_username` names them. The handler acts for the clicker, not the creator;
4. writes one audit row per run (`run`, `run_as` = `clicker`).

An inactive clicker, or one who lost the right, makes `verify_run_context` raise `SchedulerRunContextInvalid` (fail closed). Every other manual run (undeclared action, user-owned schedule, one-off, self-test, any call of `queue_manual_run` without a person) behaves as before. Scheduled runs are untouched.

## Module-facing change

- `verify_run_context` / `VerifiedSchedulerRun`: new last field `started_by_username` (default None). Handler context: new key `started_by_username` (display only). `queue_manual_run(schedule, *, started_by=None)`: new optional keyword.
- Advanced Patch Management and Communicator need no change: their handlers already call `verify_run_context(require_owner=True)`, so Run now works with Core 1.17.85. The "manual run has no person" text only remains for a run with no clicker or an older Core.
- Documented in `docs/module-scheduling.md` and the `verify_run_context` contract text.

## Migration

`0039_run_started_by`: a nullable user link and a blank name on `TecTacScheduleRun`. Written by hand (Django is not installed here). On the dev server check `manage.py makemigrations --check --dry-run`.

## Tests

`tests/scheduler-manual-run-person-1.17.85.py`: the clicker is the person (not the creator), with and without a stored creator; no clicker, undeclared, delisted and foreign actions get no person; inactive, no permission and no scope are refused; the creator losing the right does not stop a clicker who holds it; the audit and view wiring and the documentation text are present.

## Test checklist (dev02, Johan)

1. Sign in as a person who holds the patch install permission and scope. Open the APM notice schedule and press Run now. **Expected:** the run ends `succeeded`; the notice is sent; the audit log has a `run` row with run_as `clicker` naming you. **FAIL:** still "no person behind it". Send back: the run's error text and the Core log lines for the run id.
2. Sign in as a person without that permission and press Run now. **Expected:** refused with "You do not have permission to run this action"; no run is created; the audit log has a `deny` row naming that person. **FAIL:** a run starts.
3. As a scoped person, press Run now on a schedule whose targets lie outside your scope. **Expected:** refused with "outside your Tactical scope". **FAIL:** a run starts.
4. Let the scheduled run fire on its own. **Expected:** unchanged, runs as the creator. **FAIL:** any change.
5. Run now on any schedule of another module's action. **Expected:** unchanged.

## Not run here

Django is not installed on this PC: the migration, the view and the Celery path were not run. The stub-harness test, `py_compile` and the integrity script were.
