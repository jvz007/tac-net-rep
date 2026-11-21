# Tec-Tac Framework 1.18.31

Date: 21 November 2026. Tactical's own upgrade from 1.5.2 to 1.6.1 no longer trips over a Core migration. Migration 0038 is pinned to accounts `0042` and creates the Communicator role and user with a raw INSERT over the live table columns. A new idempotent migration, `0045`, retries that creation on servers where `0038` already failed. No contract, endpoint or screen changes. `main` stays held.

## Module-facing change

None. No contract, capability, endpoint or declared operation changes. No module in `modules/` uses `__latest__` or `__first__`, and none refers to Core's migration 0038.

## Closes

- The PRIORITY entry of 21 November 2026 for Core: migration `0038_communicator_service_user` blocked Tactical's `migrate` after 1.5.2 to 1.6.1.

## What changed and why

- `framwork/tec_tac/migrations/0038_communicator_service_user.py`: the dependency `("accounts", "__latest__")` becomes `("accounts", "0042_copy_mesh_permission_to_terminal")`, with a comment saying why. `0042` is the newest accounts migration that exists in both Tactical 1.5.2 and 1.6.1. The flag the migration reads, `can_send_cmd`, exists since accounts `0017`, so the `RunPython` step finds it as before. The file keeps LF line endings.
- Why it failed: a floating `__latest__` resolves to the newest accounts migration the server has. On 1.6.1 that is `0044`. Core's `0038` was already applied before `0044` existed, so Django saw an applied migration whose dependency was not applied, and `migrate` stopped with `InconsistentMigrationHistory`. Tactical's upgrade script does not stop on that error, so it hid the failure.
- Why it is safe for installed servers: Django stores which migrations ran, not their dependencies. Changing the dependency of an applied migration changes nothing in the database. New installs now depend on a migration that exists in both Tactical versions.
- `tests/migration-no-floating-dependency-1.18.31.py` (new) is called from `tests/release-integrity.sh`, so the check runs before every pack.
- Version 1.18.31 in `VERSION` and `tec_tac_package.json`.
- `framwork/tec_tac/migrations/0038_communicator_service_user.py` (second change, see "Fixed after review"): the role and user rows are inserted with SQL over the live table columns, not through the historical model.
- `framwork/tec_tac/migrations/0045_communicator_service_user_retry.py` (new): the same idempotent creation, on top of `0044_core_secret`, for servers where `0038` failed and only logged.

## Assumptions

- `0042` is the right pin. It is the last accounts migration in the 1.5.2 reference tree. The 1.6.1 file list was not available here beyond what the request states; the request says `0043` and `0044` are newer.
- `migrations.swappable_dependency(settings.AUTH_USER_MODEL)` (used by `0001` to `0039`) stays. It resolves to the first accounts migration, which never moves. The new test allows it.

## Retired or changed checks

- `tests/version-1.18.30.py` moved to `tests/legacy/`, and `RELEASE_NOTES_1.18.30.md` moved to `docs/releases/`. Release integrity allows one root note.

## New tests

- `tests/migration-no-floating-dependency-1.18.31.py`: parses every Core migration with `ast` and fails on any `__latest__` or `__first__`. It checks that `0038` depends on exactly the pinned accounts migration, runs a negative self-test on synthetic sources, checks the pinned file and `can_send_cmd` in `reference/tacticalrmm` when present, and checks that `release-integrity.sh` calls it and that `0038` keeps LF.
- `tests/communicator-service-user-1.18.31.py`: builds a real sqlite stand-in of the live accounts tables and checks the raw INSERT and the shape of `0045`.
- `tests/version-1.18.31.py`: release bookkeeping.

## What could not be run here

Django is not installed on this PC. `makemigrations --check` and a real `migrate` on Tactical 1.5.2 and 1.6.1 did not run. The `ast` test covers the dependency text only, not Django's graph resolution.

## Johan dev02 checklist

dev02 already applied accounts `0043` and `0044` by hand. A normal `migrate` must now run clean without any manual step. Run this after the signed build installs.

1. Run `manage.py migrate --plan` as the Tactical user.
   - PASS: it lists no pending Core step and prints no `InconsistentMigrationHistory`.
   - FAIL: that error, or any Core migration listed as pending. Send the full output.
2. Run `manage.py migrate`, then `manage.py showmigrations tec_tac`.
   - PASS: `migrate` ends without error and `0038_communicator_service_user` shows `[X]`.
   - FAIL: any traceback, or `0038` not applied. Send the output.
3. Open Core UI and sign in.
   - PASS: sign-in and the module list work as on 1.18.30.
   - FAIL: any error page or a missing module. Send the message and the time.
4. Open Users in Core UI and look for the Communicator service user.
   - PASS: the user is listed and unchanged.
   - FAIL: it is missing or duplicated. Send a screenshot.

## Exit list

- Dependency pin, comment, no-floating-dependency test, pre-pack guard: done.
- Real Django migrate on Tactical 1.5.2 and 1.6.1, signing and review: not done here (pipeline, dev02).
- Module validator gate for floating dependencies in modules: not Core's. Written to `reviews/requests/_unsorted.md` for the pipeline owner.

## Fixed after review

Round 1 blocked 1.18.31 with one High finding: pinning `0038` to accounts `0042` fixes the migration history, but the historical `Role` model at `0042` does not know the columns Tactical 1.6.1 adds in accounts `0043` and `0044`. A fresh Core install over 1.6.1 inserted the role without them. A NOT NULL boolean with no database default failed, the error was logged, and the service user was never made.

- `0038_communicator_service_user.py`: the role and the user are now inserted with SQL over the live table columns, read through `connection.introspection`. Every boolean column of the role is false except `can_send_cmd`, even one whose database default is true. Unknown NOT NULL columns of the user get a neutral value (false, 0, empty text, now). A NOT NULL column of a kind with no safe value is refused and logged, never guessed. The existence checks and the "never change an existing row" rule stay as before.
- `0045_communicator_service_user_retry.py` (new): runs the same idempotent creation on top of `0044_core_secret`, with the same accounts `0042` pin. Servers where `0038` already failed and logged get the user on their next `migrate`. Servers that have the user are untouched.
- `tests/communicator-service-user-1.18.31.py` (new): stubs Django and builds a real sqlite `accounts_role` and `accounts_user` with extra NOT NULL columns and no database default. It checks that the role and user exist, that `can_send_cmd` is the only true flag, and that the old insert fails on the same schema. It also checks `0045`'s dependencies.
- `tests/secret-store-1.17.100.py`: the single-leaf check now expects `0045` on top of `0044`.
- Siblings checked: no other Core migration or module creates a Tactical accounts row through a historical model.
- Not run here: Django is not installed, so a real `migrate` against accounts `0044` did not run. The dev02 check below covers it.

Extra dev02 step: on a fresh database, install Tactical 1.6.1 first, then Core. Run `manage.py migrate`, then check the Core log for "could not be made".
- PASS: no such line, and the Communicator user exists with only the send-commands role.
- FAIL: the line appears, or the user is missing. Send the log.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
