# Tec-Tac Framework 1.17.36

Date: 14 October 2026.

This patch release closes the HIGH install failure found on the dev server after 1.17.35. The install stopped at its migration drift check (`makemigrations tec_tac --check --dry-run`), because two new tables declared their primary key differently in the model and in the migration. The fix is in the model only. Nothing in the database changes, and no new migration is added.

## Module-facing changes

None. No capability, contract, endpoint or import changes, and no database change. Modules that already use `core.module_preferences` (1.17.35) need no change.

## What changed and why

1. **The notice ledger and module preference models use the implicit id (`models.py`).** `TecTacNoticeLedger` and `TecTacModulePreference` declared `id = models.BigAutoField(primary_key=True)` by hand. Migrations `0030_notice_ledger` and `0031_module_preferences` create the same column as Django's implicit id (`auto_created=True`, `verbose_name="ID"`). Django treats those as different, so `makemigrations --check` wanted a new migration. The two explicit lines are removed, and a one-line comment says the id is implicit on purpose. The column is the same bigint identity either way, so the database is unchanged. Migrations 0030 and 0031 are not edited, and no `0032` is added. Other models are not touched.
2. **The 1.17.35 preferences test follows the model (`tests/module-preferences-1.17.35.py`).** Its expected model field list no longer includes `id`, and a comment says where the id is checked now.
3. **A new test reads models and migrations together (`tests/migration-model-id-agreement-1.17.36.py`).** It replays every migration into a state, then checks each model against it, using `ast` so it needs no Django. It checks the primary key of every model, the field names and classes of every model, the index and constraint names of every model, and every kwarg, index and constraint of the two new tables. It also checks that no `0032` exists and that 0030 and 0031 still carry the exact implicit id line. Checked against the 1.17.35 models, the new test fails on `TecTacNoticeLedger` with the migration-drift message. Checked against a copy with `max_length` changed, it fails on that field.
4. **Version and release notes.** `VERSION` and `tec_tac_package.json` are 1.17.36. The 1.17.35 note moves to `docs/releases/` (a rename, as in earlier releases), because `tests/release-integrity.sh` allows exactly one root note.

## Closes

The HIGH install failure reported against 1.17.35 (the migration drift check). No entry in `reviews/requests/core.md` closes with this release, so none is removed.

## Held, not in this release

The Medium from the 1.17.35 review, "Python contract takes any user and any module id with no verified caller" (`module_preferences.py`), is left out. It changes what the `core.module_preferences` contract accepts (AD-26 caller verification) and needs its own release and review. No module uses the contract yet. The question is in `reviews/questions/core.md`.

## Tests

Added: `tests/migration-model-id-agreement-1.17.36.py`. Changed: `tests/module-preferences-1.17.35.py` (see item 2).

## Checks run on this PC

- `bash tests/release-integrity.sh`: passes. This PC has no working `python3` command, so the run used a shim that calls the same Python 3.12.
- `bash tests/migration-hygiene-foundation.sh`: passes.
- `python tests/migration-model-id-agreement-1.17.36.py`: passes. Run against a copy with the 1.17.35 models, it fails on `TecTacNoticeLedger` (the migration drift). Run against a copy with one changed `max_length`, it fails on that field.
- `python tests/module-preferences-1.17.35.py`, `python tests/module-failure-notices-1.17.34.py` and `python tests/module-failure-notices-1.17.35.py`: pass.
- The newest-migration pins `tests/update-source-1.17.2.py`, `tests/session-theme-1.17.24.py`, `tests/runtime-settings-upload-1.17.14.py` and `tests/priority-mail-no-private-relay-1.17.28.py`: pass.
- `python -m py_compile` on `framwork/tec_tac/models.py` and the new test: passes.
- `ruff check` with the pipeline gate's rules (`--select E9,F63,F7,F82`, as in `pipeline/tectac/checks.py`) on the whole tree: passes.

## What could not run on this PC

Django is not installed here, so `manage.py makemigrations --check --dry-run` could not run. The real proof is that command on the dev server, after the update. The new test shows the model and the migrations agree by reading the code; it does not replace that check.

## Versions

Core 1.17.36. No module requires a new framework version.
