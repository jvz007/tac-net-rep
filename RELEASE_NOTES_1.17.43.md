# Tec-Tac Framework 1.17.43

This patch release points the official repository at the confirmed index path, closes three held findings from the 1.17.42 review,
makes a refused system update leave the installed version alone, and adds two opt-in declaration keys for Tactical operations. Everything is
additive. No migration, no database change, and no change to a key a module already reads.

1. **The official repository uses the confirmed path (CQ125).** Johan confirmed the index path on the licensing server: the development channel.
   A fresh server gets it disabled, as before. A 1.17.42 record that still holds the assumed path is corrected once, at the next tick. Its
   enabled flag, name and priority stay as they are, and an address an administrator has edited is never replaced. The channel for a production
   server is not decided yet (CQ128).
2. **The daily sync time zone is stated in the docs (CQ126).** The sync runs at 03:00 in the server's own time zone, Django's `TIME_ZONE`.
   Stock Tactical v1.5.2 sets it to UTC, so 03:00 UTC is 05:00 in South Africa. The docs and the contract note say so. No schedule code changed.
3. **Three held findings from the 1.17.42 review are fixed.** The seed no longer does a DNS lookup on every tick. A repository's skipped entries
   count only when its sync succeeded in the run. The repository configuration has a bounded lock, so a seed, a save and a delete cannot
   overwrite each other.
4. **A refused system update does not roll back (system update helper).** An installer that refuses in its own pre-flight returns status 78.
   The helper then restores only the source checkout. It does not run the installer again, and it does not log `ROLLBACK FAILED`. Any other
   failure keeps the full rollback.
5. **`metadata.object_count` for a list scope (agents 0.6.0 request, optional).** A row written for a call whose first scope entry names more
   than one id now says how many ids it named.
6. **`audit.secret_fields`: a change marker for a secret body field (tasks 0.5.0 round 2, globalsettings 0.3.0 (b), remote-background fix round 1 (e)).**
   A declared secret field is never recorded. The row shows `changed`, or `present` before and `changed` or `unchanged` after when Tactical's
   before read holds the field. The comparison happens in memory on a SHA-256 of the canonical JSON.

## What changed

- **Repository address (`module_repository.py`).** `DEFAULT_REPOSITORIES` holds the development-channel URL. A new table,
  `SUPERSEDED_DEFAULT_URLS`, names the 1.17.42 address. `seed_default_repositories` replaces the address of the `tec-tac-official` record once,
  only when it equals that address exactly, and it keeps the enabled flag, name and priority.
- **No network call in the seed.** The seed uses `_seed_address_check`: it refuses a credential, `localhost`, a reserved or loopback address, and a
  private literal unless the trust is internal. A host name is not resolved. `_fetch` still resolves and checks the address at every real sync, and
  `upsert_repository` keeps its full check. A manual add resolves the host before the lock is taken.
- **Configuration lock (`_config_lock`).** A sibling file, `repositories.lock`, held with `fcntl.flock`. The wait is bounded at 5 seconds. The seed,
  the upsert and the delete each read the configuration again inside the lock. A busy lock raises `The repository configuration is busy. Try again.`
  The seed logs one warning and tries on the next tick, and it never raises. `fcntl` is imported inside the function, so the module still imports on
  a Windows PC.
- **Skipped entries (`run_scheduled_sync`).** `skipped_count` is added only in the branch where the repository's sync has no error.
- **Refused update (`scripts/system-update-helper.py`).** `INSTALL_REFUSED_EXIT = 78`, `_UpdateRefused`, and `_installer_refusal_reason`, which
  reads the installer's own `[TEC-TAC-INSTALL] REFUSED:` line from the end of the update log. In `run_job` the refusal branch restores the source
  only, records stage `failed-pre-mutation` with `rollback {performed: false, status: not-required, reason: installer-refused}`, and logs
  `SOURCE RESTORE FAILED` if the restore itself fails. The job still ends failed with a terminal write.
- **Installer pre-flight (`install.sh`).** `refuse()` prints the error, prints the marker line and exits 78. It is used only for the payload
  layout check and the system Python cryptography check, both before the first change. Every later failure keeps `fail()` and exit 1.
- **Tactical operations (`tactical_operations.py`).** `register_tactical_operation` accepts `audit.secret_fields`. `object_count` is added to the
  rows of a call whose first scope entry names more than one id. `CAPABILITY_VERSION` is 1.12.0. Both changes ship in this release, so they share
  that capability version.
- **Contract and docs.** `contracts.py` has one 1.17.43 note row for the repository and one for the Tactical operations. `docs/module-repositories.md`,
  `docs/scheduler.md`, `docs/tactical-operations.md` and `docs/system-update-signed-releases.md` describe the changes.

## Module-facing changes

- **`core.tactical_operations` 1.12.0 (needs framework 1.17.43 or later; feature-detect with `>= 1.12.0`).** Two opt-in changes. A declaration
  that uses neither behaves exactly as before, and a row without them is unchanged.
  - `audit.secret_fields` (a list of up to eight body fields). Each named field must be in `body_fields`, and it cannot also be in
    `audit_fields`, `audit_lists`, the fields of `audit.before`, `audit.object_body_field` or a body scope source. A success row shows the
    marker. A failed, denied, core_refused or outcome-unknown row shows none.
  - `metadata.object_count` on the rows of a call whose first scope entry names more than one id. It is a number, never an id, and the object id is
    unchanged.
- **Modules that want the marker** declare it in their own release. Requests are in `reviews/requests/core-modules.md` (tasks, globalsettings,
  remote-background), each with `requires.framework >=1.17.43`.
- **Capability pins.** Existing tests that pinned `core.tactical_operations` 1.11.0 now pin 1.12.0. No behaviour assertion changed.
- **Repository routes.** No route, field or response changed. The seeded address is the only visible change.

## Closes

- `reviews/requests/core.md`: the optional `object_count` entry from agents 0.6.0 (removed), the sentence "Agents waits on the same item" (edited),
  the tasks 0.5.0 round 2 entry (option a shipped; each module adopts it in its own release), the secret-fields half (b) of globalsettings 0.3.0
  (the literal object id, half (a), stays open), and item (e) of remote-background 0.3.0 fix round 1.
- The held 1.17.42 review findings: the DNS Medium on every tick, the `skipped_count` Low after a failed sync, and the lock Low.
- The "server time" Low (docs, contract note, docstring). The schedule itself is unchanged.

## Not built, on purpose

- The welcome contracts (`core.initial_setup.*`, `core.module_setup.*`), licensing, the licence token (CQ129), paging a whole-list answer (CQ130),
  the failed row for a GET (CQ131), the literal audit object id for globalsettings, and the production channel (CQ128). Each waits on Johan or on
  design work of its own (`reviews/questions/core.md`).
- The UI half of the refusal (exit 78 from `workspace/ui/scripts/install.sh`). It waits for a UI release (`reviews/requests/ui.md`). Until then a UI
  refusal keeps the full rollback, as before.

## Not run on the development PC

- Django is not installed here, so the Django-dependent tests (`tactical-operations-runtime-*`) cannot run.
- `fcntl`, `pwd`, `grp` and the trusted root-owned bash do not exist on Windows. The lock is tested with a stub. The real two-process race and a
  real refused install need the dev server.
- `tests/backup-recovery-system-update-1.15.140.py` could not load on Windows. Its path-rendering assertions compare POSIX paths with Windows
  paths. It was run from a scratch copy with only those lines removed (five path assertions and the two assignments they read), and its `run_job` checks passed. The repository copy is unchanged.
- `tests/safe-files-atomic-json.py` needs symlink privilege, which this session does not hold. `tests/m15-low-batch.py` imports the Django package.
- `ruff check` reports one new BLE001 (blind `except Exception`) on the source-restore branch of the refused-update path. It is the same kind as the
  existing rollback catch next to it, and it guards a restore that must not stop the job's terminal write.

## Checks run

- New: `tests/repository-seed-1.17.43.py`, `tests/repository-seed-lock-1.17.43.py`, `tests/system-update-refused-1.17.43.py`,
  `tests/tactical-operation-object-count-1.17.43.py`, `tests/tactical-operation-secret-fields-1.17.43.py`. All pass.
- Changed and existing: `tests/default-repository-1.17.42.py` (the URL pin and the helper names), `tests/repository-daily-sync-1.17.42.py`,
  `tests/online-catalog-availability-1.17.41.py`, `tests/module-repository-skipped-1.17.39.py`, every `tests/tactical-operation*` test that
  runs without Django, `tests/contract-export-1.17.16.py`, `tests/audit-correlation-1.17.16.py`, and `tests/system-update-rollback-backup-safety.py`
  (through a scratch runner that supplies the POSIX names; the test is unchanged).
- `python -m py_compile` on the changed Python files, `bash -n install.sh`, and `ruff check --config pipeline/pyproject.toml` on the four changed
  Python files, compared with the committed versions.
