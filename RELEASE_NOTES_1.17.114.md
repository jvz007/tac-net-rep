# Tec-Tac Framework 1.17.114

Date: 10 November 2026. A module's own root program can now receive that module's own secret. The feature was built in 1.17.113 and held back until Johan signed it. He did (AD-62). This release switches it on and closes three held Lows.

Closes: Johan's answers of 10 November 2026 ("1 - yes", "2 - okay", AD-62), the held Lows of Core 1.17.113 (`cancel_failed` secret folder; Core and the helper parse `secret_inputs` differently) and the held Low of 1.17.112 (program-taken lock, closed with no code).

**Flagged for human review: security item.** This release turns on a Core read of a module's secret. The purpose is the one AD-62 signed and nothing wider. No new trusted purpose, no new caller, no other module.

## What changed and why

1. **Secret inputs are ON (`SECRET_INPUTS_ENABLED = True`).**
   * Why: AD-62 (Johan, 10 November 2026) signed that Core hands a module's own secret to that module's own signed server-maintenance action. certificatemanagement 0.5.0 and 0.6.0 need it.
   * Now: `start()` of an action that lists `secret_inputs` reads the owner's secrets and hands them to the root helper on stdin, as 1.17.113 built it. The provider metadata field `secret_inputs_enabled` is now `true`.
   * The constant stays as the **kill switch**. Set it to `False` and `start()` refuses with `secret_inputs_disabled`, reads nothing and creates no job.
   * Every guard from 1.17.113 is unchanged: owner only; the action registered by a signed module manifest; an enabled, non-legacy owner; the code-object identity check in `secret_store._read_for_server_maintenance`; the strict audit row before the dispatch; tmpfs folders at 0700 and files at 0400.
   * Code: `server_maintenance.py` (`SECRET_INPUTS_ENABLED`, comments and the `_resolve_secret_inputs` docstring), `secret_store.py` (docstring only), `contracts.py` (the `core.server_maintenance` text now says ON since 1.17.114 (AD-62) instead of "switched OFF").
2. **Core and the helper read `secret_inputs` by the same rules (held Low of 1.17.113).**
   * Why: Core accepted only objects with both keys. The helper also accepts a plain name and an object without `required`. A registry file the helper would run could therefore hand over nothing, or two readers could disagree.
   * Now: `server_maintenance._parse_secret_inputs` follows the helper's `normalize_secret_inputs`. A plain name means required. An object has `name` and optionally `required`, no other key. `required` must be a boolean. Names match the `core.secrets` pattern, no repeats, at most 8. `None` means none.
   * A value that fails those rules makes `start()` refuse with `action_invalid` before anything is read, written or dispatched. `list_actions` still lists the action and shows no names (`_action_secret_inputs` never raises).
   * The helper call now gets `stdin=subprocess.DEVNULL` whenever there is no hand-over (`--dispatch` without secrets, `--cancel`, `--signal`). The helper can never read or block on the Django worker's inherited stdin. With a hand-over the `input=` option stays.
3. **A failed stop no longer leaves the secret folder to the next sweep, and the sweep no longer removes the folder of a running unit (held Low of 1.17.113).**
   * Why: when `systemctl stop` failed, `cancel_job` marked the job failed and raised before the folder was cleaned. The job was then terminal while the program might still run. The next helper start swept the folder of any terminal job, under a program that could still need it.
   * Now: a new `_unit_gone(unit)` asks `systemctl is-active`. Only `inactive`, `failed` or an unknown unit counts as gone. `active`, `activating`, `deactivating` and `reloading` count as running.
   * In the `cancel_failed` branch the folder is removed only when the unit is confirmed gone. Otherwise the folder stays, the job is still marked failed and `cancel_job` still raises. A line without any value goes to stderr.
   * `sweep_secret_dirs` keeps the folder of a terminal job while its unit is active, and removes it as soon as the unit is gone. A folder of an unknown job or a bad name is removed as before, without asking systemctl. `run_job`'s own `finally` removes the folder when the surviving program ends.
   * A `systemctl` that cannot be run counts as gone. Root-only plaintext does not stay on tmpfs on a guess. This is the behaviour before this release.
4. **Held Low of 1.17.112 (program-taken lock for `waits_for_person`): closed with no code.**
   * Johan accepted option (a) on 10 November 2026 ("2 - okay", AD-62). Nothing is built and no behaviour changes. The Low at `scripts/server-maintenance-helper.py:495` is closed. The release manager removes it from `reviews/core/BACKLOG-new-findings.md`.
5. **The workspace was moved onto the signed 1.17.113.** The workspace carried three unsigned local commits (1.17.113-1) that the pipeline had already signed as 1.17.113 (commit 7408545). This release starts from that commit. The three superseded commits are kept on the local branch `backup-dev-1.17.113-1` and add nothing the signed commit lacks.

## Module-facing changes: core.server_maintenance 1.3.0 (unchanged version)

* `secret_inputs` works. The capability stays at **1.3.0**. A module that needs the feature sets `requires.framework` to `>=1.17.114`, or reads `secret_inputs_enabled` from the provider metadata. On a Core still at 1.17.113 an action that lists `secret_inputs` is refused with `secret_inputs_disabled`: a clear refusal, not a silent failure.
* An action whose `secret_inputs` Core cannot read is refused with classification `action_invalid`. Before, it started with no secrets.
* Plain names and objects without `required` in the registry file are now handed over (they were ignored by Core before).
* Calls to the helper without a hand-over no longer inherit stdin. Nothing a module calls changes shape.
* Used by certificatemanagement (0.5.0 and 0.6.0 will be the first users). securityWAF and tacticalupdater register actions without secrets: their behaviour is unchanged. No module in `modules/` lists `secret_inputs` yet.
* Contract text: the `core.server_maintenance` row now says ON since 1.17.114 (AD-62) and states the standing limits below. Export a fresh public contract after this release is installed.

## Standing limits (unchanged, said again)

* The Core worker holds the plaintext in memory for the moment of the call.
* The log scrub replaces the secret values with `***` only after the program exits. A program that prints a secret while it runs puts it in the live log until then. The program must read the file and never print it. Core cannot enforce that.
* Core's check of the calling code (the code-object identity of `_resolve_secret_inputs`) is code-path evidence. It is not a sandbox.

## Tests

* New `tests/server-maintenance-secrets-on-1.17.114.py`: the shipped default is on and the metadata says so; a start hands the secret over on stdin only (never argv, environment, job file, audit row or log) with one audit row before the dispatch; a `compile()`-forged `_resolve_secret_inputs` with the real file name and `__name__` gets `caller_not_allowed` with the switch on, for its own and for another module's action (regression for the 1.17.113 High); with the switch off `start()` refuses with `secret_inputs_disabled`, reads nothing and creates no job; the contract text no longer says OFF.
* New `tests/server-maintenance-secret-parse-1.17.114.py`: plain-string registry hand-over; a missing `required` means required; six kinds of unparseable value refuse with `action_invalid` and create nothing; `stdin=DEVNULL` without a hand-over and `input=` with one; `list_actions` of an unparseable action; one table of cases fed to Core's parser and the helper's `normalize_secret_inputs` with the same result.
* New `tests/server-maintenance-secret-cancel-failed-1.17.114.py`: the seven cases of the plan (stop fails with the unit active; the sweep keeps, then removes; stop fails with the unit inactive; stop succeeds; systemctl cannot be run; unknown and malformed folders without a systemctl call).
* Updated `tests/server-maintenance-secret-inputs-1.17.113.py`: the line that asserted OFF by default now asserts ON. The "disabled" section already set the switch to `False` itself.
* Re-run and passing: the 1.17.113 secret-inputs test, the 1.17.112 signals and waits tests, `tests/scheduler-wide-recheck-1.17.65.py`, `tests/contract-text-spacing-1.17.112.py`, and the 1.17.17, 1.17.18 and 1.17.62 server-maintenance tests.

## Not run here

* Django is not installed on this PC. The new tests load `server_maintenance.py`, `secret_store.py` and the helper directly, so they ran. Tests that need Django did not run.
* `tests/server-maintenance-privilege-boundary.py` needs `fcntl` (Linux). `tests/server-maintenance-root-layout.py` and `tests/secret-store-1.17.100.py` fail here the same way on the signed 1.17.113 (an index error and a missing Django name): not caused by this release.
* The helper as root through sudo and systemd, and tmpfs, cannot run on this PC. Johan ran `tests/server-maintenance-secrets-runtime-1.17.113.sh` on tectical-dev02 on 10 November 2026 (all PASS) against Core 1.17.113. The two helper changes in this release (`is-active` in the cancel and sweep paths, and `stdin=DEVNULL`) are covered only by the tests above. Rerun the same script on the dev server after 1.17.114 is installed.

## Assumptions (also in reviews/questions/core.md)

* The capability stays at 1.3.0 (no 1.3.1). Modules gate on `requires.framework >=1.17.114` or on `secret_inputs_enabled`.
* An unreadable `systemctl` counts as "unit gone" and the secret folder is removed.
* A `secret_inputs` value Core cannot parse is refused with `action_invalid`. Fail closed.
* Left out: `module_manager._refuse_unmet_framework` catches only `OSError`, so a corrupt `VERSION` file escapes `inspect_archive`. It is different code and goes to the next patch.
