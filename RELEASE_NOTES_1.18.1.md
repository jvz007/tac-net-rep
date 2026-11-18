# Tec-Tac Framework 1.18.1

Date: 18 November 2026. This release makes Core start faster. It changes no behaviour and no contract.

Johan's baseline of the beta server showed that every new Django process (uWSGI worker, Celery child) pays Tec-Tac's full import cost, and Tactical replaces a worker every 100 requests. This release removes the biggest single cost and trims the rest where that is safe.

## What changed and why

* **The dummy backup-code hash is built on first use (`mfa_backup.py`).** Before, Core ran `make_password(...)` when the file loaded: about 445 ms of CPU in every process on the beta server. Now a cached helper `_dummy_code_hash()` builds it the first time a failed sign-in needs it. Every failed path still runs the same number of hash checks (10 by default), so the timing protection is unchanged. Each process still gets its own salt. The first failed sign-in that needs the dummy in each new process pays the hash once. Two requests racing at that moment may each hash once; both hashes are valid dummies.
* **Regular expressions compile on first use.** A small helper, `framwork/tec_tac/lazy_patterns.py`, holds a pattern's text and flags and compiles it on the first call. It offers `match`, `fullmatch`, `search`, `sub`, `findall` and, through delegation, every other `re.Pattern` method and attribute. Used for the 20 module-level patterns in `tactical_operations.py` and the four in `system_actions.py`. Every name (`_ID_RE`, `_SECRET_NAME_RE`, `_PARAM_VALUE_RE` and the rest) stays importable and answers the same.
* **`diagnostics.py` imports Django's migration tools, `subprocess` and `shutil` inside the one function that uses each.** The text `MigrationAutodetector` stays in the file.

## Measured result, and what is left

Measured on this PC with `python -X importtime`, seven runs each, `tec_tac.tactical_operations` self time (no Django needed): median **28 ms before, 21 ms after**, a cut of about a quarter (run-to-run spread is wide, 20 to 50 ms before, 15 to 28 ms after). The dummy hash is removed from import entirely: `tec_tac.mfa_backup` no longer calls `make_password` at import (a test proves it).

We did **not** reach the request's target of cutting Core's own import self time by half. Mechanical lazy loading cannot get there without changing behaviour. What is left, and why it stays:

* The frozen dataclasses (`TacticalOperation`, `TacticalOperationResult`, `SystemFunction` and the others) cost about 17 ms in `tactical_operations.py`. They are public classes modules use.
* `SYSTEM_FUNCTIONS` is a public table modules read.
* The roughly 30 `extend_schema_view` decorators in `views.py` build the OpenAPI documentation.
* The intra-package imports (`capabilities`, `contracts`, `scheduler` and others) are loaded by other Core files at start-up anyway, so moving them gains nothing.

Reviewed and left alone:

* `scheduler.py` (CRLF): one pattern (`_TACTICAL_ENTRY_RE`), about half a millisecond. Not worth touching.
* `views.py`: `pyotp` and DRF are already imported by Tactical. No Core-only import there saves measurable time.
* `apps.py` `ready()`: every `register_core_*` call stays, because modules resolve capabilities in their own `ready()`. The imports inside `ready()` are already local. `patch_lockdown.apply_at_startup()` reads settings and is fail-safe on purpose. Nothing moved.

Both requests ask for the beta server's own numbers. The checklist below asks Johan for them. The "mfa_backup under 10 ms" target is met by construction. The "at least half" target is not met, as stated above; the remainder needs a separate decision (see `reviews/questions/core.md`).

## Requests closed

* `reviews/requests/core.md`, "core: build the dummy backup-code hash on first use, not at import": shipped in 1.18.1.
* `reviews/requests/core.md`, "core: keep start-up imports light in Core's own files": partly shipped in 1.18.1 (above). The shortfall against "down by at least half" is stated; the release manager decides whether to close or keep it open after the beta-server numbers.

## Module-facing

No contract, capability, endpoint or import changes. Every public name in `tec_tac.tactical_operations`, `tec_tac.scheduler` and `tec_tac.system_actions` is kept. The only names that changed are private: `_DUMMY_CODE_HASH` in `mfa_backup.py` is replaced by `_dummy_code_hash()` (nothing in Core, its tests or `modules/` reads it), and the private regex names are now lazy objects with the same methods. A grep of `modules/` found no import of any of them. Every installed module's `requires.framework` upper bound is `<2.0.0`, so 1.18.1 satisfies them all.

## What is not in this release

* Request counts per endpoint in diagnostics.
* A public operation that returns a request's client IP.
* The UI sync script and session IP-change policy install fixes.
* Permission rename declaration and the secret-store uninstall hook.
* Lazy dataclasses, a lazy `SYSTEM_FUNCTIONS` and fewer `extend_schema_view` decorators (they would change public classes or the OpenAPI output).
* Any change to Tactical's uWSGI `max-requests` (Johan's decision, already in `reviews/questions/core.md`).

## Checks run here

`bash tests/release-integrity.sh`, `tests/version-1.18.1.py`, `tests/mfa-backup-lazy-dummy-1.18.1.py`, `tests/startup-imports-1.18.1.py`, `python -m py_compile` and `ruff check` on the changed files. Django-dependent tests and a full `manage.py check` could not run on this PC (no Tactical project, no `pyotp`). `tests/version-1.18.0.py` moved to `tests/legacy/` because it pins version 1.18.0 and one root note.

## Johan test checklist (beta server)

Update the server to Core 1.18.1 first.

1. Take the import numbers. Run `cd /rmm/api/tacticalrmm && python -X importtime manage.py check 2>&1 | grep tec_tac` and send the output. Compare with the 1.18.0 baseline in `debug/server optimise.log`.
   * PASS: `tec_tac.mfa_backup` is under 10 ms self, and the Core files in the list are lower than before.
   * FAIL: `tec_tac.mfa_backup` is still near 445 ms. Send the full output.
2. Sign in with a correct password and no second factor set up.
   * PASS: you are in, as before.
   * FAIL: any error. Send the Core log.
3. Sign in with a wrong password.
   * PASS: the normal "invalid sign-in" answer, no 500 error.
   * FAIL: a 500 error or a hang.
4. Sign in with a correct password and a wrong recovery code on an account that has two-factor on.
   * PASS: the normal refusal; the answer takes about as long as with a wrong password.
   * FAIL: a 500 error, or an answer that is much faster than the wrong-password case.
5. Sign in with a valid recovery code.
   * PASS: you are in and the code is spent.
   * FAIL: refused, or the code still works a second time.
6. Open System Diagnostics.
   * PASS: the page loads and the migration and storage checks show results.
   * FAIL: a check shows an import or attribute error. Send the text.
