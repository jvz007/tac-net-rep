# Tec-Tac Framework 1.17.59

A replacement module, such as Advanced Patch Management, now installs while the module it replaces is still enabled. The job switches the replaced module off first, then installs. The release also records one decision and fixes the dev-server licensing test.

Date: 20 October 2026. No route, contract row, capability or import changes.

## What changed

### Installing a replacement while the replaced module is enabled (CQ169, from Johan's dev02 test)

On dev02, installing Advanced Patch Management 0.11.2 over Windows Patching failed with status 1. Both modules were enabled while the install shell ran. Core's loader drops a replacement while its replaced module is enabled, so the migration step could not import it and raised `ModuleNotFoundError`.

The job now does what an operator does by hand: it disables the replaced module, then installs. The new order, in one root job:

1. Back up the code and the module state.
2. Per module, before its install shell: re-check under the module-state lock, and disable the confirmed replaced module.
3. Run the install shell (copy, check, migrate).
4. Verify the rules and categories on the installed manifests. This still runs in full.
5. Record the versions.
6. Run the runtime sync.
7. Register the server-maintenance actions.

On any failure the job restores the code and the module state, re-enables the replaced module and syncs again. That includes a failing install shell.

- **What it checks first.** The step acts only on a fresh install of a replacement. The replaced module must be installed with a trusted, root-owned manifest, must be a core or server module, must be enabled, and must not be installed by the same job. An upgrade, a module that was installed before the job, and a replaced module that is already off change nothing.
- **Confirmation is unchanged.** What the job disables must be inside the operator's confirmed `disable_modules` list. If it is not, the job fails with "module replacement would disable a module the operator did not confirm", before that module's script runs and with nothing disabled.
- **How the helper learns what is replaced.** A new reader, `package_replaces`, takes the `replaces` value from the manifest inside the root-private, hash-checked package. It extracts nothing. It fails closed on zero or two manifests, an id that does not match, an oversized manifest, a bad `replaces` value or a path that leaves the archive.
- **Batches and bundles.** A single package, a bundle and a batch all take this path. In a batch with a dependency, the disable comes right before the replacement's own install shell, not before the dependency's.
- **Audit.** The job's `disabled_modules` is the union of what was disabled before the shell and what the verify step names. The audit rows read it as before.
- **The window.** The replaced module is off from step 2 until the job ends or rolls back, about a minute. A helper process killed outright cannot roll back. That limit is not new.
- **The plain install helper.** `scripts/module-job-helper.py` is reached only when `disable_modules` is empty. It has no disable step and needs no change.
- Core's scheduler should no longer queue a reconcile job during such an install, because there is no both-enabled window. This was read from the code and not run.

`docs/module-replacement.md` ("Enabling or installing a replacement") carries the new order.

### Decision record: AD-37 covers a premium module that honours AD-20 (Johan, Q-APM8, answer a, 20 October 2026)

This is a decision record. No code changed for it.

- **What is allowed.** The rule "a refusal made before Core is called writes no audit row" now also covers a premium module that honours AD-20 as a replacement. It covers only the routes that module takes over from the replaced module. Advanced Patch Management's `changes.py` routes mirror Windows Patching: a 400 for bad input or a 503 for a missing dependency writes no row, and a missing permission still writes one `deny` row.
- **What stays.** It does not cover the premium module's own routes (the install queue, rule evaluation and other routes only it has). Those keep writing `failed` rows.
- **Not recorded.** No AD-41 and no licensing decision. Johan has not confirmed a licensing decision in chat.
- **Where it is recorded.** These files sit at the project root, outside the signed package: `docs/tec-tac-module-standard.md` (section 3, the AD-37 bullet) and `docs/review-accepted-decisions.md` (row 37).
- **Answered.** Q-APM8. Marking it answered in `reviews/questions/premium-modules.md` is passed to the release manager through `reviews/requests/premium-modules.md`, because that file is outside Core's area.
- **Later, not built.** Q-APM6 (the pipeline test gate should create the Django tables a module's tests need) is pipeline tooling. Johan asked for it later, not yet. It is recorded as a request for the release manager, not built here.

### The dev-server licensing runtime test signs in properly (test only)

`tests/licensing-mode-runtime-1.17.58.py` used `force_authenticate`, which leaves the request with no Tec-Tac credential. Core's session guard could not identify it and answered 401 `session_invalid_state`. Production code is unchanged and Core's authentication is not weakened.

- Each throwaway person now gets a real Knox token and a `totp_key`. The request carries `Authorization: Token <raw>`, so Tactical's real Knox authentication runs.
- Every assert now names its step. A failed request shows its status and body, and a failure prints the failing step.
- New route checks: the runtime-settings read and write for `licensing_enforcement_mode` (default, each of the three values, and back to the default), a bad value (400, nothing stored), a plain person (exactly 403), `GET /api/tfd/system/licensing/` (superuser 200 with no key, token or fingerprint text; plain person exactly 403), and the agent list sort (`sort_by=hostname&sort_dir=desc`, and `sort_by=bogus` as 400 `invalid_resource_request`).
- A closing step counts, outside the transaction, that the throwaway people, tokens, session rows and probe audit rows are gone.

## Module-facing change

Patchmanagement can now be installed over an enabled patching. No contract, route or capability changes. No module needs a change.

## Tests

- New: `tests/module-replacement-install-order-1.17.59.py`. It runs the real `install_packages` with a fake of `install-extension.sh` that fails the way dev02 did when both modules are enabled. It fails on 1.17.58. It covers the order of events, the rollback on a failing shell and on a failing sync, an unconfirmed disable, the cases where nothing is disabled, bundles, batches with a dependency, `package_replaces`, and a static check that `run_job` calls `install_packages` once with `prepare=`.
- New: `tests/decision-record-ad37-premium-replacement-1.17.59.py` (no Django).
- New: `tests/licensing-mode-runtime-static-1.17.59.py`. It checks the shape of the runtime test with `ast`, and checks the runtime test's sign-in against Core's own `_credential_identity` with stubs.
- Changed: `tests/module-replacement-helper-1.17.11.py` and `tests/server-maintenance-module-actions-1.17.17.py`: their fake `install_packages` accepts the new `prepare` keyword. Their meaning is unchanged.
- `RELEASE_NOTES_1.17.58.md` moved to `docs/releases/`.

## Dev-server checks (Johan)

1. Replacement install. Install Advanced Patch Management 0.11.2 from `releases/modules/Advanced Patch Management` through the Module Manager, and confirm the Windows Patching disable in the popup. PASS if the job succeeds, Windows Patching is disabled, Advanced Patch Management is enabled and nothing else changed. FAIL if the install fails or both are enabled; send the job log.
2. Licensing runtime test. On dev02 run `cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/licensing-mode-runtime-1.17.58.py`. PASS if the last line is PASS. FAIL if any step prints FAIL; send back the step it names. Run it at most once a minute (the settings write throttle).

## Requests closed or answered

- Answered: Q-APM8 (decision record above). CQ169 raised as information.
- Passed on: Q-APM6 (release manager, later).

## Not run on the build PC

Django is not installed on this PC. These could not run here: the helper as root, the real `install-extension.sh` with Django and the migration, a real reload, and the dev-server licensing runtime test itself. The helper's behaviour is covered by the new test with fakes for the shell and the reload.
