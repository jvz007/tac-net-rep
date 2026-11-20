# Tec-Tac Framework 1.18.29

Date: 20 November 2026. Core now finishes the sandbox set-up by itself. After an install or update it runs the canary (the attack test the sandbox needs before any run may start). After a module's Install or Repair runtime action it re-checks that module's runners. You no longer run a sweep or a canary by hand. The kill switch stays on (`SANDBOX_ENABLED = True`) and every AD-65 gate stays: a run still needs a ready selftest and a canary that passed for this Core build and this selftest run. `main` stays held.

## Module-facing changes

`core.sandbox` stays 1.1.0. No route, permission, capability key, `status()` key or error code is added, removed or renamed.

- `ai`: `runtime_verified` is now current right after its Install runtime or Repair runtime action ends. Before, every start was refused with `runtime_unverified` until the next sweep. `ai` needs no change. It may drop any wording that tells the administrator to wait for the sweep.
- The contract rule text for `core.sandbox` (in `contracts.py`) now names `ai` (0.8.5 and newer) as the first module that uses it, and says that Core runs the canary at the end of an install or update and re-verifies a module's runners after its server-maintenance action job ends. Text only.
- Modules in `modules/`: only `ai` uses `core.sandbox`. No compatibility path is needed.

## Closes

- Request "re-verify a module's runners after its runtime action" (from the ai 0.8.5 review, round 1, 20 November 2026).
- Request "run the sandbox canary automatically after a Core install or update".
- Held Low from the review of 1.18.28: the contract rule still said "No module uses core.sandbox yet (1.18.27)".

## What changed and why

1. Re-verify after a runtime action.
   - `scripts/sandbox-helper.py` has a new root-only mode, `--verify-module <module-id>`. The sweep's per-runner loop moved into one shared function, `reverify_runners(owner=None)`. The sweep calls it for every row. The new mode calls it for one module's rows only. It judges against the recorded listing hash exactly as the sweep does, so a runtime that does not match its signed listing stays unverified. It writes one audit row, `module.runners_verified` (module, runners_checked, runtime_state_changed). A module with no runners is a quiet no-op. The id goes through the existing module id check.
   - `scripts/server-maintenance-helper.py` (the root worker) calls the new mode after an action of a signed module ends. It follows `sync_sandbox_runners` in `module-job-helper.py`: no helper means nothing happens, a helper that is not root-owned or is group or world writable is refused, the call is bounded at 120 s, and every exception is caught. It runs on every end path: success, non-zero exit, timeout, cancel and worker error. It runs after the program has ended and the global lock is released, and before the job is marked finished, so the page sees a verified runner the moment it sees the job done. A failure, non-zero exit or timeout becomes one lifecycle line and one audit row (`job.sandbox_reverify`) and never changes the job's status, exit result or failure. A hand-registered action, an action with no owner, and a job cancelled before it ran trigger nothing.
   - Why: the sweep only ran at boot and daily, so after Repair runtime the AI page stayed on "the server sandbox is not active".
   - No sudoers change. The Tactical account still has exactly `--start`, `--stop` and `--status`. The worker is root, and the new mode is not reachable through sudo.
2. Canary at the end of install and update.
   - `install.sh` has a new block after the ownership check and before "Installation complete.", so the services run again when it starts. It reads `--status`. If the selftest is not ready it logs `Sandbox: not active: <reason>` and skips. Otherwise it runs `sandbox-selftest.py --selftest --canary` (the command that writes `canary.json`), then reads `--status` again and logs exactly one line: `Sandbox: active`, or `Sandbox: not active: <reason>`.
   - Reasons are one printable ASCII line of at most 300 characters: the selftest reason, `the canary did not finish in <n> s`, `the canary failed: <failing row ids>`, or `not enough install time left to run the canary`.
   - Time: the canary is bounded at 900 s, reduced to `1700 - SECONDS` when the install already took long (the update worker bounds the whole installer at 1800 s), and skipped when fewer than 120 s are left.
   - It never fails the install. The step runs inside a function called with `|| true`. A failed, timed-out or crashed canary leaves the sandbox inactive (`canary_ok` false, fail closed) and the reason shows on the status route. An update takes a few minutes longer.
   - It adds nothing to sudoers, does not touch rmm, daphne, celery, celerybeat or nginx, and does not grant `sandbox.register`.
3. Contract text. The stale sentence is replaced (CRLF kept). The same stale wording in `docs/sandbox-capability.md` and `docs/capabilities.md` is fixed too. `docs/server-maintenance-capability.md` and `docs/system-update-logs.md` each gain one paragraph.

## Assumptions

- The install-time canary is the command that writes `canary.json`, not the whole `tests/sandbox-canary-1.18.28.sh`. It is the same canary the gate already requires, it needs no tests folder on the server, and the script stays the manual evidence run.
- The canary may hold up an install for at most 900 s, and less when the install is already slow. A skip or timeout leaves the sandbox off and never fails the install.
- The new root-only mode takes only a validated module id and widens no trust. If you decline it, leave `runtime_verified` to the sweep, as in 1.18.28.
- The module id check is the helper's existing rule, which allows capital letters, like every other mode. The plan listed uppercase as refused. That would make `--verify-module` stricter than `--register-module` and would fail for a module such as `securityWAF`, so it is not applied.
- The install guide (`docs/guides/tec-tac-install-existing-server.html`, step 10) is outside Core. The request is written to `reviews/requests/_unsorted.md`.

## Retired or changed checks

Retired to `tests/legacy/` with a 1.18.29 copy in `tests/`:

- `sandbox-installer-1.18.28.py` to `sandbox-installer-1.18.29.py`. Every assertion kept, plus the canary block. The allowed list of `SANDBOX_*` literals gains `SANDBOX_SELFTEST_PY`.
- `sandbox-contract-1.18.28.py` to `sandbox-contract-1.18.29.py`. Line 462 now asserts the new sentence and the absence of the stale one.
- `sandbox-doc-text-1.18.28.py` to `sandbox-doc-text-1.18.29.py`. Same assertions, plus the stale phrase must be gone from `contracts.py` and every doc, in both wordings.
- `version-1.18.28.py` to `version-1.18.29.py`.

Unchanged and still passing: `sandbox-switch-on`, `sandbox-verify-code`, `sandbox-canary-record`, `sandbox-launch`, `sandbox-django-launch`, `sandbox-helper-register`, `sandbox-private-network`, `sandbox-run-private`, `sandbox-canary-script` (all 1.18.28), and `sandbox-canary-1.18.28.sh`, which is not touched.

## New tests

- `tests/sandbox-reverify-1.18.29.py`: `--verify-module` changes only the named module's rows, in both directions; another module's rows stay byte for byte; no-op for a module with none; bad ids refused; audit row; non-root refused; the sweep still judges every row; the sudoers line still lists only the three commands.
- `tests/server-maintenance-sandbox-reverify-1.18.29.py`: exact argv after success, non-zero exit, timeout, cancel and worker error; called before the final status write; not called for a hand registration, an action with no owner or a job cancelled before it ran; a missing helper is silent; a writable or non-root helper is refused; a helper that exits 1, raises or hangs leaves the job unchanged; 120 s bound; lifecycle line and audit row.
- `tests/sandbox-install-canary-1.18.29.sh`: cuts the canary block out of `install.sh` and runs it with a stub `timeout` and helper (no network, no systemd). Pass, canary exit 1, timeout, crash, selftest not ready, `SECONDS` forced high, `SECONDS` partly used, unreadable status. Every case ends with exit status 0 and exactly one result line.
- `tests/version-1.18.29.py`.

## What could not be run here

- Django is not installed on this PC: `tec_tac_check_contract_export` and every Django test did not run.
- A real install (root, systemd, `visudo`), the real canary and the real root worker did not run. The tests above use a fake file layer, a fake subprocess and stubbed helpers.
- `tests/server-maintenance-privilege-boundary.py` needs `fcntl` (Linux only). `tests/server-maintenance-root-layout.py` fails on this PC the same way before and after this release. Both are unchanged.

## Johan dev02 checklist

1. Update Core to 1.18.29 from dev.
   - PASS: the install log shows `Sandbox: active`.
   - FAIL: the log shows `Sandbox: not active: <reason>`, or the update fails. Send the line and the install log.
2. Run `sudo /usr/local/sbin/tec-tac-sandbox --status` without running the canary by hand.
   - PASS: `enabled` true, `ready` true, `canary_ok` true.
   - FAIL: `canary_ok` false. Send the `--status` output and `/var/lib/tec-tac/sandbox/canary.json`.
3. In ai, press Repair runtime.
   - PASS: the AI page shows both providers available, and you did not run `systemctl start tec-tac-sandbox-sweep.service`.
   - FAIL: the page still says "The server sandbox is not active", or the reason is `runtime_unverified`. Send the job log, the last 40 lines of `/var/lib/tec-tac/sandbox/audit.jsonl` and the `--status` output.
4. Run `sudo cat /etc/sudoers.d/tec-tac-sandbox`.
   - PASS: the file is unchanged, with exactly three commands (`--start`, `--stop`, `--status`).
   - FAIL: any other command appears. Send the file.

## Where the plan did not fit the code

- Uppercase module ids: see Assumptions. The existing id rule is kept.
- `sandbox.register` already appears once in `install.sh`, in a comment that says Core never grants it. The check is that no line grants it, so the comment stays.
- The worker error path is handled by `run_job`'s `finally`. A pending-re-verify table keeps the call to once per job.

## Exit list

- The automatic grant of `sandbox.register` to the Tech Flow Dynamics dev publisher is not built. It widens trust. The question is open in `reviews/questions/core.md` and stays install guide step 10.2.
- The full `sandbox-canary-1.18.28.sh` (the Patch B and C exit lists, the switch-on proofs, the tie proofs) is not run by the installer. It stays the manual evidence run.
- Speeding up the Core install is a separate request. This canary adds a few minutes, which that request must count.
- A fresh public contract export under `docs/contracts` needs a running server and is still pending.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.
