# Tec-Tac Framework 1.18.28

Date: 20 November 2026. This is the second rebuild of 1.18.28. It is published as 1.18.28 when it passes review. The core.sandbox kill switch is on: `SANDBOX_ENABLED = True` in `framwork/tec_tac/sandbox.py` and in `scripts/sandbox-helper.py`. The gates stay fail-closed. A run still needs a ready selftest and a passed canary for this Core build and this selftest run. `main` stays held.

Why it is on. Johan amended AD-65 in chat on 20 November 2026 (switch-on baseline). The amendment is recorded in `docs/review-accepted-decisions.md`. His words, for the record:

> currently we're testing on ubuntu 24.04 as the dev box. that's the baseline. We'll test on 26.04 but and only if found there are issues we will disable the AI module.

The first rebuild held the switch because that entry did not exist yet. It exists now, so this build switches on again. The review of the first rebuild passed on the code and stopped on text and on rebuild labels in source files. Those are fixed here (see Fixed after review).

## Module-facing change

`core.sandbox` stays 1.1.0. No route, key, permission or error code is added, removed or renamed.

- `status()['enabled']` is `True` (it was `False` in 1.18.27). Only a forced-off constant gives `False` again.
- `status()['active']` is `enabled and ready and canary_ok`. `canary_ok` is `True` only when the last full canary passed for this Core build (`canary.json` `core_version` equals the installed `VERSION` text) and this selftest run (`canary.json` `selftest_at` equals the `selftest_at` in `status.json`). A missing key, a value that is not text, a different value, `ok` not `True` or an unreadable `VERSION` file gives `False`. `canary_at` is unchanged. No new status key.
- `start()` and `run()`: with no caller they still raise `not_owner` first, before any readiness check. Otherwise they raise `sandbox_not_ready` (HTTP 503) when the selftest is not ready or there is no passed canary for this build and selftest run, with one `sandbox.run.refused` row and no helper started. `sandbox_disabled` is raised only if the constant is forced off. `cancel()` is never gated by readiness.
- The root helper makes the same check for a real `--start` (`ready_status()`), and `--status` reports the same `canary_ok`. The canary's own runs and the root-only canary launch skip it, because they make the canary.
- Consequence for modules: every later selftest (each install or update runs one) gives a new `selftest_at` and so makes `canary_ok` false until a full canary runs again.
- Modules in `modules/`: only `ai` uses `core.sandbox`. It reads `status()['active']` and already maps `sandbox_not_ready` and `sandbox_disabled` by code. No `ai` change is needed. `ai` stays unavailable on a server until the canary has passed there. No compatibility path is needed.

## Closes

- The Medium and the Low of the review of the first rebuild (`core-1.18.28-1-20261120-140529`) and the promotion stop for rebuild labels (below).
- The core.sandbox plan entry in `reviews/requests/core.md`: the switch is on. The release manager annotates or removes it after signing.
- The canary tie held as a Low in the first rebuild (the canary record carried no Core version).

## Fixed after review

Review `core-1.18.28-1-20261120-140529` passed the code and stopped at signing. Three items.

1. Medium, stale module-facing text. Every string said the switch was held or off, and one sentence defined `active` as `enabled and ready` without `canary_ok`. All of it now says the state that ships: `enabled` true since 1.18.28 (AD-65 amendment), `active` is `enabled and ready and canary_ok`, `sandbox_not_ready` when not active, `sandbox_disabled` only if the constant is forced off. Files: `contracts.py` (CRLF kept), `sandbox.py`, `sandbox-helper.py`, `apps.py`, `install.sh`, `docs/sandbox-capability.md`, `docs/capabilities.md`. `tests/sandbox-doc-text-1.18.28.py` now fails on any stale wording in those files and on any definition of `active` that leaves out `canary_ok`.
2. Low, held: the canary was not tied to the build. The selftest now writes `core_version` (the installed `VERSION` text) and `selftest_at` into `canary.json` (read before the canary runs). The helper and Django count a canary only when both still match. The comparison is exact text, with no label stripping. `tests/sandbox-canary-record-1.18.28.py` covers every case on both sides.
3. Promotion stop: no rebuild label in any source file. The label of the rebuilds is only in `VERSION`, `tec_tac_package.json` and these notes. `tests/version-1.18.28.py` fails when any other file carries it.

## What changed and why

- `SANDBOX_ENABLED = True` in `framwork/tec_tac/sandbox.py` and `scripts/sandbox-helper.py`. The helper's constant is the one that counts. `--start` and `--stop` no longer end in the final-refusal frame.
- Kept from the first rebuild: `start()` and `run()` refuse with `sandbox_not_ready` unless the selftest is ready and the canary passed; the canary's own launch skips the canary check; cancel and `--stop` are not gated.
- New in the helper: `installed_core_version()` (reads the root-owned installed `VERSION` file through the trusted-file reader; unreadable means not passed), `canary_record_state()`, `canary_passed()`. `show_status()` and `ready_status()` use them.
- New in `scripts/sandbox-selftest.py`: the canary command reads `status.json` before the canary runs and writes `core_version` and `selftest_at` into `canary.json`. The record stays free of secrets.
- New in `framwork/tec_tac/sandbox.py`: `VERSION_FILE` and the same three-way rule in `status()`.
- The installer check `VERIFY_SANDBOX_CODE` still expects `not_owner` (the constant is on). `start()` with no caller raises `not_owner` before any readiness refusal, so a server that is not ready, or has no canary, still installs. The install log line now says the switch is on and a run needs the canary.
- `tests/sandbox-canary-1.18.28.sh` expects the on state everywhere: 3c and 5m expect a refused garbage header; 5l expects `enabled` true; 5k checks `core_version` and `selftest_at` in `canary.json` against the installed `VERSION` and `status.json`; step 6 starts a real inert run and expects `run.started` and `run.ended`; 6c forces a not-ready status (restored by a trap) and expects `sandbox_not_ready`; new step 6e rewrites `core_version`, then `selftest_at`, in `canary.json` (restored by a trap), and expects `canary_ok` false, `active` false and a refusal each time, then true again after the restore. Modes `network` and `patchc` stay. The script says they re-run the selftest and so end with `canary_ok` false until the full canary runs again. The old wording about a second kind of server is gone.

## Assumptions

- Information, no wait: the canary needs `selftest_at` as well as the Core version (Johan: "write the Core version and selftest_at into canary.json and require both to match"). Options: (a) require both; (b) the Core version only. I went on with (a), the fail-closed choice. The cost: the `ai` module stays unavailable after any selftest until the full canary runs again. The dev02 checklist therefore runs `network` and `patchc` first and the full canary last.
- Information, no wait: the running Core version for the canary check is the text of the installed `VERSION` file (root-owned, installed by `install.sh`), compared as exact text. The installed file holds the clean 1.18.28 after signing, and the canary is written on that installed build, so the comparison is consistent on dev02.
- Information, no wait, flagged for human review (security): the switch is on under Johan's chat amendment, recorded in AD-65. The gates are fail-closed. A High or Critical finding in the review is not argued. The fallback is to set the constant back to `False` in both files (see the exit list). Johan alone promotes `main`.
- Information, no wait: the capability stays `core.sandbox` 1.1.0. The registered notes and description change, the version does not.

## Retired or changed checks

No test of an existing behaviour is dropped. The tests that asserted the shipped-off constant now assert `True`; where a test proves the forced-off path it sets the constant to `False` inside the test. Changed: `sandbox-switch-on`, `sandbox-contract`, `sandbox-doc-text`, `sandbox-installer`, `sandbox-verify-code`, `sandbox-launch`, `sandbox-django-launch`, `sandbox-helper-register`, `sandbox-private-network`, `sandbox-run-private`, `sandbox-canary`, `sandbox-canary-script` and `version` (all `-1.18.28`), and the shared harness `sandbox-harness-1.17.118.py`, which now writes a canary with `core_version` and `selftest_at` and an installed `VERSION` file for the helper. The contract test also expects the new wording of the forced-off refusal ("forced off").

## New tests

- `tests/sandbox-canary-record-1.18.28.py`: the selftest writes the two keys; helper (`show_status`, `ready_status`, `canary_passed`) and Django (`status()`) agree on 18 cases (matching, other Core version, other selftest run, missing keys, values that are not text, `ok` false, an old record, an unreadable canary, an unreadable `VERSION` file, no label stripping); the canary's own launch skips the check; a later selftest run makes the same record not count.
- `tests/sandbox-switch-on-1.18.28.py` gains the helper cases for the new rule.
- `tests/sandbox-doc-text-1.18.28.py` scans the listed files for stale wording and for any definition of `active` without `canary_ok`.
- `tests/version-1.18.28.py` asserts `SANDBOX_ENABLED = True` in both files and scans the tree for the rebuild label.
- `tests/sandbox-canary-script-1.18.28.py` runs step 6 and the new step 6e in bash against stand-ins (a passing run, a server that ignores the canary, a server that ignores readiness, and the traps that restore `status.json` and `canary.json`).

All of them stub sockets, use 127.0.0.1 only, bind nothing on `0.0.0.0` and contact no public address.

## What could not be run

Django is not installed on this PC, so the Django-bound tests and the contract export test did not run (the Django side of the canary rule is tested against the real `sandbox.py` with its file reader replaced). A fresh export of the public contracts into `docs/contracts` needs a running server, so the release manager does it after signing. The canary shell script needs root, systemd and dev02: it was syntax-checked with `bash -n` and its logic was checked against stand-ins. The real start and run of the inert test runner, and the real canary, are verified only on dev02, by Johan.

## Johan dev02 checklist

a. Update dev02 to Core 1.18.28 from `dev`, then run `cd /opt/tec-tac-src/framework && cat VERSION`.
   PASS: it prints `1.18.28`.
   FAIL: any other version. Send the output and stop.

b. Compare the installed files with the source: `sha256sum` of the installed helper, `sandbox-selftest.py`, the launcher, the egress program and the canary runner against the files in `scripts/`.
   PASS: every pair matches and the selftest file is `root:root 700`.
   FAIL: any mismatch. Send the output and stop.

c. Run `sudo bash tests/sandbox-canary-1.18.28.sh network`, then `sudo bash tests/sandbox-canary-1.18.28.sh patchc`. Both re-run the selftest, so the canary does not count until step d.
   PASS: each ends with `ALL CANARY STEPS PASSED`; step 5t shows 9 proxy rows OK; step 5w shows PATCH C ROWS 9 OK.
   FAIL: any ATTACK SUCCEEDED row or any FAIL line. Send the whole output and stop.

d. Run the full canary last: `sudo bash tests/sandbox-canary-1.18.28.sh 2>&1 | tee ~/sandbox-canary-1.18.28-$(date +%Y%m%d-%H%M).log`. It also writes `canary.json` with `core_version` and `selftest_at`.
   PASS: `ALL CANARY STEPS PASSED`, 0 ATTACK SUCCEEDED, 0 NOT RUN; the log says `kill switch in the installed helper: on`; 6b shows `run.started` then `run.ended` for a real inert run; 6c shows `sandbox_not_ready` while status is forced and `status.json` back byte for byte; 6e shows `canary_ok` false for another `core_version` and for another `selftest_at`, and true again after the restore.
   FAIL: any ATTACK SUCCEEDED row, a hash mismatch or any FAIL line. Send the log and run nothing else in the sandbox.

e. Run no other sandbox command. Then check the status: `sudo /usr/local/sbin/tec-tac-sandbox --status`.
   PASS: `enabled` true, `ready` true, `canary_ok` true; Core's `active` is true as well (the `ai` module shows its sandbox as available).
   FAIL: any value that is not true. Send the whole output, `cat /var/lib/tec-tac/sandbox/canary.json`, `cat /var/lib/tec-tac/sandbox/status.json` and `cat /opt/tec-tac/VERSION`.

f. If any step fails: set `SANDBOX_ENABLED` back to `False` in `scripts/sandbox-helper.py` and `framwork/tec_tac/sandbox.py` (or disable the `ai` module on that server) and send the log. Ubuntu 26.04 is tested afterwards. The `ai` module is disabled there only if issues are found. `main` stays held; Johan promotes.

## Where the plan did not fit the code

- The plan named install.sh line ~1302 for the pass-line wording and line ~1073 for a comment. Both were changed. A third comment near the installer's verify step also said `enabled` stays false, and it is changed too.
- `contracts.py`, `apps.py` and `docs/capabilities.md` use CRLF line endings, not LF as the plan assumed. Their endings are kept. Several test files also use CRLF; theirs are kept.
- The helper's installed `VERSION` path is the fixed `/opt/tec-tac/VERSION` (a module constant, so tests point it elsewhere). It is not read from the root layout file, so a Core installed elsewhere would fail closed (canary not passed) rather than read a wrong file.
- `ready=False` servers: the install check still passes because `start()` with no caller raises `not_owner` before any readiness check. No change to the order was needed.

## Exit list

For this build: the dev02 checklist passes in full. Then Ubuntu 26.04 is tested. If 26.04 shows issues, Johan's amendment says the `ai` module is disabled there. If dev02 fails, the constant goes back to `False` in both files. `main` is promoted only by Johan.

## Main stays held

`main` stays at Core 1.17.110. This release goes to `dev` only. Johan promotes `main`, and only him.
