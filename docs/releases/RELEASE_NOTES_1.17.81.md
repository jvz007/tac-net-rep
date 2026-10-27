# Tec-Tac Framework 1.17.81

Date: 27 October 2026. Closes the two held findings of the 1.17.80 review (reviews/core/core-1.17.80-20261027-122318/REPORT.md). No migration, no new route, no new setting.

## What changed and why

1. **Faster scheduled runs (Medium, performance).** Core read every installed manifest up to three times for each dispatched run of a module schedule. It now reads them once and keeps the answer. The answer is tied to a fingerprint of the manifest files (path, change time, size). An install, upgrade or removal changes a manifest file, so the next run reads them again. With 50 module schedules Core scans once, not 150 times.
2. **A broken manifest now says so.** Any error still means "no person" (fail closed, same refusal as before). Core now also logs `reason=manifest_unreadable` with the schedule id, and keeps the reason with the cached answer, so the refusal is no longer silent. Fixing the manifest clears it on the next run.
3. **Manifest rule (Low).** A manifest that lists `scheduler_person_actions` must now state `requires.framework` of `>=1.17.80` or higher. Without it the manifest is refused with a plain reason. An empty list is still fine.

## Module-facing change

None in behaviour. Rule 3 only enforces what the 1.17.80 notes already asked for. Users checked in `modules/`: only Advanced Patch Management declares the key, and its manifest already requires `>=1.17.80,<2.0.0`, so it still parses (the test reads the real file).

## Tests

- `tests/scheduler-manifest-cache-1.17.81.py`: `discover_plugins` runs once for 50 module lookups and for 200 more; a changed, added or removed manifest is read again; a broken manifest answers False, logs the reason, is not rescanned and recovers when fixed; the parser refuses the key without a framework floor and accepts it with one; APM's real manifest parses.
- `tests/scheduler-person-actions-1.17.80.py` adjusted only to give the cache a fingerprint from its stub registry.

## Test checklist (dev02)

1. Install Core 1.17.81. Save an APM profile with a patch notice a few minutes ahead. **Expected:** at the due time the run succeeds and the audit shows one `run` row with `run_as` creator, as in 1.17.80. **FAIL:** "This run has no person behind it." Send back: the Scheduler run entry and the Core log lines containing `tec_tac.scheduler`.
2. Upgrade or reinstall APM (any version), then wait for the next run. **Expected:** it still succeeds, so Core noticed the new manifest. **FAIL:** a refusal that lasts after the upgrade. Send back: the run entry and the manifest `tec_tac.json` of APM.
3. Press Run now on the schedule. **Expected:** no person, nothing sent, as in 1.17.80. **FAIL:** it sends.
4. Check the Core log after steps 1 and 2. **Expected:** no `manifest_unreadable` lines. **FAIL:** any such line while APM works. Send back: the log lines.

## Not run here

Django is not installed on this PC. The tests run on the stub harness. Tests that need Django or the real `accounts` app (for example `scheduler-completion-runtime-1.17.61.py`) did not run here, before or after this change; the module-scanning compat tests fail the same way as before.
