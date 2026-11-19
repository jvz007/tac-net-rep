# Tec-Tac Framework 1.18.17

Date: 19 November 2026. The sandbox canary's memory row now judges on systemd's own record of the run, and no failed run unit is left behind. This is one theme, the last Patch A row. Nothing changes for modules, and the sandbox stays off.

## What changed and why

On dev02, Core 1.18.16 passed every canary row except the memory row: "allocated 112 MiB, ended exited (exit 1), oom_kills 0 ... no evidence". Johan then ran a plain `systemd-run` allocation loop on dev02 (systemd 255). It counted to 112 MiB, then printed `Finished with result: oom-kill` and `code=killed/status=KILL`, and systemd-run exited 1.

That tells us three things. The kernel kills the process, so no `MemoryError` ever reaches Python. The `exit 1` is systemd-run's own code, not the program's. And the helper started the unit with `--collect`, which deletes the unit's record the moment it ends, so the result and the cgroup counters were gone before anyone looked.

### 1. The run unit keeps its record, and the helper reads it

- `build_argv` no longer passes `--collect` for the run unit (`--pipe --wait --quiet --unit --slice` stay). The selftest and canary probe units keep `--collect`: nothing reads their result.
- New `read_unit_result(run_id)` runs one `systemctl show tectac-sbx-<id>.service --property=LoadState,ActiveState,Result,ExecMainCode,ExecMainStatus` through the existing `systemctl()` wrapper (so the clean environment and the 15 second timeout apply). It parses exact `Key=Value` lines and checks every value against a whitelist: `LoadState` must be exactly `loaded`, `Result` must be a known systemd word, the two numbers must be 1 to 4 digits. A duplicate, unknown or missing key, an unloaded unit or a failed call gives `None`. Nothing is guessed. A unit that exited 0 is garbage-collected, and systemd then reports `Result=success` and status 0 by default, which proves nothing; that is why `LoadState` is checked first.
- The helper never reads stream text for the result. The sandboxed program writes to the same stderr as systemd-run, so a program could print `Finished with result: success`. A test does exactly that and the end stays `oom`.
- In `_supervise`, after the process ends and the last forced cgroup poll, the helper reads the unit result once. The helper's own stop reasons (timeout, cancelled, output_limit, start_failed) always win. With none of them set, `Result=oom-kill` gives reason `oom`, and `Result=timeout` gives reason `timeout`.
- `in_memory_handoff` and `merge_memory_evidence` take the unit result. The evidence name is `unit_result` (text `systemd unit result oom-kill`) when the unit said oom-kill and the cgroup counters said nothing. The live poll and the forced poll still win when they saw the kill. `service_result` stays accepted for old callers.
- The end frame gains additive keys: `signal` (int or none), `unit_result` (whitelisted word or none) and `exit_source` (`unit` or `systemd-run`). `exit` is now the program's real exit code (`ExecMainCode` 1), or none when a signal ended it (`ExecMainCode` 2 or 3, with the signal number in `signal`). With no unit record, `exit` falls back to systemd-run's own code and `exit_source` says so.
- The cgroup counters (`memory.events`, `memory.peak`) stay as extra evidence when they are read.
- This also closes the held Low of 1.18.14: end-of-run evidence no longer depends on the last poll before the cgroup disappears.

### 2. Failed run units are reset

- New `reset_failed_unit(run_id)` runs `systemctl reset-failed` in the `finally` block of `launch()`. It runs on every path after the unit was started: normal end, cancel, helper fault. It is skipped when the unit record was not loaded, to save a call. The result is ignored ("not loaded" is normal).
- The sweep (boot and daily) lists failed units with `systemctl list-units --state=failed --plain --no-legend --no-pager 'tectac-*'`. It keeps only names that match `^tectac-[a-z0-9-]+\.service$`, skips a run unit whose run record or handoff is younger than 120 seconds (its helper may still be about to read the result) and skips active units, then resets the rest. A failed call never aborts the sweep.
- The sweep's printed JSON and its audit row gain `units_reset` (names only).

### 3. Memory row: unit result and real exit

- The row reads `unit_result` and `signal` from the end frame, with the same whitelist style as the counters. The text shows the program's real end (`exit N` or `killed by signal 9`) and `unit result oom-kill`, never systemd-run's code.
- OK with proof `systemd unit result oom-kill` when the end reason is `oom`, the unit result is `oom-kill`, the probe did not finish, and the allocated MiB and the peak (whichever are known, at least one) are at or below MemoryMax. dev02's case (112 MiB allocated, no peak) is enough. ATTACK SUCCEEDED rules are unchanged.
- Held Low: the `memory.events max` proof is accepted only when the run ended by `oom` or `exited`. On `timeout`, `cancelled`, `output_limit` or `start_failed` the row is NOT RUN with "ended by <reason>, not by the memory limit".
- The probe's first stderr line and the `memory.events` counters stay in the row. The other limit rows are unchanged.

## Module-facing change

None. No module uses `core.sandbox` today (`SANDBOX_ENABLED` is False; the only mention in `modules/` is the ai module's `OS_SANDBOX_AVAILABLE` flag). The new end-frame keys are internal and additive: Core's `_end_event` picks keys by name and drops the rest, and a test pins that. The run result a module would see keeps its shape, with one accuracy change: a program killed by a signal now reports `exit_code` none, not systemd-run's 1. The `run.ended` audit row is unchanged in shape (the new keys are not in it).

## Johan test checklist (dev02)

Run these in order. Each step says what a pass looks like and what to send back on a FAIL.

a. Install Core 1.18.17. PASS: the install ends without an error. FAIL: send the last 40 lines of the install output.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest`. PASS: it ends `exit=0` with `ready true`. FAIL: send the selftest JSON.

c. `sudo bash tests/sandbox-canary-1.18.17.sh`. PASS: it ends `ALL CANARY STEPS PASSED`, with 0 rows ATTACK SUCCEEDED and 0 rows NOT RUN. FAIL: send the whole output, the canary log from `debug/`, `sudo /usr/local/sbin/tec-tac-sandbox --status` and the last 40 lines of `/var/lib/tec-tac/sandbox/audit.jsonl`.

d. In the canary output, read the memory row (step 4u). PASS: it is OK, says `killed by signal 9` and `unit result oom-kill`, and ends `proof: systemd unit result oom-kill` (or another named proof). It does not say `exit 1`. FAIL: send the memory row with its counters.

e. In the canary output, read step 5r and step 5s. PASS for 5r: `Result=oom-kill`, ExecMainCode killed (2), ExecMainStatus 9, and the plain test unit is gone after `reset-failed`. PASS for 5s: `systemctl list-units --state=failed 'tectac-*'` prints nothing. FAIL: send the information line of step 5r, `systemctl --version`, and the listing from 5s.

f. `sudo ls -A /run/tec-tac/sandbox/secrets /run/tec-tac/sandbox/handoff /run/tec-tac/sandbox/runs` and `systemctl list-units --state=failed 'tectac-*'`. PASS: all print nothing. Then check that the Tactical web page and an agent check-in still work. FAIL: send the listings and what you saw.

## What could not be run

Django is not installed on this PC, and there is no systemd, no cgroup v2 and no root. These could not run: the real `systemctl show` of a unit, the real OOM kill, the real failed-unit list, the sudo rule and the installer. The real systemd result and the dev02 canary decide. What ran: `bash tests/release-integrity.sh`, the new and touched sandbox tests with a fake `systemd-run` and `systemctl` and a fake file layer, `python -m py_compile` and `ruff check`.

## Assumptions

- Nothing uses `core.sandbox` yet, so reporting a signal-killed program as `exit_code` none (not systemd-run's 1) changes no module. We did not report `128 + signal`: it invents a number the program never returned.
- Two extra `systemctl` calls per run (one `show`, one `reset-failed`) are acceptable. The reset is skipped when systemd reports the unit as not loaded.
- `systemctl show` prints `ExecMainCode` as a number (1 exited, 2 killed, 3 dumped). The helper accepts digits only; the canary step 5r also accepts the word `killed`.
- The test harness change is additive: the fake `systemd-run` writes a unit record and the fake `systemctl` answers `show` from it before its older `Exec` branch (`ExecMainCode` starts with `Exec`).

## What is not in this release

- Sandbox Patch B: it waits for the dev02 canary to end `ALL CANARY STEPS PASSED`.
- Every other open Core request (probe transport C1 and C2, contract export, audit row for a refused premium untick, lifecycle and licensing items): this release is one theme.
- Other held Lows in the backlog on different code paths (credential remover gives up silently, the canary's `/run/systemd` allowance, the post-run re-check of owner and mode, the v1 helper uninstall lock, the older module-v2 job helper Lows).
- `unit_result` or `signal` in the helper's `run.ended` row or in Core's run result: kept out so the audit allow-list and the module-facing result stay as they are.
- The selftest and canary probe units keep `--collect`.
